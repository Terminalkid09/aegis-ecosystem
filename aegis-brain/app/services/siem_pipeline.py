"""Pipeline di ingestione SIEM: dal payload grezzo all'alert.

Sequenza (e perché in quest'ordine):
1. **parse** — un parser esplicito o auto-detection; il payload non
   riconosciuto viene contato, mai trasformato in un evento vuoto;
2. **dedup + store + commit** — i dati grezzi si salvano *prima* della
   detection: un bug nel motore non deve far perdere telemetria;
3. **detection** (Sigma + correlazione) e creazione alert in una seconda
   transazione, best-effort: un errore qui viene loggato e non annulla lo store;
4. **playbook SOAR** sugli alert nuovi, riusando il motore esistente.

Gli alert generati da sorgenti esterne entrano nello stesso flusso degli
agenti: ogni sorgente ha un agente "logsource" sintetico, così UI, triage,
dedup, suppression e SOAR funzionano senza modifiche ai consumer.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_audit
from app.core.config import settings
from app.core.logging import get_logger
from app.database.models import Agent, Alert
from app.ingest import default_registry
from app.ingest.base import UnifiedEvent
from app.rules.mitre import tactic_from_tags, technique_name
from app.rules.sigma import get_engine as get_sigma_engine
from app.services import siem_store
from app.services.correlation import CorrelationMatch, get_correlation_engine

logger = get_logger(__name__)

_SOURCE_AGENT_CACHE: Dict[str, uuid.UUID] = {}
LOGS_SOURCE_AGENT_TYPE = "logsource"


async def get_or_create_source_agent(db: AsyncSession, source_name: str,
                                     source_type: str) -> Agent:
    """Agente sintetico che rappresenta una sorgente di log.

    Perché non una tabella `detections` separata: gli alert delle sorgenti
    esterne devono avere lo stesso ciclo di vita (triage, incidenti, playbook,
    dashboard) di quelli degli agenti. Rappresentare la sorgente come agente
    evita di duplicare tutta quella macchina.
    """
    cached = _SOURCE_AGENT_CACHE.get(source_name)
    if cached is not None:
        # `first()` chiude il Result: va letto una volta sola, altrimenti il
        # secondo accesso solleva "This result object is closed" (bug reale,
        # coperto da tests/integration/test_siem_ingest.py).
        existing = await db.execute(select(Agent).where(Agent.agent_id == cached))
        agent = existing.scalars().first()
        if agent is not None:
            return agent

    os_type = f"{LOGS_SOURCE_AGENT_TYPE}:{source_type}"
    result = await db.execute(select(Agent).where(Agent.hostname == source_name,
                                                  Agent.os_type == os_type))
    agent = result.scalars().first()
    if agent is None:
        agent = Agent(
            hostname=source_name,
            os_type=os_type,
            agent_type=LOGS_SOURCE_AGENT_TYPE,
            agent_version="siem-ingest",
            is_demo=False,
            isolated=False,
            meta={"kind": LOGS_SOURCE_AGENT_TYPE, "source_type": source_type,
                  "note": "Sorgente di log esterna: non è un endpoint gestito."},
        )
        db.add(agent)
        await db.flush()
    _SOURCE_AGENT_CACHE[source_name] = agent.agent_id
    return agent


def _severity_rank(severity: str) -> int:
    return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(
        (severity or "INFO").upper(), 0)


def _alert_from_sigma(event: UnifiedEvent, match: Any, agent_id: uuid.UUID) -> Alert:
    technique = match.mitre_techniques[0] if match.mitre_techniques else None
    tactic = tactic_from_tags(getattr(match, "tags", None))
    return Alert(
        agent_id=agent_id,
        severity=match.level.upper() if match.level else "MEDIUM",
        pid=event.pid,
        parent_pid=event.parent_pid,
        parent_process_name=event.parent_process_name,
        process_name=(event.process_name or event.signature or event.source or "log-source")[:255],
        process_path=event.process_path or event.file_path,
        event_type=str(event.extra.get("event_type") or event.source_type)[:100],
        description=f"[SIGMA {match.rule_id}] {match.title}"
                    + (f" — {event.message[:200]}" if event.message else ""),
        mitre_tactic_id=tactic[0] if tactic else None,
        mitre_tactic_name=tactic[1] if tactic else None,
        mitre_technique_id=technique,
        mitre_technique_name=technique_name(technique),
    )


def _alert_from_correlation(match: CorrelationMatch, agent_id: uuid.UUID) -> Alert:
    event = match.event
    technique = match.mitre[0] if match.mitre else None
    tactic = tactic_from_tags(match.tags)
    detail = f" ({match.group_label})" if match.group_label else ""
    return Alert(
        agent_id=agent_id,
        severity=match.severity,
        pid=event.pid if event else None,
        process_name=(event.process_name if event and event.process_name
                      else (match.group_label or "log-source"))[:255],
        event_type="CORRELATION",
        description=f"[CORRELATION {match.rule_id}] {match.title}{detail} — "
                    f"{match.observed} eventi in {match.window_seconds}s",
        mitre_tactic_id=tactic[0] if tactic else None,
        mitre_tactic_name=tactic[1] if tactic else None,
        mitre_technique_id=technique,
        mitre_technique_name=technique_name(technique),
    )


async def _detect_and_alert(db: AsyncSession, source_name: str, source_type: str,
                            events: Sequence[UnifiedEvent]) -> Dict[str, Any]:
    """Sigma + correlazione sugli eventi appena salvati. Best-effort."""
    sigma = get_sigma_engine()
    correlation = get_correlation_engine()

    sigma_matches: List[Tuple[UnifiedEvent, Any]] = []
    for event in events:
        for match in sigma.evaluate(event):
            sigma_matches.append((event, match))
    try:
        correlation_matches = await correlation.evaluate(events)
    except Exception as exc:
        logger.warning(f"Correlazione non valutata per {source_name}: {exc}")
        correlation_matches = []

    if not sigma_matches and not correlation_matches:
        return {"sigma": 0, "correlation": 0, "alerts": 0}

    agent = await get_or_create_source_agent(db, source_name, source_type)
    new_alerts: List[Alert] = []
    for event, match in sigma_matches:
        new_alerts.append(_alert_from_sigma(event, match, agent.agent_id))
    for match in correlation_matches:
        new_alerts.append(_alert_from_correlation(match, agent.agent_id))
    for alert in new_alerts:
        db.add(alert)
    await db.flush()
    return {
        "sigma": len(sigma_matches),
        "correlation": len(correlation_matches),
        "alerts": len(new_alerts),
        "alert_ids": [a.id for a in new_alerts],
        "sigma_rules": sorted({m.title for _e, m in sigma_matches}),
        "correlation_rules": sorted({m.title for m in correlation_matches}),
    }


async def run_playbooks_for_alerts(db: AsyncSession, alert_ids: Sequence[int]) -> int:
    """Fa girare i playbook SOAR sugli alert nuovi (stesso motore degli agenti)."""
    if not alert_ids:
        return 0
    executed = 0
    try:
        from app.services.playbook_engine import check_and_execute_playbooks
        result = await db.execute(select(Alert).where(Alert.id.in_(list(alert_ids)[:200])))
        for alert in result.scalars().all():
            try:
                await check_and_execute_playbooks(db, alert)
                executed += 1
            except Exception as exc:
                logger.warning(f"Playbook su alert {alert.id} fallito: {exc}")
    except Exception as exc:
        logger.warning(f"Motore playbook non disponibile: {exc}")
    return executed


async def process_events(db: AsyncSession, source_name: str, source_type: str,
                         events: Sequence[UnifiedEvent]) -> Dict[str, Any]:
    """Salva gli eventi, esegue le detection e crea gli alert."""
    if not events:
        return {"accepted": 0, "duplicates": 0, "stored": 0, "alerts": 0}

    fresh: List[UnifiedEvent] = []
    duplicates = 0
    for event in events:
        if await siem_store.claim_event(event.event_id):
            fresh.append(event)
        else:
            duplicates += 1

    stored = 0
    if fresh:
        try:
            stored = await siem_store.store_events(db, fresh)
            await db.commit()
        except Exception as exc:
            await db.rollback()
            logger.error(f"Store eventi fallito per {source_name}: {exc}")
            return {"accepted": len(events), "duplicates": duplicates,
                    "stored": 0, "alerts": 0, "error": "store failed"}

    detection: Dict[str, Any] = {"sigma": 0, "correlation": 0, "alerts": 0}
    if fresh:
        try:
            detection = await _detect_and_alert(db, source_name, source_type, fresh)
            await db.commit()
        except Exception as exc:
            await db.rollback()
            logger.error(f"Detection fallita per {source_name}: {exc}")
            detection = {"sigma": 0, "correlation": 0, "alerts": 0, "error": "detection failed"}

    if detection.get("alert_ids"):
        try:
            await run_playbooks_for_alerts(db, detection["alert_ids"])
            await db.commit()
        except Exception as exc:
            await db.rollback()
            logger.warning(f"Playbook non eseguiti: {exc}")

    return {
        "accepted": len(events),
        "duplicates": duplicates,
        "stored": stored,
        **{k: v for k, v in detection.items() if k != "alert_ids"},
    }


async def ingest_payload(db: AsyncSession, source_name: str, payload: Any,
                         meta: Optional[Dict[str, Any]] = None,
                         parser: Optional[str] = None) -> Dict[str, Any]:
    """Ingerisce un payload: parse → pipeline. Contabilizza sempre la sorgente."""
    if not settings.SIEM_ENABLED:
        return {"accepted": 0, "stored": 0, "alerts": 0,
                "error": "SIEM ingestion disabled"}

    meta = dict(meta or {})
    meta.setdefault("source", source_name)
    meta.setdefault("received_at", datetime.now(timezone.utc).isoformat())

    result = default_registry.parse(parser or source_name, payload, meta)
    events = result.events
    if len(events) > settings.SIEM_MAX_EVENTS_PER_REQUEST:
        events = events[: settings.SIEM_MAX_EVENTS_PER_REQUEST]

    outcome: Dict[str, Any] = {
        "source": source_name,
        "parser": result.parser,
        "detected_by": result.detected_by,
        "unparsed": result.unparsed,
        "errors": result.errors[:5],
    }

    try:
        await siem_store.upsert_source(
            db, source_name,
            source_type=(events[0].source_type if events else meta.get("source_type", "unknown")),
            parser=result.parser or (parser or "auto"),
            description=meta.get("description"),
        )
        await db.commit()
    except Exception as exc:
        await db.rollback()
        logger.warning(f"Registro sorgente {source_name} non aggiornato: {exc}")

    if not events:
        try:
            await siem_store.record_source_result(
                db, source_name, accepted=0,
                invalid=max(1, result.unparsed),
                error="; ".join(result.errors[:2]) or "no parser matched")
            await db.commit()
        except Exception:
            await db.rollback()
        outcome.update({"accepted": 0, "stored": 0, "alerts": 0})
        return outcome

    pipeline_result = await process_events(db, source_name, events[0].source_type, events)
    outcome.update(pipeline_result)

    try:
        await siem_store.record_source_result(
            db, source_name, accepted=pipeline_result.get("stored", 0),
            invalid=result.unparsed,
            error="; ".join(result.errors[:2]) if result.errors else None)
        await db.commit()
    except Exception:
        await db.rollback()
    return outcome


async def ingest_batch(db: AsyncSession, source_name: str,
                       payloads: List[Any]) -> Dict[str, Any]:
    """Ingerisce più payload (es. sfaturati su uno stesso canale)."""
    totals = {"accepted": 0, "stored": 0, "alerts": 0, "duplicates": 0, "errors": []}
    for payload in payloads:
        result = await ingest_payload(db, source_name, payload)
        totals["accepted"] += result.get("accepted", 0)
        totals["stored"] += result.get("stored", 0)
        totals["alerts"] += result.get("alerts", 0)
        totals["duplicates"] += result.get("duplicates", 0)
        if result.get("errors"):
            totals["errors"].extend(result["errors"])
    return totals
