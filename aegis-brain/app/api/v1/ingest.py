"""Endpoint di ingestione multi-sorgente.

Due modi di autenticarsi, entrambi espliciti:
- **X-Api-Key** (la stessa chiave usata da Aegis-Link) per shipper e
  integrazioni server-to-server;
- **Bearer JWT** per la dashboard e per l'operatore che fa una prova.

L'ingestione è idempotente per `event_id`: un relay che reinvia la stessa riga
non produce alert duplicati (vedi `siem_store.claim_event`).
"""
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request
from sqlalchemy import select
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_audit
from app.core.config import settings
from app.core.deps import get_current_user, require_perm
from app.core.rate_limit import limiter
from app.services.api_keys import resolve_api_key, source_allowed
from app.database.connection import get_db
from app.ingest import default_registry
from app.ingest.registry import parser_catalog
from app.rules.sigma import get_engine as get_sigma_engine
from app.services import siem_store
from app.services.correlation import get_correlation_engine
from app.services.siem_pipeline import ingest_payload
from app.database.models import DeceptionSession, Incident, IncidentAlert
from app.ingest.base import parse_timestamp


router = APIRouter(tags=["SIEM Ingest"])


async def ingest_auth(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Accetta API key globale/per-sorgente oppure JWT valido.

    Una chiave DB viene risolta per hash e puo' essere revocata senza toccare
    le altre integrazioni. Il rate limit usa l'identita' della chiave, non
    l'IP del proxy.
    """
    if x_api_key:
        auth = await resolve_api_key(db, x_api_key)
        if auth is None:
            raise HTTPException(status_code=403, detail="Forbidden: Invalid or revoked X-Api-Key")
        request.state.rate_limit_key = f"api-key:{auth.get('id') or 'global'}"
        return auth
    if authorization:
        try:
            user = await _resolve_user(authorization, db)
        except HTTPException:
            raise HTTPException(status_code=401, detail="Invalid token")
        request.state.rate_limit_key = f"user:{user.id}"
        return {"kind": "bearer", "username": user.username, "role": user.role}
    raise HTTPException(
        status_code=401,
        detail="Ingestion requires X-Api-Key or a Bearer token",
    )


def _ingest_rate_key(request: Request) -> str:
    return getattr(request.state, "rate_limit_key", "anonymous")


async def _resolve_user(authorization: str, db: AsyncSession):
    from app.core.deps import _validate_token
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    return await _validate_token(authorization[7:], db)


class SourceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    source_type: Optional[str] = Field(None, max_length=64)
    parser: str = Field("auto", max_length=64)
    description: Optional[str] = Field(None, max_length=255)


class ParseTestBody(BaseModel):
    parser: str = "auto"
    payload: Any


@router.get("/catalog")
async def parser_catalog_endpoint(user=Depends(get_current_user)):
    """Sorgenti supportate: nome parser + tipo. Usato dalla UI Log Sources."""
    return {
        "parsers": [{"name": name, "source_type": source_type}
                    for name, source_type in parser_catalog()],
        "aliases": {
            "winevent": "windows_event", "evtx": "windows_event",
            "eve": "suricata", "ids": "suricata", "bro": "zeek",
            "opnsense": "pfsense", "filterlog": "pfsense",
            "windows_firewall": "pfirewall", "ufw": "iptables",
            "apache": "nginx", "httpd": "nginx", "access_log": "nginx",
            "rfc5424": "syslog", "rfc3164": "syslog", "ndjson": "json",
        },
        "note": "With source='auto' the parser is chosen from the payload "
                "shape; an unrecognized payload is counted as unparsed and "
                "produces no events.",
    }


@router.get("/sources")
async def list_sources(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    return {"items": await siem_store.list_sources(db)}


@router.post("/sources")
async def upsert_source(
    payload: SourceCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_perm("deploy")),
):
    """Registra (o aggiorna) una sorgente senza inviare eventi.

    Utile per preparare il canale e monitorarne la salute prima che i log
    arrivino.
    """
    parser_name = payload.parser or "auto"
    if parser_name != "auto" and default_registry.get(parser_name) is None:
        raise HTTPException(status_code=422,
                            detail=f"unknown parser {parser_name!r}; see /ingest/catalog")
    resolved = default_registry.get(parser_name) if parser_name != "auto" else None
    source = await siem_store.upsert_source(
        db, payload.name,
        source_type=payload.source_type or (resolved.source_type if resolved else "unknown"),
        parser=parser_name,
        description=payload.description,
    )
    await log_audit(db, action="ingest_source_upsert", resource="log_source",
                    resource_id=payload.name, details={"parser": parser_name},
                    user_id=user.id, username=user.username,
                    ip_address=request.client.host if request.client else None)
    await db.commit()
    return {"status": "ok", "id": source.id, "name": source.name, "parser": source.parser}


@router.post("/test")
async def test_parse(payload: ParseTestBody, user=Depends(get_current_user)):
    """Prova un parser senza salvare nulla: serve a chi integra una sorgente."""
    result = default_registry.parse(payload.parser, payload.payload,
                                    {"source": "preview", "received_at": None})
    return {
        "parser": result.parser,
        "detected_by": result.detected_by,
        "unparsed": result.unparsed,
        "errors": result.errors,
        "events": [event.to_record() for event in result.events[:50]],
    }


@router.get("/stats")
async def ingest_stats(hours: int = Query(24, ge=1, le=720),
                       db: AsyncSession = Depends(get_db),
                       user=Depends(get_current_user)):
    stats = await siem_store.event_stats(db, hours=hours)
    signs = get_sigma_engine()
    correlation = get_correlation_engine()
    stats["detection"] = {
        "sigma_rules": signs.coverage()["rules_executable"],
        "sigma_rules_total": signs.coverage()["rules_total"],
        "correlation_rules": correlation.coverage()["rules_executable"],
        "correlation_rules_total": correlation.coverage()["rules_total"],
    }
    return stats


@router.get("/detection-coverage")
async def detection_coverage(user=Depends(get_current_user)):
    """Copertura reale: quante regole Sigma e di correlazione girano, e perché
    le altre sono escluse. Un numero onesto invece di un conteggio gonfiato."""
    return {
        "sigma": get_sigma_engine().coverage(),
        "correlation": get_correlation_engine().coverage(),
    }


def _kraken_allowed(auth: Dict[str, Any]) -> bool:
    """Kraken needs its own source and an explicit write scope.

    The global API key is the bootstrap/backward-compatible path; every
    per-service key must be restricted to `source=kraken` and to the
    `kraken:write` scope. A generic ingest key is not enough.
    """
    if auth.get("kind") != "api_key":
        return False
    if auth.get("global"):
        return True
    if not source_allowed(auth, "kraken"):
        return False
    scopes = auth.get("scopes") or {}
    if isinstance(scopes, dict):
        scopes = scopes.get("scopes") or []
    return "*" in scopes or "kraken:write" in scopes


async def _upsert_deception_sessions(
    db: AsyncSession,
    events: List[Dict[str, Any]],
    incident_id: Optional[int] = None,
) -> int:
    """Aggiorna la copia Aegis delle sessioni deception.

    Una sessione può arrivare in più richieste (comandi successivi, retry del
    sensore). L'upsert è idempotente per `session_id`: non crea righe duplicate
    e conserva il primo `first_seen`.
    """
    touched = 0
    for row in events:
        if not isinstance(row, dict):
            continue
        raw = row.get("raw") if isinstance(row.get("raw"), dict) else {}
        network = row.get("network") if isinstance(row.get("network"), dict) else {}
        user = row.get("user") if isinstance(row.get("user"), dict) else {}
        session_id = str(raw.get("session_id") or row.get("event_id") or "")[:64]
        if not session_id:
            continue
        occurred = parse_timestamp(row.get("occurred_at") or row.get("time"))
        context = str(raw.get("context") or "sensor").lower()
        if context not in ("sensor", "lab"):
            context = "sensor"
        existing = (await db.execute(
            select(DeceptionSession).where(DeceptionSession.session_id == session_id)
        )).scalars().first()
        if existing is None:
            db.add(DeceptionSession(
                session_id=session_id,
                sensor=str(raw.get("sensor") or row.get("source") or "kraken")[:32],
                context=context,
                src_ip=network.get("src_ip") or row.get("ip"),
                username=str(user.get("name"))[:255] if user.get("name") else None,
                first_seen=occurred,
                last_seen=occurred,
                event_count=1,
                run_id=str(raw.get("run_id"))[:64] if raw.get("run_id") else None,
                scenario_id=str(raw.get("scenario_id"))[:64] if raw.get("scenario_id") else None,
                topology_id=str(raw.get("topology_id"))[:64] if raw.get("topology_id") else None,
                incident_id=incident_id,
                status="shadow" if context == "lab" else "active",
            ))
        else:
            existing.last_seen = max(existing.last_seen, occurred)
            existing.event_count = int(existing.event_count or 0) + 1
            existing.sensor = str(raw.get("sensor") or existing.sensor or "kraken")[:32]
            existing.context = context
            existing.src_ip = network.get("src_ip") or existing.src_ip
            if user.get("name"):
                existing.username = str(user.get("name"))[:255]
            if incident_id:
                existing.incident_id = incident_id
            if context == "lab":
                existing.status = "shadow"
        touched += 1
    await db.flush()
    return touched


async def _ensure_kraken_incident(db: AsyncSession, events: List[Dict[str, Any]],
                                  alert_ids: List[int]) -> Optional[int]:
    """Attach the new alerts to one open incident, creating the timeline row.

    The alert is the detection; the incident is what the SOC timeline reads.
    Grouping by session (or event id when the sensor omits it) avoids creating
    a new incident for every command in the same attack.
    """
    if not alert_ids:
        return None
    first = events[0]
    raw = first.get("raw") if isinstance(first.get("raw"), dict) else {}
    network = first.get("network") if isinstance(first.get("network"), dict) else {}
    session = raw.get("session_id") or first.get("event_id")
    source_ip = network.get("src_ip") or "unknown"
    title = f"[KRAKEN] {session} from {source_ip}"[:255]

    existing = await db.execute(
        select(Incident).where(
            Incident.title == title,
            Incident.status.in_(("open", "investigating")),
        )
    )
    incident = existing.scalars().first()
    if incident is None:
        ranks = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        severity = max(
            (str(e.get("severity") or "MEDIUM").upper() for e in events),
            key=lambda s: ranks.get(s, 0),
        )
        incident = Incident(
            title=title,
            severity=severity if severity in ranks and severity != "INFO" else "MEDIUM",
            status="open",
            agent_id="kraken",
        )
        db.add(incident)
        await db.flush()

    for alert_id in sorted(set(alert_ids)):
        linked = await db.execute(
            select(IncidentAlert).where(
                IncidentAlert.incident_id == incident.id,
                IncidentAlert.alert_id == alert_id,
            )
        )
        if linked.scalars().first() is None:
            db.add(IncidentAlert(incident_id=incident.id, alert_id=alert_id))
    await db.commit()
    return incident.id


@router.post("/kraken")
@limiter.limit("300/minute", key_func=_ingest_rate_key)
async def ingest_kraken_event(
    request: Request,
    db: AsyncSession = Depends(get_db),
    auth=Depends(ingest_auth),
):
    """Ingest the signed Kraken contract and turn it into an Aegis timeline.

    This route is deliberately before `/{source}`: otherwise the generic
    dynamic route would swallow `/kraken` and bypass the HMAC check.
    """
    if not settings.KRAKEN_INGEST_ENABLED:
        raise HTTPException(status_code=503, detail="Kraken ingestion is disabled")
    secret = (settings.KRAKEN_INGEST_SECRET or "").strip()
    if len(secret) < 32:
        raise HTTPException(status_code=503, detail="Kraken ingestion secret is not configured")
    if not _kraken_allowed(auth):
        raise HTTPException(status_code=403, detail="Kraken requires source=kraken and scope kraken:write")

    raw_body = await request.body()
    if len(raw_body) > settings.KRAKEN_INGEST_MAX_BYTES:
        raise HTTPException(status_code=413, detail="Kraken payload too large")
    signature = (request.headers.get("X-Kraken-Signature") or "").strip()
    if signature.lower().startswith("sha256="):
        signature = signature[7:]
    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    if not signature or not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=401, detail="Invalid Kraken HMAC signature")

    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="Kraken payload must be JSON")
    rows = payload.get("events") if isinstance(payload, dict) else None
    if not isinstance(rows, list) or not rows:
        raise HTTPException(status_code=422, detail="Kraken payload must contain events")
    if len(rows) > settings.KRAKEN_INGEST_MAX_EVENTS:
        raise HTTPException(status_code=422, detail="too many Kraken events")

    cutoff = datetime.now(timezone.utc) - timedelta(days=7)
    for row in rows:
        if not isinstance(row, dict):
            raise HTTPException(status_code=422, detail="each Kraken event must be an object")
        occurred = parse_timestamp(row.get("occurred_at") or row.get("time"))
        if occurred < cutoff:
            raise HTTPException(status_code=422, detail="Kraken event older than 7 days")

    result = await ingest_payload(db, "kraken", payload, parser="kraken")
    if not result.get("accepted"):
        raise HTTPException(status_code=422, detail={
            "message": "no Kraken event could be parsed",
            "errors": result.get("errors"),
        })

    incident_id = await _ensure_kraken_incident(db, rows, result.get("alert_ids") or [])
    sessions = await _upsert_deception_sessions(db, rows, incident_id)
    await db.commit()
    return {"status": "ok", **result, "incident_id": incident_id,
            "deception_sessions": sessions}


@router.post("/{source}")
@limiter.limit("600/minute", key_func=_ingest_rate_key)
async def ingest_event(
    source: str,
    request: Request,
    payload: Any = Body(...),
    db: AsyncSession = Depends(get_db),
    auth=Depends(ingest_auth),
    parser: Optional[str] = Query(None, description="Forza il parser (default: nome sorgente o auto)"),
):
    """Ingerisce uno o più eventi per la sorgente indicata.

    `source` è il nome della sorgente (libero) oppure il nome di un parser.
    Con `parser` si forza esplicitamente il formato; senza, si usa il nome
    sorgente se è un parser noto, altrimenti auto-detection.
    """
    if not settings.SIEM_ENABLED:
        raise HTTPException(status_code=503, detail="SIEM ingestion is disabled")
    if auth.get("kind") == "api_key" and not source_allowed(auth, source):
        raise HTTPException(
            status_code=403,
            detail=f"API key {auth.get('name')!r} is not allowed to write source {source!r}",
        )
    if source == "auto" and parser is None:
        parser = "auto"
    result = await ingest_payload(db, source, payload, parser=parser)
    if not result.get("accepted"):
        # Payload arrivato ma nessun evento riconosciuto: 422 con la diagnosi,
        # così l'integratore capisce subito e non pensa a un problema di rete.
        # Un 200 silenzioso qui è il modo in cui una sorgente resta rotta per
        # settimane senza che nessuno se ne accorga.
        raise HTTPException(status_code=422, detail={
            "message": "payload received but no event could be parsed",
            "source": source,
            "parser": result.get("parser"),
            "unparsed": result.get("unparsed"),
            "errors": result.get("errors"),
        })
    if not result.get("stored") and not result.get("duplicates"):
        # Eventi riconosciuti ma non salvati: è un guasto dello store, non un
        # problema del payload. Dichiararlo evita di far credere all'integratore
        # che il formato sia sbagliato.
        raise HTTPException(status_code=503, detail={
            "message": "events parsed but store failed",
            "source": source,
            "accepted": result.get("accepted"),
        })
    return result

