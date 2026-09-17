"""Servizio condiviso per eventi file (FIM) e match YARA.

Esiste perché la stessa logica di alerting doveva valere per DUE pipeline
distinte: gli eventi `report` diretti degli agenti (telemetry_service) e gli
eventi batch che arrivano dal gateway di ingestione (redis_consumer). Prima
viveva solo nel consumer: gli eventi FIM/YARA degli agenti reali cadevano
nel vuoto (nessun alert, nessun evento SIEM) senza che nessuno se ne
accorgesse. La duplicazione silenziosa di logica tra pipeline è esattamente
il tipo di bug che non si vede nell'unit test ma solo end-to-end.

MITRE per FIM dipende dal percorso: Run keys/tasks/services -> Persistence
(T1547/T1543), tutto il resto -> T1565.001 (Stored Data Manipulation, il più
vicino onesto per modifiche file generiche). I match YARA sono HIGH.
"""

from __future__ import annotations

import time
import uuid

from app.core.logging import get_logger
from app.database.models import Alert
from app.api.schemas.common import EventSchema
from app.services.ocsf import severity_to_ocsf
from app.services import siem_store
from app.ingest.base import UnifiedEvent

logger = get_logger(__name__)

# Soglie: FILE_MODIFIED è rumore di fondo normale su endpoint monitorati;
# senza rate-limit un ransomware (o un builder) genererebbe una tempesta di
# alert identici. Il tetto protegge il SOC, non nasconde i dati: gli eventi
# restano nel SIEM store, sono solo gli ALERT a essere limitati.
FIM_ALERTS_PER_MINUTE = 60
YARA_ALERTS_PER_MINUTE = 30


class _RateWindow:
    """Finestra fissa 60s, in-process (per-worker, sufficiente qui)."""

    def __init__(self) -> None:
        self.window_start: float | None = None
        self.counts = {"fim": 0, "yara": 0}

    def allow(self, kind: str) -> bool:
        now = time.time()
        if self.window_start is None or now - self.window_start >= 60:
            self.window_start = now
            self.counts = {"fim": 0, "yara": 0}
        limit = FIM_ALERTS_PER_MINUTE if kind == "fim" else YARA_ALERTS_PER_MINUTE
        if self.counts.get(kind, 0) >= limit:
            return False
        self.counts[kind] = self.counts.get(kind, 0) + 1
        return True


_rate = _RateWindow()


def classify_fim_mitre(path: str) -> tuple[str, str, str]:
    """(tactic_name, technique_id, technique_name) per un percorso FIM."""
    low = path.lower()
    if any(k in low for k in ("\\tasks", "currentversion\\run", "startup", "/cron.", "/systemd/", "/rc")):
        return "Persistence", "T1547", "Boot or Logon Autostart Execution"
    if any(k in low for k in ("\\services", "/etc/init.d", "systemd")):
        return "Persistence", "T1543", "Create or Modify System Process"
    return "Impact", "T1565.001", "Stored Data Manipulation"


async def handle_file_event(db, event: EventSchema) -> None:
    """Alert MITRE statico + evento normalizzato nel SIEM store.

    Chiamato da telemetry_service (pipeline `report` agenti) e da
    redis_consumer (pipeline batch del gateway). Non committa: la transazione
    la possiede il chiamante.
    """
    kind = "yara" if event.event_type == "YARA_MATCH" else "fim"

    agent_id_str = str(event.agent_id)
    try:
        agent_uuid = uuid.UUID(agent_id_str)
    except ValueError:
        agent_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, agent_id_str)

    raw = (event.command_line or "").strip()
    path = raw.replace("[FIM] ", "").strip() or (event.process_name or "?")
    # Guard invia "[FIM] <change>: <path>": separo il verbo dal percorso,
    # altrimenti finisce duplicato nella descrizione ("modified: modified:").
    change = "modified"
    for kw in ("created", "modified", "deleted"):
        prefix = f"{kw}: "
        if path.lower().startswith(prefix):
            change = kw
            path = path[len(prefix):].strip()
            break

    if kind == "yara":
        alert = Alert(
            agent_id=agent_uuid,
            severity="HIGH",
            process_name=event.process_name,  # nome della regola YARA
            event_type="yara_match",
            description=f"YARA match '{event.process_name}': {path}",
            mitre_tactic_name="Execution",
            mitre_technique_id="T1204",
            mitre_technique_name="User Execution",
        )
    else:
        tactic, tech_id, tech_name = classify_fim_mitre(path)
        alert = Alert(
            agent_id=agent_uuid,
            severity="MEDIUM",
            event_type="fim_file_change",
            description=f"FIM: file {change}: {path}",
            process_name=event.process_name or "file",
            mitre_tactic_name=tactic,
            mitre_technique_id=tech_id,
            mitre_technique_name=tech_name,
        )

    if not _rate.allow(kind):
        logger.debug("Rate-limit alert %s su %s (evento comunque in SIEM store)", kind, path)
    else:
        db.add(alert)

    # Evento nel SIEM store (ricercabile in Log Search, OCSF File Activity).
    # Sempre, anche se l'alert è stato rate-limitato.
    try:
        unified = UnifiedEvent(
            time=event.timestamp,
            source=f"agent:{event.agent_id}",
            source_type="agent_file",
            event_id=event.event_id or uuid.uuid5(
                uuid.NAMESPACE_DNS, f"{event.agent_id}:{event.timestamp}:{path}"
            ),
            ocsf_class_uid=1001,
            severity="NOTICE" if kind == "fim" else "HIGH",
            hostname=event.hostname,
            user=event.user,
            process_name=event.process_name,
            file_path=path if kind == "fim" else path.split("-> ")[-1],
            file_hash=event.file_hash,
            command_line=event.command_line,
        )
        unified.severity_id = severity_to_ocsf(unified.severity)
        await siem_store.store_events(db, [unified])
    except Exception:
        logger.exception("SIEM store evento file fallito")
