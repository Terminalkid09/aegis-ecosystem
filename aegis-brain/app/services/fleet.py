"""Flotta SOC: siti, stato agent e retention (M7 Fase 8). Migration-free.

- Siti/gruppi: dentro Agent.meta JSON ({"site": "hq", "group": "..."});
  nessuna nuova tabella, filtro post-query documentato.
- Stato: online/stale/offline da last_seen (soglie configurabili).
- Retention: cutoff puri + statement DELETE compilabili (wiring scheduler
  in Fase 9, qui solo perimetro verificabile senza DB).
"""
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

SITE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
DEFAULT_SITE = "default"

ONLINE = "online"
STALE = "stale"
OFFLINE = "offline"
UNKNOWN = "unknown"


def normalize_site(site: Any) -> str:
    """Valida un nome sito (minuscolo, dns-safe). Lancia ValueError se no."""
    s = str(site or "").strip().lower()
    if not SITE_RE.match(s):
        raise ValueError(
            "site non valido: minuscolo, [a-z0-9-], max 64 char")
    return s


def get_site(agent: Any) -> str:
    """Sito dell'agente da meta JSON, default se assente/malformato."""
    try:
        meta = agent.meta if not isinstance(agent, dict) else agent.get("meta")
        if isinstance(meta, dict):
            site = str(meta.get("site") or "").strip().lower()
            if SITE_RE.match(site):
                return site
    except (AttributeError, TypeError):
        pass
    return DEFAULT_SITE


def set_site_meta(meta: Any, site: str) -> Dict:
    """Nuovo meta con sito validato (non muta l'input)."""
    clean = normalize_site(site)
    base = dict(meta) if isinstance(meta, dict) else {}
    base["site"] = clean
    return base


def agent_status(last_seen: Any, now: Optional[datetime] = None,
                 online_min: int = 15, offline_h: int = 24) -> str:
    """online (<15m) / stale / offline (>24h) / unknown (mai visto)."""
    if last_seen is None:
        return UNKNOWN
    try:
        if isinstance(last_seen, str):
            last_seen = datetime.fromisoformat(last_seen)
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        now = now or datetime.now(timezone.utc)
        age = (now - last_seen).total_seconds()
    except (ValueError, TypeError, AttributeError):
        return UNKNOWN
    if age < 0:
        return ONLINE  # clock skew futuro: non punire l'agente
    if age < online_min * 60:
        return ONLINE
    if age < offline_h * 3600:
        return STALE
    return OFFLINE


def retention_cutoffs(telemetry_days: int = 14, alerts_days: int = 90,
                      audit_days: int = 365, syslog_days: int = 30,
                      now: Optional[datetime] = None) -> Dict[str, datetime]:
    """Cutoff puri: tutto ciò che è più vecchio va purgato."""
    now = now or datetime.now(timezone.utc)
    for v in (telemetry_days, alerts_days, audit_days, syslog_days):
        if int(v) <= 0:
            raise ValueError("retention days deve essere positivo")
    return {
        "telemetry": now - timedelta(days=telemetry_days),
        "alerts": now - timedelta(days=alerts_days),
        "audit": now - timedelta(days=audit_days),
        "syslog": now - timedelta(days=syslog_days),
    }


def purge_statements(cutoffs: Dict[str, datetime]):
    """Statement DELETE per tabella (compilabili senza DB, wiring Fase 9)."""
    from sqlalchemy import delete
    from app.database.models import Telemetry, Alert, AuditLog, SyslogEvent
    return [
        ("telemetry", delete(Telemetry).where(Telemetry.timestamp < cutoffs["telemetry"])),
        ("alerts", delete(Alert).where(Alert.timestamp < cutoffs["alerts"])),
        ("audit", delete(AuditLog).where(AuditLog.created_at < cutoffs["audit"])),
        ("syslog", delete(SyslogEvent).where(SyslogEvent.timestamp < cutoffs["syslog"])),
    ]
