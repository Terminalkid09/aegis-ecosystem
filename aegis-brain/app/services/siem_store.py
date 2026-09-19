"""Store e query degli eventi normalizzati.

Responsabilità:
- inserimento in blocco con dedup per `event_id`,
- gestione delle partizioni mensili (su PostgreSQL partizionato),
- query filtrabile e statistiche per la dashboard,
- registro delle sorgenti (contatori, ultimo evento, ultimo errore).

Il dedup sta in Redis e non in un vincolo UNIQUE: su una tabella partizionata
la chiave unica dovrebbe contenere la chiave di partizione, e comunque un
`INSERT ... ON CONFLICT` per ogni riga costerebbe più di un SETNX. Redis ha
già l'infrastruttura e il TTL che serve.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

import redis.asyncio as redis_lib
import sqlalchemy as sa
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.logging import get_logger
from app.core.redaction import strip_control_chars
from app.database.models import LogSource, SiemEvent
from app.ingest.base import UnifiedEvent

logger = get_logger(__name__)

rc = redis_lib.from_url(settings.REDIS_URL, decode_responses=True)

# Un solo tentativo di gestione partizioni per processo: la verifica costa una
# query di catalogo, non va fatta a ogni insert.
_partitions_ready = False
PARTITION_LOOKAHEAD_MONTHS = 2

# Colonne che la ricerca libera e i filtri possono toccare (allowlist esplicita:
# nessun nome di colonna arriva mai dal client).
FILTERABLE_FIELDS = frozenset({
    "source", "source_type", "severity", "hostname", "ip", "user", "src_ip",
    "dst_ip", "src_port", "dst_port", "protocol", "process_name", "file_name",
    "file_path", "domain", "dns_query", "signature", "signature_id", "category",
    "message_id", "url", "http_method", "http_status", "event_id",
})


# ─── partizioni ──────────────────────────────────────────────────────────────

def _month_start(moment: datetime) -> datetime:
    return moment.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _next_month(moment: datetime) -> datetime:
    return (_month_start(moment) + timedelta(days=32)).replace(day=1)


async def ensure_monthly_partitions(db: AsyncSession, months_ahead: int = PARTITION_LOOKAHEAD_MONTHS) -> int:
    """Crea le partizioni dei prossimi mesi se la tabella è partizionata.

    No-op (e non un errore) su tabella piatta o su dialetti non-PostgreSQL:
    l'applicazione non dipende dalla partizione.
    """
    global _partitions_ready
    if _partitions_ready:
        return 0
    try:
        kind = await db.scalar(sa.text(
            "SELECT relkind FROM pg_class WHERE relname = 'siem_events'"))
    except Exception:
        _partitions_ready = True
        return 0
    if kind != "p":
        _partitions_ready = True
        return 0
    created = 0
    moment = _month_start(datetime.now(timezone.utc))
    for _ in range(max(1, months_ahead) + 1):
        name = f"siem_events_{moment:%Y_%m}"
        try:
            await db.execute(sa.text(
                f"CREATE TABLE IF NOT EXISTS {name} PARTITION OF siem_events "
                f"FOR VALUES FROM ('{moment:%Y-%m-%d}') TO ('{_next_month(moment):%Y-%m-%d}')"))
            created += 1
        except Exception as exc:  # permessi/DDL non disponibili: si continua
            logger.warning(f"Partizione {name} non creata: {exc}")
            break
        moment = _next_month(moment)
    _partitions_ready = True
    return created


async def drop_old_partitions(db: AsyncSession, retention_days: int = 0) -> List[str]:
    """Retention per partizione: DROP invece di DELETE (istantaneo, senza WAL).

    Restituisce i nomi delle partizioni eliminate.
    """
    days = retention_days or settings.SIEM_RETENTION_DAYS
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    try:
        rows = await db.execute(sa.text(
            "SELECT child.relname FROM pg_inherits "
            "JOIN pg_class parent ON pg_inherits.inhparent = parent.oid "
            "JOIN pg_class child ON pg_inherits.inhrelid = child.oid "
            "WHERE parent.relname = 'siem_events' AND child.relname LIKE 'siem_events_2%'"))
    except Exception:
        return []
    dropped: List[str] = []
    for (name,) in rows.all():
        suffix = name.replace("siem_events_", "")
        try:
            partition_start = datetime.strptime(suffix, "%Y_%m").replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        if _next_month(partition_start) <= cutoff:
            await db.execute(sa.text(f"DROP TABLE IF EXISTS {name}"))
            dropped.append(name)
    return dropped


# ─── dedup ───────────────────────────────────────────────────────────────────

async def claim_event(event_id: str) -> bool:
    """True se l'evento è nuovo (dedup atomica). Fail-open su Redis assente.

    Fail-open è deliberato: un blip di Redis non deve far perdere telemetria.
    Il costo di un raro duplicato è un alert in più, non un evento perso.
    """
    if not event_id:
        return True
    try:
        claimed = await rc.set(f"siem:evt:{event_id}", "1",
                               ex=settings.SIEM_EVENT_DEDUP_TTL_S, nx=True)
        return bool(claimed)
    except Exception:
        return True


# ─── inserimento ─────────────────────────────────────────────────────────────

def _strip_structure(value: Any, changed: List[bool]) -> Any:
    """Rimuove i caratteri di controllo non memorizzabili da una riga.

    Vale per `extra` (JSON) oltre che per i campi testuali: anche un campo
    jsonb rifiuta \\u0000 nella stringa.
    """
    if isinstance(value, str):
        cleaned = strip_control_chars(value)
        if cleaned != value:
            changed[0] = True
        return cleaned
    if isinstance(value, dict):
        return {k: _strip_structure(v, changed) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_strip_structure(v, changed) for v in value]
    return value


def event_to_row(event: UnifiedEvent) -> Dict[str, Any]:
    row = {
        "time": event.time,
        "source": event.source,
        "source_type": event.source_type,
        "event_id": event.event_id,
        "severity": event.severity,
        "ocsf_class_uid": event.ocsf_class_uid,
        "hostname": event.hostname,
        "ip": event.ip,
        "user": event.user,
        "user_domain": event.user_domain,
        "process_name": event.process_name,
        "pid": event.pid,
        "parent_process_name": event.parent_process_name,
        "parent_pid": event.parent_pid,
        "process_path": event.process_path,
        "command_line": event.command_line,
        "file_path": event.file_path,
        "file_name": event.file_name,
        "file_hash": event.file_hash,
        "src_ip": event.src_ip,
        "src_port": event.src_port,
        "dst_ip": event.dst_ip,
        "dst_port": event.dst_port,
        "protocol": event.protocol,
        "url": event.url,
        "http_method": event.http_method,
        "http_status": event.http_status,
        "user_agent": event.user_agent,
        "domain": event.domain,
        "dns_query": event.dns_query,
        "signature": event.signature,
        "signature_id": event.signature_id,
        "category": event.category,
        "message": event.message,
        "message_id": event.message_id,
        "search_text": event.searchable_text()[:4000],
        "extra": event.extra or None,
    }
    # Perché qui e non nel parser: `store_events` inserisce TUTTE le righe con
    # un solo INSERT, quindi una riga che il database rifiuta (NUL in una
    # colonna text) faceva fallire l'intero blocco — e un log sorgente con
    # qualche byte binario dentro è la norma, non l'eccezione. Risultato
    # osservato: `store failed`, cioè centinaia di righe di log perse per un
    # carattere. Si ripulisce la riga e la perdita si DICHIARA nel log.
    changed = [False]
    clean = {k: _strip_structure(v, changed) for k, v in row.items()}
    if changed[0]:
        logger.warning("Evento da %s ripulito da caratteri di controllo "
                       "non memorizzabili (event_id=%s)",
                       event.source, event.event_id or "assente")
    return clean


async def store_events(db: AsyncSession, events: Sequence[UnifiedEvent]) -> int:
    """Inserisce eventi in blocco. Ritorna il numero di righe scritte."""
    if not events:
        return 0
    await ensure_monthly_partitions(db)
    rows = [event_to_row(e) for e in events]
    await db.execute(sa.insert(SiemEvent), rows)
    return len(rows)


# ─── registro sorgenti ───────────────────────────────────────────────────────

async def upsert_source(db: AsyncSession, name: str, source_type: str,
                        parser: str, description: Optional[str] = None) -> LogSource:
    result = await db.execute(select(LogSource).where(LogSource.name == name))
    source = result.scalars().first()
    if source is None:
        source = LogSource(name=name, source_type=source_type, parser=parser,
                           description=description)
        db.add(source)
        await db.flush()
    else:
        source.source_type = source_type
        source.parser = parser
        if description:
            source.description = description
    return source


async def record_source_result(db: AsyncSession, name: str, *, accepted: int,
                               invalid: int = 0, error: Optional[str] = None) -> None:
    """Aggiorna i contatori della sorgente. Non solleva mai: la statistica non
    deve far fallire l'ingestione che sta registrando."""
    try:
        result = await db.execute(select(LogSource).where(LogSource.name == name))
        source = result.scalars().first()
        if source is None:
            return
        source.events_total = (source.events_total or 0) + accepted
        source.events_invalid = (source.events_invalid or 0) + invalid
        if accepted:
            source.last_event_at = datetime.now(timezone.utc)
        source.last_error = (error or "")[:2000] or source.last_error
        if not error:
            source.last_error = None
    except Exception as exc:
        logger.warning(f"Statistiche sorgente {name} non aggiornate: {exc}")


async def list_sources(db: AsyncSession) -> List[Dict[str, Any]]:
    result = await db.execute(select(LogSource).order_by(LogSource.name))
    out = []
    for source in result.scalars().all():
        out.append({
            "id": source.id,
            "name": source.name,
            "source_type": source.source_type,
            "parser": source.parser,
            "description": source.description,
            "enabled": source.enabled,
            "events_total": source.events_total,
            "events_invalid": source.events_invalid,
            "last_event_at": source.last_event_at.isoformat() if source.last_event_at else None,
            "last_error": source.last_error,
            "created_at": source.created_at.isoformat() if source.created_at else None,
        })
    return out


# ─── query ───────────────────────────────────────────────────────────────────

def apply_filters(stmt, filters: Dict[str, Any]):
    """Applica i filtri ammessi. I campi sconosciuti vengono ignorati."""
    for field, value in (filters or {}).items():
        if value in (None, "", []):
            continue
        if field not in FILTERABLE_FIELDS:
            continue
        column = getattr(SiemEvent, field)
        if isinstance(value, (list, tuple, set)):
            stmt = stmt.where(column.in_(list(value)[:50]))
        else:
            stmt = stmt.where(column == value)
    return stmt


async def query_events(db: AsyncSession, *, since: Optional[datetime] = None,
                       until: Optional[datetime] = None,
                       text: Optional[str] = None,
                       filters: Optional[Dict[str, Any]] = None,
                       limit: int = 100, offset: int = 0,
                       order: str = "desc") -> Dict[str, Any]:
    """Ricerca eventi. `text` è una ricerca libera su `search_text`/message."""
    limit = max(1, min(int(limit), settings.SIEM_SEARCH_MAX_LIMIT))
    stmt = select(SiemEvent)
    count_stmt = select(func.count(SiemEvent.id))
    conditions = []
    if since:
        conditions.append(SiemEvent.time >= since)
    if until:
        conditions.append(SiemEvent.time <= until)
    if text:
        # LIKE con escape: `%` e `_` dell'utente non devono diventare wildcard.
        escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = f"%{escaped}%"
        conditions.append(or_(
            SiemEvent.search_text.ilike(pattern, escape="\\"),
            SiemEvent.message.ilike(pattern, escape="\\"),
        ))
    stmt = stmt.where(*conditions) if conditions else stmt
    count_stmt = count_stmt.where(*conditions) if conditions else count_stmt
    stmt = apply_filters(stmt, filters or {})
    count_stmt = apply_filters(count_stmt, filters or {})
    stmt = stmt.order_by(SiemEvent.time.asc() if order == "asc" else SiemEvent.time.desc())
    stmt = stmt.offset(max(0, offset)).limit(limit)

    total = await db.scalar(count_stmt) or 0
    result = await db.execute(stmt)
    return {
        "total": int(total),
        "limit": limit,
        "offset": max(0, offset),
        "items": [_row_out(row) for row in result.scalars().all()],
    }


def _row_out(row: SiemEvent) -> Dict[str, Any]:
    return {
        "id": row.id,
        "time": row.time.isoformat() if row.time else None,
        "source": row.source,
        "source_type": row.source_type,
        "event_id": row.event_id,
        "severity": row.severity,
        "ocsf_class_uid": row.ocsf_class_uid,
        "hostname": row.hostname,
        "user": row.user,
        "user_domain": row.user_domain,
        "src_ip": row.src_ip,
        "src_port": row.src_port,
        "dst_ip": row.dst_ip,
        "dst_port": row.dst_port,
        "protocol": row.protocol,
        "process_name": row.process_name,
        "pid": row.pid,
        "parent_process_name": row.parent_process_name,
        "process_path": row.process_path,
        "command_line": row.command_line,
        "file_path": row.file_path,
        "file_name": row.file_name,
        "file_hash": row.file_hash,
        "url": row.url,
        "http_method": row.http_method,
        "http_status": row.http_status,
        "user_agent": row.user_agent,
        "domain": row.domain,
        "dns_query": row.dns_query,
        "signature": row.signature,
        "signature_id": row.signature_id,
        "category": row.category,
        "message_id": row.message_id,
        "message": row.message,
        "extra": row.extra,
    }


async def event_stats(db: AsyncSession, hours: int = 24) -> Dict[str, Any]:
    """Statistiche per la dashboard: EPS, distribuzione per sorgente/severità."""
    since = datetime.now(timezone.utc) - timedelta(hours=max(1, hours))
    total = await db.scalar(select(func.count(SiemEvent.id)).where(SiemEvent.time >= since)) or 0
    by_severity = await db.execute(
        select(SiemEvent.severity, func.count(SiemEvent.id))
        .where(SiemEvent.time >= since).group_by(SiemEvent.severity))
    by_source = await db.execute(
        select(SiemEvent.source, func.count(SiemEvent.id))
        .where(SiemEvent.time >= since)
        .group_by(SiemEvent.source).order_by(func.count(SiemEvent.id).desc()).limit(20))
    by_source_type = await db.execute(
        select(SiemEvent.source_type, func.count(SiemEvent.id))
        .where(SiemEvent.time >= since).group_by(SiemEvent.source_type))
    top_hosts = await db.execute(
        select(SiemEvent.src_ip, func.count(SiemEvent.id))
        .where(SiemEvent.time >= since, SiemEvent.src_ip.is_not(None))
        .group_by(SiemEvent.src_ip).order_by(func.count(SiemEvent.id).desc()).limit(10))
    window_seconds = max(1, hours) * 3600
    return {
        "window_hours": hours,
        "total": int(total),
        "events_per_second": round(total / window_seconds, 4),
        "by_severity": {sev or "INFO": int(count) for sev, count in by_severity.all()},
        "by_source": [{"source": s, "count": int(c)} for s, c in by_source.all()],
        "by_source_type": {t or "unknown": int(c) for t, c in by_source_type.all()},
        "top_src_ips": [{"ip": ip, "count": int(c)} for ip, c in top_hosts.all()],
    }


async def purge_expired(db: AsyncSession, retention_days: int = 0) -> Dict[str, Any]:
    """Retention: DROP partizioni vecchie + DELETE di sicurezza sulle flat table."""
    days = retention_days or settings.SIEM_RETENTION_DAYS
    dropped = await drop_old_partitions(db, days)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    deleted = 0
    if not dropped:
        # Tabella piatta (o partizioni non ancora oltre soglia): DELETE bounded.
        result = await db.execute(
            sa.delete(SiemEvent).where(SiemEvent.time < cutoff))
        deleted = result.rowcount or 0
    return {"retention_days": days, "partitions_dropped": dropped, "rows_deleted": deleted}
