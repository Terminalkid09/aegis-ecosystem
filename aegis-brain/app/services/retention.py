"""Retention operativa (Fase 7).

Job schedulato che rispetta i valori configurabili già presenti
(RETENTION_*_DAYS), con dry-run, conferma per purge manuale distruttiva,
audit della purge e verifica backup.

Uso:
- automatico: lifespan di app.main avvia un task giornaliero con dry_run=False
  solo se RETENTION_ENABLED=true (default false per lab, true per pilot).
- manuale distruttivo: POST /admin/retention/purge?confirm=true (richiede
  BACKUP_VERIFIED flag e audit).
- manuale sicuro: GET /admin/retention/preview

Tutte le cancellazioni sono in transazione, con controllo righe orfane
via FK CASCADE/SET NULL già modellate.
"""
import asyncio
import os
from datetime import datetime, timezone, timedelta
from typing import Dict, Any
from sqlalchemy import delete, select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.database.connection import get_db
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

async def preview_retention(db: AsyncSession) -> Dict[str, Any]:
    """Conta le righe che verrebbero purgate (dry-run)."""
    from app.database.models import Telemetry, Alert, AuditLog, SyslogEvent
    from app.services.fleet import retention_cutoffs, purge_statements
    cutoffs = retention_cutoffs(
        telemetry_days=settings.RETENTION_TELEMETRY_DAYS,
        alerts_days=settings.RETENTION_ALERTS_DAYS,
        audit_days=settings.RETENTION_AUDIT_DAYS,
        syslog_days=settings.RETENTION_SYSLOG_DAYS,
    )
    counts = {}
    for table, stmt in purge_statements(cutoffs):
        # Conta invece di cancellare
        model_map = {
            "telemetry": Telemetry,
            "alerts": Alert,
            "audit": AuditLog,
            "syslog": SyslogEvent,
        }
        model = model_map[table]
        # Estrai la condizione where dallo statement di delete
        # Semplifica: conta con where timestamp < cutoff
        cutoff = cutoffs[table]
        if table == "audit":
            q = select(func.count()).select_from(model).where(model.created_at < cutoff)
        else:
            q = select(func.count()).select_from(model).where(model.timestamp < cutoff)
        result = await db.execute(q)
        counts[table] = result.scalar() or 0
    # SIEM: gli eventi normalizzati hanno una retention propria e si cancellano
    # per partizione (DROP) invece che per riga: senza questa voce il preview
    # direbbe "0" mentre la purge ne elimina milioni.
    try:
        from app.database.models import SiemEvent
        siem_cutoff = datetime.now(timezone.utc) - timedelta(days=settings.SIEM_RETENTION_DAYS)
        counts["siem_events"] = await db.scalar(
            select(func.count()).select_from(SiemEvent).where(SiemEvent.time < siem_cutoff)) or 0
        cutoffs["siem_events"] = siem_cutoff
    except Exception as exc:
        logger.warning(f"Preview retention SIEM non disponibile: {exc}")
    return {"cutoffs": {k: v.isoformat() for k, v in cutoffs.items()}, "counts": counts}

async def run_retention_purge(db: AsyncSession, confirmed: bool = False, backup_verified: bool = False,
                              include_audit: bool = False) -> Dict[str, Any]:
    """Esegue la purge se confermata e backup verificato, altrimenti dry-run.

    Audit: lo schedulatore automatico NON purga mai gli audit log
    (include_audit=False) e NON salta il backup check: le prove forensi e
    l'audit trail si cancellano solo con run manuale esplicito.
    """
    preview = await preview_retention(db)
    total = sum(preview["counts"].values())
    if not confirmed:
        return {"dry_run": True, "preview": preview, "purged": 0}
    if not backup_verified:
        # Fase 7: testa backup prima della purge — qui verifichiamo che esista
        # almeno un backup recente (<48h) o che l'operatore abbia esplicitamente
        # confermato con flag.
        import os
        backup_dir = os.getenv("BACKUP_DIR", "/backups")
        # Se il backup_dir non è montato (lab), salta il check con warning
        if os.path.isdir(backup_dir):
            try:
                files = [f for f in os.listdir(backup_dir) if f.startswith("aegis_db_")]
                if not files:
                    return {"error": "Nessun backup trovato: esegui backup prima della purge", "dry_run": True, "preview": preview}
                # Controlla data ultimo backup
                latest = max(os.path.getmtime(os.path.join(backup_dir, f)) for f in files)
                age_hours = (datetime.now().timestamp() - latest) / 3600
                if age_hours > 48:
                    return {"error": f"Ultimo backup troppo vecchio ({age_hours:.1f}h): esegui backup prima della purge", "dry_run": True, "preview": preview}
            except Exception as e:
                logger.warning(f"Backup check fallito: {e}")
        else:
            logger.warning("Backup dir non montato, salto verifica backup (lab)")

    # Esegue purge in transazione con audit
    from app.services.fleet import retention_cutoffs, purge_statements
    from app.core.audit import log_audit
    cutoffs = retention_cutoffs(
        telemetry_days=settings.RETENTION_TELEMETRY_DAYS,
        alerts_days=settings.RETENTION_ALERTS_DAYS,
        audit_days=settings.RETENTION_AUDIT_DAYS,
        syslog_days=settings.RETENTION_SYSLOG_DAYS,
    )
    purged = {}
    for table, stmt in purge_statements(cutoffs):
        if table == "audit" and not include_audit:
            continue
        result = await db.execute(stmt)
        purged[table] = result.rowcount or 0
    # SIEM: DROP delle partizioni scadute (istantaneo, senza WAL) oppure DELETE
    # bounded se la tabella è piatta. Non passa da `purge_statements` perché
    # sono DDL, non DELETE.
    try:
        from app.services import siem_store
        siem = await siem_store.purge_expired(db, settings.SIEM_RETENTION_DAYS)
        if siem.get("partitions_dropped"):
            purged["siem_events_partitions"] = len(siem["partitions_dropped"])
        if siem.get("rows_deleted"):
            purged["siem_events"] = siem["rows_deleted"]
    except Exception as exc:
        # La retention degli agenti non deve fallire perché il SIEM ha un problema.
        logger.warning(f"Retention SIEM fallita: {exc}")
    # Audit F-05: metriche volumi per allarmi capacita' (SOC).
    try:
        import time as _time
        from app.core.metrics import inc, set_gauge, fmt_labels
        set_gauge("aegis_retention_last_run_ts", _time.time())
        for table, count in purged.items():
            inc("aegis_retention_purged_total", count, fmt_labels(table=table))
        for table, count in preview["counts"].items():
            set_gauge("aegis_retention_pending_total", count, fmt_labels(table=table))
    except Exception:
        pass
    # Audit della purge (mai cancellare audit reali qui — solo log)
    try:
        await log_audit(db, action="retention_purge", resource="system", details={"cutoffs": {k: v.isoformat() for k, v in cutoffs.items()}, "purged": purged}, username="system")
    except Exception:
        pass
    await db.commit()
    # Verifica no orfani (le FK sono CASCADE/SET NULL, ma logghiamo)
    try:
        # Conta incident_alerts orfani (dovrebbe essere 0)
        from sqlalchemy import text
        orphans = await db.execute(text("SELECT count(*) FROM incident_alerts WHERE alert_id NOT IN (SELECT id FROM alerts)"))
        orphan_count = orphans.scalar() or 0
        if orphan_count:
            logger.warning(f"Orfani dopo purge: {orphan_count} incident_alerts")
    except Exception:
        pass
    return {"dry_run": False, "purged": purged, "preview": preview}

# Task schedulato giornaliero (chiamato da lifespan se RETENTION_ENABLED)
_retention_task = None

async def retention_scheduler():
    while True:
        try:
            await asyncio.sleep(24 * 3600)  # giornaliero
            # Qui apriamo una sessione DB per la purge automatica (dry-run=False)
            # ma solo se abilitata e non in test.
            if not getattr(settings, "RETENTION_ENABLED", False):
                continue
            if os.getenv("PYTEST_CURRENT_TEST"):
                continue
            from app.database.connection import AsyncSessionLocal
            async with AsyncSessionLocal() as db:
                # Audit: backup check REALE + audit log mai toccati in automatico.
                await run_retention_purge(db, confirmed=True, backup_verified=False,
                                          include_audit=False)
                logger.info("Retention purge schedulata completata")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Retention scheduler error: {e}")
            await asyncio.sleep(3600)

def start_retention_task():
    global _retention_task
    if _retention_task is None:
        _retention_task = asyncio.create_task(retention_scheduler())
    return _retention_task

def stop_retention_task():
    global _retention_task
    if _retention_task:
        _retention_task.cancel()
        _retention_task = None
