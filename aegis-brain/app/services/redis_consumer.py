import json
import asyncio
import uuid
import redis.asyncio as redis
from datetime import datetime, timezone
from app.core.config import settings
from app.core.logging import get_logger
from app.core.redis_utils import get_redis_url
from app.database.connection import AsyncSessionLocal
from app.database.models import Agent, Alert, Telemetry
from app.api.schemas.common import EventSchema
from app.rules.heuristic_engine import HeuristicEngine
from app.rules.correlation_engine import correlation_engine
from app.services.anomaly_engine import anomaly_engine
from app.core.metrics import inc, observe_hist, set_gauge
from sqlalchemy import select

logger = get_logger(__name__)

PROCESSING_LIST = "aegis:events:processing"
DLQ_LIST = "aegis:events:dlq"
DLQ_MAX = 10000
REQUEUE_MAX = 5000

class RedisConsumer:
    def __init__(self):
        self._running = False
        self._engine = HeuristicEngine()
        self._client = redis.from_url(get_redis_url(), decode_responses=True)

    async def start(self):
        self._running = True
        logger.info("Async RedisConsumer started on queue 'aegis:events'")
        # Audit: al boot si ricodano gli eventi rimasti in processing da un
        # crash precedente (altrimenti persi per sempre).
        await self._requeue_processing()
        while self._running:
            try:
                # BRPOPLPUSH atomico: l'evento resta in processing finche'
                # non e' confermato (niente piu' rimozione-prima-di-processare).
                raw_json = await self._client.brpoplpush("aegis:events", PROCESSING_LIST, timeout=2)
                if raw_json:
                    ok = await self._process_raw(raw_json)
                    if ok:
                        await self._client.lrem(PROCESSING_LIST, 1, raw_json)
                    else:
                        await self._to_dlq(raw_json)
            except redis.ConnectionError as e:
                logger.error(f"Redis connection lost: {e}")
                await asyncio.sleep(5)
            except Exception as e:
                logger.exception(f"Error in consumer loop: {e}")

    async def _requeue_processing(self) -> int:
        """Rimette in coda gli eventi orfani in processing (crash recovery)."""
        moved = 0
        try:
            while moved < REQUEUE_MAX:
                item = await self._client.rpoplpush(PROCESSING_LIST, "aegis:events")
                if item is None:
                    break
                moved += 1
        except Exception as e:
            logger.error(f"Requeue processing failed: {e}")
        if moved:
            logger.warning(f"Requeued {moved} orphan events from {PROCESSING_LIST}")
        return moved

    async def _to_dlq(self, raw_json: str) -> None:
        try:
            await self._client.lpush(DLQ_LIST, raw_json)
            await self._client.ltrim(DLQ_LIST, 0, DLQ_MAX - 1)
            inc("aegis_events_dlq_total", 1)
        except Exception as e:
            logger.error(f"DLQ push failed: {e}")

    def stop(self):
        self._running = False

    async def _process_raw(self, raw_data):
        import time as _time
        _t0 = _time.perf_counter()
        try:
            data = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
            event = EventSchema.model_validate(data)

            async with AsyncSessionLocal() as db:
                # 1. Update Agent Status
                await self._update_agent(db, event)

                # 2. Process by Type
                if event.event_type == "PROCESS_CREATED":
                    await self._process_security_event(db, event)

                elif event.event_type in ("FILE_MODIFIED", "YARA_MATCH"):
                    await self._process_file_event(db, event)

                elif event.event_type in ["METRICS_REPORT", "AGENT_HEARTBEAT"]:
                    await self._process_telemetry(db, event)

                # 3. Process Correlation (for all events)
                await correlation_engine.analyze(event, db)

                await db.commit()
            observe_hist("aegis_detection_latency_seconds", _time.perf_counter() - _t0)
            depth = await self._client.llen("aegis:events")
            set_gauge("aegis_queue_depth", depth, 'stage="redis"')
            return True
        except Exception as e:
            inc("aegis_events_lost_total", 1, 'reason="consumer_error"')
            logger.error(f"Processing error: {e}")
            return False

    def _get_agent_uuid(self, agent_id_str: str) -> uuid.UUID:
        try:
            return uuid.UUID(agent_id_str)
        except ValueError:
            # Generate deterministic UUID for network devices or custom string IDs
            return uuid.uuid5(uuid.NAMESPACE_DNS, agent_id_str)

    async def _process_file_event(self, db, event: EventSchema):
        """FILE_MODIFIED (FIM) e YARA_MATCH: delega al servizio condiviso.

        La logica (alert MITRE + evento SIEM) vive in
        app.services.file_event_service ed e' la stessa usata dalla pipeline
        `report` degli agenti: una sola implementazione, due pipeline.
        """
        from app.services.file_event_service import handle_file_event

        await handle_file_event(db, event)

    async def _update_agent(self, db, event: EventSchema):
        agent_id_uuid = self._get_agent_uuid(event.agent_id)

        result = await db.execute(select(Agent).where(Agent.agent_id == agent_id_uuid))
        agent = result.scalars().first()
        if agent:
            agent.last_seen = datetime.now(timezone.utc)
            if event.hostname: agent.hostname = event.hostname
            if event.ip_address: agent.ip_address = event.ip_address
            db.add(agent)

    async def _process_security_event(self, db, event: EventSchema):
        agent_id_uuid = self._get_agent_uuid(event.agent_id)

        analysis = await self._engine.analyze(event, db)
        if analysis.is_threat:
            alert = Alert(
                agent_id=agent_id_uuid,
                severity=analysis.severity,
                pid=event.pid,
                parent_pid=event.parent_pid,
                parent_process_name=event.parent_process_name,
                process_name=event.process_name or "unknown",
                process_path=event.process_path,
                event_type=event.event_type,
                description=analysis.description,
                mitre_tactic_name=analysis.mitre_tactic,
                mitre_technique_name=analysis.mitre_technique,
                mitre_technique_id=analysis.mitre_technique_id,
            )
            db.add(alert)
            await db.flush()
            logger.warning(f"THREAT DETECTED on {event.agent_id}: {analysis.description}")

            asyncio.ensure_future(self._enrich_alert_async(alert.id))
            
            if analysis.auto_remediation:
                await self._execute_auto_remediation(db, alert, analysis, event)

    async def _execute_auto_remediation(self, db, alert, analysis, event):
        from app.database.models import RemediationAction
        import datetime
        action = analysis.auto_remediation
        logger.warning(f"[AUTO-REMEDIATION] Executing '{action}' for alert {alert.id} on agent {event.agent_id}")
        remediation = RemediationAction(
            alert_id=alert.id,
            agent_id=self._get_agent_uuid(event.agent_id),
            action=action,
            target=event.process_name or event.ip_address or 'unknown',
            status='executed',
            executed_at=datetime.datetime.now(datetime.timezone.utc)
        )
        db.add(remediation)
        if action == 'kill_process' and event.pid:
            # MAI os.kill qui: questo è il SERVER, il PID vive sull'AGENTE.
            # (Prima: os.kill(event.pid) uccideva un processo casuale del server
            # con lo stesso PID — bug pericoloso.) Si accoda il comando.
            try:
                from app.services.telemetry_service import send_command_to_agent
                await send_command_to_agent(event.agent_id, {
                    "command": "KILL_PROCESS",
                    "pid": event.pid,
                    "process_name": event.process_name,
                    "alert_id": alert.id,
                })
                logger.info(f"[AUTO-REMEDIATION] KILL_PROCESS queued for PID {event.pid} on {event.agent_id}")
            except Exception as e:
                logger.warning(f"[AUTO-REMEDIATION] queue failed: {e}")
                remediation.status = 'failed'

    async def _process_telemetry(self, db, event: EventSchema):
        agent_id_uuid = self._get_agent_uuid(event.agent_id)

        # Store Telemetry
        if event.cpu_usage is not None or event.ram_usage is not None:
            telemetry = Telemetry(
                device_id=agent_id_uuid,
                cpu_usage=event.cpu_usage,
                ram_usage=event.ram_usage,
                disk_free=event.disk_free,
                disk_total=event.disk_total,
                network_sent=event.network_sent,
                network_received=event.network_received,
                processes={"list": event.processes} if event.processes else None
            )
            db.add(telemetry)

            # Statistical Anomaly Detection
            metrics = {}
            if event.cpu_usage is not None: metrics["cpu_usage"] = event.cpu_usage
            if event.ram_usage is not None: metrics["ram_usage"] = event.ram_usage
            
            anomalies = await anomaly_engine.analyze(event.agent_id, metrics)
            for anomaly in anomalies:
                alert = Alert(
                    agent_id=agent_id_uuid,
                    severity=anomaly["severity"],
                    process_name="System",
                    event_type="statistical_anomaly",
                    description=f"Anomaly in {anomaly['metric']}: {anomaly['value']} (z={anomaly['z_score']:.1f})"
                )
                db.add(alert)

    async def _enrich_alert_async(self, alert_id: int):
        try:
            from app.services.alert_enrichment import enrich_alert
            await enrich_alert(alert_id)
        except Exception as e:
            logger.error(f"Alert enrichment failed for {alert_id}: {e}")
