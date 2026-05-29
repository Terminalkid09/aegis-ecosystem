import json
import asyncio
import uuid
import redis.asyncio as redis
from datetime import datetime, timezone
from app.core.config import settings
from app.core.logging import get_logger
from app.database.connection import AsyncSessionLocal
from app.database.models import Agent, Alert, Telemetry
from app.api.schemas.common import EventSchema
from app.rules.heuristic_engine import HeuristicEngine
from app.services.anomaly_engine import anomaly_engine
from sqlalchemy import select

logger = get_logger(__name__)

class RedisConsumer:
    def __init__(self):
        self._running = False
        self._engine = HeuristicEngine()
        self._client = redis.from_url(settings.REDIS_URL, decode_responses=True)

    async def start(self):
        self._running = True
        logger.info("Async RedisConsumer started on queue 'aegis:events'")
        while self._running:
            try:
                # BRPOP returns (key, value)
                result = await self._client.brpop("aegis:events", timeout=2)
                if result:
                    _, raw_json = result
                    await self._process_raw(raw_json)
            except redis.ConnectionError as e:
                logger.error(f"Redis connection lost: {e}")
                await asyncio.sleep(5)
            except Exception as e:
                logger.exception(f"Error in consumer loop: {e}")

    def stop(self):
        self._running = False

    async def _process_raw(self, raw_data):
        try:
            data = json.loads(raw_data) if isinstance(raw_data, str) else raw_data
            event = EventSchema.model_validate(data)
            
            async with AsyncSessionLocal() as db:
                # 1. Update Agent Status
                await self._update_agent(db, event)
                
                # 2. Process by Type
                if event.event_type == "PROCESS_CREATED":
                    await self._process_security_event(db, event)
                
                elif event.event_type in ["METRICS_REPORT", "AGENT_HEARTBEAT"]:
                    await self._process_telemetry(db, event)

                await db.commit()
        except Exception as e:
            logger.error(f"Processing error: {e}")

    async def _update_agent(self, db, event: EventSchema):
        try:
            agent_id_uuid = uuid.UUID(event.agent_id)
        except ValueError:
            logger.error(f"Invalid Agent ID format in event: {event.agent_id}")
            return

        result = await db.execute(select(Agent).where(Agent.agent_id == agent_id_uuid))
        agent = result.scalars().first()
        if agent:
            agent.last_seen = datetime.now(timezone.utc)
            if event.hostname: agent.hostname = event.hostname
            if event.ip_address: agent.ip_address = event.ip_address
            db.add(agent)

    async def _process_security_event(self, db, event: EventSchema):
        try:
            agent_id_uuid = uuid.UUID(event.agent_id)
        except ValueError:
            return

        analysis = self._engine.analyze(event)
        if analysis.is_threat:
            alert = Alert(
                agent_id=agent_id_uuid,
                severity=analysis.severity,
                pid=event.pid,
                process_name=event.process_name or "unknown",
                process_path=event.process_path,
                event_type=event.event_type,
                description=analysis.description
            )
            db.add(alert)
            logger.warning(f"THREAT DETECTED on {event.agent_id}: {analysis.description}")

    async def _process_telemetry(self, db, event: EventSchema):
        try:
            agent_id_uuid = uuid.UUID(event.agent_id)
        except ValueError:
            return

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
            
            anomalies = anomaly_engine.analyze(event.agent_id, metrics)
            for anomaly in anomalies:
                alert = Alert(
                    agent_id=agent_id_uuid,
                    severity=anomaly["severity"],
                    process_name="System",
                    event_type="statistical_anomaly",
                    description=f"Anomaly in {anomaly['metric']}: {anomaly['value']} (z={anomaly['z_score']:.1f})"
                )
                db.add(alert)
