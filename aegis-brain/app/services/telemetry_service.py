import json
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone
from app.database.models import Telemetry, Alert, Agent
from app.core.logging import get_logger
import redis.asyncio as redis
from app.core.config import settings
from app.services.anomaly_engine import anomaly_engine

logger = get_logger(__name__)
redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)


async def process_telemetry(db: AsyncSession, agent_id: Any, data: Dict[str, Any]):
    # 1. Store raw telemetry
    telemetry = Telemetry(
        device_id=agent_id,
        cpu_usage=data.get("cpu_usage"),
        ram_usage=data.get("ram_usage"),
        disk_free=data.get("disk_free"),
        disk_total=data.get("disk_total"),
        network_sent=data.get("network_sent"),
        network_received=data.get("network_received"),
        processes={"list": data.get("processes")} if isinstance(data.get("processes"), list) else data.get("processes"),
        ip_local=data.get("ip_local"),
        ip_public=data.get("ip_public"),
        geo_country=data.get("geo_country"),
        geo_city=data.get("geo_city")
    )
    db.add(telemetry)

    # 1.b Update or create Agent record so UI list and stats remain consistent
    try:
        result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
        agent = result.scalars().first()
        now = datetime.now(timezone.utc)
        if agent:
            agent.last_seen = now
            # update optional metadata if provided
            if data.get("hostname"):
                agent.hostname = data.get("hostname")
            if data.get("ip_address"):
                agent.ip_address = data.get("ip_address")
            if data.get("os") or data.get("os_type"):
                agent.os_type = data.get("os") or data.get("os_type")
        else:
            # create a minimal agent record (assume nodetrace if not otherwise specified)
            agent = Agent(
                agent_id=agent_id,
                hostname=data.get("hostname") or None,
                ip_address=data.get("ip_address") or None,
                os_type=data.get("os") or data.get("os_type") or None,
                agent_type=data.get("agent_type") or "nodetrace",
                last_seen=now
            )
            db.add(agent)
    except Exception:
        # Keep telemetry processing robust; log but continue
        logger.exception("Failed to update/create Agent record during telemetry processing")

    # 2. Statistical Anomaly Detection
    metrics = {}
    if data.get("cpu_usage") is not None:
        metrics["cpu_usage"] = data.get("cpu_usage")
    if data.get("ram_usage") is not None:
        metrics["ram_usage"] = data.get("ram_usage")
    anomalies = anomaly_engine.analyze(str(agent_id), metrics)

    for anomaly in anomalies:
        alert = Alert(
            agent_id=agent_id,
            severity=anomaly["severity"],
            process_name="System",
            event_type="statistical_anomaly",
            description=f"Anomaly detected in {anomaly['metric']}: value={anomaly['value']} (z-score={anomaly['z_score']:.2f})"
        )
        db.add(alert)

    await db.commit()


async def send_command_to_agent(agent_id: Any, command: Dict[str, Any]):
    queue_name = f"aegis:commands:{str(agent_id)}"
    await redis_client.lpush(queue_name, json.dumps(command))
    await redis_client.ltrim(queue_name, 0, 99)
