import json
import re
from typing import List, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timezone
from app.database.models import Telemetry, Alert, Agent, CustomRule
from app.core.logging import get_logger
from app.api.schemas.common import EventSchema
from app.rules.heuristic_engine import HeuristicEngine, SEVERITY_WEIGHT
from app.rules.rule_definitions import ALL_RULES
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
        geo_city=data.get("geo_city"),
        users=data.get("users"),
        network_flows=data.get("network_flows")
    )
    db.add(telemetry)

    # 1.b Update or create Agent record so UI list and stats remain consistent
    try:
        result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
        agent = result.scalars().first()
        now = datetime.now(timezone.utc)
        if agent:
            agent.last_seen = now
            if data.get("ip_address"):
                agent.ip_address = data.get("ip_address")
            try:
                agent.hostname = data.get("hostname") or agent.hostname
                agent.os_type = data.get("os") or data.get("os_type") or agent.os_type
                await db.flush()
            except IntegrityError:
                await db.rollback()
                # constraint conflict — just update last_seen to keep agent alive
                result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
                agent = result.scalars().first()
                if agent:
                    agent.last_seen = now
                    if data.get("ip_address"):
                        agent.ip_address = data.get("ip_address")
        else:
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
        logger.exception("Failed to update/create Agent record during telemetry processing")

    # 2. Statistical Anomaly Detection
    metrics = {}
    if data.get("cpu_usage") is not None:
        metrics["cpu_usage"] = data.get("cpu_usage")
    if data.get("ram_usage") is not None:
        metrics["ram_usage"] = data.get("ram_usage")
    anomalies = await anomaly_engine.analyze(str(agent_id), metrics)

    for anomaly in anomalies:
        alert = Alert(
            agent_id=agent_id,
            severity=anomaly["severity"],
            process_name="System",
            event_type="statistical_anomaly",
            description=f"Anomaly detected in {anomaly['metric']}: value={anomaly['value']} (z-score={anomaly['z_score']:.2f})"
        )
        db.add(alert)

    # 3. Custom Rule Matching
    try:
        rules_result = await db.execute(
            select(CustomRule).where(CustomRule.is_active == True)
        )
        custom_rules = rules_result.scalars().all()
    except Exception:
        custom_rules = []

    if custom_rules:
        processes = data.get("processes", [])
        if isinstance(processes, list):
            for rule in custom_rules:
                field = rule.target_field
                pattern = rule.pattern
                try:
                    compiled = re.compile(pattern, re.IGNORECASE)
                except re.error:
                    continue

                # Extract values from each process entry
                for proc in processes:
                    proc_name = proc.get("name") or proc.get("process_name") or ""
                    proc_path = proc.get("path") or proc.get("process_path") or ""
                    values_to_check = {"process_name": proc_name, "process_path": proc_path}

                    value = values_to_check.get(field, "")
                    if value and compiled.search(value):
                        alert = Alert(
                            agent_id=agent_id,
                            severity=rule.severity.upper(),
                            process_name=proc_name or "Unknown",
                            event_type="custom_rule",
                            description=f"Rule '{rule.name}' matched: {field}='{value}' matched pattern /{pattern}/"
                        )
                        db.add(alert)
                        logger.info(f"Custom rule '{rule.name}' triggered for agent {agent_id} on process '{proc_name}'")
                        break  # one alert per rule per telemetry batch

    # 4. Static Heuristic Rule Matching (for PROCESS_CREATED events)
    event_type = data.get("event_type", "")
    if event_type == "PROCESS_CREATED":
        try:
            event = EventSchema(**data)
            for rule in ALL_RULES:
                try:
                    rule_result = rule(event)
                    if rule_result.triggered:
                        alert = Alert(
                            agent_id=agent_id,
                            severity=rule_result.severity,
                            pid=data.get("pid"),
                            process_name=data.get("process_name") or "unknown",
                            process_path=data.get("process_path"),
                            event_type=event_type,
                            description=rule_result.description
                        )
                        db.add(alert)
                        logger.warning(f"THREAT DETECTED on {agent_id}: {rule_result.description}")
                        break
                except Exception as e:
                    logger.error("Error in static rule '%s': %s", rule.__name__, str(e))
        except Exception as e:
            logger.error("Failed to process static rules for event: %s", str(e))

    await db.commit()


async def send_command_to_agent(agent_id: Any, command: Dict[str, Any]):
    queue_name = f"aegis:commands:{str(agent_id)}"
    await redis_client.lpush(queue_name, json.dumps(command))
    await redis_client.ltrim(queue_name, 0, 99)
