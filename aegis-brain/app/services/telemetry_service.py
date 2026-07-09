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
        top_proc = "unknown"
        processes = data.get("processes", [])
        if isinstance(processes, list) and processes:
            try:
                normalized = []
                for p in processes:
                    if isinstance(p, dict):
                        normalized.append(p)
                    elif isinstance(p, str) and '(' in p:
                        name = p.split('(')[0].strip()
                        try: pid = int(p.split('(')[1].rstrip(')'))
                        except: pid = 0
                        normalized.append({"name": name, "pid": pid, "cpu_percent": 0})
                
                metric_key = anomaly["metric"]
                cpu_keys = ["cpu_percent", "cpu_usage", "cpu", "percent"]
                ram_keys = ["memory_percent", "ram_usage", "memory_percent", "mem_usage", "ram", "memory"]
                keys_to_check = cpu_keys if "cpu" in metric_key else ram_keys
                def get_proc_score(p):
                    for k in keys_to_check:
                        v = p.get(k)
                        if v is not None:
                            try: return float(v)
                            except: pass
                    return 0
                sorted_procs = sorted(
                    [p for p in normalized if get_proc_score(p) > 0],
                    key=get_proc_score, reverse=True
                )
                if sorted_procs:
                    top_proc = sorted_procs[0].get("name") or sorted_procs[0].get("process_name") or "unknown"
                elif normalized:
                    top_proc = normalized[0].get("name") or "unknown"
            except Exception:
                pass
        alert = Alert(
            agent_id=agent_id,
            severity=anomaly["severity"],
            process_name=top_proc,
            event_type="statistical_anomaly",
            description=(
                f"Suspicious {anomaly['metric'].replace('_', ' ').title()} spike "
                f"(z-score={anomaly['z_score']:.1f}, threshold=4.0) "
                f"on process '{top_proc}': "
                f"current={anomaly['value']:.1f}% — "
                f"significantly above normal baseline. "
            )
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
                            description=f"Rule '{rule.name}' matched: {field}='{value}' matched pattern /{pattern}/",
                            mitre_tactic_id=rule.mitre_tactic_id or rule.mitre_tactic,
                            mitre_technique_id=rule.mitre_technique_id or rule.mitre_technique,
                            mitre_tactic_name=rule.mitre_tactic,
                            mitre_technique_name=rule.mitre_technique,
                        )
                        db.add(alert)
                        logger.info(f"Custom rule '{rule.name}' triggered for agent {agent_id} on process '{proc_name}'")
                        break  # one alert per rule per telemetry batch

    # 4. Static Heuristic Rule Matching (for PROCESS_CREATED events)
    event_type = data.get("event_type") or data.get("eventType") or ""
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
                            pid=event.pid,
                            parent_pid=event.parent_pid,
                            parent_process_name=event.parent_process_name,
                            process_name=event.process_name or "unknown",
                            process_path=event.process_path,
                            event_type=event.event_type,
                            description=rule_result.description,
                            mitre_tactic_id=rule_result.mitre_tactic_id or rule_result.mitre_tactic,
                            mitre_technique_id=rule_result.mitre_technique_id,
                            mitre_tactic_name=rule_result.mitre_tactic,
                            mitre_technique_name=rule_result.mitre_technique,
                        )
                        db.add(alert)
                        logger.warning(f"THREAT DETECTED on {agent_id}: {rule_result.description}")
                        break
                except Exception as e:
                    logger.error("Error in static rule '%s': %s", rule.__name__, str(e))
        except Exception as e:
            logger.error("Failed to process static rules for event: %s", str(e))

    await db.commit()

    # Trigger SOAR playbooks on newly created alerts (best-effort)
    try:
        from app.services.playbook_engine import check_and_execute_playbooks
        alert_result = await db.execute(
            select(Alert).where(Alert.agent_id == agent_id).order_by(Alert.timestamp.desc()).limit(5)
        )
        for alert in alert_result.scalars().all():
            await check_and_execute_playbooks(db, alert)
    except Exception:
        logger.exception("SOAR playbook execution failed")

    # Immediate enrichment (OSINT + AI) for newly created alerts
    try:
        from app.services.alert_enrichment import enrich_alert
        alert_result = await db.execute(
            select(Alert).where(Alert.agent_id == agent_id).order_by(Alert.timestamp.desc()).limit(5)
        )
        for alert in alert_result.scalars().all():
            await enrich_alert(alert.id)
    except Exception:
        logger.exception("Alert enrichment failed")


async def send_command_to_agent(agent_id: Any, command: Dict[str, Any]):
    queue_name = f"aegis:commands:{str(agent_id)}"
    await redis_client.lpush(queue_name, json.dumps(command))
    await redis_client.ltrim(queue_name, 0, 99)
