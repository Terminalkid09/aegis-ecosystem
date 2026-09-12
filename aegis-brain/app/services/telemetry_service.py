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
from app.rules.rule_definitions import ALL_RULES, stamp_result, is_canary_rule
import redis.asyncio as redis
from app.core.config import settings
from app.services.anomaly_engine import anomaly_engine

logger = get_logger(__name__)
redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)

# Dedup alert: stessa (agent, regola, processo) una volta ogni ora.
# Senza, ogni batch di telemetria ricrea gli stessi alert (FP storm che
# seppellisce il SOC). Fail-open se Redis è giù.
ALERT_SUPPRESS_TTL = 3600


async def _suppressed(agent_id: Any, key: str) -> bool:
    cache_key = f"sup:alert:{agent_id}:{key}"
    try:
        if await redis_client.exists(cache_key):
            return True
        await redis_client.setex(cache_key, ALERT_SUPPRESS_TTL, "1")
        return False
    except Exception:
        return False


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
                if data.get("agent_version"):
                    agent.agent_version = str(data.get("agent_version"))[:50]
                if isinstance(data.get("capabilities"), (dict, list)):
                    agent.capabilities = data.get("capabilities")
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
                f"(z-score={anomaly['z_score']:.1f}, threshold={anomaly.get('threshold', 3.0):.1f}) "
                f"on process '{top_proc}': "
                f"current={anomaly['value']:.1f}% — "
                f"significantly above normal baseline. "
            )
        )
        if await _suppressed(agent_id, f"anomaly:{anomaly['metric']}:{top_proc}"):
            logger.debug(f"Anomaly alert suppressed (cooldown): {anomaly['metric']} on {top_proc}")
        else:
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
                        rule.trigger_count = (rule.trigger_count or 0) + 1
                        rule.last_triggered = datetime.now(timezone.utc)
                        if await _suppressed(agent_id, f"custom:{rule.id}:{proc_name}"):
                            logger.debug(f"Custom rule '{rule.name}' suppressed (cooldown) on '{proc_name}'")
                            break
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
    if event_type == "CONNECTION_ESTABLISHED":
        # Eventi connessione dal sensore eBPF/ETW: solo beacon correlation
        # (niente statiche/custom: servono process_name+path). Fail-open.
        try:
            from app.rules.correlation_engine import correlation_engine as _ce
            conns = data.get("network_connections") or []
            if data.get("remote") and not conns:
                conns = [{"remote": data["remote"], "state": "ESTABLISHED"}]
            if conns:
                ping = EventSchema(
                    agent_id=str(agent_id), timestamp=datetime.now(timezone.utc),
                    event_type="CONNECTION_ESTABLISHED",
                    process_name=data.get("process_name") or data.get("comm") or "unknown",
                    network_connections=conns,
                )
                try:
                    await _ce.analyze(ping, db)
                except Exception:
                    pass
        except Exception:
            pass
        await db.commit()
        return
    if event_type == "PROCESS_CREATED":
        try:
            event = EventSchema(**data)
            triggered_rules = []
            # Contesto arricchente (signature, prevalence, first_seen) prima di pesare i trigger.
            # Best-effort: mai blocca la detection se il DB è down.
            ctx = {}
            try:
                from app.services.detection_context import fetch_context, is_trusted_signed
                ctx = await fetch_context(db, event)
            except Exception:
                ctx = {}
                from app.services.detection_context import is_trusted_signed
            else:
                from app.services.detection_context import is_trusted_signed

            # Regole rumorose che si sopprimono se il binario è firmato trusted
            # (riduce FP su System32, updater, ecc. senza perdere i veri attack tool).
            TRUSTED_SUPPRESS = {"AEGIS-S009", "AEGIS-S010", "AEGIS-S012", "AEGIS-S014"}
            trusted = is_trusted_signed(event)

            for rule in ALL_RULES:
                try:
                    rule_result = rule(event)
                    if rule_result.triggered:
                        stamp_result(rule, rule_result)
                        # Abbassa confidence se firmato trusted (evidence separata dalla severity).
                        if trusted and rule_result.rule_id in TRUSTED_SUPPRESS:
                            rule_result.confidence = "low"
                            # Non sopprime i CRITICAL/high, ma marca low confidence
                            # e lascia al SOC il triage con evidence.
                        if is_canary_rule(rule_result.rule_id):
                            # Canary: log-only, MAI alert (rollout sicuro).
                            logger.warning(
                                "CANARY %s v%s avrebbe allertato su %s (%s)",
                                rule_result.rule_id, rule_result.version,
                                event.process_name, rule_result.description[:160])
                        else:
                            triggered_rules.append(rule_result)
                except Exception as e:
                    logger.error("Error in static rule '%s': %s", rule.__name__, str(e))

            if triggered_rules:
                score_map = {"CRITICAL": 100, "HIGH": 50, "MEDIUM": 25, "LOW": 10}
                total_score = sum(score_map.get(res.severity, 10) for res in triggered_rules)

                if total_score >= 100:
                    overall_severity = "CRITICAL"
                elif total_score >= 50:
                    overall_severity = "HIGH"
                elif total_score >= 25:
                    overall_severity = "MEDIUM"
                else:
                    overall_severity = "LOW"
                # Suppressione per severity massima: un LOW non deve mai
                # nascondere un CRITICAL successivo (buco di detection).
                if await _suppressed(agent_id, f"static:{overall_severity}:{event.process_name}"):
                    logger.debug("Multi-static rule suppressed (cooldown)")
                else:
                        descriptions = " | ".join(res.description for res in triggered_rules)
                        best_res = max(triggered_rules, key=lambda x: score_map.get(x.severity, 10))
                        # Evidence separata da severity/confidence, con reason leggibile
                        try:
                            from app.services.detection_context import build_evidence
                            evidence = build_evidence(event, triggered_rules, ctx)
                            reason = (
                                f"Reason: {best_res.description} | "
                                f"Confidence={best_res.confidence} | "
                                f"TrustedSigned={evidence['identity']['trusted']} | "
                                f"Prevalence={ctx.get('prevalence')} | "
                                f"Lineage={event.parent_process_name}->{event.process_name}"
                            )
                        except Exception:
                            evidence = {}
                            reason = best_res.description

                        alert = Alert(
                            agent_id=agent_id,
                            severity=overall_severity,
                            pid=event.pid,
                            parent_pid=event.parent_pid,
                            parent_process_name=event.parent_process_name,
                            process_name=event.process_name or "unknown",
                            process_path=event.process_path,
                            event_type=event.event_type,
                            description=(f"Multiple indicators ({total_score} score): {descriptions} | {reason}" if len(triggered_rules) > 1 else f"{best_res.description} | {reason}"),
                            mitre_tactic_id=best_res.mitre_tactic_id or best_res.mitre_tactic,
                            mitre_technique_id=best_res.mitre_technique_id,
                            mitre_tactic_name=best_res.mitre_tactic,
                            mitre_technique_name=best_res.mitre_technique,
                        )
                        db.add(alert)
                        logger.warning(f"THREAT DETECTED on {agent_id}: {alert.description} | evidence={evidence}")
        except Exception as e:
            logger.error("Failed to process static rules for event: %s", str(e))

    # 5. Agent-Side Behavioral Tags (from Aegis-Guard) & Anomalies (from NodeTrace)
    BEHAVIORAL_TAG_MITRE = {
        "SUSPICIOUS_SVCHOST_PARENT":      ("HIGH",     "Defense Evasion",      "T1055",  "Process Injection"),
        "OFFICE_SPAWNED_SHELL":           ("CRITICAL", "Execution",            "T1566",  "Phishing / Macro Execution"),
        "SUSPICIOUS_POWERSHELL_ARGS":     ("HIGH",     "Execution",            "T1059.001", "PowerShell"),
        "HIDDEN_OR_BYPASS_EXECUTION":     ("HIGH",     "Defense Evasion",      "T1562",  "Impair Defenses"),
        "CREDENTIAL_DUMPING_TOOL_DETECTED": ("CRITICAL","Credential Access",  "T1003",  "OS Credential Dumping"),
        "POSSIBLE_CRYPTOMINER":           ("HIGH",     "Impact",               "T1496",  "Resource Hijacking"),
        "SUSPICIOUS_LOLBIN_MEMORY":       ("MEDIUM",   "Execution",            "T1218",  "System Binary Proxy Execution"),
        "HIGH_CONNECTION_COUNT_TO_IP":    ("HIGH",     "Command and Control",  "T1071",  "Application Layer Protocol"),
    }

    behavioral_tags = data.get("behavioral_tags") or data.get("behavioralTags") or []
    agent_anomalies = data.get("anomalies") or []

    for tag in behavioral_tags:
        mapping = BEHAVIORAL_TAG_MITRE.get(tag)
        severity, tactic, technique_id, technique_name = mapping if mapping else ("MEDIUM", "Unknown", None, tag)
        sup_key = f"btag:{tag}:{data.get('process_name', 'unknown')}"
        if not await _suppressed(agent_id, sup_key):
            cmd_line = data.get("command_line") or data.get("commandLine") or ""
            alert = Alert(
                agent_id=agent_id,
                severity=severity,
                pid=data.get("pid"),
                parent_pid=data.get("parent_pid"),
                parent_process_name=data.get("parent_process_name"),
                process_name=data.get("process_name") or "unknown",
                process_path=data.get("process_path"),
                event_type="behavioral_detection",
                description=f"[Sensor Heuristic] {tag}: {data.get('process_name','?')} ← {data.get('parent_process_name','?')} | CLI: {cmd_line[:200]}",
                mitre_tactic_name=tactic,
                mitre_technique_id=technique_id,
                mitre_technique_name=technique_name,
            )
            db.add(alert)
            logger.warning("BEHAVIORAL_TAG alert: %s | agent=%s | tag=%s", data.get('process_name'), agent_id, tag)

    for anomaly_str in agent_anomalies:
        tag_key = anomaly_str.split(":")[0].strip()
        mapping = BEHAVIORAL_TAG_MITRE.get(tag_key)
        severity, tactic, technique_id, technique_name = mapping if mapping else ("MEDIUM", "Unknown", None, anomaly_str)
        sup_key = f"anomaly_nt:{anomaly_str[:80]}"
        if not await _suppressed(agent_id, sup_key):
            alert = Alert(
                agent_id=agent_id,
                severity=severity,
                process_name=anomaly_str.split(":")[-1].strip() if ":" in anomaly_str else "unknown",
                event_type="behavioral_detection",
                description=f"[NodeTrace Heuristic] {anomaly_str}",
                mitre_tactic_name=tactic,
                mitre_technique_id=technique_id,
                mitre_technique_name=technique_name,
            )
            db.add(alert)
            logger.warning("NODETRACE_ANOMALY alert: agent=%s | %s", agent_id, anomaly_str)

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

    # Arricchimento (OSINT + AI) FUORI dal request path: qui siamo nel mezzo
    # di un POST /telemetry/report e ogni enrich fa HTTP esterne + LLM
    # (secondi/minuti) — sotto storm di eventi inchioderebbe l'ingestion.
    # Ci pensa il loop _auto_enrich_loop (main.py, ogni 15s) + il consumer
    # Redis (async). Niente sync qui: realtime prima di tutto.


async def send_command_to_agent(agent_id: Any, command: Dict[str, Any]):
    # FIFO: RPUSH + LPOP (was LPUSH + LPOP = LIFO, order reversed).
    # Consistent with deploy.py scan-via-agent (rpush).
    queue_name = f"aegis:commands:{str(agent_id)}"
    await redis_client.rpush(queue_name, json.dumps(command))
    await redis_client.ltrim(queue_name, 0, 99)
