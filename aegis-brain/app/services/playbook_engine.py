import json
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timezone
from app.database.models import Playbook, PlaybookAction, PlaybookExecution, Alert, RemediationAction
from app.core.logging import get_logger
import redis.asyncio as redis
from app.core.config import settings

logger = get_logger(__name__)
rc = redis.from_url(settings.REDIS_URL, decode_responses=True)

# M5 Fase 6: ogni automazione dichiara precondizioni operative.
# risk: low|medium|high|critical — approver: ruolo minimo per l'esecuzione
# live — reversible: True se l'effetto si annulla senza danni.
ACTION_RISK = {
    "webhook": {"risk": "low", "approver": "analyst", "reversible": True,
                "preconditions": "reachable https URL"},
    "verify": {"risk": "low", "approver": "analyst", "reversible": True,
               "preconditions": "PID present in the alert"},
    "collect_ioc": {"risk": "low", "approver": "analyst", "reversible": True,
                    "preconditions": "PID present in the alert"},
    "kill_process": {"risk": "high", "approver": "analyst", "reversible": False,
                     "preconditions": "PID present, high confidence"},
    "kill_process_tree": {"risk": "high", "approver": "analyst", "reversible": False,
                          "preconditions": "PID present, high confidence"},
    "quarantine_binary": {"risk": "medium", "approver": "analyst", "reversible": True,
                          "preconditions": "PID present, readable binary",
                          "rollback": "restore from quarantine/ + ACL"},
    "remove_persistence": {"risk": "high", "approver": "analyst", "reversible": False,
                           "preconditions": "persistence evidence present"},
    "dns_sinkhole": {"risk": "medium", "approver": "analyst", "reversible": True,
                      "preconditions": "confirmed malicious domain",
                      "rollback": "remove hosts entry"},
    "block_ip": {"risk": "high", "approver": "analyst", "reversible": True,
                 "preconditions": "IP not in the allowlist",
                 "rollback": "remove firewall rule"},
    "block_ip_temporal": {"risk": "medium", "approver": "analyst", "reversible": True,
                          "preconditions": "IP not in the allowlist",
                          "rollback": "automatic expiry"},
    "isolate_host": {"risk": "critical", "approver": "analyst", "reversible": True,
                     "preconditions": "explicit approval, non-critical host",
                     "rollback": "DEISOLATE_HOST"},
    "deisolate_host": {"risk": "low", "approver": "analyst", "reversible": True,
                       "preconditions": "host is isolated"},
    "release_host": {"risk": "low", "approver": "analyst", "reversible": True,
                     "preconditions": "host is isolated"},
    "update_agent": {"risk": "medium", "approver": "analyst", "reversible": True,
                     "preconditions": "signed artifact published",
                     "rollback": "UPDATE_AGENT to the previous version"},
    "script": {"risk": "critical", "approver": "admin", "reversible": False,
               "preconditions": "admin only, reviewed command, audited"},
    "eradicate": {"risk": "critical", "approver": "analyst", "reversible": False,
                  "preconditions": "chain COLLECT→QUARANTINE→KILL→REMOVE→VERIFY"},
}


def describe_action(action_type: str) -> Dict[str, Any]:
    """Metadati rischio puri (testabili senza DB). Sconosciuto = critical."""
    meta = ACTION_RISK.get((action_type or "").lower())
    if meta is None:
        return {"risk": "critical", "approver": "admin", "reversible": False,
                "preconditions": "tipo azione sconosciuto: revisione manuale"}
    return dict(meta)


async def check_and_execute_playbooks(
    db: AsyncSession,
    alert: Alert,
    triggered_by: Optional[int] = None,
    dry_run: bool = False,
):
    result = await db.execute(
        select(Playbook).where(Playbook.is_active == True)
    )
    playbooks = result.scalars().all()

    for playbook in playbooks:
        if not _matches_trigger(playbook, alert):
            continue

        if dry_run:
            # Dry-run: calcola le azioni che SCATTEREBBERO, zero effetti
            # (niente comandi, niente cooldown, niente remediation).
            actions_q = await db.execute(
                select(PlaybookAction)
                .where(PlaybookAction.playbook_id == playbook.id)
                .order_by(PlaybookAction.order)
            )
            would = [{
                "action_type": pa.action_type, "target": pa.target,
                "params": pa.params, "order": pa.order,
                **describe_action(pa.action_type),
            } for pa in actions_q.scalars().all()]
            execution = PlaybookExecution(
                playbook_id=playbook.id,
                alert_id=alert.id,
                triggered_by=triggered_by,
                status="dry_run",
                result={"dry_run": True, "actions": would},
            )
            db.add(execution)
            await db.flush()
            execution.completed_at = datetime.now(timezone.utc)
            continue

        # Idempotenza per (playbook, alert) — Audit L1.
        # Prima c'era solo un cooldown per-agente di 60s: lo stesso alert non
        # risolto ri-attivava il playbook a ogni ciclo di telemetria una volta
        # scaduto il cooldown, rieseguendo contenimento (kill/isolate/eradicate)
        # su un incidente già gestito. Ora le azioni si eseguono UNA volta per
        # alert, entro una finestra configurabile.
        idem_key = f"playbook:exec:{playbook.id}:{alert.id}"
        try:
            claimed = await rc.set(idem_key, "1", ex=settings.PLAYBOOK_IDEMPOTENCY_TTL_S, nx=True)
        except Exception as exc:
            # Fail-closed sull'automazione: meglio zero esecuzioni che
            # contenimento ripetuto su un host di produzione.
            logger.error("Playbook %s: idempotency store unavailable (%s), skip", playbook.id, exc)
            continue
        if not claimed:
            logger.info("Playbook %s già eseguito per alert %s — skip (idempotente)",
                        playbook.id, alert.id)
            continue

        # Cooldown per-agente: anti-burst quando arrivano più alert NUOVI
        # insieme (non è più la difesa contro le riesecuzioni).
        cooldown_key = f"playbook:cooldown:{playbook.id}:{alert.agent_id}"
        try:
            if await rc.get(cooldown_key):
                logger.info(f"Playbook {playbook.id} for agent {alert.agent_id} is in cooldown. Skipping.")
                continue
            await rc.setex(cooldown_key, 60, "1")
        except Exception:
            # Cooldown non disponibile: l'idempotenza sopra resta la garanzia
            # forte, quindi si procede (fail-open qui, fail-closed là).
            pass

        execution = PlaybookExecution(
            playbook_id=playbook.id,
            alert_id=alert.id,
            triggered_by=triggered_by,
            status="running",
        )
        db.add(execution)
        await db.flush()

        try:
            actions_result = []
            actions_q = await db.execute(
                select(PlaybookAction)
                .where(PlaybookAction.playbook_id == playbook.id)
                .order_by(PlaybookAction.order)
            )
            actions = actions_q.scalars().all()

            for pa in actions:
                result = await _execute_action(db, pa, alert)
                actions_result.append(result)

                rem = RemediationAction(
                    alert_id=alert.id,
                    agent_id=alert.agent_id,
                    action=pa.action_type,
                    target=pa.target,
                    status=result.get("status", "failed"),
                    details=result.get("output", ""),
                )
                db.add(rem)

            execution.status = "completed"
            execution.result = {"actions": actions_result}
        except Exception as e:
            execution.status = "failed"
            execution.result = {"error": str(e)}
            logger.error(f"Playbook {playbook.id} execution failed: {e}")
        finally:
            execution.completed_at = datetime.now(timezone.utc)

    await db.commit()


def _matches_trigger(playbook: Playbook, alert: Alert) -> bool:
    if playbook.trigger_severity and playbook.trigger_severity.upper() != alert.severity.upper():
        return False
    if playbook.trigger_event_type and playbook.trigger_event_type != alert.event_type:
        return False
    if playbook.trigger_process_name and playbook.trigger_process_name.lower() not in (alert.process_name or "").lower():
        return False
    return True


async def _execute_action(
    db: AsyncSession,
    action: PlaybookAction,
    alert: Alert,
) -> Dict[str, Any]:
    action_type = action.action_type
    target = action.target
    params = action.params or {}

    if action_type == "webhook":
        import httpx
        try:
            payload = {
                "alert_id": alert.id,
                "severity": alert.severity,
                "process_name": alert.process_name,
                "description": alert.description,
                **params,
            }
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(target, json=payload)
                return {"status": "completed" if resp.is_success else "failed", "output": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"status": "failed", "output": str(e)}

    elif action_type == "block_ip":
        return await _send_agent_command(alert.agent_id, {
            "command": "BLOCK_IP",
            "ip": target,
            "alert_id": alert.id,
        })

    elif action_type in ("kill_process", "kill_process_tree"):
        if alert.pid:
            cmd = "KILL_PROCESS_TREE" if action_type == "kill_process_tree" else "KILL_PROCESS"
            return await _send_agent_command(alert.agent_id, {
                "command": cmd,
                "pid": alert.pid,
                "process_name": alert.process_name,
                "alert_id": alert.id,
            })
        return {"status": "failed", "output": "No PID available"}

    elif action_type == "block_ip_temporal":
        return await _send_agent_command(alert.agent_id, {
            "command": "BLOCK_IP_TEMPORAL",
            "ip": target,
            "duration_seconds": int(params.get("duration_seconds", 3600)),
            "alert_id": alert.id,
        })

    elif action_type == "isolate_host":
        return await _send_agent_command(alert.agent_id, {
            "command": "ISOLATE_HOST",
            "alert_id": alert.id,
        })

    elif action_type in ("deisolate_host", "release_host"):
        return await _send_agent_command(alert.agent_id, {
            "command": "DEISOLATE_HOST",
            "alert_id": alert.id,
        })

    elif action_type == "update_agent":
        # target = "aegis-guard" | "nodetrace" (default nodetrace), params.version
        from app.api.v1.deploy import (
            artifact_name_for, build_update_command, sha256_file, sign_artifact,
        )
        from app.core.config import settings as _settings
        from pathlib import Path as _Path
        version = str(params.get("version", "latest"))
        atype = "aegis-guard" if "guard" in str(target).lower() else "nodetrace"
        fname = artifact_name_for(atype, version)
        path = _Path(_settings.ARTIFACT_DIR) / fname
        if not path.is_file():
            return {"status": "failed", "output": f"Artifact {fname} not published"}
        digest = sha256_file(path)
        cmd = build_update_command(atype, version, _settings.PUBLIC_BASE_URL,
                                   digest, sign_artifact(digest))
        cmd["alert_id"] = alert.id
        return await _send_agent_command(alert.agent_id, cmd)

    elif action_type == "script":
        # DANGER: arbitrary shell on the BRAIN server. Gated at API layer
        # (admin-only + feature flag, see playbooks.py) AND here at execution
        # (defense in depth: righe scritte prima del flag o a mano nel DB).
        from app.core.config import settings as _settings
        if not _settings.PLAYBOOK_SCRIPT_ENABLED:
            logger.warning("Playbook 'script' blocked: PLAYBOOK_SCRIPT_ENABLED=false")
            return {"status": "blocked", "output": "script actions disabled"}
        import subprocess
        try:
            result = subprocess.run(
                target.split(),
                capture_output=True,
                text=True,
                timeout=min(int(params.get("timeout", 30)), 120),
            )
            return {
                "status": "completed" if result.returncode == 0 else "failed",
                "output": (result.stdout or result.stderr)[:4000],
            }
        except Exception as e:
            return {"status": "failed", "output": str(e)[:500]}

    elif action_type == "quarantine_binary":
        if alert.pid:
            return await _send_agent_command(alert.agent_id, {
                "command": "QUARANTINE_BINARY",
                "pid": alert.pid,
                "process_name": alert.process_name,
                "alert_id": alert.id,
            })
        return {"status": "failed", "output": "No PID available"}

    elif action_type == "remove_persistence":
        return await _send_agent_command(alert.agent_id, {
            "command": "REMOVE_PERSISTENCE",
            "process_name": alert.process_name,
            "alert_id": alert.id,
        })

    elif action_type == "verify":
        if alert.pid:
            return await _send_agent_command(alert.agent_id, {
                "command": "VERIFY",
                "pid": alert.pid,
                "alert_id": alert.id,
            })
        return {"status": "failed", "output": "No PID available"}

    elif action_type == "dns_sinkhole":
        return await _send_agent_command(alert.agent_id, {
            "command": "DNS_SINKHOLE",
            "domain": target,
            "alert_id": alert.id,
        })

    elif action_type == "collect_ioc":
        if alert.pid:
            return await _send_agent_command(alert.agent_id, {
                "command": "COLLECT_IOC",
                "pid": alert.pid,
                "process_name": alert.process_name,
                "alert_id": alert.id,
            })
        return {"status": "failed", "output": "No PID available"}

    elif action_type == "eradicate":
        results = []
        if alert.pid:
            results.append(await _send_agent_command(alert.agent_id, {
                "command": "COLLECT_IOC", "pid": alert.pid,
                "process_name": alert.process_name, "alert_id": alert.id,
            }))
        if alert.pid:
            results.append(await _send_agent_command(alert.agent_id, {
                "command": "QUARANTINE_BINARY", "pid": alert.pid,
                "process_name": alert.process_name, "alert_id": alert.id,
            }))
        if alert.pid:
            results.append(await _send_agent_command(alert.agent_id, {
                "command": "KILL_PROCESS_TREE", "pid": alert.pid,
                "process_name": alert.process_name, "alert_id": alert.id,
            }))
        results.append(await _send_agent_command(alert.agent_id, {
            "command": "REMOVE_PERSISTENCE",
            "process_name": alert.process_name, "alert_id": alert.id,
        }))
        if alert.pid:
            results.append(await _send_agent_command(alert.agent_id, {
                "command": "VERIFY", "pid": alert.pid, "alert_id": alert.id,
            }))
        return {"status": "completed", "output": "Eradication chain executed", "chain": results}

    return {"status": "failed", "output": f"Unknown action type: {action_type}"}


async def _send_agent_command(agent_id, command: Dict[str, Any]):
    import json
    queue_name = f"aegis:commands:{str(agent_id)}"
    try:
        # FIFO: RPUSH + LPOP (was LPUSH = LIFO, order reversed vs telemetry).
        await rc.rpush(queue_name, json.dumps(command))
        await rc.ltrim(queue_name, 0, 99)
    except Exception as e:
        logger.warning(f"Command queue unavailable for {agent_id}: {e}")
        return {"status": "failed", "output": f"Queue unavailable: {command.get('command')}"}
    return {"status": "completed", "output": f"Command queued: {command.get('command')}"}
