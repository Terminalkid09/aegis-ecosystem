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

async def check_and_execute_playbooks(
    db: AsyncSession,
    alert: Alert,
    triggered_by: Optional[int] = None,
):
    result = await db.execute(
        select(Playbook).where(Playbook.is_active == True)
    )
    playbooks = result.scalars().all()

    for playbook in playbooks:
        if not _matches_trigger(playbook, alert):
            continue

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

    elif action_type == "script":
        import subprocess
        try:
            result = subprocess.run(
                target.split(),
                capture_output=True,
                text=True,
                timeout=int(params.get("timeout", 30)),
            )
            return {
                "status": "completed" if result.returncode == 0 else "failed",
                "output": result.stdout or result.stderr,
            }
        except Exception as e:
            return {"status": "failed", "output": str(e)}

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
    await rc.lpush(queue_name, json.dumps(command))
    await rc.ltrim(queue_name, 0, 99)
    return {"status": "completed", "output": f"Command queued: {command.get('command')}"}
