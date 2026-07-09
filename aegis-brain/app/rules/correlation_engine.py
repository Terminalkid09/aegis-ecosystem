import json
import uuid
from datetime import datetime, timezone
import redis.asyncio as redis
from app.api.schemas.common import EventSchema
from app.database.models import Alert
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.core.logging import get_logger
from app.core.redis_utils import get_redis_url

logger = get_logger(__name__)

class CorrelationEngine:
    def __init__(self):
        self.redis = redis.from_url(get_redis_url(), decode_responses=True)

    async def analyze(self, event: EventSchema, db: AsyncSession):
        await self._brute_force_detection(event, db)
        await self._process_lineage_alert(event, db)
        await self._beacon_detection(event, db)

    async def _brute_force_detection(self, event: EventSchema, db: AsyncSession):
        if event.event_type == "SYSLOG_NETWORK" and event.file_hash:
            msg = event.file_hash.lower()
            if "failed password" in msg or "authentication failure" in msg:
                key = f"corr:bf:{event.agent_id}"
                count = await self.redis.incr(key)
                if count == 1:
                    await self.redis.expire(key, 60)

                if count >= 5:
                    await self._generate_alert(
                        db,
                        agent_id=event.agent_id,
                        severity="CRITICAL",
                        process_name="syslog_auth",
                        event_type="correlation_bruteforce",
                        description=f"Multiple failed login attempts ({count}) detected within 60 seconds on {event.hostname}."
                    )
                    await self.redis.delete(key)

    async def _process_lineage_alert(self, event: EventSchema, db: AsyncSession):
        """
        Track parent-child process relationships over time.
        If parent was previously flagged as suspicious, escalate child.
        Uses Redis to store recent suspicious parent PIDs.
        """
        if event.event_type != "PROCESS_CREATED":
            return
        if not event.parent_process_name:
            return

        # Check if parent was recently flagged as malicious
        parent_key = f"corr:mal-parent:{event.agent_id}:{event.parent_pid or 'unknown'}"
        was_suspicious = await self.redis.get(parent_key)
        if was_suspicious:
            await self._generate_alert(
                db,
                agent_id=event.agent_id,
                severity="HIGH",
                process_name=event.process_name or "unknown",
                event_type="correlation_lineage",
                description=f"Child process '{event.process_name}' (PID {event.pid}) spawned by previously flagged parent '{event.parent_process_name}' (PID {event.parent_pid}). Possible ongoing compromise."
            )

        # Check for suspicious parent-child combinations dynamically
        parent = (event.parent_process_name or "").lower()
        child = (event.process_name or "").lower()

        # Office/productivity spawning network tools
        office_parents = ["winword.exe", "word.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                          "acrord32.exe", "acrord64.exe", "foxitreader.exe"]
        network_tools = ["curl.exe", "curl", "wget.exe", "wget", "nc.exe", "ncat.exe",
                         "powershell.exe", "powershell", "cmd.exe", "bitsadmin.exe"]

        if any(p in parent for p in office_parents):
            if any(c in child for c in network_tools):
                await self._generate_alert(
                    db,
                    agent_id=event.agent_id,
                    severity="CRITICAL",
                    process_name=event.process_name or "unknown",
                    event_type="correlation_lineage",
                    description=f"Suspicious child process '{event.process_name}' spawned by '{event.parent_process_name}' — possible macro/document exploit."
                )
                # Mark parent as malicious for future child tracking
                parent_key = f"corr:mal-parent:{event.agent_id}:{event.parent_pid or 'unknown'}"
                await self.redis.setex(parent_key, 300, "1")

    async def _beacon_detection(self, event: EventSchema, db: AsyncSession):
        """
        Detect C2 beaconing by tracking processes that connect to the same
        remote IP at regular time intervals.
        Uses Redis sorted set to track connection timestamps per (agent, pid, remote_ip).
        """
        if not event.network_connections:
            return

        now = datetime.now(timezone.utc).timestamp()

        for conn in event.network_connections:
            remote = conn.get("remote", "")
            state = conn.get("state", "")
            if ":" not in remote or state != "ESTABLISHED":
                continue

            host, port = remote.rsplit(":", 1)

            # Skip private IPs
            if _is_private_ip(host):
                continue

            beacon_key = f"corr:beacon:{event.agent_id}:{event.pid or 'unknown'}:{host}"
            try:
                # Add timestamp to sorted set
                await self.redis.zadd(beacon_key, {json.dumps({"ts": now, "port": port}): now})
                # Keep only last 20 entries
                await self.redis.zremrangebyrank(beacon_key, 0, -21)
                # Expire key after 1 hour
                await self.redis.expire(beacon_key, 3600)

                # Check if we have enough data points for beacon analysis
                count = await self.redis.zcard(beacon_key)
                if count >= 5:
                    entries = await self.redis.zrange(beacon_key, 0, -1)
                    timestamps = sorted([json.loads(e)["ts"] for e in entries])

                    if len(timestamps) >= 5:
                        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                        if intervals:
                            avg_interval = sum(intervals) / len(intervals)
                            variance = sum((i - avg_interval)**2 for i in intervals) / len(intervals)

                            # Low variance = regular intervals = beaconing
                            if variance < 5.0 and avg_interval > 0:
                                ports_used = list(set([json.loads(e).get("port", "") for e in entries]))
                                port_str = ",".join(ports_used[:5])

                                await self._generate_alert(
                                    db,
                                    agent_id=event.agent_id,
                                    severity="HIGH",
                                    process_name=event.process_name or "unknown",
                                    event_type="correlation_beacon",
                                    description=f"Potential C2 beacon detected: process '{event.process_name}' (PID {event.pid}) "
                                                f"connecting to {host}:{port_str} every {avg_interval:.1f}s "
                                                f"(variance={variance:.2f}, {count} samples)."
                                )
                                # Reset counter to avoid duplicate alerts
                                await self.redis.delete(beacon_key)
            except Exception as e:
                logger.warning(f"Beacon detection error: {e}")

    async def _generate_alert(self, db: AsyncSession, agent_id: str, severity: str,
                               process_name: str, event_type: str, description: str):
        try:
            agent_id_uuid = uuid.UUID(agent_id)
        except ValueError:
            agent_id_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, agent_id)
        alert = Alert(
            agent_id=agent_id_uuid,
            severity=severity,
            process_name=process_name,
            event_type=event_type,
            description=description
        )
        db.add(alert)
        await db.flush()
        logger.warning(f"CORRELATION ALERT: {description}")

_PRIVATE_RANGES = __import__("re").compile(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|0\.)')
_IPV6_PRIVATE = __import__("re").compile(r'^(::1|fe80:|fc00:|fd00:|fec0:)', __import__("re").IGNORECASE)

def _is_private_ip(ip: str) -> bool:
    if _IPV6_PRIVATE.match(ip):
        return True
    return bool(_PRIVATE_RANGES.match(ip))

correlation_engine = CorrelationEngine()
