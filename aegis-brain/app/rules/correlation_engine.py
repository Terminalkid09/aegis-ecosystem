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
# Audit: unica implementazione (quella di correlation era IPv6, quella statica
# IPv4-only: ora entrambe usano questa, IPv4+IPv6).
from app.rules.rule_definitions import _is_private_ip, SUSPICIOUS_PARENT_CHILD

logger = get_logger(__name__)

class CorrelationEngine:
    def __init__(self):
        self.redis = redis.from_url(get_redis_url(), decode_responses=True)

    async def analyze(self, event: EventSchema, db: AsyncSession):
        # Fail-open: se Redis è giù, la correlazione salta ma l'evento
        # è già stato processato dalle regole statiche (niente 500 a cascata).
        try:
            await self._brute_force_detection(event, db)
            await self._process_lineage_alert(event, db)
            await self._beacon_detection(event, db)
        except Exception as e:
            logger.warning(f"Correlation engine skipped (redis down?): {e}")

    async def _brute_force_detection(self, event: EventSchema, db: AsyncSession):
        # Audit: il messaggio di autenticazione NON e' mai stato in file_hash
        # (hash = identita' file, max 64 char) e nessun producer emette
        # SYSLOG_NETWORK. Si legge il testo libero (command_line) e si
        # chiave per (agent, user).
        if event.event_type == "SYSLOG_NETWORK" or (
                event.process_name or "").lower() in {"sshd", "sshd.exe", "winlogon.exe"}:
            msg = (event.command_line or "").lower()
            if "failed password" in msg or "authentication failure" in msg:
                user = (event.user or "unknown").lower().strip() or "unknown"
                key = f"corr:bf:{event.agent_id}:{user}"
                window = settings.CORR_BRUTEFORCE_WINDOW_S
                threshold = settings.CORR_BRUTEFORCE_THRESHOLD
                count = await self.redis.incr(key)
                if count == 1:
                    await self.redis.expire(key, window)

                if count >= threshold:
                    await self._generate_alert(
                        db,
                        agent_id=event.agent_id,
                        severity="CRITICAL",
                        process_name="syslog_auth",
                        event_type="correlation_bruteforce",
                        description=f"Multiple failed login attempts ({count}) detected within {window} seconds on {event.hostname}."
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

        # Check for suspicious parent-child combinations (stem matching,
        # non substring: "mywordviewer" non deve matchare "word").
        def _stem(n: str) -> str:
            b = (n or "").lower().strip().replace("\\", "/").rsplit("/", 1)[-1]
            for ext in (".exe", ".com", ".dll"):
                if b.endswith(ext):
                    b = b[: -len(ext)]
                    break
            return b

        parent = _stem(event.parent_process_name)
        child = _stem(event.process_name)

        # Audit: stesse coppie della regola statica S002 (prima divergevano:
        # winword->wscript veniva perso in correlazione). Derivate da
        # SUSPICIOUS_PARENT_CHILD invece di liste parallele.
        watched: set[tuple[str, str]] = set()
        for parents, children, *_rest in SUSPICIOUS_PARENT_CHILD:
            for p in parents:
                for c in children:
                    watched.add((_stem(p), _stem(c)))

        if (parent, child) in watched:
            # Cooldown: stesso (agent,parent,child) una volta ogni finestra,
            # altrimenti ogni evento del figlio rifà l'alert (FP storm).
            cool = f"corr:lineage-sent:{event.agent_id}:{parent}:{child}"
            if await self.redis.get(cool):
                return
            await self.redis.setex(cool, settings.CORR_LINEAGE_COOLDOWN_S, "1")
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
            await self.redis.setex(parent_key, settings.CORR_LINEAGE_PARENT_TTL_S, "1")

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
                min_samples = settings.CORR_BEACON_MIN_SAMPLES
                # Add timestamp to sorted set
                await self.redis.zadd(beacon_key, {json.dumps({"ts": now, "port": port}): now})
                # Keep only last 20 entries
                await self.redis.zremrangebyrank(beacon_key, 0, -21)
                # Expire key after window
                await self.redis.expire(beacon_key, settings.CORR_BEACON_WINDOW_S)

                # Check if we have enough data points for beacon analysis
                count = await self.redis.zcard(beacon_key)
                if count >= min_samples:
                    entries = await self.redis.zrange(beacon_key, 0, -1)
                    timestamps = sorted([json.loads(e)["ts"] for e in entries])

                    if len(timestamps) >= min_samples:
                        from app.services.incident_grouping import beacon_verdict
                        verdict = beacon_verdict(
                            timestamps, min_samples,
                            settings.CORR_BEACON_MAX_VARIANCE)

                        if verdict["beacon"]:
                            ports_used = list(set([json.loads(e).get("port", "") for e in entries]))
                            port_str = ",".join(ports_used[:5])

                            await self._generate_alert(
                                db,
                                agent_id=event.agent_id,
                                severity="HIGH",
                                process_name=event.process_name or "unknown",
                                event_type="correlation_beacon",
                                description=f"Potential C2 beacon detected: process '{event.process_name}' (PID {event.pid}) "
                                            f"connecting to {host}:{port_str} every {verdict['avg_interval']:.1f}s "
                                            f"(variance={verdict['variance']:.2f}, {count} samples)."
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

correlation_engine = CorrelationEngine()
