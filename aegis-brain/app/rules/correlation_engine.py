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
        # Rule 1: Brute Force Detection
        # Assume Syslog SSH or Auth failed events contain "Failed password" or "authentication failure" in the file_hash/msg
        if event.event_type == "SYSLOG_NETWORK" and event.file_hash:
            msg = event.file_hash.lower()
            if "failed password" in msg or "authentication failure" in msg:
                # Extract username or IP if possible. For simplicity, track by agent_id (hostname)
                key = f"corr:bf:{event.agent_id}"
                count = await self.redis.incr(key)
                if count == 1:
                    await self.redis.expire(key, 60) # Window of 60 seconds
                
                if count >= 5:
                    await self._generate_alert(
                        db,
                        agent_id=event.agent_id,
                        severity="CRITICAL",
                        process_name="syslog_auth",
                        event_type="correlation_bruteforce",
                        description=f"Multiple failed login attempts ({count}) detected within 60 seconds on {event.hostname}."
                    )
                    await self.redis.delete(key) # Reset after alert

        # Rule 2: Impossible Travel / Remote Desktop Access
        # If we see a login from a remote user, we track their IP and compare locations
        # For simplicity in this implementation, if we see a syslog message indicating successful login
        # we track the IP if it's public.
        if event.event_type == "SYSLOG_NETWORK" and event.file_hash:
            msg = event.file_hash.lower()
            if "accepted password" in msg or "session opened" in msg:
                # We could extract IPs here, but let's leave a placeholder or simple logic
                logger.info(f"Successful login detected on {event.hostname}")

        # Rule 3: Process sequence (e.g., cmd.exe spawned by a web server)
        # This is typically done by tracking parent-child process relationships over time.
        
    async def _generate_alert(self, db: AsyncSession, agent_id: str, severity: str, process_name: str, event_type: str, description: str):
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
        await db.commit()
        logger.warning(f"CORRELATION ALERT: {description}")

correlation_engine = CorrelationEngine()
