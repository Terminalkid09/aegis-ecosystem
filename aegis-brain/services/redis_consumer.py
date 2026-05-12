import json
import uuid
import os
import redis
from datetime import datetime, timezone
from collections import defaultdict

from api.schemas import EventSchema
from database.connection import SessionLocal
from database.models import Agent, Alert
from rules.heuristic_engine import HeuristicEngine
from utils.logger import get_logger

logger = get_logger(__name__)

REDIS_HOST    = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT    = int(os.getenv("REDIS_PORT", "6379"))
EVENTS_QUEUE  = "aegis:events"
BRPOP_TIMEOUT = 2
AGENT_UPDATE_INTERVAL_SEC = 30  # Aggiorna last_seen max ogni 30 sec

class RedisConsumer:
    def __init__(self):
        self._running = False
        self._engine  = HeuristicEngine()
        self._client  = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        self._last_agent_update = defaultdict(lambda: None)  # Traccia ultimo update per agente


    def start(self):
        self._running = True
        logger.info("RedisConsumer started on queue '%s'", EVENTS_QUEUE)
        while self._running:
            try:
                result = self._client.brpop(EVENTS_QUEUE, timeout=BRPOP_TIMEOUT)
                if result:
                    _, raw_json = result
                    self._process_raw(raw_json)
            except redis.ConnectionError as e:
                logger.error("Redis connection lost: %s", e)
                import time; time.sleep(5)
            except Exception as e:
                logger.error("Error in consumer: %s", e)
        logger.info("RedisConsumer stopped.")

    def stop(self):
        self._running = False

    def _process_raw(self, raw_data):
        try:
            # raw_data può essere una stringa JSON o un dizionario
            if isinstance(raw_data, str):
                data = json.loads(raw_data)
            else:
                data = raw_data
            event = EventSchema.model_validate(data)
            self._save_agent(event)
            analysis = self._engine.analyze(event)
            if analysis.is_threat:
                self._save_alert(event, analysis.severity, analysis.description)
        except Exception as e:
            logger.error("Processing error: %s", e)

    def _save_agent(self, event: EventSchema):
        db = SessionLocal()
        try:
            agent_uuid = uuid.UUID(event.agent_id)
            agent = db.get(Agent, agent_uuid)
            if not agent:
                agent = Agent(
                    agent_id=agent_uuid,
                    os_type=event.os,
                    hostname=getattr(event, 'hostname', None),
                    ip_address=getattr(event, 'ip_address', None)
                )
                db.add(agent)
            else:
                # Update last_seen and system info on every event
                agent.last_seen = datetime.now(timezone.utc)
                if hasattr(event, 'hostname') and event.hostname:
                    agent.hostname = event.hostname
                if hasattr(event, 'ip_address') and event.ip_address:
                    agent.ip_address = event.ip_address
            db.commit()
            logger.info(f"Agent {agent.agent_id} updated: hostname={agent.hostname}, ip={agent.ip_address}, last_seen={agent.last_seen}")
        except Exception as e:
            db.rollback()
            logger.error("DB error saving agent: %s", e)
        finally:
            db.close()

    def _save_alert(self, event: EventSchema, severity: str, description: str):
        db = SessionLocal()
        try:
            agent_uuid = uuid.UUID(event.agent_id)
            alert = Alert(
                agent_id=agent_uuid,
                severity=severity,
                pid=event.pid,
                process_name=event.process_name,
                process_path=event.process_path,
                event_type=event.event_type,
                description=description
            )
            db.add(alert)
            db.commit()
        except Exception as e:
            db.rollback()
            logger.error("DB error saving alert: %s", e)
        finally:
            db.close()
