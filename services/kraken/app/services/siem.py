import os
import json
from loguru import logger
from datetime import datetime, timezone
from app.core.config import settings

class SIEMLogger:
    def __init__(self):
        self.log_file = settings.SIEM_LOG_FILE
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

    def _write_event(self, event_type: str, data: dict):
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "event_type": event_type,
            **data
        }
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.error(f"SIEM log write error: {e}")

    def log_attack(self, data: dict):
        self._write_event("attack_event", data)

    def log_malware(self, data: dict):
        self._write_event("malware_capture", data)

siem_logger = SIEMLogger()
