from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class EventSchema(BaseModel):
    agent_id: str
    process_name: str
    pid: int
    timestamp: datetime
