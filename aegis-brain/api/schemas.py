from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime
from uuid import UUID

class BaseResponse(BaseModel):
    model_config = {"from_attributes": True}

    @field_validator("*", mode="before")
    @classmethod
    def convert_uuid_to_str(cls, v):
        if isinstance(v, UUID):
            return str(v)
        return v

class EventSchema(BaseModel):
    model_config = {"populate_by_name": True, "extra": "ignore"}
    agent_id: str           = Field(alias="agentId")
    pid: int
    process_name: str       = Field(alias="processName")
    process_path: Optional[str] = Field(default=None, alias="processPath")
    user: Optional[str]     = None
    os: str
    file_hash: Optional[str]= Field(default=None, alias="fileHash")
    event_type: str         = Field(alias="eventType")
    timestamp: datetime
    hostname: Optional[str] = None
    ip_address: Optional[str] = Field(default=None, alias="ipAddress")

class AlertResponse(BaseResponse):
    id: int
    agent_id: str
    timestamp: datetime
    severity: str
    pid: Optional[int]
    process_name: str
    process_path: Optional[str]
    event_type: str
    description: str
    is_resolved: bool

class AgentResponse(BaseResponse):
    agent_id: str
    hostname: Optional[str]
    ip_address: Optional[str]
    os_type: Optional[str]
    last_seen: Optional[datetime]

class StatsResponse(BaseModel):
    total_alerts: int
    unresolved_alerts: int
    current_critical_alerts: int
    current_high_alerts: int
    current_medium_alerts: int
    current_low_alerts: int
    active_agents: int

class ResolveRequest(BaseModel):
    resolved: bool = True
