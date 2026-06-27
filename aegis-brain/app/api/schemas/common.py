from pydantic import BaseModel, ConfigDict, Field, alias_generators, BeforeValidator
from typing import Optional, List, Dict, Any, Annotated
from datetime import datetime
from uuid import UUID

# Helper to ensure UUIDs are treated as strings in responses
UUIDStr = Annotated[UUID, BeforeValidator(lambda v: str(v) if isinstance(v, UUID) else v)]

class BaseSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

class UserOut(BaseSchema):
    id: int
    username: str
    email: str
    role: str
    active: bool
    created_at: datetime

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut

class NoteCreate(BaseModel):
    title: str = Field(..., max_length=255)
    content: str = Field(..., max_length=10000)
    mood: Optional[str] = Field(None, max_length=20)
    tags: Optional[List[str]] = Field(None, max_length=20)

class NoteOut(BaseSchema):
    id: int
    title: str
    content: str
    mood: Optional[str] = None
    tags: Optional[List[str]] = None

class AlertResponse(BaseSchema):
    id: int
    agent_id: UUIDStr
    timestamp: datetime
    severity: str
    pid: Optional[int] = None
    process_name: str
    event_type: str
    description: str
    is_resolved: bool

class AgentResponse(BaseSchema):
    agent_id: UUIDStr
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os_type: Optional[str] = None
    agent_type: Optional[str] = None
    is_demo: bool = False
    last_seen: Optional[datetime] = None

class EventSchema(BaseModel):
    model_config = ConfigDict(
        alias_generator=alias_generators.to_camel,
        populate_by_name=True
    )

    agent_id: str = Field(..., max_length=64)
    timestamp: datetime
    event_type: str = Field(..., max_length=50)
    
    # System Info
    hostname: Optional[str] = Field(None, max_length=255)
    ip_address: Optional[str] = Field(None, max_length=45)
    os: Optional[str] = Field(None, max_length=50)
    
    # Process Info
    pid: Optional[int] = None
    process_name: Optional[str] = Field(None, max_length=255)
    process_path: Optional[str] = Field(None, max_length=1024)
    user: Optional[str] = Field(None, max_length=255)
    file_hash: Optional[str] = Field(None, max_length=64)
    
    # Metrics
    cpu_usage: Optional[float] = None
    ram_usage: Optional[float] = None
    disk_free: Optional[int] = None
    disk_total: Optional[int] = None
    network_sent: Optional[int] = None
    network_received: Optional[int] = None
    processes: Optional[List[Dict[str, Any]]] = Field(None, max_length=500)
    users: Optional[List[Dict[str, Any]]] = None
    network_flows: Optional[List[Dict[str, Any]]] = None

class StatsResponse(BaseModel):
    total_alerts: int
    unresolved_alerts: int
    active_agents: int
    current_critical_alerts: int = 0
    current_high_alerts: int = 0
    current_medium_alerts: int = 0
    current_low_alerts: int = 0
    demo_agents: int = 0
