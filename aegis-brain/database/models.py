import uuid
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from database.connection import Base

class Agent(Base):
    __tablename__ = "agents"
    agent_id   = Column(UUID(as_uuid=False), primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname   = Column(String(255), nullable=True)
    ip_address = Column(String(45),  nullable=True)
    os_type    = Column(String(50),  nullable=True)
    last_seen  = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class Alert(Base):
    __tablename__ = "alerts"
    id           = Column(Integer, primary_key=True, autoincrement=True)
    agent_id     = Column(UUID(as_uuid=False), ForeignKey("agents.agent_id"), nullable=False)
    timestamp    = Column(DateTime(timezone=True), server_default=func.now())
    severity     = Column(String(20),  nullable=False)
    pid          = Column(Integer,     nullable=True)
    process_name = Column(String(255), nullable=False)
    process_path = Column(Text,        nullable=True)
    event_type   = Column(String(100), nullable=False)
    description  = Column(Text,        nullable=False)
    is_resolved  = Column(Boolean,     default=False, nullable=False)
