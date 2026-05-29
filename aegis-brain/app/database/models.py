import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import String, Integer, Boolean, DateTime, Text, ForeignKey, Float, BigInteger, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from app.database.base import Base

def utc_now():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(150), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(500), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="user")
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    encrypted_dek: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    notes: Mapped[List["Note"]] = relationship(back_populates="user", cascade="all, delete-orphan")

class Note(Base):
    __tablename__ = "notes"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    mood: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    tags: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    user: Mapped["User"] = relationship(back_populates="notes")

class AIThread(Base):
    __tablename__ = "ai_threads"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False, default="Security Investigation")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class AIMessage(Base):
    __tablename__ = "ai_messages"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    thread_id: Mapped[int] = mapped_column(ForeignKey("ai_threads.id"), nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    model: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

from sqlalchemy.dialects.postgresql import UUID as PG_UUID

class Agent(Base):
    __tablename__ = "agents"
    agent_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    os_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    agent_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    meta: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    device_token_hash: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    agent_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.agent_id"), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    process_name: Mapped[str] = mapped_column(String(255), nullable=False)
    process_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

class Telemetry(Base):
    __tablename__ = "telemetry"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    device_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agents.agent_id"), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    cpu_usage: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    ram_usage: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    disk_free: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    disk_total: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    network_sent: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    network_received: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)
    processes: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    ip_local: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    ip_public: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    geo_country: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    geo_city: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

class OSINTReport(Base):
    __tablename__ = "osint_reports"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    query: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False)
    data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    cached_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class APIKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    hashed_key: Mapped[str] = mapped_column(String(512), nullable=False)
    scopes: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
