from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Float, ForeignKey, Index, JSON
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.db.session import Base


class User(Base):
    __tablename__ = "users"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    hashed_password = Column(String(256), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AttackEvent(Base):
    __tablename__ = "attack_events"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(64), unique=True, index=True, nullable=False)
    attacker_ip = Column(String(45), nullable=False, index=True)
    attacker_port = Column(Integer, nullable=True)
    sensor_type = Column(String(32), nullable=False, index=True)
    sensor_port = Column(Integer, nullable=True)
    timestamp_start = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    timestamp_end = Column(DateTime(timezone=True), nullable=True)

    # GeoIP enrichment
    country = Column(String(64), nullable=True, index=True)
    city = Column(String(64), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    asn = Column(String(128), nullable=True)
    isp = Column(String(128), nullable=True)

    # Threat intel
    is_known_threat = Column(Boolean, default=False)
    threat_tags = Column(String(256), nullable=True)

    commands = relationship("AttackCommand", back_populates="event", cascade="all, delete-orphan", uselist=True)
    credentials = relationship("CredentialAttempt", back_populates="event", cascade="all, delete-orphan", uselist=True)
    malware_samples = relationship("MalwareSample", back_populates="event", cascade="all, delete-orphan", uselist=True)

    __table_args__ = (
        Index("ix_attack_events_ip_sensor", "attacker_ip", "sensor_type"),
        Index("ix_attack_events_timestamp", "timestamp_start"),
    )


class AttackCommand(Base):
    __tablename__ = "attack_commands"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("attack_events.id", ondelete="CASCADE"), nullable=False)
    command = Column(Text, nullable=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    event = relationship("AttackEvent", back_populates="commands")


class CredentialAttempt(Base):
    __tablename__ = "credential_attempts"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("attack_events.id", ondelete="CASCADE"), nullable=False)
    username = Column(String(128), nullable=True)
    password = Column(String(256), nullable=True)
    # NetNTLMv2 response material only (never a plaintext password).
    ntlm_hash = Column(String(1024), nullable=True)
    success = Column(Boolean, default=False)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    event = relationship("AttackEvent", back_populates="credentials")


class Outbox(Base):
    """Eventi Kraken in attesa di consegna ad Aegis.

    La riga viene scritta nella stessa transazione dell'evento: se il commit
    fallisce non esiste né l'evento né la consegna; se Aegis è irraggiungibile
    l'evento resta qui e il worker lo ritenta. Non è una coda Redis: Redis non
    è transazionale con l'ingest.
    """
    __tablename__ = "outbox"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, nullable=False, index=True)
    payload = Column(JSON, nullable=False)
    status = Column(String(16), nullable=False, default="pending", index=True)
    attempts = Column(Integer, nullable=False, default=0)
    next_attempt_at = Column(DateTime(timezone=True), nullable=False, index=True)
    claimed_at = Column(DateTime(timezone=True), nullable=True)
    sent_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_outbox_due", "status", "next_attempt_at"),
    )


class MalwareSample(Base):
    __tablename__ = "malware_samples"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("attack_events.id", ondelete="CASCADE"), nullable=False)
    filename = Column(String(256), nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    path = Column(String(512), nullable=True)
    size = Column(Integer, nullable=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    event = relationship("AttackEvent", back_populates="malware_samples")


class Campaign(Base):
    """A named intrusion campaign; never stores raw credentials."""
    __tablename__ = "campaigns"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    status = Column(String(24), nullable=False, default="active", index=True)
    fingerprint = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SensorNode(Base):
    """A managed Kraken sensor node. Only the key hash is persisted."""
    __tablename__ = "sensor_nodes"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True, index=True)
    node_id = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(128), nullable=False)
    site = Column(String(64), nullable=False, default="default", index=True)
    status = Column(String(24), nullable=False, default="pending", index=True)
    key_hash = Column(String(128), nullable=False)
    config = Column(JSON, nullable=False, default=dict)
    config_version = Column(Integer, nullable=False, default=1)
    applied_version = Column(Integer, nullable=False, default=0)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Topology(Base):
    """Lab network definition. It is data, not an executable scenario."""
    __tablename__ = "topologies"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    spec = Column(JSON, nullable=False, default=dict)
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class LabRun(Base):
    """A shadow-only Lab run; it can never trigger destructive actions."""
    __tablename__ = "lab_runs"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(64), unique=True, nullable=False, index=True)
    topology_id = Column(Integer, ForeignKey("topologies.id", ondelete="SET NULL"), nullable=True)
    scenario_id = Column(String(64), nullable=False, index=True)
    mode = Column(String(16), nullable=False, default="shadow")
    status = Column(String(24), nullable=False, default="running", index=True)
    evidence = Column(JSON, nullable=False, default=dict)
    started_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    finished_at = Column(DateTime(timezone=True), nullable=True)



class AnalysisJob(Base):
    """Async static file/ZIP analysis. The sample never enters Aegis."""
    __tablename__ = "analysis_jobs"
    __allow_unmapped__ = True

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String(64), unique=True, nullable=False, index=True)
    sha256 = Column(String(64), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    size = Column(Integer, nullable=False, default=0)
    storage_path = Column(String(1024), nullable=True)
    status = Column(String(24), nullable=False, default="queued", index=True)
    report = Column(JSON, nullable=False, default=dict)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    finished_at = Column(DateTime(timezone=True), nullable=True)
