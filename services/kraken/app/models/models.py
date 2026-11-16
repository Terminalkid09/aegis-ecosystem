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
