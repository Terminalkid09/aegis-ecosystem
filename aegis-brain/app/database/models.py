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
from sqlalchemy import UniqueConstraint

class Agent(Base):
    __tablename__ = "agents"
    __table_args__ = (
        UniqueConstraint("hostname", "os_type", name="uq_agent_hostname_os"),
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    os_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    agent_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    agent_version: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    capabilities: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    isolated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
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
    parent_pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    parent_process_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    process_name: Mapped[str] = mapped_column(String(255), nullable=False)
    process_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    # Contesto strutturato dell'alert (endpoint remoto, conteggio connessioni,
    # processi possessori, command line...): la description resta leggibile,
    # l'evidence e' la parte che un analista puo' interrogare. Nullable perche'
    # gli alert pre-0019 e alcune sorgenti (Sigma) non la popolano ancora.
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # MITRE ATT&CK mapping (populated from CustomRule or enrichment)
    mitre_tactic_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    mitre_tactic_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    mitre_technique_name: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)

    # relation
    agent: Mapped["Agent"] = relationship()

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
    users: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(JSON, nullable=True)
    network_flows: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(JSON, nullable=True)

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

class CustomRule(Base):
    __tablename__ = "custom_rules"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    target_field: Mapped[str] = mapped_column(String(100), nullable=False)
    pattern: Mapped[str] = mapped_column(String(500), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="MEDIUM")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # MITRE ATT&CK mapping
    mitre_tactic_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    mitre_tactic: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    mitre_technique_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    mitre_technique: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Logic type: "simple" (default) or "and"/"or" for multi-condition
    logic_type: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)

    # AND/OR conditions (JSON array of {target_field, pattern, operator})
    conditions: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Whitelist: hostnames/IPs to exclude
    whitelist: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Auto-remediation action
    auto_remediation: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)

    # Counter / tracking
    trigger_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_triggered: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class RemediationAction(Base):
    __tablename__ = "remediation_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[int] = mapped_column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    agent_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("agents.agent_id", ondelete="CASCADE"), nullable=False)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

class DiscoveredHost(Base):
    __tablename__ = "discovered_hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False, index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String(17), nullable=True)
    vendor: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    os_guess: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    os_confidence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="unknown", nullable=False)
    open_ports: Mapped[Optional[List[int]]] = mapped_column(JSON, nullable=True)
    guard_status: Mapped[str] = mapped_column(String(30), default="not_deployed", nullable=False)
    nodetrace_status: Mapped[str] = mapped_column(String(30), default="not_deployed", nullable=False)
    source: Mapped[str] = mapped_column(String(50), default="scan", nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

class ThreatReport(Base):
    __tablename__ = "threat_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[int] = mapped_column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False, index=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    recommended_actions: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    osint_data: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    ai_analysis: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_auto_generated: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

class IPReputation(Base):
    __tablename__ = "ip_reputations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(30), default="unknown", nullable=False)
    confidence: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    source: Mapped[str] = mapped_column(String(100), default="manual", nullable=False)
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    username: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    is_test: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

class Playbook(Base):
    __tablename__ = "playbooks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    
    # Trigger conditions
    trigger_event_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    trigger_severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    trigger_process_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    trigger_condition: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    actions: Mapped[List["PlaybookAction"]] = relationship(back_populates="playbook", cascade="all, delete-orphan")

class PlaybookAction(Base):
    __tablename__ = "playbook_actions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    playbook_id: Mapped[int] = mapped_column(ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False)
    action_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    params: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    playbook: Mapped["Playbook"] = relationship(back_populates="actions")

class PlaybookExecution(Base):
    __tablename__ = "playbook_executions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    playbook_id: Mapped[int] = mapped_column(ForeignKey("playbooks.id", ondelete="CASCADE"), nullable=False)
    alert_id: Mapped[Optional[int]] = mapped_column(ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True)
    triggered_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    result: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

class IntegrationSetting(Base):
    """Chiavi API di integrazione (provider OSINT ecc.) cifrate con il KEK.

    Scope: chiavi di SERVIZIO (una per deployment), non per-utente: per questo
    non usano il DEK per-utente del VaultX ma encrypt_value/decrypt_value.
    La risoluzione runtime è env -> override DB: chiave in env ha precedenza
    (12-factor), l'override in DB serve quando non vuoi toccare il .env o
    fare restart del container.
    """
    __tablename__ = "integration_settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    updated_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AppSetting(Base):
    """Impostazioni di deployment NON segrete, modificabili dalla UI.

    Perché non in `integration_settings`: quella è cifrata ed esiste per le
    chiavi API. Provider AI, modello o simili non sono segreti, e tenerli
    cifrati renderebbe illeggibile il DB per debug e la UI incapace di
    mostrarli. Qui vivono solo valori leggibili, con la precedenza dichiarata
    dal servizio (`app_settings.py`): env esplicito > DB > default.
    """
    __tablename__ = "app_settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    updated_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class YaraRule(Base):
    """Regola YARA gestita dal SOC, spedita agli agenti su scansione.

    Perché in DB e non su filesystem: la regola deve viaggiare sul canale
    comandi (brain -> agente) e vuole ciclo di vita (attiva/disattiva,
    audit, chi l'ha creata) — il DB lo dà gratis.
    """
    __tablename__ = "yara_rules"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), index=True)
    content: Mapped[str] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class SyslogEvent(Base):
    __tablename__ = "syslog_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    facility: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    severity: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    app_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    raw: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    processed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


# ─── M1: modern deploy (Falcon-style one-liner + job queue) ────────────
# NOTE: agent_id kept as String(36) on purpose for SQLite/aio tests compat
# (Agent.agent_id uses PG UUID which is Postgres-only).

class RememberDevice(Base):
    """Token "Mantieni l'accesso su questo dispositivo" (remember-me).

    Modello GitHub/Google: il cookie contiene SOLO il token opaco; sul server
    c'e' solo l'hash (sha256), quindi il dump del DB non permette di spacciarsi
    per un dispositivo. Revocabile singolarmente dal pannello Users. La
    revoca dell'account (active=False) invalida tutti i remember-token
    dell'utente perche' la validazione passa da get_current_user.
    """
    __tablename__ = "remember_devices"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    device_label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class EnrollToken(Base):
    """Short-lived single-use enrollment tokens for one-liner install.

    Replaces the static AGENT_ENROLL_KEY for interactive installs.
    The static key stays valid as fallback for headless/IoT provisioning.
    """
    __tablename__ = "enroll_tokens"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    label: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    agent_type: Mapped[str] = mapped_column(String(50), default="aegis-guard", nullable=False)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    used_by_hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    used_agent_types: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    install_config: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DeployJob(Base):
    """Mass deploy job: N targets, server-side execution, WS-streamable logs.

    Credentials are NEVER persisted: only a transient reference + username
    (for audit) is stored. Passwords live only in the worker memory.
    """
    __tablename__ = "deploy_jobs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_type: Mapped[str] = mapped_column(String(50), default="nodetrace", nullable=False)
    agent_version: Mapped[str] = mapped_column(String(50), default="latest", nullable=False)
    targets: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    # per-target status: {ip: {status, log, updated_at}}
    status: Mapped[str] = mapped_column(String(30), default="queued", nullable=False)
    results: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class DeployCredential(Base):
    """Ephemeral credential reference for a DeployJob.

    Only the username + vault pointer is stored. The secret itself must be
    supplied per-request (modal) or resolved server-side from VaultX at
    execution time with a 60s lease, then wiped from memory.
    """
    __tablename__ = "deploy_credentials"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("deploy_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    method: Mapped[str] = mapped_column(String(20), default="ssh", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ─── M2: Aegis Total (internal static analyzer) ─────────────────────────
# Non e' un decompilatore: il "preview" mostra il contenuto del file caricato
# (utile per script e sorgenti), i binari si leggono per struttura (sezioni,
# entropia, import, firma, stringhe, IOC), non per codice.

AEGIS_TOTAL_DISCLAIMER = (
    "Aegis Total mostra metadati, disassemblato/decompilato approssimativo e IOC "
    "a solo scopo difensivo (DFIR, threat-intel, audit su sistemi di cui hai "
    "autorizzazione). Caricando dichiari di averne diritto. Vietato usare il "
    "servizio per rimuovere protezioni, generare crack/serial o violare IP altrui. "
    "Le analisi sono registrate. Uso improprio = ban + segnalazione."
)


class TotalReport(Base):
    """Aggregated file/project analysis report (dedup by sha256)."""
    __tablename__ = "total_reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sha256: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    kind: Mapped[str] = mapped_column(String(30), default="file", nullable=False)
    score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    verdict: Mapped[str] = mapped_column(String(30), default="unknown", nullable=False)
    engines: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    files: Mapped[Optional[List[Dict[str, Any]]]] = mapped_column(JSON, nullable=True)
    sbom: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    ai_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    disclaimer_accepted_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ─── SOC incidents (commercial triage: group alerts, status, assignee) ──

INCIDENT_STATUSES = ("open", "investigating", "contained", "resolved", "closed")
SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM", nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="open", nullable=False)
    assignee_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    attached_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class RevokedCert(Base):
    """Revoca persistita in DB con audit (Fase 4). File `revoked.txt` resta fallback."""
    __tablename__ = "revoked_certs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    serial: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    fingerprint: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    revoked_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


# ─── SIEM v4: store eventi normalizzati + registro sorgenti ─────────────────
# `extra` conserva TUTTI i campi sorgente (es. `win.ServiceName`, `conn_state`):
# è ciò che permette a una regola Sigma di trovare il dato senza che lo schema
# unificato debba avere una colonna per ogni prodotto.
#
# In produzione la tabella è RANGE-partizionata per mese (vedi migrazione
# 0013_siem_ingest): retention = DROP PARTITION invece di DELETE su milioni di
# righe. Il modello non dichiara la partizione perché la stessa tabella deve
# poter nascere da `create_all` negli ambienti di test; l'app non dipende mai
# dalla partizione (la crea `siem_store.ensure_monthly_partitions`).

class SiemEvent(Base):
    __tablename__ = "siem_events"
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="INFO", index=True)
    ocsf_class_uid: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    user_domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    process_name: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    parent_process_name: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    parent_pid: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    process_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    command_line: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    file_name: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    file_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    src_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    dst_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True, index=True)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)

    url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    http_method: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    http_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    dns_query: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    signature: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    signature_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    message_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    # Testo aggregato su cui gira la ricerca libera (bounded lato app).
    search_text: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    extra: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class LogSource(Base):
    """Sorgente di log configurata: nome, parser e statistiche di ingestione."""
    __tablename__ = "log_sources"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    parser: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    events_total: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    events_invalid: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    last_event_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
