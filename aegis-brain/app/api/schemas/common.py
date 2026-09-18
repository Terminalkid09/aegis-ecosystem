from annotated_types import MaxLen
from pydantic import (BaseModel, ConfigDict, Field, alias_generators,
                      BeforeValidator, model_validator)
from typing import Optional, List, Dict, Any, Annotated
from datetime import datetime
from uuid import UUID

# Marcatore di troncatura: finisce in `quality` (es. 'truncated:command_line').
TRUNCATION_TAG = "truncated"

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
    parent_pid: Optional[int] = None
    parent_process_name: Optional[str] = None
    process_name: str
    process_path: Optional[str] = None
    event_type: str
    description: str
    is_resolved: bool
    mitre_tactic_id: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_tactic_name: Optional[str] = None
    mitre_technique_name: Optional[str] = None

class AgentResponse(BaseSchema):
    agent_id: UUIDStr
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    os_type: Optional[str] = None
    agent_type: Optional[str] = None
    agent_version: Optional[str] = None
    isolated: bool = False
    is_demo: bool = False
    last_seen: Optional[datetime] = None
    # M7 Fase 8: sito (da meta), stato e capabilities (additivi, default sicuri).
    site: str = "default"
    status: str = "unknown"
    capabilities: Optional[Any] = None

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
    parent_pid: Optional[int] = Field(None, alias="parentPid")
    parent_process_name: Optional[str] = Field(None, max_length=255, alias="parentProcessName")
    process_name: Optional[str] = Field(None, max_length=255)
    process_path: Optional[str] = Field(None, max_length=1024)
    user: Optional[str] = Field(None, max_length=255)
    file_hash: Optional[str] = Field(None, max_length=64)
    thread_count: Optional[int] = Field(None, alias="threadCount")
    
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

    # Security signals
    network_connections: Optional[List[Dict[str, Any]]] = Field(None, alias="networkConnections")

    # Fleet management (Guard sends camelCase agentVersion, NodeTrace snake_case)
    agent_version: Optional[str] = Field(None, max_length=50, alias="agentVersion")
    capabilities: Optional[Any] = None

    # Agent-side behavioral detection (Phase 5)
    command_line: Optional[str] = Field(None, max_length=4096, alias="commandLine")
    behavioral_tags: Optional[List[str]] = Field(None, alias="behavioralTags")
    anomalies: Optional[List[str]] = None
    # Moduli caricati (audit: la S011 DLL-hijacking non puo' vedersi dal solo
    # process_path; i sensori futuri popolano questa lista).
    loaded_modules: Optional[List[str]] = Field(None, max_length=256, alias="loadedModules")

    # Event identity + sequencing (schema v2, M1 Fase 2 — tutti opzionali:
    # gli agenti legacy v1 continuano a funzionare senza questi campi).
    event_id: Optional[str] = Field(
        None, max_length=64, alias="eventId",
        description="UUID per evento, chiave di idempotenza/dedup")
    schema_version: Optional[int] = Field(None, alias="schemaVersion")
    boot_id: Optional[str] = Field(None, max_length=64, alias="bootId")
    seq: Optional[int] = Field(None, ge=0, description="Sequence per (agent_id, boot_id); negativo = corrotto, rifiutato")
    ts_monotonic_ns: Optional[int] = Field(None, alias="tsMonotonicNs")
    ts_wall_ns: Optional[int] = Field(None, alias="tsWallNs")
    proc_start_ns: Optional[int] = Field(
        None, alias="procStartNs",
        description="Start monotonico processo: con pid risolve PID reuse")
    session_id: Optional[str] = Field(None, max_length=128, alias="sessionId")
    integrity_level: Optional[str] = Field(None, max_length=64, alias="integrityLevel")
    signature: Optional[str] = Field(None, max_length=256)
    publisher: Optional[str] = Field(None, max_length=256)
    proto: Optional[str] = Field(None, max_length=16)
    direction: Optional[str] = Field(None, max_length=16)
    container_id: Optional[str] = Field(None, max_length=128, alias="containerId")
    cgroup: Optional[str] = Field(None, max_length=512)
    net_namespace: Optional[str] = Field(None, max_length=128, alias="netNamespace")
    provenance: Optional[str] = Field(None, max_length=32)
    quality: Optional[str] = Field(None, max_length=64)
    sampling: Optional[str] = Field(None, max_length=32)
    drop_reason: Optional[str] = Field(None, max_length=128, alias="dropReason")

    @model_validator(mode="before")
    @classmethod
    def _clamp_oversized_strings(cls, data: Any) -> Any:
        """Tronca i campi stringa oltre il limite dichiarato invece di
        rifiutare l'evento.

        Perché: con la validazione stretta bastava UNA command line lunga —
        un processo che si rilancia con un JSON di 12 KB in argv, esattamente
        ciò che fa l'agente NodeTrace con curl — per far fallire con 422
        l'INTERO batch. L'outbox dell'agente rigioca il batch, quindi falliva
        per sempre: la telemetria di quell'endpoint non arrivava più al brain,
        nessun processo, nessun alert, in silenzio.

        La redazione a valle (`redact_text`) tronca già a 4096, ma gira DOPO
        la validazione: non proteggeva nulla. Qui si applica prima, ai limiti
        dichiarati dai campi stessi (quindi anche ai campi futuri, senza
        doverli elencare) e lo si dichiara in `quality`, stessa convenzione di
        'degraded:etw-disabled'. La telemetria non si butta: si tronca, e la
        perdita è visibile.
        """
        if not isinstance(data, dict):
            return data

        # Limite per ciascun campo, indicizzato sia col nome sia con l'alias
        # accettato dall'agente (camelCase).
        limits: dict[str, tuple[str, int]] = {}
        for name, info in cls.model_fields.items():
            max_len = next((meta.max_length for meta in info.metadata
                            if isinstance(meta, MaxLen)), None)
            if not max_len:
                continue
            limits[name] = (name, max_len)
            if info.alias:
                limits[info.alias] = (name, max_len)

        clean = dict(data)
        truncated: list[str] = []
        for key, value in data.items():
            entry = limits.get(key)
            if entry is None or not isinstance(value, str):
                continue
            field_name, max_len = entry
            if len(value) > max_len:
                clean[key] = value[:max_len]
                if field_name != "quality":
                    truncated.append(field_name)

        if truncated:
            marker = TRUNCATION_TAG + ":" + ",".join(sorted(set(truncated)))
            existing = clean.get("quality")
            merged = f"{existing};{marker}" if existing else marker
            q_limit = limits["quality"][1]
            clean["quality"] = merged[:q_limit]

        return clean

class StatsResponse(BaseModel):
    total_alerts: int
    unresolved_alerts: int
    active_agents: int
    current_critical_alerts: int = 0
    current_high_alerts: int = 0
    current_medium_alerts: int = 0
    current_low_alerts: int = 0
    demo_agents: int = 0
    # Pipeline M1 Fase 2: duplicati scartati e gap di sequenza (perdite misurate).
    events_duplicated: int = 0
    events_seq_gaps: int = 0
    events_seq_gap_events: int = 0
    # Flotta M7 Fase 8: salute sensori (additivi).
    isolated_agents: int = 0
    stale_agents: int = 0
    offline_agents: int = 0
