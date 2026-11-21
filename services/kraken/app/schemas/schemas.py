from pydantic import BaseModel, field_validator, Field
from typing import Optional, List
from datetime import datetime
import ipaddress


# ── Auth ──────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class SsoRequest(BaseModel):
    token: str = Field(..., min_length=20, max_length=8192)


# ── User ──────────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    password: str = Field(..., min_length=8, max_length=128)
    # `is_admin` non esiste piu' nel contratto: il primo admin nasce solo
    # dallo script locale, mai da una richiesta HTTP pubblica.
    model_config = {"extra": "forbid"}


class UserOut(BaseModel):
    id: int
    username: str
    is_active: bool
    is_admin: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Nested ────────────────────────────────────────────────────────────────────

class CredentialAttemptOut(BaseModel):
    id: int
    username: Optional[str]
    success: bool
    timestamp: datetime

    model_config = {"from_attributes": True}


class AttackCommandOut(BaseModel):
    id: int
    command: str
    timestamp: datetime

    model_config = {"from_attributes": True}


# ── Events ────────────────────────────────────────────────────────────────────

class AttackEventOut(BaseModel):
    id: int
    session_id: str
    attacker_ip: str
    attacker_port: Optional[int]
    sensor_type: str
    sensor_port: Optional[int]
    timestamp_start: datetime
    timestamp_end: Optional[datetime]
    country: Optional[str]
    city: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    asn: Optional[str]
    isp: Optional[str]
    is_known_threat: bool
    threat_tags: Optional[str]
    commands: List[AttackCommandOut] = []
    credentials: List[CredentialAttemptOut] = []
    malware_samples: List[dict] = []

    model_config = {"from_attributes": True}


class AttackEventSummary(BaseModel):
    id: int
    session_id: str
    attacker_ip: str
    sensor_type: str
    timestamp_start: datetime
    country: Optional[str]
    city: Optional[str]
    is_known_threat: bool

    model_config = {"from_attributes": True}


# ── Stats ─────────────────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_attacks: int
    attacks_today: int
    unique_ips: int
    top_countries: List[dict]
    top_sensors: List[dict]
    attacks_over_time: List[dict]
    geo_points: List[dict]


# ── Sensor telemetry ingest ───────────────────────────────────────────────────

_ALLOWED_SENSORS = {"ssh", "http", "ftp", "telnet", "smtp", "rdp", "smb"}


class SensorEventIn(BaseModel):
    sensor_type: str = Field(..., max_length=32)
    attacker_ip: str = Field(..., max_length=45)
    attacker_port: int = Field(..., ge=1, le=65535)
    sensor_port: int = Field(..., ge=1, le=65535)
    session_id: str = Field(..., min_length=8, max_length=64)
    username: Optional[str] = Field(None, max_length=128)
    password: Optional[str] = Field(None, max_length=256)
    # NetNTLMv2 response captured by the SMB sensor. It is a challenge
    # response, not a reusable plaintext credential.
    ntlm_hash: Optional[str] = Field(None, max_length=1024)
    commands: Optional[List[str]] = Field(default_factory=list)
    # ``sensor`` is a real honeypot; ``lab`` is a shadow scenario. The Brain
    # must keep them distinguishable: a lab event is evidence, not an attack
    # against production.
    context: str = Field("sensor", pattern=r"^(sensor|lab)$")
    run_id: Optional[str] = Field(None, max_length=64)
    scenario_id: Optional[str] = Field(None, max_length=64)
    topology_id: Optional[str] = Field(None, max_length=64)
    # Cap applied in the validator (200 commands) instead of rejecting a
    # slightly oversized sensor batch with a 422.

    @field_validator("sensor_type")
    @classmethod
    def validate_sensor_type(cls, v: str) -> str:
        if v.lower() not in _ALLOWED_SENSORS:
            raise ValueError(f"sensor_type must be one of {_ALLOWED_SENSORS}")
        return v.lower()

    @field_validator("attacker_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError("Invalid IP address format")
        return v

    @field_validator("commands")
    @classmethod
    def truncate_commands(cls, v: Optional[List[str]]) -> List[str]:
        if v is None:
            return []
        return [cmd[:512] for cmd in v[:200]]
