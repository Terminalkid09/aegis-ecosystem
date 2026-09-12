from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, model_validator
from typing import Optional
import base64

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App Config
    APP_NAME: str = "Aegis-Brain"
    DEBUG: bool = False
    ALLOWED_ORIGINS: str = "https://aegis.local,http://localhost:3000"

    # Database & Redis
    DATABASE_URL: str = "postgresql+asyncpg://postgres@localhost:5432/aegis"
    DB_BOOTSTRAP_CREATE_ALL: bool = False
    
    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def ensure_asyncpg_driver(cls, v: str) -> str:
        if v.startswith("postgresql://"):
            return v.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v

    REDIS_URL: str = "redis://localhost:6379"
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: Optional[str] = None

    # JWT Security
    JWT_SECRET: Optional[str] = None
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60

    # Encryption (Envelope)
    MASTER_KEY_B64: Optional[str] = None

    # OSINT Providers
    SHODAN_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    OSINT_CACHE_TTL: int = 86400  # 24 hours

    # AI Config
    OLLAMA_URL: Optional[str] = None
    OLLAMA_DEFAULT_MODEL: str = "aegis-default"
    AI_RATE_LIMIT_PER_MIN: int = 20
    # Enterprise default: NO silent stub. In DEBUG lab it may fallback for DX,
    # in prod it must return an explicit degraded error instead of fake AI text.
    AI_DEV_FALLBACK: bool = False

    # Security Keys
    AEGIS_API_KEY: Optional[str] = None
    AGENT_ENROLL_KEY: Optional[str] = None

    # Detection canary (M4 Fase 5): rule_id separati da virgola in log-only.
    RULE_CANARY_IDS: str = ""

    # Correlation windows (M5 Fase 6): finestre configurabili, mai hardcodate.
    CORR_BRUTEFORCE_THRESHOLD: int = 5
    CORR_BRUTEFORCE_WINDOW_S: int = 60
    CORR_LINEAGE_COOLDOWN_S: int = 1800
    CORR_LINEAGE_PARENT_TTL_S: int = 300
    CORR_BEACON_MIN_SAMPLES: int = 5
    CORR_BEACON_WINDOW_S: int = 3600
    CORR_BEACON_MAX_VARIANCE: float = 5.0
    CORR_AUTOGROUP_WINDOW_MIN: int = 30

    # Demo / lab endpoints (MUST stay False in prod — SentinelOne-style hardening)
    ALLOW_DEMO: bool = False

    # Modern deploy (one-liner + job queue, Falcon-style)
    DEPLOY_TOKEN_TTL_MINUTES: int = 15
    ARTIFACT_DIR: str = "/app/artifacts"
    PUBLIC_BASE_URL: str = "https://aegis.local"

    # Device PKI (M6 Fase 7): CA + revoche + chiave manifest, fuori dal repo.
    PKI_DIR: str = "/app/pki"
    PKI_CA_TTL_DAYS: int = 3650
    PKI_DEVICE_TTL_DAYS: int = 825
    # Mutual auth agent (post-audit): off | optional | required.
    MTLS_MODE: str = "off"
    # Guard production (gap-closing P2.7): con true il brain RIFIUTA di partire
    # se MTLS_MODE != required. Default false (dev/lab liberi).
    ENTERPRISE_STRICT: bool = False

    # Aegis Total (VirusTotal interno + code viewer)
    TOTAL_MAX_FILE_MB: int = 100
    TOTAL_MAX_ZIP_MB: int = 200
    TOTAL_MAX_FILES_PER_ZIP: int = 2000
    TOTAL_RETENTION_DAYS: int = 7

    # Data retention in giorni (configurabile — decisioni M0 Fase 1).
    # Enforcement (purge job) in Fase 8/9; qui solo perimetro configurabile.
    RETENTION_TELEMETRY_DAYS: int = 14
    RETENTION_ALERTS_DAYS: int = 90
    RETENTION_AUDIT_DAYS: int = 365
    RETENTION_SYSLOG_DAYS: int = 30
    RETENTION_ENABLED: bool = False

    # Dedup event_id (Fase 4): TTL in Redis, fallback in memoria 20k.
    DEDUP_TTL_SECONDS: int = 86400
    DEDUP_CAPACITY: int = 20000

    # Anti flood (Fase 1): ceiling eventi/min per agente. Default 10000 —
    # ordini di grandezza sopra il tasso reale di un sensore, sotto una tempesta.
    APP_EVENTS_PER_MIN: int = 10000

    @field_validator(
        "RETENTION_TELEMETRY_DAYS",
        "RETENTION_ALERTS_DAYS",
        "RETENTION_AUDIT_DAYS",
        "RETENTION_SYSLOG_DAYS",
        mode="before",
    )
    @classmethod
    def _positive_retention(cls, v) -> int:
        iv = int(v)
        if iv <= 0:
            raise ValueError("retention days must be positive")
        return iv

    @model_validator(mode="after")
    def validate_secrets(self):
        if not self.DEBUG:
            if not self.JWT_SECRET or len(self.JWT_SECRET) < 32:
                raise ValueError("JWT_SECRET must be at least 32 characters in production")
            if not self.AGENT_ENROLL_KEY or len(self.AGENT_ENROLL_KEY) < 16:
                raise ValueError("AGENT_ENROLL_KEY must be at least 16 characters in production")
            if not self.AEGIS_API_KEY or len(self.AEGIS_API_KEY) < 32:
                raise ValueError("AEGIS_API_KEY must be at least 32 characters in production")
            if not self.MASTER_KEY_B64:
                raise ValueError("MASTER_KEY_B64 is required in production")
            try:
                if len(base64.b64decode(self.MASTER_KEY_B64, validate=True)) != 32:
                    raise ValueError
            except Exception as exc:
                raise ValueError("MASTER_KEY_B64 must decode to exactly 32 bytes") from exc
            insecure_markers = ("change-me", "replace-with", "password", "for_v3.0.0")
            for name in ("JWT_SECRET", "AGENT_ENROLL_KEY", "AEGIS_API_KEY", "REDIS_PASSWORD"):
                value = getattr(self, name, None)
                if value and any(marker in value.lower() for marker in insecure_markers):
                    raise ValueError(f"{name} contains an insecure placeholder")
        return self

settings = Settings()
