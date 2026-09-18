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
    # Versione della piattaforma: una sola fonte per OpenAPI, endpoint root e
    # dashboard (prima era scritta a mano in due punti e la UI mostrava una
    # versione diversa da quella vera). Si alza qui, in un posto solo.
    APP_VERSION: str = "4.0.0"
    OLLAMA_URL: Optional[str] = None
    OLLAMA_DEFAULT_MODEL: str = "aegis-default"
    # Audit: allowlist modelli caricabili via API (niente pull arbitrari).
    # Vuoto = solo default + tinyllama (uso interno report).
    OLLAMA_ALLOWED_MODELS: str = ""
    # --- Provider AI pluggabile ---------------------------------------
    # auto      = ollama se configurato, altrimenti gemini/openai se la
    #             chiave esiste, altrimenti disabled (nessuna chiamata)
    # disabled  = AI spenta per scelta: gli endpoint rispondono con stato
    #             esplicito, mai testo finto
    # ollama    = modello locale (o server potente in rete via OLLAMA_URL)
    # gemini    = Google AI Studio (free tier), chiave dalla dashboard
    # openai    = qualunque endpoint OpenAI-compatibile (OPENAI_BASE_URL)
    AI_PROVIDER: str = "auto"
    # Vuoto = default del provider (OLLAMA_DEFAULT_MODEL / GEMINI_MODEL / ...)
    AI_MODEL: str = ""
    # Consenso all'arricchimento automatico degli alert con provider CLOUD.
    # false = con Gemini/OpenAI il contenuto (anonimizzato) esce SOLO su
    # richiesta dell'operatore; i provider locali (ollama) sono sempre
    # automatici perche' nulla lascia la rete. Prima era true, che con una
    # chiave cloud configurata significava esfiltrazione senza opt-in:
    # impostabile anche dalla dashboard (app_settings.ai.automatic_enrich).
    AI_AUTOMATIC_ENRICH: bool = False
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.0-flash"
    OPENAI_API_KEY: str = ""
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    OPENAI_MODEL: str = "gpt-4o-mini"
    AI_RATE_LIMIT_PER_MIN: int = 20
    # Enterprise default: NO silent stub. In DEBUG lab it may fallback for DX,
    # in prod it must return an explicit degraded error instead of fake AI text.
    AI_DEV_FALLBACK: bool = False

    # Security Keys
    AEGIS_API_KEY: Optional[str] = None
    AGENT_ENROLL_KEY: Optional[str] = None
    # Audit: registrazione aperta (lab) vs solo-admin (enterprise).
    # False = POST /auth/register richiede JWT admin (niente self-service).
    ALLOW_OPEN_REGISTRATION: bool = True

    # Automazione SOAR idempotente (audit L1): un playbook esegue le sue azioni
    # una sola volta per (playbook, alert) entro questa finestra. Evita che un
    # alert non risolto ri-attivi contenimento (kill/isolate) ogni minuto.
    PLAYBOOK_IDEMPOTENCY_TTL_S: int = 86400

    # Rate limiting (audit S1). Lo storage in memoria vale solo per il singolo
    # processo uvicorn: in pilot/HA va puntato a Redis (es. redis://...).
    RATE_LIMIT_STORAGE_URI: Optional[str] = None
    # Dietro reverse proxy (Caddy) request.client.host è SEMPRE l'IP del proxy:
    # senza questo flag tutti i limiti per-IP collassano in un bucket unico
    # condiviso da tutti gli utenti. Attivare solo se l'ingress è il nostro proxy.
    RATE_LIMIT_TRUST_FORWARDED_FOR: bool = False

    # Detection canary (M4 Fase 5): rule_id separati da virgola in log-only.
    RULE_CANARY_IDS: str = ""
    # Audit F-02: azioni playbook "script" = shell sul server Brain.
    # Default OFF: abilitarle solo in enterprise con approvazione documentata.
    PLAYBOOK_SCRIPT_ENABLED: bool = False

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

    # Aegis Total (analisi statica: nessun decompilatore, solo struttura/stringhe/IOC)
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
    # Audit F-05: retention attiva di default (con guardie: backup verificato
    # e audit mai auto-purgati in run_retention_purge). Disattivare solo in lab.
    RETENTION_ENABLED: bool = True

    # Dedup event_id (Fase 4): TTL in Redis, fallback in memoria 20k.
    DEDUP_TTL_SECONDS: int = 86400
    DEDUP_CAPACITY: int = 20000

    # Anti flood (Fase 1): ceiling eventi/min per agente. Default 10000 —
    # ordini di grandezza sopra il tasso reale di un sensore, sotto una tempesta.
    APP_EVENTS_PER_MIN: int = 10000

    # ── SIEM v4: ingestione multi-sorgente ──────────────────────────────────
    # `SIEM_ENABLED` spegne l'intero percorso di ingestione esterna (parser,
    # store, detection Sigma) lasciando intatta la pipeline degli agenti.
    SIEM_ENABLED: bool = True
    SIEM_RETENTION_DAYS: int = 30
    # Dedup eventi per `event_id` (hash sorgente+payload): un relay che
    # reinvia la stessa riga non crea un alert duplicato.
    SIEM_EVENT_DEDUP_TTL_S: int = 86400
    # Bound sull'ingestione: oltre, il payload viene troncato dichiarandolo.
    SIEM_MAX_EVENTS_PER_REQUEST: int = 5000
    SIEM_SEARCH_MAX_LIMIT: int = 500
    # Listener syslog (UDP+TCP). Default OFF: si abilita esplicitamente, così
    # nessuna porta in ascolto compare per caso in un deploy.
    SYSLOG_ENABLED: bool = False
    # Secure by default: in loopback. Per ricevere da rsyslog/firewall su altri
    # host va impostato esplicitamente a 0.0.0.0 (consapevolmente, dietro firewall).
    SYSLOG_BIND: str = "127.0.0.1"
    SYSLOG_PORT: int = 5514
    SYSLOG_TCP_ENABLED: bool = True

    @field_validator(
        "RETENTION_TELEMETRY_DAYS",
        "RETENTION_ALERTS_DAYS",
        "RETENTION_AUDIT_DAYS",
        "RETENTION_SYSLOG_DAYS",
        "SIEM_RETENTION_DAYS",
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
            insecure_markers = ("change-me", "replace-with", "password", "for_v4.0.0")
            for name in ("JWT_SECRET", "AGENT_ENROLL_KEY", "AEGIS_API_KEY", "REDIS_PASSWORD"):
                value = getattr(self, name, None)
                if value and any(marker in value.lower() for marker in insecure_markers):
                    raise ValueError(f"{name} contains an insecure placeholder")
            # Audit F-01: registrazione self-service vietata fuori dal lab.
            if self.ALLOW_OPEN_REGISTRATION:
                raise ValueError("ALLOW_OPEN_REGISTRATION must be false in production")
        # Audit F-01: vale anche col flag enterprise esplicito in lab.
        if self.ENTERPRISE_STRICT and self.ALLOW_OPEN_REGISTRATION:
            raise ValueError("ALLOW_OPEN_REGISTRATION must be false when ENTERPRISE_STRICT is true")
        # Audit F-03: profili enterprise senza mTLS required non partono.
        if self.ENTERPRISE_STRICT and (self.MTLS_MODE or "").lower() != "required":
            raise ValueError("ENTERPRISE_STRICT requires MTLS_MODE=required")
        return self

settings = Settings()
