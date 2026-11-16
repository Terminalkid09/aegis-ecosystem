from __future__ import annotations
import secrets
import sys
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings
from loguru import logger


class Settings(BaseSettings):
    # App
    APP_NAME: str = "Kraken"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = ""
    INTERNAL_API_KEY: str = ""
    ALLOW_REGISTRATION: bool = False
    # Mounted behind Caddy at /kraken in the Aegis stack; empty = standalone.
    PUBLIC_BASE_PATH: str = ""

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://kraken:kraken_pass@localhost:5432/krakendb"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_PASSWORD: Optional[str] = None

    # JWT
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_EXPIRE_MINUTES: int = 60 * 24 * 7
    JWT_ISSUER: str = "kraken"
    # Delegated login from the Aegis Brain. The assertion is signed with a
    # dedicated secret (never the Brain JWT key) and exchanged exactly once.
    KRAKEN_SSO_ENABLED: bool = False
    KRAKEN_SSO_SECRET: str = ""
    KRAKEN_SSO_ISSUER: str = "aegis-brain"
    KRAKEN_SSO_AUDIENCE: str = "kraken"

    # Docker sandbox
    SANDBOX_IMAGE: str = "kraken_sandbox"
    SANDBOX_MAX_LIFETIME: int = 300
    # Legacy: accepted for existing .env files; sandboxes now use network_mode=none.
    SANDBOX_NETWORK: str = "kraken_sandbox_net"
    SANDBOX_MAX_CONCURRENT: int = 20
    SANDBOX_BROKER_URL: str = "http://kraken_sandbox_broker:8100"
    SANDBOX_BROKER_TOKEN: str = ""
    MALWARE_MAX_FILE_BYTES: int = 64 * 1024 * 1024
    MALWARE_MAX_SESSION_BYTES: int = 256 * 1024 * 1024
    MALWARE_RETENTION_DAYS: int = 30
    MALWARE_MAX_TOTAL_BYTES: int = 5 * 1024 * 1024 * 1024

    # Paths — configurabili
    DATA_DIR: str = "/app/data"
    MALWARE_DIR: str = "/app/data/malware"
    LOGS_DIR: str = "/app/data/logs"
    SIEM_LOG_FILE: str = "/app/data/logs/siem.jsonl"
    GEOIP_DB_PATH: str = "/app/data/GeoLite2-City.mmdb"

    # Aegis control plane (Kraken → Brain)
    AEGIS_INGEST_ENABLED: bool = False
    AEGIS_INGEST_URL: str = ""
    AEGIS_INGEST_KEY: str = ""
    AEGIS_INGEST_SECRET: str = ""
    AEGIS_INGEST_TIMEOUT_S: float = 5.0
    # Transactional outbox worker. The defaults drain quickly without hammering
    # Aegis; max attempts prevents a poison event from looping forever.
    AEGIS_OUTBOX_POLL_INTERVAL_S: float = 2.0
    AEGIS_OUTBOX_BATCH_SIZE: int = 50
    AEGIS_OUTBOX_MAX_ATTEMPTS: int = 8
    AEGIS_OUTBOX_BACKOFF_BASE_S: float = 2.0
    AEGIS_OUTBOX_BACKOFF_MAX_S: float = 300.0
    AEGIS_OUTBOX_STALE_AFTER_S: int = 300

    # Telegram
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    TELEGRAM_CHAT_ID: Optional[str] = None

    # Sensors
    SSH_SENSOR_PORT: int = 2222
    HTTP_SENSOR_PORT: int = 8080
    FTP_SENSOR_PORT: int = 2121
    TELNET_SENSOR_PORT: int = 2323

    # Rate limiting
    RATE_LIMIT_LOGIN: str = "10/minute"
    RATE_LIMIT_INGEST: str = "200/minute"
    RATE_LIMIT_DEFAULT: str = "60/minute"
    RATE_LIMIT_EXPORT: str = "30/minute"

    # CORS — comma-separated origins, e.g. "https://mydomain.com,https://other.com"
    CORS_ORIGINS: str = "http://localhost:8000"

    # Body limit
    MAX_BODY_SIZE: int = 65_536

    # Sandbox API (sensors -> app via HTTP instead of Docker socket)
    SANDBOX_API_URL: str = "http://kraken_app:8000/api/v1/containers"

    # Security
    BCRYPT_ROUNDS: int = 12

    class Config:
        env_file = ".env"
        case_sensitive = True

    def validate_secrets(self):
        """Auto-generate secrets only in DEBUG; refuse placeholders and weak keys."""
        markers = ("changeme", "change-me", "replace-with", "please_change", "example", "dummy")
        for name, value in (("SECRET_KEY", self.SECRET_KEY), ("INTERNAL_API_KEY", self.INTERNAL_API_KEY)):
            if value and any(marker in value.lower() for marker in markers):
                print(f"❌ {name} contains a known placeholder; generate a random value.")
                sys.exit(1)
        if not self.SECRET_KEY or len(self.SECRET_KEY) < 32:
            if self.DEBUG:
                self.SECRET_KEY = secrets.token_hex(32)
                logger.warning("Auto-generated SECRET_KEY for DEBUG mode (value not logged).")
            else:
                print("❌ SECRET_KEY not configured. Set a random value of at least 32 characters.")
                sys.exit(1)
        if not self.INTERNAL_API_KEY or len(self.INTERNAL_API_KEY) < 32:
            if self.DEBUG:
                self.INTERNAL_API_KEY = secrets.token_hex(32)
                logger.warning("Auto-generated INTERNAL_API_KEY for DEBUG mode.")
            else:
                print("❌ INTERNAL_API_KEY not configured. Set a random value of at least 32 characters.")
                sys.exit(1)
        if self.AEGIS_INGEST_ENABLED:
            if not self.AEGIS_INGEST_URL or not self.AEGIS_INGEST_KEY:
                print("❌ AEGIS_INGEST_URL and AEGIS_INGEST_KEY are required when AEGIS_INGEST_ENABLED=true.")
                sys.exit(1)
            if len(self.AEGIS_INGEST_SECRET) < 32:
                print("❌ AEGIS_INGEST_SECRET must be at least 32 characters.")
                sys.exit(1)
        if self.KRAKEN_SSO_ENABLED:
            if len(self.KRAKEN_SSO_SECRET) < 32:
                print("❌ KRAKEN_SSO_SECRET must be at least 32 characters when KRAKEN_SSO_ENABLED=true.")
                sys.exit(1)
            if self.KRAKEN_SSO_SECRET == self.SECRET_KEY:
                print("❌ KRAKEN_SSO_SECRET must be distinct from SECRET_KEY.")
                sys.exit(1)

    def base_path(self) -> str:
        """Normalised public prefix ('' or '/kraken')."""
        path = (self.PUBLIC_BASE_PATH or "").strip().rstrip("/")
        if path and not path.startswith("/"):
            path = "/" + path
        return path

    def get_cors_origins(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    def ensure_dirs(self):
        Path(self.DATA_DIR).mkdir(parents=True, exist_ok=True)
        Path(self.MALWARE_DIR).mkdir(parents=True, exist_ok=True)
        Path(self.LOGS_DIR).mkdir(parents=True, exist_ok=True)


settings = Settings()
