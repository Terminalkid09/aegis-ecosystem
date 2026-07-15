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

    # Docker sandbox
    SANDBOX_IMAGE: str = "kraken_sandbox"
    SANDBOX_MAX_LIFETIME: int = 300
    SANDBOX_NETWORK: str = "kraken_sandbox_net"
    SANDBOX_MAX_CONCURRENT: int = 20

    # Paths — configurabili
    DATA_DIR: str = "/app/data"
    MALWARE_DIR: str = "/app/data/malware"
    LOGS_DIR: str = "/app/data/logs"
    SIEM_LOG_FILE: str = "/app/data/logs/siem.jsonl"
    GEOIP_DB_PATH: str = "/app/data/GeoLite2-City.mmdb"

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
        """Auto-generate secrets if not configured, refuse weak keys in production."""
        if not self.SECRET_KEY or len(self.SECRET_KEY) < 32:
            if self.DEBUG:
                self.SECRET_KEY = secrets.token_hex(32)
                logger.warning(f"Auto-generated SECRET_KEY for DEBUG mode: {self.SECRET_KEY}")
            else:
                gen = secrets.token_hex(32)
                print(f"❌ SECRET_KEY not configured. Set in .env or use this generated key:\n   SECRET_KEY={gen}")
                sys.exit(1)
        if not self.INTERNAL_API_KEY or len(self.INTERNAL_API_KEY) < 32:
            if self.DEBUG:
                self.INTERNAL_API_KEY = secrets.token_hex(32)
                logger.warning(f"Auto-generated INTERNAL_API_KEY for DEBUG mode")
            else:
                gen = secrets.token_hex(32)
                print(f"❌ INTERNAL_API_KEY not configured. Set in .env or use this generated key:\n   INTERNAL_API_KEY={gen}")
                sys.exit(1)

    def get_cors_origins(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    def ensure_dirs(self):
        Path(self.DATA_DIR).mkdir(parents=True, exist_ok=True)
        Path(self.MALWARE_DIR).mkdir(parents=True, exist_ok=True)
        Path(self.LOGS_DIR).mkdir(parents=True, exist_ok=True)


settings = Settings()
