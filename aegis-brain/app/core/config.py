from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, model_validator
from typing import Optional
import sys

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App Config
    APP_NAME: str = "Aegis-Brain"
    DEBUG: bool = False
    ALLOWED_ORIGINS: str = "http://localhost:3000"

    # Database & Redis
    DATABASE_URL: str = "postgresql+asyncpg://postgres:password@localhost:5432/aegis"
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
    AI_DEV_FALLBACK: bool = True

    # Security Keys
    AEGIS_API_KEY: Optional[str] = None
    AGENT_ENROLL_KEY: Optional[str] = None

    @model_validator(mode="after")
    def validate_secrets(self):
        if not self.DEBUG:
            if not self.JWT_SECRET or len(self.JWT_SECRET) < 32:
                print("ERROR: JWT_SECRET must be at least 32 characters")
                sys.exit(1)
            if not self.AGENT_ENROLL_KEY or len(self.AGENT_ENROLL_KEY) < 16:
                print("ERROR: AGENT_ENROLL_KEY must be at least 16 characters")
                sys.exit(1)
            if not self.MASTER_KEY_B64:
                print("ERROR: MASTER_KEY_B64 is required")
                sys.exit(1)
        return self

settings = Settings()
