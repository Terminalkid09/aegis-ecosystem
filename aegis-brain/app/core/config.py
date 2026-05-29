from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
from typing import Optional

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # App Config
    APP_NAME: str = "Aegis-Brain"
    DEBUG: bool = False
    ALLOWED_ORIGINS: str = "http://localhost:3000"

    # Database & Redis
    DATABASE_URL: str = "postgresql+asyncpg://postgres:password@localhost:5432/aegis"
    
    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def ensure_asyncpg_driver(cls, v: str) -> str:
        if v.startswith("postgresql://"):
            return v.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v

    REDIS_URL: str = "redis://localhost:6379"
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379

    # JWT Security
    JWT_SECRET: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60

    # Encryption (Envelope)
    MASTER_KEY_B64: Optional[str] = None

    # OSINT Providers
    SHODAN_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    OSINT_CACHE_TTL: int = 86400  # 24 hours

    # AI Config
    OLLAMA_URL: Optional[str] = None
    OLLAMA_DEFAULT_MODEL: str = "aegis-default"
    AI_RATE_LIMIT_PER_MIN: int = 20
    AI_DEV_FALLBACK: bool = True

    # Security Keys
    AEGIS_API_KEY: Optional[str] = None
    AGENT_ENROLL_KEY: str = "aegis-enrollment-token-2024"

settings = Settings()
