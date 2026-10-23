"""
SentinelScan Core Configuration
Handles environment settings, safe defaults, and security bounds.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # Application
    APP_NAME: str = "SentinelScan"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    API_V1_PREFIX: str = "/api"

    # Database
    DATABASE_URL: str = "sqlite:///./sentinelscan.db"

    # Security & CORS
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    SECRET_KEY: str = "sentinelscan-insecure-dev-secret-key-change-in-prod"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24

    # Scanner Operational & SSRF Protection Limits
    SCAN_DEFAULT_TIMEOUT_SECONDS: float = 10.0
    SCAN_MAX_TIMEOUT_SECONDS: float = 30.0
    SCAN_MAX_REDIRECTS: int = 5
    SCAN_MAX_RESPONSE_BYTES: int = 2 * 1024 * 1024  # 2MB max download per probe
    MAX_CONCURRENT_SCANS: int = 5
    SCAN_GLOBAL_TIMEOUT_SECONDS: float = 90.0

    # SSRF & Target Policy
    ALLOW_PRIVATE_IPS: bool = False  # NEVER allow private/loopback/cloud metadata in normal operation
    BLOCKED_PORTS: list[int] = [22, 23, 25, 53, 110, 135, 137, 138, 139, 445, 1433, 3306, 3389, 5432, 6379, 27017]
    ALLOWED_PORTS: list[int] = [80, 443, 8080, 8443]

    # AI Explanation Engine (Optional - disabled by default)
    AI_ENABLED: bool = False
    AI_PROVIDER: str | None = None  # e.g. "openai", "gemini"
    AI_API_KEY: str | None = None


settings = Settings()
