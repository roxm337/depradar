from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DEPRADAR_", env_file=".env", extra="ignore")

    database_url: str = "postgresql+psycopg://depradar:depradar@localhost:5432/depradar"
    bootstrap_token: SecretStr = SecretStr("")
    storage_dir: Path = Path("data/inventories")
    allowed_origin: str = "http://localhost:8000"
    secure_cookies: bool = False
    session_hours: int = Field(default=24, ge=1, le=168)
    upload_limit_bytes: int = Field(default=10 * 1024 * 1024, ge=1024, le=10 * 1024 * 1024)
    scanner_url: str = "http://scanner:8001"
    scanner_timeout_seconds: int = Field(default=180, ge=5, le=240)
    worker_poll_seconds: float = Field(default=2, ge=0.1)
    job_lease_seconds: int = Field(default=300, ge=270)
    max_job_attempts: int = Field(default=3, ge=1, le=10)
    osv_binary: str = "/usr/local/bin/osv-scanner"
    smtp_password: SecretStr = SecretStr("")
    telegram_bot_token: SecretStr = SecretStr("")
    telegram_api_base_url: str = "https://api.telegram.org"
    allow_insecure_smtp: bool = False
    dashboard_url: str = "http://localhost:8000"
    delivery_max_attempts: int = Field(default=5, ge=1, le=10)
    intelligence_refresh_hours: int = Field(default=24, ge=1, le=168)
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    kev_feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
