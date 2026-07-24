import os
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_security_memory_database_path() -> Path:
    xdg_data_home = os.environ.get("XDG_DATA_HOME")

    if xdg_data_home:
        data_root = Path(
            xdg_data_home
        ).expanduser()
    else:
        data_root = (
            Path.home()
            / ".local"
            / "share"
        )

    return (
        data_root
        / "aegis"
        / "security-memory.sqlite3"
    )


class Settings(BaseSettings):
    app_name: str = "Aegis"
    app_version: str = "0.1.0"

    security_memory_database_path: Path = Field(
        default_factory=(
            _default_security_memory_database_path
        ),
    )

    aegis_fingerprint_key: str = Field(
        min_length=32,
    )

    nvidia_api_key: str
    nvidia_base_url: str = "https://integrate.api.nvidia.com/v1"
    nvidia_model: str = "openai/gpt-oss-120b"

    ai_request_timeout_seconds: float = Field(
        default=45.0,
        ge=5.0,
        le=600.0,
    )
    ai_max_retries: int = Field(
        default=0,
        ge=0,
        le=3,
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
