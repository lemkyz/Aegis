import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

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

    # Legacy NVIDIA configuration.
    #
    # These fields remain supported while Aegis transitions to the
    # provider-independent AI_PRIMARY_* / AI_VERIFIER_* contract.
    nvidia_api_key: str | None = None
    nvidia_base_url: str = "https://integrate.api.nvidia.com/v1"
    nvidia_model: str = "openai/gpt-oss-120b"
    nvidia_verifier_model: str | None = None

    # OpenRouter provider configuration.
    openrouter_api_key: str | None = None
    openrouter_base_url: str = "https://openrouter.ai/api/v1"

    # Groq provider configuration.
    groq_api_key: str | None = None
    groq_base_url: str = "https://api.groq.com/openai/v1"

    # Role-specific custom OpenAI-compatible configuration.
    ai_primary_api_key: str | None = None
    ai_primary_base_url: str | None = None
    ai_verifier_api_key: str | None = None
    ai_verifier_base_url: str | None = None

    # Provider-independent model routing configuration.
    #
    # Explicit AI_* model values take precedence over the legacy
    # NVIDIA_* model values. Provider-specific credentials and
    # transports are introduced by the following Step 43 phases.
    ai_primary_provider: str = "nvidia"
    ai_primary_model: str | None = None
    ai_verifier_provider: str | None = None
    ai_verifier_model: str | None = None

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

    ai_request_profile: Literal[
        "fast",
        "balanced",
        "thorough",
    ] = "balanced"

    ai_primary_timeout_seconds: float | None = Field(
        default=None,
        ge=5.0,
        le=600.0,
    )
    ai_verifier_timeout_seconds: float | None = Field(
        default=None,
        ge=5.0,
        le=600.0,
    )

    ai_primary_max_retries: int | None = Field(
        default=None,
        ge=0,
        le=3,
    )
    ai_verifier_max_retries: int | None = Field(
        default=None,
        ge=0,
        le=3,
    )

    ai_primary_max_tokens: int | None = Field(
        default=None,
        ge=128,
        le=16_384,
    )
    ai_verifier_max_tokens: int | None = Field(
        default=None,
        ge=128,
        le=16_384,
    )

    @property
    def resolved_primary_provider(self) -> str:
        return self.ai_primary_provider.strip().lower()

    @property
    def resolved_primary_model(self) -> str:
        configured_model = self.ai_primary_model or self.nvidia_model
        return configured_model.strip()

    @property
    def resolved_verifier_provider(self) -> str:
        configured_provider = (
            self.ai_verifier_provider
            or self.resolved_primary_provider
        )
        return configured_provider.strip().lower()

    @property
    def resolved_verifier_model(self) -> str:
        configured_model = (
            self.ai_verifier_model
            or self.nvidia_verifier_model
            or self.resolved_primary_model
        )
        return configured_model.strip()

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
