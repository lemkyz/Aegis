from dataclasses import dataclass
from typing import Literal

from aegis.config.settings import Settings


ModelRequestRole = Literal["primary", "verifier"]


@dataclass(frozen=True, slots=True)
class ModelRequestConfig:
    role: ModelRequestRole
    profile: str
    timeout_seconds: float
    max_retries: int
    max_tokens: int


_PROFILE_TOKEN_LIMITS = {
    "fast": {
        "primary": 900,
        "verifier": 700,
    },
    "balanced": {
        "primary": 1600,
        "verifier": 1200,
    },
    "thorough": {
        "primary": 2400,
        "verifier": 1800,
    },
}


def _profile_timeout(
    settings: Settings,
) -> float:
    timeout = settings.ai_request_timeout_seconds

    if settings.ai_request_profile == "fast":
        return min(timeout, 45.0)

    if settings.ai_request_profile == "thorough":
        return max(timeout, 180.0)

    return timeout


def _profile_retries(
    settings: Settings,
) -> int:
    retries = settings.ai_max_retries

    if settings.ai_request_profile == "fast":
        return 0

    if settings.ai_request_profile == "thorough":
        return max(retries, 1)

    return retries


def resolve_model_request_config(
    settings: Settings,
    *,
    role: ModelRequestRole,
) -> ModelRequestConfig:
    if role == "primary":
        explicit_timeout = (
            settings.ai_primary_timeout_seconds
        )
        explicit_retries = (
            settings.ai_primary_max_retries
        )
        explicit_tokens = (
            settings.ai_primary_max_tokens
        )
    else:
        explicit_timeout = (
            settings.ai_verifier_timeout_seconds
        )
        explicit_retries = (
            settings.ai_verifier_max_retries
        )
        explicit_tokens = (
            settings.ai_verifier_max_tokens
        )

    timeout_seconds = (
        explicit_timeout
        if explicit_timeout is not None
        else _profile_timeout(settings)
    )

    max_retries = (
        explicit_retries
        if explicit_retries is not None
        else _profile_retries(settings)
    )

    max_tokens = (
        explicit_tokens
        if explicit_tokens is not None
        else _PROFILE_TOKEN_LIMITS[
            settings.ai_request_profile
        ][role]
    )

    return ModelRequestConfig(
        role=role,
        profile=settings.ai_request_profile,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
        max_tokens=max_tokens,
    )
