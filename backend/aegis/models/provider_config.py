from dataclasses import dataclass
from typing import Literal

from aegis.config.settings import Settings


ModelRole = Literal["primary", "verifier"]


class ModelProviderConfigurationError(ValueError):
    """
    Raised when a configured provider is missing a required model,
    credential, or endpoint.
    """


@dataclass(frozen=True, slots=True)
class ModelEndpointConfig:
    role: ModelRole
    provider: str
    model: str
    api_key: str
    base_url: str


def _required_value(
    value: str | None,
    *,
    variable_name: str,
    role: ModelRole,
    provider: str,
) -> str:
    normalized = value.strip() if value else ""

    if not normalized:
        raise ModelProviderConfigurationError(
            f"The {role} model provider {provider!r} requires "
            f"{variable_name}."
        )

    return normalized


def resolve_model_endpoint(
    settings: Settings,
    *,
    role: ModelRole,
    provider_override: str | None = None,
    model_override: str | None = None,
) -> ModelEndpointConfig:
    if role == "primary":
        provider = (
            provider_override
            or settings.resolved_primary_provider
        )
        model = (
            model_override
            or settings.resolved_primary_model
        )
    else:
        provider = (
            provider_override
            or settings.resolved_verifier_provider
        )
        model = (
            model_override
            or settings.resolved_verifier_model
        )

    provider = provider.strip().lower()

    model = _required_value(
        model,
        variable_name=(
            "AI_PRIMARY_MODEL"
            if role == "primary"
            else "AI_VERIFIER_MODEL"
        ),
        role=role,
        provider=provider,
    )

    if provider == "nvidia":
        api_key = _required_value(
            settings.nvidia_api_key,
            variable_name="NVIDIA_API_KEY",
            role=role,
            provider=provider,
        )
        base_url = _required_value(
            settings.nvidia_base_url,
            variable_name="NVIDIA_BASE_URL",
            role=role,
            provider=provider,
        )

    elif provider == "openrouter":
        api_key = _required_value(
            settings.openrouter_api_key,
            variable_name="OPENROUTER_API_KEY",
            role=role,
            provider=provider,
        )
        base_url = _required_value(
            settings.openrouter_base_url,
            variable_name="OPENROUTER_BASE_URL",
            role=role,
            provider=provider,
        )

    elif provider == "groq":
        api_key = _required_value(
            settings.groq_api_key,
            variable_name="GROQ_API_KEY",
            role=role,
            provider=provider,
        )
        base_url = _required_value(
            settings.groq_base_url,
            variable_name="GROQ_BASE_URL",
            role=role,
            provider=provider,
        )

    elif provider == "openai_compatible":
        if role == "primary":
            api_key_value = settings.ai_primary_api_key
            base_url_value = settings.ai_primary_base_url
            api_key_name = "AI_PRIMARY_API_KEY"
            base_url_name = "AI_PRIMARY_BASE_URL"
        else:
            api_key_value = settings.ai_verifier_api_key
            base_url_value = settings.ai_verifier_base_url
            api_key_name = "AI_VERIFIER_API_KEY"
            base_url_name = "AI_VERIFIER_BASE_URL"

        api_key = _required_value(
            api_key_value,
            variable_name=api_key_name,
            role=role,
            provider=provider,
        )
        base_url = _required_value(
            base_url_value,
            variable_name=base_url_name,
            role=role,
            provider=provider,
        )

    else:
        raise ModelProviderConfigurationError(
            f"Provider configuration is not defined for "
            f"{provider!r}."
        )

    return ModelEndpointConfig(
        role=role,
        provider=provider,
        model=model,
        api_key=api_key,
        base_url=base_url.rstrip("/"),
    )
