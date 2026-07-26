from aegis.config.settings import Settings, get_settings
from aegis.models.nvidia import NvidiaModelClient
from aegis.models.nvidia_verifier import NvidiaVerifierClient
from aegis.models.openai_compatible_primary import (
    OpenAICompatibleSecurityModelClient,
)
from aegis.models.openai_compatible_verifier import (
    OpenAICompatibleVerifierClient,
)
from aegis.models.protocol import (
    SecurityModelClient,
    SecurityVerifierClient,
)


class UnsupportedModelProviderError(ValueError):
    """Raised when model routing names an unsupported provider."""


SUPPORTED_MODEL_PROVIDERS = frozenset(
    {
        "groq",
        "nvidia",
        "openai_compatible",
        "openrouter",
    }
)


def _validate_provider(
    *,
    provider: str,
    role: str,
) -> str:
    normalized = provider.strip().lower()

    if not normalized:
        raise UnsupportedModelProviderError(
            f"The {role} model provider cannot be empty."
        )

    if normalized not in SUPPORTED_MODEL_PROVIDERS:
        supported = ", ".join(
            sorted(SUPPORTED_MODEL_PROVIDERS)
        )
        raise UnsupportedModelProviderError(
            f"Unsupported {role} model provider "
            f"{normalized!r}. Supported providers: {supported}."
        )

    return normalized


def create_primary_model_client(
    settings: Settings | None = None,
) -> SecurityModelClient:
    resolved_settings = settings or get_settings()

    provider = _validate_provider(
        provider=(
            resolved_settings.resolved_primary_provider
        ),
        role="primary",
    )

    if provider == "nvidia":
        return NvidiaModelClient(resolved_settings)

    return OpenAICompatibleSecurityModelClient(
        resolved_settings
    )


def create_verifier_model_client(
    settings: Settings | None = None,
) -> SecurityVerifierClient:
    resolved_settings = settings or get_settings()

    provider = _validate_provider(
        provider=(
            resolved_settings.resolved_verifier_provider
        ),
        role="verifier",
    )

    if provider == "nvidia":
        return NvidiaVerifierClient(resolved_settings)

    return OpenAICompatibleVerifierClient(
        resolved_settings
    )



class InvalidFallbackRouteError(ValueError):
    """Raised when an explicit fallback duplicates its active route."""


def _same_route(
    *,
    active_provider: str,
    active_model: str,
    fallback_provider: str,
    fallback_model: str,
) -> bool:
    return (
        active_provider.strip().lower()
        == fallback_provider.strip().lower()
        and active_model.strip().lower()
        == fallback_model.strip().lower()
    )


def create_primary_fallback_model_client(
    settings: Settings | None = None,
) -> SecurityModelClient | None:
    resolved_settings = settings or get_settings()

    provider = (
        resolved_settings.resolved_primary_fallback_provider
    )
    model = (
        resolved_settings.resolved_primary_fallback_model
    )

    if provider is None and model is None:
        return None

    if provider is None or model is None:
        raise InvalidFallbackRouteError(
            "Primary fallback requires both "
            "AI_PRIMARY_FALLBACK_PROVIDER and "
            "AI_PRIMARY_FALLBACK_MODEL."
        )

    provider = _validate_provider(
        provider=provider,
        role="primary fallback",
    )

    if _same_route(
        active_provider=(
            resolved_settings.resolved_primary_provider
        ),
        active_model=(
            resolved_settings.resolved_primary_model
        ),
        fallback_provider=provider,
        fallback_model=model,
    ):
        raise InvalidFallbackRouteError(
            "Primary fallback route must differ from "
            "the active primary route."
        )

    return OpenAICompatibleSecurityModelClient(
        resolved_settings,
        provider_override=provider,
        model_override=model,
    )


def create_verifier_fallback_model_client(
    settings: Settings | None = None,
) -> SecurityVerifierClient | None:
    resolved_settings = settings or get_settings()

    provider = (
        resolved_settings.resolved_verifier_fallback_provider
    )
    model = (
        resolved_settings.resolved_verifier_fallback_model
    )

    if provider is None and model is None:
        return None

    if provider is None or model is None:
        raise InvalidFallbackRouteError(
            "Verifier fallback requires both "
            "AI_VERIFIER_FALLBACK_PROVIDER and "
            "AI_VERIFIER_FALLBACK_MODEL."
        )

    provider = _validate_provider(
        provider=provider,
        role="verifier fallback",
    )

    if _same_route(
        active_provider=(
            resolved_settings.resolved_verifier_provider
        ),
        active_model=(
            resolved_settings.resolved_verifier_model
        ),
        fallback_provider=provider,
        fallback_model=model,
    ):
        raise InvalidFallbackRouteError(
            "Verifier fallback route must differ from "
            "the active verifier route."
        )

    return OpenAICompatibleVerifierClient(
        resolved_settings,
        provider_override=provider,
        model_override=model,
    )
