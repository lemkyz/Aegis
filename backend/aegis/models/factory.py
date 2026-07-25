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
