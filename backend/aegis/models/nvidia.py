from aegis.config.settings import Settings, get_settings
from aegis.models.openai_compatible_primary import (
    OpenAICompatibleSecurityModelClient,
)
from aegis.models.provider_config import (
    ModelProviderConfigurationError,
)


class NvidiaModelClient(
    OpenAICompatibleSecurityModelClient
):
    """
    Backward-compatible NVIDIA primary-model client.

    The security-review implementation is shared by all providers
    exposing an OpenAI-compatible chat-completions endpoint.
    """

    def __init__(
        self,
        settings: Settings | None = None,
    ) -> None:
        resolved_settings = settings or get_settings()

        if (
            resolved_settings.resolved_primary_provider
            != "nvidia"
        ):
            raise ModelProviderConfigurationError(
                "NvidiaModelClient requires the primary "
                "provider to be 'nvidia'."
            )

        super().__init__(resolved_settings)
