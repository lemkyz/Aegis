from aegis.config.settings import Settings, get_settings
from aegis.models.openai_compatible_verifier import (
    OpenAICompatibleVerifierClient,
)
from aegis.models.provider_config import (
    ModelProviderConfigurationError,
)


class NvidiaVerifierClient(
    OpenAICompatibleVerifierClient
):
    """
    Backward-compatible NVIDIA verifier client.

    The independent-verification implementation is shared by all
    providers exposing an OpenAI-compatible endpoint.
    """

    def __init__(
        self,
        settings: Settings | None = None,
    ) -> None:
        resolved_settings = settings or get_settings()

        if (
            resolved_settings.resolved_verifier_provider
            != "nvidia"
        ):
            raise ModelProviderConfigurationError(
                "NvidiaVerifierClient requires the verifier "
                "provider to be 'nvidia'."
            )

        super().__init__(resolved_settings)
