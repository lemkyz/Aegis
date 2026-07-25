import pytest

from aegis.config.settings import Settings
from aegis.models.factory import (
    UnsupportedModelProviderError,
    create_primary_model_client,
    create_verifier_model_client,
)
from aegis.models.nvidia import NvidiaModelClient
from aegis.models.nvidia_verifier import NvidiaVerifierClient
from aegis.models.openai_compatible_primary import (
    OpenAICompatibleSecurityModelClient,
)
from aegis.models.openai_compatible_verifier import (
    OpenAICompatibleVerifierClient,
)


BASE_SETTINGS = {
    "_env_file": None,
    "aegis_fingerprint_key": "f" * 32,
}


def test_factory_creates_nvidia_primary_client() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        nvidia_api_key="test-key",
        ai_primary_provider="nvidia",
        ai_primary_model="fake/primary",
    )

    client = create_primary_model_client(settings)

    assert isinstance(client, NvidiaModelClient)
    assert client.provider == "nvidia"
    assert client.model == "fake/primary"


def test_factory_creates_nvidia_verifier_client() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        nvidia_api_key="test-key",
        ai_primary_provider="nvidia",
        ai_primary_model="fake/primary",
        ai_verifier_provider="nvidia",
        ai_verifier_model="fake/verifier",
    )

    client = create_verifier_model_client(settings)

    assert isinstance(client, NvidiaVerifierClient)
    assert client.provider == "nvidia"
    assert client.model == "fake/verifier"


@pytest.mark.parametrize(
    (
        "provider",
        "credential_fields",
    ),
    [
        (
            "openrouter",
            {
                "openrouter_api_key": "test-key",
            },
        ),
        (
            "groq",
            {
                "groq_api_key": "test-key",
            },
        ),
        (
            "openai_compatible",
            {
                "ai_primary_api_key": "test-key",
                "ai_primary_base_url": (
                    "https://primary.example/v1"
                ),
            },
        ),
    ],
)
def test_factory_creates_generic_primary_client(
    provider,
    credential_fields,
) -> None:
    settings = Settings(
        **BASE_SETTINGS,
        ai_primary_provider=provider,
        ai_primary_model="fake/primary",
        **credential_fields,
    )

    client = create_primary_model_client(settings)

    assert isinstance(
        client,
        OpenAICompatibleSecurityModelClient,
    )
    assert not isinstance(client, NvidiaModelClient)
    assert client.provider == provider
    assert client.model == "fake/primary"


@pytest.mark.parametrize(
    (
        "provider",
        "credential_fields",
    ),
    [
        (
            "openrouter",
            {
                "openrouter_api_key": "test-key",
            },
        ),
        (
            "groq",
            {
                "groq_api_key": "test-key",
            },
        ),
        (
            "openai_compatible",
            {
                "ai_verifier_api_key": "test-key",
                "ai_verifier_base_url": (
                    "https://verifier.example/v1"
                ),
            },
        ),
    ],
)
def test_factory_creates_generic_verifier_client(
    provider,
    credential_fields,
) -> None:
    settings = Settings(
        **BASE_SETTINGS,
        nvidia_api_key="primary-key",
        ai_primary_provider="nvidia",
        ai_primary_model="fake/primary",
        ai_verifier_provider=provider,
        ai_verifier_model="fake/verifier",
        **credential_fields,
    )

    client = create_verifier_model_client(settings)

    assert isinstance(
        client,
        OpenAICompatibleVerifierClient,
    )
    assert not isinstance(client, NvidiaVerifierClient)
    assert client.provider == provider
    assert client.model == "fake/verifier"


def test_factory_rejects_unknown_primary_provider() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        ai_primary_provider="unknown-provider",
        ai_primary_model="fake/primary",
    )

    with pytest.raises(
        UnsupportedModelProviderError,
        match="Unsupported primary model provider",
    ):
        create_primary_model_client(settings)


def test_factory_rejects_unknown_verifier_provider() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        nvidia_api_key="primary-key",
        ai_primary_provider="nvidia",
        ai_primary_model="fake/primary",
        ai_verifier_provider="unknown-provider",
        ai_verifier_model="fake/verifier",
    )

    with pytest.raises(
        UnsupportedModelProviderError,
        match="Unsupported verifier model provider",
    ):
        create_verifier_model_client(settings)
