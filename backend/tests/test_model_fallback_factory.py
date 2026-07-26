import pytest

from aegis.config.settings import Settings
from aegis.models.factory import (
    InvalidFallbackRouteError,
    create_primary_fallback_model_client,
    create_verifier_fallback_model_client,
)
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


def test_missing_primary_fallback_returns_none() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        nvidia_api_key="primary-key",
    )

    assert (
        create_primary_fallback_model_client(settings)
        is None
    )


def test_missing_verifier_fallback_returns_none() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        nvidia_api_key="primary-key",
    )

    assert (
        create_verifier_fallback_model_client(settings)
        is None
    )


def test_partial_primary_fallback_is_rejected() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        ai_primary_fallback_provider="openrouter",
    )

    with pytest.raises(
        InvalidFallbackRouteError,
        match="requires both",
    ):
        create_primary_fallback_model_client(settings)


def test_same_primary_fallback_route_is_rejected() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        nvidia_api_key="test-key",
        ai_primary_provider="nvidia",
        ai_primary_model="fake/model",
        ai_primary_fallback_provider="nvidia",
        ai_primary_fallback_model="fake/model",
    )

    with pytest.raises(
        InvalidFallbackRouteError,
        match="must differ",
    ):
        create_primary_fallback_model_client(settings)


def test_same_verifier_fallback_route_is_rejected() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        nvidia_api_key="test-key",
        ai_primary_provider="nvidia",
        ai_primary_model="fake/primary",
        ai_verifier_provider="nvidia",
        ai_verifier_model="fake/verifier",
        ai_verifier_fallback_provider="nvidia",
        ai_verifier_fallback_model="fake/verifier",
    )

    with pytest.raises(
        InvalidFallbackRouteError,
        match="must differ",
    ):
        create_verifier_fallback_model_client(settings)


def test_creates_explicit_primary_fallback_client() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        nvidia_api_key="primary-key",
        ai_primary_provider="nvidia",
        ai_primary_model="fake/primary",
        ai_primary_fallback_provider="openrouter",
        ai_primary_fallback_model="fake/fallback",
        openrouter_api_key="fallback-key",
    )

    client = create_primary_fallback_model_client(
        settings
    )

    assert isinstance(
        client,
        OpenAICompatibleSecurityModelClient,
    )
    assert client.provider == "openrouter"
    assert client.model == "fake/fallback"


def test_creates_explicit_verifier_fallback_client() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        nvidia_api_key="primary-key",
        ai_primary_provider="nvidia",
        ai_primary_model="fake/primary",
        ai_verifier_provider="nvidia",
        ai_verifier_model="fake/verifier",
        ai_verifier_fallback_provider="groq",
        ai_verifier_fallback_model="fake/fallback",
        groq_api_key="fallback-key",
    )

    client = create_verifier_fallback_model_client(
        settings
    )

    assert isinstance(
        client,
        OpenAICompatibleVerifierClient,
    )
    assert client.provider == "groq"
    assert client.model == "fake/fallback"



def test_creates_nvidia_primary_fallback_from_other_provider() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        ai_primary_provider="openrouter",
        ai_primary_model="fake/active",
        openrouter_api_key="active-key",
        ai_primary_fallback_provider="nvidia",
        ai_primary_fallback_model="fake/nvidia-fallback",
        nvidia_api_key="fallback-key",
    )

    client = create_primary_fallback_model_client(
        settings
    )

    assert isinstance(
        client,
        OpenAICompatibleSecurityModelClient,
    )
    assert client.provider == "nvidia"
    assert client.model == "fake/nvidia-fallback"
    assert client.transport.base_url == (
        "https://integrate.api.nvidia.com/v1"
    )


def test_creates_nvidia_verifier_fallback_from_other_provider() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        ai_primary_provider="openrouter",
        ai_primary_model="fake/primary",
        openrouter_api_key="active-key",
        ai_verifier_provider="groq",
        ai_verifier_model="fake/active-verifier",
        groq_api_key="verifier-key",
        ai_verifier_fallback_provider="nvidia",
        ai_verifier_fallback_model="fake/nvidia-fallback",
        nvidia_api_key="fallback-key",
    )

    client = create_verifier_fallback_model_client(
        settings
    )

    assert isinstance(
        client,
        OpenAICompatibleVerifierClient,
    )
    assert client.provider == "nvidia"
    assert client.model == "fake/nvidia-fallback"
    assert client.transport.base_url == (
        "https://integrate.api.nvidia.com/v1"
    )
