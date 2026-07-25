import pytest

from aegis.config.settings import Settings
from aegis.models.provider_config import (
    ModelProviderConfigurationError,
    resolve_model_endpoint,
)


BASE_SETTINGS = {
    "_env_file": None,
    "aegis_fingerprint_key": "f" * 32,
}


def test_resolves_nvidia_primary_endpoint() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        nvidia_api_key="nvidia-key",
        ai_primary_provider="nvidia",
        ai_primary_model="fake/primary",
    )

    endpoint = resolve_model_endpoint(
        settings,
        role="primary",
    )

    assert endpoint.provider == "nvidia"
    assert endpoint.model == "fake/primary"
    assert endpoint.api_key == "nvidia-key"
    assert endpoint.base_url == (
        "https://integrate.api.nvidia.com/v1"
    )


def test_resolves_openrouter_verifier_endpoint() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        ai_primary_provider="nvidia",
        ai_primary_model="fake/primary",
        ai_verifier_provider="openrouter",
        ai_verifier_model="fake/verifier",
        openrouter_api_key="openrouter-key",
    )

    endpoint = resolve_model_endpoint(
        settings,
        role="verifier",
    )

    assert endpoint.provider == "openrouter"
    assert endpoint.model == "fake/verifier"
    assert endpoint.api_key == "openrouter-key"
    assert endpoint.base_url == (
        "https://openrouter.ai/api/v1"
    )


def test_resolves_groq_primary_endpoint() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        ai_primary_provider="groq",
        ai_primary_model="fake/groq-model",
        groq_api_key="groq-key",
    )

    endpoint = resolve_model_endpoint(
        settings,
        role="primary",
    )

    assert endpoint.provider == "groq"
    assert endpoint.api_key == "groq-key"
    assert endpoint.base_url == (
        "https://api.groq.com/openai/v1"
    )


def test_resolves_role_specific_custom_endpoints() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        ai_primary_provider="openai_compatible",
        ai_primary_model="custom/primary",
        ai_primary_api_key="primary-key",
        ai_primary_base_url=(
            "https://primary.example/v1/"
        ),
        ai_verifier_provider="openai_compatible",
        ai_verifier_model="custom/verifier",
        ai_verifier_api_key="verifier-key",
        ai_verifier_base_url=(
            "https://verifier.example/v1/"
        ),
    )

    primary = resolve_model_endpoint(
        settings,
        role="primary",
    )
    verifier = resolve_model_endpoint(
        settings,
        role="verifier",
    )

    assert primary.api_key == "primary-key"
    assert primary.base_url == (
        "https://primary.example/v1"
    )
    assert verifier.api_key == "verifier-key"
    assert verifier.base_url == (
        "https://verifier.example/v1"
    )


def test_missing_provider_key_raises_clear_error() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        ai_primary_provider="openrouter",
        ai_primary_model="fake/model",
    )

    with pytest.raises(
        ModelProviderConfigurationError,
        match="OPENROUTER_API_KEY",
    ):
        resolve_model_endpoint(
            settings,
            role="primary",
        )


def test_configuration_error_never_contains_secret() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        ai_primary_provider="openai_compatible",
        ai_primary_model="fake/model",
        ai_primary_api_key="do-not-leak-this",
        ai_primary_base_url=None,
    )

    with pytest.raises(
        ModelProviderConfigurationError,
    ) as error:
        resolve_model_endpoint(
            settings,
            role="primary",
        )

    assert "do-not-leak-this" not in str(error.value)
    assert "AI_PRIMARY_BASE_URL" in str(error.value)


def test_unknown_provider_has_no_implicit_fallback() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        ai_primary_provider="unknown",
        ai_primary_model="fake/model",
    )

    with pytest.raises(
        ModelProviderConfigurationError,
        match="not defined",
    ):
        resolve_model_endpoint(
            settings,
            role="primary",
        )
