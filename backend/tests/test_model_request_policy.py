from aegis.config.settings import Settings
from aegis.models.request_policy import (
    resolve_model_request_config,
)


BASE_SETTINGS = {
    "_env_file": None,
    "aegis_fingerprint_key": "f" * 32,
}


def test_balanced_profile_preserves_legacy_behavior() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        ai_request_profile="balanced",
        ai_request_timeout_seconds=75.0,
        ai_max_retries=2,
    )

    primary = resolve_model_request_config(
        settings,
        role="primary",
    )
    verifier = resolve_model_request_config(
        settings,
        role="verifier",
    )

    assert primary.timeout_seconds == 75.0
    assert verifier.timeout_seconds == 75.0
    assert primary.max_retries == 2
    assert verifier.max_retries == 2
    assert primary.max_tokens == 1600
    assert verifier.max_tokens == 1200


def test_fast_profile_limits_latency_and_tokens() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        ai_request_profile="fast",
        ai_request_timeout_seconds=240.0,
        ai_max_retries=3,
    )

    primary = resolve_model_request_config(
        settings,
        role="primary",
    )
    verifier = resolve_model_request_config(
        settings,
        role="verifier",
    )

    assert primary.timeout_seconds == 45.0
    assert verifier.timeout_seconds == 45.0
    assert primary.max_retries == 0
    assert verifier.max_retries == 0
    assert primary.max_tokens == 900
    assert verifier.max_tokens == 700


def test_thorough_profile_expands_request_budget() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        ai_request_profile="thorough",
        ai_request_timeout_seconds=60.0,
        ai_max_retries=0,
    )

    primary = resolve_model_request_config(
        settings,
        role="primary",
    )
    verifier = resolve_model_request_config(
        settings,
        role="verifier",
    )

    assert primary.timeout_seconds == 180.0
    assert verifier.timeout_seconds == 180.0
    assert primary.max_retries == 1
    assert verifier.max_retries == 1
    assert primary.max_tokens == 2400
    assert verifier.max_tokens == 1800


def test_role_specific_values_override_profile() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        ai_request_profile="fast",
        ai_primary_timeout_seconds=150.0,
        ai_verifier_timeout_seconds=210.0,
        ai_primary_max_retries=2,
        ai_verifier_max_retries=3,
        ai_primary_max_tokens=3000,
        ai_verifier_max_tokens=2500,
    )

    primary = resolve_model_request_config(
        settings,
        role="primary",
    )
    verifier = resolve_model_request_config(
        settings,
        role="verifier",
    )

    assert primary.timeout_seconds == 150.0
    assert verifier.timeout_seconds == 210.0
    assert primary.max_retries == 2
    assert verifier.max_retries == 3
    assert primary.max_tokens == 3000
    assert verifier.max_tokens == 2500
