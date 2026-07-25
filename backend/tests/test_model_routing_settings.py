from aegis.config.settings import Settings


BASE_SETTINGS = {
    "_env_file": None,
    "aegis_fingerprint_key": "f" * 32,
    "nvidia_api_key": "test-key",
}


def test_new_primary_model_overrides_legacy_model() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        nvidia_model="legacy/primary",
        ai_primary_provider="NVIDIA",
        ai_primary_model="new/primary",
    )

    assert settings.resolved_primary_provider == "nvidia"
    assert settings.resolved_primary_model == "new/primary"


def test_primary_model_falls_back_to_legacy_nvidia_model() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        nvidia_model="legacy/primary",
    )

    assert settings.resolved_primary_provider == "nvidia"
    assert settings.resolved_primary_model == "legacy/primary"


def test_new_verifier_configuration_takes_precedence() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        nvidia_model="legacy/primary",
        nvidia_verifier_model="legacy/verifier",
        ai_primary_provider="nvidia",
        ai_primary_model="new/primary",
        ai_verifier_provider="OPENAI_COMPATIBLE",
        ai_verifier_model="new/verifier",
    )

    assert (
        settings.resolved_verifier_provider
        == "openai_compatible"
    )
    assert settings.resolved_verifier_model == "new/verifier"


def test_verifier_falls_back_to_legacy_verifier_model() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        nvidia_model="legacy/primary",
        nvidia_verifier_model="legacy/verifier",
    )

    assert settings.resolved_verifier_provider == "nvidia"
    assert settings.resolved_verifier_model == "legacy/verifier"


def test_verifier_falls_back_to_resolved_primary() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        nvidia_model="legacy/primary",
        ai_primary_provider="openai_compatible",
        ai_primary_model="new/primary",
    )

    assert (
        settings.resolved_verifier_provider
        == "openai_compatible"
    )
    assert settings.resolved_verifier_model == "new/primary"
