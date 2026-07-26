from aegis.config.settings import Settings


BASE_SETTINGS = {
    "_env_file": None,
    "aegis_fingerprint_key": "f" * 32,
}


def test_fallback_routes_are_disabled_by_default() -> None:
    settings = Settings(**BASE_SETTINGS)

    assert (
        settings.resolved_primary_fallback_provider
        is None
    )
    assert (
        settings.resolved_primary_fallback_model
        is None
    )
    assert (
        settings.resolved_verifier_fallback_provider
        is None
    )
    assert (
        settings.resolved_verifier_fallback_model
        is None
    )


def test_fallback_route_values_are_normalized() -> None:
    settings = Settings(
        **BASE_SETTINGS,
        ai_primary_fallback_provider=" OpenRouter ",
        ai_primary_fallback_model=" fallback/model ",
        ai_verifier_fallback_provider=" GROQ ",
        ai_verifier_fallback_model=" verifier/model ",
    )

    assert (
        settings.resolved_primary_fallback_provider
        == "openrouter"
    )
    assert (
        settings.resolved_primary_fallback_model
        == "fallback/model"
    )
    assert (
        settings.resolved_verifier_fallback_provider
        == "groq"
    )
    assert (
        settings.resolved_verifier_fallback_model
        == "verifier/model"
    )
