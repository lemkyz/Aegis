from aegis.security.model_route_policy import (
    ModelRouteIdentity,
    ModelRoutePolicy,
)


def route(
    provider: str,
    model: str,
    base_url: str,
) -> ModelRouteIdentity:
    return ModelRouteIdentity(
        provider=provider,
        model=model,
        base_url=base_url,
    )


def test_same_route_is_not_independent() -> None:
    assessment = ModelRoutePolicy().assess(
        primary=route(
            "nvidia",
            "model-a",
            "https://example.test/v1",
        ),
        verifier=route(
            "nvidia",
            "model-a",
            "https://example.test/v1/",
        ),
    )

    assert assessment.classification == "same_route"
    assert assessment.independently_verified is False


def test_same_model_distinct_endpoint_is_not_independent() -> None:
    assessment = ModelRoutePolicy().assess(
        primary=route(
            "provider-a",
            "model-a",
            "https://one.test/v1",
        ),
        verifier=route(
            "provider-b",
            "model-a",
            "https://two.test/v1",
        ),
    )

    assert (
        assessment.classification
        == "same_model_distinct_endpoint"
    )
    assert assessment.independently_verified is False


def test_same_provider_distinct_model_is_independent() -> None:
    assessment = ModelRoutePolicy().assess(
        primary=route(
            "nvidia",
            "model-a",
            "https://example.test/v1",
        ),
        verifier=route(
            "nvidia",
            "model-b",
            "https://example.test/v1",
        ),
    )

    assert (
        assessment.classification
        == "same_provider_distinct_model"
    )
    assert assessment.independently_verified is True


def test_distinct_provider_and_model_is_independent() -> None:
    assessment = ModelRoutePolicy().assess(
        primary=route(
            "nvidia",
            "model-a",
            "https://one.test/v1",
        ),
        verifier=route(
            "openrouter",
            "model-b",
            "https://two.test/v1",
        ),
    )

    assert assessment.classification == "independent"
    assert assessment.independently_verified is True
