from dataclasses import dataclass
from typing import Literal


RouteIndependence = Literal[
    "same_route",
    "same_model_distinct_endpoint",
    "same_provider_distinct_model",
    "independent",
]


@dataclass(frozen=True, slots=True)
class ModelRouteIdentity:
    provider: str
    model: str
    base_url: str


@dataclass(frozen=True, slots=True)
class ModelRouteAssessment:
    classification: RouteIndependence
    independently_verified: bool
    reasons: tuple[str, ...]


class ModelRoutePolicy:
    def assess(
        self,
        *,
        primary: ModelRouteIdentity,
        verifier: ModelRouteIdentity,
    ) -> ModelRouteAssessment:
        same_provider = (
            primary.provider.strip().lower()
            == verifier.provider.strip().lower()
        )
        same_model = (
            primary.model.strip().lower()
            == verifier.model.strip().lower()
        )
        same_endpoint = (
            primary.base_url.rstrip("/").strip().lower()
            == verifier.base_url.rstrip("/").strip().lower()
        )

        if same_provider and same_model and same_endpoint:
            return ModelRouteAssessment(
                classification="same_route",
                independently_verified=False,
                reasons=(
                    "Primary and verifier use the same provider, "
                    "model, and endpoint.",
                    "The second review is corroboration, not "
                    "independent model verification.",
                ),
            )

        if same_model:
            return ModelRouteAssessment(
                classification=(
                    "same_model_distinct_endpoint"
                ),
                independently_verified=False,
                reasons=(
                    "Primary and verifier use the same model "
                    "through distinct routes.",
                    "Route diversity does not establish model "
                    "independence.",
                ),
            )

        if same_provider:
            return ModelRouteAssessment(
                classification=(
                    "same_provider_distinct_model"
                ),
                independently_verified=True,
                reasons=(
                    "Primary and verifier use distinct models "
                    "from the same provider.",
                ),
            )

        return ModelRouteAssessment(
            classification="independent",
            independently_verified=True,
            reasons=(
                "Primary and verifier use distinct providers "
                "and distinct models.",
            ),
        )
