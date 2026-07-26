from aegis.schemas.analysis import SecurityFinding
from aegis.schemas.model_verification import (
    FindingVerification,
    VerifierReviewResult,
)
from aegis.security.model_consensus import (
    ModelConsensusEvaluator,
)
from aegis.security.model_route_policy import (
    ModelRouteAssessment,
)


def finding() -> SecurityFinding:
    return SecurityFinding(
        title="Command injection",
        severity="high",
        confidence=0.98,
        summary="Unsafe shell execution.",
        evidence=["shell=True"],
        recommended_fix="Disable shell execution.",
    )


def verifier() -> VerifierReviewResult:
    return VerifierReviewResult(
        model="same/model",
        status="completed",
        verifications=[
            FindingVerification(
                finding_index=0,
                verdict="supported",
                confidence=0.98,
                reasoning="The code confirms the issue.",
            )
        ],
    )


def test_same_route_cannot_claim_independent_verification() -> None:
    result = ModelConsensusEvaluator().evaluate(
        primary_model="same/model",
        primary_findings=[finding()],
        verifier_result=verifier(),
        route_assessment=ModelRouteAssessment(
            classification="same_route",
            independently_verified=False,
            reasons=(
                "The same route was used.",
            ),
        ),
    )

    assert result.status == "partial"
    assert result.route_independence == "same_route"
    assert result.independently_verified is False
    assert result.decisions[0].verdict == "confirmed"
    assert result.decisions[0].confidence == 0.85
    assert "not independent" in (
        result.decisions[0].reasons[0]
    )


def test_independent_route_keeps_completed_consensus() -> None:
    result = ModelConsensusEvaluator().evaluate(
        primary_model="provider-a/model-a",
        primary_findings=[finding()],
        verifier_result=verifier(),
        route_assessment=ModelRouteAssessment(
            classification="independent",
            independently_verified=True,
            reasons=(
                "Distinct provider and model.",
            ),
        ),
    )

    assert result.status == "completed"
    assert result.route_independence == "independent"
    assert result.independently_verified is True
    assert result.decisions[0].confidence == 0.98
