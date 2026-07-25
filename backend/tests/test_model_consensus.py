import pytest

from aegis.schemas.analysis import SecurityFinding
from aegis.schemas.model_verification import (
    FindingVerification,
    VerifierReviewResult,
)
from aegis.security.model_consensus import (
    ModelConsensusEvaluator,
)


def finding(
    confidence: float = 0.90,
) -> SecurityFinding:
    return SecurityFinding(
        title="Command injection",
        severity="high",
        confidence=confidence,
        summary="Untrusted input reaches a shell.",
        evidence=["shell=True"],
        recommended_fix="Disable shell execution.",
    )


def test_supported_finding_becomes_confirmed() -> None:
    result = ModelConsensusEvaluator().evaluate(
        primary_model="fake/primary",
        primary_findings=[finding()],
        verifier_result=VerifierReviewResult(
            model="fake/verifier",
            status="completed",
            verifications=[
                FindingVerification(
                    finding_index=0,
                    verdict="supported",
                    confidence=0.94,
                    reasoning="The code confirms the flow.",
                )
            ],
        ),
    )

    assert result.status == "completed"
    assert result.decisions[0].verdict == "confirmed"
    assert result.decisions[0].confidence == pytest.approx(
        0.92
    )


def test_refuted_finding_becomes_disputed() -> None:
    result = ModelConsensusEvaluator().evaluate(
        primary_model="fake/primary",
        primary_findings=[finding()],
        verifier_result=VerifierReviewResult(
            model="fake/verifier",
            status="completed",
            verifications=[
                FindingVerification(
                    finding_index=0,
                    verdict="refuted",
                    confidence=0.88,
                    reasoning="The input is constant.",
                )
            ],
        ),
    )

    assert result.decisions[0].verdict == "disputed"
    assert result.decisions[0].confidence == 0.88


def test_uncertain_verification_stays_uncertain() -> None:
    result = ModelConsensusEvaluator().evaluate(
        primary_model="fake/primary",
        primary_findings=[finding(0.91)],
        verifier_result=VerifierReviewResult(
            model="fake/verifier",
            status="completed",
            verifications=[
                FindingVerification(
                    finding_index=0,
                    verdict="uncertain",
                    confidence=0.55,
                    reasoning="Input origin is unknown.",
                )
            ],
        ),
    )

    assert result.decisions[0].verdict == "uncertain"
    assert result.decisions[0].confidence == 0.55


def test_failed_verifier_never_marks_finding_confirmed() -> None:
    result = ModelConsensusEvaluator().evaluate(
        primary_model="fake/primary",
        primary_findings=[finding(0.96)],
        verifier_result=VerifierReviewResult(
            model="fake/verifier",
            status="failed",
            error="timeout",
        ),
    )

    assert result.status == "partial"
    assert result.decisions[0].verdict == "unverified"
    assert result.decisions[0].confidence == 0.70
    assert result.errors == ["timeout"]


def test_missing_and_unknown_indices_are_partial() -> None:
    result = ModelConsensusEvaluator().evaluate(
        primary_model="fake/primary",
        primary_findings=[
            finding(),
            finding(),
        ],
        verifier_result=VerifierReviewResult(
            model="fake/verifier",
            status="completed",
            verifications=[
                FindingVerification(
                    finding_index=7,
                    verdict="supported",
                    confidence=0.90,
                    reasoning="Invalid reference.",
                )
            ],
        ),
    )

    assert result.status == "partial"
    assert [
        decision.verdict
        for decision in result.decisions
    ] == [
        "unverified",
        "unverified",
    ]
    assert result.errors


def test_duplicate_verifier_decision_is_rejected_safely() -> None:
    result = ModelConsensusEvaluator().evaluate(
        primary_model="fake/primary",
        primary_findings=[finding()],
        verifier_result=VerifierReviewResult(
            model="fake/verifier",
            status="completed",
            verifications=[
                FindingVerification(
                    finding_index=0,
                    verdict="supported",
                    confidence=0.95,
                    reasoning="First decision.",
                ),
                FindingVerification(
                    finding_index=0,
                    verdict="refuted",
                    confidence=0.99,
                    reasoning="Conflicting duplicate.",
                ),
            ],
        ),
    )

    assert result.status == "partial"
    assert result.decisions[0].verdict == "confirmed"
    assert any(
        "duplicate decisions" in error
        for error in result.errors
    )


def test_completed_empty_verifier_result_is_not_clean() -> None:
    result = ModelConsensusEvaluator().evaluate(
        primary_model="fake/primary",
        primary_findings=[finding(0.97)],
        verifier_result=VerifierReviewResult(
            model="fake/verifier",
            status="completed",
            verifications=[],
        ),
    )

    assert result.status == "partial"
    assert result.decisions[0].verdict == "unverified"
    assert result.decisions[0].confidence == 0.70


def test_no_primary_findings_produces_empty_completed_consensus() -> None:
    result = ModelConsensusEvaluator().evaluate(
        primary_model="fake/primary",
        primary_findings=[],
        verifier_result=VerifierReviewResult(
            model="fake/verifier",
            status="completed",
            verifications=[],
        ),
    )

    assert result.status == "completed"
    assert result.decisions == []
    assert result.errors == []


def test_verifier_decisions_cannot_confirm_unknown_findings() -> None:
    result = ModelConsensusEvaluator().evaluate(
        primary_model="fake/primary",
        primary_findings=[],
        verifier_result=VerifierReviewResult(
            model="fake/verifier",
            status="completed",
            verifications=[
                FindingVerification(
                    finding_index=0,
                    verdict="supported",
                    confidence=0.99,
                    reasoning="Invented finding reference.",
                )
            ],
        ),
    )

    assert result.status == "partial"
    assert result.decisions == []
    assert result.errors == [
        (
            "Verifier referenced an unknown primary "
            "finding index: 0."
        )
    ]


def test_each_primary_finding_requires_its_own_decision() -> None:
    result = ModelConsensusEvaluator().evaluate(
        primary_model="fake/primary",
        primary_findings=[
            finding(0.90),
            finding(0.86),
        ],
        verifier_result=VerifierReviewResult(
            model="fake/verifier",
            status="completed",
            verifications=[
                FindingVerification(
                    finding_index=0,
                    verdict="supported",
                    confidence=0.92,
                    reasoning="First finding supported.",
                )
            ],
        ),
    )

    assert result.status == "partial"
    assert [
        decision.verdict
        for decision in result.decisions
    ] == [
        "confirmed",
        "unverified",
    ]
