import pytest
from pydantic import ValidationError

from aegis.schemas.model_verification import (
    FindingVerification,
    ModelReviewResult,
    VerifierReviewResult,
)


def test_primary_model_result_defaults_to_empty_findings() -> None:
    result = ModelReviewResult(
        role="primary",
        model="fake/primary",
        status="completed",
    )

    assert result.findings == []
    assert result.error is None


def test_verifier_failure_preserves_error_without_findings() -> None:
    result = ModelReviewResult(
        role="verifier",
        model="fake/verifier",
        status="failed",
        error="timeout",
    )

    assert result.findings == []
    assert result.error == "timeout"


def test_rejects_unknown_model_role() -> None:
    with pytest.raises(ValidationError):
        ModelReviewResult(
            role="judge",
            model="fake/model",
            status="completed",
        )


def test_verifier_can_support_primary_finding() -> None:
    result = VerifierReviewResult(
        model="fake/verifier",
        status="completed",
        verifications=[
            FindingVerification(
                finding_index=0,
                verdict="supported",
                confidence=0.94,
                reasoning=(
                    "Scanner evidence and source behavior agree."
                ),
                evidence=[
                    "subprocess.run uses shell=True",
                ],
            )
        ],
    )

    assert result.role == "verifier"
    assert result.verifications[0].verdict == (
        "supported"
    )
    assert result.additional_findings == []


def test_verifier_can_refute_primary_finding() -> None:
    result = VerifierReviewResult(
        model="fake/verifier",
        status="completed",
        verifications=[
            FindingVerification(
                finding_index=1,
                verdict="refuted",
                confidence=0.88,
                reasoning="The input is a fixed constant.",
            )
        ],
    )

    assert result.verifications[0].finding_index == 1
    assert result.verifications[0].verdict == (
        "refuted"
    )


def test_verifier_can_leave_finding_uncertain() -> None:
    result = FindingVerification(
        finding_index=1,
        verdict="uncertain",
        confidence=0.55,
        reasoning=(
            "The origin of the input cannot be established."
        ),
    )

    assert result.verdict == "uncertain"


def test_rejects_invalid_verification_confidence() -> None:
    with pytest.raises(ValidationError):
        FindingVerification(
            finding_index=0,
            verdict="uncertain",
            confidence=1.5,
            reasoning="Insufficient evidence.",
        )


def test_rejects_invalid_finding_index() -> None:
    with pytest.raises(ValidationError):
        FindingVerification(
            finding_index=-1,
            verdict="supported",
            confidence=0.9,
            reasoning="Invalid index.",
        )
