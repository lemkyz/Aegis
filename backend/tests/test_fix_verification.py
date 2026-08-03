import pytest
from pydantic import ValidationError

from aegis.schemas.validation import (
    FixProjectCheck,
    UnifiedFixVerificationRequest,
    UnifiedFixVerificationResponse,
    ValidationReplayCompareResponse,
)
from aegis.security.fix_verification import (
    UnifiedFixVerificationEvaluator,
)


def _replay(
    *,
    claim_id: str = "claim-command-001",
    verdict: str = "fixed",
    fixed: bool = True,
) -> ValidationReplayCompareResponse:
    return ValidationReplayCompareResponse(
        comparator=(
            "aegis-dynamic-validation-replay-v1"
        ),
        threat_id="threat-command-001",
        claim_id=claim_id,
        category="command_injection",
        verdict=verdict,
        fixed=fixed,
        confidence=0.99,
        before_verdict="confirmed",
        after_verdict=(
            "not_reproduced"
            if verdict == "fixed"
            else (
                "confirmed"
                if verdict == "still_exploitable"
                else "execution_error"
            )
        ),
        reasons=[],
        denials=[],
    )


def _request(
    *,
    replay: ValidationReplayCompareResponse | None = None,
    target_resolved: bool = True,
    regression_free: bool = True,
    checks: list[FixProjectCheck] | None = None,
) -> UnifiedFixVerificationRequest:
    return UnifiedFixVerificationRequest(
        claim_id="claim-command-001",
        patch_sha256="0" * 64,
        replay=replay or _replay(),
        project_checks=checks or [
            FixProjectCheck(
                name="Syntax check",
                status="passed",
                details="Syntax is valid.",
            ),
            FixProjectCheck(
                name="Tests",
                status="passed",
                details="All tests passed.",
            ),
            FixProjectCheck(
                name="Build",
                status="passed",
                details="Build passed.",
            ),
        ],
        static_target_resolved=target_resolved,
        static_regression_free=regression_free,
    )


def test_verifies_complete_fix_evidence() -> None:
    result = (
        UnifiedFixVerificationEvaluator()
        .evaluate(_request())
    )

    assert result.verdict == "verified"
    assert result.verified is True
    assert result.project_checks_passed is True
    assert result.static_target_resolved is True
    assert result.static_regression_free is True
    assert result.dynamic_replay_fixed is True


def test_reports_failed_project_check() -> None:
    result = (
        UnifiedFixVerificationEvaluator()
        .evaluate(
            _request(
                checks=[
                    FixProjectCheck(
                        name="Tests",
                        status="failed",
                        details="One test failed.",
                    )
                ]
            )
        )
    )

    assert result.verdict == "project_failed"
    assert result.verified is False
    assert result.failed_checks == ["Tests"]


def test_reports_unresolved_static_target() -> None:
    result = (
        UnifiedFixVerificationEvaluator()
        .evaluate(
            _request(
                target_resolved=False,
            )
        )
    )

    assert result.verdict == (
        "target_not_resolved"
    )
    assert result.verified is False


def test_reports_static_regression() -> None:
    result = (
        UnifiedFixVerificationEvaluator()
        .evaluate(
            _request(
                regression_free=False,
            )
        )
    )

    assert result.verdict == (
        "regression_detected"
    )
    assert result.verified is False


def test_reports_still_exploitable() -> None:
    result = (
        UnifiedFixVerificationEvaluator()
        .evaluate(
            _request(
                replay=_replay(
                    verdict="still_exploitable",
                    fixed=False,
                )
            )
        )
    )

    assert result.verdict == (
        "still_exploitable"
    )
    assert result.dynamic_replay_fixed is False


def test_reports_inconclusive_replay() -> None:
    result = (
        UnifiedFixVerificationEvaluator()
        .evaluate(
            _request(
                replay=_replay(
                    verdict="inconclusive",
                    fixed=False,
                )
            )
        )
    )

    assert result.verdict == "inconclusive"
    assert result.verified is False


def test_skipped_check_fails_closed() -> None:
    result = (
        UnifiedFixVerificationEvaluator()
        .evaluate(
            _request(
                checks=[
                    FixProjectCheck(
                        name="Syntax check",
                        status="passed",
                    ),
                    FixProjectCheck(
                        name="Tests",
                        status="skipped",
                    ),
                ]
            )
        )
    )

    assert result.verdict == "inconclusive"
    assert result.verified is False
    assert result.project_checks_passed is False

    assert result.passed_checks == [
        "Syntax check",
    ]
    assert result.failed_checks == []
    assert result.skipped_checks == [
        "Tests",
    ]

    assert any(
        "skipped" in reason.lower()
        or "incomplete" in reason.lower()
        for reason in result.reasons
    )


def test_request_preserves_exact_patch_provenance() -> None:
    request = _request()

    assert request.claim_id == (
        request.replay.claim_id
    )
    assert request.patch_sha256 == "0" * 64


def test_request_rejects_replay_claim_mismatch() -> None:
    with pytest.raises(
        ValidationError,
        match=(
            "verification claim identity must match "
            "the replay claim"
        ),
    ):
        _request(
            replay=_replay(
                claim_id="claim-other",
            )
        )


def test_verified_result_emits_no_identified_residual_risk() -> None:
    result = (
        UnifiedFixVerificationEvaluator()
        .evaluate(_request())
    )

    assert result.residual_risk.claim_id == (
        "claim-command-001"
    )
    assert result.residual_risk.patch_sha256 == (
        "0" * 64
    )
    assert result.residual_risk.status == (
        "none_identified"
    )
    assert result.residual_risk.reasons == (
        result.reasons
    )


def test_still_exploitable_result_emits_identified_residual_risk() -> None:
    result = (
        UnifiedFixVerificationEvaluator()
        .evaluate(
            _request(
                replay=_replay(
                    verdict="still_exploitable",
                    fixed=False,
                )
            )
        )
    )

    assert result.residual_risk.status == (
        "identified"
    )
    assert result.residual_risk.reasons == (
        result.reasons
    )

def test_response_preserves_exact_patch_provenance() -> None:
    result = (
        UnifiedFixVerificationEvaluator()
        .evaluate(_request())
    )

    assert result.patch_sha256 == (
        result.residual_risk.patch_sha256
    )
    assert result.patch_sha256 == "0" * 64


def test_response_rejects_residual_risk_patch_mismatch() -> None:
    result = (
        UnifiedFixVerificationEvaluator()
        .evaluate(_request())
    )
    payload = result.model_dump(
        mode="json"
    )
    payload["residual_risk"][
        "patch_sha256"
    ] = "f" * 64

    with pytest.raises(
        ValidationError,
        match=(
            "residual risk patch digest must match "
            "the unified verification patch"
        ),
    ):
        UnifiedFixVerificationResponse.model_validate(
            payload
        )
