from aegis.schemas.analysis import SecurityFinding
from aegis.schemas.validation import (
    DynamicValidationEvidenceResponse,
    ResidualRiskStatus,
    UnifiedFixVerificationResponse,
    ValidationReplayCompareResponse,
)
from aegis.security.claim_adapter import finding_to_claim
from aegis.security.dynamic_claim_evidence import (
    apply_dynamic_evidence,
    apply_fix_verification,
)


def base_claim():
    finding = SecurityFinding(
        title="Command Injection",
        severity="high",
        confidence=0.9,
        summary="Untrusted input reaches a shell command.",
        evidence=[],
        scanner_evidence=[],
        cwe=["CWE-78"],
        owasp=["A03:2021"],
        vulnerable_lines=[10],
        false_positive_notes=[],
        recommended_fix="Disable shell execution.",
        proposed_patch=None,
    )

    return finding_to_claim(
        finding,
        filename="app.py",
    )


def dynamic_result(
    *,
    verdict: str,
    claim_id: str,
) -> DynamicValidationEvidenceResponse:
    return DynamicValidationEvidenceResponse(
        evaluator="aegis-dynamic-validation-evidence-v1",
        threat_id="threat-command-001",
        claim_id=claim_id,
        category="command_injection",
        verdict=verdict,
        dynamically_confirmed=(
            verdict == "confirmed"
        ),
        confidence=0.99,
        evidence=[
            "Sandbox status: completed",
            "Exit code: 0",
            "Captured stdout: exploit marker",
        ],
        reasons=[
            "Dynamic validation completed.",
        ],
        execution_status="completed",
        exit_code=0,
        duration_ms=12,
    )


def replay_result(
    *,
    claim_id: str,
) -> ValidationReplayCompareResponse:
    return ValidationReplayCompareResponse(
        comparator="aegis-dynamic-validation-replay-v1",
        threat_id="threat-command-001",
        claim_id=claim_id,
        category="command_injection",
        verdict="fixed",
        fixed=True,
        confidence=0.98,
        before_verdict="confirmed",
        after_verdict="not_reproduced",
        reasons=[
            "The exploit no longer reproduces.",
        ],
        denials=[],
    )


def verification_result(
    *,
    claim_id: str,
    verified: bool = True,
    patch_sha256: str = "0" * 64,
    residual_status: ResidualRiskStatus | None = None,
) -> UnifiedFixVerificationResponse:
    return UnifiedFixVerificationResponse(
        evaluator="aegis-unified-fix-verification-v1",
        threat_id="threat-command-001",
        claim_id=claim_id,
        patch_sha256=patch_sha256,
        category="command_injection",
        verdict=(
            "verified"
            if verified
            else "inconclusive"
        ),
        verified=verified,
        confidence=0.98,
        project_checks_passed=True,
        static_target_resolved=True,
        static_regression_free=True,
        dynamic_replay_fixed=verified,
        residual_risk={
            "claim_id": claim_id,
            "patch_sha256": patch_sha256,
            "status": (
                residual_status
                if residual_status is not None
                else (
                    "none_identified"
                    if verified
                    else "inconclusive"
                )
            ),
            "reasons": [
                "Unified verification completed.",
            ],
        },
        reasons=[
            "Unified verification completed.",
        ],
        failed_checks=[],
    )


def test_confirmed_dynamic_result_updates_claim() -> None:
    claim = base_claim()

    updated = apply_dynamic_evidence(
        claim,
        dynamic_result(
            verdict="confirmed",
            claim_id=claim.claim_id,
        ),
    )

    assert updated.state == "confirmed"
    assert len(updated.evidence) == 1

    evidence = updated.evidence[0]

    assert evidence.source.kind == "dynamic_probe"
    assert evidence.source.name == (
        "aegis-dynamic-validation-evidence-v1"
    )
    assert evidence.confidence == 0.99
    assert evidence.details
    assert evidence.evidence_id.startswith(
        "evidence:sha256:"
    )


def test_dynamic_evidence_id_is_deterministic() -> None:
    claim = base_claim()
    result = dynamic_result(
        verdict="confirmed",
        claim_id=claim.claim_id,
    )

    first = apply_dynamic_evidence(
        claim,
        result,
    )
    second = apply_dynamic_evidence(
        claim,
        result,
    )

    assert (
        first.evidence[0].evidence_id
        == second.evidence[0].evidence_id
    )


def test_dynamic_result_rejects_wrong_claim_id() -> None:
    claim = base_claim()

    try:
        apply_dynamic_evidence(
            claim,
            dynamic_result(
                verdict="confirmed",
                claim_id="claim:sha256:different",
            ),
        )
    except ValueError as exc:
        assert "claim" in str(exc).lower()
    else:
        raise AssertionError(
            "Expected mismatched claim_id to fail"
        )


def test_not_reproduced_does_not_confirm_claim() -> None:
    claim = base_claim()

    updated = apply_dynamic_evidence(
        claim,
        dynamic_result(
            verdict="not_reproduced",
            claim_id=claim.claim_id,
        ),
    )

    assert updated.state == "suspected"
    assert updated.evidence[0].source.kind == (
        "dynamic_probe"
    )


def test_verified_fix_updates_claim_state() -> None:
    claim = base_claim()

    updated = apply_fix_verification(
        claim,
        replay=replay_result(
            claim_id=claim.claim_id,
        ),
        verification=verification_result(
            claim_id=claim.claim_id,
        ),
    )

    assert updated.state == "verified_fixed"
    assert len(updated.evidence) == 2
    assert {
        item.source.kind
        for item in updated.evidence
    } == {
        "runtime_execution",
        "test_result",
    }

    verification_evidence = next(
        item
        for item in updated.evidence
        if item.source.kind == "test_result"
    )
    assert (
        f"Verification claim identifier: "
        f"{claim.claim_id}"
        in verification_evidence.details
    )
    assert (
        f"Patch SHA-256: {'0' * 64}"
        in verification_evidence.details
    )
    assert (
        "Residual risk status: none_identified"
        in verification_evidence.details
    )
    assert (
        "Residual risk reason: "
        "Unified verification completed."
        in verification_evidence.details
    )


def test_residual_risk_prevents_verified_fixed_state() -> None:
    claim = base_claim()

    updated = apply_fix_verification(
        claim,
        replay=replay_result(
            claim_id=claim.claim_id,
        ),
        verification=verification_result(
            claim_id=claim.claim_id,
            verified=True,
            residual_status="inconclusive",
        ),
    )

    assert updated.state == "suspected"


def test_fix_verification_evidence_id_tracks_patch_digest() -> None:
    claim = base_claim()

    first = apply_fix_verification(
        claim,
        replay=replay_result(
            claim_id=claim.claim_id,
        ),
        verification=verification_result(
            claim_id=claim.claim_id,
            patch_sha256="0" * 64,
        ),
    )
    second = apply_fix_verification(
        claim,
        replay=replay_result(
            claim_id=claim.claim_id,
        ),
        verification=verification_result(
            claim_id=claim.claim_id,
            patch_sha256="f" * 64,
        ),
    )

    first_id = next(
        item.evidence_id
        for item in first.evidence
        if item.source.kind == "test_result"
    )
    second_id = next(
        item.evidence_id
        for item in second.evidence
        if item.source.kind == "test_result"
    )

    assert first_id != second_id


def test_inconclusive_verification_does_not_mark_fixed() -> None:
    claim = base_claim()

    updated = apply_fix_verification(
        claim,
        replay=replay_result(
            claim_id=claim.claim_id,
        ),
        verification=verification_result(
            claim_id=claim.claim_id,
            verified=False,
        ),
    )

    assert updated.state == "suspected"


def test_fix_verification_rejects_wrong_claim_id() -> None:
    claim = base_claim()

    try:
        apply_fix_verification(
            claim,
            replay=replay_result(
                claim_id=claim.claim_id,
            ),
            verification=verification_result(
                claim_id="claim:sha256:different",
            ),
        )
    except ValueError as exc:
        assert "claim" in str(exc).lower()
    else:
        raise AssertionError(
            "Expected mismatched claim_id to fail"
        )
