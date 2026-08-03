import hashlib

from aegis.schemas.claims import (
    EvidenceItem,
    EvidenceSource,
    SecurityClaim,
)
from aegis.schemas.validation import (
    DynamicValidationEvidenceResponse,
    UnifiedFixVerificationResponse,
    ValidationReplayCompareResponse,
)


def apply_dynamic_evidence(
    claim: SecurityClaim,
    result: DynamicValidationEvidenceResponse,
) -> SecurityClaim:
    _require_matching_claim_id(
        claim.claim_id,
        result.claim_id,
    )

    evidence = EvidenceItem(
        evidence_id=_stable_id(
            "evidence",
            "dynamic_probe",
            claim.claim_id,
            result.evaluator,
            result.threat_id,
            result.category,
            result.verdict,
            result.execution_status,
            str(result.exit_code),
            str(result.duration_ms),
            "\n".join(result.evidence),
            "\n".join(result.reasons),
        ),
        source=EvidenceSource(
            kind="dynamic_probe",
            name=result.evaluator,
        ),
        summary=(
            "Dynamic validation verdict: "
            f"{result.verdict}."
        ),
        confidence=result.confidence,
        locations=[],
        details=[
            *result.evidence,
            *result.reasons,
            (
                "Execution status: "
                f"{result.execution_status}"
            ),
            (
                "Exit code: "
                f"{result.exit_code}"
            ),
            (
                "Duration: "
                f"{result.duration_ms} ms"
            ),
            (
                "Threat identifier: "
                f"{result.threat_id}"
            ),
        ],
    )

    state = claim.state

    if result.verdict == "confirmed":
        state = "confirmed"

    return claim.model_copy(
        deep=True,
        update={
            "state": state,
            "evidence": _append_unique_evidence(
                claim.evidence,
                evidence,
            ),
        },
    )


def apply_fix_verification(
    claim: SecurityClaim,
    *,
    replay: ValidationReplayCompareResponse,
    verification: UnifiedFixVerificationResponse,
) -> SecurityClaim:
    _require_matching_claim_id(
        claim.claim_id,
        replay.claim_id,
    )
    _require_matching_claim_id(
        claim.claim_id,
        verification.claim_id,
    )

    replay_evidence = EvidenceItem(
        evidence_id=_stable_id(
            "evidence",
            "runtime_execution",
            claim.claim_id,
            replay.comparator,
            replay.threat_id,
            replay.category,
            replay.verdict,
            replay.before_verdict,
            replay.after_verdict,
            "\n".join(replay.reasons),
            "\n".join(replay.denials),
        ),
        source=EvidenceSource(
            kind="runtime_execution",
            name=replay.comparator,
        ),
        summary=(
            "Dynamic replay verdict: "
            f"{replay.verdict}."
        ),
        confidence=replay.confidence,
        locations=[],
        details=[
            *replay.reasons,
            *replay.denials,
            (
                "Before verdict: "
                f"{replay.before_verdict}"
            ),
            (
                "After verdict: "
                f"{replay.after_verdict}"
            ),
            (
                "Threat identifier: "
                f"{replay.threat_id}"
            ),
        ],
    )

    verification_evidence = EvidenceItem(
        evidence_id=_stable_id(
            "evidence",
            "test_result",
            claim.claim_id,
            verification.evaluator,
            verification.threat_id,
            verification.category,
            verification.verdict,
            str(verification.verified),
            str(
                verification.project_checks_passed
            ),
            str(
                verification.static_target_resolved
            ),
            str(
                verification.static_regression_free
            ),
            str(
                verification.dynamic_replay_fixed
            ),
            verification.claim_id,
            verification.patch_sha256,
            verification.residual_risk.claim_id,
            verification.residual_risk.patch_sha256,
            verification.residual_risk.status,
            "\n".join(
                verification.residual_risk.reasons
            ),
            "\n".join(verification.reasons),
            "\n".join(
                verification.failed_checks
            ),
        ),
        source=EvidenceSource(
            kind="test_result",
            name=verification.evaluator,
        ),
        summary=(
            "Unified fix verification verdict: "
            f"{verification.verdict}."
        ),
        confidence=verification.confidence,
        locations=[],
        details=[
            *verification.reasons,
            *[
                f"Failed check: {check}"
                for check
                in verification.failed_checks
            ],
            (
                "Project checks passed: "
                f"{verification.project_checks_passed}"
            ),
            (
                "Static target resolved: "
                f"{verification.static_target_resolved}"
            ),
            (
                "Static regression free: "
                f"{verification.static_regression_free}"
            ),
            (
                "Dynamic replay fixed: "
                f"{verification.dynamic_replay_fixed}"
            ),
            (
                "Verification claim identifier: "
                f"{verification.claim_id}"
            ),
            (
                "Patch SHA-256: "
                f"{verification.patch_sha256}"
            ),
            (
                "Residual risk status: "
                f"{verification.residual_risk.status}"
            ),
            *[
                (
                    "Residual risk reason: "
                    f"{reason}"
                )
                for reason
                in verification.residual_risk.reasons
            ],
        ],
    )

    evidence = _append_unique_evidence(
        claim.evidence,
        replay_evidence,
        verification_evidence,
    )

    state = claim.state

    if (
        replay.verdict == "fixed"
        and replay.fixed
        and verification.verdict == "verified"
        and verification.verified
        and verification.project_checks_passed
        and verification.static_target_resolved
        and verification.static_regression_free
        and verification.dynamic_replay_fixed
        and (
            verification.residual_risk.status
            == "none_identified"
        )
    ):
        state = "verified_fixed"

    return claim.model_copy(
        deep=True,
        update={
            "state": state,
            "evidence": evidence,
        },
    )


def _append_unique_evidence(
    existing: list[EvidenceItem],
    *items: EvidenceItem,
) -> list[EvidenceItem]:
    result = list(existing)
    known_ids = {
        item.evidence_id
        for item in existing
    }

    for item in items:
        if item.evidence_id in known_ids:
            continue

        result.append(item)
        known_ids.add(item.evidence_id)

    return result


def _require_matching_claim_id(
    expected: str,
    observed: str | None,
) -> None:
    if observed != expected:
        raise ValueError(
            "Dynamic evidence must reference "
            "the same claim identifier."
        )


def _stable_id(
    prefix: str,
    *parts: str,
) -> str:
    payload = "\x1f".join(parts)
    digest = hashlib.sha256(
        payload.encode("utf-8"),
    ).hexdigest()

    return f"{prefix}:sha256:{digest}"
