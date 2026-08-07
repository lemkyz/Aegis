import hashlib

from aegis.schemas.claims import (
    EvidenceItem,
    EvidenceRelationship,
    EvidenceSource,
    SecurityClaim,
)
from aegis.schemas.fixes import (
    RemediationLifecycleOutcome,
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
    lifecycle_outcome: (
        RemediationLifecycleOutcome
        | None
    ) = None,
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

    lifecycle_evidence: EvidenceItem | None = None
    if lifecycle_outcome is not None:
        _require_lifecycle_outcome_matches_verification(
            claim_id=claim.claim_id,
            verification=verification,
            outcome=lifecycle_outcome,
        )
        outcome_sha256 = (
            lifecycle_outcome.outcome_sha256()
        )
        lifecycle_evidence = EvidenceItem(
            evidence_id=_stable_id(
                "evidence",
                "remediation_lifecycle",
                claim.claim_id,
                outcome_sha256,
            ),
            source=EvidenceSource(
                kind="test_result",
                name=(
                    "Aegis Remediation Lifecycle"
                ),
                rule_id=(
                    "aegis.remediation.lifecycle"
                ),
                version=(
                    lifecycle_outcome.schema_version
                ),
            ),
            summary=(
                "Immutable remediation lifecycle "
                "outcome: "
                f"{lifecycle_outcome.transaction_state}."
            ),
            confidence=verification.confidence,
            locations=[],
            details=[
                (
                    "Manifest ID: "
                    f"{lifecycle_outcome.manifest_id}"
                ),
                (
                    "Manifest SHA-256: "
                    f"{lifecycle_outcome.manifest_sha256}"
                ),
                (
                    "Static verification SHA-256: "
                    f"{lifecycle_outcome.static_verification_sha256}"
                ),
                (
                    "Dynamic validation SHA-256: "
                    f"{lifecycle_outcome.dynamic_validation_sha256}"
                ),
                (
                    "Outcome SHA-256: "
                    f"{outcome_sha256}"
                ),
                (
                    "Unified verdict: "
                    f"{lifecycle_outcome.unified_verdict}"
                ),
                (
                    "Transaction state: "
                    f"{lifecycle_outcome.transaction_state}"
                ),
                (
                    "Residual risk: "
                    f"{lifecycle_outcome.residual_risk.status}"
                ),
            ],
        )

    evidence_items = [
        replay_evidence,
        verification_evidence,
    ]
    if lifecycle_evidence is not None:
        evidence_items.append(
            lifecycle_evidence
        )

    evidence = _append_unique_evidence(
        claim.evidence,
        *evidence_items,
    )
    relationship_reason = (
        "Unified fix verification verifies the "
        "authorized dynamic replay result."
    )
    verification_relationship = EvidenceRelationship(
        relationship_id=_stable_id(
            "relationship",
            "verifies",
            verification_evidence.evidence_id,
            replay_evidence.evidence_id,
            relationship_reason,
        ),
        source_evidence_id=(
            verification_evidence.evidence_id
        ),
        target_evidence_id=replay_evidence.evidence_id,
        kind="verifies",
        reason=relationship_reason,
    )
    lifecycle_relationships = []
    if lifecycle_evidence is not None:
        lifecycle_reason = (
            "Immutable remediation lifecycle outcome "
            "is derived from the unified fix "
            "verification evidence."
        )
        lifecycle_relationships = [
            EvidenceRelationship(
                relationship_id=_stable_id(
                    "relationship",
                    "derived_from",
                    lifecycle_evidence.evidence_id,
                    verification_evidence.evidence_id,
                    lifecycle_reason,
                ),
                source_evidence_id=(
                    lifecycle_evidence.evidence_id
                ),
                target_evidence_id=(
                    verification_evidence.evidence_id
                ),
                kind="derived_from",
                reason=lifecycle_reason,
            )
        ]

    verified_fix = (
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
        and (
            lifecycle_outcome is None
            or lifecycle_outcome.transaction_state
            == "committed"
        )
    )
    mitigation_reason = (
        "Verified remediation mitigates the "
        "original vulnerability evidence."
    )
    original_evidence = [
        item
        for item in claim.evidence
        if item.source.kind
        not in {
            "runtime_execution",
            "test_result",
            "patch_diff",
            "user_decision",
        }
    ]
    mitigation_relationships = [
        EvidenceRelationship(
            relationship_id=_stable_id(
                "relationship",
                "mitigates",
                verification_evidence.evidence_id,
                item.evidence_id,
                mitigation_reason,
            ),
            source_evidence_id=(
                verification_evidence.evidence_id
            ),
            target_evidence_id=item.evidence_id,
            kind="mitigates",
            reason=mitigation_reason,
        )
        for item in original_evidence
    ] if verified_fix else []
    relationships = _append_unique_relationships(
        claim.relationships,
        verification_relationship,
        *lifecycle_relationships,
        *mitigation_relationships,
    )

    state = claim.state

    if verified_fix:
        state = "verified_fixed"

    return claim.model_copy(
        deep=True,
        update={
            "state": state,
            "evidence": evidence,
            "relationships": relationships,
        },
    )


def _require_lifecycle_outcome_matches_verification(
    *,
    claim_id: str,
    verification: UnifiedFixVerificationResponse,
    outcome: RemediationLifecycleOutcome,
) -> None:
    if (
        outcome.residual_risk.claim_id
        != claim_id
    ):
        raise ValueError(
            "Remediation lifecycle outcome must "
            "reference the same claim identifier."
        )

    if (
        outcome.residual_risk.patch_sha256
        != verification.patch_sha256
    ):
        raise ValueError(
            "Remediation lifecycle outcome patch "
            "digest must match fix verification."
        )

    if (
        outcome.unified_verdict
        != verification.verdict
    ):
        raise ValueError(
            "Remediation lifecycle outcome verdict "
            "must match fix verification."
        )

    if (
        outcome.residual_risk
        != verification.residual_risk
    ):
        raise ValueError(
            "Remediation lifecycle outcome residual "
            "risk must match fix verification."
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


def _append_unique_relationships(
    existing: list[EvidenceRelationship],
    *items: EvidenceRelationship,
) -> list[EvidenceRelationship]:
    result = list(existing)
    known_ids = {
        item.relationship_id
        for item in existing
    }

    for item in items:
        if item.relationship_id in known_ids:
            continue

        result.append(item)
        known_ids.add(item.relationship_id)

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
