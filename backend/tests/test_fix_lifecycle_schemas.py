import pytest
from pydantic import ValidationError

from aegis.schemas.fixes import (
    FixPlan,
    FixVerificationCheck,
    FixVerificationPlan,
    ResidualRiskAssessment,
    SecureFixProposal,
    StaticFixVerificationArtifact,
)


def project_check(
    *,
    check_id: str = "check:project-tests",
) -> FixVerificationCheck:
    return FixVerificationCheck(
        check_id=check_id,
        kind="project",
        name="Project tests",
    )


def dynamic_replay_check() -> FixVerificationCheck:
    return FixVerificationCheck(
        check_id="check:dynamic-replay",
        kind="dynamic_replay",
        name="Authorized dynamic replay",
    )


def fix_proposal() -> SecureFixProposal:
    return SecureFixProposal(
        claim_id="claim-command-001",
        target_path="app.py",
        expected_file_sha256="a" * 64,
        expected_selection_sha256="b" * 64,
        start_offset=10,
        end_offset=20,
        replacement="safe_call()",
    )


def fix_plan() -> FixPlan:
    proposal = fix_proposal()

    return FixPlan(
        plan_id="fix-plan:claim-command-001",
        proposal=proposal,
        verification_plan=FixVerificationPlan(
            plan_id=(
                "verification-plan:"
                "claim-command-001"
            ),
            claim_id=proposal.claim_id,
            patch_sha256=proposal.patch_sha256(),
            checks=[
                project_check(),
            ],
        ),
    )


def residual_risk() -> ResidualRiskAssessment:
    return ResidualRiskAssessment(
        claim_id="claim-command-001",
        patch_sha256="a" * 64,
        status="none_identified",
        reasons=[
            "All required verification checks passed.",
        ],
    )


def test_verification_plan_round_trips_deterministically() -> None:
    plan = FixVerificationPlan(
        plan_id="verification-plan:claim-command-001",
        claim_id="claim-command-001",
        patch_sha256="a" * 64,
        checks=[
            project_check(),
            FixVerificationCheck(
                check_id="check:static-security",
                kind="static_security",
                name="Static security scan",
            ),
            dynamic_replay_check(),
        ],
        requires_dynamic_replay=True,
    )

    serialized = plan.model_dump_json()
    restored = (
        FixVerificationPlan
        .model_validate_json(serialized)
    )

    assert restored == plan
    assert restored.model_dump_json() == serialized
    assert restored.plan_sha256() == (
        plan.plan_sha256()
    )
    assert [
        check.check_id
        for check in restored.checks
    ] == [
        "check:project-tests",
        "check:static-security",
        "check:dynamic-replay",
    ]


def test_verification_check_rejects_unknown_fields() -> None:
    with pytest.raises(
        ValidationError,
        match="Extra inputs are not permitted",
    ):
        FixVerificationCheck.model_validate(
            {
                "check_id": "check:project-tests",
                "kind": "project",
                "name": "Project tests",
                "executor": "shell",
            }
        )


def test_verification_plan_rejects_unknown_fields() -> None:
    with pytest.raises(
        ValidationError,
        match="Extra inputs are not permitted",
    ):
        FixVerificationPlan.model_validate(
            {
                "plan_id": (
                    "verification-plan:"
                    "claim-command-001"
                ),
                "claim_id": "claim-command-001",
                "patch_sha256": "a" * 64,
                "checks": [
                    project_check().model_dump(
                        mode="json"
                    )
                ],
                "requires_dynamic_replay": False,
                "verified": True,
            }
        )


def test_verification_plan_rejects_coerced_boolean() -> None:
    with pytest.raises(ValidationError):
        FixVerificationPlan.model_validate(
            {
                "plan_id": (
                    "verification-plan:"
                    "claim-command-001"
                ),
                "claim_id": "claim-command-001",
                "patch_sha256": "a" * 64,
                "checks": [
                    dynamic_replay_check().model_dump(
                        mode="json"
                    )
                ],
                "requires_dynamic_replay": "true",
            }
        )


def test_verification_plan_rejects_duplicate_check_ids() -> None:
    with pytest.raises(
        ValidationError,
        match="check IDs must be unique",
    ):
        FixVerificationPlan(
            plan_id=(
                "verification-plan:"
                "claim-command-001"
            ),
            claim_id="claim-command-001",
            patch_sha256="a" * 64,
            checks=[
                project_check(),
                project_check(),
            ],
        )


def test_required_dynamic_replay_must_have_check() -> None:
    with pytest.raises(
        ValidationError,
        match="requires a dynamic_replay check",
    ):
        FixVerificationPlan(
            plan_id=(
                "verification-plan:"
                "claim-command-001"
            ),
            claim_id="claim-command-001",
            patch_sha256="a" * 64,
            checks=[
                project_check(),
            ],
            requires_dynamic_replay=True,
        )


def test_dynamic_replay_check_requires_plan_flag() -> None:
    with pytest.raises(
        ValidationError,
        match="requires_dynamic_replay must be true",
    ):
        FixVerificationPlan(
            plan_id=(
                "verification-plan:"
                "claim-command-001"
            ),
            claim_id="claim-command-001",
            patch_sha256="a" * 64,
            checks=[
                project_check(),
                dynamic_replay_check(),
            ],
            requires_dynamic_replay=False,
        )

def test_fix_plan_round_trips_deterministically() -> None:
    plan = fix_plan()

    serialized = plan.model_dump_json()
    restored = FixPlan.model_validate_json(
        serialized
    )

    assert restored == plan
    assert restored.model_dump_json() == serialized
    assert restored.plan_sha256() == (
        plan.plan_sha256()
    )
    assert restored.verification_plan.patch_sha256 == (
        restored.proposal.patch_sha256()
    )


def test_fix_plan_rejects_claim_identity_mismatch() -> None:
    proposal = fix_proposal()

    with pytest.raises(
        ValidationError,
        match="claim identity must match",
    ):
        FixPlan(
            plan_id="fix-plan:claim-command-001",
            proposal=proposal,
            verification_plan=FixVerificationPlan(
                plan_id="verification-plan:other",
                claim_id="claim-other",
                patch_sha256=(
                    proposal.patch_sha256()
                ),
                checks=[
                    project_check(),
                ],
            ),
        )


def test_fix_plan_rejects_patch_digest_mismatch() -> None:
    proposal = fix_proposal()

    with pytest.raises(
        ValidationError,
        match="patch digest must match",
    ):
        FixPlan(
            plan_id="fix-plan:claim-command-001",
            proposal=proposal,
            verification_plan=FixVerificationPlan(
                plan_id=(
                    "verification-plan:"
                    "claim-command-001"
                ),
                claim_id=proposal.claim_id,
                patch_sha256="f" * 64,
                checks=[
                    project_check(),
                ],
            ),
        )


def test_fix_plan_rejects_unknown_fields() -> None:
    plan = fix_plan()
    payload = plan.model_dump(
        mode="json"
    )
    payload["verified"] = True

    with pytest.raises(
        ValidationError,
        match="Extra inputs are not permitted",
    ):
        FixPlan.model_validate(payload)



def test_fix_plan_rejects_unknown_proposal_fields() -> None:
    plan = fix_plan()
    payload = plan.model_dump(
        mode="json"
    )
    payload["proposal"]["authorized"] = True

    with pytest.raises(
        ValidationError,
        match="Extra inputs are not permitted",
    ):
        FixPlan.model_validate(payload)


def test_fix_plan_rejects_coerced_proposal_offsets() -> None:
    plan = fix_plan()
    payload = plan.model_dump(
        mode="json"
    )
    payload["proposal"]["start_offset"] = "10"

    with pytest.raises(ValidationError):
        FixPlan.model_validate(payload)


def test_fix_plan_rejects_coerced_identifier() -> None:
    plan = fix_plan()
    payload = plan.model_dump(
        mode="json"
    )
    payload["plan_id"] = 46

    with pytest.raises(ValidationError):
        FixPlan.model_validate(payload)


def test_residual_risk_round_trips_deterministically() -> None:
    assessment = residual_risk()

    serialized = assessment.model_dump_json()
    restored = (
        ResidualRiskAssessment
        .model_validate_json(serialized)
    )

    assert restored == assessment
    assert restored.model_dump_json() == serialized


def test_residual_risk_rejects_unknown_fields() -> None:
    payload = residual_risk().model_dump(
        mode="json"
    )
    payload["accepted"] = True

    with pytest.raises(
        ValidationError,
        match="Extra inputs are not permitted",
    ):
        ResidualRiskAssessment.model_validate(
            payload
        )


def test_residual_risk_requires_evidence_reasons() -> None:
    with pytest.raises(ValidationError):
        ResidualRiskAssessment(
            claim_id="claim-command-001",
            patch_sha256="a" * 64,
            status="inconclusive",
            reasons=[],
        )


def test_residual_risk_rejects_blank_reasons() -> None:
    with pytest.raises(
        ValidationError,
        match="must not be blank",
    ):
        ResidualRiskAssessment(
            claim_id="claim-command-001",
            patch_sha256="a" * 64,
            status="identified",
            reasons=["   "],
        )


def test_residual_risk_rejects_coerced_status() -> None:
    payload = residual_risk().model_dump(
        mode="json"
    )
    payload["status"] = 1

    with pytest.raises(ValidationError):
        ResidualRiskAssessment.model_validate(
            payload
        )


def static_artifact_payload() -> dict[str, object]:
    return {
        "handler": "test-fix-verification",
        "source_artifacts": [
            "applied_patch",
        ],
        "applied_patch": {
            "handler": "test-secure-fix",
            "transaction_id": "fix:test",
            "claim_id": "claim-command-001",
            "target_path": "app.py",
            "approval_id": "approval:test",
            "patch_sha256": "0" * 64,
            "before_sha256": "1" * 64,
            "after_sha256": "2" * 64,
            "changed_characters": 10,
            "policy": {
                "engine": "test-policy",
                "policy_version": "1.0",
                "profile": "balanced",
                "decision": "allow",
                "risk_score": 0,
                "risk_level": "none",
                "blocking_paths": [],
                "review_paths": [],
                "assessments": [],
                "summary": {
                    "files_evaluated": 0,
                    "allowed": 0,
                    "review_required": 0,
                    "blocked": 0,
                    "highest_risk_score": 0,
                    "highest_risk_level": "none",
                    "sensitive_files": 0,
                    "dangerous_patterns": 0,
                    "truncated_files": 0,
                    "binary_files": 0,
                },
                "reasons": [],
            },
            "transaction_state": "pending",
            "outputs_redacted": True,
        },
        "verifier": "test-static-verifier",
        "project_checks": [
            {
                "name": "Tests",
                "status": "passed",
                "details": "Passed.",
            },
        ],
        "security_delta": {
            "scanner": "test-scanner",
            "before_scan_sha256": "3" * 64,
            "after_scan_sha256": "4" * 64,
            "target_finding_ids": [
                "finding:target",
            ],
            "remaining_target_finding_ids": [],
            "introduced_finding_ids": [],
        },
        "static_target_resolved": True,
        "static_regression_free": True,
        "verdict": "awaiting_dynamic",
        "ready_for_dynamic": True,
        "transaction_state": "pending",
        "reasons": [
            "Final proof awaits dynamic replay.",
        ],
        "residual_risk": {
            "claim_id": "claim-command-001",
            "patch_sha256": "0" * 64,
            "status": "inconclusive",
            "reasons": [
                "Dynamic replay has not run.",
            ],
        },
        "outputs_redacted": True,
    }


def test_static_artifact_preserves_residual_risk_provenance() -> None:
    artifact = (
        StaticFixVerificationArtifact
        .model_validate(
            static_artifact_payload()
        )
    )

    serialized = artifact.model_dump_json()
    restored = (
        StaticFixVerificationArtifact
        .model_validate_json(serialized)
    )

    assert restored == artifact
    assert restored.model_dump_json() == serialized
    assert restored.residual_risk.claim_id == (
        restored.applied_patch.claim_id
    )
    assert restored.residual_risk.patch_sha256 == (
        restored.applied_patch.patch_sha256
    )


def test_static_artifact_requires_residual_risk() -> None:
    payload = static_artifact_payload()
    payload.pop("residual_risk")

    with pytest.raises(ValidationError):
        StaticFixVerificationArtifact.model_validate(
            payload
        )


def test_static_artifact_rejects_residual_risk_claim_mismatch() -> None:
    payload = static_artifact_payload()
    residual_risk = payload["residual_risk"]
    assert isinstance(residual_risk, dict)
    residual_risk["claim_id"] = "claim-other"

    with pytest.raises(
        ValidationError,
        match="residual risk claim identity must match",
    ):
        StaticFixVerificationArtifact.model_validate(
            payload
        )


def test_static_artifact_rejects_residual_risk_patch_mismatch() -> None:
    payload = static_artifact_payload()
    residual_risk = payload["residual_risk"]
    assert isinstance(residual_risk, dict)
    residual_risk["patch_sha256"] = "f" * 64

    with pytest.raises(
        ValidationError,
        match="residual risk patch digest must match",
    ):
        StaticFixVerificationArtifact.model_validate(
            payload
        )
