import pytest
from pydantic import ValidationError

from aegis.schemas import fixes as fix_schemas


def manifest_type():
    value = getattr(
        fix_schemas,
        "RemediationLifecycleManifest",
        None,
    )

    assert value is not None, (
        "RemediationLifecycleManifest is not implemented."
    )

    return value


def proposal():
    return fix_schemas.SecureFixProposal(
        claim_id="claim-command-001",
        target_path="app.py",
        expected_file_sha256="a" * 64,
        expected_selection_sha256="b" * 64,
        start_offset=10,
        end_offset=20,
        replacement="safe_call()",
    )


def fix_plan():
    value = proposal()

    return fix_schemas.FixPlan(
        plan_id="fix-plan:claim-command-001",
        proposal=value,
        verification_plan=(
            fix_schemas.FixVerificationPlan(
                plan_id=(
                    "verification-plan:"
                    "claim-command-001"
                ),
                claim_id=value.claim_id,
                patch_sha256=value.patch_sha256(),
                checks=[
                    fix_schemas.FixVerificationCheck(
                        check_id="check:project-tests",
                        kind="project",
                        name="Project tests",
                    ),
                ],
            )
        ),
    )


def applied_patch(
    *,
    claim_id: str = "claim-command-001",
    target_path: str = "app.py",
    patch_sha256: str | None = None,
    before_sha256: str = "a" * 64,
    transaction_state: str = "pending",
):
    plan = fix_plan()

    return fix_schemas.AppliedPatchArtifact.model_validate(
        {
            "handler": "test-secure-fix",
            "transaction_id": "fix:transaction-001",
            "claim_id": claim_id,
            "target_path": target_path,
            "approval_id": "approval:test",
            "patch_sha256": (
                patch_sha256
                if patch_sha256 is not None
                else plan.proposal.patch_sha256()
            ),
            "before_sha256": before_sha256,
            "after_sha256": "c" * 64,
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
            "transaction_state": transaction_state,
            "outputs_redacted": True,
        }
    )


def manifest(**updates):
    plan = fix_plan()
    payload = {
        "manifest_id": (
            "remediation-manifest:"
            "claim-command-001"
        ),
        "fix_plan": plan,
        "fix_plan_sha256": plan.plan_sha256(),
        "applied_patch": applied_patch(),
    }
    payload.update(updates)

    return manifest_type()(**payload)


def test_manifest_round_trips_deterministically() -> None:
    value = manifest()

    serialized = value.model_dump_json()
    restored = manifest_type().model_validate_json(
        serialized
    )

    assert restored == value
    assert restored.model_dump_json() == serialized
    assert restored.manifest_sha256() == (
        value.manifest_sha256()
    )
    assert restored.schema_version == "1.0"


def test_manifest_is_immutable() -> None:
    value = manifest()

    with pytest.raises(
        ValidationError,
        match="frozen",
    ):
        value.manifest_id = "remediation-manifest:other"


def test_manifest_rejects_unknown_fields() -> None:
    value = manifest().model_dump(mode="json")
    value["mutable"] = True

    with pytest.raises(
        ValidationError,
        match="Extra inputs are not permitted",
    ):
        manifest_type().model_validate(value)


def test_manifest_rejects_fix_plan_digest_mismatch() -> None:
    with pytest.raises(
        ValidationError,
        match="fix plan digest must match",
    ):
        manifest(
            fix_plan_sha256="f" * 64,
        )


def test_manifest_rejects_claim_identity_mismatch() -> None:
    with pytest.raises(
        ValidationError,
        match="claim identity must match",
    ):
        manifest(
            applied_patch=applied_patch(
                claim_id="claim-other",
            ),
        )


def test_manifest_rejects_patch_digest_mismatch() -> None:
    with pytest.raises(
        ValidationError,
        match="patch digest must match",
    ):
        manifest(
            applied_patch=applied_patch(
                patch_sha256="f" * 64,
            ),
        )


def test_manifest_rejects_target_path_mismatch() -> None:
    with pytest.raises(
        ValidationError,
        match="target path must match",
    ):
        manifest(
            applied_patch=applied_patch(
                target_path="other.py",
            ),
        )


def test_manifest_rejects_before_digest_mismatch() -> None:
    with pytest.raises(
        ValidationError,
        match="before digest must match",
    ):
        manifest(
            applied_patch=applied_patch(
                before_sha256="f" * 64,
            ),
        )


def test_manifest_requires_pending_transaction() -> None:
    with pytest.raises(
        ValidationError,
        match="transaction state must be pending",
    ):
        manifest(
            applied_patch=applied_patch(
                transaction_state="committed",
            ),
        )
