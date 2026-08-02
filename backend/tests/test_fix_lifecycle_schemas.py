import pytest
from pydantic import ValidationError

from aegis.schemas.fixes import (
    FixVerificationCheck,
    FixVerificationPlan,
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
