from aegis.schemas.fixes import (
    FixVerificationCheck,
    FixVerificationPlan,
)


def test_verification_plan_round_trips_deterministically() -> None:
    plan = FixVerificationPlan(
        plan_id="verification-plan:claim-command-001",
        claim_id="claim-command-001",
        patch_sha256="a" * 64,
        checks=[
            FixVerificationCheck(
                check_id="check:project-tests",
                kind="project",
                name="Project tests",
            ),
            FixVerificationCheck(
                check_id="check:static-security",
                kind="static_security",
                name="Static security scan",
            ),
            FixVerificationCheck(
                check_id="check:dynamic-replay",
                kind="dynamic_replay",
                name="Authorized dynamic replay",
            ),
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
