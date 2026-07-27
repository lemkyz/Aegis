from aegis.orchestrator.security_task_planner import (
    SecurityTaskPlanner,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskPlanRequest,
)
from aegis.schemas.validation import (
    ValidationAuthorizationRequest,
)


def authorization(
    **overrides: object,
) -> ValidationAuthorizationRequest:
    values: dict[str, object] = {
        "authorization_confirmed": True,
        "target_type": "local_repository",
        "target": "/tmp/aegis-project",
        "allowed_test_types": [
            "command_injection",
        ],
        "dry_run": False,
        "timeout_seconds": 10,
        "memory_limit_mb": 256,
        "cpu_limit": 0.5,
        "network_policy": "disabled",
    }
    values.update(overrides)

    return ValidationAuthorizationRequest(
        **values,
    )


def task_by_id(result, task_id):
    return next(
        task
        for task in result.tasks
        if task.task_id == task_id
    )


def request_with_authorization(
    validation_authorization=...,
):
    values = {
        "operation": "fix_and_verify",
        "has_proposed_patch": True,
        "human_approval_confirmed": True,
        "include_dynamic_validation": True,
        "include_security_memory": False,
        "include_policy_evaluation": False,
    }

    if validation_authorization is not ...:
        values["validation_authorization"] = (
            validation_authorization
        )

    return SecurityTaskPlanRequest(**values)


def test_structured_authorization_allows_validation() -> None:
    result = SecurityTaskPlanner().plan(
        request_with_authorization(
            authorization()
        )
    )

    validation = task_by_id(
        result,
        "dynamic_validation",
    )

    assert result.status == "ready"
    assert validation.state == "waiting"
    assert any(
        "Execution may be planned" in reason
        for reason in validation.reasons
    )


def test_dry_run_blocks_execution_but_preserves_scope() -> None:
    result = SecurityTaskPlanner().plan(
        request_with_authorization(
            authorization(
                dry_run=True,
            )
        )
    )

    validation = task_by_id(
        result,
        "dynamic_validation",
    )

    assert result.status == "blocked"
    assert (
        task_by_id(
            result,
            "secure_fix",
        ).state
        == "blocked"
    )
    assert validation.state == "blocked"
    assert any(
        "Dry-run mode prevents execution" in reason
        for reason in validation.reasons
    )
    assert any(
        "execution is not allowed" in reason
        for reason in validation.reasons
    )


def test_missing_explicit_authorization_propagates_denial() -> None:
    result = SecurityTaskPlanner().plan(
        request_with_authorization(
            authorization(
                authorization_confirmed=False,
            )
        )
    )

    validation = task_by_id(
        result,
        "dynamic_validation",
    )

    assert validation.state == "blocked"
    assert any(
        "Explicit authorization is required"
        in reason
        for reason in validation.reasons
    )


def test_unsafe_repository_network_policy_is_denied() -> None:
    result = SecurityTaskPlanner().plan(
        request_with_authorization(
            authorization(
                network_policy="loopback",
            )
        )
    )

    validation = task_by_id(
        result,
        "dynamic_validation",
    )

    assert validation.state == "blocked"
    assert any(
        "networking disabled" in reason
        for reason in validation.reasons
    )


def test_relative_repository_target_is_denied() -> None:
    result = SecurityTaskPlanner().plan(
        request_with_authorization(
            authorization(
                target="relative/project",
            )
        )
    )

    validation = task_by_id(
        result,
        "dynamic_validation",
    )

    assert validation.state == "blocked"
    assert any(
        "absolute path" in reason
        for reason in validation.reasons
    )


def test_missing_structured_authorization_is_blocked() -> None:
    result = SecurityTaskPlanner().plan(
        request_with_authorization()
    )

    validation = task_by_id(
        result,
        "dynamic_validation",
    )

    assert validation.state == "blocked"
    assert any(
        "structured validation authorization"
        in reason.lower()
        for reason in validation.reasons
    )


def test_legacy_authorization_flag_remains_compatible() -> None:
    result = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="fix_and_verify",
            has_proposed_patch=True,
            human_approval_confirmed=True,
            include_dynamic_validation=True,
            authorization_confirmed=True,
            include_security_memory=False,
            include_policy_evaluation=False,
        )
    )

    validation = task_by_id(
        result,
        "dynamic_validation",
    )

    assert validation.state == "waiting"
    assert any(
        "Legacy authorization confirmation"
        in reason
        for reason in validation.reasons
    )
