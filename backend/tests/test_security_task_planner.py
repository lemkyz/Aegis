from aegis.orchestrator.security_task_planner import (
    SecurityTaskPlanner,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskPlanRequest,
)


def task_by_id(result, task_id):
    return next(
        task
        for task in result.tasks
        if task.task_id == task_id
    )


def test_fast_scan_plans_scanner_only_pipeline() -> None:
    result = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="fast_scan",
        )
    )

    assert result.status == "ready"
    assert result.entry_task_ids == [
        "repository_context"
    ]
    assert result.terminal_task_ids == [
        "deterministic_scan"
    ]
    assert [
        task.task_id
        for task in result.tasks
    ] == [
        "repository_context",
        "deterministic_scan",
    ]


def test_deep_analysis_with_evidence_plans_consensus() -> None:
    result = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="deep_analysis",
            has_scanner_evidence=True,
        )
    )

    assert result.status == "ready"
    assert (
        task_by_id(
            result,
            "primary_model_review",
        ).state
        == "waiting"
    )
    assert (
        task_by_id(
            result,
            "verifier_review",
        ).state
        == "waiting"
    )
    assert (
        task_by_id(
            result,
            "model_consensus",
        ).state
        == "waiting"
    )
    assert result.terminal_task_ids == [
        "policy_evaluation"
    ]


def test_deep_analysis_without_evidence_skips_ai_tasks() -> None:
    result = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="deep_analysis",
            has_scanner_evidence=False,
            include_security_memory=False,
            include_policy_evaluation=False,
        )
    )

    assert (
        task_by_id(
            result,
            "primary_model_review",
        ).state
        == "skipped"
    )
    assert (
        task_by_id(
            result,
            "verifier_review",
        ).state
        == "skipped"
    )
    assert (
        task_by_id(
            result,
            "model_consensus",
        ).state
        == "skipped"
    )


def test_deep_analysis_can_explicitly_include_threat_model() -> None:
    result = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="deep_analysis",
            has_scanner_evidence=True,
            include_threat_model=True,
            include_security_memory=False,
            include_policy_evaluation=False,
        )
    )

    assert (
        task_by_id(
            result,
            "threat_model",
        ).state
        == "waiting"
    )
    assert any(
        "explicitly requested"
        in reason
        for reason in result.reasons
    )


def test_repository_review_plans_parallel_inputs() -> None:
    result = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="repository_review",
        )
    )

    threat_model = task_by_id(
        result,
        "threat_model",
    )

    assert {
        dependency.task_id
        for dependency in threat_model.dependencies
    } == {
        "secret_analysis",
        "dependency_scan",
        "attack_surface",
    }


def test_fix_requires_patch_and_human_approval() -> None:
    result = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="fix_and_verify",
            has_proposed_patch=True,
            human_approval_confirmed=False,
        )
    )

    assert result.status == "blocked"
    assert (
        task_by_id(
            result,
            "secure_fix",
        ).state
        == "blocked"
    )
    assert (
        task_by_id(
            result,
            "fix_verification",
        ).state
        == "blocked"
    )


def test_dynamic_validation_requires_authorization() -> None:
    result = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="fix_and_verify",
            has_proposed_patch=True,
            human_approval_confirmed=True,
            include_dynamic_validation=True,
            authorization_confirmed=False,
        )
    )

    assert result.status == "blocked"
    assert (
        task_by_id(
            result,
            "secure_fix",
        ).state
        == "blocked"
    )

    validation = task_by_id(
        result,
        "dynamic_validation",
    )

    assert validation.state == "blocked"
    assert "authorization" in validation.gates


def test_authorized_fix_plan_reaches_policy_evaluation() -> None:
    result = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="fix_and_verify",
            has_proposed_patch=True,
            human_approval_confirmed=True,
            include_dynamic_validation=True,
            authorization_confirmed=True,
        )
    )

    assert result.status == "ready"
    assert (
        task_by_id(
            result,
            "secure_fix",
        ).state
        == "ready"
    )
    assert (
        task_by_id(
            result,
            "dynamic_validation",
        ).state
        == "waiting"
    )
    assert result.terminal_task_ids == [
        "policy_evaluation"
    ]



def test_planner_emits_dependency_safe_execution_order() -> None:
    result = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="deep_analysis",
            has_scanner_evidence=True,
        )
    )

    positions = {
        task_id: index
        for index, task_id
        in enumerate(result.execution_order)
    }

    for task in result.tasks:
        for dependency in task.dependencies:
            assert (
                positions[dependency.task_id]
                < positions[task.task_id]
            )


def test_repository_parallel_tasks_precede_threat_model() -> None:
    result = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="repository_review",
        )
    )

    positions = {
        task_id: index
        for index, task_id
        in enumerate(result.execution_order)
    }

    assert (
        positions["secret_analysis"]
        < positions["threat_model"]
    )
    assert (
        positions["dependency_scan"]
        < positions["threat_model"]
    )
    assert (
        positions["attack_surface"]
        < positions["threat_model"]
    )

def test_dynamic_validation_declares_lifecycle_outcome_artifact() -> None:
    result = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="fix_and_verify",
            has_proposed_patch=True,
            human_approval_confirmed=True,
            include_dynamic_validation=True,
            authorization_confirmed=True,
        )
    )

    validation = task_by_id(
        result,
        "dynamic_validation",
    )

    assert validation.produces == [
        "dynamic_validation_evidence",
        "remediation_lifecycle_outcome",
    ]

def test_step49_4_deep_analysis_routes_through_attack_graph() -> None:
    result = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="deep_analysis",
            has_scanner_evidence=True,
            include_threat_model=True,
            include_security_memory=True,
            include_policy_evaluation=False,
        )
    )

    attack_graph = task_by_id(
        result,
        "attack_graph",
    )
    assert attack_graph.kind == "attack_graph"
    assert attack_graph.produces == [
        "attack_graph",
    ]
    assert {
        dependency.task_id
        for dependency
        in attack_graph.dependencies
    } == {
        "attack_surface",
        "threat_model",
    }

    memory = task_by_id(
        result,
        "security_memory",
    )
    assert {
        dependency.task_id
        for dependency in memory.dependencies
    } == {"attack_graph"}


def test_step49_4_repository_review_routes_policy_through_attack_graph() -> None:
    result = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="repository_review",
            include_security_memory=False,
            include_policy_evaluation=True,
        )
    )

    attack_graph = task_by_id(
        result,
        "attack_graph",
    )
    policy = task_by_id(
        result,
        "policy_evaluation",
    )

    assert {
        dependency.task_id
        for dependency
        in attack_graph.dependencies
    } == {
        "attack_surface",
        "threat_model",
    }
    assert {
        dependency.task_id
        for dependency in policy.dependencies
    } == {"attack_graph"}

    positions = {
        task_id: index
        for index, task_id
        in enumerate(result.execution_order)
    }
    assert (
        positions["threat_model"]
        < positions["attack_graph"]
        < positions["policy_evaluation"]
    )
