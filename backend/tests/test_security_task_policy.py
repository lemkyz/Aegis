from aegis.orchestrator.security_task_planner import (
    SecurityTaskPlanner,
)
from aegis.orchestrator.security_task_policy import (
    SecurityTaskPlanningPolicy,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskPlanRequest,
)


def task_ids(result):
    return [
        task.task_id
        for task in result.tasks
    ]


def test_standard_risk_does_not_require_threat_model() -> None:
    decision = SecurityTaskPlanningPolicy().evaluate(
        SecurityTaskPlanRequest(
            operation="deep_analysis",
            has_scanner_evidence=True,
            highest_severity="medium",
            finding_confidence=0.7,
        )
    )

    assert decision.elevated_risk is False
    assert decision.require_threat_model is False
    assert (
        decision.recommend_dynamic_validation
        is False
    )


def test_high_risk_requires_threat_model() -> None:
    decision = SecurityTaskPlanningPolicy().evaluate(
        SecurityTaskPlanRequest(
            operation="deep_analysis",
            has_scanner_evidence=True,
            highest_severity="high",
            finding_confidence=0.95,
        )
    )

    assert decision.elevated_risk is True
    assert decision.require_threat_model is True


def test_proven_flow_requires_threat_model() -> None:
    decision = SecurityTaskPlanningPolicy().evaluate(
        SecurityTaskPlanRequest(
            operation="deep_analysis",
            has_scanner_evidence=True,
            highest_severity="medium",
            finding_confidence=0.8,
            has_proven_data_flow=True,
        )
    )

    assert decision.require_threat_model is True


def test_critical_proven_flow_recommends_validation() -> None:
    decision = SecurityTaskPlanningPolicy().evaluate(
        SecurityTaskPlanRequest(
            operation="deep_analysis",
            has_scanner_evidence=True,
            highest_severity="critical",
            finding_confidence=0.95,
            has_proven_data_flow=True,
        )
    )

    assert (
        decision.recommend_dynamic_validation
        is True
    )
    assert any(
        "explicit authorization" in reason
        for reason in decision.reasons
    )


def test_high_risk_deep_plan_includes_threat_model() -> None:
    result = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="deep_analysis",
            has_scanner_evidence=True,
            highest_severity="high",
            finding_confidence=0.95,
            independently_verified=True,
        )
    )

    assert "threat_model" in task_ids(result)

    threat_model = next(
        task
        for task in result.tasks
        if task.task_id == "threat_model"
    )

    assert [
        dependency.task_id
        for dependency in threat_model.dependencies
    ] == [
        "model_consensus"
    ]

    memory = next(
        task
        for task in result.tasks
        if task.task_id == "security_memory"
    )

    assert [
        dependency.task_id
        for dependency in memory.dependencies
    ] == [
        "attack_graph"
    ]


def test_standard_deep_plan_keeps_existing_pipeline() -> None:
    result = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="deep_analysis",
            has_scanner_evidence=True,
            highest_severity="low",
            finding_confidence=0.8,
        )
    )

    assert "threat_model" not in task_ids(result)
    assert result.execution_order == [
        "repository_context",
        "deterministic_scan",
        "primary_model_review",
        "verifier_review",
        "model_consensus",
        "security_memory",
        "policy_evaluation",
    ]


def test_validation_is_recommended_not_auto_scheduled() -> None:
    result = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="deep_analysis",
            has_scanner_evidence=True,
            highest_severity="critical",
            finding_confidence=0.95,
            has_proven_data_flow=True,
        )
    )

    assert "dynamic_validation" not in task_ids(
        result
    )
    assert any(
        "Controlled dynamic validation" in reason
        for reason in result.reasons
    )
