import pytest

from aegis.orchestrator.security_task_aggregator import (
    SecurityTaskAggregationError,
    SecurityTaskResultAggregator,
)
from aegis.orchestrator.security_task_execution import (
    SecurityTaskExecutionMachine,
)
from aegis.orchestrator.security_task_planner import (
    SecurityTaskPlanner,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskPlanRequest,
)


def machine():
    return SecurityTaskExecutionMachine(
        id_factory=lambda: "execution:aggregate",
    )


def fast_plan():
    return SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="fast_scan",
            include_security_memory=False,
            include_policy_evaluation=False,
        )
    )


def task_summary(result, task_id):
    return next(
        summary
        for summary in result.task_summaries
        if summary.task_id == task_id
    )


def execute_context(engine, execution):
    execution = engine.start_task(
        execution,
        "repository_context",
    )

    return engine.complete_task(
        execution,
        "repository_context",
        output={
            "repository_context": {
                "file_count": 4,
                "language": "python",
            }
        },
    )


def test_aggregates_created_execution() -> None:
    execution = machine().create(
        fast_plan()
    )

    result = SecurityTaskResultAggregator().aggregate(
        execution
    )

    assert result.status == "in_progress"
    assert result.ready_task_ids == [
        "repository_context"
    ]
    assert result.pending_terminal_task_ids == [
        "deterministic_scan"
    ]
    assert result.completed_task_ids == []


def test_aggregates_completed_execution() -> None:
    engine = machine()
    execution = engine.create(
        fast_plan()
    )

    execution = execute_context(
        engine,
        execution,
    )

    execution = engine.start_task(
        execution,
        "deterministic_scan",
    )
    execution = engine.complete_task(
        execution,
        "deterministic_scan",
        output={
            "scanner_evidence": [
                {
                    "rule_id": "B602",
                }
            ],
            "scanner_findings": [
                {
                    "severity": "high",
                }
            ],
        },
    )

    result = SecurityTaskResultAggregator().aggregate(
        execution
    )

    assert result.status == "completed"
    assert result.completed_task_ids == [
        "repository_context",
        "deterministic_scan",
    ]
    assert result.pending_terminal_task_ids == []
    assert result.completed_terminal_task_ids == [
        "deterministic_scan"
    ]
    assert [
        artifact.name
        for artifact in result.artifacts
    ] == [
        "repository_context",
        "scanner_evidence",
        "scanner_findings",
    ]


def test_preserves_dependency_safe_summary_order() -> None:
    execution = machine().create(
        fast_plan()
    )

    result = SecurityTaskResultAggregator().aggregate(
        execution
    )

    assert [
        summary.task_id
        for summary in result.task_summaries
    ] == execution.plan.execution_order


def test_records_task_attempts_and_output() -> None:
    engine = machine()
    execution = engine.create(
        fast_plan()
    )
    execution = execute_context(
        engine,
        execution,
    )

    result = SecurityTaskResultAggregator().aggregate(
        execution
    )

    summary = task_summary(
        result,
        "repository_context",
    )

    assert summary.attempts == 1
    assert summary.success is True
    assert summary.output[
        "repository_context"
    ]["file_count"] == 4


def test_failed_task_is_visible_in_aggregation() -> None:
    engine = machine()
    execution = engine.create(
        fast_plan()
    )
    execution = execute_context(
        engine,
        execution,
    )

    execution = engine.start_task(
        execution,
        "deterministic_scan",
    )
    execution = engine.fail_task(
        execution,
        "deterministic_scan",
        error="Scanner crashed.",
    )

    result = SecurityTaskResultAggregator().aggregate(
        execution
    )

    assert result.status == "failed"
    assert result.failed_task_ids == [
        "deterministic_scan"
    ]
    assert result.errors == [
        "deterministic_scan: Scanner crashed."
    ]

    summary = task_summary(
        result,
        "deterministic_scan",
    )

    assert summary.success is False
    assert summary.error == "Scanner crashed."


def test_skipped_chain_is_reported_as_partial() -> None:
    planner = SecurityTaskPlanner()
    engine = machine()

    plan = planner.plan(
        SecurityTaskPlanRequest(
            operation="deep_analysis",
            has_scanner_evidence=True,
            include_security_memory=False,
            include_policy_evaluation=False,
        )
    )

    gates = {
        "scanner_evidence",
        "ai_available",
    }

    execution = engine.create(
        plan,
        satisfied_gates=gates,
    )

    execution = engine.start_task(
        execution,
        "repository_context",
        satisfied_gates=gates,
    )
    execution = engine.complete_task(
        execution,
        "repository_context",
        satisfied_gates=gates,
    )

    execution = engine.start_task(
        execution,
        "deterministic_scan",
        satisfied_gates=gates,
    )
    execution = engine.complete_task(
        execution,
        "deterministic_scan",
        satisfied_gates=gates,
    )

    execution = engine.skip_task(
        execution,
        "primary_model_review",
        reason="No independent model route.",
        satisfied_gates=gates,
    )

    result = SecurityTaskResultAggregator().aggregate(
        execution
    )

    assert result.status == "partial"
    assert result.skipped_task_ids == [
        "primary_model_review",
        "verifier_review",
        "model_consensus",
    ]


def test_only_declared_artifacts_are_exported() -> None:
    engine = machine()
    execution = engine.create(
        fast_plan()
    )

    execution = engine.start_task(
        execution,
        "repository_context",
    )
    execution = engine.complete_task(
        execution,
        "repository_context",
        output={
            "repository_context": {
                "file_count": 1,
            },
            "internal_debug_value": "hidden",
        },
    )

    result = SecurityTaskResultAggregator().aggregate(
        execution
    )

    assert [
        artifact.name
        for artifact in result.artifacts
    ] == [
        "repository_context"
    ]


def test_rejects_duplicate_artifact_producers() -> None:
    plan = fast_plan()

    plan.tasks[1].produces.append(
        "repository_context"
    )

    engine = machine()
    execution = engine.create(plan)

    execution = engine.start_task(
        execution,
        "repository_context",
    )
    execution = engine.complete_task(
        execution,
        "repository_context",
        output={
            "repository_context": {
                "source": "context",
            }
        },
    )

    execution = engine.start_task(
        execution,
        "deterministic_scan",
    )
    execution = engine.complete_task(
        execution,
        "deterministic_scan",
        output={
            "repository_context": {
                "source": "scanner",
            }
        },
    )

    with pytest.raises(
        SecurityTaskAggregationError,
        match="produced by multiple tasks",
    ):
        SecurityTaskResultAggregator().aggregate(
            execution
        )


def test_audit_summary_matches_execution_events() -> None:
    engine = machine()
    execution = engine.create(
        fast_plan()
    )
    execution = execute_context(
        engine,
        execution,
    )

    result = SecurityTaskResultAggregator().aggregate(
        execution
    )

    assert result.audit_event_count == len(
        execution.events
    )
    assert result.last_event_sequence == (
        execution.events[-1].sequence
    )


def test_aggregation_does_not_mutate_execution() -> None:
    execution = machine().create(
        fast_plan()
    )

    before = execution.model_dump()

    SecurityTaskResultAggregator().aggregate(
        execution
    )

    assert execution.model_dump() == before
