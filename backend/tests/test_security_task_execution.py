from datetime import UTC, datetime, timedelta

import pytest

from aegis.orchestrator.security_task_execution import (
    SecurityTaskExecutionMachine,
    SecurityTaskTransitionError,
)
from aegis.orchestrator.security_task_planner import (
    SecurityTaskPlanner,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskPlanRequest,
)


class Clock:
    def __init__(self) -> None:
        self.value = datetime(
            2026,
            7,
            26,
            18,
            0,
            tzinfo=UTC,
        )

    def __call__(self) -> datetime:
        current = self.value
        self.value += timedelta(seconds=1)
        return current


def machine() -> SecurityTaskExecutionMachine:
    return SecurityTaskExecutionMachine(
        clock=Clock(),
        id_factory=lambda: "execution:test",
    )


def fast_plan():
    return SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="fast_scan",
        )
    )


def deep_plan():
    return SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="deep_analysis",
            has_scanner_evidence=True,
            include_security_memory=False,
            include_policy_evaluation=False,
        )
    )


def task(execution, task_id):
    return next(
        item
        for item in execution.plan.tasks
        if item.task_id == task_id
    )


def record(execution, task_id):
    return next(
        item
        for item in execution.runtime
        if item.task_id == task_id
    )


def test_creates_execution_with_runtime_records() -> None:
    execution = machine().create(
        fast_plan()
    )

    assert execution.execution_id == (
        "execution:test"
    )
    assert execution.status == "created"
    assert len(execution.runtime) == 2
    assert execution.events[0].event_type == (
        "execution_created"
    )
    assert [
        event.sequence
        for event in execution.events
    ] == [1]


def test_starts_ready_entry_task() -> None:
    engine = machine()
    execution = engine.create(
        fast_plan()
    )

    execution = engine.start_task(
        execution,
        "repository_context",
    )

    assert (
        task(
            execution,
            "repository_context",
        ).state
        == "running"
    )
    assert execution.status == "running"
    assert (
        record(
            execution,
            "repository_context",
        ).attempts
        == 1
    )


def test_cannot_start_waiting_dependency() -> None:
    engine = machine()
    execution = engine.create(
        fast_plan()
    )

    with pytest.raises(
        SecurityTaskTransitionError,
        match="cannot start",
    ):
        engine.start_task(
            execution,
            "deterministic_scan",
        )


def test_completion_unlocks_dependent_task() -> None:
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
            "files_indexed": 4,
        },
    )

    assert (
        task(
            execution,
            "repository_context",
        ).state
        == "completed"
    )
    assert (
        task(
            execution,
            "deterministic_scan",
        ).state
        == "ready"
    )
    assert (
        record(
            execution,
            "repository_context",
        ).result.output["files_indexed"]
        == 4
    )


def test_completed_task_cannot_start_again() -> None:
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
    )

    with pytest.raises(
        SecurityTaskTransitionError,
        match="cannot start",
    ):
        engine.start_task(
            execution,
            "repository_context",
        )


def test_failed_task_blocks_downstream_chain() -> None:
    engine = machine()
    execution = engine.create(
        deep_plan(),
        satisfied_gates={
            "scanner_evidence",
            "ai_available",
        },
    )

    execution = engine.start_task(
        execution,
        "repository_context",
        satisfied_gates={
            "scanner_evidence",
            "ai_available",
        },
    )
    execution = engine.complete_task(
        execution,
        "repository_context",
        satisfied_gates={
            "scanner_evidence",
            "ai_available",
        },
    )

    execution = engine.start_task(
        execution,
        "deterministic_scan",
        satisfied_gates={
            "scanner_evidence",
            "ai_available",
        },
    )
    execution = engine.fail_task(
        execution,
        "deterministic_scan",
        error="Scanner process exited unexpectedly.",
        satisfied_gates={
            "scanner_evidence",
            "ai_available",
        },
    )

    assert (
        task(
            execution,
            "deterministic_scan",
        ).state
        == "failed"
    )
    assert (
        task(
            execution,
            "primary_model_review",
        ).state
        == "blocked"
    )
    assert (
        task(
            execution,
            "verifier_review",
        ).state
        == "blocked"
    )
    assert (
        task(
            execution,
            "model_consensus",
        ).state
        == "blocked"
    )
    assert execution.status in {
        "failed",
        "blocked",
        "partial",
    }


def test_full_fast_execution_completes() -> None:
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
    )
    execution = engine.start_task(
        execution,
        "deterministic_scan",
    )
    execution = engine.complete_task(
        execution,
        "deterministic_scan",
        output={
            "finding_count": 2,
        },
    )

    assert execution.status == "completed"
    assert all(
        item.state == "completed"
        for item in execution.plan.tasks
    )


def test_task_must_be_running_before_completion() -> None:
    engine = machine()
    execution = engine.create(
        fast_plan()
    )

    with pytest.raises(
        SecurityTaskTransitionError,
        match="cannot complete",
    ):
        engine.complete_task(
            execution,
            "repository_context",
        )


def test_failed_task_requires_error_message() -> None:
    engine = machine()
    execution = engine.create(
        fast_plan()
    )

    execution = engine.start_task(
        execution,
        "repository_context",
    )

    with pytest.raises(
        ValueError,
        match="must include an error",
    ):
        engine.fail_task(
            execution,
            "repository_context",
            error="   ",
        )


def test_skip_propagates_to_dependents() -> None:
    engine = machine()
    execution = engine.create(
        deep_plan(),
        satisfied_gates={
            "scanner_evidence",
            "ai_available",
        },
    )

    execution = engine.start_task(
        execution,
        "repository_context",
        satisfied_gates={
            "scanner_evidence",
            "ai_available",
        },
    )
    execution = engine.complete_task(
        execution,
        "repository_context",
        satisfied_gates={
            "scanner_evidence",
            "ai_available",
        },
    )
    execution = engine.start_task(
        execution,
        "deterministic_scan",
        satisfied_gates={
            "scanner_evidence",
            "ai_available",
        },
    )
    execution = engine.complete_task(
        execution,
        "deterministic_scan",
        satisfied_gates={
            "scanner_evidence",
            "ai_available",
        },
    )

    execution = engine.skip_task(
        execution,
        "primary_model_review",
        reason="No model route was available.",
        satisfied_gates={
            "scanner_evidence",
            "ai_available",
        },
    )

    assert (
        task(
            execution,
            "primary_model_review",
        ).state
        == "skipped"
    )
    assert (
        task(
            execution,
            "verifier_review",
        ).state
        == "skipped"
    )
    assert (
        task(
            execution,
            "model_consensus",
        ).state
        == "skipped"
    )


def test_events_have_contiguous_sequences() -> None:
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
    )

    assert [
        event.sequence
        for event in execution.events
    ] == list(
        range(1, len(execution.events) + 1)
    )


def test_execution_records_successful_output() -> None:
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
            "language": "python",
            "file_count": 12,
        },
    )

    result = record(
        execution,
        "repository_context",
    ).result

    assert result is not None
    assert result.success is True
    assert result.output == {
        "language": "python",
        "file_count": 12,
    }


def test_unknown_task_id_is_rejected() -> None:
    engine = machine()
    execution = engine.create(
        fast_plan()
    )

    with pytest.raises(
        KeyError,
        match="Unknown security task ID",
    ):
        engine.start_task(
            execution,
            "missing_task",
        )
