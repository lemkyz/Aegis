from __future__ import annotations

import asyncio
import time
from typing import Any, Mapping

import pytest

from aegis.orchestrator.security_task_execution import (
    SecurityTaskExecutionMachine,
)
from aegis.orchestrator.security_task_executor import (
    SecurityTaskExecutor,
    SecurityTaskExecutorContractError,
    SecurityTaskNotReadyError,
)
from aegis.orchestrator.security_task_handler import (
    SecurityTaskArtifactStore,
    SecurityTaskHandlerCapability,
    SecurityTaskHandlerContext,
    SecurityTaskHandlerRegistry,
    SecurityTaskHandlerResult,
)
from aegis.orchestrator.security_task_planner import (
    SecurityTaskPlanner,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
    SecurityTaskPlanRequest,
)


class RepositoryContextHandler:
    capability = SecurityTaskHandlerCapability(
        kind="repository_context",
        produced_artifacts=frozenset({
            "repository_context",
        }),
    )

    async def execute(
        self,
        *,
        task: SecurityTaskNode,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> SecurityTaskHandlerResult:
        del task
        del inputs

        return SecurityTaskHandlerResult(
            output={
                "repository_context": {
                    "language": context.language,
                    "operation": (
                        context.operation
                    ),
                },
            },
        )


class DeterministicScanHandler:
    capability = SecurityTaskHandlerCapability(
        kind="deterministic_scan",
        required_artifacts=frozenset({
            "repository_context",
        }),
        produced_artifacts=frozenset({
            "scanner_evidence",
            "scanner_findings",
        }),
    )

    async def execute(
        self,
        *,
        task: SecurityTaskNode,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> SecurityTaskHandlerResult:
        del task
        del context

        return SecurityTaskHandlerResult(
            output={
                "scanner_evidence": [
                    {
                        "source": "fake-scanner",
                        "language": inputs[
                            "repository_context"
                        ]["language"],
                    },
                ],
                "scanner_findings": [],
            },
        )


class FailingContextHandler:
    capability = SecurityTaskHandlerCapability(
        kind="repository_context",
        produced_artifacts=frozenset({
            "repository_context",
        }),
    )

    async def execute(
        self,
        *,
        task: SecurityTaskNode,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> SecurityTaskHandlerResult:
        del task
        del context
        del inputs

        raise RuntimeError(
            "Repository context failed."
        )


class MutatingTaskHandler:
    capability = SecurityTaskHandlerCapability(
        kind="repository_context",
        produced_artifacts=frozenset({
            "repository_context",
        }),
    )

    async def execute(
        self,
        *,
        task: SecurityTaskNode,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> SecurityTaskHandlerResult:
        del context
        del inputs

        task.state = "failed"

        return SecurityTaskHandlerResult(
            output={
                "repository_context": {},
            },
        )


class SlowContextHandler(
    RepositoryContextHandler
):
    async def execute(
        self,
        *,
        task: SecurityTaskNode,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> SecurityTaskHandlerResult:
        await asyncio.sleep(0.1)

        return await super().execute(
            task=task,
            context=context,
            inputs=inputs,
        )


def plan():
    return SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="fast_scan",
            include_security_memory=False,
            include_policy_evaluation=False,
        )
    )


def registry(
    *handlers: object,
) -> SecurityTaskHandlerRegistry:
    value = SecurityTaskHandlerRegistry()

    for handler in handlers:
        value.register(handler)

    value.freeze()
    return value


def context(
    execution_id: str,
    *,
    operation: str = "fast_scan",
    cancelled: bool = False,
) -> SecurityTaskHandlerContext:
    return SecurityTaskHandlerContext(
        execution_id=execution_id,
        operation=operation,
        language="python",
        cancellation_requested=(
            lambda: cancelled
        ),
    )


def execute(coro):
    return asyncio.run(coro)


def task_state(
    execution,
    task_id: str,
) -> str:
    return next(
        task.state
        for task in execution.plan.tasks
        if task.task_id == task_id
    )


def test_executes_ready_task() -> None:
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: "execution:test",
    )
    execution = machine.create(plan())
    store = SecurityTaskArtifactStore()

    executor = SecurityTaskExecutor(
        registry=registry(
            RepositoryContextHandler(),
        ),
        machine=machine,
    )

    step = execute(
        executor.execute_task(
            execution=execution,
            task_id="repository_context",
            context=context(
                execution.execution_id
            ),
            artifact_store=store,
        )
    )

    assert step.success is True
    assert step.error is None
    assert step.task_id == (
        "repository_context"
    )

    assert task_state(
        step.execution,
        "repository_context",
    ) == "completed"

    assert task_state(
        step.execution,
        "deterministic_scan",
    ) == "ready"

    assert store.value(
        "repository_context"
    ) == {
        "language": "python",
        "operation": "fast_scan",
    }


def test_records_artifact_provenance() -> None:
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: "execution:test",
    )
    execution = machine.create(plan())
    store = SecurityTaskArtifactStore()

    executor = SecurityTaskExecutor(
        registry=registry(
            RepositoryContextHandler(),
        ),
        machine=machine,
    )

    step = execute(
        executor.execute_task(
            execution=execution,
            task_id="repository_context",
            context=context(
                execution.execution_id
            ),
            artifact_store=store,
        )
    )

    assert len(step.artifacts) == 1
    assert step.artifacts[
        0
    ].name == "repository_context"
    assert step.artifacts[
        0
    ].producer_task_id == (
        "repository_context"
    )


def test_rejects_waiting_task() -> None:
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: "execution:test",
    )
    execution = machine.create(plan())

    executor = SecurityTaskExecutor(
        registry=registry(
            DeterministicScanHandler(),
        ),
        machine=machine,
    )

    with pytest.raises(
        SecurityTaskNotReadyError,
        match="expected 'ready'",
    ):
        execute(
            executor.execute_task(
                execution=execution,
                task_id=(
                    "deterministic_scan"
                ),
                context=context(
                    execution.execution_id
                ),
                artifact_store=(
                    SecurityTaskArtifactStore()
                ),
            )
        )


def test_rejects_context_execution_mismatch() -> None:
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: "execution:test",
    )
    execution = machine.create(plan())

    executor = SecurityTaskExecutor(
        registry=registry(
            RepositoryContextHandler(),
        ),
        machine=machine,
    )

    with pytest.raises(
        SecurityTaskExecutorContractError,
        match="execution ID",
    ):
        execute(
            executor.execute_task(
                execution=execution,
                task_id="repository_context",
                context=context(
                    "execution:wrong"
                ),
                artifact_store=(
                    SecurityTaskArtifactStore()
                ),
            )
        )


def test_rejects_context_operation_mismatch() -> None:
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: "execution:test",
    )
    execution = machine.create(plan())

    executor = SecurityTaskExecutor(
        registry=registry(
            RepositoryContextHandler(),
        ),
        machine=machine,
    )

    with pytest.raises(
        SecurityTaskExecutorContractError,
        match="operation",
    ):
        execute(
            executor.execute_task(
                execution=execution,
                task_id="repository_context",
                context=context(
                    execution.execution_id,
                    operation="deep_analysis",
                ),
                artifact_store=(
                    SecurityTaskArtifactStore()
                ),
            )
        )


def test_handler_failure_marks_task_failed() -> None:
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: "execution:test",
    )
    execution = machine.create(plan())

    executor = SecurityTaskExecutor(
        registry=registry(
            FailingContextHandler(),
        ),
        machine=machine,
    )

    step = execute(
        executor.execute_task(
            execution=execution,
            task_id="repository_context",
            context=context(
                execution.execution_id
            ),
            artifact_store=(
                SecurityTaskArtifactStore()
            ),
        )
    )

    assert step.success is False
    assert step.error == (
        "Repository context failed."
    )

    assert task_state(
        step.execution,
        "repository_context",
    ) == "failed"

    assert task_state(
        step.execution,
        "deterministic_scan",
    ) == "blocked"


def test_cancelled_execution_marks_task_failed() -> None:
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: "execution:test",
    )
    execution = machine.create(plan())

    executor = SecurityTaskExecutor(
        registry=registry(
            RepositoryContextHandler(),
        ),
        machine=machine,
    )

    step = execute(
        executor.execute_task(
            execution=execution,
            task_id="repository_context",
            context=context(
                execution.execution_id,
                cancelled=True,
            ),
            artifact_store=(
                SecurityTaskArtifactStore()
            ),
        )
    )

    assert step.success is False
    assert step.error == (
        "Security task execution was cancelled."
    )
    assert task_state(
        step.execution,
        "repository_context",
    ) == "failed"
    assert any(
        event.event_type == "task_failed"
        and event.task_id
        == "repository_context"
        for event in step.execution.events
    )


def test_execution_budget_timeout_is_audited(
) -> None:
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: "execution:test",
    )
    execution = machine.create(plan())
    executor = SecurityTaskExecutor(
        registry=registry(
            SlowContextHandler(),
        ),
        machine=machine,
    )
    timed_context = SecurityTaskHandlerContext(
        execution_id=execution.execution_id,
        operation="fast_scan",
        deadline_monotonic=(
            time.monotonic() + 0.01
        ),
    )

    step = execute(
        executor.execute_task(
            execution=execution,
            task_id="repository_context",
            context=timed_context,
            artifact_store=(
                SecurityTaskArtifactStore()
            ),
        )
    )

    assert step.success is False
    assert step.error == (
        "Security task execution exceeded "
        "its time budget."
    )
    assert task_state(
        step.execution,
        "repository_context",
    ) == "failed"
    assert any(
        event.event_type == "task_failed"
        for event in step.execution.events
    )


def test_mid_handler_cancellation_is_audited(
) -> None:
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: "execution:test",
    )
    execution = machine.create(plan())
    executor = SecurityTaskExecutor(
        registry=registry(
            SlowContextHandler(),
        ),
        machine=machine,
    )
    cancel_at = time.monotonic() + 0.01
    cancelled_context = (
        SecurityTaskHandlerContext(
            execution_id=(
                execution.execution_id
            ),
            operation="fast_scan",
            cancellation_requested=(
                lambda: (
                    time.monotonic()
                    >= cancel_at
                )
            ),
        )
    )

    step = execute(
        executor.execute_task(
            execution=execution,
            task_id="repository_context",
            context=cancelled_context,
            artifact_store=(
                SecurityTaskArtifactStore()
            ),
        )
    )

    assert step.success is False
    assert step.error == (
        "Security task execution was cancelled."
    )
    assert task_state(
        step.execution,
        "repository_context",
    ) == "failed"


def test_handler_receives_task_copy() -> None:
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: "execution:test",
    )
    execution = machine.create(plan())

    executor = SecurityTaskExecutor(
        registry=registry(
            MutatingTaskHandler(),
        ),
        machine=machine,
    )

    step = execute(
        executor.execute_task(
            execution=execution,
            task_id="repository_context",
            context=context(
                execution.execution_id
            ),
            artifact_store=(
                SecurityTaskArtifactStore()
            ),
        )
    )

    assert step.success is True

    assert task_state(
        step.execution,
        "repository_context",
    ) == "completed"


def test_executes_second_task_with_first_artifact() -> None:
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: "execution:test",
    )
    execution = machine.create(plan())
    store = SecurityTaskArtifactStore()

    executor = SecurityTaskExecutor(
        registry=registry(
            RepositoryContextHandler(),
            DeterministicScanHandler(),
        ),
        machine=machine,
    )

    first = execute(
        executor.execute_task(
            execution=execution,
            task_id="repository_context",
            context=context(
                execution.execution_id
            ),
            artifact_store=store,
        )
    )

    second = execute(
        executor.execute_task(
            execution=first.execution,
            task_id="deterministic_scan",
            context=context(
                execution.execution_id
            ),
            artifact_store=store,
        )
    )

    assert second.success is True
    assert second.execution.status == (
        "completed"
    )

    assert store.value(
        "scanner_evidence"
    )[0]["language"] == "python"

    assert store.value(
        "scanner_findings"
    ) == []


def test_successful_handler_creates_audit_events() -> None:
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: "execution:test",
    )
    execution = machine.create(plan())

    executor = SecurityTaskExecutor(
        registry=registry(
            RepositoryContextHandler(),
        ),
        machine=machine,
    )

    step = execute(
        executor.execute_task(
            execution=execution,
            task_id="repository_context",
            context=context(
                execution.execution_id
            ),
            artifact_store=(
                SecurityTaskArtifactStore()
            ),
        )
    )

    event_types = [
        event.event_type
        for event in step.execution.events
    ]

    assert "task_started" in event_types
    assert "task_completed" in event_types


def test_failed_handler_creates_failure_event() -> None:
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: "execution:test",
    )
    execution = machine.create(plan())

    executor = SecurityTaskExecutor(
        registry=registry(
            FailingContextHandler(),
        ),
        machine=machine,
    )

    step = execute(
        executor.execute_task(
            execution=execution,
            task_id="repository_context",
            context=context(
                execution.execution_id
            ),
            artifact_store=(
                SecurityTaskArtifactStore()
            ),
        )
    )

    event_types = [
        event.event_type
        for event in step.execution.events
    ]

    assert "task_failed" in event_types


def test_executor_does_not_mutate_input_execution() -> None:
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: "execution:test",
    )
    execution = machine.create(plan())
    before = execution.model_dump()

    executor = SecurityTaskExecutor(
        registry=registry(
            RepositoryContextHandler(),
        ),
        machine=machine,
    )

    execute(
        executor.execute_task(
            execution=execution,
            task_id="repository_context",
            context=context(
                execution.execution_id
            ),
            artifact_store=(
                SecurityTaskArtifactStore()
            ),
        )
    )

    assert execution.model_dump() == before
