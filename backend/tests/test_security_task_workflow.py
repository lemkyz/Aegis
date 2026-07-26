from __future__ import annotations

import asyncio
from typing import Any, Mapping

import pytest

from aegis.orchestrator.security_task_execution import (
    SecurityTaskExecutionMachine,
)
from aegis.orchestrator.security_task_executor import (
    SecurityTaskExecutor,
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
from aegis.orchestrator.security_task_workflow import (
    SecurityTaskWorkflowContractError,
    SecurityTaskWorkflowRunner,
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
                    "operation": context.operation,
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
                        "source": "workflow-test",
                        "language": inputs[
                            "repository_context"
                        ]["language"],
                    }
                ],
                "scanner_findings": [
                    {
                        "title": (
                            "Example scanner finding"
                        ),
                        "severity": "medium",
                    }
                ],
            },
        )


class FailingRepositoryContextHandler:
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
            "Unable to collect repository context."
        )


def fast_plan():
    return SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="fast_scan",
            include_security_memory=False,
            include_policy_evaluation=False,
        )
    )


def build_registry(
    *handlers: object,
) -> SecurityTaskHandlerRegistry:
    registry = SecurityTaskHandlerRegistry()

    for handler in handlers:
        registry.register(handler)

    registry.freeze()
    return registry


def build_execution():
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: (
            "execution:workflow-test"
        ),
    )

    return (
        machine,
        machine.create(
            fast_plan()
        ),
    )


def build_context(
    execution_id: str,
    *,
    operation: str = "fast_scan",
) -> SecurityTaskHandlerContext:
    return SecurityTaskHandlerContext(
        execution_id=execution_id,
        operation=operation,
        language="python",
    )


def run(coro):
    return asyncio.run(coro)


def task_states(execution):
    return {
        task.task_id: task.state
        for task in execution.plan.tasks
    }


def test_runs_complete_fast_scan_workflow() -> None:
    machine, execution = build_execution()
    store = SecurityTaskArtifactStore()

    executor = SecurityTaskExecutor(
        registry=build_registry(
            RepositoryContextHandler(),
            DeterministicScanHandler(),
        ),
        machine=machine,
    )

    workflow = SecurityTaskWorkflowRunner(
        executor=executor,
    )

    result = run(
        workflow.run(
            execution=execution,
            context=build_context(
                execution.execution_id
            ),
            artifact_store=store,
        )
    )

    assert result.status == "completed"
    assert result.execution.status == (
        "completed"
    )

    assert result.executed_task_ids == (
        "repository_context",
        "deterministic_scan",
    )

    assert result.successful_task_ids == (
        "repository_context",
        "deterministic_scan",
    )

    assert result.failed_task_ids == ()

    assert task_states(
        result.execution
    ) == {
        "repository_context": "completed",
        "deterministic_scan": "completed",
    }

    assert result.aggregation.status == (
        "completed"
    )

    assert result.aggregation.completed_task_ids == [
        "repository_context",
        "deterministic_scan",
    ]

    assert store.value(
        "scanner_evidence"
    )[0]["language"] == "python"


def test_selects_tasks_in_execution_order() -> None:
    machine, execution = build_execution()

    executor = SecurityTaskExecutor(
        registry=build_registry(
            RepositoryContextHandler(),
            DeterministicScanHandler(),
        ),
        machine=machine,
    )

    result = run(
        SecurityTaskWorkflowRunner(
            executor=executor,
        ).run(
            execution=execution,
            context=build_context(
                execution.execution_id
            ),
        )
    )

    assert result.executed_task_ids == tuple(
        execution.plan.execution_order
    )


def test_failure_stops_required_workflow() -> None:
    machine, execution = build_execution()

    executor = SecurityTaskExecutor(
        registry=build_registry(
            FailingRepositoryContextHandler(),
        ),
        machine=machine,
    )

    result = run(
        SecurityTaskWorkflowRunner(
            executor=executor,
        ).run(
            execution=execution,
            context=build_context(
                execution.execution_id
            ),
        )
    )

    states = task_states(
        result.execution
    )

    assert result.status == "failed"
    assert result.executed_task_ids == (
        "repository_context",
    )
    assert result.successful_task_ids == ()
    assert result.failed_task_ids == (
        "repository_context",
    )

    assert states[
        "repository_context"
    ] == "failed"

    assert states[
        "deterministic_scan"
    ] == "blocked"

    assert result.errors == (
        "Unable to collect repository context.",
    )

    assert result.aggregation.failed_task_ids == [
        "repository_context",
    ]


def test_missing_handler_returns_controlled_failure() -> None:
    machine, execution = build_execution()

    executor = SecurityTaskExecutor(
        registry=build_registry(),
        machine=machine,
    )

    result = run(
        SecurityTaskWorkflowRunner(
            executor=executor,
        ).run(
            execution=execution,
            context=build_context(
                execution.execution_id
            ),
        )
    )

    assert result.status == "failed"
    assert result.executed_task_ids == ()
    assert len(result.errors) == 1
    assert "No handler is registered" in (
        result.errors[0]
    )

    assert task_states(
        result.execution
    )["repository_context"] == "ready"


def test_step_limit_stops_workflow() -> None:
    machine, execution = build_execution()
    store = SecurityTaskArtifactStore()

    executor = SecurityTaskExecutor(
        registry=build_registry(
            RepositoryContextHandler(),
            DeterministicScanHandler(),
        ),
        machine=machine,
    )

    result = run(
        SecurityTaskWorkflowRunner(
            executor=executor,
            max_steps=1,
        ).run(
            execution=execution,
            context=build_context(
                execution.execution_id
            ),
            artifact_store=store,
        )
    )

    assert result.status == (
        "step_limit_reached"
    )

    assert result.executed_task_ids == (
        "repository_context",
    )

    assert task_states(
        result.execution
    ) == {
        "repository_context": "completed",
        "deterministic_scan": "ready",
    }

    assert result.aggregation.status == (
        "in_progress"
    )


def test_rejects_zero_step_limit() -> None:
    machine, _ = build_execution()

    executor = SecurityTaskExecutor(
        registry=build_registry(),
        machine=machine,
    )

    with pytest.raises(
        SecurityTaskWorkflowContractError,
        match="at least one",
    ):
        SecurityTaskWorkflowRunner(
            executor=executor,
            max_steps=0,
        )


def test_rejects_context_execution_mismatch() -> None:
    machine, execution = build_execution()

    executor = SecurityTaskExecutor(
        registry=build_registry(
            RepositoryContextHandler(),
        ),
        machine=machine,
    )

    workflow = SecurityTaskWorkflowRunner(
        executor=executor,
    )

    with pytest.raises(
        SecurityTaskWorkflowContractError,
        match="execution ID",
    ):
        run(
            workflow.run(
                execution=execution,
                context=build_context(
                    "execution:wrong"
                ),
            )
        )


def test_rejects_context_operation_mismatch() -> None:
    machine, execution = build_execution()

    executor = SecurityTaskExecutor(
        registry=build_registry(
            RepositoryContextHandler(),
        ),
        machine=machine,
    )

    workflow = SecurityTaskWorkflowRunner(
        executor=executor,
    )

    with pytest.raises(
        SecurityTaskWorkflowContractError,
        match="operation",
    ):
        run(
            workflow.run(
                execution=execution,
                context=build_context(
                    execution.execution_id,
                    operation="deep_analysis",
                ),
            )
        )


def test_workflow_does_not_mutate_input_execution() -> None:
    machine, execution = build_execution()
    before = execution.model_dump()

    executor = SecurityTaskExecutor(
        registry=build_registry(
            RepositoryContextHandler(),
            DeterministicScanHandler(),
        ),
        machine=machine,
    )

    run(
        SecurityTaskWorkflowRunner(
            executor=executor,
        ).run(
            execution=execution,
            context=build_context(
                execution.execution_id
            ),
        )
    )

    assert execution.model_dump() == before


def test_workflow_result_contains_executor_steps() -> None:
    machine, execution = build_execution()

    executor = SecurityTaskExecutor(
        registry=build_registry(
            RepositoryContextHandler(),
            DeterministicScanHandler(),
        ),
        machine=machine,
    )

    result = run(
        SecurityTaskWorkflowRunner(
            executor=executor,
        ).run(
            execution=execution,
            context=build_context(
                execution.execution_id
            ),
        )
    )

    assert len(result.steps) == 2

    assert [
        step.task_id
        for step in result.steps
    ] == [
        "repository_context",
        "deterministic_scan",
    ]

    assert all(
        step.success
        for step in result.steps
    )


def test_completed_workflow_has_terminal_reason() -> None:
    machine, execution = build_execution()

    executor = SecurityTaskExecutor(
        registry=build_registry(
            RepositoryContextHandler(),
            DeterministicScanHandler(),
        ),
        machine=machine,
    )

    result = run(
        SecurityTaskWorkflowRunner(
            executor=executor,
        ).run(
            execution=execution,
            context=build_context(
                execution.execution_id
            ),
        )
    )

    assert result.stop_reason == (
        "All executable security tasks completed."
    )
