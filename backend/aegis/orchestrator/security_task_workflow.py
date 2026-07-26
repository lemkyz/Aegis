from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Literal

from aegis.orchestrator.security_task_aggregator import (
    SecurityTaskResultAggregator,
)
from aegis.orchestrator.security_task_executor import (
    SecurityTaskExecutionStep,
    SecurityTaskExecutor,
)
from aegis.orchestrator.security_task_handler import (
    SecurityTaskArtifactStore,
    SecurityTaskHandlerContext,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskAggregation,
    SecurityTaskExecution,
    SecurityTaskGate,
    SecurityTaskNode,
)


SecurityWorkflowStatus = Literal[
    "completed",
    "failed",
    "blocked",
    "stopped",
    "step_limit_reached",
]


class SecurityTaskWorkflowError(RuntimeError):
    """Base workflow orchestration error."""


class SecurityTaskWorkflowContractError(
    SecurityTaskWorkflowError
):
    pass


@dataclass(frozen=True, slots=True)
class SecurityTaskWorkflowResult:
    workflow: str
    status: SecurityWorkflowStatus
    execution: SecurityTaskExecution
    aggregation: SecurityTaskAggregation
    executed_task_ids: tuple[str, ...]
    successful_task_ids: tuple[str, ...]
    failed_task_ids: tuple[str, ...]
    steps: tuple[SecurityTaskExecutionStep, ...]
    errors: tuple[str, ...]
    stop_reason: str


class SecurityTaskWorkflowRunner:
    """
    Executes ready tasks in deterministic plan order.

    The workflow never starts waiting, blocked, skipped,
    completed, failed, or running tasks directly.
    """

    workflow = "aegis-security-task-workflow-v1"

    def __init__(
        self,
        *,
        executor: SecurityTaskExecutor,
        aggregator: (
            SecurityTaskResultAggregator
            | None
        ) = None,
        max_steps: int = 100,
        stop_on_failure: bool = True,
    ) -> None:
        if max_steps < 1:
            raise SecurityTaskWorkflowContractError(
                "Workflow max_steps must be at least one."
            )

        self._executor = executor
        self._aggregator = (
            aggregator
            or SecurityTaskResultAggregator()
        )
        self._max_steps = max_steps
        self._stop_on_failure = stop_on_failure

    async def run(
        self,
        *,
        execution: SecurityTaskExecution,
        context: SecurityTaskHandlerContext,
        artifact_store: (
            SecurityTaskArtifactStore
            | None
        ) = None,
        satisfied_gates: Iterable[
            SecurityTaskGate
        ] = (),
    ) -> SecurityTaskWorkflowResult:
        self._validate_context(
            execution,
            context,
        )

        current = execution.model_copy(
            deep=True
        )
        store = (
            artifact_store
            if artifact_store is not None
            else SecurityTaskArtifactStore()
        )
        gates = tuple(satisfied_gates)

        steps: list[
            SecurityTaskExecutionStep
        ] = []
        errors: list[str] = []

        for _ in range(self._max_steps):
            ready_task = self._next_ready_task(
                current
            )

            if ready_task is None:
                return self._result(
                    execution=current,
                    steps=steps,
                    errors=errors,
                    stop_reason=(
                        self._terminal_reason(
                            current
                        )
                    ),
                )

            try:
                step = (
                    await self._executor.execute_task(
                        execution=current,
                        task_id=ready_task.task_id,
                        context=context,
                        artifact_store=store,
                        satisfied_gates=gates,
                    )
                )
            except Exception as exc:
                errors.append(
                    self._error_message(exc)
                )

                return self._result(
                    execution=current,
                    steps=steps,
                    errors=errors,
                    status_override="failed",
                    stop_reason=(
                        "Workflow stopped before task "
                        f"{ready_task.task_id!r} could "
                        "be executed."
                    ),
                )

            steps.append(step)
            current = step.execution

            if not step.success:
                if step.error:
                    errors.append(step.error)

                if self._stop_on_failure:
                    return self._result(
                        execution=current,
                        steps=steps,
                        errors=errors,
                        stop_reason=(
                            "Workflow stopped after "
                            f"task {step.task_id!r} "
                            "failed."
                        ),
                    )

        return self._result(
            execution=current,
            steps=steps,
            errors=errors,
            status_override=(
                "step_limit_reached"
            ),
            stop_reason=(
                "Workflow stopped because the "
                f"maximum of {self._max_steps} "
                "execution steps was reached."
            ),
        )

    def _result(
        self,
        *,
        execution: SecurityTaskExecution,
        steps: list[
            SecurityTaskExecutionStep
        ],
        errors: list[str],
        stop_reason: str,
        status_override: (
            SecurityWorkflowStatus
            | None
        ) = None,
    ) -> SecurityTaskWorkflowResult:
        aggregation = (
            self._aggregator.aggregate(
                execution
            )
        )

        status = (
            status_override
            or self._workflow_status(
                execution,
                aggregation,
            )
        )

        executed_task_ids = tuple(
            step.task_id
            for step in steps
        )

        successful_task_ids = tuple(
            step.task_id
            for step in steps
            if step.success
        )

        failed_task_ids = tuple(
            step.task_id
            for step in steps
            if not step.success
        )

        return SecurityTaskWorkflowResult(
            workflow=self.workflow,
            status=status,
            execution=execution.model_copy(
                deep=True
            ),
            aggregation=aggregation.model_copy(
                deep=True
            ),
            executed_task_ids=(
                executed_task_ids
            ),
            successful_task_ids=(
                successful_task_ids
            ),
            failed_task_ids=(
                failed_task_ids
            ),
            steps=tuple(steps),
            errors=tuple(errors),
            stop_reason=stop_reason,
        )

    @staticmethod
    def _next_ready_task(
        execution: SecurityTaskExecution,
    ) -> SecurityTaskNode | None:
        tasks_by_id = {
            task.task_id: task
            for task in execution.plan.tasks
        }

        for task_id in (
            execution.plan.execution_order
        ):
            task = tasks_by_id[task_id]

            if task.state == "ready":
                return task

        return None

    @staticmethod
    def _workflow_status(
        execution: SecurityTaskExecution,
        aggregation: SecurityTaskAggregation,
    ) -> SecurityWorkflowStatus:
        if aggregation.failed_task_ids:
            return "failed"

        if (
            execution.status == "completed"
            or aggregation.status == "completed"
        ):
            return "completed"

        if aggregation.blocked_task_ids:
            return "blocked"

        return "stopped"

    @staticmethod
    def _terminal_reason(
        execution: SecurityTaskExecution,
    ) -> str:
        states = {
            task.state
            for task in execution.plan.tasks
        }

        if execution.status == "completed":
            return (
                "All executable security tasks "
                "completed."
            )

        if "failed" in states:
            return (
                "No ready tasks remain after a "
                "task failure."
            )

        if "blocked" in states:
            return (
                "No ready tasks remain because the "
                "remaining workflow is blocked."
            )

        if states <= {
            "completed",
            "skipped",
        }:
            return (
                "All planned tasks reached terminal "
                "states."
            )

        return (
            "No ready tasks remain; the workflow "
            "cannot make further progress."
        )

    @staticmethod
    def _validate_context(
        execution: SecurityTaskExecution,
        context: SecurityTaskHandlerContext,
    ) -> None:
        if (
            context.execution_id
            != execution.execution_id
        ):
            raise SecurityTaskWorkflowContractError(
                "Workflow context execution ID does "
                "not match the execution contract."
            )

        if (
            context.operation
            != execution.plan.operation
        ):
            raise SecurityTaskWorkflowContractError(
                "Workflow context operation does not "
                "match the execution plan."
            )

    @staticmethod
    def _error_message(
        exc: BaseException,
    ) -> str:
        message = str(exc).strip()

        if message:
            return message

        return exc.__class__.__name__
