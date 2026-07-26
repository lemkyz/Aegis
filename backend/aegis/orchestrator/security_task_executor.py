from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from aegis.orchestrator.security_task_execution import (
    SecurityTaskExecutionMachine,
    SecurityTaskTransitionError,
)
from aegis.orchestrator.security_task_handler import (
    SecurityTaskArtifact,
    SecurityTaskArtifactStore,
    SecurityTaskExecutionCancelled,
    SecurityTaskHandlerContext,
    SecurityTaskHandlerRegistry,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskExecution,
    SecurityTaskGate,
    SecurityTaskNode,
)


class SecurityTaskExecutorError(RuntimeError):
    """Base executor error."""


class SecurityTaskNotReadyError(
    SecurityTaskExecutorError
):
    pass


class SecurityTaskExecutorContractError(
    SecurityTaskExecutorError
):
    pass


@dataclass(frozen=True, slots=True)
class SecurityTaskExecutionStep:
    execution: SecurityTaskExecution
    artifacts: tuple[
        SecurityTaskArtifact,
        ...,
    ]
    task_id: str
    success: bool
    error: str | None = None


class SecurityTaskExecutor:
    """
    Executes exactly one ready security task.

    State transitions always pass through the existing
    SecurityTaskExecutionMachine. Handlers never mutate
    the execution contract directly.
    """

    executor = "aegis-security-task-executor-v1"

    def __init__(
        self,
        *,
        registry: SecurityTaskHandlerRegistry,
        machine: (
            SecurityTaskExecutionMachine
            | None
        ) = None,
    ) -> None:
        self._registry = registry
        self._machine = (
            machine
            or SecurityTaskExecutionMachine()
        )

    async def execute_task(
        self,
        *,
        execution: SecurityTaskExecution,
        task_id: str,
        context: SecurityTaskHandlerContext,
        artifact_store: SecurityTaskArtifactStore,
        satisfied_gates: Iterable[
            SecurityTaskGate
        ] = (),
    ) -> SecurityTaskExecutionStep:
        task = self._task(
            execution,
            task_id,
        )

        if task.state != "ready":
            raise SecurityTaskNotReadyError(
                f"Security task {task_id!r} "
                "cannot execute from state "
                f"{task.state!r}; expected 'ready'."
            )

        if context.execution_id != (
            execution.execution_id
        ):
            raise SecurityTaskExecutorContractError(
                "Handler context execution ID does "
                "not match the execution contract."
            )

        if context.operation != (
            execution.plan.operation
        ):
            raise SecurityTaskExecutorContractError(
                "Handler context operation does not "
                "match the execution plan."
            )

        handler = self._registry.resolve(
            task.kind
        )

        if (
            handler.capability.kind
            != task.kind
        ):
            raise SecurityTaskExecutorContractError(
                "Resolved handler capability does "
                "not match the selected task kind."
            )

        context.raise_if_cancelled()

        inputs = (
            artifact_store.resolve_inputs(
                handler.capability
            )
        )

        gates = set(satisfied_gates)

        running_execution = (
            self._machine.start_task(
                execution,
                task_id,
                satisfied_gates=gates,
            )
        )

        running_task = self._task(
            running_execution,
            task_id,
        )

        try:
            result = await handler.execute(
                task=running_task.model_copy(
                    deep=True
                ),
                context=context,
                inputs=inputs,
            )

            context.raise_if_cancelled()

            artifacts = (
                artifact_store
                .record_handler_result(
                    task=running_task,
                    capability=(
                        handler.capability
                    ),
                    result=result,
                )
            )

            completed_execution = (
                self._machine.complete_task(
                    running_execution,
                    task_id,
                    output=dict(
                        result.output
                    ),
                    satisfied_gates=gates,
                )
            )

            return SecurityTaskExecutionStep(
                execution=completed_execution,
                artifacts=artifacts,
                task_id=task_id,
                success=True,
            )

        except (
            SecurityTaskExecutionCancelled,
            Exception,
        ) as exc:
            error = self._error_message(exc)

            failed_execution = (
                self._machine.fail_task(
                    running_execution,
                    task_id,
                    error=error,
                    satisfied_gates=gates,
                )
            )

            return SecurityTaskExecutionStep(
                execution=failed_execution,
                artifacts=(),
                task_id=task_id,
                success=False,
                error=error,
            )

    @staticmethod
    def _task(
        execution: SecurityTaskExecution,
        task_id: str,
    ) -> SecurityTaskNode:
        for task in execution.plan.tasks:
            if task.task_id == task_id:
                return task

        raise KeyError(
            f"Unknown security task ID: "
            f"{task_id}."
        )

    @staticmethod
    def _error_message(
        exc: BaseException,
    ) -> str:
        message = str(exc).strip()

        if message:
            return message

        return exc.__class__.__name__
