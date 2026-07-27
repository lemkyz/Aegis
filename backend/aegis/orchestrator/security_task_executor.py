from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from aegis.orchestrator.security_task_execution import (
    SecurityTaskExecutionMachine,
    SecurityTaskTransitionError,
)
from aegis.orchestrator.security_task_handler import (
    SecurityTaskArtifact,
    SecurityTaskArtifactStore,
    SecurityTaskExecutionTimedOut,
    SecurityTaskHandler,
    SecurityTaskHandlerContext,
    SecurityTaskHandlerResult,
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
            context.raise_if_cancelled()

            inputs = (
                artifact_store.resolve_inputs(
                    handler.capability
                )
            )

            result = await self._execute_handler(
                handler=handler,
                task=running_task,
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

        except Exception as exc:
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
    async def _execute_handler(
        *,
        handler: SecurityTaskHandler,
        task: SecurityTaskNode,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> SecurityTaskHandlerResult:
        async def invoke(
        ) -> SecurityTaskHandlerResult:
            return await handler.execute(
                task=task.model_copy(
                    deep=True
                ),
                context=context,
                inputs=inputs,
            )

        handler_task = asyncio.create_task(
            invoke()
        )

        try:
            while True:
                context.raise_if_cancelled()
                remaining = (
                    context.remaining_seconds()
                )
                poll_seconds = 0.1

                if remaining is not None:
                    if remaining <= 0:
                        raise (
                            SecurityTaskExecutionTimedOut(
                                "Security task "
                                "execution exceeded "
                                "its time budget."
                            )
                        )

                    poll_seconds = min(
                        poll_seconds,
                        remaining,
                    )

                done, _pending = (
                    await asyncio.wait(
                        {handler_task},
                        timeout=poll_seconds,
                    )
                )

                if done:
                    return await handler_task
        except BaseException:
            if not handler_task.done():
                handler_task.cancel()

                with suppress(
                    asyncio.CancelledError
                ):
                    await handler_task

            raise

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
