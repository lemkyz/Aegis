from collections.abc import Callable
from datetime import UTC, datetime
from uuid import uuid4

from aegis.orchestrator.security_task_state import (
    SecurityTaskStateResolver,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskEventType,
    SecurityTaskExecution,
    SecurityTaskExecutionEvent,
    SecurityTaskPlanResponse,
    SecurityTaskResult,
    SecurityTaskRuntimeRecord,
)


class SecurityTaskTransitionError(ValueError):
    pass


class SecurityTaskExecutionMachine:
    engine = "aegis-security-task-execution-v1"

    def __init__(
        self,
        *,
        resolver: SecurityTaskStateResolver | None = None,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self._resolver = (
            resolver
            if resolver is not None
            else SecurityTaskStateResolver()
        )
        self._clock = (
            clock
            if clock is not None
            else lambda: datetime.now(UTC)
        )
        self._id_factory = (
            id_factory
            if id_factory is not None
            else lambda: f"execution:{uuid4()}"
        )

    def create(
        self,
        plan: SecurityTaskPlanResponse,
        *,
        satisfied_gates: set[str] | None = None,
    ) -> SecurityTaskExecution:
        now = self._clock()

        resolved_plan = self._resolver.resolve(
            plan,
            satisfied_gates=(
                satisfied_gates or set()
            ),
        )

        execution = SecurityTaskExecution(
            execution_id=self._id_factory(),
            status=self._execution_status(
                resolved_plan
            ),
            plan=resolved_plan,
            runtime=[
                SecurityTaskRuntimeRecord(
                    task_id=task.task_id,
                )
                for task in resolved_plan.tasks
            ],
            events=[],
            created_at=now,
            updated_at=now,
        )

        self._append_event(
            execution,
            event_type="execution_created",
            message=(
                "Security task execution was created "
                "from an inspectable task plan."
            ),
        )

        return execution

    def start_task(
        self,
        execution: SecurityTaskExecution,
        task_id: str,
        *,
        satisfied_gates: set[str] | None = None,
    ) -> SecurityTaskExecution:
        updated = execution.model_copy(deep=True)

        self._resolve(
            updated,
            satisfied_gates=satisfied_gates,
        )

        task = self._task(updated, task_id)

        if task.state != "ready":
            raise SecurityTaskTransitionError(
                f"Task {task_id!r} cannot start from "
                f"state {task.state!r}."
            )

        record = self._record(updated, task_id)
        previous_state = task.state

        task.state = "running"
        record.attempts += 1
        record.started_at = self._clock()
        record.finished_at = None
        record.result = None

        updated.updated_at = record.started_at
        updated.status = "running"

        self._append_event(
            updated,
            event_type="task_started",
            task_id=task_id,
            previous_state=previous_state,
            new_state="running",
            message=(
                f"Security task {task_id} started."
            ),
        )

        return updated

    def complete_task(
        self,
        execution: SecurityTaskExecution,
        task_id: str,
        *,
        output: dict[str, object] | None = None,
        satisfied_gates: set[str] | None = None,
    ) -> SecurityTaskExecution:
        updated = execution.model_copy(deep=True)
        task = self._task(updated, task_id)

        if task.state != "running":
            raise SecurityTaskTransitionError(
                f"Task {task_id!r} cannot complete from "
                f"state {task.state!r}."
            )

        record = self._record(updated, task_id)
        previous_state = task.state
        now = self._clock()

        task.state = "completed"
        record.finished_at = now
        record.result = SecurityTaskResult(
            task_id=task_id,
            success=True,
            output=output or {},
        )

        updated.updated_at = now

        self._append_event(
            updated,
            event_type="task_completed",
            task_id=task_id,
            previous_state=previous_state,
            new_state="completed",
            message=(
                f"Security task {task_id} completed."
            ),
        )

        self._resolve(
            updated,
            satisfied_gates=satisfied_gates,
        )

        return updated

    def fail_task(
        self,
        execution: SecurityTaskExecution,
        task_id: str,
        *,
        error: str,
        output: dict[str, object] | None = None,
        satisfied_gates: set[str] | None = None,
    ) -> SecurityTaskExecution:
        updated = execution.model_copy(deep=True)
        task = self._task(updated, task_id)

        if task.state != "running":
            raise SecurityTaskTransitionError(
                f"Task {task_id!r} cannot fail from "
                f"state {task.state!r}."
            )

        normalized_error = error.strip()

        if not normalized_error:
            raise ValueError(
                "A failed task must include an error."
            )

        record = self._record(updated, task_id)
        previous_state = task.state
        now = self._clock()

        task.state = "failed"
        task.reasons.append(
            f"Task execution failed: "
            f"{normalized_error}"
        )

        record.finished_at = now
        record.result = SecurityTaskResult(
            task_id=task_id,
            success=False,
            output=output or {},
            error=normalized_error,
        )

        updated.updated_at = now

        self._append_event(
            updated,
            event_type="task_failed",
            task_id=task_id,
            previous_state=previous_state,
            new_state="failed",
            message=(
                f"Security task {task_id} failed: "
                f"{normalized_error}"
            ),
        )

        self._resolve(
            updated,
            satisfied_gates=satisfied_gates,
        )

        return updated

    def skip_task(
        self,
        execution: SecurityTaskExecution,
        task_id: str,
        *,
        reason: str,
        satisfied_gates: set[str] | None = None,
    ) -> SecurityTaskExecution:
        updated = execution.model_copy(deep=True)
        task = self._task(updated, task_id)

        if task.state not in {
            "ready",
            "waiting",
            "planned",
        }:
            raise SecurityTaskTransitionError(
                f"Task {task_id!r} cannot be skipped "
                f"from state {task.state!r}."
            )

        normalized_reason = reason.strip()

        if not normalized_reason:
            raise ValueError(
                "A skipped task must include a reason."
            )

        previous_state = task.state
        now = self._clock()

        task.state = "skipped"
        task.reasons.append(normalized_reason)

        record = self._record(updated, task_id)
        record.finished_at = now
        record.result = SecurityTaskResult(
            task_id=task_id,
            success=False,
            error=normalized_reason,
        )

        updated.updated_at = now

        self._append_event(
            updated,
            event_type="task_skipped",
            task_id=task_id,
            previous_state=previous_state,
            new_state="skipped",
            message=(
                f"Security task {task_id} was skipped: "
                f"{normalized_reason}"
            ),
        )

        self._resolve(
            updated,
            satisfied_gates=satisfied_gates,
        )

        return updated

    def _resolve(
        self,
        execution: SecurityTaskExecution,
        *,
        satisfied_gates: set[str] | None,
    ) -> None:
        completed = {
            task.task_id
            for task in execution.plan.tasks
            if task.state == "completed"
        }

        failed = {
            task.task_id
            for task in execution.plan.tasks
            if task.state == "failed"
        }

        skipped = {
            task.task_id
            for task in execution.plan.tasks
            if task.state == "skipped"
        }

        running = {
            task.task_id
            for task in execution.plan.tasks
            if task.state == "running"
        }

        resolved = self._resolver.resolve(
            execution.plan,
            completed_task_ids=completed,
            failed_task_ids=failed,
            skipped_task_ids=skipped,
            satisfied_gates=(
                satisfied_gates or set()
            ),
        )

        for task in resolved.tasks:
            if task.task_id in running:
                task.state = "running"

        execution.plan = resolved
        execution.status = self._execution_status(
            resolved
        )
        execution.updated_at = self._clock()

        self._append_event(
            execution,
            event_type="state_resolved",
            message=(
                "Dependency and gate states were "
                "recalculated."
            ),
        )

    @staticmethod
    def _execution_status(
        plan: SecurityTaskPlanResponse,
    ) -> str:
        states = {
            task.state
            for task in plan.tasks
        }

        terminal_states = {
            "completed",
            "failed",
            "blocked",
            "skipped",
        }

        if states and states <= terminal_states:
            if "failed" in states:
                return "failed"

            if "blocked" in states:
                return "blocked"

            if "skipped" in states:
                return "partial"

            return "completed"

        if "running" in states:
            return "running"

        if "failed" in states or "blocked" in states:
            return "partial"

        return "created"

    @staticmethod
    def _task(
        execution: SecurityTaskExecution,
        task_id: str,
    ):
        for task in execution.plan.tasks:
            if task.task_id == task_id:
                return task

        raise KeyError(
            f"Unknown security task ID: {task_id}."
        )

    @staticmethod
    def _record(
        execution: SecurityTaskExecution,
        task_id: str,
    ) -> SecurityTaskRuntimeRecord:
        for record in execution.runtime:
            if record.task_id == task_id:
                return record

        raise KeyError(
            f"Missing runtime record for task: "
            f"{task_id}."
        )

    def _append_event(
        self,
        execution: SecurityTaskExecution,
        *,
        event_type: SecurityTaskEventType,
        message: str,
        task_id: str | None = None,
        previous_state: str | None = None,
        new_state: str | None = None,
    ) -> None:
        execution.events.append(
            SecurityTaskExecutionEvent(
                sequence=len(execution.events) + 1,
                event_type=event_type,
                task_id=task_id,
                previous_state=previous_state,
                new_state=new_state,
                message=message,
                occurred_at=self._clock(),
            )
        )
