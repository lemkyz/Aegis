from aegis.schemas.security_task_plan import (
    SecurityArtifactRecord,
    SecurityTaskAggregation,
    SecurityTaskExecution,
    SecurityTaskOutputSummary,
)


class SecurityTaskAggregationError(ValueError):
    pass


class SecurityTaskResultAggregator:
    aggregator = "aegis-security-task-aggregator-v1"

    def aggregate(
        self,
        execution: SecurityTaskExecution,
    ) -> SecurityTaskAggregation:
        runtime_by_id = {
            record.task_id: record
            for record in execution.runtime
        }

        tasks_by_id = {
            task.task_id: task
            for task in execution.plan.tasks
        }

        summaries: list[
            SecurityTaskOutputSummary
        ] = []

        artifacts: list[
            SecurityArtifactRecord
        ] = []

        artifact_producers: dict[str, str] = {}

        ready_task_ids: list[str] = []
        running_task_ids: list[str] = []
        completed_task_ids: list[str] = []
        failed_task_ids: list[str] = []
        blocked_task_ids: list[str] = []
        skipped_task_ids: list[str] = []

        errors: list[str] = []

        for task_id in execution.plan.execution_order:
            task = tasks_by_id[task_id]
            record = runtime_by_id[task_id]
            result = record.result

            success = (
                result.success
                if result is not None
                else None
            )

            output = (
                dict(result.output)
                if result is not None
                else {}
            )

            error = (
                result.error
                if result is not None
                else None
            )

            summaries.append(
                SecurityTaskOutputSummary(
                    task_id=task.task_id,
                    kind=task.kind,
                    state=task.state,
                    attempts=record.attempts,
                    success=success,
                    output=output,
                    error=error,
                    reasons=list(task.reasons),
                )
            )

            if task.state == "ready":
                ready_task_ids.append(task_id)
            elif task.state == "running":
                running_task_ids.append(task_id)
            elif task.state == "completed":
                completed_task_ids.append(task_id)
            elif task.state == "failed":
                failed_task_ids.append(task_id)
            elif task.state == "blocked":
                blocked_task_ids.append(task_id)
            elif task.state == "skipped":
                skipped_task_ids.append(task_id)

            if error:
                errors.append(
                    f"{task_id}: {error}"
                )

            if result is None or not result.success:
                continue

            for artifact_name in task.produces:
                if artifact_name not in output:
                    continue

                previous_producer = (
                    artifact_producers.get(
                        artifact_name
                    )
                )

                if previous_producer is not None:
                    raise SecurityTaskAggregationError(
                        "Artifact "
                        f"{artifact_name!r} was produced "
                        "by multiple tasks: "
                        f"{previous_producer!r} and "
                        f"{task_id!r}."
                    )

                artifact_producers[
                    artifact_name
                ] = task_id

                artifacts.append(
                    SecurityArtifactRecord(
                        name=artifact_name,
                        producer_task_id=task_id,
                        value=output[artifact_name],
                    )
                )

        terminal_ids = set(
            execution.plan.terminal_task_ids
        )

        completed_terminal_task_ids = [
            task_id
            for task_id
            in execution.plan.terminal_task_ids
            if task_id in completed_task_ids
        ]

        pending_terminal_task_ids = [
            task_id
            for task_id
            in execution.plan.terminal_task_ids
            if task_id
            not in completed_terminal_task_ids
        ]

        status = self._status(
            execution=execution,
            terminal_ids=terminal_ids,
            completed_task_ids=set(
                completed_task_ids
            ),
            failed_task_ids=set(failed_task_ids),
            blocked_task_ids=set(
                blocked_task_ids
            ),
            skipped_task_ids=set(
                skipped_task_ids
            ),
            running_task_ids=set(
                running_task_ids
            ),
        )

        reasons = self._reasons(
            status=status,
            ready_task_ids=ready_task_ids,
            running_task_ids=running_task_ids,
            completed_terminal_task_ids=(
                completed_terminal_task_ids
            ),
            pending_terminal_task_ids=(
                pending_terminal_task_ids
            ),
            failed_task_ids=failed_task_ids,
            blocked_task_ids=blocked_task_ids,
            skipped_task_ids=skipped_task_ids,
        )

        return SecurityTaskAggregation(
            aggregator=self.aggregator,
            execution_id=execution.execution_id,
            operation=execution.plan.operation,
            status=status,
            execution_status=execution.status,
            task_summaries=summaries,
            artifacts=artifacts,
            ready_task_ids=ready_task_ids,
            running_task_ids=running_task_ids,
            completed_task_ids=completed_task_ids,
            failed_task_ids=failed_task_ids,
            blocked_task_ids=blocked_task_ids,
            skipped_task_ids=skipped_task_ids,
            completed_terminal_task_ids=(
                completed_terminal_task_ids
            ),
            pending_terminal_task_ids=(
                pending_terminal_task_ids
            ),
            reasons=reasons,
            errors=errors,
            audit_event_count=len(
                execution.events
            ),
            last_event_sequence=(
                execution.events[-1].sequence
                if execution.events
                else None
            ),
        )

    @staticmethod
    def _status(
        *,
        execution: SecurityTaskExecution,
        terminal_ids: set[str],
        completed_task_ids: set[str],
        failed_task_ids: set[str],
        blocked_task_ids: set[str],
        skipped_task_ids: set[str],
        running_task_ids: set[str],
    ) -> str:
        if (
            terminal_ids
            and terminal_ids
            <= completed_task_ids
        ):
            return "completed"

        if failed_task_ids:
            if (
                terminal_ids
                & failed_task_ids
            ):
                return "failed"

            return "partial"

        if blocked_task_ids:
            progress_states = {
                "ready",
                "running",
                "waiting",
                "completed",
            }

            has_progress = any(
                task.state in progress_states
                for task in execution.plan.tasks
            )

            return (
                "partial"
                if has_progress
                else "blocked"
            )

        if skipped_task_ids:
            return "partial"

        if running_task_ids:
            return "in_progress"

        return "in_progress"

    @staticmethod
    def _reasons(
        *,
        status: str,
        ready_task_ids: list[str],
        running_task_ids: list[str],
        completed_terminal_task_ids: list[str],
        pending_terminal_task_ids: list[str],
        failed_task_ids: list[str],
        blocked_task_ids: list[str],
        skipped_task_ids: list[str],
    ) -> list[str]:
        reasons = [
            (
                "Execution results were aggregated "
                "deterministically in dependency-safe "
                "task order."
            )
        ]

        if status == "completed":
            reasons.append(
                "All terminal security tasks completed "
                "successfully."
            )

        if ready_task_ids:
            reasons.append(
                "Ready task(s): "
                + ", ".join(ready_task_ids)
                + "."
            )

        if running_task_ids:
            reasons.append(
                "Running task(s): "
                + ", ".join(running_task_ids)
                + "."
            )

        if failed_task_ids:
            reasons.append(
                "Failed task(s): "
                + ", ".join(failed_task_ids)
                + "."
            )

        if blocked_task_ids:
            reasons.append(
                "Blocked task(s): "
                + ", ".join(blocked_task_ids)
                + "."
            )

        if skipped_task_ids:
            reasons.append(
                "Skipped task(s): "
                + ", ".join(skipped_task_ids)
                + "."
            )

        if completed_terminal_task_ids:
            reasons.append(
                "Completed terminal task(s): "
                + ", ".join(
                    completed_terminal_task_ids
                )
                + "."
            )

        if pending_terminal_task_ids:
            reasons.append(
                "Pending terminal task(s): "
                + ", ".join(
                    pending_terminal_task_ids
                )
                + "."
            )

        return reasons
