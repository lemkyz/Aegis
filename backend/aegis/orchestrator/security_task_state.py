from collections.abc import Iterable

from aegis.schemas.security_task_plan import (
    SecurityTaskGate,
    SecurityTaskPlanResponse,
)


class SecurityTaskStateResolver:
    hard_gates: frozenset[SecurityTaskGate] = frozenset(
        {
            "authorization",
            "human_approval",
            "proposed_patch",
        }
    )

    def resolve(
        self,
        plan: SecurityTaskPlanResponse,
        *,
        completed_task_ids: Iterable[str] = (),
        failed_task_ids: Iterable[str] = (),
        skipped_task_ids: Iterable[str] = (),
        satisfied_gates: Iterable[
            SecurityTaskGate
        ] = (),
    ) -> SecurityTaskPlanResponse:
        resolved = plan.model_copy(deep=True)

        completed = set(completed_task_ids)
        failed = set(failed_task_ids)
        skipped = set(skipped_task_ids)
        gates = set(satisfied_gates)

        known_ids = {
            task.task_id
            for task in resolved.tasks
        }

        for supplied_ids, label in (
            (completed, "completed"),
            (failed, "failed"),
            (skipped, "skipped"),
        ):
            unknown = supplied_ids - known_ids

            if unknown:
                unknown_list = ", ".join(
                    sorted(unknown)
                )
                raise ValueError(
                    f"Unknown {label} task ID(s): "
                    f"{unknown_list}."
                )

        state_by_id = {
            task.task_id: task.state
            for task in resolved.tasks
        }

        for task_id in completed:
            state_by_id[task_id] = "completed"

        for task_id in failed:
            state_by_id[task_id] = "failed"

        for task_id in skipped:
            state_by_id[task_id] = "skipped"

        tasks_by_id = {
            task.task_id: task
            for task in resolved.tasks
        }

        for task_id in resolved.execution_order:
            task = tasks_by_id[task_id]

            if task_id in completed:
                task.state = "completed"
                continue

            if task_id in failed:
                task.state = "failed"
                continue

            if task_id in skipped:
                task.state = "skipped"
                continue

            if task.state in {
                "blocked",
                "skipped",
                "completed",
                "failed",
                "running",
            }:
                state_by_id[task_id] = task.state
                continue

            dependency_states = {
                dependency.task_id: (
                    state_by_id[dependency.task_id]
                )
                for dependency in task.dependencies
            }

            failed_dependencies = [
                dependency_id
                for dependency_id, state
                in dependency_states.items()
                if state in {
                    "failed",
                    "blocked",
                }
            ]

            if failed_dependencies:
                task.state = "blocked"
                task.reasons.append(
                    "Blocked because required "
                    "dependency task(s) failed or "
                    "were blocked: "
                    + ", ".join(
                        failed_dependencies
                    )
                    + "."
                )
                state_by_id[task_id] = task.state
                continue

            skipped_dependencies = [
                dependency_id
                for dependency_id, state
                in dependency_states.items()
                if state == "skipped"
            ]

            if skipped_dependencies:
                task.state = "skipped"
                task.reasons.append(
                    "Skipped because required "
                    "dependency task(s) were skipped: "
                    + ", ".join(
                        skipped_dependencies
                    )
                    + "."
                )
                state_by_id[task_id] = task.state
                continue

            dependencies_ready = all(
                state_by_id[dependency.task_id]
                in dependency.required_states
                for dependency in task.dependencies
            )

            if not dependencies_ready:
                task.state = "waiting"
                state_by_id[task_id] = task.state
                continue

            unmet_gates = {
                gate
                for gate in task.gates
                if gate != "none"
                and gate not in gates
            }

            unmet_hard_gates = (
                unmet_gates
                & self.hard_gates
            )

            if unmet_hard_gates:
                task.state = "blocked"
                task.reasons.append(
                    "Blocked by unmet mandatory "
                    "gate(s): "
                    + ", ".join(
                        sorted(unmet_hard_gates)
                    )
                    + "."
                )
                state_by_id[task_id] = task.state
                continue

            if unmet_gates:
                task.state = "waiting"
                task.reasons.append(
                    "Waiting for gate(s): "
                    + ", ".join(
                        sorted(unmet_gates)
                    )
                    + "."
                )
                state_by_id[task_id] = task.state
                continue

            task.state = "ready"
            state_by_id[task_id] = task.state

        resolved.status = self._plan_status(
            resolved
        )

        resolved.reasons.append(
            "Task states were resolved from current "
            "dependency and gate evidence."
        )

        return resolved

    @staticmethod
    def _plan_status(
        plan: SecurityTaskPlanResponse,
    ) -> str:
        states = {
            task.state
            for task in plan.tasks
        }

        has_progress = bool(
            states
            & {
                "ready",
                "running",
                "completed",
                "waiting",
            }
        )

        has_degradation = bool(
            states
            & {
                "blocked",
                "failed",
                "skipped",
            }
        )

        if has_degradation and has_progress:
            return "partial"

        if states and states <= {
            "blocked",
            "failed",
            "skipped",
        }:
            return "blocked"

        return "ready"
