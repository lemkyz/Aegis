from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import ValidationError

from aegis.orchestrator.security_task_handler import (
    SecurityTaskArtifactStore,
)
from aegis.orchestrator.security_task_workflow import (
    SecurityTaskWorkflowResult,
)
from aegis.schemas.memory import RepositoryContext
from aegis.schemas.security_task_run import (
    SecurityTaskRunIntegrity,
)


class SecurityTaskIntegrityError(
    RuntimeError
):
    pass


class SecurityTaskIntegrityVerifier:
    verifier = (
        "aegis-security-task-integrity-v1"
    )

    def attest(
        self,
        *,
        source_code: str,
        result: SecurityTaskWorkflowResult,
        artifacts: SecurityTaskArtifactStore,
        expected_repository: RepositoryContext,
        observed_repository: RepositoryContext,
    ) -> SecurityTaskRunIntegrity:
        if observed_repository != (
            expected_repository
        ):
            raise SecurityTaskIntegrityError(
                "Repository revision changed during "
                "production workflow execution."
            )

        repository = self._repository(
            artifacts,
            expected_repository=(
                expected_repository
            ),
        )
        self._validate_execution(result)
        self._validate_artifacts(
            result=result,
            artifacts=artifacts,
        )

        return SecurityTaskRunIntegrity(
            source_sha256=self._bytes_sha256(
                source_code.encode("utf-8")
            ),
            repository_revision=(
                repository.revision
            ),
            plan_sha256=self._json_sha256(
                result.execution.plan.model_dump(
                    mode="json"
                )
            ),
            audit_sha256=self._json_sha256([
                event.model_dump(mode="json")
                for event
                in result.execution.events
            ]),
            artifact_manifest_sha256=(
                self._json_sha256([
                    artifact.model_dump(
                        mode="json"
                    )
                    for artifact
                    in sorted(
                        result.aggregation.artifacts,
                        key=lambda item: item.name,
                    )
                ])
            ),
            verified=True,
        )

    @staticmethod
    def _repository(
        artifacts: SecurityTaskArtifactStore,
        *,
        expected_repository: RepositoryContext,
    ) -> RepositoryContext:
        if not artifacts.contains(
            "repository_context"
        ):
            return expected_repository.model_copy(
                deep=True
            )

        try:
            repository = RepositoryContext.model_validate(
                artifacts.value(
                    "repository_context"
                )
            )
        except ValidationError as exc:
            raise SecurityTaskIntegrityError(
                "Production workflow repository "
                "provenance is invalid."
            ) from exc

        if repository != expected_repository:
            raise SecurityTaskIntegrityError(
                "Production workflow repository "
                "provenance changed during execution."
            )

        return repository

    @staticmethod
    def _validate_execution(
        result: SecurityTaskWorkflowResult,
    ) -> None:
        execution = result.execution
        aggregation = result.aggregation

        if (
            aggregation.execution_id
            != execution.execution_id
        ):
            raise SecurityTaskIntegrityError(
                "Execution and aggregation IDs "
                "do not match."
            )

        if (
            aggregation.operation
            != execution.plan.operation
        ):
            raise SecurityTaskIntegrityError(
                "Execution and aggregation "
                "operations do not match."
            )

        expected_sequences = list(
            range(
                1,
                len(execution.events) + 1,
            )
        )
        actual_sequences = [
            event.sequence
            for event in execution.events
        ]

        if actual_sequences != expected_sequences:
            raise SecurityTaskIntegrityError(
                "Audit event sequence is not "
                "contiguous."
            )

        if aggregation.audit_event_count != len(
            execution.events
        ):
            raise SecurityTaskIntegrityError(
                "Audit event count does not match "
                "the execution history."
            )

        task_by_id = {
            task.task_id: task
            for task in execution.plan.tasks
        }
        runtime_by_id = {
            record.task_id: record
            for record in execution.runtime
        }
        summary_by_id = {
            summary.task_id: summary
            for summary
            in aggregation.task_summaries
        }

        if not (
            set(task_by_id)
            == set(runtime_by_id)
            == set(summary_by_id)
        ):
            raise SecurityTaskIntegrityError(
                "Task plan, runtime, and aggregation "
                "do not describe the same tasks."
            )

        for task_id, task in task_by_id.items():
            runtime = runtime_by_id[task_id]
            summary = summary_by_id[task_id]

            if (
                summary.state != task.state
                or summary.attempts
                != runtime.attempts
            ):
                raise SecurityTaskIntegrityError(
                    "Aggregated task state does not "
                    f"match runtime for {task_id!r}."
                )

            runtime_success = (
                runtime.result.success
                if runtime.result is not None
                else None
            )

            if summary.success != runtime_success:
                raise SecurityTaskIntegrityError(
                    "Aggregated task result does not "
                    f"match runtime for {task_id!r}."
                )

        if result.status == "completed":
            if (
                execution.status != "completed"
                or aggregation.status
                != "completed"
                or result.errors
            ):
                raise SecurityTaskIntegrityError(
                    "A completed workflow contains "
                    "incomplete or failed state."
                )

        if aggregation.running_task_ids:
            raise SecurityTaskIntegrityError(
                "A returned production workflow "
                "cannot retain running tasks."
            )

    @classmethod
    def _validate_artifacts(
        cls,
        *,
        result: SecurityTaskWorkflowResult,
        artifacts: SecurityTaskArtifactStore,
    ) -> None:
        aggregated_names = {
            artifact.name
            for artifact
            in result.aggregation.artifacts
        }

        if aggregated_names != set(
            artifacts.names()
        ):
            raise SecurityTaskIntegrityError(
                "Execution-local artifacts do not "
                "match the aggregation manifest."
            )

        task_by_id = {
            task.task_id: task
            for task
            in result.execution.plan.tasks
        }

        for record in (
            result.aggregation.artifacts
        ):
            stored = artifacts.artifact(
                record.name
            )
            producer = task_by_id.get(
                record.producer_task_id
            )

            if (
                stored.producer_task_id
                != record.producer_task_id
                or producer is None
                or producer.state != "completed"
                or record.name
                not in producer.produces
            ):
                raise SecurityTaskIntegrityError(
                    "Artifact provenance is invalid "
                    f"for {record.name!r}."
                )

            if cls._json_sha256(
                stored.value
            ) != cls._json_sha256(
                record.value
            ):
                raise SecurityTaskIntegrityError(
                    "Artifact value does not match "
                    f"the manifest for {record.name!r}."
                )

    @classmethod
    def _json_sha256(
        cls,
        value: Any,
    ) -> str:
        try:
            payload = json.dumps(
                value,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (
            TypeError,
            ValueError,
        ) as exc:
            raise SecurityTaskIntegrityError(
                "Integrity payload is not canonical "
                "JSON."
            ) from exc

        return cls._bytes_sha256(payload)

    @staticmethod
    def _bytes_sha256(
        payload: bytes,
    ) -> str:
        return hashlib.sha256(
            payload
        ).hexdigest()
