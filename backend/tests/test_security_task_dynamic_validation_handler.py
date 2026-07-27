from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from aegis.orchestrator.security_task_dynamic_validation_handler import (
    DynamicValidationTaskHandler,
)
from aegis.orchestrator.security_task_handler import (
    SecurityTaskHandlerContext,
)
from aegis.orchestrator.security_task_handlers import (
    SecurityTaskInputError,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
)
from aegis.schemas.validation import (
    DynamicValidationEvidenceRequest,
    DynamicValidationTaskArtifact,
    ValidationAuthorizationRequest,
    ValidationExecutionResult,
    ValidationPlanRequest,
    ValidationReplayCompareRequest,
    ValidationReplayRequest,
    ValidationReplayResponse,
    ValidationSuccessCriteria,
)
from aegis.security.validation_evidence import (
    DynamicValidationEvaluator,
)
from aegis.security.validation_replay import (
    ValidationReplayComparator,
)


EXPLOIT_MARKER = (
    "AEGIS_EXPLOIT_CONFIRMED"
)


def run(coro):
    return asyncio.run(coro)


def task() -> SecurityTaskNode:
    return SecurityTaskNode(
        task_id="dynamic_validation",
        kind="dynamic_validation",
        state="ready",
        produces=[
            "dynamic_validation_evidence",
        ],
    )


def execution(
    *,
    stdout: str,
    status: str = "completed",
    exit_code: int | None = 0,
) -> ValidationExecutionResult:
    return ValidationExecutionResult(
        runner=(
            "aegis-safe-container-runner-v1"
        ),
        status=status,
        runtime_executable=(
            "/usr/bin/podman"
        ),
        started=(
            status
            not in {
                "rejected",
                "runtime_unavailable",
            }
        ),
        timed_out=(
            status == "timed_out"
        ),
        exit_code=exit_code,
        duration_ms=12,
        stdout=stdout,
        stderr="",
        argv=[
            "/usr/bin/podman",
            "run",
            "--rm",
        ],
        reasons=[],
        denials=[],
    )


def replay_request(
    repository_root: Path,
    *,
    authorization_confirmed: bool = True,
    dry_run: bool = False,
    target: str | None = None,
) -> ValidationReplayRequest:
    return ValidationReplayRequest(
        threat_id="threat-command-001",
        claim_id="claim-command-001",
        category="command_injection",
        plan=ValidationPlanRequest(
            authorization=(
                ValidationAuthorizationRequest(
                    authorization_confirmed=(
                        authorization_confirmed
                    ),
                    target_type=(
                        "local_repository"
                    ),
                    target=(
                        target
                        or str(repository_root)
                    ),
                    allowed_test_types=[
                        "command_injection",
                    ],
                    dry_run=dry_run,
                    timeout_seconds=10,
                    memory_limit_mb=256,
                    cpu_limit=0.5,
                    network_policy="disabled",
                )
            ),
            runtime="python",
            entrypoint="validation.py",
            test_type="command_injection",
        ),
        success_criteria=(
            ValidationSuccessCriteria(
                expected_exit_code=0,
                stdout_contains=(
                    EXPLOIT_MARKER
                ),
            )
        ),
        before_execution=execution(
            stdout=(
                f"{EXPLOIT_MARKER}\n"
            ),
        ),
    )


def replay_response(
    request: ValidationReplayRequest,
    *,
    after_execution: (
        ValidationExecutionResult
        | None
    ) = None,
) -> ValidationReplayResponse:
    evaluator = DynamicValidationEvaluator()
    before_evidence = evaluator.evaluate(
        DynamicValidationEvidenceRequest(
            threat_id=request.threat_id,
            claim_id=request.claim_id,
            category=request.category,
            execution=(
                request.before_execution
            ),
            success_criteria=(
                request.success_criteria
            ),
        )
    )
    resolved_after = (
        after_execution
        or execution(
            stdout="AEGIS_SAFE_BEHAVIOR\n",
        )
    )
    after_evidence = evaluator.evaluate(
        DynamicValidationEvidenceRequest(
            threat_id=request.threat_id,
            claim_id=request.claim_id,
            category=request.category,
            execution=resolved_after,
            success_criteria=(
                request.success_criteria
            ),
        )
    )
    comparison = (
        ValidationReplayComparator()
        .compare(
            ValidationReplayCompareRequest(
                before=before_evidence,
                after=after_evidence,
            )
        )
    )

    return ValidationReplayResponse(
        orchestrator=(
            "fake-replay-orchestrator"
        ),
        threat_id=request.threat_id,
        claim_id=request.claim_id,
        category=request.category,
        before_execution=(
            request.before_execution
        ),
        before_evidence=before_evidence,
        after_execution=resolved_after,
        after_evidence=after_evidence,
        comparison=comparison,
    )


class RecordingReplayOrchestrator:
    def __init__(
        self,
        *,
        response_factory=(
            replay_response
        ),
    ) -> None:
        self.calls: list[
            ValidationReplayRequest
        ] = []
        self._response_factory = (
            response_factory
        )

    async def replay(
        self,
        request: ValidationReplayRequest,
    ) -> ValidationReplayResponse:
        self.calls.append(request)
        return self._response_factory(
            request
        )


def context(
    repository_root: Path,
    request: ValidationReplayRequest,
) -> SecurityTaskHandlerContext:
    return SecurityTaskHandlerContext(
        execution_id=(
            "execution:dynamic-validation"
        ),
        operation="fix_and_verify",
        language="python",
        repository_root=str(
            repository_root
        ),
        metadata={
            "validation_replay_request": (
                request.model_dump(
                    mode="json"
                )
            ),
        },
    )


def inputs() -> dict:
    return {
        "fix_verification_result": {
            "status": "completed",
        },
    }


def test_authorized_replay_emits_auditable_artifact(
    tmp_path: Path,
) -> None:
    request = replay_request(
        tmp_path
    )
    replay = RecordingReplayOrchestrator()
    handler = DynamicValidationTaskHandler(
        replay_orchestrator=replay,
    )

    result = run(
        handler.execute(
            task=task(),
            context=context(
                tmp_path,
                request,
            ),
            inputs=inputs(),
        )
    )

    artifact = (
        DynamicValidationTaskArtifact
        .model_validate(
            result.output[
                "dynamic_validation_evidence"
            ]
        )
    )

    assert replay.calls == [request]
    assert artifact.authorization.authorized
    assert (
        artifact.authorization
        .execution_allowed
    )
    assert artifact.execution_plan.ready
    assert (
        artifact.execution_plan
        .sandbox.network
    ) == "none"
    assert (
        artifact.execution_plan
        .sandbox.read_only_root
    ) is True
    assert (
        artifact.execution_plan
        .sandbox.host_path_relabeling
    ) is False
    assert (
        artifact.execution_plan
        .sandbox.image_pull_policy
    ) == "never"
    assert (
        artifact.execution_plan
        .mounts[0].read_only
    ) is True
    assert artifact.replay.comparison.verdict == (
        "fixed"
    )
    assert artifact.outputs_redacted is True
    assert artifact.source_artifacts == [
        "fix_verification_result",
    ]
    assert result.metadata[
        "outputs_redacted"
    ] is True


@pytest.mark.parametrize(
    (
        "authorization_confirmed",
        "dry_run",
    ),
    [
        (False, False),
        (True, True),
    ],
)
def test_denied_scope_never_invokes_replay(
    tmp_path: Path,
    authorization_confirmed: bool,
    dry_run: bool,
) -> None:
    request = replay_request(
        tmp_path,
        authorization_confirmed=(
            authorization_confirmed
        ),
        dry_run=dry_run,
    )
    replay = RecordingReplayOrchestrator()
    handler = DynamicValidationTaskHandler(
        replay_orchestrator=replay,
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="denied",
    ):
        run(
            handler.execute(
                task=task(),
                context=context(
                    tmp_path,
                    request,
                ),
                inputs=inputs(),
            )
        )

    assert replay.calls == []


def test_target_mismatch_never_invokes_replay(
    tmp_path: Path,
) -> None:
    active_root = (
        tmp_path / "active"
    )
    active_root.mkdir()
    other_root = (
        tmp_path / "other"
    )
    other_root.mkdir()
    request = replay_request(
        active_root,
        target=str(other_root),
    )
    replay = RecordingReplayOrchestrator()
    handler = DynamicValidationTaskHandler(
        replay_orchestrator=replay,
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="does not match",
    ):
        run(
            handler.execute(
                task=task(),
                context=context(
                    active_root,
                    request,
                ),
                inputs=inputs(),
            )
        )

    assert replay.calls == []


def test_missing_fix_artifact_fails_closed(
    tmp_path: Path,
) -> None:
    request = replay_request(
        tmp_path
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="fix_verification_result",
    ):
        run(
            DynamicValidationTaskHandler()
            .execute(
                task=task(),
                context=context(
                    tmp_path,
                    request,
                ),
                inputs={},
            )
        )


def test_runtime_failure_remains_inconclusive(
    tmp_path: Path,
) -> None:
    request = replay_request(
        tmp_path
    )

    def response_factory(
        value: ValidationReplayRequest,
    ) -> ValidationReplayResponse:
        return replay_response(
            value,
            after_execution=execution(
                stdout="",
                status="runtime_unavailable",
                exit_code=None,
            ),
        )

    handler = DynamicValidationTaskHandler(
        replay_orchestrator=(
            RecordingReplayOrchestrator(
                response_factory=(
                    response_factory
                ),
            )
        ),
    )

    result = run(
        handler.execute(
            task=task(),
            context=context(
                tmp_path,
                request,
            ),
            inputs=inputs(),
        )
    )
    artifact = (
        DynamicValidationTaskArtifact
        .model_validate(
            result.output[
                "dynamic_validation_evidence"
            ]
        )
    )

    assert (
        artifact.replay.comparison.verdict
    ) == "inconclusive"
    assert artifact.replay.comparison.fixed is False


def test_handler_redacts_injected_replay_output(
    tmp_path: Path,
) -> None:
    request = replay_request(
        tmp_path
    )
    synthetic_secret = (
        'PASSWORD="'
        'fixture-dynamic-secret-value"'
    )
    request.before_execution.stdout = (
        f"{EXPLOIT_MARKER}\n"
        f"{synthetic_secret}\n"
    )

    def response_factory(
        value: ValidationReplayRequest,
    ) -> ValidationReplayResponse:
        return replay_response(
            value,
            after_execution=execution(
                stdout=(
                    "AEGIS_SAFE_BEHAVIOR\n"
                    f"{synthetic_secret}\n"
                ),
            ),
        )

    handler = DynamicValidationTaskHandler(
        replay_orchestrator=(
            RecordingReplayOrchestrator(
                response_factory=(
                    response_factory
                ),
            )
        ),
    )

    result = run(
        handler.execute(
            task=task(),
            context=context(
                tmp_path,
                request,
            ),
            inputs=inputs(),
        )
    )
    serialized = str(
        result.output[
            "dynamic_validation_evidence"
        ]
    )

    assert (
        "fixture-dynamic-secret-value"
        not in serialized
    )
    assert "<AEGIS_REDACTED_SECRET_" in (
        serialized
    )
