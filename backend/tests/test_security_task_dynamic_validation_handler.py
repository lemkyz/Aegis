from __future__ import annotations

import asyncio
import hashlib
import json
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
from aegis.schemas.change_policy import (
    ChangePolicyDecisionResponse,
    ChangePolicySummary,
)
from aegis.schemas.fixes import (
    AppliedPatchArtifact,
    FixPlan,
    FixVerificationCheck,
    FixVerificationPlan,
    RemediationLifecycleManifest,
    SecureFixProposal,
    StaticFixVerificationArtifact,
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
from aegis.security.secure_fix import (
    SecureFixTransactionStore,
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


def _canonical_sha256(
    value: dict,
) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(
        canonical
    ).hexdigest()


def _manifest_bound_verification(
    applied: AppliedPatchArtifact,
) -> StaticFixVerificationArtifact:
    proposal = SecureFixProposal(
        claim_id=applied.claim_id,
        target_path=applied.target_path,
        expected_file_sha256=(
            applied.before_sha256
        ),
        expected_selection_sha256=(
            "5" * 64
        ),
        start_offset=0,
        end_offset=1,
        replacement="0",
    )
    resolved_applied = applied.model_copy(
        deep=True,
        update={
            "patch_sha256": (
                proposal.patch_sha256()
            ),
            "transaction_state": "pending",
        },
    )
    verification_plan = (
        FixVerificationPlan(
            plan_id=(
                "verification-plan:"
                f"{applied.claim_id}"
            ),
            claim_id=applied.claim_id,
            patch_sha256=(
                resolved_applied.patch_sha256
            ),
            checks=[
                FixVerificationCheck(
                    check_id=(
                        "check:project-tests"
                    ),
                    kind="project",
                    name="Project tests",
                ),
                FixVerificationCheck(
                    check_id=(
                        "check:static-security"
                    ),
                    kind="static_security",
                    name="Static security scan",
                ),
                FixVerificationCheck(
                    check_id=(
                        "check:dynamic-replay"
                    ),
                    kind="dynamic_replay",
                    name=(
                        "Authorized dynamic replay"
                    ),
                ),
            ],
            requires_dynamic_replay=True,
        )
    )
    plan = FixPlan(
        plan_id=(
            "fix-plan:"
            f"{applied.claim_id}"
        ),
        proposal=proposal,
        verification_plan=(
            verification_plan
        ),
    )
    plan_sha256 = plan.plan_sha256()
    manifest = RemediationLifecycleManifest(
        manifest_id=(
            "remediation-manifest:"
            f"{plan_sha256}"
        ),
        fix_plan=plan,
        fix_plan_sha256=plan_sha256,
        applied_patch=resolved_applied,
    )

    return StaticFixVerificationArtifact(
        handler="test-fix-verification",
        source_artifacts=[
            "applied_patch",
            "remediation_manifest",
        ],
        applied_patch=resolved_applied,
        remediation_manifest=manifest,
        manifest_sha256=(
            manifest.manifest_sha256()
        ),
        verifier="test-static-verifier",
        project_checks=[
            {
                "name": "Tests",
                "status": "passed",
                "details": "Passed.",
            }
        ],
        security_delta={
            "scanner": "test-scanner",
            "before_scan_sha256": (
                "3" * 64
            ),
            "after_scan_sha256": (
                "4" * 64
            ),
            "target_finding_ids": [
                "finding:target",
            ],
            "remaining_target_finding_ids": [],
            "introduced_finding_ids": [],
        },
        static_target_resolved=True,
        static_regression_free=True,
        verdict="awaiting_dynamic",
        ready_for_dynamic=True,
        transaction_state="pending",
        residual_risk={
            "claim_id": (
                resolved_applied.claim_id
            ),
            "patch_sha256": (
                resolved_applied.patch_sha256
            ),
            "status": "inconclusive",
            "reasons": [
                "Dynamic replay has not run.",
            ],
        },
        reasons=[],
        outputs_redacted=True,
    )


def inputs() -> dict:
    policy = ChangePolicyDecisionResponse(
        engine="test-policy",
        policy_version="1.0",
        profile="balanced",
        decision="allow",
        risk_score=0,
        risk_level="none",
        blocking_paths=[],
        review_paths=[],
        assessments=[],
        summary=ChangePolicySummary(
            files_evaluated=0,
            allowed=0,
            review_required=0,
            blocked=0,
            highest_risk_score=0,
            highest_risk_level="none",
            sensitive_files=0,
            dangerous_patterns=0,
            truncated_files=0,
            binary_files=0,
        ),
        reasons=[],
    )
    applied = AppliedPatchArtifact(
        handler="test-secure-fix",
        transaction_id="fix:test",
        claim_id="claim-command-001",
        target_path="app.py",
        approval_id="approval:test",
        patch_sha256="0" * 64,
        before_sha256="1" * 64,
        after_sha256="2" * 64,
        changed_characters=10,
        policy=policy,
        transaction_state="pending",
        outputs_redacted=True,
    )
    verification = (
        _manifest_bound_verification(
            applied
        )
    )

    return {
        "fix_verification_result": (
            verification.model_dump(
                mode="json"
            )
        ),
    }


def pending_transaction_inputs(
    repository_root: Path,
    store: SecureFixTransactionStore,
) -> tuple[dict, str]:
    target = repository_root / "app.py"
    original = b"unsafe = True\n"
    updated = b"unsafe = False\n"
    target.write_bytes(original)
    transaction = store.begin(
        target=target,
        original_content=original,
        updated_content=updated,
        file_mode=target.stat().st_mode,
    )
    store.atomic_write(
        target,
        updated,
        file_mode=target.stat().st_mode,
    )
    base = (
        StaticFixVerificationArtifact
        .model_validate(
            inputs()[
                "fix_verification_result"
            ]
        )
    )
    applied = (
        base.applied_patch.model_copy(
            deep=True,
            update={
                "transaction_id": (
                    transaction.transaction_id
                ),
                "before_sha256": (
                    transaction.before_sha256
                ),
                "after_sha256": (
                    transaction.after_sha256
                ),
            },
        )
    )
    resolved = (
        _manifest_bound_verification(
            applied
        )
    )

    return {
        "fix_verification_result": (
            resolved.model_dump(
                mode="json"
            )
        ),
    }, transaction.transaction_id


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
    assert (
        artifact.fix_verification.verdict
        == "verified"
    )
    assert artifact.transaction_state == (
        "pending"
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
    assert (
        artifact.fix_verification.verdict
        == "inconclusive"
    )


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


def test_inconclusive_replay_rolls_back_pending_fix(
    tmp_path: Path,
) -> None:
    request = replay_request(
        tmp_path
    )
    store = SecureFixTransactionStore(
        id_factory=lambda: "fix:dynamic",
    )
    fix_inputs, transaction_id = (
        pending_transaction_inputs(
            tmp_path,
            store,
        )
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
                response_factory=response_factory,
            )
        ),
        transactions=store,
    )

    result = run(
        handler.execute(
            task=task(),
            context=context(
                tmp_path,
                request,
            ),
            inputs=fix_inputs,
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
        artifact.fix_verification.verdict
        == "inconclusive"
    )
    assert (
        artifact.fix_verification
        .residual_risk.status
        == "inconclusive"
    )
    assert artifact.transaction_state == (
        "rolled_back"
    )
    assert not store.contains(
        transaction_id
    )
    assert (
        tmp_path / "app.py"
    ).read_bytes() == b"unsafe = True\n"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("claim_id", "claim-other"),
        ("patch_sha256", "f" * 64),
    ],
)
def test_mismatched_unified_provenance_rolls_back_pending_fix(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    from aegis.schemas.validation import (
        UnifiedFixVerificationRequest,
        UnifiedFixVerificationResponse,
    )
    from aegis.security.fix_verification import (
        UnifiedFixVerificationEvaluator,
    )

    request = replay_request(
        tmp_path
    )
    store = SecureFixTransactionStore(
        id_factory=lambda: "fix:dynamic",
    )
    fix_inputs, transaction_id = (
        pending_transaction_inputs(
            tmp_path,
            store,
        )
    )

    class MismatchedProvenanceEvaluator(
        UnifiedFixVerificationEvaluator
    ):
        def evaluate(
            self,
            value_request: UnifiedFixVerificationRequest,
        ) -> UnifiedFixVerificationResponse:
            result = (
                UnifiedFixVerificationEvaluator()
                .evaluate(value_request)
            )
            payload = result.model_dump(
                mode="json"
            )
            payload[field] = value
            payload["residual_risk"][
                field
            ] = value
            return (
                UnifiedFixVerificationResponse
                .model_validate(payload)
            )

    handler = DynamicValidationTaskHandler(
        replay_orchestrator=(
            RecordingReplayOrchestrator()
        ),
        fix_evaluator=(
            MismatchedProvenanceEvaluator()
        ),
        transactions=store,
    )

    result = run(
        handler.execute(
            task=task(),
            context=context(
                tmp_path,
                request,
            ),
            inputs=fix_inputs,
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

    assert artifact.fix_verification.verified
    assert (
        artifact.fix_verification.verdict
        == "verified"
    )
    assert (
        artifact.fix_verification
        .residual_risk.status
        == "none_identified"
    )
    assert artifact.transaction_state == (
        "rolled_back"
    )
    assert not store.contains(
        transaction_id
    )
    assert (
        tmp_path / "app.py"
    ).read_bytes() == b"unsafe = True\n"


def test_verified_replay_commits_pending_fix(
    tmp_path: Path,
) -> None:
    request = replay_request(
        tmp_path
    )
    store = SecureFixTransactionStore(
        id_factory=lambda: "fix:dynamic",
    )
    fix_inputs, transaction_id = (
        pending_transaction_inputs(
            tmp_path,
            store,
        )
    )
    handler = DynamicValidationTaskHandler(
        replay_orchestrator=(
            RecordingReplayOrchestrator()
        ),
        transactions=store,
    )

    result = run(
        handler.execute(
            task=task(),
            context=context(
                tmp_path,
                request,
            ),
            inputs=fix_inputs,
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

    assert artifact.fix_verification.verified
    assert artifact.transaction_state == (
        "committed"
    )
    assert not store.contains(
        transaction_id
    )
    assert (
        tmp_path / "app.py"
    ).read_bytes() == b"unsafe = False\n"


def test_still_exploitable_replay_rolls_back_fix(
    tmp_path: Path,
) -> None:
    request = replay_request(
        tmp_path
    )
    store = SecureFixTransactionStore(
        id_factory=lambda: "fix:dynamic",
    )
    fix_inputs, transaction_id = (
        pending_transaction_inputs(
            tmp_path,
            store,
        )
    )

    def response_factory(
        value: ValidationReplayRequest,
    ) -> ValidationReplayResponse:
        return replay_response(
            value,
            after_execution=execution(
                stdout=(
                    f"{EXPLOIT_MARKER}\n"
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
        transactions=store,
    )

    result = run(
        handler.execute(
            task=task(),
            context=context(
                tmp_path,
                request,
            ),
            inputs=fix_inputs,
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
        artifact.fix_verification.verdict
        == "still_exploitable"
    )
    assert artifact.transaction_state == (
        "rolled_back"
    )
    assert not store.contains(
        transaction_id
    )
    assert (
        tmp_path / "app.py"
    ).read_bytes() == b"unsafe = True\n"


def test_invalid_replay_contract_rolls_back_fix(
    tmp_path: Path,
) -> None:
    store = SecureFixTransactionStore(
        id_factory=lambda: "fix:dynamic",
    )
    fix_inputs, transaction_id = (
        pending_transaction_inputs(
            tmp_path,
            store,
        )
    )
    invalid_context = (
        SecurityTaskHandlerContext(
            execution_id=(
                "execution:dynamic-validation"
            ),
            operation="fix_and_verify",
            language="python",
            repository_root=str(
                tmp_path
            ),
            metadata={},
        )
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="requires a valid",
    ):
        run(
            DynamicValidationTaskHandler(
                transactions=store,
            ).execute(
                task=task(),
                context=invalid_context,
                inputs=fix_inputs,
            )
        )

    assert not store.contains(
        transaction_id
    )
    assert (
        tmp_path / "app.py"
    ).read_bytes() == b"unsafe = True\n"

def test_dynamic_validation_rejects_manifestless_static_verification(
    tmp_path: Path,
) -> None:
    request = replay_request(
        tmp_path
    )
    payload = inputs()
    verification = (
        StaticFixVerificationArtifact
        .model_validate(
            payload[
                "fix_verification_result"
            ]
        )
    )
    legacy = verification.model_copy(
        deep=True,
        update={
            "source_artifacts": [
                "applied_patch",
            ],
            "remediation_manifest": None,
            "manifest_sha256": None,
        },
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="manifest",
    ):
        run(
            DynamicValidationTaskHandler(
                replay_orchestrator=(
                    RecordingReplayOrchestrator()
                ),
            ).execute(
                task=task(),
                context=context(
                    tmp_path,
                    request,
                ),
                inputs={
                    "fix_verification_result": (
                        legacy.model_dump(
                            mode="json"
                        )
                    ),
                },
            )
        )


def test_dynamic_validation_emits_manifest_provenance(
    tmp_path: Path,
) -> None:
    request = replay_request(
        tmp_path
    )
    payload = inputs()
    verification = (
        StaticFixVerificationArtifact
        .model_validate(
            payload[
                "fix_verification_result"
            ]
        )
    )
    manifest = (
        verification.remediation_manifest
    )
    assert manifest is not None

    result = run(
        DynamicValidationTaskHandler(
            replay_orchestrator=(
                RecordingReplayOrchestrator()
            ),
        ).execute(
            task=task(),
            context=context(
                tmp_path,
                request,
            ),
            inputs=payload,
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
    static_sha256 = _canonical_sha256(
        verification.model_dump(
            mode="json"
        )
    )

    assert artifact.source_artifacts == [
        "fix_verification_result",
    ]
    assert artifact.manifest_id == (
        manifest.manifest_id
    )
    assert artifact.manifest_sha256 == (
        manifest.manifest_sha256()
    )
    assert (
        artifact.static_verification_sha256
        == static_sha256
    )
    assert result.metadata[
        "manifest_id"
    ] == manifest.manifest_id
    assert result.metadata[
        "manifest_sha256"
    ] == manifest.manifest_sha256()
    assert result.metadata[
        "static_verification_sha256"
    ] == static_sha256


@pytest.mark.parametrize(
    (
        "after_execution",
        "expected_state",
    ),
    [
        (
            execution(
                stdout="AEGIS_SAFE_BEHAVIOR\n",
            ),
            "committed",
        ),
        (
            execution(
                stdout="",
                status="runtime_unavailable",
                exit_code=None,
            ),
            "rolled_back",
        ),
    ],
)
def test_dynamic_transaction_outcome_preserves_manifest_reference(
    tmp_path: Path,
    after_execution: ValidationExecutionResult,
    expected_state: str,
) -> None:
    request = replay_request(
        tmp_path
    )
    store = SecureFixTransactionStore(
        id_factory=lambda: (
            "fix:manifest-continuity"
        ),
    )
    payload, _ = pending_transaction_inputs(
        tmp_path,
        store,
    )
    verification = (
        StaticFixVerificationArtifact
        .model_validate(
            payload[
                "fix_verification_result"
            ]
        )
    )
    manifest = (
        verification.remediation_manifest
    )
    assert manifest is not None

    def response_factory(
        value: ValidationReplayRequest,
    ) -> ValidationReplayResponse:
        return replay_response(
            value,
            after_execution=after_execution,
        )

    result = run(
        DynamicValidationTaskHandler(
            replay_orchestrator=(
                RecordingReplayOrchestrator(
                    response_factory=(
                        response_factory
                    ),
                )
            ),
            transactions=store,
        ).execute(
            task=task(),
            context=context(
                tmp_path,
                request,
            ),
            inputs=payload,
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

    assert artifact.transaction_state == (
        expected_state
    )
    assert artifact.manifest_id == (
        manifest.manifest_id
    )
    assert artifact.manifest_sha256 == (
        manifest.manifest_sha256()
    )
    assert (
        manifest.applied_patch
        .transaction_state
    ) == "pending"
