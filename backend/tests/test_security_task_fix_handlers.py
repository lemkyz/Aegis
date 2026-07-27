from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest

from aegis.orchestrator.security_task_fix_handlers import (
    FixVerificationTaskHandler,
    SecureFixTaskHandler,
)
from aegis.orchestrator.security_task_execution import (
    SecurityTaskExecutionMachine,
)
from aegis.orchestrator.security_task_executor import (
    SecurityTaskExecutor,
)
from aegis.orchestrator.security_task_handler import (
    SecurityTaskArtifactStore,
    SecurityTaskExecutionCancelled,
    SecurityTaskHandlerContext,
    SecurityTaskHandlerRegistry,
)
from aegis.orchestrator.security_task_handlers import (
    RepositoryContextTaskHandler,
    SecurityTaskInputError,
)
from aegis.orchestrator.security_task_planner import (
    SecurityTaskPlanner,
)
from aegis.orchestrator.security_task_workflow import (
    SecurityTaskWorkflowRunner,
)
from aegis.schemas.fixes import (
    AppliedPatchArtifact,
    SecureFixApproval,
    SecureFixProposal,
    SecureFixRequest,
    StaticFixVerificationArtifact,
    StaticFixVerificationRequest,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
    SecurityTaskPlanRequest,
)
from aegis.security.secure_fix import (
    SecureFixTransactionStore,
)


ORIGINAL = (
    "import subprocess\n\n"
    "subprocess.run(command, shell=True)\n"
)
VULNERABLE = (
    "subprocess.run(command, shell=True)"
)
REPLACEMENT = (
    "subprocess.run(command, shell=False)"
)


def run(coro):
    return asyncio.run(coro)


def digest(value: str) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def secure_task() -> SecurityTaskNode:
    return SecurityTaskNode(
        task_id="secure_fix",
        kind="secure_fix",
        state="ready",
        produces=["applied_patch"],
    )


def verification_task() -> SecurityTaskNode:
    return SecurityTaskNode(
        task_id="fix_verification",
        kind="fix_verification",
        state="ready",
        produces=[
            "fix_verification_result",
        ],
    )


def proposal(
    *,
    replacement: str = REPLACEMENT,
    target_path: str = "app.py",
) -> SecureFixProposal:
    start = ORIGINAL.index(VULNERABLE)

    return SecureFixProposal(
        claim_id="claim-command-001",
        target_path=target_path,
        expected_file_sha256=digest(
            ORIGINAL
        ),
        expected_selection_sha256=digest(
            VULNERABLE
        ),
        start_offset=start,
        end_offset=(
            start + len(VULNERABLE)
        ),
        replacement=replacement,
    )


def fix_request(
    value: SecureFixProposal,
    *,
    approved_digest: str | None = None,
) -> SecureFixRequest:
    return SecureFixRequest(
        proposal=value,
        approval=SecureFixApproval(
            confirmed=True,
            approval_id="approval:test",
            approved_patch_sha256=(
                approved_digest
                or value.patch_sha256()
            ),
        ),
    )


def context(
    repository_root: Path,
    request: SecureFixRequest,
    *,
    verification: (
        StaticFixVerificationRequest
        | None
    ) = None,
) -> SecurityTaskHandlerContext:
    metadata = {
        "secure_fix_request": (
            request.model_dump(
                mode="json"
            )
        ),
    }

    if verification is not None:
        metadata[
            "static_fix_verification_request"
        ] = verification.model_dump(
            mode="json"
        )

    return SecurityTaskHandlerContext(
        execution_id="execution:fix-test",
        operation="fix_and_verify",
        language="python",
        repository_root=str(
            repository_root
        ),
        metadata=metadata,
    )


def repository_inputs(
    repository_root: Path,
) -> dict:
    return {
        "repository_context": {
            "repository_root": str(
                repository_root
            ),
        },
    }


def transaction_store() -> (
    SecureFixTransactionStore
):
    return SecureFixTransactionStore(
        id_factory=lambda: (
            "fix:deterministic-test"
        ),
    )


def apply_fix(
    repository_root: Path,
    *,
    store: SecureFixTransactionStore,
    request: SecureFixRequest | None = None,
) -> tuple[
    AppliedPatchArtifact,
    SecureFixRequest,
]:
    resolved_request = (
        request
        or fix_request(proposal())
    )
    result = run(
        SecureFixTaskHandler(
            transactions=store,
        ).execute(
            task=secure_task(),
            context=context(
                repository_root,
                resolved_request,
            ),
            inputs=repository_inputs(
                repository_root
            ),
        )
    )
    artifact = (
        AppliedPatchArtifact.model_validate(
            result.output[
                "applied_patch"
            ]
        )
    )

    return artifact, resolved_request


def verification_request(
    *,
    check_status: str = "passed",
    target_resolved: bool = True,
    regression_free: bool = True,
    requires_dynamic: bool = False,
    details: str = "Project checks passed.",
) -> StaticFixVerificationRequest:
    return StaticFixVerificationRequest(
        claim_id="claim-command-001",
        verifier="test-static-verifier",
        project_checks=[
            {
                "name": "Project tests",
                "status": check_status,
                "details": details,
            }
        ],
        security_delta={
            "scanner": "test-scanner",
            "before_scan_sha256": (
                "a" * 64
            ),
            "after_scan_sha256": (
                "b" * 64
            ),
            "target_finding_ids": [
                "finding:target",
            ],
            "remaining_target_finding_ids": (
                []
                if target_resolved
                else ["finding:target"]
            ),
            "introduced_finding_ids": (
                []
                if regression_free
                else ["finding:new"]
            ),
        },
        requires_dynamic_replay=(
            requires_dynamic
        ),
    )


def setup_repository(
    tmp_path: Path,
) -> Path:
    target = tmp_path / "app.py"
    target.write_text(
        ORIGINAL,
        encoding="utf-8",
    )
    return target


def test_exact_approved_patch_is_applied_atomically(
    tmp_path: Path,
) -> None:
    target = setup_repository(
        tmp_path
    )
    store = transaction_store()

    artifact, _ = apply_fix(
        tmp_path,
        store=store,
    )

    assert target.read_text(
        encoding="utf-8"
    ) == ORIGINAL.replace(
        VULNERABLE,
        REPLACEMENT,
    )
    assert artifact.transaction_state == (
        "pending"
    )
    assert artifact.policy.decision in {
        "allow",
        "review",
    }
    assert store.contains(
        artifact.transaction_id
    )
    serialized = str(
        artifact.model_dump(mode="json")
    )
    assert VULNERABLE not in serialized
    assert REPLACEMENT not in serialized


def test_mismatched_approval_never_edits_target(
    tmp_path: Path,
) -> None:
    target = setup_repository(
        tmp_path
    )
    store = transaction_store()
    value = proposal()
    request = fix_request(
        value,
        approved_digest="f" * 64,
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="does not match",
    ):
        apply_fix(
            tmp_path,
            store=store,
            request=request,
        )

    assert target.read_text(
        encoding="utf-8"
    ) == ORIGINAL


def test_stale_file_never_receives_patch(
    tmp_path: Path,
) -> None:
    target = setup_repository(
        tmp_path
    )
    store = transaction_store()
    request = fix_request(
        proposal()
    )
    target.write_text(
        ORIGINAL + "# user edit\n",
        encoding="utf-8",
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="changed after analysis",
    ):
        apply_fix(
            tmp_path,
            store=store,
            request=request,
        )

    assert target.read_text(
        encoding="utf-8"
    ).endswith(
        "# user edit\n"
    )


def test_symbolic_link_target_is_rejected(
    tmp_path: Path,
) -> None:
    real_target = (
        tmp_path / "real.py"
    )
    real_target.write_text(
        ORIGINAL,
        encoding="utf-8",
    )
    link = tmp_path / "app.py"
    link.symlink_to(real_target)
    store = transaction_store()

    with pytest.raises(
        SecurityTaskInputError,
        match="symbolic-link",
    ):
        apply_fix(
            tmp_path,
            store=store,
        )

    assert real_target.read_text(
        encoding="utf-8"
    ) == ORIGINAL


def test_parent_traversal_proposal_is_rejected() -> None:
    with pytest.raises(
        ValueError,
        match="inside the repository",
    ):
        proposal(
            target_path="../outside.py",
        )


def test_secret_bearing_replacement_is_rejected(
    tmp_path: Path,
) -> None:
    target = setup_repository(
        tmp_path
    )
    store = transaction_store()
    request = fix_request(
        proposal(
            replacement=(
                'PASSWORD="'
                'fixture-secret-value"'
            ),
        )
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="secrets",
    ):
        apply_fix(
            tmp_path,
            store=store,
            request=request,
        )

    assert target.read_text(
        encoding="utf-8"
    ) == ORIGINAL


def test_blocking_change_policy_prevents_edit(
    tmp_path: Path,
) -> None:
    target = setup_repository(
        tmp_path
    )
    store = transaction_store()
    request = fix_request(
        proposal(
            replacement=(
                "requests.get(url, "
                "verify=False)"
            ),
        )
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="policy blocked",
    ):
        apply_fix(
            tmp_path,
            store=store,
            request=request,
        )

    assert target.read_text(
        encoding="utf-8"
    ) == ORIGINAL


def test_cancellation_after_write_restores_original(
    tmp_path: Path,
) -> None:
    target = setup_repository(
        tmp_path
    )
    store = transaction_store()
    request = fix_request(
        proposal()
    )
    checks = 0

    def cancelled() -> bool:
        nonlocal checks
        checks += 1
        return checks >= 3

    cancelled_context = (
        SecurityTaskHandlerContext(
            execution_id=(
                "execution:cancelled-fix"
            ),
            operation="fix_and_verify",
            language="python",
            repository_root=str(
                tmp_path
            ),
            metadata={
                "secure_fix_request": (
                    request.model_dump(
                        mode="json"
                    )
                ),
            },
            cancellation_requested=(
                cancelled
            ),
        )
    )

    with pytest.raises(
        SecurityTaskExecutionCancelled,
    ):
        run(
            SecureFixTaskHandler(
                transactions=store,
            ).execute(
                task=secure_task(),
                context=cancelled_context,
                inputs=repository_inputs(
                    tmp_path
                ),
            )
        )

    assert target.read_text(
        encoding="utf-8"
    ) == ORIGINAL
    assert not store.contains(
        "fix:deterministic-test"
    )


def test_failed_project_check_rolls_back(
    tmp_path: Path,
) -> None:
    target = setup_repository(
        tmp_path
    )
    store = transaction_store()
    applied, request = apply_fix(
        tmp_path,
        store=store,
    )
    verification = verification_request(
        check_status="failed",
        details=(
            'PASSWORD="'
            'fixture-check-secret"'
        ),
    )

    result = run(
        FixVerificationTaskHandler(
            transactions=store,
        ).execute(
            task=verification_task(),
            context=context(
                tmp_path,
                request,
                verification=verification,
            ),
            inputs={
                "applied_patch": (
                    applied.model_dump(
                        mode="json"
                    )
                ),
            },
        )
    )
    artifact = (
        StaticFixVerificationArtifact
        .model_validate(
            result.output[
                "fix_verification_result"
            ]
        )
    )

    assert artifact.verdict == "failed"
    assert artifact.transaction_state == (
        "rolled_back"
    )
    assert target.read_text(
        encoding="utf-8"
    ) == ORIGINAL
    assert not store.contains(
        applied.transaction_id
    )
    assert (
        "fixture-check-secret"
        not in str(
            artifact.model_dump(
                mode="json"
            )
        )
    )


def test_invalid_verification_contract_rolls_back(
    tmp_path: Path,
) -> None:
    target = setup_repository(
        tmp_path
    )
    store = transaction_store()
    applied, request = apply_fix(
        tmp_path,
        store=store,
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="requires a valid",
    ):
        run(
            FixVerificationTaskHandler(
                transactions=store,
            ).execute(
                task=verification_task(),
                context=context(
                    tmp_path,
                    request,
                ),
                inputs={
                    "applied_patch": (
                        applied.model_dump(
                            mode="json"
                        )
                    ),
                },
            )
        )

    assert target.read_text(
        encoding="utf-8"
    ) == ORIGINAL
    assert not store.contains(
        applied.transaction_id
    )


def test_rollback_never_overwrites_newer_user_edit(
    tmp_path: Path,
) -> None:
    target = setup_repository(
        tmp_path
    )
    store = transaction_store()
    applied, request = apply_fix(
        tmp_path,
        store=store,
    )
    target.write_text(
        "# newer user work\n",
        encoding="utf-8",
    )
    verification = verification_request(
        check_status="failed",
    )

    result = run(
        FixVerificationTaskHandler(
            transactions=store,
        ).execute(
            task=verification_task(),
            context=context(
                tmp_path,
                request,
                verification=verification,
            ),
            inputs={
                "applied_patch": (
                    applied.model_dump(
                        mode="json"
                    )
                ),
            },
        )
    )
    artifact = (
        StaticFixVerificationArtifact
        .model_validate(
            result.output[
                "fix_verification_result"
            ]
        )
    )

    assert artifact.transaction_state == (
        "rollback_blocked"
    )
    assert target.read_text(
        encoding="utf-8"
    ) == "# newer user work\n"


def test_static_success_without_replay_is_partial(
    tmp_path: Path,
) -> None:
    target = setup_repository(
        tmp_path
    )
    store = transaction_store()
    applied, request = apply_fix(
        tmp_path,
        store=store,
    )
    verification = verification_request()

    result = run(
        FixVerificationTaskHandler(
            transactions=store,
        ).execute(
            task=verification_task(),
            context=context(
                tmp_path,
                request,
                verification=verification,
            ),
            inputs={
                "applied_patch": (
                    applied.model_dump(
                        mode="json"
                    )
                ),
            },
        )
    )
    artifact = (
        StaticFixVerificationArtifact
        .model_validate(
            result.output[
                "fix_verification_result"
            ]
        )
    )

    assert artifact.verdict == "partial"
    assert artifact.ready_for_dynamic is False
    assert artifact.transaction_state == (
        "committed"
    )
    assert not store.contains(
        applied.transaction_id
    )
    assert REPLACEMENT in target.read_text(
        encoding="utf-8"
    )


def test_static_success_hands_pending_fix_to_replay(
    tmp_path: Path,
) -> None:
    setup_repository(tmp_path)
    store = transaction_store()
    applied, request = apply_fix(
        tmp_path,
        store=store,
    )
    verification = verification_request(
        requires_dynamic=True,
    )

    result = run(
        FixVerificationTaskHandler(
            transactions=store,
        ).execute(
            task=verification_task(),
            context=context(
                tmp_path,
                request,
                verification=verification,
            ),
            inputs={
                "applied_patch": (
                    applied.model_dump(
                        mode="json"
                    )
                ),
            },
        )
    )
    artifact = (
        StaticFixVerificationArtifact
        .model_validate(
            result.output[
                "fix_verification_result"
            ]
        )
    )

    assert artifact.verdict == (
        "awaiting_dynamic"
    )
    assert artifact.ready_for_dynamic is True
    assert artifact.transaction_state == (
        "pending"
    )
    assert store.contains(
        applied.transaction_id
    )


def test_fix_and_verify_workflow_composes_handlers(
    tmp_path: Path,
) -> None:
    target = setup_repository(
        tmp_path
    )
    store = transaction_store()
    request = fix_request(
        proposal()
    )
    verification = verification_request()
    registry = SecurityTaskHandlerRegistry()
    registry.register(
        RepositoryContextTaskHandler()
    )
    registry.register(
        SecureFixTaskHandler(
            transactions=store,
        )
    )
    registry.register(
        FixVerificationTaskHandler(
            transactions=store,
        )
    )
    registry.freeze()
    plan = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="fix_and_verify",
            has_proposed_patch=True,
            human_approval_confirmed=True,
            include_dynamic_validation=False,
            include_security_memory=False,
            include_policy_evaluation=False,
        )
    )
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: (
            "execution:fix-workflow"
        ),
    )
    execution = machine.create(plan)
    workflow = SecurityTaskWorkflowRunner(
        executor=SecurityTaskExecutor(
            registry=registry,
            machine=machine,
        )
    )
    artifacts = SecurityTaskArtifactStore()
    workflow_context = (
        SecurityTaskHandlerContext(
            execution_id=(
                execution.execution_id
            ),
            operation="fix_and_verify",
            language="python",
            repository_root=str(
                tmp_path
            ),
            metadata={
                "secure_fix_request": (
                    request.model_dump(
                        mode="json"
                    )
                ),
                (
                    "static_fix_verification_"
                    "request"
                ): (
                    verification.model_dump(
                        mode="json"
                    )
                ),
            },
        )
    )

    result = run(
        workflow.run(
            execution=execution,
            context=workflow_context,
            artifact_store=artifacts,
            satisfied_gates={
                "proposed_patch",
                "human_approval",
            },
        )
    )

    assert result.status == "completed"
    assert result.executed_task_ids == (
        "repository_context",
        "secure_fix",
        "fix_verification",
    )
    assert (
        artifacts.artifact(
            "applied_patch"
        ).producer_task_id
        == "secure_fix"
    )
    assert (
        artifacts.artifact(
            "fix_verification_result"
        ).producer_task_id
        == "fix_verification"
    )
    assert REPLACEMENT in target.read_text(
        encoding="utf-8"
    )
