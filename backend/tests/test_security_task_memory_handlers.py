from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from aegis.orchestrator.security_task_handler import (
    SecurityTaskArtifact,
    SecurityTaskArtifactStore,
    SecurityTaskHandlerContext,
    SecurityTaskHandlerRegistry,
)
from aegis.orchestrator.security_task_execution import (
    SecurityTaskExecutionMachine,
)
from aegis.orchestrator.security_task_executor import (
    SecurityTaskExecutor,
)
from aegis.orchestrator.security_task_handlers import (
    SecurityTaskInputError,
)
from aegis.orchestrator.security_task_memory_handlers import (
    PolicyEvaluationTaskHandler,
    SecurityMemoryTaskHandler,
)
from aegis.orchestrator.security_task_workflow import (
    SecurityTaskWorkflowRunner,
)
from aegis.schemas.claims import SecurityClaim
from aegis.schemas.fixes import (
    RemediationLifecycleOutcome,
)
from aegis.schemas.memory import (
    SecurityMemoryTaskArtifact,
    SecurityMemoryTaskInput,
)
from aegis.schemas.policy import (
    SecurityPolicyTaskArtifact,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskDependency,
    SecurityTaskNode,
    SecurityTaskPlanResponse,
)
from aegis.schemas.validation import (
    DynamicValidationTaskArtifact,
    UnifiedFixVerificationResponse,
    ValidationReplayCompareResponse,
    ValidationReplayResponse,
)
from aegis.security.project_identity import (
    ProjectIdentityResolver,
)
from aegis.security.security_memory import (
    SecurityMemoryService,
)
from aegis.security.sqlite_memory import (
    SQLiteProjectMemoryStore,
)


def run(coro):
    return asyncio.run(coro)


def repository(
    tmp_path: Path,
) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "app.py").write_text(
        "print('hello')\n",
        encoding="utf-8",
    )
    return root


def memory_service(
    tmp_path: Path,
) -> SecurityMemoryService:
    return SecurityMemoryService(
        store=SQLiteProjectMemoryStore(
            tmp_path / "memory.sqlite3"
        )
    )


def claim(
    *,
    claim_id: str = "claim:critical",
    state: str = "confirmed",
    statement: str = (
        "Untrusted input reaches a shell."
    ),
    severity: str = "critical",
) -> SecurityClaim:
    return SecurityClaim(
        claim_id=claim_id,
        statement=statement,
        category="command-injection",
        severity=severity,
        confidence=0.99,
        state=state,
        cwe=["CWE-78"],
        remediation=(
            "Disable shell execution."
        ),
    )


def memory_task() -> SecurityTaskNode:
    return SecurityTaskNode(
        task_id="security_memory",
        kind="security_memory",
        state="ready",
        produces=["security_snapshot"],
    )


def policy_task() -> SecurityTaskNode:
    return SecurityTaskNode(
        task_id="policy_evaluation",
        kind="policy_evaluation",
        state="ready",
        produces=["policy_decision"],
    )


def memory_context(
    root: Path,
    memory_input: SecurityMemoryTaskInput,
    *,
    policy_request: dict | None = None,
) -> SecurityTaskHandlerContext:
    metadata = {
        "security_memory_input": (
            memory_input.model_dump(
                mode="json"
            )
        ),
    }

    if policy_request is not None:
        metadata[
            "security_policy_request"
        ] = policy_request

    return SecurityTaskHandlerContext(
        execution_id="execution:memory-test",
        operation="deep_analysis",
        language="python",
        repository_root=str(root),
        metadata=metadata,
    )


def repository_artifact(
    root: Path,
) -> dict:
    return (
        ProjectIdentityResolver()
        .resolve(root)
        .model_dump(mode="json")
    )


def memory_input(
    claims: list[SecurityClaim],
    *,
    status: str = "complete",
    allow_empty: bool = False,
    sources: list[str] | None = None,
    coverage: str = "targeted_analysis",
) -> SecurityMemoryTaskInput:
    return SecurityMemoryTaskInput(
        analysis_status=status,
        coverage=coverage,
        claims=claims,
        source_artifacts=(
            sources
            or ["consensus_decisions"]
        ),
        allow_empty_snapshot=allow_empty,
    )


def execute_memory(
    *,
    root: Path,
    service: SecurityMemoryService,
    request: SecurityMemoryTaskInput,
    extra_inputs: dict | None = None,
) -> SecurityMemoryTaskArtifact:
    inputs = {
        "repository_context": (
            repository_artifact(root)
        ),
        "consensus_decisions": {
            "status": "completed",
        },
    }
    inputs.update(
        extra_inputs or {}
    )
    result = run(
        SecurityMemoryTaskHandler(
            memory_service=service,
        ).execute(
            task=memory_task(),
            context=memory_context(
                root,
                request,
            ),
            inputs=inputs,
        )
    )

    return (
        SecurityMemoryTaskArtifact
        .model_validate(
            result.output[
                "security_snapshot"
            ]
        )
    )


def test_complete_snapshot_feeds_policy_output(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    service = memory_service(
        tmp_path
    )
    memory_artifact = execute_memory(
        root=root,
        service=service,
        request=memory_input(
            [claim()]
        ),
    )

    policy_result = run(
        PolicyEvaluationTaskHandler()
        .execute(
            task=policy_task(),
            context=memory_context(
                root,
                memory_input([claim()]),
            ),
            inputs={
                "security_snapshot": (
                    memory_artifact
                    .model_dump(
                        mode="json"
                    )
                ),
            },
        )
    )
    policy = (
        SecurityPolicyTaskArtifact
        .model_validate(
            policy_result.output[
                "policy_decision"
            ]
        )
    )

    assert memory_artifact.claims_recorded == 1
    assert (
        memory_artifact
        .memory.reconciliation.summary.new
        == 1
    )
    assert policy.snapshot_id == (
        memory_artifact
        .memory.snapshot.snapshot_id
    )
    assert policy.decision.decision == "block"
    assert policy.decision.risk_level == (
        "critical"
    )


@pytest.mark.parametrize(
    "status",
    ["partial", "failed"],
)
def test_incomplete_analysis_is_never_persisted(
    tmp_path: Path,
    status: str,
) -> None:
    root = repository(tmp_path)
    service = memory_service(
        tmp_path
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="refuses partial or failed",
    ):
        execute_memory(
            root=root,
            service=service,
            request=memory_input(
                [claim()],
                status=status,
            ),
        )

    assert service.latest(root) is None


def test_empty_snapshot_requires_explicit_confirmation(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    service = memory_service(
        tmp_path
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="empty security snapshot",
    ):
        execute_memory(
            root=root,
            service=service,
            request=memory_input([]),
        )

    artifact = execute_memory(
        root=root,
        service=service,
        request=memory_input(
            [],
            allow_empty=True,
        ),
    )

    assert artifact.claims_recorded == 0
    assert artifact.memory.snapshot.claims == []


def test_missing_provenance_source_fails_closed(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    service = memory_service(
        tmp_path
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="missing source",
    ):
        execute_memory(
            root=root,
            service=service,
            request=memory_input(
                [claim()],
                sources=["threat_model"],
            ),
        )

    assert service.latest(root) is None


def test_partial_consensus_is_never_a_clean_baseline(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    service = memory_service(
        tmp_path
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="Partial or failed model consensus",
    ):
        execute_memory(
            root=root,
            service=service,
            request=memory_input(
                [claim()]
            ),
            extra_inputs={
                "consensus_decisions": {
                    "status": "partial",
                },
            },
        )

    assert service.latest(root) is None


def test_incomplete_dependency_coverage_is_not_clean(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    service = memory_service(
        tmp_path
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="Incomplete dependency coverage",
    ):
        execute_memory(
            root=root,
            service=service,
            request=memory_input(
                [],
                allow_empty=True,
                sources=[
                    "dependency_findings",
                ],
            ),
            extra_inputs={
                "dependency_findings": {
                    "scan": {
                        "scan_status": (
                            "partial"
                        ),
                    },
                },
            },
        )

    assert service.latest(root) is None


def test_incomplete_scanner_coverage_is_not_clean(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    service = memory_service(tmp_path)

    with pytest.raises(
        SecurityTaskInputError,
        match="Incomplete scanner coverage",
    ):
        execute_memory(
            root=root,
            service=service,
            request=memory_input(
                [],
                allow_empty=True,
                sources=[
                    "scanner_coverage",
                ],
            ),
            extra_inputs={
                "scanner_coverage": {
                    "status": "partial",
                    "coverage_complete": False,
                },
            },
        )

    assert service.latest(root) is None


def test_claims_can_be_derived_from_consensus_artifact(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    service = memory_service(tmp_path)
    request = SecurityMemoryTaskInput(
        analysis_status="complete",
        coverage="targeted_analysis",
        claims=[],
        claims_artifact=(
            "consensus_claims"
        ),
        source_artifacts=[
            "consensus_decisions",
            "consensus_claims",
        ],
    )

    artifact = execute_memory(
        root=root,
        service=service,
        request=request,
        extra_inputs={
            "consensus_claims": [
                claim().model_dump(
                    mode="json"
                )
            ],
        },
    )

    assert artifact.claims_recorded == 1
    assert (
        artifact.memory.snapshot.claims[0]
        .claim_id
        == "claim:critical"
    )


def test_caller_cannot_assert_verified_fixed(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    service = memory_service(
        tmp_path
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="must be derived",
    ):
        execute_memory(
            root=root,
            service=service,
            request=memory_input([
                claim(
                    state="verified_fixed",
                )
            ]),
        )

    assert service.latest(root) is None


def test_claim_secrets_are_redacted_before_storage(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    service = memory_service(
        tmp_path
    )
    synthetic_secret = (
        'PASSWORD="'
        'fixture-memory-secret-value"'
    )
    artifact = execute_memory(
        root=root,
        service=service,
        request=memory_input([
            claim(
                statement=(
                    "Unsafe credential: "
                    f"{synthetic_secret}"
                ),
            )
        ]),
    )
    serialized = artifact.model_dump_json()

    assert (
        "fixture-memory-secret-value"
        not in serialized
    )
    assert "<AEGIS_REDACTED_SECRET_" in (
        serialized
    )
    database_bytes = (
        tmp_path / "memory.sqlite3"
    ).read_bytes()
    assert (
        b"fixture-memory-secret-value"
        not in database_bytes
    )


def test_repeated_snapshot_is_idempotent(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    service = memory_service(
        tmp_path
    )
    request = memory_input(
        [claim()]
    )
    first = execute_memory(
        root=root,
        service=service,
        request=request,
    )
    second = execute_memory(
        root=root,
        service=service,
        request=request,
    )

    assert (
        first.memory.snapshot.snapshot_id
        == second.memory.snapshot.snapshot_id
    )
    assert (
        second.memory.persisted_new_snapshot
        is False
    )
    assert (
        second.memory.project_snapshot_count
        == 1
    )


def verified_dynamic_artifact(
    claim_id: str,
) -> DynamicValidationTaskArtifact:
    comparison = (
        ValidationReplayCompareResponse(
            comparator="test-comparator",
            threat_id="threat:test",
            claim_id=claim_id,
            category="command_injection",
            verdict="fixed",
            fixed=True,
            confidence=0.99,
            before_verdict="confirmed",
            after_verdict="not_reproduced",
            reasons=["Exploit no longer reproduced."],
            denials=[],
        )
    )
    verification = (
        UnifiedFixVerificationResponse(
            evaluator="test-fix-verifier",
            threat_id="threat:test",
            claim_id=claim_id,
            patch_sha256="0" * 64,
            category="command_injection",
            verdict="verified",
            verified=True,
            confidence=0.99,
            project_checks_passed=True,
            static_target_resolved=True,
            static_regression_free=True,
            dynamic_replay_fixed=True,
            residual_risk={
                "claim_id": claim_id,
                "patch_sha256": "0" * 64,
                "status": "none_identified",
                "reasons": ["Fix verified."],
            },
            reasons=["Fix verified."],
            failed_checks=[],
        )
    )
    replay = (
        ValidationReplayResponse
        .model_construct(
            comparison=comparison,
        )
    )

    return (
        DynamicValidationTaskArtifact
        .model_construct(
            replay=replay,
            fix_verification=verification,
        )
    )


def test_verified_fix_updates_claim_before_memory(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    service = memory_service(
        tmp_path
    )
    current_claim = claim()
    dynamic = verified_dynamic_artifact(
        current_claim.claim_id
    )
    artifact = execute_memory(
        root=root,
        service=service,
        request=memory_input(
            [current_claim],
            coverage="fix_verification",
            sources=[
                "dynamic_validation_evidence",
            ],
        ),
        extra_inputs={
            "dynamic_validation_evidence": (
                dynamic
            ),
        },
    )

    assert artifact.fix_verification_applied
    assert (
        artifact.memory.snapshot
        .claims[0].state
        == "verified_fixed"
    )
    assert len(
        artifact.memory.snapshot
        .claims[0].evidence
    ) == 2


def test_policy_without_memory_requires_provenance(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    service = memory_service(
        tmp_path
    )
    memory_artifact = execute_memory(
        root=root,
        service=service,
        request=memory_input(
            [claim()]
        ),
    )
    reconciliation = (
        memory_artifact
        .memory.reconciliation
    )
    policy_context = memory_context(
        root,
        memory_input([claim()]),
        policy_request={
            "profile": "strict",
            "reconciliation": (
                reconciliation.model_dump(
                    mode="json"
                )
            ),
            "source_artifacts": [
                "consensus_decisions",
            ],
        },
    )

    result = run(
        PolicyEvaluationTaskHandler()
        .execute(
            task=policy_task(),
            context=policy_context,
            inputs={
                "consensus_decisions": {
                    "status": "completed",
                },
            },
        )
    )
    policy = (
        SecurityPolicyTaskArtifact
        .model_validate(
            result.output[
                "policy_decision"
            ]
        )
    )

    assert policy.snapshot_id is None
    assert policy.source_artifacts == [
        "consensus_decisions",
    ]
    assert policy.decision.profile == "strict"


def test_policy_rejects_secret_bearing_claim_identity(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    artifact = execute_memory(
        root=root,
        service=memory_service(tmp_path),
        request=memory_input([claim()]),
    )
    reconciliation = (
        artifact.memory.reconciliation
    )
    unsafe_delta = (
        reconciliation.deltas[0].model_copy(
            update={
                "claim_id": (
                    "claim:token='synthetic-value'"
                ),
            },
        )
    )
    unsafe_reconciliation = (
        reconciliation.model_copy(
            update={
                "deltas": [unsafe_delta],
            },
        )
    )
    context = memory_context(
        root,
        memory_input([claim()]),
        policy_request={
            "reconciliation": (
                unsafe_reconciliation.model_dump(
                    mode="json"
                )
            ),
            "source_artifacts": [
                "consensus_decisions",
            ],
        },
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="identities must not contain secrets",
    ):
        run(
            PolicyEvaluationTaskHandler()
            .execute(
                task=policy_task(),
                context=context,
                inputs={
                    "consensus_decisions": {
                        "status": "completed",
                    },
                },
            )
        )


def test_policy_cannot_hide_snapshot_provenance(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    artifact = execute_memory(
        root=root,
        service=memory_service(tmp_path),
        request=memory_input([claim()]),
    )
    context = memory_context(
        root,
        memory_input([claim()]),
        policy_request={
            "source_artifacts": [
                "consensus_decisions",
            ],
        },
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="must name the security_snapshot",
    ):
        run(
            PolicyEvaluationTaskHandler()
            .execute(
                task=policy_task(),
                context=context,
                inputs={
                    "security_snapshot": (
                        artifact.model_dump(
                            mode="json"
                        )
                    ),
                    "consensus_decisions": {
                        "status": "completed",
                    },
                },
            )
        )


def test_memory_and_policy_compose_in_workflow(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    service = memory_service(
        tmp_path
    )
    registry = SecurityTaskHandlerRegistry()
    registry.register(
        SecurityMemoryTaskHandler(
            memory_service=service,
        )
    )
    registry.register(
        PolicyEvaluationTaskHandler()
    )
    registry.freeze()
    plan = SecurityTaskPlanResponse(
        planner="test-planner",
        operation="deep_analysis",
        status="ready",
        tasks=[
            SecurityTaskNode(
                task_id="security_memory",
                kind="security_memory",
                state="ready",
                produces=[
                    "security_snapshot",
                ],
            ),
            SecurityTaskNode(
                task_id="policy_evaluation",
                kind="policy_evaluation",
                state="waiting",
                dependencies=[
                    SecurityTaskDependency(
                        task_id=(
                            "security_memory"
                        ),
                    )
                ],
                produces=[
                    "policy_decision",
                ],
            ),
        ],
        entry_task_ids=[
            "security_memory",
        ],
        terminal_task_ids=[
            "policy_evaluation",
        ],
        execution_order=[
            "security_memory",
            "policy_evaluation",
        ],
    )
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: (
            "execution:memory-workflow"
        ),
    )
    execution = machine.create(plan)
    store = SecurityTaskArtifactStore({
        "repository_context": (
            SecurityTaskArtifact(
                name="repository_context",
                producer_task_id=(
                    "repository_context"
                ),
                value=repository_artifact(
                    root
                ),
            )
        ),
        "consensus_decisions": (
            SecurityTaskArtifact(
                name="consensus_decisions",
                producer_task_id=(
                    "model_consensus"
                ),
                value={
                    "status": "completed",
                },
            )
        ),
    })
    context = memory_context(
        root,
        memory_input([claim()]),
    )
    context = SecurityTaskHandlerContext(
        execution_id=(
            execution.execution_id
        ),
        operation=context.operation,
        language=context.language,
        repository_root=(
            context.repository_root
        ),
        metadata=context.metadata,
    )
    workflow = SecurityTaskWorkflowRunner(
        executor=SecurityTaskExecutor(
            registry=registry,
            machine=machine,
        )
    )

    result = run(
        workflow.run(
            execution=execution,
            context=context,
            artifact_store=store,
        )
    )

    assert result.status == "completed"
    assert result.executed_task_ids == (
        "security_memory",
        "policy_evaluation",
    )
    assert (
        store.artifact(
            "security_snapshot"
        ).producer_task_id
        == "security_memory"
    )
    assert (
        store.artifact(
            "policy_decision"
        ).producer_task_id
        == "policy_evaluation"
    )

def _lifecycle_bound_dynamic_artifact(
    claim_id: str,
    *,
    transaction_state: str = "committed",
) -> tuple[
    DynamicValidationTaskArtifact,
    RemediationLifecycleOutcome,
]:
    dynamic = verified_dynamic_artifact(
        claim_id
    ).model_copy(
        deep=True,
        update={
            "handler": (
                "test-dynamic-lifecycle-handler"
            ),
            "source_artifacts": [
                "fix_verification_result",
            ],
            "manifest_id": (
                "manifest:memory-lifecycle"
            ),
            "manifest_sha256": "a" * 64,
            "static_verification_sha256": (
                "b" * 64
            ),
            "transaction_state": (
                transaction_state
            ),
            "outputs_redacted": True,
        },
    )
    outcome = RemediationLifecycleOutcome(
        manifest_id=dynamic.manifest_id,
        manifest_sha256=(
            dynamic.manifest_sha256
        ),
        static_verification_sha256=(
            dynamic.static_verification_sha256
        ),
        dynamic_validation_sha256=(
            dynamic.artifact_sha256()
        ),
        unified_verdict=(
            dynamic.fix_verification.verdict
        ),
        transaction_state=(
            transaction_state
        ),
        residual_risk=(
            dynamic.fix_verification.residual_risk
        ),
    )
    return dynamic, outcome


def test_memory_capability_accepts_lifecycle_outcome_provenance() -> None:
    assert (
        "remediation_lifecycle_outcome"
        in SecurityMemoryTaskHandler
        .capability.optional_artifacts
    )


def test_manifest_aware_dynamic_memory_requires_lifecycle_outcome(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    current_claim = claim()
    dynamic, _ = (
        _lifecycle_bound_dynamic_artifact(
            current_claim.claim_id,
        )
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="lifecycle|remediation",
    ):
        execute_memory(
            root=root,
            service=memory_service(
                tmp_path
            ),
            request=memory_input(
                [current_claim],
                coverage="fix_verification",
                sources=[
                    "dynamic_validation_evidence",
                ],
            ),
            extra_inputs={
                "dynamic_validation_evidence": (
                    dynamic
                ),
            },
        )


def test_lifecycle_outcome_must_match_exact_dynamic_digest(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    current_claim = claim()
    dynamic, outcome = (
        _lifecycle_bound_dynamic_artifact(
            current_claim.claim_id,
        )
    )
    mismatched = outcome.model_copy(
        deep=True,
        update={
            "dynamic_validation_sha256": (
                "f" * 64
            ),
        },
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="lifecycle|dynamic.*digest|provenance",
    ):
        execute_memory(
            root=root,
            service=memory_service(
                tmp_path
            ),
            request=memory_input(
                [current_claim],
                coverage="fix_verification",
                sources=[
                    "dynamic_validation_evidence",
                    "remediation_lifecycle_outcome",
                ],
            ),
            extra_inputs={
                "dynamic_validation_evidence": (
                    dynamic
                ),
                "remediation_lifecycle_outcome": (
                    mismatched
                ),
            },
        )


def test_lifecycle_bound_memory_persists_outcome_evidence_deterministically(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    service = memory_service(tmp_path)
    current_claim = claim()
    dynamic, outcome = (
        _lifecycle_bound_dynamic_artifact(
            current_claim.claim_id,
        )
    )
    request = memory_input(
        [current_claim],
        coverage="fix_verification",
        sources=[
            "dynamic_validation_evidence",
            "remediation_lifecycle_outcome",
        ],
    )
    extra_inputs = {
        "dynamic_validation_evidence": (
            dynamic
        ),
        "remediation_lifecycle_outcome": (
            outcome
        ),
    }

    first = execute_memory(
        root=root,
        service=service,
        request=request,
        extra_inputs=extra_inputs,
    )
    second = execute_memory(
        root=root,
        service=service,
        request=request,
        extra_inputs=extra_inputs,
    )

    first_claim = (
        first.memory.snapshot.claims[0]
    )
    lifecycle_evidence = next(
        item
        for item in first_claim.evidence
        if item.source.name
        == "Aegis Remediation Lifecycle"
    )

    assert first_claim.state == "verified_fixed"
    assert (
        f"Outcome SHA-256: "
        f"{outcome.outcome_sha256()}"
        in lifecycle_evidence.details
    )
    assert any(
        relationship.kind == "derived_from"
        and relationship.source_evidence_id
        == lifecycle_evidence.evidence_id
        for relationship
        in first_claim.relationships
    )
    assert (
        first.memory.snapshot.snapshot_id
        == second.memory.snapshot.snapshot_id
    )
    assert (
        second.memory.persisted_new_snapshot
        is False
    )


def test_rolled_back_lifecycle_is_remembered_but_not_verified_fixed(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    current_claim = claim()
    dynamic, outcome = (
        _lifecycle_bound_dynamic_artifact(
            current_claim.claim_id,
            transaction_state="rolled_back",
        )
    )

    artifact = execute_memory(
        root=root,
        service=memory_service(
            tmp_path
        ),
        request=memory_input(
            [current_claim],
            coverage="fix_verification",
            sources=[
                "dynamic_validation_evidence",
                "remediation_lifecycle_outcome",
            ],
        ),
        extra_inputs={
            "dynamic_validation_evidence": (
                dynamic
            ),
            "remediation_lifecycle_outcome": (
                outcome
            ),
        },
    )

    remembered = (
        artifact.memory.snapshot.claims[0]
    )
    assert remembered.state != "verified_fixed"
    assert any(
        item.source.name
        == "Aegis Remediation Lifecycle"
        for item in remembered.evidence
    )
