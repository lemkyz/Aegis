from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from aegis.orchestrator.security_task_handler import (
    SecurityTaskHandlerContractError,
)
from aegis.orchestrator.security_task_registry_factory import (
    create_deep_analysis_security_task_registry,
)
from aegis.schemas.analysis import (
    ScannerEvidence,
    SecurityFinding,
)
from aegis.schemas.model_verification import (
    FindingVerification,
    VerifierReviewResult,
)


class FakeResolvedProject:
    identity_source = "test"
    dirty = False

    def __init__(
        self,
        *,
        repository_root: str,
    ) -> None:
        self.repository_root = repository_root

    def model_dump(
        self,
        *,
        mode: str,
    ) -> dict[str, Any]:
        assert mode == "json"

        return {
            "project_id": "project:test",
            "repository_root": self.repository_root,
            "identity_source": self.identity_source,
            "revision": "revision:test",
            "dirty": self.dirty,
            "metadata": {},
        }


class FakeResolvedProject:
    identity_source = "test"
    dirty = False

    def __init__(
        self,
        *,
        repository_root: str,
    ) -> None:
        self.repository_root = repository_root

    def model_dump(
        self,
        *,
        mode: str,
    ) -> dict[str, Any]:
        assert mode == "json"

        return {
            "project_id": "project:test",
            "repository_root": self.repository_root,
            "identity_source": self.identity_source,
            "revision": "revision:test",
            "dirty": self.dirty,
            "metadata": {},
        }


class FakeProjectIdentityResolver:
    name = "fake-project-identity"

    def resolve(
        self,
        repository_root: object,
    ) -> FakeResolvedProject:
        return FakeResolvedProject(
            repository_root=str(repository_root),
        )


class FakeScannerOrchestrator:
    async def scan(
        self,
        *,
        code: str,
        language: str,
        filename: str,
    ):
        del code
        del language
        del filename

        return SimpleNamespace(
            evidence=[],
            executions=[],
        )


class FakePrimaryClient:
    provider = "provider-a"
    model = "primary/model"
    transport = SimpleNamespace(
        base_url=(
            "https://primary.invalid/v1"
        ),
    )

    async def analyze_security(
        self,
        *,
        code: str,
        language: str,
        filename: str,
        scanner_evidence: list[
            ScannerEvidence
        ],
    ) -> list[SecurityFinding]:
        del code
        del language
        del filename
        del scanner_evidence

        return []


class FakeVerifierClient:
    provider = "provider-b"
    model = "verifier/model"
    transport = SimpleNamespace(
        base_url=(
            "https://verifier.invalid/v1"
        ),
    )

    async def verify_findings(
        self,
        *,
        code: str,
        language: str,
        filename: str,
        scanner_evidence: list[
            ScannerEvidence
        ],
        primary_findings: list[
            SecurityFinding
        ],
    ) -> VerifierReviewResult:
        del code
        del language
        del filename
        del scanner_evidence
        del primary_findings

        return VerifierReviewResult(
            model=self.model,
            status="completed",
            verifications=[
                FindingVerification(
                    finding_index=0,
                    verdict="supported",
                    confidence=0.90,
                    reasoning="Supported.",
                )
            ],
        )


def test_deep_analysis_registry_contains_full_pipeline() -> None:
    registry = (
        create_deep_analysis_security_task_registry(
            project_identity_resolver=(
                FakeProjectIdentityResolver()
            ),
            scanner_orchestrator=(
                FakeScannerOrchestrator()
            ),
            primary_client=(
                FakePrimaryClient()
            ),
            verifier_client=(
                FakeVerifierClient()
            ),
        )
    )

    assert registry.frozen is True

    assert registry.registered_kinds() == (
        "deterministic_scan",
        "model_consensus",
        "primary_model_review",
        "repository_context",
        "verifier_review",
    )


def test_injected_clients_are_used() -> None:
    primary = FakePrimaryClient()
    verifier = FakeVerifierClient()

    registry = (
        create_deep_analysis_security_task_registry(
            project_identity_resolver=(
                FakeProjectIdentityResolver()
            ),
            scanner_orchestrator=(
                FakeScannerOrchestrator()
            ),
            primary_client=primary,
            verifier_client=verifier,
        )
    )

    primary_handler = registry.resolve(
        "primary_model_review"
    )
    verifier_handler = registry.resolve(
        "verifier_review"
    )

    assert (
        primary_handler._primary_client
        is primary
    )

    assert (
        verifier_handler._verifier_client
        is verifier
    )


def test_deep_registry_rejects_blank_fingerprint_key() -> None:
    with pytest.raises(
        SecurityTaskHandlerContractError,
        match="must not be blank",
    ):
        create_deep_analysis_security_task_registry(
            fingerprint_key="   ",
            project_identity_resolver=(
                FakeProjectIdentityResolver()
            ),
            scanner_orchestrator=(
                FakeScannerOrchestrator()
            ),
            primary_client=(
                FakePrimaryClient()
            ),
            verifier_client=(
                FakeVerifierClient()
            ),
        )


import asyncio

from aegis.orchestrator.security_task_execution import (
    SecurityTaskExecutionMachine,
)
from aegis.orchestrator.security_task_executor import (
    SecurityTaskExecutor,
)
from aegis.orchestrator.security_task_handler import (
    SecurityTaskArtifactStore,
    SecurityTaskHandlerContext,
)
from aegis.orchestrator.security_task_planner import (
    SecurityTaskPlanner,
)
from aegis.orchestrator.security_task_workflow import (
    SecurityTaskWorkflowRunner,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskPlanRequest,
)


class WorkflowScannerOrchestrator:
    async def scan(
        self,
        *,
        code: str,
        language: str,
        filename: str,
    ):
        del code
        del language
        del filename

        evidence = ScannerEvidence(
            tool="workflow-scanner",
            rule_id="workflow.command-injection",
            message="Unsafe shell execution.",
            severity="HIGH",
            file="app.py",
            line_start=4,
            line_end=4,
            code="subprocess.run(command, shell=True)",
            cwe=["CWE-78"],
        )

        return SimpleNamespace(
            evidence=[evidence],
            executions=[],
        )


class WorkflowPrimaryClient:
    provider = "provider-a"
    model = "primary/workflow"
    transport = SimpleNamespace(
        base_url="https://primary.invalid/v1",
    )

    async def analyze_security(
        self,
        *,
        code: str,
        language: str,
        filename: str,
        scanner_evidence: list[
            ScannerEvidence
        ],
    ) -> list[SecurityFinding]:
        del code
        del language
        del filename

        return [
            SecurityFinding(
                title="Command injection",
                severity="high",
                confidence=0.90,
                primary_model=self.model,
                summary=(
                    "Untrusted input reaches "
                    "shell execution."
                ),
                evidence=[
                    "subprocess.run(command, shell=True)"
                ],
                scanner_evidence=scanner_evidence,
                cwe=["CWE-78"],
                recommended_fix=(
                    "Disable shell execution."
                ),
            )
        ]


class WorkflowVerifierClient:
    provider = "provider-b"
    model = "verifier/workflow"
    transport = SimpleNamespace(
        base_url="https://verifier.invalid/v1",
    )

    async def verify_findings(
        self,
        *,
        code: str,
        language: str,
        filename: str,
        scanner_evidence: list[
            ScannerEvidence
        ],
        primary_findings: list[
            SecurityFinding
        ],
    ) -> VerifierReviewResult:
        del code
        del language
        del filename
        del scanner_evidence

        assert len(primary_findings) == 1

        return VerifierReviewResult(
            model=self.model,
            status="completed",
            verifications=[
                FindingVerification(
                    finding_index=0,
                    verdict="supported",
                    confidence=0.94,
                    reasoning=(
                        "The scanner evidence and "
                        "source confirm the flow."
                    ),
                    evidence=["shell=True"],
                )
            ],
        )


def test_deep_registry_runs_five_stage_workflow() -> None:
    registry = (
        create_deep_analysis_security_task_registry(
            project_identity_resolver=(
                FakeProjectIdentityResolver()
            ),
            scanner_orchestrator=(
                WorkflowScannerOrchestrator()
            ),
            primary_client=(
                WorkflowPrimaryClient()
            ),
            verifier_client=(
                WorkflowVerifierClient()
            ),
        )
    )

    planner = SecurityTaskPlanner()

    plan = planner.plan(
        SecurityTaskPlanRequest(
            operation="deep_analysis",
            language="python",
            has_scanner_evidence=True,
            include_security_memory=False,
            include_policy_evaluation=False,
        )
    )

    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: (
            "execution:deep-registry-test"
        ),
    )

    execution = machine.create(plan)

    executor = SecurityTaskExecutor(
        registry=registry,
        machine=machine,
    )

    workflow = SecurityTaskWorkflowRunner(
        executor=executor,
    )

    store = SecurityTaskArtifactStore()

    result = asyncio.run(
        workflow.run(
            execution=execution,
                context=SecurityTaskHandlerContext(
                    execution_id=(
                        execution.execution_id
                    ),
                    operation="deep_analysis",
                    language="python",
                    repository_root=(
                        "/tmp/aegis-workflow"
                    ),
                    metadata={
                        "filename": "app.py",
                        "source_code": """
import subprocess


def run(command: str) -> None:
    subprocess.run(command, shell=True)
""".strip(),
                    },
                ),
            artifact_store=store,
            satisfied_gates={
                "scanner_evidence",
                "ai_available",
            },
        )
    )

    assert result.executed_task_ids == (
        "repository_context",
        "deterministic_scan",
        "primary_model_review",
        "verifier_review",
        "model_consensus",
    )

    assert result.failed_task_ids == ()

    consensus = store.value(
        "consensus_decisions"
    )

    assert consensus["status"] == "completed"

    assert consensus[
        "decisions"
    ][0]["verdict"] == "confirmed"

    assert consensus[
        "route_independence"
    ] == "independent"

    assert store.artifact(
        "primary_model_route"
    ).producer_task_id == (
        "primary_model_review"
    )

    assert store.artifact(
        "verifier_model_route"
    ).producer_task_id == (
        "verifier_review"
    )

    assert store.artifact(
        "consensus_decisions"
    ).producer_task_id == (
        "model_consensus"
    )
