from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from aegis.orchestrator.security_task_handler import (
    SecurityTaskHandlerRegistry,
)
from aegis.orchestrator.security_task_handlers import (
    DeterministicScanTaskHandler,
    RepositoryContextTaskHandler,
)
from aegis.orchestrator.security_task_memory_handlers import (
    PolicyEvaluationTaskHandler,
    SecurityMemoryTaskHandler,
)
from aegis.orchestrator.security_task_model_handlers import (
    ModelConsensusTaskHandler,
    PrimaryModelReviewTaskHandler,
    VerifierReviewTaskHandler,
)
from aegis.orchestrator.security_task_production import (
    SecurityTaskProductionError,
    SecurityTaskProductionRunner,
)
from aegis.orchestrator.security_task_threat_model_handler import (
    ThreatModelTaskHandler,
)
from aegis.schemas.analysis import (
    ScannerEvidence,
    SecurityFinding,
)
from aegis.schemas.model_verification import (
    FindingVerification,
    VerifierReviewResult,
)
from aegis.schemas.security_task_run import (
    SecurityTaskRunRequest,
)
from aegis.security.orchestrator import (
    ScannerExecution,
    ScannerOrchestrationResult,
)
from aegis.security.security_memory import (
    SecurityMemoryService,
)
from aegis.security.sqlite_memory import (
    SQLiteProjectMemoryStore,
)


class NoopConfigScanner:
    name = "noop-config"

    def supports(
        self,
        *,
        filename: str,
        language: str,
    ) -> bool:
        del filename
        del language
        return False

    def scan(
        self,
        *,
        code: str,
        filename: str,
        language: str,
    ) -> list[ScannerEvidence]:
        del code
        del filename
        del language
        return []


class ProductionScanner:
    def __init__(
        self,
        *,
        failed: bool = False,
    ) -> None:
        self.failed = failed

    async def scan(
        self,
        *,
        code: str,
        language: str,
        filename: str,
    ) -> ScannerOrchestrationResult:
        del code
        del language
        del filename

        evidence = (
            []
            if self.failed
            else [
                ScannerEvidence(
                    tool="production-scanner",
                    rule_id=(
                        "workflow.command-injection"
                    ),
                    message=(
                        "Untrusted input reaches "
                        "shell execution."
                    ),
                    severity="CRITICAL",
                    file="app.py",
                    line_start=2,
                    line_end=2,
                    code=(
                        "subprocess.run(value, "
                        "shell=True)"
                    ),
                    cwe=["CWE-78"],
                )
            ]
        )

        return ScannerOrchestrationResult(
            evidence=evidence,
            executions=[
                ScannerExecution(
                    name="production-scanner",
                    status=(
                        "failed"
                        if self.failed
                        else "completed"
                    ),
                    evidence_count=len(
                        evidence
                    ),
                    error=(
                        "scanner unavailable"
                        if self.failed
                        else None
                    ),
                )
            ],
        )


class ProductionPrimaryClient:
    provider = "provider-primary"
    model = "primary/production"
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

        return [
            SecurityFinding(
                title="Command injection",
                severity="critical",
                confidence=0.96,
                primary_model=self.model,
                summary=(
                    "Untrusted input reaches "
                    "shell execution."
                ),
                evidence=[
                    "shell=True accepts attacker "
                    "controlled input."
                ],
                scanner_evidence=(
                    scanner_evidence
                ),
                cwe=["CWE-78"],
                recommended_fix=(
                    "Disable shell execution."
                ),
            )
        ]


class ProductionVerifierClient:
    provider = "provider-verifier"
    model = "verifier/production"
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

        assert len(primary_findings) == 1

        return VerifierReviewResult(
            model=self.model,
            status="completed",
            verifications=[
                FindingVerification(
                    finding_index=0,
                    verdict="supported",
                    confidence=0.98,
                    reasoning=(
                        "The scanner and source "
                        "independently support the "
                        "claim."
                    ),
                    evidence=["shell=True"],
                )
            ],
        )


def repository(
    tmp_path: Path,
) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "app.py").write_text(
        (
            "import subprocess\n"
            "subprocess.run(value, shell=True)\n"
        ),
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


def registry(
    *,
    scanner: ProductionScanner,
    memory: SecurityMemoryService,
) -> SecurityTaskHandlerRegistry:
    result = SecurityTaskHandlerRegistry()
    result.register(
        RepositoryContextTaskHandler()
    )
    result.register(
        DeterministicScanTaskHandler(
            scanner_orchestrator=scanner,
            config_scanner=(
                NoopConfigScanner()
            ),
        )
    )
    result.register(
        PrimaryModelReviewTaskHandler(
            primary_client=(
                ProductionPrimaryClient()
            ),
        )
    )
    result.register(
        VerifierReviewTaskHandler(
            verifier_client=(
                ProductionVerifierClient()
            ),
        )
    )
    result.register(
        ModelConsensusTaskHandler()
    )
    result.register(
        ThreatModelTaskHandler()
    )
    result.register(
        SecurityMemoryTaskHandler(
            memory_service=memory,
        )
    )
    result.register(
        PolicyEvaluationTaskHandler()
    )
    result.freeze()
    return result


def request(
    root: Path,
) -> SecurityTaskRunRequest:
    return SecurityTaskRunRequest(
        repository_path=str(root),
        code=(
            "import subprocess\n"
            "subprocess.run(value, shell=True)\n"
        ),
        filename="app.py",
        language="python",
    )


def run(coro):
    return asyncio.run(coro)


def test_production_run_completes_trust_pipeline(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    memory = memory_service(tmp_path)
    result = run(
        SecurityTaskProductionRunner(
            registry=registry(
                scanner=ProductionScanner(),
                memory=memory,
            )
        ).run(request(root))
    )

    assert result.workflow_status == "completed"
    assert result.execution.status == "completed"
    assert (
        result.aggregation.completed_task_ids
        == [
            "repository_context",
            "deterministic_scan",
            "primary_model_review",
            "verifier_review",
            "model_consensus",
            "threat_model",
            "security_memory",
            "policy_evaluation",
        ]
    )
    assert (
        result.analysis.findings[0]
        .consensus_verdict
        == "confirmed"
    )
    assert (
        result.analysis.claims[0].state
        == "confirmed"
    )
    assert result.threat_model is not None
    assert result.security_memory is not None
    assert result.policy_decision is not None
    assert (
        result.policy_decision
        .decision.decision
        == "block"
    )
    assert (
        result.aggregation.audit_event_count
        == 33
    )
    assert result.integrity.verified is True
    assert (
        result.integrity.source_sha256
        == hashlib.sha256(
            request(root).code.encode("utf-8")
        ).hexdigest()
    )
    assert (
        result.integrity.repository_revision
        == result.security_memory
        .memory.repository.revision
    )
    assert len(
        result.integrity.audit_sha256
    ) == 64
    assert len(memory.history(root)) == 1


def test_incomplete_scanner_coverage_cannot_persist(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    memory = memory_service(tmp_path)
    result = run(
        SecurityTaskProductionRunner(
            registry=registry(
                scanner=ProductionScanner(
                    failed=True
                ),
                memory=memory,
            )
        ).run(request(root))
    )

    assert result.workflow_status == "failed"
    assert "security_memory" in (
        result.aggregation.failed_task_ids
    )
    assert result.security_memory is None
    assert result.policy_decision is None
    assert memory.history(root) == []
    assert any(
        "Incomplete scanner coverage"
        in error
        for error in result.errors
    )


def test_run_request_rejects_unsafe_filename(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ValidationError,
        match="repository-relative",
    ):
        SecurityTaskRunRequest(
            repository_path=str(tmp_path),
            code="print('safe')",
            filename="../outside.py",
        )


def test_run_request_bounds_execution_timeout(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ValidationError,
        match="less than or equal to 900",
    ):
        SecurityTaskRunRequest(
            repository_path=str(tmp_path),
            code="print('safe')",
            filename="app.py",
            timeout_seconds=901,
        )


def test_production_run_rejects_stale_source(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    stale_request = request(root)
    stale_request.code = "print('different')\n"

    with pytest.raises(
        SecurityTaskProductionError,
        match="persisted file",
    ):
        run(
            SecurityTaskProductionRunner(
                registry=registry(
                    scanner=(
                        ProductionScanner()
                    ),
                    memory=memory_service(
                        tmp_path
                    ),
                )
            ).run(stale_request)
        )


def test_cancelled_production_run_fails_with_audit(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    memory = memory_service(tmp_path)
    result = run(
        SecurityTaskProductionRunner(
            registry=registry(
                scanner=ProductionScanner(),
                memory=memory,
            )
        ).run(
            request(root),
            cancellation_requested=(
                lambda: True
            ),
        )
    )

    assert result.workflow_status == "failed"
    assert result.integrity.verified is True
    assert (
        result.aggregation.failed_task_ids
        == ["repository_context"]
    )
    assert any(
        event.event_type == "task_failed"
        and event.task_id
        == "repository_context"
        for event in result.execution.events
    )
    assert result.security_memory is None
    assert result.policy_decision is None
    assert memory.history(root) == []
