from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
import subprocess
from types import SimpleNamespace
from typing import Any, Mapping

import pytest

from aegis.orchestrator.security_task_handler import (
    SecurityTaskHandlerContext,
    SecurityTaskHandlerRegistry,
    SecurityTaskHandlerResult,
)
from aegis.orchestrator.security_task_integrity import (
    SecurityTaskIntegrityError,
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
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
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


VULNERABLE_SOURCE = """\
import subprocess


def run_command(user_input: str) -> None:
    subprocess.run(user_input, shell=True, check=True)
"""


FIXED_SOURCE = """\
import subprocess


def run_command(arguments: list[str]) -> None:
    subprocess.run(arguments, shell=False, check=True)
"""


def git(
    repository: Path,
    *arguments: str,
) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def commit_source(
    repository: Path,
    source: str,
    message: str,
) -> str:
    (repository / "app.py").write_text(
        source,
        encoding="utf-8",
    )
    git(repository, "add", "app.py")
    git(repository, "commit", "-m", message)
    return git(repository, "rev-parse", "HEAD")


def real_repository(
    tmp_path: Path,
) -> tuple[Path, str]:
    repository = tmp_path / "sample-service"
    repository.mkdir()
    git(repository, "init", "-b", "main")
    git(
        repository,
        "config",
        "user.email",
        "acceptance@aegis.local",
    )
    git(
        repository,
        "config",
        "user.name",
        "Aegis Acceptance",
    )
    git(
        repository,
        "remote",
        "add",
        "origin",
        (
            "https://example.invalid/"
            "aegis/sample-service.git"
        ),
    )
    revision = commit_source(
        repository,
        VULNERABLE_SOURCE,
        "Add vulnerable command runner",
    )
    return repository, revision


class AcceptanceConfigScanner:
    name = "acceptance-config"

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


class AcceptanceScanner:
    async def scan(
        self,
        *,
        code: str,
        language: str,
        filename: str,
    ) -> ScannerOrchestrationResult:
        del language
        vulnerable = "shell=True" in code
        evidence = (
            [
                ScannerEvidence(
                    tool="acceptance-scanner",
                    rule_id=(
                        "python.command-injection"
                    ),
                    message=(
                        "Untrusted input reaches a "
                        "shell command."
                    ),
                    severity="CRITICAL",
                    file=filename,
                    line_start=5,
                    line_end=5,
                    code=(
                        "subprocess.run("
                        "user_input, shell=True)"
                    ),
                    cwe=["CWE-78"],
                )
            ]
            if vulnerable
            else []
        )

        return ScannerOrchestrationResult(
            evidence=evidence,
            executions=[
                ScannerExecution(
                    name="acceptance-scanner",
                    status="completed",
                    evidence_count=len(evidence),
                )
            ],
        )


class AcceptancePrimaryClient:
    provider = "acceptance-primary"
    model = "acceptance/primary"
    transport = SimpleNamespace(
        base_url=(
            "https://primary.example.invalid/v1"
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

        if not scanner_evidence:
            return []

        return [
            SecurityFinding(
                title="Command injection",
                severity="critical",
                confidence=0.98,
                primary_model=self.model,
                summary=(
                    "Caller-controlled text reaches "
                    "a shell interpreter."
                ),
                evidence=[
                    (
                        "shell=True passes the value "
                        "to the platform shell."
                    )
                ],
                scanner_evidence=(
                    scanner_evidence
                ),
                cwe=["CWE-78"],
                recommended_fix=(
                    "Pass an argument list with "
                    "shell disabled."
                ),
            )
        ]


class AcceptanceVerifierClient:
    provider = "acceptance-verifier"
    model = "acceptance/verifier"
    transport = SimpleNamespace(
        base_url=(
            "https://verifier.example.invalid/v1"
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

        return VerifierReviewResult(
            model=self.model,
            status="completed",
            verifications=[
                FindingVerification(
                    finding_index=index,
                    verdict="supported",
                    confidence=0.99,
                    reasoning=(
                        "The source and scanner "
                        "evidence support the claim."
                    ),
                    evidence=["shell=True"],
                )
                for index, _finding
                in enumerate(primary_findings)
            ],
        )


class MutatingThreatModelTaskHandler(
    ThreatModelTaskHandler
):
    def __init__(
        self,
        repository: Path,
    ) -> None:
        super().__init__()
        self._repository = repository

    async def execute(
        self,
        *,
        task: SecurityTaskNode,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> SecurityTaskHandlerResult:
        result = await super().execute(
            task=task,
            context=context,
            inputs=inputs,
        )
        source_path = (
            self._repository / "app.py"
        )
        source_path.write_text(
            source_path.read_text(
                encoding="utf-8"
            )
            + "\n# changed during analysis\n",
            encoding="utf-8",
        )
        return result


def registry(
    memory: SecurityMemoryService,
    *,
    threat_model_handler=None,
) -> SecurityTaskHandlerRegistry:
    value = SecurityTaskHandlerRegistry()
    value.register(
        RepositoryContextTaskHandler()
    )
    value.register(
        DeterministicScanTaskHandler(
            scanner_orchestrator=(
                AcceptanceScanner()
            ),
            config_scanner=(
                AcceptanceConfigScanner()
            ),
        )
    )
    value.register(
        PrimaryModelReviewTaskHandler(
            primary_client=(
                AcceptancePrimaryClient()
            ),
        )
    )
    value.register(
        VerifierReviewTaskHandler(
            verifier_client=(
                AcceptanceVerifierClient()
            ),
        )
    )
    value.register(
        ModelConsensusTaskHandler()
    )
    value.register(
        threat_model_handler
        or ThreatModelTaskHandler()
    )
    value.register(
        SecurityMemoryTaskHandler(
            memory_service=memory,
        )
    )
    value.register(
        PolicyEvaluationTaskHandler()
    )
    value.freeze()
    return value


def run_request(
    runner: SecurityTaskProductionRunner,
    repository: Path,
    source: str,
):
    return asyncio.run(
        runner.run(
            SecurityTaskRunRequest(
                repository_path=str(
                    repository
                ),
                code=source,
                filename="app.py",
                language="python",
            )
        )
    )


@pytest.mark.acceptance
def test_real_git_repository_blocks_then_clears_fix(
    tmp_path: Path,
) -> None:
    repository, vulnerable_commit = (
        real_repository(tmp_path)
    )
    memory = SecurityMemoryService(
        store=SQLiteProjectMemoryStore(
            tmp_path / "memory.sqlite3"
        )
    )
    runner = SecurityTaskProductionRunner(
        registry=registry(memory)
    )

    vulnerable = run_request(
        runner,
        repository,
        VULNERABLE_SOURCE,
    )

    assert vulnerable.workflow_status == (
        "completed"
    )
    assert vulnerable.integrity.verified is True
    assert (
        vulnerable.integrity.repository_revision
        == f"git:{vulnerable_commit}"
    )
    assert (
        vulnerable.integrity.source_sha256
        == hashlib.sha256(
            VULNERABLE_SOURCE.encode("utf-8")
        ).hexdigest()
    )
    assert (
        vulnerable.policy_decision is not None
        and vulnerable.policy_decision
        .decision.decision
        == "block"
    )
    assert len(vulnerable.analysis.claims) == 1

    fixed_commit = commit_source(
        repository,
        FIXED_SOURCE,
        "Remove shell command execution",
    )
    fixed = run_request(
        runner,
        repository,
        FIXED_SOURCE,
    )

    assert fixed.workflow_status == "completed"
    assert fixed.integrity.verified is True
    assert (
        fixed.integrity.repository_revision
        == f"git:{fixed_commit}"
    )
    assert (
        fixed.integrity.repository_revision
        != vulnerable.integrity
        .repository_revision
    )
    assert (
        fixed.policy_decision is not None
        and fixed.policy_decision
        .decision.decision
        == "allow"
    )
    assert fixed.analysis.findings == []
    assert fixed.analysis.claims == []
    assert fixed.security_memory is not None
    assert (
        fixed.security_memory.memory
        .reconciliation.summary.resolved
        == 1
    )
    assert len(memory.history(repository)) == 2
    assert git(
        repository,
        "status",
        "--porcelain=v1",
    ) == ""


@pytest.mark.acceptance
def test_repository_revision_drift_fails_closed(
    tmp_path: Path,
) -> None:
    repository, _revision = (
        real_repository(tmp_path)
    )
    memory = SecurityMemoryService(
        store=SQLiteProjectMemoryStore(
            tmp_path / "memory.sqlite3"
        )
    )
    runner = SecurityTaskProductionRunner(
        registry=registry(
            memory,
            threat_model_handler=(
                MutatingThreatModelTaskHandler(
                    repository
                )
            ),
        )
    )

    with pytest.raises(
        SecurityTaskIntegrityError,
        match="revision changed",
    ):
        run_request(
            runner,
            repository,
            VULNERABLE_SOURCE,
        )

    assert memory.history(repository) == []
