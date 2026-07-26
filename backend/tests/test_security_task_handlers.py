from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Mapping

import pytest

from aegis.orchestrator.security_task_handler import (
    SecurityTaskArtifactStore,
    SecurityTaskHandlerContext,
    SecurityTaskHandlerContractError,
)
from aegis.orchestrator.security_task_handlers import (
    DeterministicScanTaskHandler,
    RepositoryContextTaskHandler,
    SecurityTaskInputError,
    create_core_security_task_registry,
)
from aegis.schemas.analysis import (
    ScannerEvidence,
)
from aegis.schemas.memory import (
    RepositoryContext,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
)
from aegis.security.orchestrator import (
    ScannerExecution,
    ScannerOrchestrationResult,
)


class FakeProjectIdentityResolver:
    name = "fake-project-identity"

    def resolve(
        self,
        path: str | Path,
    ) -> RepositoryContext:
        return RepositoryContext(
            project_id="project:test",
            repository_root=str(
                Path(path).resolve()
            ),
            identity_source="local_path",
            remote=None,
            branch="main",
            head_commit="abc123",
            revision="git:abc123",
            dirty=False,
        )


class FakeScannerOrchestrator:
    def __init__(
        self,
        *,
        evidence: list[
            ScannerEvidence
        ] | None = None,
        failed: bool = False,
    ) -> None:
        self._evidence = evidence or []
        self._failed = failed

    async def scan(
        self,
        *,
        code: str,
        filename: str,
        language: str,
    ) -> ScannerOrchestrationResult:
        del code
        del filename
        del language

        executions = [
            ScannerExecution(
                name="fake-scanner",
                status=(
                    "failed"
                    if self._failed
                    else "completed"
                ),
                evidence_count=(
                    0
                    if self._failed
                    else len(
                        self._evidence
                    )
                ),
                error=(
                    "fake scanner failed"
                    if self._failed
                    else None
                ),
            )
        ]

        return ScannerOrchestrationResult(
            evidence=list(
                self._evidence
            ),
            executions=executions,
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


def repository_task() -> SecurityTaskNode:
    return SecurityTaskNode(
        task_id="repository_context",
        kind="repository_context",
        state="ready",
        produces=[
            "repository_context",
        ],
    )


def scan_task() -> SecurityTaskNode:
    return SecurityTaskNode(
        task_id="deterministic_scan",
        kind="deterministic_scan",
        state="ready",
        produces=[
            "scanner_evidence",
            "scanner_findings",
        ],
    )


def context(
    *,
    repository_root: str | None = None,
    metadata: Mapping[
        str,
        Any,
    ] | None = None,
) -> SecurityTaskHandlerContext:
    return SecurityTaskHandlerContext(
        execution_id="execution:test",
        operation="fast_scan",
        language="python",
        repository_root=repository_root,
        metadata=metadata or {},
    )


def run(coro):
    return asyncio.run(coro)


def evidence() -> ScannerEvidence:
    return ScannerEvidence(
        tool="fake-scanner",
        rule_id=(
            "aegis.python.command-injection"
        ),
        message=(
            "User input reaches a shell command."
        ),
        severity="ERROR",
        file="example.py",
        line_start=3,
        line_end=3,
        code="os.system(user_input)",
        cwe=["CWE-78"],
        owasp=["A03:2021"],
    )


def test_repository_handler_resolves_context(
    tmp_path: Path,
) -> None:
    handler = RepositoryContextTaskHandler(
        resolver=FakeProjectIdentityResolver(),
    )

    result = run(
        handler.execute(
            task=repository_task(),
            context=context(
                repository_root=str(
                    tmp_path
                )
            ),
            inputs={},
        )
    )

    repository = result.output[
        "repository_context"
    ]

    assert repository[
        "project_id"
    ] == "project:test"

    assert repository[
        "revision"
    ] == "git:abc123"


def test_repository_handler_requires_root() -> None:
    handler = RepositoryContextTaskHandler(
        resolver=FakeProjectIdentityResolver(),
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="repository_root",
    ):
        run(
            handler.execute(
                task=repository_task(),
                context=context(),
                inputs={},
            )
        )


def test_scan_handler_produces_real_contracts() -> None:
    handler = DeterministicScanTaskHandler(
        scanner_orchestrator=(
            FakeScannerOrchestrator(
                evidence=[
                    evidence()
                ]
            )
        ),
        config_scanner=(
            NoopConfigScanner()
        ),
    )

    result = run(
        handler.execute(
            task=scan_task(),
            context=context(
                repository_root="/tmp",
                metadata={
                    "source_code": (
                        "import os\n"
                        "user_input = input()\n"
                        "os.system(user_input)\n"
                    ),
                    "filename": "example.py",
                },
            ),
            inputs={
                "repository_context": {
                    "project_id": (
                        "project:test"
                    ),
                },
            },
        )
    )

    assert len(
        result.output[
            "scanner_evidence"
        ]
    ) == 1

    assert len(
        result.output[
            "scanner_findings"
        ]
    ) == 1

    finding = result.output[
        "scanner_findings"
    ][0]

    assert finding[
        "severity"
    ] == "high"

    assert finding[
        "confidence"
    ] == 0.85

    assert finding[
        "vulnerable_lines"
    ] == [3]

    assert finding[
        "cwe"
    ] == ["CWE-78"]


def test_scan_handler_deduplicates_evidence() -> None:
    item = evidence()

    handler = DeterministicScanTaskHandler(
        scanner_orchestrator=(
            FakeScannerOrchestrator(
                evidence=[
                    item,
                    item.model_copy(
                        deep=True
                    ),
                ]
            )
        ),
        config_scanner=(
            NoopConfigScanner()
        ),
    )

    result = run(
        handler.execute(
            task=scan_task(),
            context=context(
                repository_root="/tmp",
                metadata={
                    "source_code": (
                        "os.system(user_input)"
                    ),
                    "filename": "example.py",
                },
            ),
            inputs={
                "repository_context": {
                    "project_id": (
                        "project:test"
                    ),
                },
            },
        )
    )

    assert len(
        result.output[
            "scanner_evidence"
        ]
    ) == 1


def test_scanner_failure_is_metadata_not_crash() -> None:
    handler = DeterministicScanTaskHandler(
        scanner_orchestrator=(
            FakeScannerOrchestrator(
                failed=True
            )
        ),
        config_scanner=(
            NoopConfigScanner()
        ),
    )

    result = run(
        handler.execute(
            task=scan_task(),
            context=context(
                repository_root="/tmp",
                metadata={
                    "source_code": (
                        "print('safe')"
                    ),
                    "filename": "example.py",
                },
            ),
            inputs={
                "repository_context": {
                    "project_id": (
                        "project:test"
                    ),
                },
            },
        )
    )

    assert result.output[
        "scanner_evidence"
    ] == []

    assert result.output[
        "scanner_findings"
    ] == []

    assert result.metadata[
        "failed_scanners"
    ][0]["name"] == (
        "fake-scanner"
    )


def test_scan_handler_requires_source_code() -> None:
    handler = DeterministicScanTaskHandler(
        scanner_orchestrator=(
            FakeScannerOrchestrator()
        ),
        config_scanner=(
            NoopConfigScanner()
        ),
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="source_code",
    ):
        run(
            handler.execute(
                task=scan_task(),
                context=context(
                    repository_root="/tmp",
                    metadata={
                        "filename": (
                            "example.py"
                        ),
                    },
                ),
                inputs={
                    "repository_context": {},
                },
            )
        )


def test_scan_handler_requires_filename() -> None:
    handler = DeterministicScanTaskHandler(
        scanner_orchestrator=(
            FakeScannerOrchestrator()
        ),
        config_scanner=(
            NoopConfigScanner()
        ),
    )

    with pytest.raises(
        SecurityTaskInputError,
        match="filename",
    ):
        run(
            handler.execute(
                task=scan_task(),
                context=context(
                    repository_root="/tmp",
                    metadata={
                        "source_code": (
                            "print('hello')"
                        ),
                    },
                ),
                inputs={
                    "repository_context": {},
                },
            )
        )


def test_core_registry_contains_real_handlers() -> None:
    registry = (
        create_core_security_task_registry(
            project_identity_resolver=(
                FakeProjectIdentityResolver()
            ),
            scanner_orchestrator=(
                FakeScannerOrchestrator()
            ),
        )
    )

    assert registry.frozen is True

    assert registry.registered_kinds() == (
        "deterministic_scan",
        "repository_context",
    )


def test_registry_rejects_blank_fingerprint_key() -> None:
    with pytest.raises(
        SecurityTaskHandlerContractError,
        match="must not be blank",
    ):
        create_core_security_task_registry(
            fingerprint_key="   ",
            project_identity_resolver=(
                FakeProjectIdentityResolver()
            ),
            scanner_orchestrator=(
                FakeScannerOrchestrator()
            ),
        )


def test_handler_result_integrates_with_artifact_store(
    tmp_path: Path,
) -> None:
    handler = RepositoryContextTaskHandler(
        resolver=FakeProjectIdentityResolver(),
    )

    result = run(
        handler.execute(
            task=repository_task(),
            context=context(
                repository_root=str(
                    tmp_path
                )
            ),
            inputs={},
        )
    )

    store = SecurityTaskArtifactStore()

    store.record_handler_result(
        task=repository_task(),
        capability=handler.capability,
        result=result,
    )

    assert store.value(
        "repository_context"
    )["project_id"] == "project:test"
