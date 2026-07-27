from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from aegis.orchestrator.security_task_execution import (
    SecurityTaskExecutionMachine,
)
from aegis.orchestrator.security_task_executor import (
    SecurityTaskExecutor,
)
from aegis.orchestrator.security_task_handler import (
    SecurityTaskArtifactStore,
    SecurityTaskHandlerContext,
    SecurityTaskHandlerRegistry,
)
from aegis.orchestrator.security_task_handlers import (
    RepositoryContextTaskHandler,
)
from aegis.orchestrator.security_task_planner import (
    SecurityTaskPlanner,
)
from aegis.orchestrator.security_task_specialist_handlers import (
    AttackSurfaceTaskHandler,
    DependencyScanTaskHandler,
    SecretAnalysisTaskHandler,
)
from aegis.schemas.dependencies import (
    DependencyPackage,
    DependencyScanResponse,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
    SecurityTaskPlanRequest,
)
from aegis.security.secrets import (
    SecretIntelligenceEngine,
)


class RecordingDependencyScanner:
    name = "recording-osv"

    def __init__(self) -> None:
        self.calls: list[
            list[DependencyPackage]
        ] = []

    async def scan(
        self,
        packages: list[DependencyPackage],
    ) -> DependencyScanResponse:
        self.calls.append(
            list(packages)
        )

        return DependencyScanResponse(
            scanner=self.name,
            packages_scanned=len(packages),
            successful_packages=len(packages),
            failed_packages=0,
            scan_status="completed",
            errors=[],
            vulnerable_packages=0,
            vulnerabilities=[],
        )


def run(coro):
    return asyncio.run(coro)


def task(
    kind: str,
    artifact: str,
) -> SecurityTaskNode:
    return SecurityTaskNode(
        task_id=kind,
        kind=kind,
        state="ready",
        produces=[artifact],
    )


def context(
    files: list[dict[str, str]],
    *,
    operation: str = "repository_review",
    repository_root: str = "/tmp",
    execution_id: str = "execution:test",
) -> SecurityTaskHandlerContext:
    return SecurityTaskHandlerContext(
        execution_id=execution_id,
        operation=operation,
        language="python",
        repository_root=repository_root,
        metadata={
            "repository_files": files,
        },
    )


def repository_input() -> dict[
    str,
    dict[str, str],
]:
    return {
        "repository_context": {
            "project_id": "project:test",
            "revision": "revision:test",
        },
    }


def test_secret_handler_redacts_raw_credentials() -> None:
    raw_secret = (
        "sk-abcdefghijklmnopqrstuvwxyz123456"
    )
    handler = SecretAnalysisTaskHandler(
        secret_engine=SecretIntelligenceEngine(
            fingerprint_key="k" * 32,
        ),
    )

    result = run(
        handler.execute(
            task=task(
                "secret_analysis",
                "secret_findings",
            ),
            context=context([
                {
                    "filename": ".env",
                    "language": "dotenv",
                    "code": (
                        f'API_KEY="{raw_secret}"'
                    ),
                }
            ]),
            inputs=repository_input(),
        )
    )

    findings = result.output[
        "secret_findings"
    ]

    assert len(findings) == 1
    assert findings[0]["secret"] is not None
    assert (
        findings[0]["secret"]["fingerprint"]
        is not None
    )
    assert raw_secret not in json.dumps(
        findings
    )
    assert "AEGIS_REDACTED" in (
        findings[0]["code"]
    )
    assert result.metadata[
        "raw_secret_values_persisted"
    ] is False


def test_dependency_handler_parses_exact_versions() -> None:
    scanner = RecordingDependencyScanner()
    handler = DependencyScanTaskHandler(
        scanner=scanner,
    )

    result = run(
        handler.execute(
            task=task(
                "dependency_scan",
                "dependency_findings",
            ),
            context=context([
                {
                    "filename": (
                        "requirements.txt"
                    ),
                    "language": "text",
                    "code": (
                        "requests==2.32.4\n"
                        "urllib3>=2.2\n"
                    ),
                }
            ]),
            inputs=repository_input(),
        )
    )

    assert len(scanner.calls) == 1
    assert [
        package.name
        for package in scanner.calls[0]
    ] == ["requests"]

    artifact = result.output[
        "dependency_findings"
    ]

    assert artifact["packages"][0][
        "manifest"
    ] == "requirements.txt"
    assert artifact["scan"][
        "scan_status"
    ] == "completed"
    assert result.metadata[
        "coverage_complete"
    ] is True


def test_dependency_handler_never_reports_missing_coverage_clean() -> None:
    scanner = RecordingDependencyScanner()
    handler = DependencyScanTaskHandler(
        scanner=scanner,
    )

    result = run(
        handler.execute(
            task=task(
                "dependency_scan",
                "dependency_findings",
            ),
            context=context([
                {
                    "filename": "app.py",
                    "language": "python",
                    "code": "print('hello')",
                }
            ]),
            inputs=repository_input(),
        )
    )

    scan = result.output[
        "dependency_findings"
    ]["scan"]

    assert scanner.calls == []
    assert scan["scan_status"] == "partial"
    assert scan["errors"]
    assert result.metadata[
        "coverage_complete"
    ] is False


def test_attack_surface_handler_produces_graph() -> None:
    handler = AttackSurfaceTaskHandler()

    result = run(
        handler.execute(
            task=task(
                "attack_surface",
                "attack_surface_graph",
            ),
            context=context([
                {
                    "filename": "api.py",
                    "language": "python",
                    "code": (
                        "from fastapi import FastAPI\n"
                        "import subprocess\n"
                        "app = FastAPI()\n"
                        '@app.get("/run/{name}")\n'
                        "def run(name: str):\n"
                        "    return subprocess.run("
                        "[name])\n"
                    ),
                }
            ]),
            inputs=repository_input(),
        )
    )

    graph = result.output[
        "attack_surface_graph"
    ]
    kinds = {
        node["kind"]
        for node in graph["nodes"]
    }

    assert "http_route" in kinds
    assert "process_execution" in kinds
    assert graph["summary"][
        "files_scanned"
    ] == 1
    assert result.metadata[
        "nodes_found"
    ] >= 2


def test_specialist_branches_preserve_artifact_provenance(
    tmp_path: Path,
) -> None:
    dependency_scanner = (
        RecordingDependencyScanner()
    )
    registry = (
        SecurityTaskHandlerRegistry()
    )
    registry.register(
        RepositoryContextTaskHandler()
    )
    registry.register(
        SecretAnalysisTaskHandler(
            secret_engine=(
                SecretIntelligenceEngine(
                    fingerprint_key="k" * 32,
                )
            ),
        )
    )
    registry.register(
        DependencyScanTaskHandler(
            scanner=dependency_scanner,
        )
    )
    registry.register(
        AttackSurfaceTaskHandler()
    )
    registry.freeze()

    plan = SecurityTaskPlanner().plan(
        SecurityTaskPlanRequest(
            operation="repository_review",
            include_security_memory=False,
            include_policy_evaluation=False,
        )
    )
    machine = SecurityTaskExecutionMachine(
        id_factory=lambda: (
            "execution:specialist-branches"
        ),
    )
    execution = machine.create(plan)
    executor = SecurityTaskExecutor(
        registry=registry,
        machine=machine,
    )
    store = SecurityTaskArtifactStore()
    handler_context = context(
        [
            {
                "filename": ".env",
                "language": "dotenv",
                "code": (
                    'API_KEY="sk-'
                    'abcdefghijklmnopqrstuvwxyz123456"'
                ),
            },
            {
                "filename": (
                    "requirements.txt"
                ),
                "language": "text",
                "code": "requests==2.32.4",
            },
            {
                "filename": "api.py",
                "language": "python",
                "code": (
                    "from fastapi import FastAPI\n"
                    "app = FastAPI()\n"
                    '@app.get("/health")\n'
                    "def health():\n"
                    "    return {'ok': True}\n"
                ),
            },
        ],
        repository_root=str(tmp_path),
        execution_id=execution.execution_id,
    )

    for task_id in (
        "repository_context",
        "secret_analysis",
        "dependency_scan",
        "attack_surface",
    ):
        step = run(
            executor.execute_task(
                execution=execution,
                task_id=task_id,
                context=handler_context,
                artifact_store=store,
            )
        )

        assert step.success is True
        execution = step.execution

    assert store.artifact(
        "secret_findings"
    ).producer_task_id == "secret_analysis"
    assert store.artifact(
        "dependency_findings"
    ).producer_task_id == "dependency_scan"
    assert store.artifact(
        "attack_surface_graph"
    ).producer_task_id == "attack_surface"

    threat_model = next(
        planned_task
        for planned_task in execution.plan.tasks
        if planned_task.task_id
        == "threat_model"
    )

    assert threat_model.state == "ready"
