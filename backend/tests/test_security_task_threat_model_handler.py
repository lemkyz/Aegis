from __future__ import annotations

import asyncio

import pytest

from aegis.orchestrator.security_task_handler import (
    SecurityTaskHandlerContext,
)
from aegis.orchestrator.security_task_handlers import (
    SecurityTaskInputError,
)
from aegis.orchestrator.security_task_threat_model_handler import (
    ThreatModelTaskHandler,
)
from aegis.schemas.analysis import (
    ScannerEvidence,
    SecretClassification,
)
from aegis.schemas.attack_surface import (
    AttackSurfaceFile,
)
from aegis.schemas.dependencies import (
    DependencyManifestScanResponse,
    DependencyPackage,
    DependencyScanResponse,
    DependencyVulnerability,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
)
from aegis.schemas.threat_model import (
    ThreatModelScanResponse,
)
from aegis.security.attack_surface import (
    AttackSurfaceMapper,
)
from aegis.security.threat_model import ThreatModeler


class ExplodingMapper:
    def scan(self, files):
        del files
        raise AssertionError(
            "attack surface was rescanned"
        )


def run(coro):
    return asyncio.run(coro)


def threat_task() -> SecurityTaskNode:
    return SecurityTaskNode(
        task_id="threat_model",
        kind="threat_model",
        state="ready",
        produces=["threat_model"],
    )


def repository_files() -> list[
    dict[str, str],
]:
    return [
        {
            "filename": ".env",
            "language": "dotenv",
            "code": (
                'API_KEY="'
                '<AEGIS_REDACTED_SECRET_1>"'
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
                "import os\n"
                "def run(command: str):\n"
                "    return os.system(command)\n"
            ),
        },
    ]


def context(
    *,
    operation: str = "repository_review",
) -> SecurityTaskHandlerContext:
    return SecurityTaskHandlerContext(
        execution_id="execution:threat-model",
        operation=operation,
        language="python",
        repository_root="/tmp",
        metadata={
            "repository_files": (
                repository_files()
            ),
        },
    )


def attack_files() -> list[
    AttackSurfaceFile
]:
    return [
        AttackSurfaceFile(
            filename=file["filename"],
            language=file["language"],
            code=file["code"],
        )
        for file in repository_files()
    ]


def secret_findings() -> list[dict]:
    evidence = ScannerEvidence(
        tool="config-secret-scanner",
        rule_id=(
            "aegis.config.hardcoded-secret"
        ),
        message=(
            "A credential appears to be "
            "embedded in configuration."
        ),
        severity="critical",
        file=".env",
        line_start=1,
        line_end=1,
        code=(
            'API_KEY="'
            '<AEGIS_REDACTED_SECRET_1>"'
        ),
        secret=SecretClassification(
            provider="openai",
            secret_type="api_key",
            confidence=0.97,
            likely_placeholder=False,
            rotation_required=True,
            fingerprint="fingerprint:test",
            entropy=4.2,
            remediation=(
                "Rotate the credential and use "
                "a secret manager."
            ),
        ),
    )

    return [
        evidence.model_dump(mode="json")
    ]


def dependency_findings(
    *,
    scan_status: str = "completed",
    with_vulnerability: bool = True,
) -> dict:
    package = DependencyPackage(
        name="requests",
        version="2.32.4",
        ecosystem="PyPI",
        manifest="requirements.txt",
        direct=True,
    )
    vulnerabilities = (
        [
            DependencyVulnerability(
                id="GHSA-test-1234",
                aliases=["CVE-2099-0001"],
                package_name=package.name,
                installed_version=(
                    package.version
                ),
                ecosystem=package.ecosystem,
                manifest=package.manifest,
                direct=package.direct,
                summary=(
                    "Test dependency "
                    "vulnerability."
                ),
                details=(
                    "A test advisory affects "
                    "the resolved package."
                ),
                severity="high",
                fixed_versions=["2.32.5"],
            )
        ]
        if with_vulnerability
        else []
    )
    scan = DependencyScanResponse(
        scanner="fake-osv",
        packages_scanned=1,
        successful_packages=(
            1
            if scan_status == "completed"
            else 0
        ),
        failed_packages=(
            0
            if scan_status == "completed"
            else 1
        ),
        scan_status=scan_status,
        errors=(
            []
            if scan_status == "completed"
            else ["OSV coverage unavailable."]
        ),
        vulnerable_packages=(
            1
            if vulnerabilities
            else 0
        ),
        vulnerabilities=vulnerabilities,
    )

    return (
        DependencyManifestScanResponse(
            packages=[package],
            scan=scan,
        )
        .model_dump(mode="json")
    )


def repository_inputs(
    *,
    dependency_status: str = "completed",
    with_vulnerability: bool = True,
) -> dict:
    graph = AttackSurfaceMapper().scan(
        attack_files()
    )

    return {
        "secret_findings": (
            secret_findings()
        ),
        "dependency_findings": (
            dependency_findings(
                scan_status=dependency_status,
                with_vulnerability=(
                    with_vulnerability
                ),
            )
        ),
        "attack_surface_graph": (
            graph.model_dump(mode="json")
        ),
    }


def test_modeler_composes_precomputed_attack_surface() -> None:
    files = attack_files()
    graph = AttackSurfaceMapper().scan(files)
    modeler = ThreatModeler(
        mapper=ExplodingMapper(),
    )

    result = modeler.compose(
        files=files,
        attack_surface=graph,
    )

    assert result.attack_surface_nodes == (
        graph.nodes
    )
    assert result.attack_surface_edges == (
        graph.edges
    )
    assert result.threats


def test_handler_composes_all_specialist_evidence() -> None:
    handler = ThreatModelTaskHandler()

    result = run(
        handler.execute(
            task=threat_task(),
            context=context(),
            inputs=repository_inputs(),
        )
    )

    model = ThreatModelScanResponse.model_validate(
        result.output["threat_model"]
    )
    categories = {
        threat.category
        for threat in model.threats
    }

    assert "command_injection" in categories
    assert "secret_exposure" in categories
    assert (
        "vulnerable_dependency"
        in categories
    )
    assert model.evidence_summary is not None
    assert (
        model.evidence_summary
        .source_artifacts
    ) == [
        "secret_findings",
        "dependency_findings",
        "attack_surface_graph",
    ]
    assert (
        model.evidence_summary
        .secret_findings
    ) == 1
    assert (
        model.evidence_summary
        .dependency_vulnerabilities
    ) == 1
    assert model.summary.threats_found == len(
        model.threats
    )


def test_partial_dependency_coverage_is_preserved() -> None:
    handler = ThreatModelTaskHandler()

    result = run(
        handler.execute(
            task=threat_task(),
            context=context(),
            inputs=repository_inputs(
                dependency_status="failed",
                with_vulnerability=False,
            ),
        )
    )
    model = ThreatModelScanResponse.model_validate(
        result.output["threat_model"]
    )

    assert model.evidence_summary is not None
    assert (
        model.evidence_summary
        .dependency_scan_status
    ) == "failed"
    assert (
        model.evidence_summary
        .dependency_coverage_complete
    ) is False
    assert result.metadata[
        "dependency_coverage_complete"
    ] is False
    assert any(
        "incomplete" in reason.lower()
        for reason in result.reasons
    )


def test_repository_handler_fails_closed_without_artifacts() -> None:
    handler = ThreatModelTaskHandler()

    with pytest.raises(
        SecurityTaskInputError,
        match="secret_findings",
    ):
        run(
            handler.execute(
                task=threat_task(),
                context=context(),
                inputs={},
            )
        )


def test_deep_analysis_uses_consensus_contract() -> None:
    handler = ThreatModelTaskHandler()

    result = run(
        handler.execute(
            task=threat_task(),
            context=context(
                operation="deep_analysis"
            ),
            inputs={
                "consensus_decisions": {
                    "primary_model": (
                        "primary/test"
                    ),
                    "verifier_model": (
                        "verifier/test"
                    ),
                    "status": "completed",
                    "decisions": [],
                },
            },
        )
    )
    model = ThreatModelScanResponse.model_validate(
        result.output["threat_model"]
    )

    assert model.evidence_summary is not None
    assert (
        model.evidence_summary
        .source_artifacts
    ) == ["consensus_decisions"]
    assert (
        model.evidence_summary
        .dependency_coverage_complete
    ) is False
    assert model.threats
