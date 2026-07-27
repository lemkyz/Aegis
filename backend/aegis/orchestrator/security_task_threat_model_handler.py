from __future__ import annotations

import hashlib
from typing import Any, Mapping

from pydantic import ValidationError

from aegis.orchestrator.security_task_handler import (
    SecurityTaskHandlerCapability,
    SecurityTaskHandlerContext,
    SecurityTaskHandlerResult,
)
from aegis.orchestrator.security_task_handlers import (
    SecurityTaskInputError,
)
from aegis.orchestrator.security_task_specialist_handlers import (
    RepositorySourceInput,
)
from aegis.schemas.analysis import ScannerEvidence
from aegis.schemas.attack_surface import (
    AttackSurfaceFile,
    AttackSurfaceScanResponse,
)
from aegis.schemas.dependencies import (
    DependencyManifestScanResponse,
    DependencyVulnerability,
)
from aegis.schemas.model_consensus import (
    ModelConsensusResult,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
)
from aegis.schemas.threat_model import (
    ThreatAsset,
    ThreatFinding,
    ThreatModelEvidenceSummary,
    ThreatModelScanResponse,
    ThreatModelSummary,
    TrustBoundary,
)
from aegis.security.threat_model import ThreatModeler


class ThreatModelTaskHandler:
    capability = SecurityTaskHandlerCapability(
        kind="threat_model",
        optional_artifacts=frozenset({
            "secret_findings",
            "dependency_findings",
            "attack_surface_graph",
            "consensus_decisions",
        }),
        produced_artifacts=frozenset({
            "threat_model",
        }),
        supports_retry=False,
        max_attempts=1,
        side_effect_free=True,
    )

    def __init__(
        self,
        *,
        modeler: ThreatModeler
        | None = None,
    ) -> None:
        self._modeler = (
            modeler
            or ThreatModeler()
        )

    async def execute(
        self,
        *,
        task: SecurityTaskNode,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> SecurityTaskHandlerResult:
        del task

        context.raise_if_cancelled()

        source_files = (
            RepositorySourceInput.from_context(
                context
            )
        )
        attack_files = [
            AttackSurfaceFile(
                filename=source.filename,
                language=source.language,
                code=source.code,
            )
            for source in source_files
        ]

        if context.operation == "repository_review":
            (
                threat_model,
                reasons,
            ) = self._repository_model(
                inputs=inputs,
                attack_files=attack_files,
            )
        elif context.operation == "deep_analysis":
            (
                threat_model,
                reasons,
            ) = self._deep_analysis_model(
                inputs=inputs,
                attack_files=attack_files,
            )
        else:
            raise SecurityTaskInputError(
                "Threat modeling supports "
                "repository_review and "
                "deep_analysis operations."
            )

        evidence_summary = (
            threat_model.evidence_summary
        )

        if evidence_summary is None:
            raise SecurityTaskInputError(
                "Composed threat model is missing "
                "its evidence summary."
            )

        return SecurityTaskHandlerResult(
            output={
                "threat_model": (
                    threat_model.model_dump(
                        mode="json"
                    )
                ),
            },
            metadata={
                "modeler": threat_model.modeler,
                "secret_findings": (
                    evidence_summary
                    .secret_findings
                ),
                "dependency_vulnerabilities": (
                    evidence_summary
                    .dependency_vulnerabilities
                ),
                "dependency_scan_status": (
                    evidence_summary
                    .dependency_scan_status
                ),
                "dependency_coverage_complete": (
                    evidence_summary
                    .dependency_coverage_complete
                ),
                "attack_surface_nodes": len(
                    threat_model
                    .attack_surface_nodes
                ),
                "attack_surface_edges": len(
                    threat_model
                    .attack_surface_edges
                ),
                "threats_found": len(
                    threat_model.threats
                ),
            },
            reasons=tuple(reasons),
        )

    def _repository_model(
        self,
        *,
        inputs: Mapping[str, Any],
        attack_files: list[
            AttackSurfaceFile
        ],
    ) -> tuple[
        ThreatModelScanResponse,
        list[str],
    ]:
        secret_findings = (
            self._secret_findings(inputs)
        )
        dependency_findings = (
            self._dependency_findings(inputs)
        )
        attack_surface = (
            self._attack_surface(inputs)
        )

        base_model = self._modeler.compose(
            files=attack_files,
            attack_surface=attack_surface,
        )
        threat_model = self._compose(
            base_model=base_model,
            secret_findings=secret_findings,
            dependency_findings=(
                dependency_findings
            ),
            attack_surface=attack_surface,
        )

        reasons = [
            (
                "Threat modeling reused the "
                "upstream attack-surface artifact "
                "without rescanning source files."
            ),
            (
                "Redacted secret evidence and "
                "dependency vulnerability evidence "
                "were composed into the model."
            ),
        ]

        if (
            dependency_findings
            .scan.scan_status
            != "completed"
        ):
            reasons.append(
                "Dependency coverage is incomplete; "
                "the threat model must not be "
                "interpreted as dependency-clean."
            )

        return threat_model, reasons

    def _deep_analysis_model(
        self,
        *,
        inputs: Mapping[str, Any],
        attack_files: list[
            AttackSurfaceFile
        ],
    ) -> tuple[
        ThreatModelScanResponse,
        list[str],
    ]:
        consensus_value = inputs.get(
            "consensus_decisions"
        )

        if not isinstance(
            consensus_value,
            Mapping,
        ):
            raise SecurityTaskInputError(
                "Deep-analysis threat modeling "
                "requires a consensus_decisions "
                "artifact."
            )

        try:
            consensus = (
                ModelConsensusResult
                .model_validate(
                    consensus_value
                )
            )
        except ValidationError as exc:
            raise SecurityTaskInputError(
                "Deep-analysis threat modeling "
                "received an invalid "
                "consensus_decisions artifact."
            ) from exc

        threat_model = self._modeler.scan(
            attack_files
        )
        evidence_summary = (
            ThreatModelEvidenceSummary(
                source_artifacts=[
                    "consensus_decisions",
                ],
                secret_findings=0,
                dependency_vulnerabilities=0,
                dependency_scan_status="partial",
                dependency_coverage_complete=False,
                attack_surface_nodes=len(
                    threat_model
                    .attack_surface_nodes
                ),
                attack_surface_edges=len(
                    threat_model
                    .attack_surface_edges
                ),
            )
        )
        threat_model = (
            threat_model.model_copy(
                deep=True,
                update={
                    "evidence_summary": (
                        evidence_summary
                    ),
                },
            )
        )

        return threat_model, [
            (
                "Deep-analysis threat modeling "
                "was gated by a "
                f"{consensus.status} "
                "model-consensus artifact and used "
                "deterministic source mapping."
            ),
            (
                "Repository dependency coverage "
                "was not part of this operation and "
                "remains explicitly incomplete."
            ),
        ]

    @staticmethod
    def _secret_findings(
        inputs: Mapping[str, Any],
    ) -> list[ScannerEvidence]:
        value = inputs.get(
            "secret_findings"
        )

        if not isinstance(value, list):
            raise SecurityTaskInputError(
                "Threat modeling requires a "
                "secret_findings list artifact."
            )

        return [
            ScannerEvidence.model_validate(
                finding
            )
            for finding in value
        ]

    @staticmethod
    def _dependency_findings(
        inputs: Mapping[str, Any],
    ) -> DependencyManifestScanResponse:
        value = inputs.get(
            "dependency_findings"
        )

        if not isinstance(value, Mapping):
            raise SecurityTaskInputError(
                "Threat modeling requires a "
                "dependency_findings artifact."
            )

        return (
            DependencyManifestScanResponse
            .model_validate(value)
        )

    @staticmethod
    def _attack_surface(
        inputs: Mapping[str, Any],
    ) -> AttackSurfaceScanResponse:
        value = inputs.get(
            "attack_surface_graph"
        )

        if not isinstance(value, Mapping):
            raise SecurityTaskInputError(
                "Threat modeling requires an "
                "attack_surface_graph artifact."
            )

        return (
            AttackSurfaceScanResponse
            .model_validate(value)
        )

    def _compose(
        self,
        *,
        base_model: ThreatModelScanResponse,
        secret_findings: list[
            ScannerEvidence
        ],
        dependency_findings: (
            DependencyManifestScanResponse
        ),
        attack_surface: (
            AttackSurfaceScanResponse
        ),
    ) -> ThreatModelScanResponse:
        assets = list(base_model.assets)
        trust_boundaries = list(
            base_model.trust_boundaries
        )
        threats = list(base_model.threats)

        for finding in secret_findings:
            asset, boundary, threat = (
                self._secret_components(
                    finding
                )
            )
            assets.append(asset)
            trust_boundaries.append(boundary)
            threats.append(threat)

        for vulnerability in (
            dependency_findings
            .scan.vulnerabilities
        ):
            asset, boundary, threat = (
                self._dependency_components(
                    vulnerability
                )
            )
            assets.append(asset)
            trust_boundaries.append(boundary)
            threats.append(threat)

        assets = self._deduplicate(
            assets
        )
        trust_boundaries = self._deduplicate(
            trust_boundaries
        )
        threats = self._deduplicate(
            threats
        )
        threats.sort(
            key=lambda threat: (
                self._severity_rank(
                    threat.severity
                ),
                threat.file,
                threat.line,
                threat.category,
                threat.id,
            )
        )

        summary = ThreatModelSummary(
            files_scanned=(
                base_model.summary.files_scanned
            ),
            assets_found=len(assets),
            trust_boundaries_found=len(
                trust_boundaries
            ),
            threats_found=len(threats),
            critical=self._count_severity(
                threats,
                "critical",
            ),
            high=self._count_severity(
                threats,
                "high",
            ),
            medium=self._count_severity(
                threats,
                "medium",
            ),
            low=self._count_severity(
                threats,
                "low",
            ),
            info=self._count_severity(
                threats,
                "info",
            ),
        )

        dependency_scan = (
            dependency_findings.scan
        )

        evidence_summary = (
            ThreatModelEvidenceSummary(
                source_artifacts=[
                    "secret_findings",
                    "dependency_findings",
                    "attack_surface_graph",
                ],
                secret_findings=len(
                    secret_findings
                ),
                dependency_vulnerabilities=len(
                    dependency_scan
                    .vulnerabilities
                ),
                dependency_scan_status=(
                    dependency_scan.scan_status
                ),
                dependency_coverage_complete=(
                    dependency_scan.scan_status
                    == "completed"
                ),
                attack_surface_nodes=len(
                    attack_surface.nodes
                ),
                attack_surface_edges=len(
                    attack_surface.edges
                ),
            )
        )

        return base_model.model_copy(
            deep=True,
            update={
                "assets": assets,
                "trust_boundaries": (
                    trust_boundaries
                ),
                "threats": threats,
                "summary": summary,
                "evidence_summary": (
                    evidence_summary
                ),
            },
        )

    def _secret_components(
        self,
        finding: ScannerEvidence,
    ) -> tuple[
        ThreatAsset,
        TrustBoundary,
        ThreatFinding,
    ]:
        identity = self._stable_id(
            finding.rule_id,
            finding.file,
            str(finding.line_start),
            str(finding.line_end),
        )
        asset_id = self._stable_id(
            "asset",
            "secret",
            identity,
        )
        boundary_id = self._stable_id(
            "boundary",
            "secret",
            identity,
        )

        classification = finding.secret
        likely_placeholder = bool(
            classification
            and classification.likely_placeholder
        )
        severity = (
            "low"
            if likely_placeholder
            else self._threat_severity(
                finding.severity
            )
        )
        confidence = (
            classification.confidence
            if classification is not None
            else 0.85
        )
        remediation = (
            classification.remediation
            if classification is not None
            else (
                "Remove the embedded credential, "
                "rotate it, and load the replacement "
                "from a dedicated secret manager."
            )
        )

        asset = ThreatAsset(
            id=asset_id,
            name="Embedded application secret",
            kind="secret_store",
            file=finding.file,
            line=finding.line_start,
            description=(
                "Credential material detected in "
                "repository configuration."
            ),
            source_node_ids=[],
        )
        boundary = TrustBoundary(
            id=boundary_id,
            label="Embedded secret boundary",
            file=finding.file,
            line=finding.line_start,
            boundary_type=(
                "sensitive_configuration"
            ),
            evidence=finding.message,
            source_node_ids=[],
        )

        evidence = [finding.message]

        if finding.code:
            evidence.append(finding.code)

        threat = ThreatFinding(
            id=self._stable_id(
                "threat",
                "secret",
                identity,
            ),
            title=(
                "Credential material is embedded "
                "in repository source"
            ),
            category="secret_exposure",
            severity=severity,
            confidence=confidence,
            file=finding.file,
            line=finding.line_start,
            entry_point=None,
            affected_asset=asset.name,
            trust_boundary=boundary.label,
            description=(
                "A credential-like value was "
                "detected in a repository file and "
                "could be exposed through source "
                "history, builds, logs, or artifacts."
            ),
            attack_path=[
                (
                    "Credential material is stored "
                    "in repository source"
                ),
                (
                    "An unauthorized actor obtains "
                    "the source or a derived artifact"
                ),
                (
                    "The credential is used against "
                    "its associated service"
                ),
            ],
            mitigations=[remediation],
            evidence=evidence,
            source_node_ids=[],
            data_flow=[],
            exploitability=(
                "unlikely"
                if likely_placeholder
                else "confirmed"
            ),
            exploitability_confidence=(
                max(confidence, 0.80)
            ),
            exploitability_reasons=[
                (
                    "The value appears to be "
                    "placeholder or test data."
                    if likely_placeholder
                    else (
                        "A deterministic secret "
                        "scanner identified embedded "
                        "credential material."
                    )
                )
            ],
            prerequisites=[
                (
                    "Access to repository source, "
                    "history, build output, or logs."
                )
            ],
            blocking_controls=[],
        )

        return asset, boundary, threat

    def _dependency_components(
        self,
        vulnerability: (
            DependencyVulnerability
        ),
    ) -> tuple[
        ThreatAsset,
        TrustBoundary,
        ThreatFinding,
    ]:
        package_identity = self._stable_id(
            vulnerability.ecosystem,
            vulnerability.package_name.lower(),
            vulnerability.installed_version,
            vulnerability.manifest,
        )
        asset_id = self._stable_id(
            "asset",
            "dependency",
            package_identity,
        )
        boundary_id = self._stable_id(
            "boundary",
            "dependency",
            package_identity,
        )
        threat_id = self._stable_id(
            "threat",
            "dependency",
            vulnerability.id,
            package_identity,
        )
        severity = self._threat_severity(
            vulnerability.severity
        )
        affected_asset = (
            f"{vulnerability.ecosystem} package "
            f"{vulnerability.package_name}@"
            f"{vulnerability.installed_version}"
        )

        fixed_versions = (
            vulnerability.fixed_versions
        )
        mitigation = (
            "Upgrade to a fixed version: "
            + ", ".join(fixed_versions)
            + "."
            if fixed_versions
            else (
                "Review the advisory, constrain "
                "exposure, and replace or patch the "
                "dependency when a fix is available."
            )
        )

        asset = ThreatAsset(
            id=asset_id,
            name=affected_asset,
            kind="third_party_dependency",
            file=vulnerability.manifest,
            line=1,
            description=(
                "Third-party package included by "
                "the repository dependency graph."
            ),
            source_node_ids=[],
        )
        boundary = TrustBoundary(
            id=boundary_id,
            label=(
                "Third-party dependency boundary"
            ),
            file=vulnerability.manifest,
            line=1,
            boundary_type=(
                "software_supply_chain"
            ),
            evidence=(
                f"{vulnerability.id}: "
                f"{vulnerability.summary}"
            ),
            source_node_ids=[],
        )

        evidence = [
            (
                f"{vulnerability.id}: "
                f"{vulnerability.summary}"
            )
        ]

        if vulnerability.aliases:
            evidence.append(
                "Aliases: "
                + ", ".join(
                    vulnerability.aliases
                )
            )

        threat = ThreatFinding(
            id=threat_id,
            title=(
                "Known vulnerability affects "
                f"{vulnerability.package_name}"
            ),
            category="vulnerable_dependency",
            severity=severity,
            confidence=self._dependency_confidence(
                vulnerability.severity
            ),
            file=vulnerability.manifest,
            line=1,
            entry_point=None,
            affected_asset=affected_asset,
            trust_boundary=boundary.label,
            description=(
                vulnerability.details
                or vulnerability.summary
            ),
            attack_path=[
                (
                    "The repository resolves the "
                    "affected package version"
                ),
                (
                    "Application behavior reaches "
                    "the vulnerable package surface"
                ),
                (
                    "An attacker satisfies advisory "
                    "exploit prerequisites"
                ),
            ],
            mitigations=[mitigation],
            evidence=evidence,
            source_node_ids=[],
            data_flow=[],
            exploitability=(
                "likely"
                if (
                    vulnerability.direct
                    and severity
                    in {"critical", "high"}
                )
                else "possible"
            ),
            exploitability_confidence=(
                0.75
                if vulnerability.direct
                else 0.60
            ),
            exploitability_reasons=[
                (
                    "The affected package is a "
                    "direct dependency."
                    if vulnerability.direct
                    else (
                        "The affected package is "
                        "transitive; runtime reachability "
                        "still requires verification."
                    )
                )
            ],
            prerequisites=[
                (
                    "The application invokes the "
                    "vulnerable package behavior."
                )
            ],
            blocking_controls=[],
        )

        return asset, boundary, threat

    @staticmethod
    def _stable_id(
        *parts: str,
    ) -> str:
        value = "::".join(parts).encode(
            "utf-8"
        )

        return hashlib.sha256(
            value
        ).hexdigest()[:20]

    @staticmethod
    def _threat_severity(
        severity: str,
    ) -> str:
        normalized = severity.strip().lower()

        if normalized in {
            "critical",
            "high",
            "medium",
            "low",
            "info",
        }:
            return normalized

        if normalized in {
            "error",
            "warning",
        }:
            return {
                "error": "high",
                "warning": "medium",
            }[normalized]

        return "info"

    @staticmethod
    def _dependency_confidence(
        severity: str,
    ) -> float:
        return {
            "critical": 0.95,
            "high": 0.90,
            "medium": 0.82,
            "low": 0.72,
            "unknown": 0.55,
        }.get(
            severity.strip().lower(),
            0.55,
        )

    @staticmethod
    def _count_severity(
        threats: list[ThreatFinding],
        severity: str,
    ) -> int:
        return sum(
            threat.severity == severity
            for threat in threats
        )

    @staticmethod
    def _severity_rank(
        severity: str,
    ) -> int:
        return {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }.get(severity, 5)

    @staticmethod
    def _deduplicate(
        values: list[Any],
    ) -> list[Any]:
        unique = {
            value.id: value
            for value in values
        }

        return list(unique.values())
