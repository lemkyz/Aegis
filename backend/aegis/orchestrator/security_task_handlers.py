from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from aegis.orchestrator.security_task_handler import (
    SecurityTaskHandlerCapability,
    SecurityTaskHandlerContext,
    SecurityTaskHandlerContractError,
    SecurityTaskHandlerRegistry,
    SecurityTaskHandlerResult,
)
from aegis.schemas.analysis import (
    ScannerEvidence,
    ScannerCoverage,
    SecurityFinding,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
)
from aegis.security.bandit import BanditScanner
from aegis.security.config_secrets import (
    ConfigSecretScanner,
)
from aegis.security.eslint import EslintSecurityScanner
from aegis.security.orchestrator import (
    ScannerOrchestrationResult,
    SecurityScannerOrchestrator,
)
from aegis.security.project_identity import (
    ProjectIdentityResolver,
)
from aegis.security.redaction import SecretRedactor
from aegis.security.secrets import (
    SecretIntelligenceEngine,
)
from aegis.security.semgrep import SemgrepScanner


class SecurityTaskInputError(
    SecurityTaskHandlerContractError
):
    pass


@dataclass(frozen=True, slots=True)
class DeterministicScanInput:
    code: str
    filename: str
    language: str

    @classmethod
    def from_context(
        cls,
        context: SecurityTaskHandlerContext,
    ) -> "DeterministicScanInput":
        code = context.metadata.get(
            "source_code"
        )
        filename = context.metadata.get(
            "filename"
        )

        if not isinstance(code, str):
            raise SecurityTaskInputError(
                "Deterministic scan requires "
                "context.metadata['source_code']."
            )

        if not code.strip():
            raise SecurityTaskInputError(
                "Deterministic scan source code "
                "must not be empty."
            )

        if not isinstance(filename, str):
            raise SecurityTaskInputError(
                "Deterministic scan requires "
                "context.metadata['filename']."
            )

        normalized_filename = filename.strip()

        if not normalized_filename:
            raise SecurityTaskInputError(
                "Deterministic scan filename must "
                "not be empty."
            )

        normalized_language = (
            context.language.strip().lower()
        )

        if not normalized_language:
            raise SecurityTaskInputError(
                "Deterministic scan language must "
                "not be empty."
            )

        return cls(
            code=code,
            filename=normalized_filename,
            language=normalized_language,
        )


class RepositoryContextTaskHandler:
    capability = SecurityTaskHandlerCapability(
        kind="repository_context",
        produced_artifacts=frozenset({
            "repository_context",
        }),
        supports_retry=False,
        max_attempts=1,
        side_effect_free=True,
    )

    def __init__(
        self,
        *,
        resolver: ProjectIdentityResolver
        | None = None,
    ) -> None:
        self._resolver = (
            resolver
            or ProjectIdentityResolver()
        )

    async def execute(
        self,
        *,
        task: SecurityTaskNode,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> SecurityTaskHandlerResult:
        del task
        del inputs

        context.raise_if_cancelled()

        repository_root = (
            context.repository_root
        )

        if repository_root is None:
            raise SecurityTaskInputError(
                "Repository context collection "
                "requires repository_root."
            )

        normalized_root = (
            repository_root.strip()
        )

        if not normalized_root:
            raise SecurityTaskInputError(
                "Repository root must not be empty."
            )

        repository = self._resolver.resolve(
            Path(normalized_root)
        )

        context.raise_if_cancelled()

        return SecurityTaskHandlerResult(
            output={
                "repository_context": (
                    repository.model_dump(
                        mode="json"
                    )
                ),
            },
            metadata={
                "resolver": self._resolver.name,
                "identity_source": (
                    repository.identity_source
                ),
                "dirty": repository.dirty,
            },
            reasons=(
                "Repository identity and revision "
                "were resolved without shell "
                "command interpolation.",
            ),
        )


class DeterministicScanTaskHandler:
    capability = SecurityTaskHandlerCapability(
        kind="deterministic_scan",
        required_artifacts=frozenset({
            "repository_context",
        }),
        produced_artifacts=frozenset({
            "scanner_coverage",
            "scanner_evidence",
            "scanner_findings",
        }),
        supports_retry=True,
        max_attempts=2,
        side_effect_free=True,
    )

    def __init__(
        self,
        *,
        scanner_orchestrator: (
            SecurityScannerOrchestrator
            | None
        ) = None,
        config_scanner: (
            ConfigSecretScanner
            | None
        ) = None,
        secret_engine: (
            SecretIntelligenceEngine
            | None
        ) = None,
        redactor: SecretRedactor
        | None = None,
    ) -> None:
        self._scanner_orchestrator = (
            scanner_orchestrator
            or SecurityScannerOrchestrator([
                SemgrepScanner(),
                BanditScanner(),
                EslintSecurityScanner(),
            ])
        )

        self._config_scanner = (
            config_scanner
            or ConfigSecretScanner()
        )

        self._secret_engine = secret_engine
        self._redactor = (
            redactor
            or SecretRedactor()
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

        scan_input = (
            DeterministicScanInput
            .from_context(context)
        )

        repository_context = inputs.get(
            "repository_context"
        )

        if not isinstance(
            repository_context,
            Mapping,
        ):
            raise SecurityTaskInputError(
                "Deterministic scan requires a "
                "repository_context artifact."
            )

        orchestration = (
            await self._scanner_orchestrator.scan(
                code=scan_input.code,
                filename=scan_input.filename,
                language=scan_input.language,
            )
        )

        context.raise_if_cancelled()

        evidence = list(
            orchestration.evidence
        )

        evidence.extend(
            self._config_scanner.scan(
                code=scan_input.code,
                filename=scan_input.filename,
                language=scan_input.language,
            )
        )

        evidence = self._deduplicate(
            evidence
        )

        if self._secret_engine is not None:
            evidence = (
                self._secret_engine
                .enrich_evidence_list(
                    evidence
                )
            )

        redaction_session = (
            self._redactor.create_session()
        )

        safe_evidence = (
            redaction_session
            .redact_evidence_list(
                evidence
            )
        )

        findings = [
            self._to_finding(item)
            for item in safe_evidence
        ]

        findings = (
            redaction_session
            .redact_findings(
                findings
            )
        )

        failed_scanners = [
            execution
            for execution
            in orchestration.executions
            if execution.status == "failed"
        ]

        completed_scanners = [
            execution
            for execution
            in orchestration.executions
            if execution.status == "completed"
        ]
        selected_scanners = [
            execution.name
            for execution
            in orchestration.executions
        ]
        completed_scanner_names = [
            execution.name
            for execution
            in completed_scanners
        ]
        config_scan_applicable = (
            self._config_scanner.supports(
                filename=scan_input.filename,
                language=scan_input.language,
            )
        )

        if config_scan_applicable:
            selected_scanners.append(
                self._config_scanner.name
            )
            completed_scanner_names.append(
                self._config_scanner.name
            )

        coverage_complete = (
            bool(completed_scanner_names)
            and not failed_scanners
        )

        if coverage_complete:
            coverage_status = "completed"
        elif selected_scanners:
            coverage_status = "partial"
        else:
            coverage_status = (
                "completed"
                if config_scan_applicable
                else "not_applicable"
            )

        coverage = ScannerCoverage(
            status=coverage_status,
            language=scan_input.language,
            selected_scanners=(
                selected_scanners
            ),
            completed_scanners=(
                completed_scanner_names
            ),
            failed_scanners=[
                execution.name
                for execution
                in failed_scanners
            ],
            configuration_scan_applicable=(
                config_scan_applicable
            ),
            coverage_complete=(
                coverage_complete
            ),
        )

        reasons = [
            (
                "Deterministic scanners completed "
                f"with {len(safe_evidence)} "
                "evidence item(s)."
            )
        ]

        if not orchestration.executions:
            reasons.append(
                "No language-specific scanner "
                "supported this input."
            )

        if config_scan_applicable:
            reasons.append(
                "Configuration secret scanning "
                "was applicable."
            )

        if failed_scanners:
            reasons.append(
                "One or more scanner failures "
                "were isolated without stopping "
                "the deterministic workflow."
            )

        return SecurityTaskHandlerResult(
            output={
                "scanner_coverage": (
                    coverage.model_dump(
                        mode="json"
                    )
                ),
                "scanner_evidence": [
                    item.model_dump(
                        mode="json"
                    )
                    for item in safe_evidence
                ],
                "scanner_findings": [
                    finding.model_dump(
                        mode="json"
                    )
                    for finding in findings
                ],
            },
            metadata={
                "filename": (
                    scan_input.filename
                ),
                "language": (
                    scan_input.language
                ),
                "selected_scanner_count": len(
                    orchestration.executions
                ),
                "completed_scanners": [
                    execution.name
                    for execution
                    in completed_scanners
                ],
                "failed_scanners": [
                    {
                        "name": execution.name,
                        "error": execution.error,
                    }
                    for execution
                    in failed_scanners
                ],
                "coverage_status": (
                    coverage.status
                ),
                "coverage_complete": (
                    coverage.coverage_complete
                ),
                "evidence_count": len(
                    safe_evidence
                ),
                "finding_count": len(
                    findings
                ),
            },
            reasons=tuple(reasons),
        )

    @staticmethod
    def _deduplicate(
        evidence: list[ScannerEvidence],
    ) -> list[ScannerEvidence]:
        unique: list[ScannerEvidence] = []
        seen: set[
            tuple[str, int, int, str]
        ] = set()

        for item in evidence:
            identity = (
                item.rule_id,
                item.line_start,
                item.line_end,
                item.code or "",
            )

            if identity in seen:
                continue

            seen.add(identity)
            unique.append(item)

        return unique

    @staticmethod
    def _to_finding(
        evidence: ScannerEvidence,
    ) -> SecurityFinding:
        severity_map = {
            "INFO": "info",
            "WARNING": "medium",
            "ERROR": "high",
            "LOW": "low",
            "MEDIUM": "medium",
            "HIGH": "high",
            "CRITICAL": "critical",
        }

        severity = severity_map.get(
            evidence.severity.upper(),
            "medium",
        )

        corroborating_tools = list(
            dict.fromkeys(
                evidence.corroborated_by
                or [evidence.tool]
            )
        )

        confidence = (
            0.95
            if len(corroborating_tools) >= 2
            else 0.85
        )

        recommended_fix = (
            "Review the flagged code and run "
            "Deep Analysis for context-aware "
            "remediation."
        )

        notes = [
            (
                "This is a deterministic "
                "scanner-only result."
            )
        ]

        if len(corroborating_tools) >= 2:
            notes.append(
                "Cross-validated by scanners: "
                + ", ".join(
                    corroborating_tools
                )
                + "."
            )

        if evidence.related_rule_ids:
            notes.append(
                "Correlated rules: "
                + ", ".join(
                    evidence.related_rule_ids
                )
                + "."
            )

        if evidence.secret is not None:
            confidence = (
                evidence.secret.confidence
            )
            recommended_fix = (
                evidence.secret.remediation
            )

            notes.append(
                "Secret classification: "
                f"{evidence.secret.provider} / "
                f"{evidence.secret.secret_type}."
            )

            if (
                evidence.secret
                .likely_placeholder
            ):
                severity = "low"
                notes.append(
                    "The value appears to be "
                    "placeholder or test data."
                )

            elif (
                evidence.secret
                .rotation_required
            ):
                notes.append(
                    "Credential rotation is "
                    "recommended."
                )

        rule_parts = (
            evidence.rule_id.split(".")
        )

        if (
            len(rule_parts) >= 3
            and rule_parts[0] == "aegis"
        ):
            rule_parts = rule_parts[2:]

        title = (
            " ".join(rule_parts)
            .replace("-", " ")
            .replace("_", " ")
            .title()
        )

        if not title.strip():
            title = "Security Scanner Finding"

        return SecurityFinding(
            title=title,
            severity=severity,
            confidence=confidence,
            summary=evidence.message,
            evidence=[
                (
                    f"{evidence.tool} matched "
                    f"{evidence.rule_id} on lines "
                    f"{evidence.line_start}-"
                    f"{evidence.line_end}."
                )
            ],
            scanner_evidence=[
                evidence
            ],
            cwe=list(evidence.cwe),
            owasp=list(evidence.owasp),
            vulnerable_lines=list(
                range(
                    evidence.line_start,
                    evidence.line_end + 1,
                )
            ),
            false_positive_notes=notes,
            recommended_fix=(
                recommended_fix
            ),
            proposed_patch=None,
        )


def create_core_security_task_registry(
    *,
    fingerprint_key: str | None = None,
    project_identity_resolver: (
        ProjectIdentityResolver
        | None
    ) = None,
    scanner_orchestrator: (
        SecurityScannerOrchestrator
        | None
    ) = None,
) -> SecurityTaskHandlerRegistry:
    secret_engine = None

    if fingerprint_key is not None:
        normalized_key = (
            fingerprint_key.strip()
        )

        if not normalized_key:
            raise SecurityTaskHandlerContractError(
                "Fingerprint key must not be "
                "blank when provided."
            )

        secret_engine = (
            SecretIntelligenceEngine(
                fingerprint_key=normalized_key
            )
        )

    registry = (
        SecurityTaskHandlerRegistry()
    )

    registry.register(
        RepositoryContextTaskHandler(
            resolver=(
                project_identity_resolver
            ),
        )
    )

    registry.register(
        DeterministicScanTaskHandler(
            scanner_orchestrator=(
                scanner_orchestrator
            ),
            secret_engine=secret_engine,
        )
    )

    registry.freeze()
    return registry
