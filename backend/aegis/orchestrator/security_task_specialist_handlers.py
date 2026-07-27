from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Mapping, Protocol

from aegis.orchestrator.security_task_handler import (
    SecurityTaskHandlerCapability,
    SecurityTaskHandlerContext,
    SecurityTaskHandlerResult,
)
from aegis.orchestrator.security_task_handlers import (
    SecurityTaskInputError,
)
from aegis.schemas.analysis import ScannerEvidence
from aegis.schemas.attack_surface import (
    AttackSurfaceFile,
)
from aegis.schemas.dependencies import (
    DependencyPackage,
    DependencyScanResponse,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
)
from aegis.security.attack_surface import (
    AttackSurfaceMapper,
)
from aegis.security.config_secrets import (
    ConfigSecretScanner,
)
from aegis.security.dependency_files import (
    parse_dependency_file,
    supported_dependency_file,
)
from aegis.security.osv import OsvDependencyScanner
from aegis.security.redaction import SecretRedactor
from aegis.security.secrets import (
    SecretIntelligenceEngine,
)


class DependencyScanner(Protocol):
    name: str

    async def scan(
        self,
        packages: list[DependencyPackage],
    ) -> DependencyScanResponse:
        ...


@dataclass(frozen=True, slots=True)
class RepositorySourceFile:
    filename: str
    language: str
    code: str


class RepositorySourceInput:
    _maximum_files = 300
    _maximum_file_bytes = 2_000_000

    @classmethod
    def from_context(
        cls,
        context: SecurityTaskHandlerContext,
    ) -> list[RepositorySourceFile]:
        raw_files = context.metadata.get(
            "repository_files"
        )

        if raw_files is None:
            return [
                cls._single_source(context)
            ]

        if (
            not isinstance(raw_files, Sequence)
            or isinstance(
                raw_files,
                (str, bytes, bytearray),
            )
        ):
            raise SecurityTaskInputError(
                "Repository specialist analysis "
                "requires metadata['repository_files'] "
                "to be a sequence."
            )

        if not raw_files:
            raise SecurityTaskInputError(
                "Repository specialist analysis "
                "requires at least one source file."
            )

        if len(raw_files) > cls._maximum_files:
            raise SecurityTaskInputError(
                "Repository specialist analysis "
                f"accepts at most {cls._maximum_files} "
                "source files."
            )

        return [
            cls._source_from_mapping(
                item,
                default_language=context.language,
            )
            for item in raw_files
        ]

    @classmethod
    def _single_source(
        cls,
        context: SecurityTaskHandlerContext,
    ) -> RepositorySourceFile:
        return cls._source_from_mapping(
            {
                "filename": context.metadata.get(
                    "filename"
                ),
                "language": context.language,
                "code": context.metadata.get(
                    "source_code"
                ),
            },
            default_language=context.language,
        )

    @classmethod
    def _source_from_mapping(
        cls,
        value: object,
        *,
        default_language: str,
    ) -> RepositorySourceFile:
        if not isinstance(value, Mapping):
            raise SecurityTaskInputError(
                "Every repository source file must "
                "be a mapping."
            )

        filename = value.get("filename")
        language = value.get(
            "language",
            default_language,
        )
        code = value.get("code")

        if not isinstance(filename, str):
            raise SecurityTaskInputError(
                "Repository source files require "
                "a filename."
            )

        normalized_filename = filename.strip()

        if (
            not normalized_filename
            or Path(normalized_filename).name
            in {"", ".", ".."}
        ):
            raise SecurityTaskInputError(
                "Repository source filenames must "
                "not be empty or ambiguous."
            )

        if not isinstance(language, str):
            raise SecurityTaskInputError(
                "Repository source files require "
                "a language."
            )

        normalized_language = (
            language.strip().lower()
        )

        if not normalized_language:
            raise SecurityTaskInputError(
                "Repository source languages must "
                "not be empty."
            )

        if not isinstance(code, str):
            raise SecurityTaskInputError(
                "Repository source files require "
                "source code."
            )

        if not code.strip():
            raise SecurityTaskInputError(
                "Repository source code must not "
                "be empty."
            )

        if (
            len(code.encode("utf-8"))
            > cls._maximum_file_bytes
        ):
            raise SecurityTaskInputError(
                "Repository source file exceeds "
                "the two megabyte safety limit."
            )

        return RepositorySourceFile(
            filename=normalized_filename,
            language=normalized_language,
            code=code,
        )


def _require_repository_context(
    inputs: Mapping[str, Any],
    *,
    task_name: str,
) -> Mapping[str, Any]:
    repository_context = inputs.get(
        "repository_context"
    )

    if not isinstance(
        repository_context,
        Mapping,
    ):
        raise SecurityTaskInputError(
            f"{task_name} requires a "
            "repository_context artifact."
        )

    return repository_context


class SecretAnalysisTaskHandler:
    capability = SecurityTaskHandlerCapability(
        kind="secret_analysis",
        required_artifacts=frozenset({
            "repository_context",
        }),
        produced_artifacts=frozenset({
            "secret_findings",
        }),
        supports_retry=False,
        max_attempts=1,
        side_effect_free=True,
    )

    def __init__(
        self,
        *,
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
        _require_repository_context(
            inputs,
            task_name="Secret analysis",
        )

        source_files = (
            RepositorySourceInput.from_context(
                context
            )
        )

        evidence: list[ScannerEvidence] = []
        applicable_files = 0

        for source in source_files:
            context.raise_if_cancelled()

            if self._config_scanner.supports(
                filename=source.filename,
                language=source.language,
            ):
                applicable_files += 1

            evidence.extend(
                self._config_scanner.scan(
                    code=source.code,
                    filename=source.filename,
                    language=source.language,
                )
            )

        evidence = self._deduplicate(evidence)

        if self._secret_engine is not None:
            evidence = (
                self._secret_engine
                .enrich_evidence_list(evidence)
            )

        redaction_session = (
            self._redactor.create_session()
        )
        safe_evidence = (
            redaction_session
            .redact_evidence_list(evidence)
        )

        classified_count = sum(
            item.secret is not None
            for item in safe_evidence
        )

        return SecurityTaskHandlerResult(
            output={
                "secret_findings": [
                    item.model_dump(mode="json")
                    for item in safe_evidence
                ],
            },
            metadata={
                "scanner": self._config_scanner.name,
                "files_received": len(source_files),
                "files_scanned": applicable_files,
                "finding_count": len(
                    safe_evidence
                ),
                "classified_count": (
                    classified_count
                ),
                "raw_secret_values_persisted": (
                    False
                ),
            },
            reasons=(
                "Configuration-oriented source "
                "files were checked for embedded "
                "credentials.",
                "All secret evidence was redacted "
                "before artifact persistence.",
            ),
        )

    @staticmethod
    def _deduplicate(
        evidence: list[ScannerEvidence],
    ) -> list[ScannerEvidence]:
        unique: list[ScannerEvidence] = []
        seen: set[
            tuple[str, str, int, int]
        ] = set()

        for item in evidence:
            identity = (
                item.rule_id,
                item.file,
                item.line_start,
                item.line_end,
            )

            if identity in seen:
                continue

            seen.add(identity)
            unique.append(item)

        return unique


class DependencyScanTaskHandler:
    capability = SecurityTaskHandlerCapability(
        kind="dependency_scan",
        required_artifacts=frozenset({
            "repository_context",
        }),
        produced_artifacts=frozenset({
            "dependency_findings",
        }),
        supports_retry=True,
        max_attempts=2,
        side_effect_free=True,
    )

    def __init__(
        self,
        *,
        scanner: DependencyScanner
        | None = None,
    ) -> None:
        self._scanner = (
            scanner
            or OsvDependencyScanner()
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
        _require_repository_context(
            inputs,
            task_name="Dependency scan",
        )

        source_files = (
            RepositorySourceInput.from_context(
                context
            )
        )

        manifest_sources = [
            source
            for source in source_files
            if supported_dependency_file(
                source.filename
            )
        ]

        packages = self._parse_manifests(
            manifest_sources
        )

        context.raise_if_cancelled()

        if packages:
            scan = await self._scanner.scan(
                packages
            )
        else:
            scan = DependencyScanResponse(
                scanner=self._scanner.name,
                packages_scanned=0,
                successful_packages=0,
                failed_packages=0,
                scan_status="partial",
                errors=[
                    (
                        "No exact dependency versions "
                        "were available from supported "
                        "manifests; vulnerability "
                        "coverage is incomplete."
                    )
                ],
                vulnerable_packages=0,
                vulnerabilities=[],
            )

        context.raise_if_cancelled()

        return SecurityTaskHandlerResult(
            output={
                "dependency_findings": {
                    "packages": [
                        package.model_dump(
                            mode="json"
                        )
                        for package in packages
                    ],
                    "scan": scan.model_dump(
                        mode="json"
                    ),
                },
            },
            metadata={
                "scanner": scan.scanner,
                "files_received": len(source_files),
                "manifests_scanned": len(
                    manifest_sources
                ),
                "packages_scanned": (
                    scan.packages_scanned
                ),
                "scan_status": scan.scan_status,
                "coverage_complete": (
                    scan.scan_status == "completed"
                ),
                "vulnerability_count": len(
                    scan.vulnerabilities
                ),
            },
            reasons=(
                "Supported dependency manifests "
                "were parsed using exact resolved "
                "versions only.",
                (
                    "Dependency vulnerability "
                    f"coverage status: "
                    f"{scan.scan_status}."
                ),
            ),
        )

    @staticmethod
    def _parse_manifests(
        sources: list[
            RepositorySourceFile
        ],
    ) -> list[DependencyPackage]:
        packages: list[DependencyPackage] = []

        with TemporaryDirectory(
            prefix="aegis-task-dependencies-",
        ) as temporary_directory:
            root = Path(temporary_directory)

            for index, source in enumerate(
                sources
            ):
                source_directory = (
                    root / str(index)
                )
                source_directory.mkdir()

                manifest_path = (
                    source_directory
                    / Path(source.filename).name
                )
                manifest_path.write_text(
                    source.code,
                    encoding="utf-8",
                )

                parsed = parse_dependency_file(
                    manifest_path
                )

                packages.extend(
                    package.model_copy(
                        update={
                            "manifest": (
                                source.filename
                            ),
                        }
                    )
                    for package in parsed
                )

        unique: dict[
            tuple[str, str, str, str],
            DependencyPackage,
        ] = {}

        for package in packages:
            identity = (
                package.ecosystem,
                package.name.lower(),
                package.version,
                package.manifest,
            )
            unique.setdefault(
                identity,
                package,
            )

        return list(unique.values())


class AttackSurfaceTaskHandler:
    capability = SecurityTaskHandlerCapability(
        kind="attack_surface",
        required_artifacts=frozenset({
            "repository_context",
        }),
        produced_artifacts=frozenset({
            "attack_surface_graph",
        }),
        supports_retry=False,
        max_attempts=1,
        side_effect_free=True,
    )

    def __init__(
        self,
        *,
        mapper: AttackSurfaceMapper
        | None = None,
    ) -> None:
        self._mapper = (
            mapper
            or AttackSurfaceMapper()
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
        _require_repository_context(
            inputs,
            task_name="Attack-surface mapping",
        )

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

        graph = self._mapper.scan(
            attack_files
        )

        context.raise_if_cancelled()

        return SecurityTaskHandlerResult(
            output={
                "attack_surface_graph": (
                    graph.model_dump(mode="json")
                ),
            },
            metadata={
                "mapper": graph.mapper,
                "files_scanned": (
                    graph.summary.files_scanned
                ),
                "nodes_found": (
                    graph.summary.nodes_found
                ),
                "edges_found": (
                    graph.summary.edges_found
                ),
            },
            reasons=(
                "Static entry points, trust "
                "boundaries, and sensitive sinks "
                "were mapped into a graph.",
            ),
        )
