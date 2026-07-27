from __future__ import annotations

from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

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
from aegis.orchestrator.security_task_planner import (
    SecurityTaskPlanner,
)
from aegis.orchestrator.security_task_workflow import (
    SecurityTaskWorkflowResult,
    SecurityTaskWorkflowRunner,
)
from aegis.schemas.analysis import (
    AnalyzeCodeResponse,
    ScannerCoverage,
    SecurityFinding,
)
from aegis.schemas.claims import (
    SecurityClaim,
)
from aegis.schemas.memory import (
    SecurityMemoryTaskArtifact,
)
from aegis.schemas.model_consensus import (
    ModelConsensusResult,
)
from aegis.schemas.policy import (
    SecurityPolicyTaskArtifact,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskPlanRequest,
)
from aegis.schemas.security_task_run import (
    SecurityTaskRunRequest,
    SecurityTaskRunResponse,
)
from aegis.schemas.threat_model import (
    ThreatModelScanResponse,
)
from aegis.security.claim_adapter import (
    finding_to_claim,
)


ArtifactModel = TypeVar(
    "ArtifactModel",
    bound=BaseModel,
)


class SecurityTaskProductionError(
    RuntimeError
):
    pass


class SecurityTaskProductionRunner:
    runner = (
        "aegis-security-task-production-runner-v1"
    )
    _maximum_source_bytes = 200_000

    def __init__(
        self,
        *,
        registry: SecurityTaskHandlerRegistry,
        planner: SecurityTaskPlanner | None = None,
        execution_machine: (
            SecurityTaskExecutionMachine
            | None
        ) = None,
        workflow_runner: (
            SecurityTaskWorkflowRunner
            | None
        ) = None,
    ) -> None:
        self._planner = (
            planner
            if planner is not None
            else SecurityTaskPlanner()
        )
        self._machine = (
            execution_machine
            if execution_machine is not None
            else SecurityTaskExecutionMachine()
        )
        self._workflow = (
            workflow_runner
            if workflow_runner is not None
            else SecurityTaskWorkflowRunner(
                executor=SecurityTaskExecutor(
                    registry=registry,
                    machine=self._machine,
                ),
            )
        )

    async def run(
        self,
        request: SecurityTaskRunRequest,
    ) -> SecurityTaskRunResponse:
        repository_root = self._repository_root(
            request
        )
        plan = self._planner.plan(
            SecurityTaskPlanRequest(
                operation=request.operation,
                language=request.language,
                has_scanner_evidence=True,
                include_threat_model=(
                    request.include_threat_model
                ),
                include_security_memory=(
                    request.include_security_memory
                ),
                include_policy_evaluation=(
                    request.include_policy_evaluation
                ),
            )
        )
        gates = {
            "scanner_evidence",
            "ai_available",
        }
        execution = self._machine.create(
            plan,
            satisfied_gates=gates,
        )
        artifact_store = (
            SecurityTaskArtifactStore()
        )
        memory_sources = [
            "scanner_coverage",
            "consensus_decisions",
            "consensus_claims",
        ]

        if request.include_threat_model:
            memory_sources.append(
                "threat_model"
            )

        context = SecurityTaskHandlerContext(
            execution_id=(
                execution.execution_id
            ),
            operation=request.operation,
            language=request.language,
            repository_root=str(
                repository_root
            ),
            metadata={
                "source_code": request.code,
                "filename": request.filename,
                "repository_files": [
                    {
                        "filename": (
                            request.filename
                        ),
                        "language": (
                            request.language
                        ),
                        "code": request.code,
                    }
                ],
                "security_memory_input": {
                    "analysis_status": (
                        "complete"
                    ),
                    "coverage": (
                        "targeted_analysis"
                    ),
                    "claims": [],
                    "claims_artifact": (
                        "consensus_claims"
                    ),
                    "source_artifacts": (
                        memory_sources
                    ),
                    "allow_empty_snapshot": (
                        True
                    ),
                },
                "security_policy_request": {
                    "profile": (
                        request.policy_profile
                    ),
                    "source_artifacts": [
                        "security_snapshot",
                    ],
                },
            },
        )
        result = await self._workflow.run(
            execution=execution,
            context=context,
            artifact_store=artifact_store,
            satisfied_gates=gates,
        )

        return self._response(
            request=request,
            result=result,
            artifacts=artifact_store,
        )

    @staticmethod
    def _repository_root(
        request: SecurityTaskRunRequest,
    ) -> Path:
        try:
            root = Path(
                request.repository_path
            ).expanduser().resolve(
                strict=True
            )
        except OSError as exc:
            raise SecurityTaskProductionError(
                "Production security workflow "
                "requires an existing repository."
            ) from exc

        if not root.is_dir():
            raise SecurityTaskProductionError(
                "Production security workflow "
                "repository_path must be a directory."
            )

        try:
            source_path = (
                root / request.filename
            ).resolve(strict=True)
        except OSError as exc:
            raise SecurityTaskProductionError(
                "Production security workflow "
                "requires an existing source file."
            ) from exc

        if (
            not source_path.is_relative_to(root)
            or not source_path.is_file()
        ):
            raise SecurityTaskProductionError(
                "Production security workflow "
                "source must be a regular file "
                "inside the repository."
            )

        request_bytes = request.code.encode(
            "utf-8"
        )

        if len(request_bytes) > (
            SecurityTaskProductionRunner
            ._maximum_source_bytes
        ):
            raise SecurityTaskProductionError(
                "Production security workflow "
                "source exceeds the 200000-byte "
                "safety limit."
            )

        try:
            with source_path.open(
                "rb"
            ) as source_handle:
                persisted_bytes = (
                    source_handle.read(
                        SecurityTaskProductionRunner
                        ._maximum_source_bytes
                        + 1
                    )
                )

            if len(persisted_bytes) > (
                SecurityTaskProductionRunner
                ._maximum_source_bytes
            ):
                raise SecurityTaskProductionError(
                    "Production security workflow "
                    "source exceeds the 200000-byte "
                    "safety limit."
                )

            persisted_code = (
                persisted_bytes.decode(
                    "utf-8"
                )
            )
        except OSError as exc:
            raise SecurityTaskProductionError(
                "Production security workflow "
                "could not read the UTF-8 source "
                "file."
            ) from exc
        except UnicodeError as exc:
            raise SecurityTaskProductionError(
                "Production security workflow "
                "source file must be valid UTF-8."
            ) from exc

        if persisted_code != request.code:
            raise SecurityTaskProductionError(
                "Production security workflow "
                "refuses source content that does "
                "not match the persisted file."
            )

        return root

    def _response(
        self,
        *,
        request: SecurityTaskRunRequest,
        result: SecurityTaskWorkflowResult,
        artifacts: SecurityTaskArtifactStore,
    ) -> SecurityTaskRunResponse:
        verified_findings = (
            self._findings(
                artifacts,
                "verified_findings",
            )
        )
        scanner_findings = (
            self._findings(
                artifacts,
                "scanner_findings",
            )
        )
        findings = (
            verified_findings
            if artifacts.contains(
                "verified_findings"
            )
            else scanner_findings
        )
        claims = self._claims(
            request=request,
            findings=findings,
            artifacts=artifacts,
        )
        consensus = self._artifact_model(
            artifacts,
            "consensus_decisions",
            ModelConsensusResult,
        )
        coverage = self._artifact_model(
            artifacts,
            "scanner_coverage",
            ScannerCoverage,
        )
        primary_route = (
            artifacts.value(
                "primary_model_route"
            )
            if artifacts.contains(
                "primary_model_route"
            )
            else {}
        )
        model = (
            primary_route.get("model")
            if isinstance(
                primary_route,
                dict,
            )
            else None
        )
        scanner = (
            "+".join(
                coverage.selected_scanners
            )
            if coverage is not None
            and coverage.selected_scanners
            else "not-applicable"
        )
        ai_result = (
            consensus is not None
            and bool(findings)
        )
        analysis = AnalyzeCodeResponse(
            filename=request.filename,
            language=request.language,
            model=(
                str(model)
                if ai_result and model
                else "not-used"
            ),
            scanner=scanner,
            analysis_status=(
                "completed"
                if result.status == "completed"
                else "fallback"
            ),
            result_source=(
                "ai"
                if ai_result
                else "scanner"
            ),
            findings=findings,
            claims=claims,
            model_consensus=consensus,
        )

        return SecurityTaskRunResponse(
            runner=self.runner,
            workflow_status=result.status,
            execution=result.execution,
            aggregation=result.aggregation,
            analysis=analysis,
            threat_model=(
                self._artifact_model(
                    artifacts,
                    "threat_model",
                    ThreatModelScanResponse,
                )
            ),
            security_memory=(
                self._artifact_model(
                    artifacts,
                    "security_snapshot",
                    SecurityMemoryTaskArtifact,
                )
            ),
            policy_decision=(
                self._artifact_model(
                    artifacts,
                    "policy_decision",
                    SecurityPolicyTaskArtifact,
                )
            ),
            errors=list(result.errors),
        )

    @staticmethod
    def _findings(
        artifacts: SecurityTaskArtifactStore,
        name: str,
    ) -> list[SecurityFinding]:
        if not artifacts.contains(name):
            return []

        value = artifacts.value(name)

        if not isinstance(value, list):
            raise SecurityTaskProductionError(
                f"Production artifact {name!r} "
                "must be a list."
            )

        return [
            SecurityFinding.model_validate(
                item
            )
            for item in value
        ]

    @staticmethod
    def _claims(
        *,
        request: SecurityTaskRunRequest,
        findings: list[SecurityFinding],
        artifacts: SecurityTaskArtifactStore,
    ) -> list[SecurityClaim]:
        if artifacts.contains(
            "consensus_claims"
        ):
            value = artifacts.value(
                "consensus_claims"
            )

            if not isinstance(value, list):
                raise SecurityTaskProductionError(
                    "consensus_claims artifact must "
                    "be a list."
                )

            return [
                SecurityClaim.model_validate(
                    item
                )
                for item in value
            ]

        return [
            finding_to_claim(
                finding,
                filename=request.filename,
                include_narrative_evidence=(
                    False
                ),
            )
            for finding in findings
        ]

    @staticmethod
    def _artifact_model(
        artifacts: SecurityTaskArtifactStore,
        name: str,
        model: type[ArtifactModel],
    ) -> ArtifactModel | None:
        if not artifacts.contains(name):
            return None

        return model.model_validate(
            artifacts.value(name)
        )
