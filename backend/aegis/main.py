from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import Depends, FastAPI, HTTPException, Query

from aegis.config.settings import get_settings
from aegis.dependencies import (
    get_change_policy_service,
    get_git_change_collector,
    get_memory_policy_engine,
    get_security_memory_policy_service,
    get_security_memory_service,
)
from aegis.orchestrator.analyzer import SecurityAnalyzer
from aegis.schemas.change_policy import (
    ChangePolicyCollectionRequest,
    ChangePolicyCollectionResponse,
)
from aegis.schemas.changes import (
    ChangeSet,
    ChangeSetCollectionRequest,
)
from aegis.schemas.analysis import AnalyzeCodeRequest, AnalyzeCodeResponse
from aegis.schemas.policy import (
    MemoryPolicyDecisionResponse,
    MemoryPolicyEvaluationRequest,
    SecurityMemoryPolicyRecordRequest,
    SecurityMemoryPolicyRecordResponse,
)
from aegis.schemas.memory import (
    SecurityMemoryHistoryResponse,
    SecurityMemoryLatestResponse,
    SecurityMemoryRecordRequest,
    SecurityMemoryRecordResponse,
    SecurityMemorySnapshotResponse,
)
from aegis.schemas.attack_surface import (
    AttackSurfaceScanRequest,
    AttackSurfaceScanResponse,
)
from aegis.schemas.threat_model import (
    ThreatModelScanRequest,
    ThreatModelScanResponse,
)
from aegis.schemas.validation import (
    ValidationAuthorizationRequest,
    ValidationAuthorizationResponse,
    ValidationExecutionPlanResponse,
    DynamicValidationEvidenceRequest,
    DynamicValidationEvidenceResponse,
    ValidationReplayCompareRequest,
    ValidationReplayCompareResponse,
    UnifiedFixVerificationRequest,
    UnifiedFixVerificationResponse,
    ValidationReplayRequest,
    ValidationReplayResponse,
    ValidationExecutionRequest,
    ValidationExecutionResult,
    ValidationPlanRequest,
)
from aegis.schemas.dependencies import (
    DependencyManifestScanRequest,
    DependencyManifestScanResponse,
    DependencyPackage,
    DependencyScanRequest,
    DependencyScanResponse,
)
from aegis.security.change_policy_service import (
    ChangePolicyService,
)
from aegis.security.git_changes import (
    GitChangeCollector,
)
from aegis.security.attack_surface import AttackSurfaceMapper
from aegis.security.dependency_files import parse_dependency_file
from aegis.security.osv import OsvDependencyScanner
from aegis.security.threat_model import ThreatModeler
from aegis.security.authorization import (
    ValidationAuthorizer,
)
from aegis.security.validation_plan import (
    ValidationPlanBuilder,
)
from aegis.security.validation_runner import (
    ValidationRunner,
)
from aegis.security.validation_evidence import (
    DynamicValidationEvaluator,
)
from aegis.security.validation_replay import (
    ValidationReplayComparator,
)
from aegis.security.validation_replay_orchestrator import (
    ValidationReplayOrchestrator,
)
from aegis.security.fix_verification import (
    UnifiedFixVerificationEvaluator,
)
from aegis.security.memory_policy import (
    MemoryAwarePolicyEngine,
)
from aegis.security.memory_policy_service import (
    SecurityMemoryPolicyService,
)
from aegis.security.security_memory import (
    SecurityMemoryService,
)


settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="AI-native secure software engineering backend",
)

analyzer = SecurityAnalyzer(
    fingerprint_key=settings.aegis_fingerprint_key,
)
attack_surface_mapper = AttackSurfaceMapper()
threat_modeler = ThreatModeler(
    mapper=attack_surface_mapper,
)
dependency_scanner = OsvDependencyScanner()
validation_authorizer = ValidationAuthorizer()
validation_plan_builder = ValidationPlanBuilder(
    authorizer=validation_authorizer,
)
validation_runner = ValidationRunner(
    planner=validation_plan_builder,
)
dynamic_validation_evaluator = (
    DynamicValidationEvaluator()
)
validation_replay_comparator = (
    ValidationReplayComparator()
)
validation_replay_orchestrator = (
    ValidationReplayOrchestrator(
        runner=validation_runner,
        evaluator=dynamic_validation_evaluator,
        comparator=validation_replay_comparator,
    )
)
unified_fix_verification_evaluator = (
    UnifiedFixVerificationEvaluator()
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": settings.app_version,
    }


@app.post("/v1/analyze", response_model=AnalyzeCodeResponse)
async def analyze_code(
    request: AnalyzeCodeRequest,
) -> AnalyzeCodeResponse:
    """
    Backward-compatible deep analysis endpoint.
    """
    try:
        return await analyzer.deep_analyze(request)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Security analysis failed: {exc}",
        ) from exc


@app.post("/v1/analyze/fast", response_model=AnalyzeCodeResponse)
async def fast_analyze_code(
    request: AnalyzeCodeRequest,
) -> AnalyzeCodeResponse:
    """
    Fast scanner-only analysis. Does not call an AI model.
    """
    try:
        return await analyzer.fast_analyze(request)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Fast security scan failed: {exc}",
        ) from exc


@app.post("/v1/analyze/deep", response_model=AnalyzeCodeResponse)
async def deep_analyze_code(
    request: AnalyzeCodeRequest,
) -> AnalyzeCodeResponse:
    """
    Semgrep evidence followed by AI analysis when evidence exists.
    """
    try:
        return await analyzer.deep_analyze(request)
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Deep security analysis failed: {exc}",
        ) from exc

@app.post(
    "/v1/attack-surface/scan",
    response_model=AttackSurfaceScanResponse,
)
async def scan_attack_surface(
    request: AttackSurfaceScanRequest,
) -> AttackSurfaceScanResponse:
    """
    Build a deterministic static map of exposed routes,
    trust boundaries, and security-sensitive operations.
    """
    try:
        return attack_surface_mapper.scan(
            request.files
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Attack-surface mapping failed: "
                f"{exc}"
            ),
        ) from exc


@app.post(
    "/v1/threat-model/scan",
    response_model=ThreatModelScanResponse,
)
async def scan_threat_model(
    request: ThreatModelScanRequest,
) -> ThreatModelScanResponse:
    """
    Build a deterministic threat model from the
    workspace attack surface.
    """
    try:
        return threat_modeler.scan(
            request.files
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Threat modeling failed: "
                f"{exc}"
            ),
        ) from exc


@app.post(
    "/v1/validation/authorize",
    response_model=ValidationAuthorizationResponse,
)
async def authorize_validation(
    request: ValidationAuthorizationRequest,
) -> ValidationAuthorizationResponse:
    """
    Validate explicit authorization, target scope,
    and safe resource limits before dynamic execution.
    This endpoint does not execute tests or commands.
    """
    try:
        return validation_authorizer.authorize(
            request
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Validation authorization failed: "
                f"{exc}"
            ),
        ) from exc


@app.post(
    "/v1/validation/plan",
    response_model=ValidationExecutionPlanResponse,
)
async def plan_validation(
    request: ValidationPlanRequest,
) -> ValidationExecutionPlanResponse:
    """
    Build an inspectable isolated-execution plan.
    This endpoint does not run Docker or any command.
    """
    try:
        return validation_plan_builder.build(
            request
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Validation planning failed: "
                f"{exc}"
            ),
        ) from exc


@app.post(
    "/v1/validation/run",
    response_model=ValidationExecutionResult,
)
async def run_validation(
    request: ValidationExecutionRequest,
) -> ValidationExecutionResult:
    """
    Execute an explicitly authorized validation plan
    inside a hardened local container runtime.
    """
    try:
        return await validation_runner.run(
            request
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Validation execution failed: "
                f"{exc}"
            ),
        ) from exc


@app.post(
    "/v1/validation/evidence",
    response_model=DynamicValidationEvidenceResponse,
)
async def evaluate_validation_evidence(
    request: DynamicValidationEvidenceRequest,
) -> DynamicValidationEvidenceResponse:
    """
    Correlate isolated execution evidence with a
    specific authorized threat validation.
    """
    try:
        return dynamic_validation_evaluator.evaluate(
            request
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Dynamic validation evidence "
                f"evaluation failed: {exc}"
            ),
        ) from exc


@app.post(
    "/v1/validation/replay/compare",
    response_model=ValidationReplayCompareResponse,
)
async def compare_validation_replay(
    request: ValidationReplayCompareRequest,
) -> ValidationReplayCompareResponse:
    """
    Compare dynamic evidence captured before and after
    a secure fix using the same threat identity.
    """
    try:
        return validation_replay_comparator.compare(
            request
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Dynamic validation replay comparison "
                f"failed: {exc}"
            ),
        ) from exc


@app.post(
    "/v1/validation/replay",
    response_model=ValidationReplayResponse,
)
async def replay_validation(
    request: ValidationReplayRequest,
) -> ValidationReplayResponse:
    """
    Re-run the same authorized validation plan after
    a fix and compare before/after dynamic evidence.
    """
    try:
        return await validation_replay_orchestrator.replay(
            request
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Dynamic validation replay failed: "
                f"{exc}"
            ),
        ) from exc


@app.post(
    "/v1/validation/fix-verification",
    response_model=UnifiedFixVerificationResponse,
)
async def evaluate_fix_verification(
    request: UnifiedFixVerificationRequest,
) -> UnifiedFixVerificationResponse:
    """
    Combine project checks, static rescanning,
    regression detection, and dynamic replay evidence.
    """
    try:
        return (
            unified_fix_verification_evaluator
            .evaluate(request)
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Unified fix verification failed: "
                f"{exc}"
            ),
        ) from exc


@app.post(
    "/v1/dependencies/manifests/scan",
    response_model=DependencyManifestScanResponse,
)
async def scan_dependency_manifests(
    request: DependencyManifestScanRequest,
) -> DependencyManifestScanResponse:
    """
    Parse supported dependency files and query OSV for the
    exact resolved package versions.
    """
    try:
        packages: list[DependencyPackage] = []

        with TemporaryDirectory(
            prefix="aegis-dependencies-",
        ) as directory:
            temporary_root = Path(directory)

            for index, manifest in enumerate(
                request.manifests
            ):
                safe_name = Path(
                    manifest.filename
                ).name

                if not safe_name:
                    continue

                manifest_directory = (
                    temporary_root / str(index)
                )

                manifest_directory.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                temporary_path = (
                    manifest_directory / safe_name
                )

                temporary_path.write_text(
                    manifest.content,
                    encoding="utf-8",
                )

                parsed = parse_dependency_file(
                    temporary_path
                )

                packages.extend(
                    package.model_copy(
                        update={
                            "manifest": manifest.manifest,
                        }
                    )
                    for package in parsed
                )

        deduplicated: dict[
            tuple[str, str, str, str],
            DependencyPackage,
        ] = {}

        for package in packages:
            key = (
                package.ecosystem,
                package.name.lower(),
                package.version,
                package.manifest,
            )

            previous = deduplicated.get(key)

            if (
                previous is None
                or (
                    package.direct
                    and not previous.direct
                )
            ):
                deduplicated[key] = package

        normalized_packages = sorted(
            deduplicated.values(),
            key=lambda package: (
                package.ecosystem,
                package.name.lower(),
                package.version,
                package.manifest,
            ),
        )

        if not normalized_packages:
            raise HTTPException(
                status_code=422,
                detail=(
                    "No exact dependency versions were "
                    "found in the supplied manifests."
                ),
            )

        scan = await dependency_scanner.scan(
            normalized_packages
        )

        return DependencyManifestScanResponse(
            packages=normalized_packages,
            scan=scan,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Dependency manifest scan failed: "
                f"{exc}"
            ),
        ) from exc


@app.post(
    "/v1/dependencies/scan",
    response_model=DependencyScanResponse,
)
async def scan_dependencies(
    request: DependencyScanRequest,
) -> DependencyScanResponse:
    """
    Query known vulnerabilities for exact dependency versions.
    """
    try:
        return await dependency_scanner.scan(
            request.packages
        )
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Dependency scan failed: {exc}",
        ) from exc


@app.post(
    "/v1/security-memory/record",
    response_model=SecurityMemoryRecordResponse,
)
def record_security_memory(
    request: SecurityMemoryRecordRequest,
    service: SecurityMemoryService = Depends(
        get_security_memory_service
    ),
) -> SecurityMemoryRecordResponse:
    """
    Record the current project-security baseline and return
    its lifecycle delta against the latest stored snapshot.
    """
    try:
        return service.record(request)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Security memory could not record "
                "the project snapshot."
            ),
        ) from exc


@app.get(
    "/v1/security-memory/latest",
    response_model=SecurityMemoryLatestResponse,
)
def get_latest_security_memory(
    repository_path: str = Query(
        min_length=1,
        max_length=2_000,
    ),
    service: SecurityMemoryService = Depends(
        get_security_memory_service
    ),
) -> SecurityMemoryLatestResponse:
    try:
        repository = (
            service.identity_resolver.resolve(
                repository_path
            )
        )
        snapshot = service.store.get_latest_snapshot(
            repository.project_id
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Security memory could not read "
                "the latest project snapshot."
            ),
        ) from exc

    if snapshot is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "No security-memory snapshot exists "
                "for this project."
            ),
        )

    return SecurityMemoryLatestResponse(
        repository=repository,
        snapshot=snapshot,
    )


@app.get(
    "/v1/security-memory/history",
    response_model=SecurityMemoryHistoryResponse,
)
def get_security_memory_history(
    repository_path: str = Query(
        min_length=1,
        max_length=2_000,
    ),
    limit: int = Query(
        default=100,
        ge=1,
        le=1_000,
    ),
    offset: int = Query(
        default=0,
        ge=0,
    ),
    service: SecurityMemoryService = Depends(
        get_security_memory_service
    ),
) -> SecurityMemoryHistoryResponse:
    try:
        repository = (
            service.identity_resolver.resolve(
                repository_path
            )
        )
        snapshots = service.store.list_snapshots(
            repository.project_id,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Security memory could not read "
                "the project history."
            ),
        ) from exc

    return SecurityMemoryHistoryResponse(
        repository=repository,
        snapshots=snapshots,
        count=len(snapshots),
        limit=limit,
        offset=offset,
    )


@app.get(
    "/v1/security-memory/snapshots/{snapshot_id}",
    response_model=SecurityMemorySnapshotResponse,
)
def get_security_memory_snapshot(
    snapshot_id: str,
    service: SecurityMemoryService = Depends(
        get_security_memory_service
    ),
) -> SecurityMemorySnapshotResponse:
    try:
        snapshot = service.store.get_snapshot(
            snapshot_id
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Security memory could not read "
                "the requested snapshot."
            ),
        ) from exc

    if snapshot is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "Security-memory snapshot was not found."
            ),
        )

    return SecurityMemorySnapshotResponse(
        snapshot=snapshot,
    )


@app.post(
    "/v1/security-memory/policy",
    response_model=MemoryPolicyDecisionResponse,
)
def evaluate_security_memory_policy(
    request: MemoryPolicyEvaluationRequest,
    engine: MemoryAwarePolicyEngine = Depends(
        get_memory_policy_engine
    ),
) -> MemoryPolicyDecisionResponse:
    """
    Evaluate a security-memory reconciliation result
    using deterministic policy rules.
    """
    return engine.evaluate(request)


@app.post(
    "/v1/security-memory/record-and-evaluate",
    response_model=SecurityMemoryPolicyRecordResponse,
)
def record_and_evaluate_security_memory(
    request: SecurityMemoryPolicyRecordRequest,
    service: SecurityMemoryPolicyService = Depends(
        get_security_memory_policy_service
    ),
) -> SecurityMemoryPolicyRecordResponse:
    """
    Persist the current project-security snapshot and apply
    deterministic policy to its lifecycle reconciliation.
    """
    try:
        return service.record_and_evaluate(request)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Security memory could not record and "
                "evaluate the project snapshot."
            ),
        ) from exc


@app.post(
    "/v1/changes/collect",
    response_model=ChangeSet,
)
def collect_repository_changes(
    request: ChangeSetCollectionRequest,
    collector: GitChangeCollector = Depends(
        get_git_change_collector
    ),
) -> ChangeSet:
    """
    Collect a deterministic staged or uncommitted Git
    change set without invoking a shell.
    """
    try:
        return collector.collect(
            request.repository_path,
            mode=request.mode,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Repository changes could not "
                "be collected."
            ),
        ) from exc


@app.post(
    "/v1/changes/collect-and-evaluate",
    response_model=ChangePolicyCollectionResponse,
)
def collect_and_evaluate_repository_changes(
    request: ChangePolicyCollectionRequest,
    service: ChangePolicyService = Depends(
        get_change_policy_service
    ),
) -> ChangePolicyCollectionResponse:
    """
    Collect staged or uncommitted Git changes and return
    a deterministic ALLOW, REVIEW, or BLOCK decision.
    """
    try:
        return service.collect_and_evaluate(request)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc
    except RuntimeError as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                "Repository changes could not be "
                "collected and evaluated."
            ),
        ) from exc
