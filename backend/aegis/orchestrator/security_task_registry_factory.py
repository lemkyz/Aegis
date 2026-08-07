from __future__ import annotations

from aegis.orchestrator.security_task_attack_graph_handler import (
    AttackGraphTaskHandler,
)

from aegis.models.factory import (
    create_primary_fallback_model_client,
    create_primary_model_client,
    create_verifier_fallback_model_client,
    create_verifier_model_client,
)
from aegis.models.protocol import (
    SecurityModelClient,
    SecurityVerifierClient,
)
from aegis.orchestrator.security_task_handler import (
    SecurityTaskHandlerRegistry,
)
from aegis.orchestrator.security_task_handlers import (
    DeterministicScanTaskHandler,
    RepositoryContextTaskHandler,
)
from aegis.orchestrator.security_task_dynamic_validation_handler import (
    DynamicValidationTaskHandler,
    ValidationReplayExecutor,
    RemediationOutcomeRecorder,
)
from aegis.orchestrator.security_task_fix_handlers import (
    FixVerificationTaskHandler,
    SecureFixTaskHandler,
)
from aegis.orchestrator.security_task_model_handlers import (
    ModelConsensusTaskHandler,
    PrimaryModelReviewTaskHandler,
    VerifierReviewTaskHandler,
)
from aegis.orchestrator.security_task_memory_handlers import (
    PolicyEvaluationTaskHandler,
    SecurityMemoryRecorder,
    SecurityMemoryTaskHandler,
)
from aegis.orchestrator.security_task_specialist_handlers import (
    AttackSurfaceTaskHandler,
    DependencyScanTaskHandler,
    DependencyScanner,
    SecretAnalysisTaskHandler,
)
from aegis.orchestrator.security_task_threat_model_handler import (
    ThreatModelTaskHandler,
)
from aegis.security.attack_surface import (
    AttackSurfaceMapper,
)
from aegis.security.config_secrets import (
    ConfigSecretScanner,
)
from aegis.security.project_identity import (
    ProjectIdentityResolver,
)
from aegis.security.model_consensus import (
    ModelConsensusEvaluator,
)
from aegis.security.model_route_policy import (
    ModelRoutePolicy,
)
from aegis.security.memory_policy import (
    MemoryAwarePolicyEngine,
)
from aegis.security.orchestrator import (
    SecurityScannerOrchestrator,
)
from aegis.security.secrets import (
    SecretIntelligenceEngine,
)
from aegis.security.threat_model import ThreatModeler
from aegis.security.validation_plan import (
    ValidationPlanBuilder,
)
from aegis.security.change_policy import (
    ChangeAwarePolicyEngine,
)
from aegis.security.secure_fix import (
    SecureFixTransactionStore,
)
from aegis.orchestrator.security_task_handler import (
    SecurityTaskHandlerContractError,
)
from aegis.dependencies import (
    get_remediation_outcome_store,
)


def create_deep_analysis_security_task_registry(
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
    config_secret_scanner: (
        ConfigSecretScanner
        | None
    ) = None,
    dependency_scanner: (
        DependencyScanner
        | None
    ) = None,
    attack_surface_mapper: (
        AttackSurfaceMapper
        | None
    ) = None,
    threat_modeler: (
        ThreatModeler
        | None
    ) = None,
    validation_plan_builder: (
        ValidationPlanBuilder
        | None
    ) = None,
    validation_replay_orchestrator: (
        ValidationReplayExecutor
        | None
    ) = None,
    secure_fix_transaction_store: (
        SecureFixTransactionStore
        | None
    ) = None,
    change_policy_engine: (
        ChangeAwarePolicyEngine
        | None
    ) = None,
    security_memory_service: (
        SecurityMemoryRecorder
        | None
    ) = None,
    memory_policy_engine: (
        MemoryAwarePolicyEngine
        | None
    ) = None,
    primary_client: (
        SecurityModelClient
        | None
    ) = None,
    primary_fallback_client: (
        SecurityModelClient
        | None
    ) = None,
    verifier_client: (
        SecurityVerifierClient
        | None
    ) = None,
    verifier_fallback_client: (
        SecurityVerifierClient
        | None
    ) = None,
    consensus_evaluator: (
        ModelConsensusEvaluator
        | None
    ) = None,
    route_policy: (
        ModelRoutePolicy
        | None
    ) = None,
    remediation_outcome_store: (
        RemediationOutcomeRecorder | None
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

    resolved_primary_client = (
        primary_client
        if primary_client is not None
        else create_primary_model_client()
    )

    resolved_primary_fallback = (
        primary_fallback_client
        if primary_fallback_client is not None
        else create_primary_fallback_model_client()
    )

    resolved_verifier_client = (
        verifier_client
        if verifier_client is not None
        else create_verifier_model_client()
    )

    resolved_verifier_fallback = (
        verifier_fallback_client
        if verifier_fallback_client is not None
        else create_verifier_fallback_model_client()
    )

    resolved_consensus_evaluator = (
        consensus_evaluator
        or ModelConsensusEvaluator()
    )

    resolved_route_policy = (
        route_policy
        or ModelRoutePolicy()
    )
    resolved_fix_transactions = (
        secure_fix_transaction_store
        if secure_fix_transaction_store
        is not None
        else SecureFixTransactionStore()
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

    registry.register(
        SecretAnalysisTaskHandler(
            config_scanner=(
                config_secret_scanner
            ),
            secret_engine=secret_engine,
        )
    )

    registry.register(
        DependencyScanTaskHandler(
            scanner=dependency_scanner,
        )
    )

    registry.register(
        AttackSurfaceTaskHandler(
            mapper=attack_surface_mapper,
        )
    )

    registry.register(
        ThreatModelTaskHandler(
            modeler=threat_modeler,
        )
    )

    registry.register(
        AttackGraphTaskHandler()
    )

    registry.register(
        SecureFixTaskHandler(
            transactions=(
                resolved_fix_transactions
            ),
            policy_engine=(
                change_policy_engine
            ),
                    manifest_store=(
                remediation_outcome_store
            ),
            manifest_store_provider=(
                None
                if remediation_outcome_store
                is not None
                else get_remediation_outcome_store
            ),
        )
    )

    registry.register(
        FixVerificationTaskHandler(
            transactions=(
                resolved_fix_transactions
            ),
        )
    )

    registry.register(
        DynamicValidationTaskHandler(
            planner=validation_plan_builder,
            replay_orchestrator=(
                validation_replay_orchestrator
            ),
            transactions=(
                resolved_fix_transactions
            ),

            outcome_store=(
                remediation_outcome_store
            ),
            outcome_store_provider=(
                None
                if remediation_outcome_store
                is not None
                else get_remediation_outcome_store
            ),
        )
    )

    registry.register(
        SecurityMemoryTaskHandler(
            memory_service=(
                security_memory_service
            ),
        )
    )

    registry.register(
        PolicyEvaluationTaskHandler(
            policy_engine=(
                memory_policy_engine
            ),
        )
    )

    registry.register(
        PrimaryModelReviewTaskHandler(
            primary_client=(
                resolved_primary_client
            ),
            fallback_client=(
                resolved_primary_fallback
            ),
        )
    )

    registry.register(
        VerifierReviewTaskHandler(
            verifier_client=(
                resolved_verifier_client
            ),
            fallback_client=(
                resolved_verifier_fallback
            ),
        )
    )

    registry.register(
        ModelConsensusTaskHandler(
            evaluator=(
                resolved_consensus_evaluator
            ),
            route_policy=(
                resolved_route_policy
            ),
        )
    )

    registry.freeze()
    return registry
