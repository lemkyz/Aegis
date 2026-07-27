from __future__ import annotations

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
from aegis.orchestrator.security_task_model_handlers import (
    ModelConsensusTaskHandler,
    PrimaryModelReviewTaskHandler,
    VerifierReviewTaskHandler,
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
from aegis.security.orchestrator import (
    SecurityScannerOrchestrator,
)
from aegis.security.secrets import (
    SecretIntelligenceEngine,
)
from aegis.orchestrator.security_task_handler import (
    SecurityTaskHandlerContractError,
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
