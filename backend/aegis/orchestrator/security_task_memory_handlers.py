from __future__ import annotations

from aegis.schemas.attack_graph import (
    AttackGraphArtifact,
)
from aegis.schemas.attack_surface import (
    AttackSurfaceScanResponse,
)
from aegis.schemas.threat_model import (
    ThreatModelScanResponse,
)
from aegis.security.attack_graph import (
    AttackGraphBuilder,
)

from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from pydantic import ValidationError

from aegis.orchestrator.security_task_handler import (
    SecurityTaskHandlerCapability,
    SecurityTaskHandlerContext,
    SecurityTaskHandlerResult,
)
from aegis.orchestrator.security_task_handlers import (
    SecurityTaskInputError,
)
from aegis.schemas.claims import (
    CodeLocation,
    EvidenceItem,
    SecurityClaim,
)
from aegis.schemas.fixes import (
    RemediationLifecycleOutcome,
)
from aegis.schemas.memory import (
    ClaimReconciliationResponse,
    RepositoryContext,
    SecurityMemoryRecordRequest,
    SecurityMemoryRecordResponse,
    SecurityMemoryTaskArtifact,
    SecurityMemoryTaskInput,
)
from aegis.schemas.policy import (
    MemoryPolicyEvaluationRequest,
    SecurityPolicyTaskArtifact,
    SecurityPolicyTaskRequest,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
)
from aegis.schemas.validation import (
    DynamicValidationTaskArtifact,
)
from aegis.security.dynamic_claim_evidence import (
    apply_fix_verification,
)
from aegis.security.memory_policy import (
    MemoryAwarePolicyEngine,
)
from aegis.security.project_identity import (
    ProjectIdentityResolver,
)
from aegis.security.redaction import (
    RedactionSession,
    SecretRedactor,
)


class SecurityMemoryRecorder(Protocol):
    def record(
        self,
        request: SecurityMemoryRecordRequest,
    ) -> SecurityMemoryRecordResponse:
        ...


MemoryServiceProvider = Callable[
    [],
    SecurityMemoryRecorder,
]


def _default_memory_service(
) -> SecurityMemoryRecorder:
    from aegis.dependencies import (
        get_security_memory_service,
    )

    return get_security_memory_service()


_MEMORY_SOURCE_ARTIFACTS = frozenset({
    "scanner_coverage",
    "scanner_evidence",
    "primary_findings",
    "consensus_decisions",
    "consensus_claims",
    "threat_model",
    "secret_findings",
    "dependency_findings",
    "attack_surface_graph",
    "attack_graph",
    "applied_patch",
    "fix_verification_result",
    "dynamic_validation_evidence",
    "remediation_lifecycle_outcome",
})


class SecurityMemoryTaskHandler:
    handler = (
        "aegis-security-memory-task-handler-v1"
    )

    capability = SecurityTaskHandlerCapability(
        kind="security_memory",
        required_artifacts=frozenset({
            "repository_context",
        }),
        optional_artifacts=(
            _MEMORY_SOURCE_ARTIFACTS
        ),
        produced_artifacts=frozenset({
            "security_snapshot",
        }),
        supports_retry=False,
        max_attempts=1,
        side_effect_free=False,
    )

    def __init__(
        self,
        *,
        memory_service: (
            SecurityMemoryRecorder
            | None
        ) = None,
        memory_service_provider: (
            MemoryServiceProvider
            | None
        ) = None,
        redactor: SecretRedactor
        | None = None,
        identity_resolver: (
            ProjectIdentityResolver
            | None
        ) = None,
    ) -> None:
        if (
            memory_service is not None
            and memory_service_provider
            is not None
        ):
            raise ValueError(
                "Provide a memory service or provider, "
                "not both."
            )

        self._memory_service = memory_service
        self._memory_service_provider = (
            memory_service_provider
            if memory_service_provider
            is not None
            else _default_memory_service
        )
        self._redactor = (
            redactor
            if redactor is not None
            else SecretRedactor()
        )
        self._identity = (
            identity_resolver
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

        context.raise_if_cancelled()

        request = self._request(context)

        if request.analysis_status != "complete":
            raise SecurityTaskInputError(
                "Security memory refuses partial or "
                "failed analysis results."
            )

        self._require_sources(
            request=request,
            inputs=inputs,
        )

        self._validate_attack_graph_provenance(
            request=request,
            inputs=inputs,
        )
        repository = self._repository(
            context=context,
            inputs=inputs,
        )
        claims = self._claims(
            request=request,
            inputs=inputs,
        )

        if (
            not claims
            and not request.allow_empty_snapshot
        ):
            raise SecurityTaskInputError(
                "An empty security snapshot requires "
                "an explicit complete-scan "
                "confirmation."
            )

        if any(
            claim.state == "verified_fixed"
            for claim in claims
        ):
            raise SecurityTaskInputError(
                "The verified_fixed state must be "
                "derived from fix-verification "
                "evidence, not supplied by the "
                "caller."
            )
        fix_verification_applied = False

        if (
            "dynamic_validation_evidence"
            in request.source_artifacts
        ):
            lifecycle_outcome_named = (
                "remediation_lifecycle_outcome"
                in request.source_artifacts
            )
            lifecycle_outcome_supplied = (
                "remediation_lifecycle_outcome"
                in inputs
            )

            if (
                lifecycle_outcome_named
                != lifecycle_outcome_supplied
            ):
                raise SecurityTaskInputError(
                    "Remediation lifecycle outcome "
                    "provenance must be named and "
                    "supplied together."
                )

            claims = self._apply_dynamic_fix(
                claims=claims,
                value=inputs[
                    "dynamic_validation_evidence"
                ],
                lifecycle_outcome_value=(
                    inputs.get(
                        "remediation_lifecycle_outcome"
                    )
                ),
            )
            fix_verification_applied = True

        safe_claims = self._redact_claims(
            claims
        )

        context.raise_if_cancelled()

        memory = self._service().record(
            SecurityMemoryRecordRequest(
                repository_path=(
                    repository.repository_root
                ),
                claims=safe_claims,
            )
        )

        if (
            memory.repository.project_id
            != repository.project_id
            or memory.repository.revision
            != repository.revision
            or Path(
                memory.repository.repository_root
            ).resolve()
            != Path(
                repository.repository_root
            ).resolve()
        ):
            raise SecurityTaskInputError(
                "Persisted security memory does not "
                "match repository provenance."
            )

        artifact = SecurityMemoryTaskArtifact(
            handler=self.handler,
            source_artifacts=list(
                request.source_artifacts
            ),
            analysis_status="complete",
            coverage=request.coverage,
            memory=memory,
            claims_recorded=len(
                memory.snapshot.claims
            ),
            fix_verification_applied=(
                fix_verification_applied
            ),
            outputs_redacted=True,
        )

        return SecurityTaskHandlerResult(
            output={
                "security_snapshot": (
                    artifact.model_dump(
                        mode="json"
                    )
                ),
            },
            metadata={
                "handler": self.handler,
                "project_id": (
                    memory.repository.project_id
                ),
                "snapshot_id": (
                    memory.snapshot.snapshot_id
                ),
                "claims_recorded": (
                    artifact.claims_recorded
                ),
                "baseline_created": (
                    memory.baseline_created
                ),
                "persisted_new_snapshot": (
                    memory.persisted_new_snapshot
                ),
                "fix_verification_applied": (
                    fix_verification_applied
                ),
                "outputs_redacted": True,
            },
            reasons=(
                (
                    "A complete, provenance-linked "
                    "security snapshot was recorded."
                ),
                (
                    "Security-memory snapshot ID: "
                    f"{memory.snapshot.snapshot_id}."
                ),
            ),
        )

    def _service(
        self,
    ) -> SecurityMemoryRecorder:
        if self._memory_service is None:
            self._memory_service = (
                self._memory_service_provider()
            )

        return self._memory_service

    @staticmethod
    def _request(
        context: SecurityTaskHandlerContext,
    ) -> SecurityMemoryTaskInput:
        value = context.metadata.get(
            "security_memory_input"
        )

        try:
            return (
                SecurityMemoryTaskInput
                .model_validate(value)
            )
        except ValidationError as exc:
            raise SecurityTaskInputError(
                "Security memory requires a valid "
                "metadata['security_memory_input'] "
                "contract."
            ) from exc

    @staticmethod
    def _require_sources(
        *,
        request: SecurityMemoryTaskInput,
        inputs: Mapping[str, Any],
    ) -> None:
        missing = [
            name
            for name
            in request.source_artifacts
            if name not in inputs
        ]

        if missing:
            raise SecurityTaskInputError(
                "Security-memory provenance is "
                "missing source artifact(s): "
                + ", ".join(sorted(missing))
                + "."
            )

        unsupported = [
            name
            for name
            in request.source_artifacts
            if name
            not in _MEMORY_SOURCE_ARTIFACTS
        ]

        if unsupported:
            raise SecurityTaskInputError(
                "Security-memory provenance contains "
                "unsupported source artifact(s): "
                + ", ".join(
                    sorted(unsupported)
                )
                + "."
            )

        if "consensus_decisions" in (
            request.source_artifacts
        ):
            consensus = inputs[
                "consensus_decisions"
            ]

            if (
                not isinstance(
                    consensus,
                    Mapping,
                )
                or consensus.get("status")
                != "completed"
            ):
                raise SecurityTaskInputError(
                    "Partial or failed model "
                    "consensus cannot become a clean "
                    "security-memory baseline."
                )

        if "scanner_coverage" in (
            request.source_artifacts
        ):
            coverage = inputs[
                "scanner_coverage"
            ]

            if (
                not isinstance(
                    coverage,
                    Mapping,
                )
                or coverage.get("status")
                != "completed"
                or coverage.get(
                    "coverage_complete"
                )
                is not True
            ):
                raise SecurityTaskInputError(
                    "Incomplete scanner coverage "
                    "cannot become a clean "
                    "security-memory baseline."
                )

        if "dependency_findings" in (
            request.source_artifacts
        ):
            dependency = inputs[
                "dependency_findings"
            ]
            scan = (
                dependency.get("scan")
                if isinstance(
                    dependency,
                    Mapping,
                )
                else None
            )

            if (
                not isinstance(scan, Mapping)
                or scan.get("scan_status")
                != "completed"
            ):
                raise SecurityTaskInputError(
                    "Incomplete dependency coverage "
                    "cannot become a clean "
                    "security-memory baseline."
                )

    @staticmethod
    def _claims(
        *,
        request: SecurityMemoryTaskInput,
        inputs: Mapping[str, Any],
    ) -> list[SecurityClaim]:
        if request.claims_artifact is None:
            return [
                claim.model_copy(deep=True)
                for claim in request.claims
            ]

        value = inputs.get(
            request.claims_artifact
        )

        if not isinstance(value, list):
            raise SecurityTaskInputError(
                "Security-memory claims artifact "
                "must be a list."
            )

        try:
            return [
                SecurityClaim.model_validate(
                    item
                )
                for item in value
            ]
        except ValidationError as exc:
            raise SecurityTaskInputError(
                "Security-memory claims artifact "
                "contains an invalid claim."
            ) from exc

    def _repository(
        self,
        *,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> RepositoryContext:
        value = inputs.get(
            "repository_context"
        )

        try:
            repository = (
                RepositoryContext.model_validate(
                    value
                )
            )
        except ValidationError as exc:
            raise SecurityTaskInputError(
                "Security memory requires valid "
                "repository provenance."
            ) from exc

        if context.repository_root is None:
            raise SecurityTaskInputError(
                "Security memory requires the active "
                "repository root."
            )

        try:
            active_root = Path(
                context.repository_root
            ).expanduser().resolve(
                strict=True
            )
            proven_root = Path(
                repository.repository_root
            ).expanduser().resolve(
                strict=True
            )
        except OSError as exc:
            raise SecurityTaskInputError(
                "Security-memory repository root "
                "could not be resolved."
            ) from exc

        if (
            active_root != proven_root
            or not active_root.is_dir()
        ):
            raise SecurityTaskInputError(
                "Security-memory repository "
                "provenance does not match the "
                "active repository."
            )

        current = self._identity.resolve(
            active_root
        )

        if (
            current.project_id
            != repository.project_id
            or current.revision
            != repository.revision
        ):
            raise SecurityTaskInputError(
                "Repository revision changed before "
                "security memory could be recorded."
            )

        return repository

    @staticmethod
    def _validate_attack_graph_provenance(
        *,
        request: SecurityMemoryTaskInput,
        inputs: Mapping[str, Any],
    ) -> None:
        if (
            "attack_graph"
            not in request.source_artifacts
        ):
            return

        required_sources = {
            "attack_surface_graph",
            "threat_model",
        }
        named_sources = set(
            request.source_artifacts
        )

        if not required_sources.issubset(
            named_sources
        ):
            raise SecurityTaskInputError(
                "Attack graph provenance requires "
                "attack_surface_graph and threat_model "
                "source artifacts."
            )

        try:
            attack_surface = (
                AttackSurfaceScanResponse
                .model_validate(
                    inputs.get(
                        "attack_surface_graph"
                    )
                )
            )
            threat_model = (
                ThreatModelScanResponse
                .model_validate(
                    inputs.get(
                        "threat_model"
                    )
                )
            )
            supplied = (
                AttackGraphArtifact
                .model_validate(
                    inputs.get(
                        "attack_graph"
                    )
                )
            )
        except ValidationError as exc:
            raise SecurityTaskInputError(
                "Attack graph provenance contains "
                "an invalid source artifact."
            ) from exc

        try:
            expected = (
                AttackGraphBuilder().build(
                    attack_surface=attack_surface,
                    threat_model=threat_model,
                )
            )
        except ValueError as exc:
            raise SecurityTaskInputError(
                "Attack graph provenance cannot be "
                "rebuilt from the named sources."
            ) from exc

        if (
            supplied != expected
            or supplied.artifact_sha256()
            != expected.artifact_sha256()
        ):
            raise SecurityTaskInputError(
                "Attack graph provenance does not "
                "match the exact attack surface and "
                "threat model."
            )


    @staticmethod
    def _apply_dynamic_fix(
        *,
        claims: list[SecurityClaim],
        value: Any,
        lifecycle_outcome_value: Any = None,
    ) -> list[SecurityClaim]:
        try:
            artifact = (
                DynamicValidationTaskArtifact
                .model_validate(value)
            )
        except ValidationError as exc:
            raise SecurityTaskInputError(
                "Dynamic fix provenance is invalid."
            ) from exc

        manifest_id = getattr(
            artifact,
            "manifest_id",
            None,
        )
        lifecycle_outcome: (
            RemediationLifecycleOutcome
            | None
        ) = None

        if manifest_id is not None:
            if lifecycle_outcome_value is None:
                raise SecurityTaskInputError(
                    "Manifest-aware dynamic fix "
                    "provenance requires the immutable "
                    "remediation lifecycle outcome."
                )

            try:
                lifecycle_outcome = (
                    RemediationLifecycleOutcome
                    .model_validate(
                        lifecycle_outcome_value
                    )
                )
            except ValidationError as exc:
                raise SecurityTaskInputError(
                    "Remediation lifecycle outcome "
                    "provenance is invalid."
                ) from exc

            (
                SecurityMemoryTaskHandler
                ._require_lifecycle_outcome_match(
                    artifact=artifact,
                    outcome=lifecycle_outcome,
                )
            )

        elif lifecycle_outcome_value is not None:
            raise SecurityTaskInputError(
                "Remediation lifecycle outcome cannot "
                "be attached to legacy dynamic "
                "provenance without a manifest."
            )

        claim_id = (
            artifact.fix_verification.claim_id
        )

        if claim_id is None:
            raise SecurityTaskInputError(
                "Dynamic fix verification is not "
                "linked to a security claim."
            )

        matches = [
            index
            for index, claim
            in enumerate(claims)
            if claim.claim_id == claim_id
        ]

        if len(matches) != 1:
            raise SecurityTaskInputError(
                "Dynamic fix verification must match "
                "exactly one current security claim."
            )

        updated = list(claims)
        index = matches[0]
        updated[index] = apply_fix_verification(
            updated[index],
            replay=artifact.replay.comparison,
            verification=(
                artifact.fix_verification
            ),
            lifecycle_outcome=(
                lifecycle_outcome
            ),
        )

        return updated

    @staticmethod
    def _require_lifecycle_outcome_match(
        *,
        artifact: DynamicValidationTaskArtifact,
        outcome: RemediationLifecycleOutcome,
    ) -> None:
        checks = (
            (
                outcome.manifest_id,
                artifact.manifest_id,
                "manifest identifier",
            ),
            (
                outcome.manifest_sha256,
                artifact.manifest_sha256,
                "manifest digest",
            ),
            (
                outcome.static_verification_sha256,
                artifact.static_verification_sha256,
                "static verification digest",
            ),
            (
                outcome.dynamic_validation_sha256,
                artifact.artifact_sha256(),
                "dynamic validation digest",
            ),
            (
                outcome.unified_verdict,
                artifact.fix_verification.verdict,
                "unified verdict",
            ),
            (
                outcome.transaction_state,
                artifact.transaction_state,
                "terminal transaction state",
            ),
            (
                outcome.residual_risk,
                artifact.fix_verification.residual_risk,
                "residual risk",
            ),
        )

        for observed, expected, label in checks:
            if observed != expected:
                raise SecurityTaskInputError(
                    "Remediation lifecycle outcome "
                    f"{label} does not match dynamic "
                    "validation provenance."
                )

    def _redact_claims(
        self,
        claims: list[SecurityClaim],
    ) -> list[SecurityClaim]:
        session = (
            self._redactor.create_session()
        )

        return [
            self._redact_claim(
                claim,
                session=session,
            )
            for claim in claims
        ]

    @classmethod
    def _redact_claim(
        cls,
        claim: SecurityClaim,
        *,
        session: RedactionSession,
    ) -> SecurityClaim:
        cls._require_safe_identity(
            claim.claim_id,
            session=session,
        )
        evidence = [
            cls._redact_evidence(
                item,
                session=session,
            )
            for item in claim.evidence
        ]
        for relationship in (
            claim.relationships
        ):
            for identity in (
                relationship.relationship_id,
                relationship.source_evidence_id,
                relationship.target_evidence_id,
            ):
                cls._require_safe_identity(
                    identity,
                    session=session,
                )

        relationships = [
            relationship.model_copy(
                deep=True,
                update={
                    "reason": (
                        session.redact_text(
                            relationship.reason
                        )
                    ),
                },
            )
            for relationship
            in claim.relationships
        ]
        redacted_patch = session.redact_text(
            claim.proposed_patch
        )

        if (
            redacted_patch
            and (
                redacted_patch
                != claim.proposed_patch
                or session.contains_placeholder(
                    redacted_patch
                )
            )
        ):
            redacted_patch = None

        return claim.model_copy(
            deep=True,
            update={
                "statement": (
                    session.redact_text(
                        claim.statement
                    )
                    or claim.statement
                ),
                "locations": [
                    cls._redact_location(
                        location,
                        session=session,
                    )
                    for location
                    in claim.locations
                ],
                "evidence": evidence,
                "relationships": (
                    relationships
                ),
                "remediation": (
                    session.redact_text(
                        claim.remediation
                    )
                ),
                "proposed_patch": (
                    redacted_patch
                ),
            },
        )

    @classmethod
    def _redact_evidence(
        cls,
        item: EvidenceItem,
        *,
        session: RedactionSession,
    ) -> EvidenceItem:
        cls._require_safe_identity(
            item.evidence_id,
            session=session,
        )
        source = item.source.model_copy(
            deep=True,
            update={
                "name": (
                    session.redact_text(
                        item.source.name
                    )
                    or item.source.name
                ),
                "rule_id": (
                    session.redact_text(
                        item.source.rule_id
                    )
                ),
                "version": (
                    session.redact_text(
                        item.source.version
                    )
                ),
            },
        )

        return item.model_copy(
            deep=True,
            update={
                "source": source,
                "summary": (
                    session.redact_text(
                        item.summary
                    )
                    or item.summary
                ),
                "details": [
                    session.redact_text(detail)
                    or detail
                    for detail
                    in item.details
                ],
                "locations": [
                    cls._redact_location(
                        location,
                        session=session,
                    )
                    for location
                    in item.locations
                ],
            },
        )

    @staticmethod
    def _redact_location(
        location: CodeLocation,
        *,
        session: RedactionSession,
    ) -> CodeLocation:
        return location.model_copy(
            deep=True,
            update={
                "file": (
                    session.redact_text(
                        location.file
                    )
                    or location.file
                ),
                "symbol": (
                    session.redact_text(
                        location.symbol
                    )
                ),
            },
        )

    @staticmethod
    def _require_safe_identity(
        value: str,
        *,
        session: RedactionSession,
    ) -> None:
        if session.redact_text(value) != value:
            raise SecurityTaskInputError(
                "Security-memory identity fields "
                "must not contain secrets."
            )


_POLICY_SOURCE_ARTIFACTS = (
    _MEMORY_SOURCE_ARTIFACTS
    | frozenset({
        "security_snapshot",
    })
)


class PolicyEvaluationTaskHandler:
    handler = (
        "aegis-policy-evaluation-task-handler-v1"
    )

    capability = SecurityTaskHandlerCapability(
        kind="policy_evaluation",
        optional_artifacts=(
            _POLICY_SOURCE_ARTIFACTS
        ),
        produced_artifacts=frozenset({
            "policy_decision",
        }),
        supports_retry=False,
        max_attempts=1,
        side_effect_free=True,
    )

    def __init__(
        self,
        *,
        policy_engine: (
            MemoryAwarePolicyEngine
            | None
        ) = None,
        redactor: SecretRedactor
        | None = None,
    ) -> None:
        self._policy_engine = (
            policy_engine
            if policy_engine is not None
            else MemoryAwarePolicyEngine()
        )
        self._redactor = (
            redactor
            if redactor is not None
            else SecretRedactor()
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

        request = self._request(
            context=context,
            inputs=inputs,
        )
        self._require_sources(
            request=request,
            inputs=inputs,
        )
        snapshot_id: str | None = None

        if "security_snapshot" in inputs:
            if (
                "security_snapshot"
                not in request.source_artifacts
            ):
                raise SecurityTaskInputError(
                    "Policy decisions derived from "
                    "security memory must name the "
                    "security_snapshot provenance "
                    "source."
                )

            try:
                memory_artifact = (
                    SecurityMemoryTaskArtifact
                    .model_validate(
                        inputs[
                            "security_snapshot"
                        ]
                    )
                )
            except ValidationError as exc:
                raise SecurityTaskInputError(
                    "Policy evaluation requires a "
                    "valid security_snapshot "
                    "artifact."
                ) from exc

            reconciliation = (
                memory_artifact
                .memory.reconciliation
            )
            snapshot_id = (
                memory_artifact
                .memory.snapshot.snapshot_id
            )

            if (
                request.reconciliation
                is not None
                and request.reconciliation
                != reconciliation
            ):
                raise SecurityTaskInputError(
                    "Policy reconciliation does not "
                    "match security-memory "
                    "provenance."
                )

        elif request.reconciliation is not None:
            reconciliation = (
                request.reconciliation
            )

        else:
            raise SecurityTaskInputError(
                "Policy evaluation requires security "
                "memory or an explicit reconciliation "
                "contract."
            )

        self._require_safe_reconciliation(
            reconciliation
        )
        decision = self._policy_engine.evaluate(
            MemoryPolicyEvaluationRequest(
                reconciliation=reconciliation,
                profile=request.profile,
            )
        )
        artifact = SecurityPolicyTaskArtifact(
            handler=self.handler,
            source_artifacts=list(
                request.source_artifacts
            ),
            snapshot_id=snapshot_id,
            decision=decision,
            outputs_redacted=True,
        )

        return SecurityTaskHandlerResult(
            output={
                "policy_decision": (
                    artifact.model_dump(
                        mode="json"
                    )
                ),
            },
            metadata={
                "handler": self.handler,
                "profile": decision.profile,
                "decision": decision.decision,
                "risk_score": (
                    decision.risk_score
                ),
                "risk_level": (
                    decision.risk_level
                ),
                "snapshot_id": snapshot_id,
                "outputs_redacted": True,
            },
            reasons=tuple(
                decision.reasons
            ),
        )

    def _require_safe_reconciliation(
        self,
        reconciliation: (
            ClaimReconciliationResponse
        ),
    ) -> None:
        session = (
            self._redactor.create_session()
        )

        for delta in reconciliation.deltas:
            identities = [
                delta.claim_id,
            ]

            if delta.previous_claim is not None:
                identities.append(
                    delta.previous_claim.claim_id
                )

            if delta.current_claim is not None:
                identities.append(
                    delta.current_claim.claim_id
                )

            if any(
                session.redact_text(identity)
                != identity
                for identity in identities
            ):
                raise SecurityTaskInputError(
                    "Policy claim identities must "
                    "not contain secrets."
                )

    @staticmethod
    def _request(
        *,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> SecurityPolicyTaskRequest:
        value = context.metadata.get(
            "security_policy_request"
        )

        if value is None:
            if "security_snapshot" not in inputs:
                raise SecurityTaskInputError(
                    "Policy evaluation requires a "
                    "security_policy_request when "
                    "security memory is disabled."
                )

            return SecurityPolicyTaskRequest(
                source_artifacts=[
                    "security_snapshot",
                ],
            )

        try:
            return (
                SecurityPolicyTaskRequest
                .model_validate(value)
            )
        except ValidationError as exc:
            raise SecurityTaskInputError(
                "Policy evaluation requires a valid "
                "metadata['security_policy_request'] "
                "contract."
            ) from exc

    @staticmethod
    def _require_sources(
        *,
        request: SecurityPolicyTaskRequest,
        inputs: Mapping[str, Any],
    ) -> None:
        if not request.source_artifacts:
            raise SecurityTaskInputError(
                "Policy evaluation requires at least "
                "one provenance source artifact."
            )

        unsupported = [
            name
            for name in request.source_artifacts
            if name
            not in _POLICY_SOURCE_ARTIFACTS
        ]
        missing = [
            name
            for name in request.source_artifacts
            if name not in inputs
        ]

        if unsupported:
            raise SecurityTaskInputError(
                "Policy provenance contains "
                "unsupported source artifact(s): "
                + ", ".join(
                    sorted(unsupported)
                )
                + "."
            )

        if missing:
            raise SecurityTaskInputError(
                "Policy provenance is missing source "
                "artifact(s): "
                + ", ".join(sorted(missing))
                + "."
            )
