from __future__ import annotations
from collections.abc import Callable

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Protocol

from pydantic import ValidationError

from aegis.orchestrator.security_task_handler import (
    SecurityTaskHandlerCapability,
    SecurityTaskHandlerContext,
    SecurityTaskHandlerResult,
)
from aegis.orchestrator.security_task_handlers import (
    SecurityTaskInputError,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
)
from aegis.schemas.fixes import (
    RemediationLifecycleOutcome,
    StaticFixVerificationArtifact,
)
from aegis.schemas.validation import (
    DynamicValidationEvidenceRequest,
    DynamicValidationTaskArtifact,
    UnifiedFixVerificationRequest,
    UnifiedFixVerificationResponse,
    ValidationExecutionResult,
    ValidationExecutionPlanResponse,
    ValidationReplayCompareRequest,
    ValidationReplayRequest,
    ValidationReplayResponse,
)
from aegis.security.redaction import (
    RedactionSession,
    SecretRedactor,
)
from aegis.security.fix_verification import (
    UnifiedFixVerificationEvaluator,
)
from aegis.security.secure_fix import (
    SecureFixTransactionError,
    SecureFixTransactionStore,
)
from aegis.security.validation_plan import (
    ValidationPlanBuilder,
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


class ValidationReplayExecutor(Protocol):
    async def replay(
        self,
        request: ValidationReplayRequest,
    ) -> ValidationReplayResponse:
        ...


class RemediationOutcomeRecorder(Protocol):
    def save_outcome(
        self,
        outcome: RemediationLifecycleOutcome,
    ) -> RemediationLifecycleOutcome:
        ...


class DynamicValidationTaskHandler:
    handler = (
        "aegis-dynamic-validation-task-handler-v1"
    )

    capability = SecurityTaskHandlerCapability(
        kind="dynamic_validation",
        required_artifacts=frozenset({
            "fix_verification_result",
        }),
        produced_artifacts=frozenset({
            "dynamic_validation_evidence",
            "remediation_lifecycle_outcome",
        }),
        supports_retry=False,
        max_attempts=1,
        side_effect_free=False,
    )

    def __init__(
        self,
        *,
        planner: ValidationPlanBuilder
        | None = None,
        replay_orchestrator: (
            ValidationReplayExecutor
            | None
        ) = None,
        redactor: SecretRedactor
        | None = None,
        evaluator: DynamicValidationEvaluator
        | None = None,
        comparator: ValidationReplayComparator
        | None = None,
        fix_evaluator: (
            UnifiedFixVerificationEvaluator
            | None
        ) = None,
        transactions: (
            SecureFixTransactionStore
            | None
        ) = None,
        outcome_store: (
            RemediationOutcomeRecorder | None
        ) = None,
            outcome_store_provider: (
            Callable[[], RemediationOutcomeRecorder] | None
        ) = None,
    ) -> None:
        self._planner = (
            planner
            if planner is not None
            else ValidationPlanBuilder()
        )
        self._replay_orchestrator = (
            replay_orchestrator
            if replay_orchestrator is not None
            else ValidationReplayOrchestrator()
        )
        self._redactor = (
            redactor
            if redactor is not None
            else SecretRedactor()
        )
        self._evaluator = (
            evaluator
            if evaluator is not None
            else DynamicValidationEvaluator()
        )
        self._comparator = (
            comparator
            if comparator is not None
            else ValidationReplayComparator()
        )
        self._fix_evaluator = (
            fix_evaluator
            if fix_evaluator is not None
            else UnifiedFixVerificationEvaluator()
        )
        self._transactions = transactions
        self._outcome_store = outcome_store
        self._outcome_store_provider = (
            outcome_store_provider
        )

    async def execute(
        self,
        *,
        task: SecurityTaskNode,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> SecurityTaskHandlerResult:
        del task

        verification = (
            self._require_fix_verification(
                inputs
            )
        )
        (
            manifest_id,
            manifest_sha256,
            static_verification_sha256,
        ) = self._manifest_provenance(
            verification
        )
        fix_target = (
            self._fix_target(
                context=context,
                verification=verification,
            )
            if self._transactions is not None
            else Path(
                context.repository_root
                or "."
            )
        )
        transaction_active = (
            self._transactions is not None
        )

        try:
            if (
                context.operation
                != "fix_and_verify"
            ):
                raise SecurityTaskInputError(
                    "Dynamic validation only supports "
                    "the fix_and_verify operation."
                )

            context.raise_if_cancelled()
            request = self._replay_request(
                context
            )

            if request.claim_id != (
                verification
                .applied_patch
                .claim_id
            ):
                raise SecurityTaskInputError(
                    "Dynamic validation claim "
                    "identity does not match static "
                    "fix verification."
                )

            if self._transactions is not None:
                self._transactions.verify_pending(
                    verification
                    .applied_patch
                    .transaction_id,
                    expected_target=fix_target,
                    expected_after_sha256=(
                        verification
                        .applied_patch
                        .after_sha256
                    ),
                )

            execution_plan = (
                self._planner.build(
                    request.plan
                )
            )

            self._require_ready_plan(
                execution_plan
            )
            self._require_repository_target(
                context=context,
                execution_plan=(
                    execution_plan
                ),
            )

            replay = (
                await self._replay_orchestrator
                .replay(request)
            )

            context.raise_if_cancelled()

            self._require_replay_identity(
                request=request,
                replay=replay,
            )
            safe_replay = (
                self._reconcile_replay(
                    request=request,
                    replay=self._redact_replay(
                        replay
                    ),
                )
            )
            unified = (
                self._fix_evaluator.evaluate(
                    UnifiedFixVerificationRequest(
                        claim_id=(
                            verification
                            .applied_patch
                            .claim_id
                        ),
                        patch_sha256=(
                            verification
                            .applied_patch
                            .patch_sha256
                        ),
                        replay=(
                            safe_replay
                            .comparison
                        ),
                        project_checks=(
                            verification
                            .project_checks
                        ),
                        static_target_resolved=(
                            verification
                            .static_target_resolved
                        ),
                        static_regression_free=(
                            verification
                            .static_regression_free
                        ),
                    )
                )
            )
            transaction_state = (
                self._close_transaction(
                    verification=(
                        verification
                    ),
                    target=fix_target,
                    result=unified,
                )
            )
            transaction_active = False
            authorization = (
                execution_plan.authorization
            )

            artifact = (
                DynamicValidationTaskArtifact(
                    handler=self.handler,
                    source_artifacts=[
                        "fix_verification_result",
                    ],
                    manifest_id=manifest_id,
                    manifest_sha256=(
                        manifest_sha256
                    ),
                    static_verification_sha256=(
                        static_verification_sha256
                    ),
                    authorization=authorization,
                    execution_plan=(
                        execution_plan
                    ),
                    replay=safe_replay,
                    fix_verification=unified,
                    transaction_state=(
                        transaction_state
                    ),
                    outputs_redacted=True,
                )
            )
            outcome = None
            if transaction_state in {
                "committed",
                "rolled_back",
                "rollback_blocked",
            }:
                outcome = RemediationLifecycleOutcome(
                    manifest_id=artifact.manifest_id,
                    manifest_sha256=(
                        artifact.manifest_sha256
                    ),
                    static_verification_sha256=(
                        artifact.static_verification_sha256
                    ),
                    dynamic_validation_sha256=(
                        artifact.artifact_sha256()
                    ),
                    unified_verdict=(
                        artifact.fix_verification.verdict
                    ),
                    transaction_state=transaction_state,
                    residual_risk=(
                        artifact.fix_verification.residual_risk
                    ),
                )
            outcome_store = self._outcome_store
            if (
                outcome_store is None
                and self._outcome_store_provider
                is not None
            ):
                outcome_store = (
                    self._outcome_store_provider()
                )

            if (
                outcome is not None
                and outcome_store is not None
            ):
                outcome_store.save_outcome(
                    outcome
                )
            comparison = (
                safe_replay.comparison
            )

            return SecurityTaskHandlerResult(
                output={
                    "dynamic_validation_evidence": (
                        artifact.model_dump(
                            mode="json"
                        )
                    ),

                    **(
                        {
                            "remediation_lifecycle_outcome": (
                                outcome.model_dump(
                                    mode="json"
                                )
                            ),
                        }
                        if outcome is not None
                        else {}
                    ),
                },
                metadata={
                    "handler": self.handler,
                    "authorization_contract": (
                        authorization.contract
                    ),
                    "authorized": (
                        authorization.authorized
                    ),
                    "execution_allowed": (
                        authorization
                        .execution_allowed
                    ),
                    "network": (
                        execution_plan
                        .sandbox.network
                    ),
                    "read_only_root": (
                        execution_plan
                        .sandbox.read_only_root
                    ),
                    "read_only_mount": (
                        execution_plan.mounts[0]
                        .read_only
                    ),
                    "before_verdict": (
                        comparison.before_verdict
                    ),
                    "after_verdict": (
                        comparison.after_verdict
                    ),
                    "replay_verdict": (
                        comparison.verdict
                    ),
                    "fix_verdict": (
                        unified.verdict
                    ),
                    "verified": unified.verified,
                    "fixed": comparison.fixed,
                    "transaction_state": (
                        transaction_state
                    ),
                    "manifest_id": manifest_id,
                    "manifest_sha256": (
                        manifest_sha256
                    ),
                    "static_verification_sha256": (
                        static_verification_sha256
                    ),
                    "outputs_redacted": True,

                    "dynamic_validation_sha256": (
                        artifact.artifact_sha256()
                    ),
                    "outcome_sha256": (
                        outcome.outcome_sha256()
                        if outcome is not None
                        else None
                    ),
                },
                reasons=(
                    (
                        "Structured authorization and "
                        "repository scope were "
                        "revalidated immediately "
                        "before replay."
                    ),
                    (
                        "The same authorized "
                        "validation plan was replayed "
                        "inside a read-only, "
                        "network-disabled container "
                        "sandbox."
                    ),
                    (
                        "Unified fix-verification "
                        f"verdict: {unified.verdict}."
                    ),
                ),
            )

        except Exception as exc:
            if (
                transaction_active
                and self._transactions is not None
            ):
                try:
                    self._transactions.rollback(
                        verification
                        .applied_patch
                        .transaction_id,
                        expected_target=(
                            fix_target
                        ),
                        expected_after_sha256=(
                            verification
                            .applied_patch
                            .after_sha256
                        ),
                    )
                except SecureFixTransactionError as rollback_exc:
                    raise SecurityTaskInputError(
                        "Dynamic validation failed and "
                        "automatic rollback was "
                        f"blocked: {rollback_exc}"
                    ) from exc

            raise

    @staticmethod
    def _canonical_sha256(
        value: Mapping[str, Any],
    ) -> str:
        canonical = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(
            canonical
        ).hexdigest()

    @staticmethod
    def _manifest_provenance(
        verification: (
            StaticFixVerificationArtifact
        ),
    ) -> tuple[str, str, str]:
        manifest = (
            verification.remediation_manifest
        )
        manifest_sha256 = (
            verification.manifest_sha256
        )

        if (
            manifest is None
            or manifest_sha256 is None
        ):
            raise SecurityTaskInputError(
                "Dynamic validation requires "
                "manifest-bound static fix "
                "verification."
            )

        static_verification_sha256 = (
            DynamicValidationTaskHandler
            ._canonical_sha256(
                verification.model_dump(
                    mode="json"
                )
            )
        )

        return (
            manifest.manifest_id,
            manifest_sha256,
            static_verification_sha256,
        )

    @staticmethod
    def _require_fix_verification(
        inputs: Mapping[str, Any],
    ) -> StaticFixVerificationArtifact:
        value = inputs.get(
            "fix_verification_result"
        )

        try:
            artifact = (
                StaticFixVerificationArtifact
                .model_validate(value)
            )
        except ValidationError as exc:
            raise SecurityTaskInputError(
                "Dynamic validation requires a valid "
                "fix_verification_result artifact."
            ) from exc

        if (
            artifact.remediation_manifest is None
            or artifact.manifest_sha256 is None
        ):
            raise SecurityTaskInputError(
                "Dynamic validation requires "
                "manifest-bound static fix "
                "verification."
            )

        if (
            not artifact.ready_for_dynamic
            or artifact.verdict
            != "awaiting_dynamic"
            or artifact.transaction_state
            != "pending"
        ):
            raise SecurityTaskInputError(
                "Static fix verification is not "
                "ready for dynamic replay."
            )

        return artifact

    @staticmethod
    def _fix_target(
        *,
        context: SecurityTaskHandlerContext,
        verification: (
            StaticFixVerificationArtifact
        ),
    ) -> Path:
        repository_root = (
            context.repository_root
        )

        if not isinstance(
            repository_root,
            str,
        ):
            raise SecurityTaskInputError(
                "Dynamic validation requires the "
                "active repository root."
            )

        try:
            root = Path(
                repository_root
            ).expanduser().resolve(
                strict=True
            )
            target = root.joinpath(
                *PurePosixPath(
                    verification
                    .applied_patch
                    .target_path
                ).parts
            ).resolve(strict=True)
            target.relative_to(root)
        except (
            OSError,
            ValueError,
        ) as exc:
            raise SecurityTaskInputError(
                "The verified patch target no longer "
                "matches the active repository."
            ) from exc

        return target

    def _close_transaction(
        self,
        *,
        verification: (
            StaticFixVerificationArtifact
        ),
        target: Path,
        result: UnifiedFixVerificationResponse,
    ) -> str:
        if self._transactions is None:
            return (
                verification.transaction_state
            )

        applied = (
            verification.applied_patch
        )
        commit_allowed = (
            result.verified
            and result.verdict == "verified"
            and (
                result.residual_risk.status
                == "none_identified"
            )
            and result.claim_id == applied.claim_id
            and (
                result.patch_sha256
                == applied.patch_sha256
            )
        )

        try:
            if not commit_allowed:
                self._transactions.rollback(
                    applied.transaction_id,
                    expected_target=target,
                    expected_after_sha256=(
                        applied.after_sha256
                    ),
                )
                return "rolled_back"

            self._transactions.finalize(
                applied.transaction_id,
                expected_target=target,
                expected_after_sha256=(
                    applied.after_sha256
                ),
            )
            return "committed"

        except SecureFixTransactionError as exc:
            raise SecurityTaskInputError(
                "The secure-fix transaction could "
                f"not be closed safely: {exc}"
            ) from exc

    @staticmethod
    def _replay_request(
        context: SecurityTaskHandlerContext,
    ) -> ValidationReplayRequest:
        value = context.metadata.get(
            "validation_replay_request"
        )

        try:
            return (
                ValidationReplayRequest
                .model_validate(value)
            )
        except ValidationError as exc:
            raise SecurityTaskInputError(
                "Dynamic validation requires a valid "
                "metadata['validation_replay_request'] "
                "contract."
            ) from exc

    @staticmethod
    def _require_ready_plan(
        plan: ValidationExecutionPlanResponse,
    ) -> None:
        if plan.ready:
            return

        details = [
            *plan.denials,
            *plan.reasons,
        ]
        message = (
            " ".join(details)
            if details
            else (
                "The validation plan is not ready "
                "for execution."
            )
        )

        raise SecurityTaskInputError(
            "Dynamic validation was denied: "
            f"{message}"
        )

    @staticmethod
    def _require_repository_target(
        *,
        context: SecurityTaskHandlerContext,
        execution_plan: (
            ValidationExecutionPlanResponse
        ),
    ) -> None:
        repository_root = (
            context.repository_root
        )

        if repository_root is None:
            raise SecurityTaskInputError(
                "Dynamic validation requires the "
                "active repository root."
            )

        try:
            active_root = Path(
                repository_root
            ).expanduser().resolve(
                strict=True
            )
        except OSError as exc:
            raise SecurityTaskInputError(
                "The active repository root could "
                "not be resolved."
            ) from exc

        if not active_root.is_dir():
            raise SecurityTaskInputError(
                "The active repository root must be "
                "a directory."
            )

        if len(execution_plan.mounts) != 1:
            raise SecurityTaskInputError(
                "Dynamic validation requires exactly "
                "one read-only repository mount."
            )

        mount = execution_plan.mounts[0]
        authorized_root = Path(
            mount.source
        ).expanduser().resolve(
            strict=False
        )

        if (
            authorized_root != active_root
        ):
            raise SecurityTaskInputError(
                "The authorized validation target "
                "does not match the active "
                "repository root."
            )

        if (
            not mount.read_only
            or mount.target != "/workspace"
        ):
            raise SecurityTaskInputError(
                "Dynamic validation requires a "
                "read-only /workspace mount."
            )

        sandbox = execution_plan.sandbox

        if (
            not sandbox.read_only_root
            or sandbox.host_path_relabeling
            or sandbox.image_pull_policy
            != "never"
            or sandbox.network != "none"
            or sandbox.drop_capabilities
            != ["ALL"]
            or not sandbox.no_new_privileges
        ):
            raise SecurityTaskInputError(
                "Dynamic validation requires the "
                "hardened no-network sandbox policy."
            )

    def _redact_replay(
        self,
        replay: ValidationReplayResponse,
    ) -> ValidationReplayResponse:
        session = (
            self._redactor.create_session()
        )
        before_execution = (
            self._redact_execution(
                replay.before_execution,
                session=session,
            )
        )
        after_execution = (
            self._redact_execution(
                replay.after_execution,
                session=session,
            )
        )
        before_evidence = (
            replay.before_evidence.model_copy(
                deep=True,
                update={
                    "evidence": (
                        self._redact_texts(
                            replay
                            .before_evidence
                            .evidence,
                            session=session,
                        )
                    ),
                    "reasons": (
                        self._redact_texts(
                            replay
                            .before_evidence
                            .reasons,
                            session=session,
                        )
                    ),
                },
            )
        )
        after_evidence = (
            replay.after_evidence.model_copy(
                deep=True,
                update={
                    "evidence": (
                        self._redact_texts(
                            replay
                            .after_evidence
                            .evidence,
                            session=session,
                        )
                    ),
                    "reasons": (
                        self._redact_texts(
                            replay
                            .after_evidence
                            .reasons,
                            session=session,
                        )
                    ),
                },
            )
        )
        comparison = (
            replay.comparison.model_copy(
                deep=True,
                update={
                    "reasons": (
                        self._redact_texts(
                            replay
                            .comparison.reasons,
                            session=session,
                        )
                    ),
                    "denials": (
                        self._redact_texts(
                            replay
                            .comparison.denials,
                            session=session,
                        )
                    ),
                },
            )
        )

        return replay.model_copy(
            deep=True,
            update={
                "before_execution": (
                    before_execution
                ),
                "before_evidence": (
                    before_evidence
                ),
                "after_execution": (
                    after_execution
                ),
                "after_evidence": (
                    after_evidence
                ),
                "comparison": comparison,
            },
        )

    def _require_replay_identity(
        self,
        *,
        request: ValidationReplayRequest,
        replay: ValidationReplayResponse,
    ) -> None:
        session = (
            self._redactor.create_session()
        )
        expected_baseline = (
            self._redact_execution(
                request.before_execution,
                session=session,
            )
        )
        observed_baseline = (
            self._redact_execution(
                replay.before_execution,
                session=session,
            )
        )

        if (
            replay.threat_id
            != request.threat_id
            or replay.claim_id
            != request.claim_id
            or replay.category
            != request.category
            or observed_baseline
            != expected_baseline
        ):
            raise SecurityTaskInputError(
                "Dynamic replay response does not "
                "match the authorized baseline "
                "identity."
            )

    def _reconcile_replay(
        self,
        *,
        request: ValidationReplayRequest,
        replay: ValidationReplayResponse,
    ) -> ValidationReplayResponse:
        before_evidence = (
            self._evaluator.evaluate(
                DynamicValidationEvidenceRequest(
                    threat_id=request.threat_id,
                    claim_id=request.claim_id,
                    category=request.category,
                    execution=(
                        replay.before_execution
                    ),
                    success_criteria=(
                        request.success_criteria
                    ),
                )
            )
        )
        after_evidence = (
            self._evaluator.evaluate(
                DynamicValidationEvidenceRequest(
                    threat_id=request.threat_id,
                    claim_id=request.claim_id,
                    category=request.category,
                    execution=(
                        replay.after_execution
                    ),
                    success_criteria=(
                        request.success_criteria
                    ),
                )
            )
        )
        comparison = self._comparator.compare(
            ValidationReplayCompareRequest(
                before=before_evidence,
                after=after_evidence,
            )
        )

        return replay.model_copy(
            deep=True,
            update={
                "before_evidence": (
                    before_evidence
                ),
                "after_evidence": (
                    after_evidence
                ),
                "comparison": comparison,
            },
        )

    @staticmethod
    def _redact_execution(
        execution: ValidationExecutionResult,
        *,
        session: RedactionSession,
    ) -> ValidationExecutionResult:
        return execution.model_copy(
            deep=True,
            update={
                "stdout": (
                    session.redact_text(
                        execution.stdout
                    )
                    or ""
                ),
                "stderr": (
                    session.redact_text(
                        execution.stderr
                    )
                    or ""
                ),
                "argv": (
                    DynamicValidationTaskHandler
                    ._redact_texts(
                        execution.argv,
                        session=session,
                    )
                ),
                "reasons": (
                    DynamicValidationTaskHandler
                    ._redact_texts(
                        execution.reasons,
                        session=session,
                    )
                ),
                "denials": (
                    DynamicValidationTaskHandler
                    ._redact_texts(
                        execution.denials,
                        session=session,
                    )
                ),
            },
        )

    @staticmethod
    def _redact_texts(
        values: list[str],
        *,
        session: RedactionSession,
    ) -> list[str]:
        return [
            session.redact_text(value)
            or value
            for value in values
        ]
