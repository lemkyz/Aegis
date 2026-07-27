from __future__ import annotations

import difflib
from pathlib import Path, PurePosixPath
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
from aegis.schemas.change_policy import (
    ChangePolicyEvaluationRequest,
)
from aegis.schemas.changes import (
    ChangeFile,
    ChangeSet,
)
from aegis.schemas.fixes import (
    AppliedPatchArtifact,
    SecureFixRequest,
    StaticSecurityDeltaEvidence,
    StaticFixVerificationArtifact,
    StaticFixVerificationRequest,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
)
from aegis.schemas.validation import FixProjectCheck
from aegis.security.change_policy import (
    ChangeAwarePolicyEngine,
)
from aegis.security.redaction import (
    RedactionSession,
    SecretRedactor,
)
from aegis.security.secure_fix import (
    SecureFixTransactionError,
    SecureFixTransactionStore,
)


class SecureFixTaskHandler:
    handler = "aegis-secure-fix-task-handler-v1"

    capability = SecurityTaskHandlerCapability(
        kind="secure_fix",
        required_artifacts=frozenset({
            "repository_context",
        }),
        produced_artifacts=frozenset({
            "applied_patch",
        }),
        supports_retry=False,
        max_attempts=1,
        side_effect_free=False,
    )

    def __init__(
        self,
        *,
        transactions: SecureFixTransactionStore,
        policy_engine: ChangeAwarePolicyEngine
        | None = None,
        redactor: SecretRedactor
        | None = None,
        max_file_bytes: int = 2_000_000,
    ) -> None:
        if max_file_bytes < 1:
            raise ValueError(
                "max_file_bytes must be at least one."
            )

        self._transactions = transactions
        self._policy_engine = (
            policy_engine
            if policy_engine is not None
            else ChangeAwarePolicyEngine()
        )
        self._redactor = (
            redactor
            if redactor is not None
            else SecretRedactor()
        )
        self._max_file_bytes = max_file_bytes

    async def execute(
        self,
        *,
        task: SecurityTaskNode,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> SecurityTaskHandlerResult:
        del task

        context.raise_if_cancelled()

        if context.operation != "fix_and_verify":
            raise SecurityTaskInputError(
                "Secure fix only supports the "
                "fix_and_verify operation."
            )

        repository_root = (
            self._repository_root(
                context=context,
                inputs=inputs,
            )
        )
        request = self._request(context)
        proposal = request.proposal
        patch_sha256 = (
            proposal.patch_sha256()
        )

        if not request.approval.confirmed:
            raise SecurityTaskInputError(
                "Secure fix requires explicit human "
                "approval."
            )

        if (
            request.approval
            .approved_patch_sha256
            != patch_sha256
        ):
            raise SecurityTaskInputError(
                "Human approval does not match the "
                "exact proposed patch."
            )

        self._require_safe_replacement(
            proposal.replacement
        )
        target = self._target(
            repository_root=repository_root,
            target_path=proposal.target_path,
        )
        original_bytes = (
            self._read_target(target)
        )
        before_sha256 = (
            self._transactions.digest(
                original_bytes
            )
        )

        if before_sha256 != (
            proposal.expected_file_sha256
        ):
            raise SecurityTaskInputError(
                "The target changed after analysis; "
                "refusing to apply a stale patch."
            )

        try:
            original_text = (
                original_bytes.decode("utf-8")
            )
        except UnicodeDecodeError as exc:
            raise SecurityTaskInputError(
                "Secure fix only supports UTF-8 "
                "text files."
            ) from exc

        if proposal.end_offset > len(
            original_text
        ):
            raise SecurityTaskInputError(
                "The approved patch range exceeds "
                "the current target."
            )

        selected = original_text[
            proposal.start_offset:
            proposal.end_offset
        ]
        selected_sha256 = (
            self._transactions.digest(
                selected.encode("utf-8")
            )
        )

        if selected_sha256 != (
            proposal.expected_selection_sha256
        ):
            raise SecurityTaskInputError(
                "The selected source changed after "
                "analysis; refusing to apply the "
                "patch."
            )

        updated_text = (
            original_text[
                :proposal.start_offset
            ]
            + proposal.replacement
            + original_text[
                proposal.end_offset:
            ]
        )

        if updated_text == original_text:
            raise SecurityTaskInputError(
                "The proposed patch does not change "
                "the target."
            )

        updated_bytes = updated_text.encode(
            "utf-8"
        )
        policy = self._evaluate_policy(
            repository_root=repository_root,
            target_path=proposal.target_path,
            original=original_text,
            updated=updated_text,
        )

        if policy.decision == "block":
            raise SecurityTaskInputError(
                "Deterministic change policy blocked "
                "the proposed patch."
            )

        context.raise_if_cancelled()

        file_mode = target.stat().st_mode
        transaction = (
            self._transactions.begin(
                target=target,
                original_content=original_bytes,
                updated_content=updated_bytes,
                file_mode=file_mode,
            )
        )

        try:
            self._transactions.atomic_write(
                target,
                updated_bytes,
                file_mode=file_mode,
            )

            if (
                self._transactions.digest(
                    target.read_bytes()
                )
                != transaction.after_sha256
            ):
                raise SecureFixTransactionError(
                    "The applied patch hash could "
                    "not be verified."
                )

            context.raise_if_cancelled()
        except Exception:
            try:
                self._transactions.rollback(
                    transaction.transaction_id,
                    expected_target=target,
                    expected_after_sha256=(
                        transaction.after_sha256
                    ),
                )
            except Exception:
                self._transactions.discard(
                    transaction.transaction_id
                )

            raise

        artifact = AppliedPatchArtifact(
            handler=self.handler,
            transaction_id=(
                transaction.transaction_id
            ),
            claim_id=proposal.claim_id,
            target_path=proposal.target_path,
            approval_id=(
                request.approval.approval_id
            ),
            patch_sha256=patch_sha256,
            before_sha256=(
                transaction.before_sha256
            ),
            after_sha256=(
                transaction.after_sha256
            ),
            changed_characters=(
                len(selected)
                + len(proposal.replacement)
            ),
            policy=policy,
            transaction_state="pending",
            outputs_redacted=True,
        )

        return SecurityTaskHandlerResult(
            output={
                "applied_patch": (
                    artifact.model_dump(
                        mode="json"
                    )
                ),
            },
            metadata={
                "handler": self.handler,
                "claim_id": proposal.claim_id,
                "target_path": (
                    proposal.target_path
                ),
                "patch_sha256": patch_sha256,
                "policy_decision": (
                    policy.decision
                ),
                "transaction_state": "pending",
                "outputs_redacted": True,
            },
            reasons=(
                (
                    "The exact human-approved patch "
                    "digest was revalidated."
                ),
                (
                    "The target and selected source "
                    "hashes matched the analysis "
                    "baseline."
                ),
                (
                    "The patch was written atomically "
                    "and retained rollback material "
                    "only in process memory."
                ),
            ),
        )

    @staticmethod
    def _request(
        context: SecurityTaskHandlerContext,
    ) -> SecureFixRequest:
        value = context.metadata.get(
            "secure_fix_request"
        )

        try:
            return SecureFixRequest.model_validate(
                value
            )
        except ValidationError as exc:
            raise SecurityTaskInputError(
                "Secure fix requires a valid "
                "metadata['secure_fix_request'] "
                "contract."
            ) from exc

    @staticmethod
    def _repository_root(
        *,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> Path:
        repository = inputs.get(
            "repository_context"
        )

        if not isinstance(
            repository,
            Mapping,
        ):
            raise SecurityTaskInputError(
                "Secure fix requires repository "
                "context provenance."
            )

        context_root = (
            context.repository_root
        )
        artifact_root = repository.get(
            "repository_root"
        )

        if (
            not isinstance(context_root, str)
            or not isinstance(artifact_root, str)
        ):
            raise SecurityTaskInputError(
                "Secure fix requires an active "
                "repository root."
            )

        try:
            active_root = Path(
                context_root
            ).expanduser().resolve(
                strict=True
            )
            proven_root = Path(
                artifact_root
            ).expanduser().resolve(
                strict=True
            )
        except OSError as exc:
            raise SecurityTaskInputError(
                "The active repository root could "
                "not be resolved."
            ) from exc

        if (
            active_root != proven_root
            or not active_root.is_dir()
        ):
            raise SecurityTaskInputError(
                "Repository context does not match "
                "the active repository."
            )

        return active_root

    @staticmethod
    def _target(
        *,
        repository_root: Path,
        target_path: str,
    ) -> Path:
        relative = PurePosixPath(
            target_path
        )
        candidate = repository_root.joinpath(
            *relative.parts
        )

        current = repository_root

        for part in relative.parts:
            current = current / part

            if current.is_symlink():
                raise SecurityTaskInputError(
                    "Secure fix refuses symbolic-link "
                    "targets."
                )

        try:
            resolved = candidate.resolve(
                strict=True
            )
            resolved.relative_to(
                repository_root
            )
        except (
            OSError,
            ValueError,
        ) as exc:
            raise SecurityTaskInputError(
                "The secure-fix target must remain "
                "inside the active repository."
            ) from exc

        if not resolved.is_file():
            raise SecurityTaskInputError(
                "The secure-fix target must be a "
                "regular file."
            )

        return resolved

    def _read_target(
        self,
        target: Path,
    ) -> bytes:
        try:
            size = target.stat().st_size
        except OSError as exc:
            raise SecurityTaskInputError(
                "The secure-fix target cannot be "
                "inspected."
            ) from exc

        if size > self._max_file_bytes:
            raise SecurityTaskInputError(
                "The secure-fix target exceeds the "
                "configured size limit."
            )

        try:
            return target.read_bytes()
        except OSError as exc:
            raise SecurityTaskInputError(
                "The secure-fix target cannot be "
                "read."
            ) from exc

    def _require_safe_replacement(
        self,
        replacement: str,
    ) -> None:
        session = (
            self._redactor.create_session()
        )
        redacted = session.redact_text(
            replacement
        )

        if (
            redacted != replacement
            or session.contains_placeholder(
                replacement
            )
        ):
            raise SecurityTaskInputError(
                "Secure fix refuses patches that "
                "contain secrets or redaction "
                "placeholders."
            )

    def _evaluate_policy(
        self,
        *,
        repository_root: Path,
        target_path: str,
        original: str,
        updated: str,
    ):
        patch = "".join(
            difflib.unified_diff(
                original.splitlines(
                    keepends=True
                ),
                updated.splitlines(
                    keepends=True
                ),
                fromfile=(
                    f"a/{target_path}"
                ),
                tofile=(
                    f"b/{target_path}"
                ),
            )
        )
        additions = sum(
            line.startswith("+")
            and not line.startswith("+++")
            for line in patch.splitlines()
        )
        deletions = sum(
            line.startswith("-")
            and not line.startswith("---")
            for line in patch.splitlines()
        )
        change = ChangeFile(
            path=target_path,
            status="modified",
            patch=patch,
            additions=additions,
            deletions=deletions,
        )
        change_set = ChangeSet(
            collector=self.handler,
            repository_root=str(
                repository_root
            ),
            mode="uncommitted",
            files=[change],
            file_count=1,
            additions=additions,
            deletions=deletions,
        )

        return self._policy_engine.evaluate(
            ChangePolicyEvaluationRequest(
                change_set=change_set,
            )
        )


class FixVerificationTaskHandler:
    handler = (
        "aegis-fix-verification-task-handler-v1"
    )

    capability = SecurityTaskHandlerCapability(
        kind="fix_verification",
        required_artifacts=frozenset({
            "applied_patch",
        }),
        produced_artifacts=frozenset({
            "fix_verification_result",
        }),
        supports_retry=False,
        max_attempts=1,
        side_effect_free=False,
    )

    def __init__(
        self,
        *,
        transactions: SecureFixTransactionStore,
        redactor: SecretRedactor
        | None = None,
    ) -> None:
        self._transactions = transactions
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

        applied = self._applied_patch(
            inputs
        )
        target = self._target(
            context=context,
            applied=applied,
        )
        request = self._guarded_request(
            context=context,
            applied=applied,
            target=target,
        )
        redaction_session = (
            self._redactor.create_session()
        )
        checks = self._redact_checks(
            request.project_checks,
            session=redaction_session,
        )
        security_delta = self._redact_delta(
            request.security_delta,
            session=redaction_session,
        )
        failed_checks = [
            check.name
            for check in checks
            if check.status == "failed"
        ]
        static_target_resolved = not (
            request.security_delta
            .remaining_target_finding_ids
        )
        static_regression_free = not (
            request.security_delta
            .introduced_finding_ids
        )
        hard_failure = bool(
            failed_checks
            or not static_target_resolved
            or not static_regression_free
        )
        reasons: list[str] = []

        if failed_checks:
            reasons.append(
                "Project verification failed: "
                + ", ".join(failed_checks)
                + "."
            )

        if not static_target_resolved:
            reasons.append(
                "The target finding remains after "
                "the patch."
            )

        if not static_regression_free:
            reasons.append(
                "The patch introduced a new static "
                "security regression."
            )

        if hard_failure:
            transaction_state = (
                self._rollback(
                    applied=applied,
                    target=target,
                    reasons=reasons,
                )
            )
            verdict = "failed"
            ready_for_dynamic = False

        elif request.requires_dynamic_replay:
            self._require_pending(
                applied=applied,
                target=target,
            )
            transaction_state = "pending"
            verdict = "awaiting_dynamic"
            ready_for_dynamic = True
            reasons.append(
                "Static and project verification "
                "passed; final proof awaits the "
                "authorized dynamic replay."
            )

        else:
            transaction_state = (
                self._finalize(
                    applied=applied,
                    target=target,
                )
            )
            verdict = "partial"
            ready_for_dynamic = False
            reasons.append(
                "Static and project verification "
                "passed, but no dynamic replay was "
                "requested; the result is partial."
            )

        artifact = (
            StaticFixVerificationArtifact(
                handler=self.handler,
                source_artifacts=[
                    "applied_patch",
                ],
                applied_patch=(
                    applied.model_copy(
                        deep=True,
                        update={
                            "transaction_state": (
                                transaction_state
                            ),
                        },
                    )
                ),
                verifier=(
                    redaction_session
                    .redact_text(
                        request.verifier
                    )
                    or request.verifier
                ),
                project_checks=checks,
                security_delta=security_delta,
                static_target_resolved=(
                    static_target_resolved
                ),
                static_regression_free=(
                    static_regression_free
                ),
                verdict=verdict,
                ready_for_dynamic=(
                    ready_for_dynamic
                ),
                transaction_state=(
                    transaction_state
                ),
                reasons=self._redact_texts(
                    reasons,
                    session=(
                        redaction_session
                    ),
                ),
                outputs_redacted=True,
            )
        )

        return SecurityTaskHandlerResult(
            output={
                "fix_verification_result": (
                    artifact.model_dump(
                        mode="json"
                    )
                ),
            },
            metadata={
                "handler": self.handler,
                "claim_id": applied.claim_id,
                "verdict": verdict,
                "ready_for_dynamic": (
                    ready_for_dynamic
                ),
                "transaction_state": (
                    transaction_state
                ),
                "outputs_redacted": True,
            },
            reasons=tuple(
                artifact.reasons
            ),
        )

    def _guarded_request(
        self,
        *,
        context: SecurityTaskHandlerContext,
        applied: AppliedPatchArtifact,
        target: Path,
    ) -> StaticFixVerificationRequest:
        try:
            if (
                context.operation
                != "fix_and_verify"
            ):
                raise SecurityTaskInputError(
                    "Fix verification only supports "
                    "the fix_and_verify operation."
                )

            context.raise_if_cancelled()
            request = self._request(
                context
            )

            if request.claim_id != (
                applied.claim_id
            ):
                raise SecurityTaskInputError(
                    "Fix-verification claim identity "
                    "does not match the applied "
                    "patch."
                )

            return request

        except Exception as exc:
            try:
                self._transactions.rollback(
                    applied.transaction_id,
                    expected_target=target,
                    expected_after_sha256=(
                        applied.after_sha256
                    ),
                )
            except SecureFixTransactionError as rollback_exc:
                raise SecurityTaskInputError(
                    "Fix verification could not start "
                    "and automatic rollback was "
                    f"blocked: {rollback_exc}"
                ) from exc

            raise

    @staticmethod
    def _applied_patch(
        inputs: Mapping[str, Any],
    ) -> AppliedPatchArtifact:
        value = inputs.get(
            "applied_patch"
        )

        try:
            return (
                AppliedPatchArtifact
                .model_validate(value)
            )
        except ValidationError as exc:
            raise SecurityTaskInputError(
                "Fix verification requires a valid "
                "applied_patch artifact."
            ) from exc

    @staticmethod
    def _request(
        context: SecurityTaskHandlerContext,
    ) -> StaticFixVerificationRequest:
        value = context.metadata.get(
            "static_fix_verification_request"
        )

        try:
            return (
                StaticFixVerificationRequest
                .model_validate(value)
            )
        except ValidationError as exc:
            raise SecurityTaskInputError(
                "Fix verification requires a valid "
                "metadata['static_fix_verification_"
                "request'] contract."
            ) from exc

    @staticmethod
    def _target(
        *,
        context: SecurityTaskHandlerContext,
        applied: AppliedPatchArtifact,
    ) -> Path:
        repository_root = (
            context.repository_root
        )

        if not isinstance(
            repository_root,
            str,
        ):
            raise SecurityTaskInputError(
                "Fix verification requires the active "
                "repository root."
            )

        try:
            root = Path(
                repository_root
            ).expanduser().resolve(
                strict=True
            )
            target = root.joinpath(
                *PurePosixPath(
                    applied.target_path
                ).parts
            ).resolve(strict=True)
            target.relative_to(root)
        except (
            OSError,
            ValueError,
        ) as exc:
            raise SecurityTaskInputError(
                "The applied patch target no longer "
                "matches the active repository."
            ) from exc

        return target

    def _require_pending(
        self,
        *,
        applied: AppliedPatchArtifact,
        target: Path,
    ) -> None:
        try:
            self._transactions.verify_pending(
                applied.transaction_id,
                expected_target=target,
                expected_after_sha256=(
                    applied.after_sha256
                ),
            )
        except SecureFixTransactionError as exc:
            raise SecurityTaskInputError(
                "The applied patch changed before "
                f"verification completed: {exc}"
            ) from exc

    def _rollback(
        self,
        *,
        applied: AppliedPatchArtifact,
        target: Path,
        reasons: list[str],
    ) -> str:
        try:
            self._transactions.rollback(
                applied.transaction_id,
                expected_target=target,
                expected_after_sha256=(
                    applied.after_sha256
                ),
            )
        except SecureFixTransactionError as exc:
            reasons.append(
                "Automatic rollback was blocked: "
                f"{exc}"
            )
            return "rollback_blocked"

        reasons.append(
            "The original source was restored "
            "automatically."
        )
        return "rolled_back"

    def _finalize(
        self,
        *,
        applied: AppliedPatchArtifact,
        target: Path,
    ) -> str:
        try:
            self._transactions.finalize(
                applied.transaction_id,
                expected_target=target,
                expected_after_sha256=(
                    applied.after_sha256
                ),
            )
        except SecureFixTransactionError as exc:
            raise SecurityTaskInputError(
                "The applied patch changed before "
                f"verification completed: {exc}"
            ) from exc

        return "committed"

    def _redact_checks(
        self,
        checks: list[FixProjectCheck],
        *,
        session: RedactionSession,
    ) -> list[FixProjectCheck]:
        return [
            check.model_copy(
                deep=True,
                update={
                    "name": (
                        session.redact_text(
                            check.name
                        )
                        or check.name
                    ),
                    "details": (
                        session.redact_text(
                            check.details
                        )
                        or ""
                    ),
                },
            )
            for check in checks
        ]

    @staticmethod
    def _redact_delta(
        delta: StaticSecurityDeltaEvidence,
        *,
        session: RedactionSession,
    ) -> StaticSecurityDeltaEvidence:
        return delta.model_copy(
            deep=True,
            update={
                "scanner": (
                    session.redact_text(
                        delta.scanner
                    )
                    or delta.scanner
                ),
                "target_finding_ids": [
                    session.redact_text(value)
                    or value
                    for value
                    in delta.target_finding_ids
                ],
                "remaining_target_finding_ids": [
                    session.redact_text(value)
                    or value
                    for value
                    in (
                        delta
                        .remaining_target_finding_ids
                    )
                ],
                "introduced_finding_ids": [
                    session.redact_text(value)
                    or value
                    for value
                    in (
                        delta
                        .introduced_finding_ids
                    )
                ],
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
