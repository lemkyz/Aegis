from aegis.schemas.validation import (
    DynamicValidationEvidenceRequest,
    ValidationExecutionRequest,
    ValidationExecutionResult,
    ValidationReplayCompareRequest,
    ValidationReplayRequest,
    ValidationReplayResponse,
)
from aegis.security.redaction import (
    RedactionSession,
    SecretRedactor,
)
from aegis.security.validation_evidence import (
    DynamicValidationEvaluator,
)
from aegis.security.validation_replay import (
    ValidationReplayComparator,
)
from aegis.security.validation_runner import (
    ValidationRunner,
)


class ValidationReplayOrchestrator:
    orchestrator = (
        "aegis-dynamic-validation-"
        "replay-orchestrator-v1"
    )

    def __init__(
        self,
        *,
        runner: ValidationRunner | None = None,
        evaluator: DynamicValidationEvaluator | None = None,
        comparator: ValidationReplayComparator | None = None,
        redactor: SecretRedactor | None = None,
    ) -> None:
        self._runner = (
            runner
            if runner is not None
            else ValidationRunner()
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
        self._redactor = (
            redactor
            if redactor is not None
            else SecretRedactor()
        )

    async def replay(
        self,
        request: ValidationReplayRequest,
    ) -> ValidationReplayResponse:
        redaction_session = (
            self._redactor.create_session()
        )
        before_execution = (
            self._redact_execution(
                request.before_execution,
                session=redaction_session,
            )
        )
        before_evidence = self._evaluate(
            request=request,
            execution=before_execution,
        )

        if before_evidence.verdict != "confirmed":
            after_execution = (
                self._blocked_replay_execution()
            )
        else:
            raw_after_execution = (
                await self._runner.run(
                    ValidationExecutionRequest(
                        plan=request.plan,
                    )
                )
            )
            after_execution = (
                self._redact_execution(
                    raw_after_execution,
                    session=redaction_session,
                )
            )

        after_evidence = self._evaluate(
            request=request,
            execution=after_execution,
        )

        comparison = self._comparator.compare(
            ValidationReplayCompareRequest(
                before=before_evidence,
                after=after_evidence,
            )
        )

        return ValidationReplayResponse(
            orchestrator=self.orchestrator,
            threat_id=request.threat_id,
            claim_id=request.claim_id,
            category=request.category,
            before_execution=(
                before_execution
            ),
            before_evidence=before_evidence,
            after_execution=after_execution,
            after_evidence=after_evidence,
            comparison=comparison,
        )

    def _blocked_replay_execution(
        self,
    ) -> ValidationExecutionResult:
        return ValidationExecutionResult(
            runner=self._runner.runner,
            status="rejected",
            started=False,
            timed_out=False,
            duration_ms=0,
            reasons=[
                (
                    "Post-fix replay was not started "
                    "because the vulnerable baseline "
                    "was not dynamically confirmed."
                )
            ],
            denials=[
                (
                    "A confirmed before-fix baseline "
                    "is required for trustworthy "
                    "dynamic replay."
                )
            ],
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
                    ValidationReplayOrchestrator
                    ._redact_texts(
                        execution.argv,
                        session=session,
                    )
                ),
                "reasons": (
                    ValidationReplayOrchestrator
                    ._redact_texts(
                        execution.reasons,
                        session=session,
                    )
                ),
                "denials": (
                    ValidationReplayOrchestrator
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

    def _evaluate(
        self,
        *,
        request: ValidationReplayRequest,
        execution,
    ):
        return self._evaluator.evaluate(
            DynamicValidationEvidenceRequest(
                threat_id=request.threat_id,
                claim_id=request.claim_id,
                category=request.category,
                execution=execution,
                success_criteria=(
                    request.success_criteria
                ),
            )
        )
