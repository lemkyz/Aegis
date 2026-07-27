from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from aegis.models.protocol import (
    SecurityModelClient,
    SecurityVerifierClient,
)
from aegis.orchestrator.security_task_handler import (
    SecurityTaskHandlerCapability,
    SecurityTaskHandlerContext,
    SecurityTaskHandlerResult,
)
from aegis.orchestrator.security_task_handlers import (
    SecurityTaskInputError,
)
from aegis.schemas.analysis import (
    ScannerEvidence,
    SecurityFinding,
)
from aegis.schemas.model_consensus import (
    ModelConsensusResult,
)
from aegis.schemas.model_verification import (
    FindingVerification,
    VerifierReviewResult,
)
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
)
from aegis.security.model_consensus import (
    ModelConsensusEvaluator,
)
from aegis.security.claim_adapter import (
    finding_to_claim,
)
from aegis.security.model_route_policy import (
    ModelRouteIdentity,
    ModelRoutePolicy,
)
from aegis.security.redaction import (
    SecretRedactor,
)


@dataclass(frozen=True, slots=True)
class PrimaryModelRoute:
    provider: str | None
    model: str
    base_url: str | None

    def as_dict(self) -> dict[str, str | None]:
        return {
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
        }


class PrimaryModelReviewTaskHandler:
    """
    Performs only the primary AI security review.

    Scanner execution, verifier review, consensus, and
    policy evaluation remain separate task handlers.
    """

    capability = SecurityTaskHandlerCapability(
        kind="primary_model_review",
        required_artifacts=frozenset({
            "scanner_evidence",
            "scanner_findings",
        }),
        optional_artifacts=frozenset({
            "repository_context",
        }),
        produced_artifacts=frozenset({
            "primary_findings",
            "primary_model_route",
        }),
        supports_retry=True,
        max_attempts=2,
        side_effect_free=True,
    )

    def __init__(
        self,
        *,
        primary_client: SecurityModelClient,
        fallback_client: (
            SecurityModelClient
            | None
        ) = None,
        redactor: SecretRedactor | None = None,
        context_lines: int = 20,
    ) -> None:
        if context_lines < 0:
            raise ValueError(
                "Primary model context_lines must "
                "not be negative."
            )

        self._primary_client = primary_client
        self._fallback_client = fallback_client
        self._redactor = (
            redactor
            or SecretRedactor()
        )
        self._context_lines = context_lines

    async def execute(
        self,
        *,
        task: SecurityTaskNode,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> SecurityTaskHandlerResult:
        del task

        context.raise_if_cancelled()

        source_code = self._source_code(
            context
        )
        filename = self._filename(
            context
        )

        scanner_evidence = (
            self._scanner_evidence(
                inputs
            )
        )
        scanner_findings = (
            self._scanner_findings(
                inputs
            )
        )

        if not scanner_evidence:
            return SecurityTaskHandlerResult(
                output={
                    "primary_findings": [],
                    "primary_model_route": (
                        self._route(
                            self._primary_client
                        ).as_dict()
                    ),
                },
                reasons=(
                    "Primary model review was not "
                    "called because scanner evidence "
                    "was empty.",
                ),
                metadata={
                    "status": "skipped",
                    "active_route": (
                        self._route(
                            self._primary_client
                        ).as_dict()
                    ),
                    "fallback_configured": (
                        self._fallback_client
                        is not None
                    ),
                    "scanner_finding_count": len(
                        scanner_findings
                    ),
                },
            )

        relevant_code = (
            self._build_relevant_context(
                code=source_code,
                scanner_evidence=(
                    scanner_evidence
                ),
                context_lines=(
                    self._context_lines
                ),
            )
        )

        redaction_session = (
            self._redactor.create_session()
        )

        safe_code = (
            redaction_session.redact_text(
                relevant_code
            )
            or relevant_code
        )

        safe_evidence = (
            redaction_session
            .redact_evidence_list(
                scanner_evidence
            )
        )

        active_client = (
            self._primary_client
        )
        fallback_used = False
        primary_error: Exception | None = None

        try:
            findings = await self._call_client(
                client=active_client,
                code=safe_code,
                language=context.language,
                filename=filename,
                scanner_evidence=(
                    safe_evidence
                ),
            )
        except Exception as exc:
            primary_error = exc

            if self._fallback_client is None:
                raise RuntimeError(
                    "Primary model review failed and "
                    "no explicit fallback route is "
                    f"configured: {exc}"
                ) from exc

            context.raise_if_cancelled()

            active_client = (
                self._fallback_client
            )
            fallback_used = True

            try:
                findings = (
                    await self._call_client(
                        client=active_client,
                        code=safe_code,
                        language=(
                            context.language
                        ),
                        filename=filename,
                        scanner_evidence=(
                            safe_evidence
                        ),
                    )
                )
            except Exception as fallback_error:
                raise RuntimeError(
                    "Primary model review and its "
                    "explicit fallback both failed. "
                    f"Primary error: {exc}. "
                    "Fallback error: "
                    f"{fallback_error}."
                ) from fallback_error

        context.raise_if_cancelled()

        findings = [
            finding.model_copy(
                deep=True,
                update={
                    "primary_model": (
                        active_client.model
                    ),
                },
            )
            for finding in findings
        ]

        safe_findings = (
            redaction_session
            .redact_findings(findings)
        )

        reasons = [
            (
                "Primary model review completed "
                f"with {len(safe_findings)} "
                "finding(s)."
            )
        ]

        if fallback_used:
            reasons.append(
                "The active primary route failed "
                "and the explicitly configured "
                "fallback route completed."
            )

        metadata: dict[str, Any] = {
            "status": (
                "fallback"
                if fallback_used
                else "completed"
            ),
            "active_route": (
                self._route(
                    self._primary_client
                ).as_dict()
            ),
            "selected_route": (
                self._route(
                    active_client
                ).as_dict()
            ),
            "fallback_configured": (
                self._fallback_client
                is not None
            ),
            "fallback_used": fallback_used,
            "scanner_evidence_count": len(
                scanner_evidence
            ),
            "scanner_finding_count": len(
                scanner_findings
            ),
            "relevant_line_count": len(
                safe_code.splitlines()
            ),
            "finding_count": len(
                safe_findings
            ),
        }

        if primary_error is not None:
            metadata["primary_error"] = str(
                primary_error
            )

        return SecurityTaskHandlerResult(
            output={
                "primary_findings": [
                    finding.model_dump(
                        mode="json"
                    )
                    for finding in safe_findings
                ],
                "primary_model_route": (
                    self._route(
                        active_client
                    ).as_dict()
                ),
            },
            reasons=tuple(reasons),
            metadata=metadata,
        )

    @staticmethod
    async def _call_client(
        *,
        client: SecurityModelClient,
        code: str,
        language: str,
        filename: str,
        scanner_evidence: list[
            ScannerEvidence
        ],
    ) -> list[SecurityFinding]:
        result = await client.analyze_security(
            code=code,
            language=language,
            filename=filename,
            scanner_evidence=(
                scanner_evidence
            ),
        )

        if not isinstance(result, list):
            raise TypeError(
                "Primary model client must return "
                "a list of SecurityFinding values."
            )

        normalized: list[
            SecurityFinding
        ] = []

        for item in result:
            if isinstance(
                item,
                SecurityFinding,
            ):
                normalized.append(
                    item.model_copy(
                        deep=True
                    )
                )
                continue

            normalized.append(
                SecurityFinding.model_validate(
                    item
                )
            )

        return normalized

    @staticmethod
    def _source_code(
        context: SecurityTaskHandlerContext,
    ) -> str:
        value = context.metadata.get(
            "source_code"
        )

        if not isinstance(value, str):
            raise SecurityTaskInputError(
                "Primary model review requires "
                "context.metadata['source_code']."
            )

        if not value.strip():
            raise SecurityTaskInputError(
                "Primary model source code must "
                "not be empty."
            )

        return value

    @staticmethod
    def _filename(
        context: SecurityTaskHandlerContext,
    ) -> str:
        value = context.metadata.get(
            "filename"
        )

        if not isinstance(value, str):
            raise SecurityTaskInputError(
                "Primary model review requires "
                "context.metadata['filename']."
            )

        normalized = value.strip()

        if not normalized:
            raise SecurityTaskInputError(
                "Primary model filename must not "
                "be empty."
            )

        return normalized

    @staticmethod
    def _scanner_evidence(
        inputs: Mapping[str, Any],
    ) -> list[ScannerEvidence]:
        value = inputs.get(
            "scanner_evidence"
        )

        if not isinstance(value, list):
            raise SecurityTaskInputError(
                "scanner_evidence artifact must "
                "be a list."
            )

        return [
            (
                item.model_copy(deep=True)
                if isinstance(
                    item,
                    ScannerEvidence,
                )
                else ScannerEvidence
                .model_validate(item)
            )
            for item in value
        ]

    @staticmethod
    def _scanner_findings(
        inputs: Mapping[str, Any],
    ) -> list[SecurityFinding]:
        value = inputs.get(
            "scanner_findings"
        )

        if not isinstance(value, list):
            raise SecurityTaskInputError(
                "scanner_findings artifact must "
                "be a list."
            )

        return [
            (
                item.model_copy(deep=True)
                if isinstance(
                    item,
                    SecurityFinding,
                )
                else SecurityFinding
                .model_validate(item)
            )
            for item in value
        ]

    @staticmethod
    def _route(
        client: SecurityModelClient,
    ) -> PrimaryModelRoute:
        provider = getattr(
            client,
            "provider",
            None,
        )

        transport = getattr(
            client,
            "transport",
            None,
        )

        base_url = getattr(
            transport,
            "base_url",
            None,
        )

        return PrimaryModelRoute(
            provider=(
                str(provider)
                if provider is not None
                else None
            ),
            model=client.model,
            base_url=(
                str(base_url)
                if base_url is not None
                else None
            ),
        )

    @staticmethod
    def _build_relevant_context(
        *,
        code: str,
        scanner_evidence: list[
            ScannerEvidence
        ],
        context_lines: int,
    ) -> str:
        source_lines = code.splitlines()

        if not source_lines:
            return code

        ranges: list[
            tuple[int, int]
        ] = []

        for evidence in scanner_evidence:
            start_index = max(
                evidence.line_start
                - 1
                - context_lines,
                0,
            )

            end_index = min(
                evidence.line_end
                + context_lines,
                len(source_lines),
            )

            ranges.append((
                start_index,
                end_index,
            ))

        ranges.sort()

        merged: list[
            tuple[int, int]
        ] = []

        for start_index, end_index in ranges:
            if not merged:
                merged.append((
                    start_index,
                    end_index,
                ))
                continue

            previous_start, previous_end = (
                merged[-1]
            )

            if start_index <= previous_end:
                merged[-1] = (
                    previous_start,
                    max(
                        previous_end,
                        end_index,
                    ),
                )
            else:
                merged.append((
                    start_index,
                    end_index,
                ))

        sections: list[str] = []

        for start_index, end_index in merged:
            start_line = start_index + 1
            end_line = end_index

            excerpt = "\n".join(
                source_lines[
                    start_index:end_index
                ]
            )

            sections.append(
                "--- ORIGINAL FILE LINES "
                f"{start_line}-{end_line} ---\n"
                f"{excerpt}"
            )

        return "\n\n".join(sections)


@dataclass(frozen=True, slots=True)
class VerifierModelRoute:
    provider: str | None
    model: str
    base_url: str | None

    def as_dict(
        self,
    ) -> dict[str, str | None]:
        return {
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
        }


class VerifierReviewTaskHandler:
    """
    Independently verifies primary-model findings.

    Consensus evaluation remains a separate security task.
    """

    capability = SecurityTaskHandlerCapability(
        kind="verifier_review",
        required_artifacts=frozenset({
            "scanner_evidence",
            "primary_findings",
        }),
        optional_artifacts=frozenset({
            "repository_context",
        }),
        produced_artifacts=frozenset({
            "verifier_decisions",
            "verifier_model_route",
        }),
        supports_retry=True,
        max_attempts=2,
        side_effect_free=True,
    )

    def __init__(
        self,
        *,
        verifier_client: SecurityVerifierClient,
        fallback_client: (
            SecurityVerifierClient
            | None
        ) = None,
        redactor: SecretRedactor | None = None,
        context_lines: int = 20,
    ) -> None:
        if context_lines < 0:
            raise ValueError(
                "Verifier context_lines must "
                "not be negative."
            )

        self._verifier_client = (
            verifier_client
        )
        self._fallback_client = (
            fallback_client
        )
        self._redactor = (
            redactor
            or SecretRedactor()
        )
        self._context_lines = context_lines

    async def execute(
        self,
        *,
        task: SecurityTaskNode,
        context: SecurityTaskHandlerContext,
        inputs: Mapping[str, Any],
    ) -> SecurityTaskHandlerResult:
        del task

        context.raise_if_cancelled()

        source_code = (
            PrimaryModelReviewTaskHandler
            ._source_code(context)
        )

        filename = (
            PrimaryModelReviewTaskHandler
            ._filename(context)
        )

        scanner_evidence = (
            PrimaryModelReviewTaskHandler
            ._scanner_evidence(inputs)
        )

        primary_findings = (
            self._primary_findings(inputs)
        )

        active_route = self._route(
            self._verifier_client
        )

        if not primary_findings:
            skipped = VerifierReviewResult(
                model=self._verifier_client.model,
                status="skipped",
                verifications=[],
                additional_findings=[],
            )

            return SecurityTaskHandlerResult(
                output={
                    "verifier_decisions": (
                        skipped.model_dump(
                            mode="json"
                        )
                    ),
                    "verifier_model_route": (
                        active_route.as_dict()
                    ),
                },
                metadata={
                    "status": "skipped",
                    "active_route": (
                        active_route.as_dict()
                    ),
                    "fallback_configured": (
                        self._fallback_client
                        is not None
                    ),
                    "scanner_evidence_count": len(
                        scanner_evidence
                    ),
                    "primary_finding_count": 0,
                    "verification_count": 0,
                },
                reasons=(
                    "Verifier review was not called "
                    "because primary findings were "
                    "empty.",
                ),
            )

        relevant_code = (
            PrimaryModelReviewTaskHandler
            ._build_relevant_context(
                code=source_code,
                scanner_evidence=(
                    scanner_evidence
                ),
                context_lines=(
                    self._context_lines
                ),
            )
        )

        redaction_session = (
            self._redactor.create_session()
        )

        safe_code = (
            redaction_session.redact_text(
                relevant_code
            )
            or relevant_code
        )

        safe_evidence = (
            redaction_session
            .redact_evidence_list(
                scanner_evidence
            )
        )

        safe_primary_findings = (
            redaction_session
            .redact_findings(
                primary_findings
            )
        )

        active_client = (
            self._verifier_client
        )

        fallback_used = False
        primary_error: Exception | None = None
        fallback_error: Exception | None = None

        try:
            result = await self._call_client(
                client=active_client,
                code=safe_code,
                language=context.language,
                filename=filename,
                scanner_evidence=(
                    safe_evidence
                ),
                primary_findings=(
                    safe_primary_findings
                ),
            )
        except Exception as exc:
            primary_error = exc

            if self._fallback_client is None:
                result = VerifierReviewResult(
                    model=active_client.model,
                    status="failed",
                    error=str(exc),
                )
            else:
                context.raise_if_cancelled()

                active_client = (
                    self._fallback_client
                )
                fallback_used = True

                try:
                    result = (
                        await self._call_client(
                            client=active_client,
                            code=safe_code,
                            language=(
                                context.language
                            ),
                            filename=filename,
                            scanner_evidence=(
                                safe_evidence
                            ),
                            primary_findings=(
                                safe_primary_findings
                            ),
                        )
                    )
                except Exception as exc2:
                    fallback_error = exc2

                    result = VerifierReviewResult(
                        model=active_client.model,
                        status="failed",
                        error=(
                            f"{primary_error}; "
                            f"{fallback_error}"
                        ),
                    )

        context.raise_if_cancelled()

        result = result.model_copy(
            deep=True,
            update={
                "model": active_client.model,
            },
        )

        normalized_result, rejected = (
            self._normalize_result(
                result=result,
                primary_finding_count=len(
                    primary_findings
                ),
                redaction_session=(
                    redaction_session
                ),
            )
        )

        status = normalized_result.status

        if (
            fallback_used
            and status == "completed"
        ):
            handler_status = "fallback"
        else:
            handler_status = status

        reasons = [
            (
                "Verifier review produced "
                f"{len(normalized_result.verifications)} "
                "accepted decision(s)."
            )
        ]

        if fallback_used:
            if status == "completed":
                reasons.append(
                    "The active verifier route "
                    "failed and the explicit "
                    "fallback route completed."
                )
            else:
                reasons.append(
                    "Both the active verifier "
                    "route and its explicit "
                    "fallback failed safely."
                )

        if rejected:
            reasons.append(
                f"{rejected} malformed, duplicate, "
                "or out-of-range verifier "
                "decision(s) were rejected."
            )

        metadata: dict[str, Any] = {
            "status": handler_status,
            "active_route": (
                active_route.as_dict()
            ),
            "selected_route": (
                self._route(
                    active_client
                ).as_dict()
            ),
            "fallback_configured": (
                self._fallback_client
                is not None
            ),
            "fallback_used": fallback_used,
            "scanner_evidence_count": len(
                scanner_evidence
            ),
            "primary_finding_count": len(
                primary_findings
            ),
            "verification_count": len(
                normalized_result.verifications
            ),
            "additional_finding_count": len(
                normalized_result
                .additional_findings
            ),
            "rejected_decision_count": (
                rejected
            ),
            "relevant_line_count": len(
                safe_code.splitlines()
            ),
        }

        if primary_error is not None:
            metadata["verifier_error"] = str(
                primary_error
            )

        if fallback_error is not None:
            metadata[
                "verifier_fallback_error"
            ] = str(fallback_error)

        return SecurityTaskHandlerResult(
            output={
                "verifier_decisions": (
                    normalized_result.model_dump(
                        mode="json"
                    )
                ),
                "verifier_model_route": (
                    self._route(
                        active_client
                    ).as_dict()
                ),
            },
            metadata=metadata,
            reasons=tuple(reasons),
        )

    @staticmethod
    async def _call_client(
        *,
        client: SecurityVerifierClient,
        code: str,
        language: str,
        filename: str,
        scanner_evidence: list[
            ScannerEvidence
        ],
        primary_findings: list[
            SecurityFinding
        ],
    ) -> VerifierReviewResult:
        raw_result = (
            await client.verify_findings(
                code=code,
                language=language,
                filename=filename,
                scanner_evidence=(
                    scanner_evidence
                ),
                primary_findings=(
                    primary_findings
                ),
            )
        )

        if isinstance(
            raw_result,
            VerifierReviewResult,
        ):
            return raw_result.model_copy(
                deep=True
            )

        return (
            VerifierReviewResult
            .model_validate(raw_result)
        )

    @staticmethod
    def _primary_findings(
        inputs: Mapping[str, Any],
    ) -> list[SecurityFinding]:
        value = inputs.get(
            "primary_findings"
        )

        if not isinstance(value, list):
            raise SecurityTaskInputError(
                "primary_findings artifact "
                "must be a list."
            )

        return [
            (
                item.model_copy(deep=True)
                if isinstance(
                    item,
                    SecurityFinding,
                )
                else SecurityFinding
                .model_validate(item)
            )
            for item in value
        ]

    @classmethod
    def _normalize_result(
        cls,
        *,
        result: VerifierReviewResult,
        primary_finding_count: int,
        redaction_session: Any,
    ) -> tuple[
        VerifierReviewResult,
        int,
    ]:
        accepted: list[
            FindingVerification
        ] = []

        seen_indices: set[int] = set()
        rejected = 0

        for verification in (
            result.verifications
        ):
            index = (
                verification.finding_index
            )

            if (
                index >= primary_finding_count
                or index in seen_indices
            ):
                rejected += 1
                continue

            seen_indices.add(index)

            reasoning = (
                redaction_session.redact_text(
                    verification.reasoning
                )
                or verification.reasoning
            )

            evidence = [
                (
                    redaction_session
                    .redact_text(item)
                    or item
                )
                for item
                in verification.evidence
            ]

            accepted.append(
                verification.model_copy(
                    deep=True,
                    update={
                        "reasoning": reasoning,
                        "evidence": evidence,
                    },
                )
            )

        safe_additional_findings = (
            redaction_session
            .redact_findings(
                result.additional_findings
            )
        )

        safe_error = (
            redaction_session.redact_text(
                result.error
            )
        )

        normalized = result.model_copy(
            deep=True,
            update={
                "verifications": accepted,
                "additional_findings": (
                    safe_additional_findings
                ),
                "error": safe_error,
            },
        )

        return normalized, rejected

    @staticmethod
    def _route(
        client: SecurityVerifierClient,
    ) -> VerifierModelRoute:
        provider = getattr(
            client,
            "provider",
            None,
        )

        transport = getattr(
            client,
            "transport",
            None,
        )

        base_url = getattr(
            transport,
            "base_url",
            None,
        )

        return VerifierModelRoute(
            provider=(
                str(provider)
                if provider is not None
                else None
            ),
            model=client.model,
            base_url=(
                str(base_url)
                if base_url is not None
                else None
            ),
        )


class ModelConsensusTaskHandler:
    """
    Deterministically combines primary findings and verifier decisions.

    The selected model routes are consumed as provenance-bearing
    artifacts. No model or network call occurs in this handler.
    """

    capability = SecurityTaskHandlerCapability(
        kind="model_consensus",
        required_artifacts=frozenset({
            "primary_findings",
            "primary_model_route",
            "verifier_decisions",
            "verifier_model_route",
        }),
        optional_artifacts=frozenset({
            "repository_context",
        }),
        produced_artifacts=frozenset({
            "consensus_decisions",
            "consensus_claims",
            "verified_findings",
        }),
        supports_retry=False,
        max_attempts=1,
        side_effect_free=True,
    )

    def __init__(
        self,
        *,
        evaluator: ModelConsensusEvaluator | None = None,
        route_policy: ModelRoutePolicy | None = None,
    ) -> None:
        self._evaluator = (
            evaluator
            or ModelConsensusEvaluator()
        )
        self._route_policy = (
            route_policy
            or ModelRoutePolicy()
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

        primary_findings = (
            VerifierReviewTaskHandler
            ._primary_findings(inputs)
        )

        verifier_result = (
            self._verifier_result(inputs)
        )

        primary_route = self._route_identity(
            inputs=inputs,
            artifact_name=(
                "primary_model_route"
            ),
        )

        verifier_route = self._route_identity(
            inputs=inputs,
            artifact_name=(
                "verifier_model_route"
            ),
        )

        self._validate_primary_models(
            primary_findings=(
                primary_findings
            ),
            route=primary_route,
        )

        self._validate_model_identity(
            artifact_name=(
                "verifier_model_route"
            ),
            route=verifier_route,
            expected_model=(
                verifier_result.model
            ),
        )

        route_assessment = (
            self._route_policy.assess(
                primary=primary_route,
                verifier=verifier_route,
            )
        )

        raw_consensus = (
            self._evaluator.evaluate(
                primary_provider=(
                    primary_route.provider
                ),
                primary_model=(
                    primary_route.model
                ),
                verifier_provider=(
                    verifier_route.provider
                ),
                primary_findings=(
                    primary_findings
                ),
                verifier_result=(
                    verifier_result
                ),
                route_assessment=(
                    route_assessment
                ),
            )
        )

        consensus = (
            ModelConsensusResult
            .model_validate(
                raw_consensus.model_dump(
                    mode="json"
                )
            )
        )
        verified_findings = (
            self._verified_findings(
                primary_findings=(
                    primary_findings
                ),
                verifier_result=(
                    verifier_result
                ),
                consensus=consensus,
            )
        )
        claims = [
            finding_to_claim(
                finding,
                filename=(
                    PrimaryModelReviewTaskHandler
                    ._filename(context)
                ),
            )
            for finding in verified_findings
        ]

        reasons = [
            (
                "Deterministic model consensus "
                f"produced "
                f"{len(consensus.decisions)} "
                "decision(s)."
            ),
            *consensus.route_reasons,
        ]

        if consensus.errors:
            reasons.append(
                "Consensus retained "
                f"{len(consensus.errors)} "
                "validation or verifier error(s)."
            )

        return SecurityTaskHandlerResult(
            output={
                "consensus_decisions": (
                    consensus.model_dump(
                        mode="json"
                    )
                ),
                "verified_findings": [
                    finding.model_dump(
                        mode="json"
                    )
                    for finding
                    in verified_findings
                ],
                "consensus_claims": [
                    claim.model_dump(
                        mode="json"
                    )
                    for claim in claims
                ],
            },
            reasons=tuple(reasons),
            metadata={
                "status": consensus.status,
                "evaluator": (
                    self._evaluator.name
                ),
                "primary_finding_count": len(
                    primary_findings
                ),
                "decision_count": len(
                    consensus.decisions
                ),
                "claim_count": len(claims),
                "error_count": len(
                    consensus.errors
                ),
                "primary_route": (
                    self._identity_dict(
                        primary_route
                    )
                ),
                "verifier_route": (
                    self._identity_dict(
                        verifier_route
                    )
                ),
                "route_independence": (
                    route_assessment
                    .classification
                ),
                "independently_verified": (
                    route_assessment
                    .independently_verified
                ),
            },
        )

    @staticmethod
    def _verified_findings(
        *,
        primary_findings: list[
            SecurityFinding
        ],
        verifier_result: VerifierReviewResult,
        consensus: ModelConsensusResult,
    ) -> list[SecurityFinding]:
        findings = [
            finding.model_copy(deep=True)
            for finding in primary_findings
        ]
        verifications = {
            item.finding_index: item
            for item
            in verifier_result.verifications
        }

        for decision in consensus.decisions:
            if (
                decision.finding_index
                >= len(findings)
            ):
                continue

            finding = findings[
                decision.finding_index
            ]
            verification = verifications.get(
                decision.finding_index
            )

            finding.primary_model = (
                consensus.primary_model
            )
            finding.verifier_model = (
                consensus.verifier_model
            )
            finding.consensus_verdict = (
                decision.verdict
            )
            finding.consensus_confidence = (
                decision.confidence
            )
            finding.consensus_reasons = list(
                decision.reasons
            )
            finding.verifier_confidence = (
                decision.verifier_confidence
            )

            if verification is not None:
                finding.verifier_verdict = (
                    verification.verdict
                )
                finding.verifier_reasoning = (
                    verification.reasoning
                )
                finding.verifier_evidence = list(
                    verification.evidence
                )

        return findings

    @staticmethod
    def _verifier_result(
        inputs: Mapping[str, Any],
    ) -> VerifierReviewResult:
        value = inputs.get(
            "verifier_decisions"
        )

        if isinstance(
            value,
            VerifierReviewResult,
        ):
            return value.model_copy(
                deep=True
            )

        if not isinstance(
            value,
            Mapping,
        ):
            raise SecurityTaskInputError(
                "verifier_decisions artifact "
                "must be a mapping or "
                "VerifierReviewResult."
            )

        return (
            VerifierReviewResult
            .model_validate(dict(value))
        )

    @staticmethod
    def _route_identity(
        *,
        inputs: Mapping[str, Any],
        artifact_name: str,
    ) -> ModelRouteIdentity:
        value = inputs.get(
            artifact_name
        )

        if not isinstance(
            value,
            Mapping,
        ):
            raise SecurityTaskInputError(
                f"{artifact_name} artifact "
                "must be a mapping."
            )

        normalized: dict[str, str] = {}

        for field_name in (
            "provider",
            "model",
            "base_url",
        ):
            field_value = value.get(
                field_name
            )

            if (
                not isinstance(
                    field_value,
                    str,
                )
                or not field_value.strip()
            ):
                raise SecurityTaskInputError(
                    f"{artifact_name}."
                    f"{field_name} must be a "
                    "non-empty string."
                )

            normalized[field_name] = (
                field_value.strip()
            )

        return ModelRouteIdentity(
            provider=normalized[
                "provider"
            ],
            model=normalized["model"],
            base_url=normalized[
                "base_url"
            ],
        )

    @classmethod
    def _validate_primary_models(
        cls,
        *,
        primary_findings: list[
            SecurityFinding
        ],
        route: ModelRouteIdentity,
    ) -> None:
        models = {
            finding.primary_model.strip()
            for finding in primary_findings
            if (
                isinstance(
                    finding.primary_model,
                    str,
                )
                and finding.primary_model.strip()
            )
        }

        if len(models) > 1:
            raise SecurityTaskInputError(
                "primary_findings contain "
                "multiple primary model "
                "identities."
            )

        if models:
            cls._validate_model_identity(
                artifact_name=(
                    "primary_model_route"
                ),
                route=route,
                expected_model=next(
                    iter(models)
                ),
            )

    @staticmethod
    def _validate_model_identity(
        *,
        artifact_name: str,
        route: ModelRouteIdentity,
        expected_model: str,
    ) -> None:
        if (
            route.model.strip().lower()
            != expected_model.strip().lower()
        ):
            raise SecurityTaskInputError(
                f"{artifact_name} model "
                f"{route.model!r} does not "
                "match result model "
                f"{expected_model!r}."
            )

    @staticmethod
    def _identity_dict(
        route: ModelRouteIdentity,
    ) -> dict[str, str]:
        return {
            "provider": route.provider,
            "model": route.model,
            "base_url": route.base_url,
        }
