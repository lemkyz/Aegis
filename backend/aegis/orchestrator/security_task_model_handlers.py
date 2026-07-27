from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from aegis.models.protocol import (
    SecurityModelClient,
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
from aegis.schemas.security_task_plan import (
    SecurityTaskNode,
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
