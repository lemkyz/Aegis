from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any

import pytest

from aegis.orchestrator.security_task_handler import (
    SecurityTaskHandlerContext,
)
from aegis.orchestrator.security_task_model_handlers import (
    PrimaryModelReviewTaskHandler,
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


class RecordingPrimaryClient:
    provider = "provider-a"
    model = "primary/active"
    transport = SimpleNamespace(
        base_url=(
            "https://primary.invalid/v1"
        ),
    )

    def __init__(self) -> None:
        self.calls: list[
            dict[str, Any]
        ] = []

    async def analyze_security(
        self,
        *,
        code: str,
        language: str,
        filename: str,
        scanner_evidence: list[
            ScannerEvidence
        ],
    ) -> list[SecurityFinding]:
        self.calls.append({
            "code": code,
            "language": language,
            "filename": filename,
            "scanner_evidence": (
                scanner_evidence
            ),
        })

        return [
            SecurityFinding(
                title="Command injection",
                severity="high",
                confidence=0.92,
                summary=(
                    "Untrusted input reaches "
                    "shell execution."
                ),
                evidence=[
                    "os.system(user_input)",
                ],
                scanner_evidence=(
                    scanner_evidence
                ),
                cwe=["CWE-78"],
                vulnerable_lines=[4],
                recommended_fix=(
                    "Avoid invoking a shell."
                ),
            )
        ]


class FailingPrimaryClient:
    provider = "provider-a"
    model = "primary/failing"
    transport = SimpleNamespace(
        base_url=(
            "https://primary.invalid/v1"
        ),
    )

    async def analyze_security(
        self,
        **kwargs: Any,
    ) -> list[SecurityFinding]:
        del kwargs

        raise TimeoutError(
            "primary timeout"
        )


class FallbackPrimaryClient(
    RecordingPrimaryClient
):
    provider = "provider-b"
    model = "primary/fallback"
    transport = SimpleNamespace(
        base_url=(
            "https://fallback.invalid/v1"
        ),
    )


def run(coro):
    return asyncio.run(coro)


def task() -> SecurityTaskNode:
    return SecurityTaskNode(
        task_id="primary_model_review",
        kind="primary_model_review",
        state="ready",
        produces=[
            "primary_findings",
        ],
    )


def context(
    *,
    source_code: str | None = None,
    filename: str | None = "app.py",
) -> SecurityTaskHandlerContext:
    metadata: dict[str, Any] = {}

    if source_code is not None:
        metadata[
            "source_code"
        ] = source_code

    if filename is not None:
        metadata[
            "filename"
        ] = filename

    return SecurityTaskHandlerContext(
        execution_id="execution:test",
        operation="deep_analysis",
        language="python",
        repository_root="/tmp/repository",
        metadata=metadata,
    )


def evidence() -> list[dict[str, Any]]:
    return [
        ScannerEvidence(
            tool="bandit",
            rule_id="bandit.python.b605",
            message="Shell execution detected.",
            severity="HIGH",
            file="app.py",
            line_start=4,
            line_end=4,
            code="os.system(user_input)",
            cwe=["CWE-78"],
        ).model_dump(
            mode="json"
        )
    ]


def scanner_findings() -> list[
    dict[str, Any]
]:
    return [
        SecurityFinding(
            title="Shell execution",
            severity="high",
            confidence=0.85,
            summary="Shell execution detected.",
            evidence=["Bandit B605"],
            scanner_evidence=[
                ScannerEvidence
                .model_validate(
                    evidence()[0]
                )
            ],
            cwe=["CWE-78"],
            vulnerable_lines=[4],
            recommended_fix=(
                "Review the shell call."
            ),
        ).model_dump(
            mode="json"
        )
    ]


def inputs(
    *,
    scanner_evidence: list[
        dict[str, Any]
    ] | None = None,
) -> dict[str, Any]:
    return {
        "repository_context": {
            "project_id": "project:test",
        },
        "scanner_evidence": (
            evidence()
            if scanner_evidence is None
            else scanner_evidence
        ),
        "scanner_findings": (
            scanner_findings()
        ),
    }


def source() -> str:
    return (
        "import os\n"
        "\n"
        "user_input = input()\n"
        "os.system(user_input)\n"
    )


def test_primary_handler_calls_client() -> None:
    client = RecordingPrimaryClient()

    result = run(
        PrimaryModelReviewTaskHandler(
            primary_client=client,
        ).execute(
            task=task(),
            context=context(
                source_code=source()
            ),
            inputs=inputs(),
        )
    )

    assert len(client.calls) == 1

    assert result.metadata[
        "status"
    ] == "completed"

    findings = result.output[
        "primary_findings"
    ]

    assert len(findings) == 1

    assert findings[0][
        "primary_model"
    ] == "primary/active"


def test_empty_evidence_skips_model() -> None:
    client = RecordingPrimaryClient()

    result = run(
        PrimaryModelReviewTaskHandler(
            primary_client=client,
        ).execute(
            task=task(),
            context=context(
                source_code=source()
            ),
            inputs=inputs(
                scanner_evidence=[],
            ),
        )
    )

    assert client.calls == []

    assert result.output[
        "primary_findings"
    ] == []

    assert result.metadata[
        "status"
    ] == "skipped"


def test_source_is_redacted_before_model() -> None:
    client = RecordingPrimaryClient()

    unsafe_source = (
        'api_key = "sk-'
        'abcdefghijklmnop123456"\n'
        "os.system(user_input)\n"
    )

    unsafe_evidence = [
        ScannerEvidence(
            tool="test",
            rule_id="test.secret",
            message=(
                "Token sk-"
                "abcdefghijklmnop123456 found."
            ),
            severity="HIGH",
            file="app.py",
            line_start=1,
            line_end=1,
            code=(
                'api_key = "sk-'
                'abcdefghijklmnop123456"'
            ),
        ).model_dump(
            mode="json"
        )
    ]

    run(
        PrimaryModelReviewTaskHandler(
            primary_client=client,
            context_lines=5,
        ).execute(
            task=task(),
            context=context(
                source_code=unsafe_source
            ),
            inputs=inputs(
                scanner_evidence=(
                    unsafe_evidence
                ),
            ),
        )
    )

    call = client.calls[0]

    assert (
        "abcdefghijklmnop123456"
        not in call["code"]
    )

    assert (
        "abcdefghijklmnop123456"
        not in call[
            "scanner_evidence"
        ][0].message
    )

    assert "AEGIS_REDACTED" in (
        call["code"]
    )


def test_relevant_context_excludes_far_code() -> None:
    client = RecordingPrimaryClient()

    source_code = "\n".join([
        "safe_line_1",
        "safe_line_2",
        "dangerous_call()",
        "safe_line_4",
        "far_line_5",
        "far_line_6",
    ])

    custom_evidence = [
        ScannerEvidence(
            tool="test",
            rule_id="test.rule",
            message="Dangerous call.",
            severity="HIGH",
            file="app.py",
            line_start=3,
            line_end=3,
            code="dangerous_call()",
        ).model_dump(
            mode="json"
        )
    ]

    run(
        PrimaryModelReviewTaskHandler(
            primary_client=client,
            context_lines=1,
        ).execute(
            task=task(),
            context=context(
                source_code=source_code
            ),
            inputs=inputs(
                scanner_evidence=(
                    custom_evidence
                ),
            ),
        )
    )

    sent_code = client.calls[0][
        "code"
    ]

    assert "safe_line_2" in sent_code
    assert "dangerous_call()" in sent_code
    assert "safe_line_4" in sent_code
    assert "far_line_6" not in sent_code


def test_explicit_fallback_is_used() -> None:
    fallback = (
        FallbackPrimaryClient()
    )

    result = run(
        PrimaryModelReviewTaskHandler(
            primary_client=(
                FailingPrimaryClient()
            ),
            fallback_client=fallback,
        ).execute(
            task=task(),
            context=context(
                source_code=source()
            ),
            inputs=inputs(),
        )
    )

    assert len(fallback.calls) == 1

    assert result.metadata[
        "status"
    ] == "fallback"

    assert result.metadata[
        "fallback_used"
    ] is True

    assert result.output[
        "primary_findings"
    ][0]["primary_model"] == (
        "primary/fallback"
    )


def test_failure_without_fallback_is_safe() -> None:
    with pytest.raises(
        RuntimeError,
        match="no explicit fallback",
    ):
        run(
            PrimaryModelReviewTaskHandler(
                primary_client=(
                    FailingPrimaryClient()
                ),
            ).execute(
                task=task(),
                context=context(
                    source_code=source()
                ),
                inputs=inputs(),
            )
        )


def test_requires_source_code() -> None:
    with pytest.raises(
        SecurityTaskInputError,
        match="source_code",
    ):
        run(
            PrimaryModelReviewTaskHandler(
                primary_client=(
                    RecordingPrimaryClient()
                ),
            ).execute(
                task=task(),
                context=context(),
                inputs=inputs(),
            )
        )


def test_requires_filename() -> None:
    with pytest.raises(
        SecurityTaskInputError,
        match="filename",
    ):
        run(
            PrimaryModelReviewTaskHandler(
                primary_client=(
                    RecordingPrimaryClient()
                ),
            ).execute(
                task=task(),
                context=context(
                    source_code=source(),
                    filename=None,
                ),
                inputs=inputs(),
            )
        )


def test_rejects_negative_context_lines() -> None:
    with pytest.raises(
        ValueError,
        match="must not be negative",
    ):
        PrimaryModelReviewTaskHandler(
            primary_client=(
                RecordingPrimaryClient()
            ),
            context_lines=-1,
        )


from aegis.orchestrator.security_task_model_handlers import (
    VerifierReviewTaskHandler,
)
from aegis.schemas.model_verification import (
    FindingVerification,
    VerifierReviewResult,
)


class RecordingVerifierClient:
    provider = "provider-verifier-a"
    model = "verifier/active"
    transport = SimpleNamespace(
        base_url=(
            "https://verifier.invalid/v1"
        ),
    )

    def __init__(self) -> None:
        self.calls: list[
            dict[str, Any]
        ] = []

    async def verify_findings(
        self,
        *,
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
        self.calls.append({
            "code": code,
            "language": language,
            "filename": filename,
            "scanner_evidence": (
                scanner_evidence
            ),
            "primary_findings": (
                primary_findings
            ),
        })

        return VerifierReviewResult(
            model=self.model,
            status="completed",
            verifications=[
                FindingVerification(
                    finding_index=0,
                    verdict="supported",
                    confidence=0.94,
                    reasoning=(
                        "The source confirms "
                        "shell execution."
                    ),
                    evidence=[
                        "os.system(user_input)",
                    ],
                )
            ],
        )


class FailingVerifierClient:
    provider = "provider-verifier-a"
    model = "verifier/failing"
    transport = SimpleNamespace(
        base_url=(
            "https://verifier.invalid/v1"
        ),
    )

    async def verify_findings(
        self,
        **kwargs: Any,
    ) -> VerifierReviewResult:
        del kwargs

        raise TimeoutError(
            "verifier timeout"
        )


class FallbackVerifierClient(
    RecordingVerifierClient
):
    provider = "provider-verifier-b"
    model = "verifier/fallback"
    transport = SimpleNamespace(
        base_url=(
            "https://verifier-fallback.invalid/v1"
        ),
    )


class InvalidDecisionVerifier(
    RecordingVerifierClient
):
    async def verify_findings(
        self,
        **kwargs: Any,
    ) -> VerifierReviewResult:
        del kwargs

        return VerifierReviewResult(
            model=self.model,
            status="completed",
            verifications=[
                FindingVerification(
                    finding_index=0,
                    verdict="supported",
                    confidence=0.91,
                    reasoning="Valid decision.",
                ),
                FindingVerification(
                    finding_index=0,
                    verdict="uncertain",
                    confidence=0.50,
                    reasoning=(
                        "Duplicate decision."
                    ),
                ),
                FindingVerification(
                    finding_index=99,
                    verdict="refuted",
                    confidence=0.90,
                    reasoning=(
                        "Out-of-range decision."
                    ),
                ),
            ],
        )


def verifier_task() -> SecurityTaskNode:
    return SecurityTaskNode(
        task_id="verifier_review",
        kind="verifier_review",
        state="ready",
        produces=[
            "verifier_decisions",
        ],
    )


def verifier_inputs(
    *,
    primary: list[
        dict[str, Any]
    ] | None = None,
) -> dict[str, Any]:
    return {
        "repository_context": {
            "project_id": "project:test",
        },
        "scanner_evidence": evidence(),
        "primary_findings": (
            scanner_findings()
            if primary is None
            else primary
        ),
    }


def test_verifier_handler_calls_client() -> None:
    client = RecordingVerifierClient()

    result = run(
        VerifierReviewTaskHandler(
            verifier_client=client,
        ).execute(
            task=verifier_task(),
            context=context(
                source_code=source()
            ),
            inputs=verifier_inputs(),
        )
    )

    assert len(client.calls) == 1

    payload = result.output[
        "verifier_decisions"
    ]

    assert payload[
        "status"
    ] == "completed"

    assert payload[
        "model"
    ] == "verifier/active"

    assert len(
        payload["verifications"]
    ) == 1

    assert payload[
        "verifications"
    ][0]["verdict"] == "supported"


def test_empty_primary_findings_skip_verifier() -> None:
    client = RecordingVerifierClient()

    result = run(
        VerifierReviewTaskHandler(
            verifier_client=client,
        ).execute(
            task=verifier_task(),
            context=context(
                source_code=source()
            ),
            inputs=verifier_inputs(
                primary=[],
            ),
        )
    )

    assert client.calls == []

    payload = result.output[
        "verifier_decisions"
    ]

    assert payload[
        "status"
    ] == "skipped"

    assert payload[
        "verifications"
    ] == []


def test_verifier_receives_redacted_inputs() -> None:
    client = RecordingVerifierClient()

    secret_value = (
        "sk-abcdefghijklmnop123456"
    )

    unsafe_evidence = [
        ScannerEvidence(
            tool="test",
            rule_id="test.secret",
            message=(
                f"Token {secret_value} found."
            ),
            severity="HIGH",
            file="app.py",
            line_start=1,
            line_end=1,
            code=(
                f'api_key = "{secret_value}"'
            ),
        ).model_dump(
            mode="json"
        )
    ]

    unsafe_finding = SecurityFinding(
        title="Exposed token",
        severity="high",
        confidence=0.90,
        summary=(
            f"Token {secret_value} is exposed."
        ),
        evidence=[
            f"Observed {secret_value}",
        ],
        scanner_evidence=[
            ScannerEvidence.model_validate(
                unsafe_evidence[0]
            )
        ],
        recommended_fix=(
            "Remove the token."
        ),
    )

    run(
        VerifierReviewTaskHandler(
            verifier_client=client,
            context_lines=5,
        ).execute(
            task=verifier_task(),
            context=context(
                source_code=(
                    f'api_key = "{secret_value}"\n'
                    "os.system(user_input)\n"
                )
            ),
            inputs={
                "scanner_evidence": (
                    unsafe_evidence
                ),
                "primary_findings": [
                    unsafe_finding.model_dump(
                        mode="json"
                    )
                ],
            },
        )
    )

    call = client.calls[0]

    assert secret_value not in (
        call["code"]
    )

    assert secret_value not in (
        call["scanner_evidence"][0]
        .message
    )

    assert secret_value not in (
        call["primary_findings"][0]
        .summary
    )


def test_verifier_fallback_is_used() -> None:
    fallback = (
        FallbackVerifierClient()
    )

    result = run(
        VerifierReviewTaskHandler(
            verifier_client=(
                FailingVerifierClient()
            ),
            fallback_client=fallback,
        ).execute(
            task=verifier_task(),
            context=context(
                source_code=source()
            ),
            inputs=verifier_inputs(),
        )
    )

    assert len(fallback.calls) == 1

    assert result.metadata[
        "status"
    ] == "fallback"

    assert result.metadata[
        "fallback_used"
    ] is True

    assert result.output[
        "verifier_decisions"
    ]["model"] == "verifier/fallback"


def test_verifier_failure_is_artifact_not_crash() -> None:
    result = run(
        VerifierReviewTaskHandler(
            verifier_client=(
                FailingVerifierClient()
            ),
        ).execute(
            task=verifier_task(),
            context=context(
                source_code=source()
            ),
            inputs=verifier_inputs(),
        )
    )

    payload = result.output[
        "verifier_decisions"
    ]

    assert payload[
        "status"
    ] == "failed"

    assert "verifier timeout" in (
        payload["error"]
    )


def test_both_verifier_routes_fail_safely() -> None:
    result = run(
        VerifierReviewTaskHandler(
            verifier_client=(
                FailingVerifierClient()
            ),
            fallback_client=(
                FailingVerifierClient()
            ),
        ).execute(
            task=verifier_task(),
            context=context(
                source_code=source()
            ),
            inputs=verifier_inputs(),
        )
    )

    payload = result.output[
        "verifier_decisions"
    ]

    assert payload[
        "status"
    ] == "failed"

    assert result.metadata[
        "fallback_used"
    ] is True

    assert (
        "verifier_fallback_error"
        in result.metadata
    )


def test_invalid_and_duplicate_decisions_rejected() -> None:
    result = run(
        VerifierReviewTaskHandler(
            verifier_client=(
                InvalidDecisionVerifier()
            ),
        ).execute(
            task=verifier_task(),
            context=context(
                source_code=source()
            ),
            inputs=verifier_inputs(),
        )
    )

    payload = result.output[
        "verifier_decisions"
    ]

    assert len(
        payload["verifications"]
    ) == 1

    assert result.metadata[
        "rejected_decision_count"
    ] == 2


def test_verifier_requires_primary_findings_list() -> None:
    with pytest.raises(
        SecurityTaskInputError,
        match="primary_findings",
    ):
        run(
            VerifierReviewTaskHandler(
                verifier_client=(
                    RecordingVerifierClient()
                ),
            ).execute(
                task=verifier_task(),
                context=context(
                    source_code=source()
                ),
                inputs={
                    "scanner_evidence": (
                        evidence()
                    ),
                    "primary_findings": {},
                },
            )
        )


def test_verifier_rejects_negative_context_lines() -> None:
    with pytest.raises(
        ValueError,
        match="must not be negative",
    ):
        VerifierReviewTaskHandler(
            verifier_client=(
                RecordingVerifierClient()
            ),
            context_lines=-1,
        )


from aegis.orchestrator.security_task_model_handlers import (
    ModelConsensusTaskHandler,
)


def consensus_task() -> SecurityTaskNode:
    return SecurityTaskNode(
        task_id="model_consensus",
        kind="model_consensus",
        state="ready",
        produces=[
            "consensus_decisions",
        ],
    )


def consensus_inputs(
    *,
    primary_route: dict[
        str,
        Any,
    ] | None = None,
    verifier_route: dict[
        str,
        Any,
    ] | None = None,
    verifier_status: str = "completed",
) -> dict[str, Any]:
    primary = scanner_findings()

    primary[0][
        "primary_model"
    ] = "primary/active"

    verifier_result = (
        VerifierReviewResult(
            model="verifier/active",
            status=verifier_status,
            verifications=(
                [
                    FindingVerification(
                        finding_index=0,
                        verdict="supported",
                        confidence=0.94,
                        reasoning=(
                            "The source confirms "
                            "shell execution."
                        ),
                    )
                ]
                if verifier_status
                == "completed"
                else []
            ),
            error=(
                None
                if verifier_status
                == "completed"
                else "verifier timeout"
            ),
        )
    )

    return {
        "primary_findings": primary,
        "primary_model_route": (
            primary_route
            or {
                "provider": "provider-a",
                "model": "primary/active",
                "base_url": (
                    "https://primary.invalid/v1"
                ),
            }
        ),
        "verifier_decisions": (
            verifier_result.model_dump(
                mode="json"
            )
        ),
        "verifier_model_route": (
            verifier_route
            or {
                "provider": "provider-b",
                "model": "verifier/active",
                "base_url": (
                    "https://verifier.invalid/v1"
                ),
            }
        ),
    }


def test_primary_handler_emits_route_artifact() -> None:
    result = run(
        PrimaryModelReviewTaskHandler(
            primary_client=(
                RecordingPrimaryClient()
            ),
        ).execute(
            task=task(),
            context=context(
                source_code=source()
            ),
            inputs=inputs(),
        )
    )

    assert result.output[
        "primary_model_route"
    ] == {
        "provider": "provider-a",
        "model": "primary/active",
        "base_url": (
            "https://primary.invalid/v1"
        ),
    }


def test_primary_fallback_route_artifact_is_selected() -> None:
    result = run(
        PrimaryModelReviewTaskHandler(
            primary_client=(
                FailingPrimaryClient()
            ),
            fallback_client=(
                FallbackPrimaryClient()
            ),
        ).execute(
            task=task(),
            context=context(
                source_code=source()
            ),
            inputs=inputs(),
        )
    )

    assert result.output[
        "primary_model_route"
    ]["model"] == "primary/fallback"


def test_verifier_handler_emits_route_artifact() -> None:
    result = run(
        VerifierReviewTaskHandler(
            verifier_client=(
                RecordingVerifierClient()
            ),
        ).execute(
            task=verifier_task(),
            context=context(
                source_code=source()
            ),
            inputs=verifier_inputs(),
        )
    )

    assert result.output[
        "verifier_model_route"
    ] == {
        "provider": (
            "provider-verifier-a"
        ),
        "model": "verifier/active",
        "base_url": (
            "https://verifier.invalid/v1"
        ),
    }


def test_verifier_fallback_route_artifact_is_selected() -> None:
    result = run(
        VerifierReviewTaskHandler(
            verifier_client=(
                FailingVerifierClient()
            ),
            fallback_client=(
                FallbackVerifierClient()
            ),
        ).execute(
            task=verifier_task(),
            context=context(
                source_code=source()
            ),
            inputs=verifier_inputs(),
        )
    )

    assert result.output[
        "verifier_model_route"
    ]["model"] == "verifier/fallback"


def test_consensus_confirms_independent_support() -> None:
    result = run(
        ModelConsensusTaskHandler().execute(
            task=consensus_task(),
            context=context(
                source_code=source()
            ),
            inputs=consensus_inputs(),
        )
    )

    consensus = result.output[
        "consensus_decisions"
    ]

    assert consensus[
        "status"
    ] == "completed"

    assert consensus[
        "decisions"
    ][0]["verdict"] == "confirmed"

    assert consensus[
        "route_independence"
    ] == "independent"

    assert consensus[
        "independently_verified"
    ] is True


def test_same_route_is_partial_and_capped() -> None:
    same_route = {
        "provider": "provider-a",
        "model": "primary/active",
        "base_url": (
            "https://primary.invalid/v1"
        ),
    }

    values = consensus_inputs(
        verifier_route=same_route,
    )

    values[
        "verifier_decisions"
    ]["model"] = "primary/active"

    result = run(
        ModelConsensusTaskHandler().execute(
            task=consensus_task(),
            context=context(
                source_code=source()
            ),
            inputs=values,
        )
    )

    consensus = result.output[
        "consensus_decisions"
    ]

    assert consensus[
        "status"
    ] == "partial"

    assert consensus[
        "route_independence"
    ] == "same_route"

    assert consensus[
        "independently_verified"
    ] is False

    assert consensus[
        "decisions"
    ][0]["confidence"] <= 0.85


def test_failed_verifier_preserves_primary() -> None:
    result = run(
        ModelConsensusTaskHandler().execute(
            task=consensus_task(),
            context=context(
                source_code=source()
            ),
            inputs=consensus_inputs(
                verifier_status="failed",
            ),
        )
    )

    consensus = result.output[
        "consensus_decisions"
    ]

    assert consensus[
        "status"
    ] == "partial"

    assert consensus[
        "decisions"
    ][0]["verdict"] == "unverified"

    assert consensus[
        "errors"
    ] == ["verifier timeout"]


def test_consensus_is_deterministic() -> None:
    handler = ModelConsensusTaskHandler()
    values = consensus_inputs()

    first = run(
        handler.execute(
            task=consensus_task(),
            context=context(
                source_code=source()
            ),
            inputs=values,
        )
    )

    second = run(
        handler.execute(
            task=consensus_task(),
            context=context(
                source_code=source()
            ),
            inputs=values,
        )
    )

    assert (
        first.output[
            "consensus_decisions"
        ]
        == second.output[
            "consensus_decisions"
        ]
    )


def test_consensus_rejects_primary_route_mismatch() -> None:
    with pytest.raises(
        SecurityTaskInputError,
        match="does not match",
    ):
        run(
            ModelConsensusTaskHandler()
            .execute(
                task=consensus_task(),
                context=context(
                    source_code=source()
                ),
                inputs=consensus_inputs(
                    primary_route={
                        "provider": (
                            "provider-a"
                        ),
                        "model": "wrong/model",
                        "base_url": (
                            "https://"
                            "primary.invalid/v1"
                        ),
                    },
                ),
            )
        )


def test_consensus_requires_complete_route() -> None:
    with pytest.raises(
        SecurityTaskInputError,
        match="base_url",
    ):
        run(
            ModelConsensusTaskHandler()
            .execute(
                task=consensus_task(),
                context=context(
                    source_code=source()
                ),
                inputs=consensus_inputs(
                    verifier_route={
                        "provider": (
                            "provider-b"
                        ),
                        "model": (
                            "verifier/active"
                        ),
                        "base_url": None,
                    },
                ),
            )
        )
