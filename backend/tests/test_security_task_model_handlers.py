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
