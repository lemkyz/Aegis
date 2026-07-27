import asyncio

from aegis.schemas.validation import (
    ValidationAuthorizationRequest,
    ValidationExecutionResult,
    ValidationPlanRequest,
    ValidationReplayRequest,
    ValidationSuccessCriteria,
)
from aegis.security.validation_replay_orchestrator import (
    ValidationReplayOrchestrator,
)


def _execution(
    *,
    stdout: str,
    status: str = "completed",
    exit_code: int | None = 0,
) -> ValidationExecutionResult:
    return ValidationExecutionResult(
        runner="aegis-safe-container-runner-v1",
        status=status,
        runtime_executable="/usr/bin/podman",
        started=True,
        timed_out=False,
        exit_code=exit_code,
        duration_ms=10,
        stdout=stdout,
        stderr="",
        argv=[
            "/usr/bin/podman",
            "run",
            "--rm",
        ],
        reasons=[],
        denials=[],
    )


def _request() -> ValidationReplayRequest:
    return ValidationReplayRequest(
        threat_id="threat-command-001",
        category="command_injection",
        plan=ValidationPlanRequest(
            authorization=(
                ValidationAuthorizationRequest(
                    authorization_confirmed=True,
                    target_type="local_repository",
                    target="/tmp/aegis-project",
                    allowed_test_types=[
                        "command_injection",
                    ],
                    dry_run=False,
                    timeout_seconds=10,
                    memory_limit_mb=256,
                    cpu_limit=0.5,
                    network_policy="disabled",
                )
            ),
            runtime="python",
            entrypoint="validation.py",
            test_type="command_injection",
        ),
        success_criteria=ValidationSuccessCriteria(
            expected_exit_code=0,
            stdout_contains=(
                "AEGIS_EXPLOIT_CONFIRMED"
            ),
        ),
        before_execution=_execution(
            stdout="AEGIS_EXPLOIT_CONFIRMED\n",
        ),
    )


def test_replay_reports_fixed(
    monkeypatch,
) -> None:
    async def fake_run(
        self,
        request,
    ) -> ValidationExecutionResult:
        return _execution(
            stdout="SAFE_BEHAVIOR\n",
        )

    monkeypatch.setattr(
        "aegis.security.validation_runner."
        "ValidationRunner.run",
        fake_run,
    )

    result = asyncio.run(
        ValidationReplayOrchestrator().replay(
            _request()
        )
    )

    assert result.before_evidence.verdict == (
        "confirmed"
    )
    assert result.after_evidence.verdict == (
        "not_reproduced"
    )
    assert result.comparison.verdict == "fixed"
    assert result.comparison.fixed is True


def test_replay_reports_still_exploitable(
    monkeypatch,
) -> None:
    async def fake_run(
        self,
        request,
    ) -> ValidationExecutionResult:
        return _execution(
            stdout="AEGIS_EXPLOIT_CONFIRMED\n",
        )

    monkeypatch.setattr(
        "aegis.security.validation_runner."
        "ValidationRunner.run",
        fake_run,
    )

    result = asyncio.run(
        ValidationReplayOrchestrator().replay(
            _request()
        )
    )

    assert result.after_evidence.verdict == (
        "confirmed"
    )
    assert result.comparison.verdict == (
        "still_exploitable"
    )
    assert result.comparison.fixed is False


def test_replay_reports_inconclusive_failure(
    monkeypatch,
) -> None:
    async def fake_run(
        self,
        request,
    ) -> ValidationExecutionResult:
        return _execution(
            stdout="",
            status="failed",
            exit_code=2,
        )

    monkeypatch.setattr(
        "aegis.security.validation_runner."
        "ValidationRunner.run",
        fake_run,
    )

    result = asyncio.run(
        ValidationReplayOrchestrator().replay(
            _request()
        )
    )

    assert result.after_evidence.verdict == (
        "execution_error"
    )
    assert result.comparison.verdict == (
        "inconclusive"
    )


def test_replay_uses_same_plan(
    monkeypatch,
) -> None:
    captured: dict[str, object] = {}

    async def fake_run(
        self,
        request,
    ) -> ValidationExecutionResult:
        captured["plan"] = request.plan

        return _execution(
            stdout="SAFE_BEHAVIOR\n",
        )

    monkeypatch.setattr(
        "aegis.security.validation_runner."
        "ValidationRunner.run",
        fake_run,
    )

    request = _request()

    asyncio.run(
        ValidationReplayOrchestrator().replay(
            request
        )
    )

    assert captured["plan"] == request.plan


def test_replay_redacts_captured_secrets(
    monkeypatch,
) -> None:
    synthetic_secret = (
        'PASSWORD="'
        'fixture-replay-secret-value"'
    )

    async def fake_run(
        self,
        request,
    ) -> ValidationExecutionResult:
        del request
        return _execution(
            stdout=(
                "SAFE_BEHAVIOR\n"
                f"{synthetic_secret}\n"
            ),
        )

    monkeypatch.setattr(
        "aegis.security.validation_runner."
        "ValidationRunner.run",
        fake_run,
    )

    request = _request()
    request.before_execution.stdout = (
        f"AEGIS_EXPLOIT_CONFIRMED\n"
        f"{synthetic_secret}\n"
    )
    request.before_execution.argv.append(
        synthetic_secret
    )
    request.before_execution.reasons.append(
        synthetic_secret
    )
    result = asyncio.run(
        ValidationReplayOrchestrator()
        .replay(request)
    )
    serialized = result.model_dump_json()

    assert (
        "fixture-replay-secret-value"
        not in serialized
    )
    assert "<AEGIS_REDACTED_SECRET_" in (
        serialized
    )


def test_unconfirmed_baseline_blocks_runtime(
    monkeypatch,
) -> None:
    calls = 0

    async def fake_run(
        self,
        request,
    ) -> ValidationExecutionResult:
        nonlocal calls
        del request
        calls += 1
        return _execution(
            stdout="SAFE_BEHAVIOR\n",
        )

    monkeypatch.setattr(
        "aegis.security.validation_runner."
        "ValidationRunner.run",
        fake_run,
    )

    request = _request()
    request.before_execution.stdout = (
        "SAFE_BEHAVIOR\n"
    )
    result = asyncio.run(
        ValidationReplayOrchestrator()
        .replay(request)
    )

    assert calls == 0
    assert result.before_evidence.verdict == (
        "not_reproduced"
    )
    assert result.after_execution.status == (
        "rejected"
    )
    assert result.comparison.verdict == (
        "inconclusive"
    )
