import asyncio

from aegis.schemas.validation import (
    DynamicValidationEvidenceRequest,
    DynamicValidationEvidenceResponse,
    FixProjectCheck,
    UnifiedFixVerificationRequest,
    ValidationAuthorizationRequest,
    ValidationExecutionResult,
    ValidationPlanRequest,
    ValidationReplayCompareRequest,
    ValidationReplayRequest,
    ValidationSuccessCriteria,
)
from aegis.security.fix_verification import (
    UnifiedFixVerificationEvaluator,
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


CLAIM_ID = (
    "claim:sha256:"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)


def execution(
    *,
    stdout: str = "AEGIS_EXPLOIT_CONFIRMED\n",
) -> ValidationExecutionResult:
    return ValidationExecutionResult(
        runner="aegis-safe-container-runner-v1",
        status="completed",
        runtime_executable="/usr/bin/podman",
        started=True,
        timed_out=False,
        exit_code=0,
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


def evidence_response(
    *,
    verdict: str,
    claim_id: str | None,
) -> DynamicValidationEvidenceResponse:
    return DynamicValidationEvidenceResponse(
        evaluator="aegis-dynamic-validation-evidence-v1",
        threat_id="threat-command-001",
        claim_id=claim_id,
        category="command_injection",
        verdict=verdict,
        dynamically_confirmed=(
            verdict == "confirmed"
        ),
        confidence=0.99,
        evidence=[
            f"Dynamic verdict: {verdict}",
        ],
        reasons=[],
        execution_status="completed",
        exit_code=0,
        duration_ms=10,
    )


def test_dynamic_evidence_propagates_claim_id() -> None:
    result = DynamicValidationEvaluator().evaluate(
        DynamicValidationEvidenceRequest(
            threat_id="threat-command-001",
            claim_id=CLAIM_ID,
            category="command_injection",
            execution=execution(),
            success_criteria=ValidationSuccessCriteria(
                expected_exit_code=0,
                stdout_contains=(
                    "AEGIS_EXPLOIT_CONFIRMED"
                ),
            ),
        )
    )

    assert result.claim_id == CLAIM_ID
    assert result.verdict == "confirmed"


def test_dynamic_evidence_remains_backward_compatible() -> None:
    result = DynamicValidationEvaluator().evaluate(
        DynamicValidationEvidenceRequest(
            threat_id="threat-command-001",
            category="command_injection",
            execution=execution(),
            success_criteria=ValidationSuccessCriteria(
                expected_exit_code=0,
                stdout_contains=(
                    "AEGIS_EXPLOIT_CONFIRMED"
                ),
            ),
        )
    )

    assert result.claim_id is None


def test_replay_propagates_matching_claim_id() -> None:
    result = ValidationReplayComparator().compare(
        ValidationReplayCompareRequest(
            before=evidence_response(
                verdict="confirmed",
                claim_id=CLAIM_ID,
            ),
            after=evidence_response(
                verdict="not_reproduced",
                claim_id=CLAIM_ID,
            ),
        )
    )

    assert result.claim_id == CLAIM_ID
    assert result.verdict == "fixed"


def test_replay_rejects_different_claim_ids() -> None:
    result = ValidationReplayComparator().compare(
        ValidationReplayCompareRequest(
            before=evidence_response(
                verdict="confirmed",
                claim_id=CLAIM_ID,
            ),
            after=evidence_response(
                verdict="not_reproduced",
                claim_id="claim:sha256:different",
            ),
        )
    )

    assert result.verdict == "inconclusive"
    assert result.fixed is False
    assert any(
        "same claim" in denial.lower()
        for denial in result.denials
    )


def test_replay_allows_legacy_missing_claim_ids() -> None:
    result = ValidationReplayComparator().compare(
        ValidationReplayCompareRequest(
            before=evidence_response(
                verdict="confirmed",
                claim_id=None,
            ),
            after=evidence_response(
                verdict="not_reproduced",
                claim_id=None,
            ),
        )
    )

    assert result.claim_id is None
    assert result.verdict == "fixed"


def test_replay_orchestrator_propagates_claim_id(
    monkeypatch,
) -> None:
    async def fake_run(
        self,
        request,
    ) -> ValidationExecutionResult:
        return execution(
            stdout="SAFE_BEHAVIOR\n",
        )

    monkeypatch.setattr(
        "aegis.security.validation_runner."
        "ValidationRunner.run",
        fake_run,
    )

    request = ValidationReplayRequest(
        threat_id="threat-command-001",
        claim_id=CLAIM_ID,
        category="command_injection",
        plan=ValidationPlanRequest(
            authorization=ValidationAuthorizationRequest(
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
        before_execution=execution(),
    )

    result = asyncio.run(
        ValidationReplayOrchestrator().replay(
            request
        )
    )

    assert result.claim_id == CLAIM_ID
    assert result.before_evidence.claim_id == CLAIM_ID
    assert result.after_evidence.claim_id == CLAIM_ID
    assert result.comparison.claim_id == CLAIM_ID


def test_unified_verification_propagates_claim_id() -> None:
    replay = ValidationReplayComparator().compare(
        ValidationReplayCompareRequest(
            before=evidence_response(
                verdict="confirmed",
                claim_id=CLAIM_ID,
            ),
            after=evidence_response(
                verdict="not_reproduced",
                claim_id=CLAIM_ID,
            ),
        )
    )

    result = UnifiedFixVerificationEvaluator().evaluate(
        UnifiedFixVerificationRequest(
            claim_id=CLAIM_ID,
            patch_sha256="0" * 64,
            replay=replay,
            project_checks=[
                FixProjectCheck(
                    name="Tests",
                    status="passed",
                    details="Tests passed.",
                ),
            ],
            static_target_resolved=True,
            static_regression_free=True,
        )
    )

    assert result.claim_id == CLAIM_ID
    assert result.verdict == "verified"
