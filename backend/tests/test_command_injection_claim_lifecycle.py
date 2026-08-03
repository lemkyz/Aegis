import asyncio
import subprocess
import sys
from pathlib import Path

from aegis.orchestrator.analyzer import SecurityAnalyzer
from aegis.schemas.analysis import AnalyzeCodeRequest
from aegis.schemas.validation import (
    DynamicValidationEvidenceRequest,
    FixProjectCheck,
    UnifiedFixVerificationRequest,
    ValidationExecutionResult,
    ValidationReplayCompareRequest,
    ValidationSuccessCriteria,
)
from aegis.security.dynamic_claim_evidence import (
    apply_dynamic_evidence,
    apply_fix_verification,
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


TARGET_RULE_ID = (
    "aegis.python.command-injection."
    "subprocess-shell"
)

THREAT_ID = "threat-command-injection-lifecycle-001"

EXPLOIT_MARKER = "AEGIS_EXPLOIT_CONFIRMED"

# The marker is encoded so the safe patched program does not merely
# echo the literal success marker supplied as user input.
EXPLOIT_PAYLOAD = (
    'safe; printf "'
    "\\101\\105\\107\\111\\123\\137"
    "\\105\\130\\120\\114\\117\\111\\124"
    "\\137\\103\\117\\116\\106\\111\\122"
    "\\115\\105\\104"
    '"'
)

VULNERABLE_SOURCE = '''\
from __future__ import annotations

import subprocess


def run_command(
    user_input: str,
) -> subprocess.CompletedProcess[str]:
    command = f'printf "%s" {user_input}'

    return subprocess.run(
        command,
        shell=True,
        text=True,
        capture_output=True,
        timeout=3,
        check=False,
    )
'''


def _execute_fixture(
    *,
    source: str,
    directory: Path,
    name: str,
) -> ValidationExecutionResult:
    fixture = directory / f"{name}.py"

    harness = (
        "\n\n"
        "if __name__ == '__main__':\n"
        f"    result = run_command({EXPLOIT_PAYLOAD!r})\n"
        "    print(result.stdout, end='')\n"
        "    print(result.stderr, end='', file=__import__('sys').stderr)\n"
    )

    fixture.write_text(
        source + harness,
        encoding="utf-8",
    )

    completed = subprocess.run(
        [sys.executable, "-I", str(fixture)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    return ValidationExecutionResult(
        runner="aegis-local-fixture-runner-v1",
        status="completed",
        runtime_executable=sys.executable,
        started=True,
        timed_out=False,
        exit_code=completed.returncode,
        duration_ms=0,
        stdout=completed.stdout,
        stderr=completed.stderr,
        argv=[
            sys.executable,
            "-I",
            str(fixture),
        ],
        reasons=[],
        denials=[],
    )


def _rule_ids(response) -> set[str]:
    return {
        evidence.rule_id
        for finding in response.findings
        for evidence in finding.scanner_evidence
    }


def _is_expected_shell_removal_finding(
    rule_id: str,
) -> bool:
    normalized = rule_id.lower()

    return (
        "b603" in normalized
        and (
            "subprocess-without-shell" in normalized
            or "subprocess_without_shell" in normalized
        )
    )


def test_command_injection_claim_lifecycle(
    tmp_path: Path,
) -> None:
    analyzer = SecurityAnalyzer(
        fingerprint_key=(
            "aegis-test-fingerprint-key-"
            "0123456789abcdef"
        ),
    )

    vulnerable_response = asyncio.run(
        analyzer.fast_analyze(
            AnalyzeCodeRequest(
                code=VULNERABLE_SOURCE,
                language="python",
                filename="command_injection_fixture.py",
            )
        )
    )

    assert len(vulnerable_response.findings) == len(
        vulnerable_response.claims
    )

    target_index = next(
        index
        for index, finding
        in enumerate(vulnerable_response.findings)
        if any(
            evidence.rule_id == TARGET_RULE_ID
            for evidence in finding.scanner_evidence
        )
    )

    finding = vulnerable_response.findings[target_index]
    claim = vulnerable_response.claims[target_index]

    assert TARGET_RULE_ID in {
        evidence.rule_id
        for evidence in finding.scanner_evidence
    }
    assert claim.claim_id.startswith("claim:sha256:")
    assert claim.state == "supported"

    before_execution = _execute_fixture(
        source=VULNERABLE_SOURCE,
        directory=tmp_path,
        name="before_fix",
    )

    assert before_execution.exit_code == 0
    assert EXPLOIT_MARKER in before_execution.stdout

    success_criteria = ValidationSuccessCriteria(
        expected_exit_code=0,
        stdout_contains=EXPLOIT_MARKER,
    )

    before_evidence = DynamicValidationEvaluator().evaluate(
        DynamicValidationEvidenceRequest(
            threat_id=THREAT_ID,
            claim_id=claim.claim_id,
            category="command_injection",
            execution=before_execution,
            success_criteria=success_criteria,
        )
    )

    assert before_evidence.verdict == "confirmed"
    assert before_evidence.dynamically_confirmed is True

    confirmed_claim = apply_dynamic_evidence(
        claim,
        before_evidence,
    )

    assert confirmed_claim.state == "confirmed"
    assert any(
        item.source.kind == "dynamic_probe"
        for item in confirmed_claim.evidence
    )

    patched_source = (
        SecurityAnalyzer._build_local_scanner_patch(
            rule_id=TARGET_RULE_ID,
            source_code=VULNERABLE_SOURCE,
        )
    )

    assert patched_source is not None
    assert "shell=True" not in patched_source
    assert "shell=False" in patched_source
    assert (
        'command = ["printf", "%s", user_input]'
        in patched_source
    )

    compile(
        patched_source,
        "command_injection_fixture.py",
        "exec",
    )

    patched_response = asyncio.run(
        analyzer.fast_analyze(
            AnalyzeCodeRequest(
                code=patched_source,
                language="python",
                filename="command_injection_fixture.py",
            )
        )
    )

    vulnerable_rule_ids = _rule_ids(
        vulnerable_response
    )
    patched_rule_ids = _rule_ids(
        patched_response
    )

    assert TARGET_RULE_ID in vulnerable_rule_ids
    assert TARGET_RULE_ID not in patched_rule_ids

    introduced_rule_ids = (
        patched_rule_ids - vulnerable_rule_ids
    )

    unexpected_regressions = {
        rule_id
        for rule_id in introduced_rule_ids
        if not _is_expected_shell_removal_finding(
            rule_id
        )
    }

    assert unexpected_regressions == set()

    after_execution = _execute_fixture(
        source=patched_source,
        directory=tmp_path,
        name="after_fix",
    )

    assert after_execution.exit_code == 0
    assert EXPLOIT_MARKER not in after_execution.stdout
    assert EXPLOIT_MARKER not in after_execution.stderr

    after_evidence = DynamicValidationEvaluator().evaluate(
        DynamicValidationEvidenceRequest(
            threat_id=THREAT_ID,
            claim_id=claim.claim_id,
            category="command_injection",
            execution=after_execution,
            success_criteria=success_criteria,
        )
    )

    assert after_evidence.verdict == "not_reproduced"
    assert after_evidence.dynamically_confirmed is False

    replay = ValidationReplayComparator().compare(
        ValidationReplayCompareRequest(
            before=before_evidence,
            after=after_evidence,
        )
    )

    assert replay.claim_id == claim.claim_id
    assert replay.verdict == "fixed"
    assert replay.fixed is True
    assert replay.denials == []

    verification = (
        UnifiedFixVerificationEvaluator().evaluate(
            UnifiedFixVerificationRequest(
                claim_id=claim.claim_id,
                patch_sha256="0" * 64,
                replay=replay,
                project_checks=[
                    FixProjectCheck(
                        name="Syntax check",
                        status="passed",
                        details=(
                            "The deterministic patch compiled "
                            "successfully."
                        ),
                    ),
                    FixProjectCheck(
                        name="Dynamic lifecycle fixture",
                        status="passed",
                        details=(
                            "The exploit reproduced before the "
                            "patch and did not reproduce after it."
                        ),
                    ),
                ],
                static_target_resolved=True,
                static_regression_free=(
                    not unexpected_regressions
                ),
            )
        )
    )

    assert verification.claim_id == claim.claim_id
    assert verification.verdict == "verified"
    assert verification.verified is True
    assert verification.project_checks_passed is True
    assert verification.static_target_resolved is True
    assert verification.static_regression_free is True
    assert verification.dynamic_replay_fixed is True

    verified_claim = apply_fix_verification(
        confirmed_claim,
        replay=replay,
        verification=verification,
    )

    assert verified_claim.claim_id == claim.claim_id
    assert verified_claim.state == "verified_fixed"

    evidence_kinds = {
        item.source.kind
        for item in verified_claim.evidence
    }

    assert "scanner" in evidence_kinds
    assert "dynamic_probe" in evidence_kinds
    assert "runtime_execution" in evidence_kinds
    assert "test_result" in evidence_kinds
