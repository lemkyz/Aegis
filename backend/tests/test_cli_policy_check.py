import io
import json
from pathlib import Path

from aegis.cli import (
    EXIT_ALLOW_OR_REVIEW,
    EXIT_ERROR,
    main,
)


def run_policy_check(
    arguments: list[str],
) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()

    exit_code = main(
        arguments,
        environment={},
        stdout=stdout,
        stderr=stderr,
    )

    return (
        exit_code,
        stdout.getvalue(),
        stderr.getvalue(),
    )


def test_no_policy_uses_balanced_default(
    tmp_path: Path,
) -> None:
    exit_code, stdout, stderr = (
        run_policy_check(
            [
                "policy-check",
                "--repository",
                str(tmp_path),
            ]
        )
    )

    assert exit_code == EXIT_ALLOW_OR_REVIEW
    assert stderr == ""
    assert "Status: VALID" in stdout
    assert "Policy file: not found" in stdout
    assert "Profile: balanced" in stdout
    assert (
        "No repository policy found"
        in stdout
    )


def test_valid_policy_text_explains_configuration(
    tmp_path: Path,
) -> None:
    (tmp_path / ".aegis.yml").write_text(
        """
version: 1
profile: strict
fail_on_review: true
rules:
  AEGIS-SHELL-EXECUTION:
    decision: block
waivers:
  - rule_id: AEGIS-SHELL-EXECUTION
    path: scripts/build.py
    reason: Legacy migration tracked in SEC-142
    expires: 2099-08-15
""".lstrip(),
        encoding="utf-8",
    )

    exit_code, stdout, stderr = (
        run_policy_check(
            [
                "policy-check",
                "--repository",
                str(tmp_path),
            ]
        )
    )

    assert exit_code == EXIT_ALLOW_OR_REVIEW
    assert stderr == ""
    assert "Profile: strict" in stdout
    assert "Fail on review: yes" in stdout
    assert "Rule overrides: 1" in stdout
    assert "1 active, 0 expired" in stdout
    assert (
        "AEGIS-SHELL-EXECUTION: BLOCK"
        in stdout
    )
    assert "[ACTIVE]" in stdout


def test_json_report_separates_active_and_expired_waivers(
    tmp_path: Path,
) -> None:
    (tmp_path / ".aegis.yml").write_text(
        """
version: 1
waivers:
  - rule_id: AEGIS-SHELL-EXECUTION
    path: scripts/current.py
    reason: Current migration tracked in SEC-200
    expires: 2099-12-31
  - rule_id: AEGIS-DYNAMIC-EXECUTION
    path: scripts/old.py
    reason: Historical migration tracked in SEC-100
    expires: 2020-01-01
""".lstrip(),
        encoding="utf-8",
    )

    exit_code, stdout, stderr = (
        run_policy_check(
            [
                "policy-check",
                "--repository",
                str(tmp_path),
                "--format",
                "json",
            ]
        )
    )

    assert exit_code == EXIT_ALLOW_OR_REVIEW
    assert stderr == ""

    payload = json.loads(stdout)

    assert payload["status"] == "valid"
    assert payload["policy_found"] is True
    assert payload["profile"] == "balanced"
    assert payload["waiver_count"] == 2
    assert payload["active_waiver_count"] == 1
    assert payload["expired_waiver_count"] == 1

    statuses = {
        waiver["rule_id"]: waiver["status"]
        for waiver in payload["waivers"]
    }

    assert statuses == {
        "AEGIS-SHELL-EXECUTION": "active",
        "AEGIS-DYNAMIC-EXECUTION": "expired",
    }


def test_invalid_policy_returns_error(
    tmp_path: Path,
) -> None:
    (tmp_path / ".aegis.yml").write_text(
        """
version: 1
rules:
  AEGIS-HARDCODED-CREDENTIAL:
    decision: allow
""".lstrip(),
        encoding="utf-8",
    )

    exit_code, stdout, stderr = (
        run_policy_check(
            [
                "policy-check",
                "--repository",
                str(tmp_path),
            ]
        )
    )

    assert exit_code == EXIT_ERROR
    assert stdout == ""
    assert (
        "Aegis policy check failed"
        in stderr
    )
    assert (
        "validation failed"
        in stderr
    )


def test_invalid_policy_json_is_machine_readable(
    tmp_path: Path,
) -> None:
    (tmp_path / ".aegis.yml").write_text(
        "version: 999\n",
        encoding="utf-8",
    )

    exit_code, stdout, stderr = (
        run_policy_check(
            [
                "policy-check",
                "--repository",
                str(tmp_path),
                "--format",
                "json",
            ]
        )
    )

    assert exit_code == EXIT_ERROR
    assert stderr == ""

    payload = json.loads(stdout)

    assert payload["status"] == "invalid"
    assert "validation failed" in payload["error"]


def test_both_policy_filenames_are_rejected(
    tmp_path: Path,
) -> None:
    (tmp_path / ".aegis.yml").write_text(
        "version: 1\n",
        encoding="utf-8",
    )
    (tmp_path / ".aegis.yaml").write_text(
        "version: 1\n",
        encoding="utf-8",
    )

    exit_code, stdout, stderr = (
        run_policy_check(
            [
                "policy-check",
                "--repository",
                str(tmp_path),
            ]
        )
    )

    assert exit_code == EXIT_ERROR
    assert stdout == ""
    assert "both" in stderr


def test_missing_repository_is_rejected(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing"

    exit_code, stdout, stderr = (
        run_policy_check(
            [
                "policy-check",
                "--repository",
                str(missing),
            ]
        )
    )

    assert exit_code == EXIT_ERROR
    assert stdout == ""
    assert "does not exist" in stderr
