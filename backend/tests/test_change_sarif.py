import json
from pathlib import Path

from aegis.cli import main
from aegis.security.change_sarif import (
    BLOCK_RULE_ID,
    REVIEW_RULE_ID,
    artifact_uri,
)

from tests.test_cli_change_gate import (
    git,
    repository,
)


def run_cli(
    arguments: list[str],
) -> tuple[int, str, str]:
    from io import StringIO

    stdout = StringIO()
    stderr = StringIO()

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


def test_artifact_uri_is_relative_and_encoded() -> None:
    assert artifact_uri(
        "src/my file.py"
    ) == "src/my%20file.py"

    assert artifact_uri(
        r"src\module.py"
    ) == "src/module.py"


def test_blocking_change_writes_sarif(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    sarif_path = tmp_path / "aegis.sarif"

    (root / "config.py").write_text(
        'api_key = "production-secret-token"\n',
        encoding="utf-8",
    )

    exit_code, _, stderr = run_cli(
        [
            "change-gate",
            "--repository",
            str(root),
            "--sarif",
            str(sarif_path),
        ]
    )

    assert exit_code == 2
    assert stderr == ""

    payload = json.loads(
        sarif_path.read_text(
            encoding="utf-8",
        )
    )

    assert payload["version"] == "2.1.0"

    run = payload["runs"][0]
    result = run["results"][0]

    assert run["tool"]["driver"]["name"] == (
        "Aegis Change Security Gate"
    )
    assert result["ruleId"] == "AEGIS-HARDCODED-CREDENTIAL"
    assert result["level"] == "error"
    assert result["locations"][0][
        "physicalLocation"
    ]["artifactLocation"]["uri"] == "config.py"
    assert result["properties"]["riskScore"] == 85
    assert result["properties"]["decision"] == "block"


def test_review_change_uses_warning_level(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    sarif_path = tmp_path / "review.sarif"

    (root / "app.py").write_text(
        "import subprocess\n"
        "subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )

    exit_code, _, stderr = run_cli(
        [
            "change-gate",
            "--repository",
            str(root),
            "--sarif",
            str(sarif_path),
        ]
    )

    assert exit_code == 0
    assert stderr == ""

    payload = json.loads(
        sarif_path.read_text(
            encoding="utf-8",
        )
    )
    result = payload["runs"][0]["results"][0]

    assert result["ruleId"] == "AEGIS-SHELL-EXECUTION"
    assert result["level"] == "warning"
    assert result["properties"]["decision"] == "review"


def test_allow_change_has_no_sarif_results(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    sarif_path = tmp_path / "allow.sarif"

    (root / "app.py").write_text(
        "print('safe')\n"
        "print('still safe')\n",
        encoding="utf-8",
    )

    exit_code, _, stderr = run_cli(
        [
            "change-gate",
            "--repository",
            str(root),
            "--sarif",
            str(sarif_path),
        ]
    )

    assert exit_code == 0
    assert stderr == ""

    payload = json.loads(
        sarif_path.read_text(
            encoding="utf-8",
        )
    )

    assert payload["runs"][0]["results"] == []


def test_pull_request_sarif_uses_commit_diff(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    sarif_path = tmp_path / "pr.sarif"

    base_commit = git(root, "rev-parse", "HEAD")

    git(root, "switch", "-c", "feature")

    (root / "config.py").write_text(
        'token = "production-secret-token"\n',
        encoding="utf-8",
    )

    git(root, "add", "config.py")
    git(root, "commit", "-m", "Dangerous change")

    head_commit = git(root, "rev-parse", "HEAD")

    exit_code, _, stderr = run_cli(
        [
            "change-gate",
            "--repository",
            str(root),
            "--mode",
            "pull_request",
            "--base",
            base_commit,
            "--head",
            head_commit,
            "--sarif",
            str(sarif_path),
        ]
    )

    assert exit_code == 2
    assert stderr == ""

    payload = json.loads(
        sarif_path.read_text(
            encoding="utf-8",
        )
    )

    properties = payload["runs"][0][
        "invocations"
    ][0]["properties"]

    assert properties["mode"] == "pull_request"
    assert properties["baseRevision"] == base_commit
    assert properties["headRevision"] == head_commit


def test_sarif_uses_specific_rule_and_source_region(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    sarif_path = tmp_path / "located.sarif"

    (root / "app.py").write_text(
        "safe = True\n"
        'api_key = "production-secret-token"\n',
        encoding="utf-8",
    )

    exit_code, _, stderr = run_cli(
        [
            "change-gate",
            "--repository",
            str(root),
            "--sarif",
            str(sarif_path),
        ]
    )

    assert exit_code == 2
    assert stderr == ""

    payload = json.loads(
        sarif_path.read_text(
            encoding="utf-8",
        )
    )

    run = payload["runs"][0]
    result = run["results"][0]
    location = result["locations"][0][
        "physicalLocation"
    ]

    assert result["ruleId"] == (
        "AEGIS-HARDCODED-CREDENTIAL"
    )
    assert location["region"]["startLine"] == 2
    assert location["region"]["startColumn"] == 1

    rule_ids = {
        rule["id"]
        for rule in run["tool"]["driver"]["rules"]
    }

    assert rule_ids == {
        "AEGIS-HARDCODED-CREDENTIAL"
    }


def test_sarif_fingerprint_survives_line_movement(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    first_path = tmp_path / "first.sarif"
    second_path = tmp_path / "second.sarif"

    (root / "config.py").write_text(
        'api_key = "production-secret-token"\n',
        encoding="utf-8",
    )

    first_exit, _, first_error = run_cli(
        [
            "change-gate",
            "--repository",
            str(root),
            "--sarif",
            str(first_path),
        ]
    )

    assert first_exit == 2
    assert first_error == ""

    (root / "config.py").write_text(
        "# configuration\n"
        "# moved downward\n"
        'api_key = "production-secret-token"\n',
        encoding="utf-8",
    )

    second_exit, _, second_error = run_cli(
        [
            "change-gate",
            "--repository",
            str(root),
            "--sarif",
            str(second_path),
        ]
    )

    assert second_exit == 2
    assert second_error == ""

    first = json.loads(
        first_path.read_text(
            encoding="utf-8",
        )
    )["runs"][0]["results"][0]

    second = json.loads(
        second_path.read_text(
            encoding="utf-8",
        )
    )["runs"][0]["results"][0]

    assert first["locations"][0][
        "physicalLocation"
    ]["region"]["startLine"] == 1

    assert second["locations"][0][
        "physicalLocation"
    ]["region"]["startLine"] == 3

    assert (
        first["partialFingerprints"][
            "aegisRulePathOccurrence/v1"
        ]
        == second["partialFingerprints"][
            "aegisRulePathOccurrence/v1"
        ]
    )


def test_generic_non_pattern_result_has_no_region(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    sarif_path = tmp_path / "binary.sarif"

    (root / "artifact.bin").write_bytes(
        b"\x00\x01\x02"
    )

    exit_code, _, stderr = run_cli(
        [
            "change-gate",
            "--repository",
            str(root),
            "--sarif",
            str(sarif_path),
        ]
    )

    assert exit_code == 0
    assert stderr == ""

    payload = json.loads(
        sarif_path.read_text(
            encoding="utf-8",
        )
    )

    result = payload["runs"][0]["results"][0]
    physical = result["locations"][0][
        "physicalLocation"
    ]

    assert result["ruleId"] == (
        "AEGIS-CHANGE-REVIEW"
    )
    assert "region" not in physical


def test_sarif_emits_each_rule_as_separate_result(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    sarif_path = tmp_path / "multiple.sarif"

    (root / "danger.py").write_text(
        "import subprocess\n"
        "subprocess.run(command, shell=True)\n"
        'api_key = "production-secret-token"\n'
        "requests.get(url, verify=False)\n",
        encoding="utf-8",
    )

    exit_code, _, stderr = run_cli(
        [
            "change-gate",
            "--repository",
            str(root),
            "--sarif",
            str(sarif_path),
        ]
    )

    assert exit_code == 2
    assert stderr == ""

    payload = json.loads(
        sarif_path.read_text(
            encoding="utf-8",
        )
    )

    results = payload["runs"][0]["results"]

    assert [
        result["ruleId"]
        for result in results
    ] == [
        "AEGIS-SHELL-EXECUTION",
        "AEGIS-TLS-VERIFICATION-DISABLED",
        "AEGIS-HARDCODED-CREDENTIAL",
    ]

    assert [
        result["locations"][0][
            "physicalLocation"
        ]["region"]["startLine"]
        for result in results
    ] == [2, 4, 3]


def test_repeated_rule_has_distinct_fingerprints(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    sarif_path = tmp_path / "repeated.sarif"

    (root / "app.py").write_text(
        "import subprocess\n"
        "subprocess.run(first, shell=True)\n"
        "subprocess.run(second, shell=True)\n",
        encoding="utf-8",
    )

    exit_code, _, stderr = run_cli(
        [
            "change-gate",
            "--repository",
            str(root),
            "--sarif",
            str(sarif_path),
        ]
    )

    assert exit_code == 0
    assert stderr == ""

    results = json.loads(
        sarif_path.read_text(
            encoding="utf-8",
        )
    )["runs"][0]["results"]

    assert len(results) == 2

    fingerprints = {
        result["partialFingerprints"][
            "aegisRulePathOccurrence/v1"
        ]
        for result in results
    }

    assert len(fingerprints) == 2
