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
    assert result["ruleId"] == BLOCK_RULE_ID
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

    assert result["ruleId"] == REVIEW_RULE_ID
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
