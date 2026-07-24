import io
import json
import subprocess
from pathlib import Path

from aegis.cli import (
    EXIT_ALLOW_OR_REVIEW,
    EXIT_BLOCK,
    EXIT_ERROR,
    main,
)
from aegis.security.change_policy import (
    ChangeAwarePolicyEngine,
)
from aegis.security.change_policy_service import (
    ChangePolicyService,
)
from aegis.security.git_changes import (
    GitChangeCollector,
)


def git(
    root: Path,
    *arguments: str,
) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )

    return result.stdout.strip()


def repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    root.mkdir()

    git(root, "init", "-b", "main")
    git(
        root,
        "config",
        "user.email",
        "aegis-tests@example.com",
    )
    git(
        root,
        "config",
        "user.name",
        "Aegis Tests",
    )

    (root / "app.py").write_text(
        "print('safe')\n",
        encoding="utf-8",
    )

    git(root, "add", "app.py")
    git(root, "commit", "-m", "Initial commit")

    return root


def service() -> ChangePolicyService:
    return ChangePolicyService(
        collector=GitChangeCollector(),
        engine=ChangeAwarePolicyEngine(),
    )


def run_cli(
    arguments: list[str],
    *,
    environment: dict[str, str] | None = None,
):
    stdout = io.StringIO()
    stderr = io.StringIO()

    exit_code = main(
        arguments,
        environment=environment or {},
        stdout=stdout,
        stderr=stderr,
        service=service(),
    )

    return (
        exit_code,
        stdout.getvalue(),
        stderr.getvalue(),
    )


def test_safe_change_returns_zero(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / "app.py").write_text(
        "print('safe')\n"
        "print('still safe')\n",
        encoding="utf-8",
    )

    exit_code, stdout, stderr = run_cli(
        [
            "change-gate",
            "--repository",
            str(root),
            "--mode",
            "uncommitted",
        ]
    )

    assert exit_code == EXIT_ALLOW_OR_REVIEW
    assert "Decision: ALLOW" in stdout
    assert stderr == ""


def test_blocking_change_returns_two(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / "config.py").write_text(
        'api_key = "production-secret-token"\n',
        encoding="utf-8",
    )

    exit_code, stdout, stderr = run_cli(
        [
            "change-gate",
            "--repository",
            str(root),
            "--format",
            "json",
        ]
    )

    assert exit_code == EXIT_BLOCK
    assert json.loads(stdout)[
        "policy"
    ]["decision"] == "block"
    assert stderr == ""


def test_review_returns_zero_by_default(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / "app.py").write_text(
        "import subprocess\n"
        "subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )

    exit_code, stdout, _ = run_cli(
        [
            "change-gate",
            "--repository",
            str(root),
        ]
    )

    assert exit_code == EXIT_ALLOW_OR_REVIEW
    assert "Decision: REVIEW" in stdout


def test_fail_on_review_returns_two(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / "app.py").write_text(
        "import subprocess\n"
        "subprocess.run(command, shell=True)\n",
        encoding="utf-8",
    )

    exit_code, _, _ = run_cli(
        [
            "change-gate",
            "--repository",
            str(root),
            "--fail-on-review",
        ]
    )

    assert exit_code == EXIT_BLOCK


def test_writes_json_artifact(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    output_path = tmp_path / "result.json"

    exit_code, _, _ = run_cli(
        [
            "change-gate",
            "--repository",
            str(root),
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == EXIT_ALLOW_OR_REVIEW

    payload = json.loads(
        output_path.read_text(
            encoding="utf-8",
        )
    )

    assert payload["policy"]["decision"] == "allow"


def test_writes_github_outputs_and_summary(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / "config.py").write_text(
        'token = "production-secret-token"\n',
        encoding="utf-8",
    )

    output_path = tmp_path / "github-output.txt"
    summary_path = tmp_path / "summary.md"

    exit_code, _, _ = run_cli(
        [
            "change-gate",
            "--repository",
            str(root),
        ],
        environment={
            "GITHUB_OUTPUT": str(output_path),
            "GITHUB_STEP_SUMMARY": str(
                summary_path
            ),
        },
    )

    assert exit_code == EXIT_BLOCK

    outputs = output_path.read_text(
        encoding="utf-8",
    )
    summary = summary_path.read_text(
        encoding="utf-8",
    )

    assert "decision=block" in outputs
    assert "risk_score=" in outputs
    assert "blocked_files=1" in outputs

    assert (
        "## Aegis Change Security Gate"
        in summary
    )
    assert "**BLOCK**" in summary
    assert "`config.py`" in summary


def test_missing_repository_returns_error(
    tmp_path: Path,
) -> None:
    exit_code, stdout, stderr = run_cli(
        [
            "change-gate",
            "--repository",
            str(tmp_path / "missing"),
        ]
    )

    assert exit_code == EXIT_ERROR
    assert stdout == ""
    assert "does not exist" in stderr


def test_pull_request_mode_evaluates_commits(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    base_commit = git(root, "rev-parse", "HEAD")

    git(root, "switch", "-c", "feature")

    (root / "config.py").write_text(
        'api_key = "production-secret-token"\n',
        encoding="utf-8",
    )
    git(root, "add", "config.py")
    git(root, "commit", "-m", "Dangerous feature")

    head_commit = git(root, "rev-parse", "HEAD")

    exit_code, stdout, stderr = run_cli(
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
            "--format",
            "json",
        ]
    )

    assert exit_code == EXIT_BLOCK
    assert stderr == ""

    payload = json.loads(stdout)

    assert payload["policy"]["decision"] == "block"
    assert payload["change_set"]["mode"] == (
        "pull_request"
    )
    assert payload["change_set"][
        "base_revision"
    ] == base_commit
    assert payload["change_set"][
        "head_revision"
    ] == head_commit


def test_pull_request_cli_requires_base(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    exit_code, stdout, stderr = run_cli(
        [
            "change-gate",
            "--repository",
            str(root),
            "--mode",
            "pull_request",
        ]
    )

    assert exit_code == EXIT_ERROR
    assert stdout == ""
    assert "requires base_revision" in stderr
