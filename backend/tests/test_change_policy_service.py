import subprocess
from pathlib import Path

from aegis.schemas.change_policy import (
    ChangePolicyCollectionRequest,
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


def test_collects_and_allows_safe_change(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / "app.py").write_text(
        "print('safe')\n"
        "print('still safe')\n",
        encoding="utf-8",
    )

    result = service().collect_and_evaluate(
        ChangePolicyCollectionRequest(
            repository_path=str(root),
            mode="uncommitted",
        )
    )

    assert result.change_set.file_count == 1
    assert result.policy.decision == "allow"


def test_collects_and_blocks_hardcoded_secret(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / "config.py").write_text(
        'api_key = "real-secret-token-value"\n',
        encoding="utf-8",
    )

    result = service().collect_and_evaluate(
        ChangePolicyCollectionRequest(
            repository_path=str(root),
            mode="uncommitted",
        )
    )

    assert result.change_set.file_count == 1
    assert result.policy.decision == "block"
    assert result.policy.blocking_paths == [
        "config.py"
    ]


def test_staged_mode_ignores_unstaged_change(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / "staged.py").write_text(
        "print('staged')\n",
        encoding="utf-8",
    )
    git(root, "add", "staged.py")

    (root / "unstaged.py").write_text(
        'token = "real-secret-token-value"\n',
        encoding="utf-8",
    )

    result = service().collect_and_evaluate(
        ChangePolicyCollectionRequest(
            repository_path=str(root),
            mode="staged",
        )
    )

    assert [
        item.path
        for item in result.change_set.files
    ] == ["staged.py"]
    assert result.policy.decision == "allow"
