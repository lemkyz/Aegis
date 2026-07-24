import subprocess
from pathlib import Path

import pytest

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


def test_collects_staged_patch_and_stats(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / "app.py").write_text(
        "print('safe')\n"
        "print('changed')\n",
        encoding="utf-8",
    )

    git(root, "add", "app.py")

    result = GitChangeCollector().collect(
        root,
        mode="staged",
    )

    assert result.mode == "staged"
    assert result.file_count == 1
    assert result.additions == 1
    assert result.deletions == 0

    change = result.files[0]

    assert change.path == "app.py"
    assert change.status == "modified"
    assert "+print('changed')" in change.patch
    assert change.binary is False


def test_uncommitted_includes_tracked_and_untracked(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / "app.py").write_text(
        "print('modified')\n",
        encoding="utf-8",
    )
    (root / "new.py").write_text(
        "print('new')\n",
        encoding="utf-8",
    )

    result = GitChangeCollector().collect(
        root,
        mode="uncommitted",
    )

    assert [
        item.path
        for item in result.files
    ] == [
        "app.py",
        "new.py",
    ]

    statuses = {
        item.path: item.status
        for item in result.files
    }

    assert statuses == {
        "app.py": "modified",
        "new.py": "added",
    }


def test_collects_staged_rename(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    git(root, "mv", "app.py", "main.py")

    result = GitChangeCollector().collect(
        root,
        mode="staged",
    )

    assert result.file_count == 1

    change = result.files[0]

    assert change.status == "renamed"
    assert change.old_path == "app.py"
    assert change.path == "main.py"


def test_truncates_large_patch(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / "app.py").write_text(
        "\n".join(
            f"print({index})"
            for index in range(100)
        ),
        encoding="utf-8",
    )

    result = GitChangeCollector(
        max_patch_chars=80,
    ).collect(
        root,
        mode="uncommitted",
    )

    assert result.files[0].truncated is True
    assert len(result.files[0].patch) == 80


def test_limits_collected_file_count(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    for name in ["a.py", "b.py"]:
        (root / name).write_text(
            "print('new')\n",
            encoding="utf-8",
        )

    result = GitChangeCollector(
        max_files=1,
    ).collect(
        root,
        mode="uncommitted",
    )

    assert result.file_count == 1
    assert result.truncated is True


def test_rejects_missing_repository(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ValueError,
        match="does not exist",
    ):
        GitChangeCollector().collect(
            tmp_path / "missing",
            mode="staged",
        )


def test_collects_pull_request_commit_diff(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    base_commit = git(root, "rev-parse", "HEAD")

    git(root, "switch", "-c", "feature")

    (root / "app.py").write_text(
        "print('safe')\n"
        "print('feature')\n",
        encoding="utf-8",
    )
    (root / "feature.py").write_text(
        "print('new feature')\n",
        encoding="utf-8",
    )

    git(root, "add", "app.py", "feature.py")
    git(root, "commit", "-m", "Feature change")

    head_commit = git(root, "rev-parse", "HEAD")

    result = GitChangeCollector().collect(
        root,
        mode="pull_request",
        base_revision=base_commit,
        head_revision=head_commit,
    )

    assert result.mode == "pull_request"
    assert result.base_revision == base_commit
    assert result.head_revision == head_commit
    assert result.file_count == 2
    assert [
        item.path
        for item in result.files
    ] == [
        "app.py",
        "feature.py",
    ]
    assert result.additions == 2
    assert result.deletions == 0


def test_pull_request_uses_merge_base(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    base_commit = git(root, "rev-parse", "HEAD")

    git(root, "switch", "-c", "feature")

    (root / "feature.py").write_text(
        "print('feature')\n",
        encoding="utf-8",
    )
    git(root, "add", "feature.py")
    git(root, "commit", "-m", "Feature commit")

    feature_commit = git(root, "rev-parse", "HEAD")

    git(root, "switch", "main")

    (root / "main_only.py").write_text(
        "print('main only')\n",
        encoding="utf-8",
    )
    git(root, "add", "main_only.py")
    git(root, "commit", "-m", "Main commit")

    main_commit = git(root, "rev-parse", "HEAD")

    result = GitChangeCollector().collect(
        root,
        mode="pull_request",
        base_revision=main_commit,
        head_revision=feature_commit,
    )

    assert result.base_revision == base_commit
    assert result.head_revision == feature_commit
    assert [
        item.path
        for item in result.files
    ] == ["feature.py"]


def test_pull_request_rejects_missing_base(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    with pytest.raises(
        ValueError,
        match="requires base_revision",
    ):
        GitChangeCollector().collect(
            root,
            mode="pull_request",
        )


def test_pull_request_rejects_invalid_revision(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    with pytest.raises(
        ValueError,
        match="could not be resolved",
    ):
        GitChangeCollector().collect(
            root,
            mode="pull_request",
            base_revision="missing-branch",
        )


def test_pull_request_rejects_option_like_revision(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    with pytest.raises(
        ValueError,
        match="cannot begin",
    ):
        GitChangeCollector().collect(
            root,
            mode="pull_request",
            base_revision="--help",
        )
