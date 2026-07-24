import subprocess
from pathlib import Path

import pytest

from aegis.security.project_identity import (
    ProjectIdentityResolver,
)


def git(
    repository: Path,
    *arguments: str,
) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
    )

    return result.stdout.strip()


def repository(
    tmp_path: Path,
    *,
    remote: str | None = None,
) -> Path:
    root = tmp_path / "project"
    root.mkdir()

    git(root, "init", "-b", "main")
    git(
        root,
        "config",
        "user.name",
        "Aegis Test",
    )
    git(
        root,
        "config",
        "user.email",
        "aegis@example.invalid",
    )

    (root / "app.py").write_text(
        "print('safe')\n",
        encoding="utf-8",
    )

    git(root, "add", "app.py")
    git(
        root,
        "commit",
        "-m",
        "Initial commit",
    )

    if remote is not None:
        git(
            root,
            "remote",
            "add",
            "origin",
            remote,
        )

    return root


def test_resolves_clean_git_repository(
    tmp_path: Path,
) -> None:
    root = repository(
        tmp_path,
        remote=(
            "https://github.com/"
            "lemkyz/aegis.git"
        ),
    )

    context = (
        ProjectIdentityResolver()
        .resolve(root)
    )

    head = git(root, "rev-parse", "HEAD")

    assert context.project_id.startswith(
        "project:sha256:"
    )
    assert context.identity_source == (
        "git_remote"
    )
    assert context.remote == (
        "https://github.com/lemkyz/aegis"
    )
    assert context.repository_root == (
        root.resolve().as_posix()
    )
    assert context.branch == "main"
    assert context.head_commit == head
    assert context.revision == f"git:{head}"
    assert context.dirty is False


@pytest.mark.parametrize(
    "remote",
    [
        "https://github.com/lemkyz/aegis.git",
        "http://github.com/lemkyz/aegis.git",
        "ssh://git@github.com/lemkyz/aegis.git",
        "git@github.com:lemkyz/aegis.git",
        "git://github.com/lemkyz/aegis.git",
    ],
)
def test_common_remote_forms_have_same_identity(
    tmp_path: Path,
    remote: str,
) -> None:
    root = repository(
        tmp_path,
        remote=remote,
    )

    context = (
        ProjectIdentityResolver()
        .resolve(root)
    )

    assert context.remote == (
        "https://github.com/lemkyz/aegis"
    )

    expected = (
        ProjectIdentityResolver()
        ._stable_id(
            "project",
            "git_remote",
            (
                "https://github.com/"
                "lemkyz/aegis"
            ),
        )
    )

    assert context.project_id == expected


def test_tracked_change_marks_revision_dirty(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    resolver = ProjectIdentityResolver()

    clean = resolver.resolve(root)

    (root / "app.py").write_text(
        "print('changed')\n",
        encoding="utf-8",
    )

    dirty = resolver.resolve(root)

    assert clean.dirty is False
    assert dirty.dirty is True
    assert dirty.head_commit == clean.head_commit
    assert dirty.revision.startswith(
        f"git:{clean.head_commit}:dirty:"
    )
    assert dirty.revision != clean.revision


def test_staged_change_affects_revision(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    resolver = ProjectIdentityResolver()

    (root / "app.py").write_text(
        "print('staged')\n",
        encoding="utf-8",
    )
    git(root, "add", "app.py")

    first = resolver.resolve(root)

    (root / "app.py").write_text(
        "print('staged-again')\n",
        encoding="utf-8",
    )
    git(root, "add", "app.py")

    second = resolver.resolve(root)

    assert first.dirty is True
    assert second.dirty is True
    assert first.revision != second.revision


def test_untracked_content_affects_revision(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    resolver = ProjectIdentityResolver()

    untracked = root / "new.py"
    untracked.write_text(
        "value = 1\n",
        encoding="utf-8",
    )

    first = resolver.resolve(root)

    untracked.write_text(
        "value = 2\n",
        encoding="utf-8",
    )

    second = resolver.resolve(root)

    assert first.dirty is True
    assert second.dirty is True
    assert first.revision != second.revision


def test_ignored_file_does_not_affect_revision(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / ".gitignore").write_text(
        "*.sqlite3\n",
        encoding="utf-8",
    )
    git(root, "add", ".gitignore")
    git(
        root,
        "commit",
        "-m",
        "Ignore local databases",
    )

    resolver = ProjectIdentityResolver()

    before = resolver.resolve(root)

    (root / "memory.sqlite3").write_bytes(
        b"local memory"
    )

    after = resolver.resolve(root)

    assert before.dirty is False
    assert after.dirty is False
    assert before.revision == after.revision


def test_same_repository_subdirectory_resolves_same_context(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    nested = root / "src" / "package"
    nested.mkdir(parents=True)

    resolver = ProjectIdentityResolver()

    from_root = resolver.resolve(root)
    from_nested = resolver.resolve(nested)

    assert (
        from_root.project_id
        == from_nested.project_id
    )
    assert (
        from_root.repository_root
        == from_nested.repository_root
    )
    assert (
        from_root.revision
        == from_nested.revision
    )


def test_remote_identity_survives_clone_location_change(
    tmp_path: Path,
) -> None:
    first_parent = tmp_path / "first"
    second_parent = tmp_path / "second"
    first_parent.mkdir()
    second_parent.mkdir()

    first = repository(
        first_parent,
        remote=(
            "git@github.com:"
            "lemkyz/aegis.git"
        ),
    )
    second = repository(
        second_parent,
        remote=(
            "https://github.com/"
            "lemkyz/aegis.git"
        ),
    )

    resolver = ProjectIdentityResolver()

    first_context = resolver.resolve(first)
    second_context = resolver.resolve(second)

    assert (
        first_context.project_id
        == second_context.project_id
    )
    assert (
        first_context.repository_root
        != second_context.repository_root
    )


def test_local_git_repository_uses_root_path_identity(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    context = (
        ProjectIdentityResolver()
        .resolve(root)
    )

    assert context.identity_source == (
        "local_path"
    )
    assert context.remote is None
    assert context.project_id.startswith(
        "project:sha256:"
    )


def test_non_git_directory_uses_working_tree_fallback(
    tmp_path: Path,
) -> None:
    root = tmp_path / "plain-project"
    root.mkdir()

    file_path = root / "app.py"
    file_path.write_text(
        "value = 1\n",
        encoding="utf-8",
    )

    resolver = ProjectIdentityResolver()

    first = resolver.resolve(root)

    file_path.write_text(
        "value = 2\n",
        encoding="utf-8",
    )

    second = resolver.resolve(root)

    assert first.identity_source == (
        "local_path"
    )
    assert first.remote is None
    assert first.head_commit is None
    assert first.branch is None
    assert first.dirty is True
    assert first.revision.startswith(
        "working-tree:"
    )
    assert first.project_id == (
        second.project_id
    )
    assert first.revision != second.revision


def test_file_path_resolves_parent_project(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    from_file = (
        ProjectIdentityResolver()
        .resolve(root / "app.py")
    )
    from_root = (
        ProjectIdentityResolver()
        .resolve(root)
    )

    assert (
        from_file.project_id
        == from_root.project_id
    )
    assert (
        from_file.repository_root
        == from_root.repository_root
    )


def test_rejects_missing_path(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ValueError,
        match="does not exist",
    ):
        ProjectIdentityResolver().resolve(
            tmp_path / "missing"
        )
