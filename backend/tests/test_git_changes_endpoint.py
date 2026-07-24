import os
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault(
    "AEGIS_FINGERPRINT_KEY",
    "test-only-fingerprint-key-32-characters",
)

from aegis.dependencies import (
    get_git_change_collector,
)
from aegis.main import app
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


@pytest.fixture
def client() -> TestClient:
    app.dependency_overrides[
        get_git_change_collector
    ] = lambda: GitChangeCollector()

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def test_collects_staged_changes(
    client: TestClient,
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / "app.py").write_text(
        "print('safe')\n"
        "print('staged')\n",
        encoding="utf-8",
    )
    git(root, "add", "app.py")

    response = client.post(
        "/v1/changes/collect",
        json={
            "repository_path": str(root),
            "mode": "staged",
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["mode"] == "staged"
    assert payload["file_count"] == 1
    assert payload["additions"] == 1
    assert payload["deletions"] == 0
    assert payload["files"][0]["path"] == "app.py"
    assert (
        payload["files"][0]["status"]
        == "modified"
    )
    assert (
        "+print('staged')"
        in payload["files"][0]["patch"]
    )


def test_collects_untracked_file(
    client: TestClient,
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / "new.py").write_text(
        "print('new')\n",
        encoding="utf-8",
    )

    response = client.post(
        "/v1/changes/collect",
        json={
            "repository_path": str(root),
            "mode": "uncommitted",
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["file_count"] == 1
    assert payload["files"][0]["path"] == "new.py"
    assert payload["files"][0]["status"] == "added"


def test_rejects_unknown_mode(
    client: TestClient,
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    response = client.post(
        "/v1/changes/collect",
        json={
            "repository_path": str(root),
            "mode": "everything",
        },
    )

    assert response.status_code == 422


def test_rejects_missing_repository(
    client: TestClient,
    tmp_path: Path,
) -> None:
    response = client.post(
        "/v1/changes/collect",
        json={
            "repository_path": str(
                tmp_path / "missing"
            ),
            "mode": "staged",
        },
    )

    assert response.status_code == 400


def test_collector_failure_is_sanitized(
    client: TestClient,
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    class BrokenCollector:
        def collect(
            self,
            repository_path: str,
            *,
            mode: str,
        ):
            raise RuntimeError(
                "sensitive internal Git detail"
            )

    app.dependency_overrides[
        get_git_change_collector
    ] = lambda: BrokenCollector()

    response = client.post(
        "/v1/changes/collect",
        json={
            "repository_path": str(root),
            "mode": "staged",
        },
    )

    assert response.status_code == 500
    assert response.json() == {
        "detail": (
            "Repository changes could not "
            "be collected."
        )
    }
    assert (
        "sensitive internal Git detail"
        not in response.text
    )
