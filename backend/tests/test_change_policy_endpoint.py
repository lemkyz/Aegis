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
    get_change_policy_service,
)
from aegis.main import app
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


@pytest.fixture
def client() -> TestClient:
    service = ChangePolicyService(
        collector=GitChangeCollector(),
        engine=ChangeAwarePolicyEngine(),
    )

    app.dependency_overrides[
        get_change_policy_service
    ] = lambda: service

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def test_endpoint_blocks_dangerous_change(
    client: TestClient,
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    (root / "config.py").write_text(
        'password = "production-password"\n',
        encoding="utf-8",
    )

    response = client.post(
        "/v1/changes/collect-and-evaluate",
        json={
            "repository_path": str(root),
            "mode": "uncommitted",
            "profile": "balanced",
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["change_set"]["file_count"] == 1
    assert payload["policy"]["decision"] == "block"
    assert payload["policy"]["blocking_paths"] == [
        "config.py"
    ]


def test_endpoint_allows_empty_change_set(
    client: TestClient,
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    response = client.post(
        "/v1/changes/collect-and-evaluate",
        json={
            "repository_path": str(root),
            "mode": "staged",
        },
    )

    assert response.status_code == 200
    assert (
        response.json()["policy"]["decision"]
        == "allow"
    )


def test_endpoint_rejects_invalid_mode(
    client: TestClient,
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)

    response = client.post(
        "/v1/changes/collect-and-evaluate",
        json={
            "repository_path": str(root),
            "mode": "all",
        },
    )

    assert response.status_code == 422


def test_endpoint_rejects_missing_repository(
    client: TestClient,
    tmp_path: Path,
) -> None:
    response = client.post(
        "/v1/changes/collect-and-evaluate",
        json={
            "repository_path": str(
                tmp_path / "missing"
            ),
            "mode": "staged",
        },
    )

    assert response.status_code == 400
