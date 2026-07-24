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
    get_security_memory_service,
)
from aegis.main import app
from aegis.schemas.memory import (
    SecurityMemoryRecordRequest,
)
from aegis.security.security_memory import (
    SecurityMemoryService,
)
from aegis.security.sqlite_memory import (
    SQLiteProjectMemoryStore,
)


client = TestClient(app)


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


def repository(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()

    git(root, "init", "-b", "main")
    git(root, "config", "user.name", "Aegis Test")
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
    git(root, "commit", "-m", "Initial commit")
    git(
        root,
        "remote",
        "add",
        "origin",
        (
            "https://github.com/"
            "lemkyz/read-endpoint-test.git"
        ),
    )

    return root


@pytest.fixture
def memory_override(tmp_path: Path):
    service = SecurityMemoryService(
        store=SQLiteProjectMemoryStore(
            tmp_path / "security-memory.sqlite3"
        )
    )

    app.dependency_overrides[
        get_security_memory_service
    ] = lambda: service

    try:
        yield service
    finally:
        app.dependency_overrides.pop(
            get_security_memory_service,
            None,
        )


def record_empty_snapshot(
    service: SecurityMemoryService,
    root: Path,
):
    return service.record(
        SecurityMemoryRecordRequest(
            repository_path=str(root),
            claims=[],
        )
    )


def test_latest_returns_project_snapshot(
    tmp_path: Path,
    memory_override: SecurityMemoryService,
) -> None:
    root = repository(tmp_path)
    recorded = record_empty_snapshot(
        memory_override,
        root,
    )

    response = client.get(
        "/v1/security-memory/latest",
        params={
            "repository_path": str(root),
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["snapshot"]["snapshot_id"] == (
        recorded.snapshot.snapshot_id
    )
    assert payload["repository"]["project_id"] == (
        recorded.repository.project_id
    )


def test_latest_returns_404_without_history(
    tmp_path: Path,
    memory_override: SecurityMemoryService,
) -> None:
    root = repository(tmp_path)

    response = client.get(
        "/v1/security-memory/latest",
        params={
            "repository_path": str(root),
        },
    )

    assert response.status_code == 404


def test_history_returns_newest_first(
    tmp_path: Path,
    memory_override: SecurityMemoryService,
) -> None:
    root = repository(tmp_path)

    first = record_empty_snapshot(
        memory_override,
        root,
    )

    (root / "app.py").write_text(
        "print('second')\n",
        encoding="utf-8",
    )
    git(root, "add", "app.py")
    git(root, "commit", "-m", "Second revision")

    second = record_empty_snapshot(
        memory_override,
        root,
    )

    response = client.get(
        "/v1/security-memory/history",
        params={
            "repository_path": str(root),
            "limit": 10,
            "offset": 0,
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["count"] == 2
    assert payload["limit"] == 10
    assert payload["offset"] == 0
    assert [
        item["snapshot_id"]
        for item in payload["snapshots"]
    ] == [
        second.snapshot.snapshot_id,
        first.snapshot.snapshot_id,
    ]


def test_history_validates_pagination(
    tmp_path: Path,
    memory_override: SecurityMemoryService,
) -> None:
    root = repository(tmp_path)

    response = client.get(
        "/v1/security-memory/history",
        params={
            "repository_path": str(root),
            "limit": 0,
            "offset": -1,
        },
    )

    assert response.status_code == 422


def test_snapshot_endpoint_returns_snapshot(
    tmp_path: Path,
    memory_override: SecurityMemoryService,
) -> None:
    root = repository(tmp_path)
    recorded = record_empty_snapshot(
        memory_override,
        root,
    )

    response = client.get(
        (
            "/v1/security-memory/snapshots/"
            + recorded.snapshot.snapshot_id
        )
    )

    assert response.status_code == 200
    assert response.json()["snapshot"][
        "snapshot_id"
    ] == recorded.snapshot.snapshot_id


def test_snapshot_endpoint_returns_404(
    memory_override: SecurityMemoryService,
) -> None:
    response = client.get(
        "/v1/security-memory/snapshots/"
        "snapshot:sha256:missing"
    )

    assert response.status_code == 404


def test_read_endpoint_runtime_errors_are_redacted(
    tmp_path: Path,
    monkeypatch,
    memory_override: SecurityMemoryService,
) -> None:
    root = repository(tmp_path)

    def fail_latest(project_id: str):
        raise RuntimeError(
            "secret sqlite payload"
        )

    monkeypatch.setattr(
        memory_override.store,
        "get_latest_snapshot",
        fail_latest,
    )

    response = client.get(
        "/v1/security-memory/latest",
        params={
            "repository_path": str(root),
        },
    )

    assert response.status_code == 500
    assert "secret sqlite payload" not in (
        response.json()["detail"]
    )
