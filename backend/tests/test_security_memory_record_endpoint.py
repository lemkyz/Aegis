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


def repository(
    tmp_path: Path,
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
    git(
        root,
        "remote",
        "add",
        "origin",
        (
            "https://github.com/"
            "lemkyz/endpoint-test.git"
        ),
    )

    return root


def claim_payload(
    claim_id: str = "claim:sha256:test",
) -> dict[str, object]:
    return {
        "claim_id": claim_id,
        "statement": (
            "Untrusted input reaches shell execution."
        ),
        "category": "command-injection",
        "severity": "high",
        "confidence": 0.9,
        "state": "supported",
        "cwe": ["CWE-78"],
        "owasp": ["A03:2021"],
        "locations": [
            {
                "file": "app.py",
                "line_start": 20,
                "line_end": 24,
            }
        ],
        "evidence": [
            {
                "evidence_id": (
                    "evidence:sha256:test"
                ),
                "source": {
                    "kind": "scanner",
                    "name": "Semgrep",
                    "rule_id": (
                        "aegis.python."
                        "command-injection"
                    ),
                },
                "summary": (
                    "Command injection detected."
                ),
                "confidence": 0.9,
            }
        ],
        "relationships": [],
        "remediation": (
            "Disable shell execution."
        ),
    }


@pytest.fixture
def memory_override(
    tmp_path: Path,
):
    service = SecurityMemoryService(
        store=SQLiteProjectMemoryStore(
            tmp_path
            / "security-memory.sqlite3"
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


def test_records_first_security_memory_baseline(
    tmp_path: Path,
    memory_override: SecurityMemoryService,
) -> None:
    root = repository(tmp_path)

    response = client.post(
        "/v1/security-memory/record",
        json={
            "repository_path": str(root),
            "claims": [
                claim_payload()
            ],
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["service"] == (
        "aegis-security-memory-service-v1"
    )
    assert payload["baseline_created"] is True
    assert (
        payload["persisted_new_snapshot"]
        is True
    )
    assert payload["previous_snapshot_id"] is None
    assert payload["project_snapshot_count"] == 1

    assert payload["repository"][
        "identity_source"
    ] == "git_remote"
    assert payload["repository"]["remote"] == (
        "https://github.com/"
        "lemkyz/endpoint-test"
    )
    assert payload["repository"]["dirty"] is False

    assert payload["snapshot"][
        "snapshot_id"
    ].startswith("snapshot:sha256:")
    assert payload["snapshot"]["claim_count"] == 1

    summary = payload["reconciliation"]["summary"]

    assert summary["new"] == 1
    assert summary["persistent"] == 0
    assert summary["changed"] == 0
    assert summary["resolved"] == 0
    assert summary["reopened"] == 0


def test_repeated_record_is_idempotent(
    tmp_path: Path,
    memory_override: SecurityMemoryService,
) -> None:
    root = repository(tmp_path)

    request = {
        "repository_path": str(root),
        "claims": [
            claim_payload()
        ],
    }

    first = client.post(
        "/v1/security-memory/record",
        json=request,
    )
    second = client.post(
        "/v1/security-memory/record",
        json=request,
    )

    assert first.status_code == 200
    assert second.status_code == 200

    first_payload = first.json()
    second_payload = second.json()

    assert (
        first_payload["snapshot"]["snapshot_id"]
        == second_payload["snapshot"]["snapshot_id"]
    )
    assert (
        second_payload["persisted_new_snapshot"]
        is False
    )
    assert second_payload["baseline_created"] is False
    assert second_payload[
        "project_snapshot_count"
    ] == 1
    assert second_payload[
        "reconciliation"
    ]["summary"]["persistent"] == 1


def test_rejects_missing_repository_path(
    tmp_path: Path,
    memory_override: SecurityMemoryService,
) -> None:
    response = client.post(
        "/v1/security-memory/record",
        json={
            "repository_path": str(
                tmp_path / "missing"
            ),
            "claims": [],
        },
    )

    assert response.status_code == 400
    assert "does not exist" in (
        response.json()["detail"]
    )


def test_validates_duplicate_claim_ids(
    tmp_path: Path,
    memory_override: SecurityMemoryService,
) -> None:
    root = repository(tmp_path)
    duplicate = claim_payload()

    response = client.post(
        "/v1/security-memory/record",
        json={
            "repository_path": str(root),
            "claims": [
                duplicate,
                duplicate,
            ],
        },
    )

    assert response.status_code == 422


def test_validates_empty_repository_path(
    memory_override: SecurityMemoryService,
) -> None:
    response = client.post(
        "/v1/security-memory/record",
        json={
            "repository_path": "",
            "claims": [],
        },
    )

    assert response.status_code == 422


def test_internal_runtime_error_is_redacted(
    tmp_path: Path,
    monkeypatch,
    memory_override: SecurityMemoryService,
) -> None:
    root = repository(tmp_path)

    def fail_record(
        request,
        *,
        created_at=None,
    ):
        raise RuntimeError(
            "secret database payload"
        )

    monkeypatch.setattr(
        memory_override,
        "record",
        fail_record,
    )

    response = client.post(
        "/v1/security-memory/record",
        json={
            "repository_path": str(root),
            "claims": [],
        },
    )

    assert response.status_code == 500

    detail = response.json()["detail"]

    assert "secret database payload" not in detail
    assert detail == (
        "Security memory could not record "
        "the project snapshot."
    )
