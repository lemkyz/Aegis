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
    get_security_memory_policy_service,
)
from aegis.main import app
from aegis.security.memory_policy import (
    MemoryAwarePolicyEngine,
)
from aegis.security.memory_policy_service import (
    SecurityMemoryPolicyService,
)
from aegis.security.security_memory import (
    SecurityMemoryService,
)
from aegis.security.sqlite_memory import (
    SQLiteProjectMemoryStore,
)


def create_repository(tmp_path: Path) -> Path:
    repository = tmp_path / "repository"
    repository.mkdir()

    commands = [
        ["git", "init", "-b", "main"],
        [
            "git",
            "config",
            "user.email",
            "aegis-tests@example.com",
        ],
        [
            "git",
            "config",
            "user.name",
            "Aegis Tests",
        ],
    ]

    for command in commands:
        subprocess.run(
            command,
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        )

    (repository / "app.py").write_text(
        "print('aegis')\n",
        encoding="utf-8",
    )

    subprocess.run(
        ["git", "add", "app.py"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )

    return repository


@pytest.fixture
def client(tmp_path: Path):
    combined_service = SecurityMemoryPolicyService(
        memory_service=SecurityMemoryService(
            store=SQLiteProjectMemoryStore(
                tmp_path / "memory.sqlite3"
            )
        ),
        policy_engine=MemoryAwarePolicyEngine(),
    )

    app.dependency_overrides[
        get_security_memory_policy_service
    ] = lambda: combined_service

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def claim_payload(
    claim_id: str,
    *,
    severity: str,
    state: str,
) -> dict[str, object]:
    return {
        "claim_id": claim_id,
        "statement": "A security issue exists.",
        "category": "command-injection",
        "severity": severity,
        "confidence": 1.0,
        "state": state,
        "cwe": ["CWE-78"],
        "owasp": ["A03:2021"],
        "locations": [],
        "evidence": [],
        "relationships": [],
        "remediation": "Apply a secure fix.",
    }


def test_record_and_evaluate_endpoint_blocks(
    client: TestClient,
    tmp_path: Path,
) -> None:
    repository = create_repository(tmp_path)

    response = client.post(
        "/v1/security-memory/record-and-evaluate",
        json={
            "repository_path": str(repository),
            "claims": [
                claim_payload(
                    "claim:critical",
                    severity="critical",
                    state="confirmed",
                )
            ],
            "profile": "balanced",
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["memory"]["baseline_created"] is True
    assert (
        payload["memory"]["reconciliation"]["summary"][
            "new"
        ]
        == 1
    )
    assert payload["policy"]["decision"] == "block"
    assert payload["policy"]["blocking_claim_ids"] == [
        "claim:critical"
    ]


def test_record_and_evaluate_validates_profile(
    client: TestClient,
    tmp_path: Path,
) -> None:
    repository = create_repository(tmp_path)

    response = client.post(
        "/v1/security-memory/record-and-evaluate",
        json={
            "repository_path": str(repository),
            "claims": [],
            "profile": "unknown",
        },
    )

    assert response.status_code == 422


def test_record_and_evaluate_rejects_missing_repo(
    client: TestClient,
    tmp_path: Path,
) -> None:
    response = client.post(
        "/v1/security-memory/record-and-evaluate",
        json={
            "repository_path": str(
                tmp_path / "missing"
            ),
            "claims": [],
        },
    )

    assert response.status_code == 400
