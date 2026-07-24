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

CLAIM_ID = (
    "claim:sha256:"
    "reopened-command-injection-lifecycle"
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


def commit_file(
    repository: Path,
    code: str,
    message: str,
) -> None:
    (repository / "app.py").write_text(
        code,
        encoding="utf-8",
    )

    git(repository, "add", "app.py")
    git(repository, "commit", "-m", message)


def create_repository(
    tmp_path: Path,
) -> Path:
    repository = tmp_path / "project"
    repository.mkdir()

    git(repository, "init", "-b", "main")
    git(
        repository,
        "config",
        "user.name",
        "Aegis Test",
    )
    git(
        repository,
        "config",
        "user.email",
        "aegis@example.invalid",
    )
    git(
        repository,
        "remote",
        "add",
        "origin",
        (
            "https://github.com/"
            "lemkyz/reopened-lifecycle-test.git"
        ),
    )

    return repository


def vulnerable_code() -> str:
    return """\
import subprocess


def run(user_input: str) -> None:
    subprocess.run(
        user_input,
        shell=True,
        check=False,
    )
"""


def fixed_code() -> str:
    return """\
import subprocess


ALLOWED_COMMANDS = {
    "status": ["git", "status", "--short"],
}


def run(command_name: str) -> None:
    command = ALLOWED_COMMANDS[command_name]

    subprocess.run(
        command,
        shell=False,
        check=True,
    )
"""


def claim(
    *,
    state: str,
    evidence_suffix: str,
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "claim_id": CLAIM_ID,
        "statement": (
            "Untrusted input reaches subprocess execution "
            "with shell=True."
        ),
        "category": "command-injection",
        "severity": "high",
        "confidence": 0.99,
        "state": state,
        "cwe": ["CWE-78"],
        "owasp": ["A03:2021"],
        "locations": [
            {
                "file": "app.py",
                "line_start": 5,
                "line_end": 10,
                "symbol": "run",
            }
        ],
        "evidence": [
            {
                "evidence_id": (
                    "evidence:sha256:"
                    f"{evidence_suffix}"
                ),
                "source": {
                    "kind": (
                        "test_result"
                        if state == "verified_fixed"
                        else "scanner"
                    ),
                    "name": (
                        "Aegis Fix Verification"
                        if state == "verified_fixed"
                        else "Semgrep"
                    ),
                    "rule_id": (
                        "aegis.fix-verification"
                        if state == "verified_fixed"
                        else (
                            "aegis.python."
                            "command-injection"
                        )
                    ),
                    "version": "1",
                },
                "summary": (
                    "The vulnerable shell execution was "
                    "verified as removed."
                    if state == "verified_fixed"
                    else (
                        "Shell command injection was "
                        "detected."
                    )
                ),
                "confidence": 0.99,
                "locations": [
                    {
                        "file": "app.py",
                        "line_start": 5,
                        "line_end": 10,
                        "symbol": "run",
                    }
                ],
                "details": [],
                "observed_at": None,
            }
        ],
        "relationships": [],
        "remediation": (
            "Use an allowlisted argument vector and "
            "shell=False."
        ),
        "proposed_patch": None,
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


def assert_lifecycle_summary(
    summary: dict[str, object],
    *,
    new: int = 0,
    persistent: int = 0,
    changed: int = 0,
    resolved: int = 0,
    reopened: int = 0,
) -> None:
    assert summary["new"] == new
    assert summary["persistent"] == persistent
    assert summary["changed"] == changed
    assert summary["resolved"] == resolved
    assert summary["reopened"] == reopened


def record(
    repository: Path,
    claims: list[dict[str, object]],
) -> dict[str, object]:
    response = client.post(
        "/v1/security-memory/record",
        json={
            "repository_path": str(repository),
            "claims": claims,
        },
    )

    assert response.status_code == 200, (
        response.text
    )

    return response.json()


def test_real_repository_claim_is_reopened_after_fix(
    tmp_path: Path,
    memory_override: SecurityMemoryService,
) -> None:
    repository = create_repository(tmp_path)

    commit_file(
        repository,
        vulnerable_code(),
        "Introduce vulnerable shell execution",
    )

    introduced = record(
        repository,
        [
            claim(
                state="confirmed",
                evidence_suffix="introduced",
            )
        ],
    )

    assert_lifecycle_summary(
        introduced["reconciliation"]["summary"],
        new=1,
    )

    first_revision = introduced[
        "repository"
    ]["revision"]
    first_snapshot = introduced[
        "snapshot"
    ]["snapshot_id"]

    commit_file(
        repository,
        fixed_code(),
        "Remove vulnerable shell execution",
    )

    verified_fix = record(
        repository,
        [
            claim(
                state="verified_fixed",
                evidence_suffix="verified-fixed",
            )
        ],
    )

    assert_lifecycle_summary(
        verified_fix["reconciliation"]["summary"],
        changed=1,
    )

    fixed_delta = verified_fix[
        "reconciliation"
    ]["deltas"][0]

    assert fixed_delta["claim_id"] == CLAIM_ID
    assert fixed_delta["status"] == "changed"
    assert fixed_delta[
        "previous_state"
    ] == "confirmed"
    assert fixed_delta[
        "current_state"
    ] == "verified_fixed"
    assert "state" in fixed_delta[
        "reasons"
    ][0]

    second_revision = verified_fix[
        "repository"
    ]["revision"]
    second_snapshot = verified_fix[
        "snapshot"
    ]["snapshot_id"]

    commit_file(
        repository,
        vulnerable_code(),
        "Reintroduce vulnerable shell execution",
    )

    reopened = record(
        repository,
        [
            claim(
                state="confirmed",
                evidence_suffix="reintroduced",
            )
        ],
    )

    assert_lifecycle_summary(
        reopened["reconciliation"]["summary"],
        reopened=1,
    )

    reopened_delta = reopened[
        "reconciliation"
    ]["deltas"][0]

    assert reopened_delta["claim_id"] == CLAIM_ID
    assert reopened_delta["status"] == "reopened"
    assert reopened_delta[
        "previous_state"
    ] == "verified_fixed"
    assert reopened_delta[
        "current_state"
    ] == "confirmed"

    third_revision = reopened[
        "repository"
    ]["revision"]
    third_snapshot = reopened[
        "snapshot"
    ]["snapshot_id"]

    assert len(
        {
            first_revision,
            second_revision,
            third_revision,
        }
    ) == 3

    assert len(
        {
            first_snapshot,
            second_snapshot,
            third_snapshot,
        }
    ) == 3

    assert reopened[
        "project_snapshot_count"
    ] == 3

    history = client.get(
        "/v1/security-memory/history",
        params={
            "repository_path": str(repository),
            "limit": 10,
            "offset": 0,
        },
    )

    assert history.status_code == 200

    history_payload = history.json()

    assert history_payload["count"] == 3
    assert [
        snapshot["snapshot_id"]
        for snapshot in history_payload[
            "snapshots"
        ]
    ] == [
        third_snapshot,
        second_snapshot,
        first_snapshot,
    ]

    latest = client.get(
        "/v1/security-memory/latest",
        params={
            "repository_path": str(repository),
        },
    )

    assert latest.status_code == 200
    assert latest.json()[
        "snapshot"
    ]["snapshot_id"] == third_snapshot


def test_reopened_lifecycle_persists_across_service_restart(
    tmp_path: Path,
) -> None:
    repository = create_repository(tmp_path)
    database_path = (
        tmp_path
        / "persistent-memory.sqlite3"
    )

    first_service = SecurityMemoryService(
        store=SQLiteProjectMemoryStore(
            database_path
        )
    )

    app.dependency_overrides[
        get_security_memory_service
    ] = lambda: first_service

    try:
        commit_file(
            repository,
            vulnerable_code(),
            "Introduce vulnerability",
        )

        introduced = record(
            repository,
            [
                claim(
                    state="confirmed",
                    evidence_suffix="restart-first",
                )
            ],
        )

        commit_file(
            repository,
            fixed_code(),
            "Verify fix",
        )

        fixed = record(
            repository,
            [
                claim(
                    state="verified_fixed",
                    evidence_suffix="restart-fixed",
                )
            ],
        )
    finally:
        app.dependency_overrides.pop(
            get_security_memory_service,
            None,
        )

    restarted_service = SecurityMemoryService(
        store=SQLiteProjectMemoryStore(
            database_path
        )
    )

    app.dependency_overrides[
        get_security_memory_service
    ] = lambda: restarted_service

    try:
        commit_file(
            repository,
            vulnerable_code(),
            "Reintroduce vulnerability",
        )

        reopened = record(
            repository,
            [
                claim(
                    state="confirmed",
                    evidence_suffix="restart-reopened",
                )
            ],
        )
    finally:
        app.dependency_overrides.pop(
            get_security_memory_service,
            None,
        )

    assert introduced[
        "snapshot"
    ]["snapshot_id"] != fixed[
        "snapshot"
    ]["snapshot_id"]

    assert reopened[
        "reconciliation"
    ]["summary"]["reopened"] == 1

    assert reopened[
        "reconciliation"
    ]["deltas"][0]["status"] == "reopened"

    assert reopened[
        "project_snapshot_count"
    ] == 3
