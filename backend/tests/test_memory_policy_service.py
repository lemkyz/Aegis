import subprocess
from datetime import UTC, datetime
from pathlib import Path

from aegis.schemas.claims import SecurityClaim
from aegis.schemas.policy import (
    SecurityMemoryPolicyRecordRequest,
)
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


def claim(
    claim_id: str,
    *,
    severity: str,
    state: str,
) -> SecurityClaim:
    return SecurityClaim(
        claim_id=claim_id,
        statement="A security issue exists.",
        category="command-injection",
        severity=severity,
        confidence=1.0,
        state=state,
        cwe=["CWE-78"],
        owasp=["A03:2021"],
        locations=[],
        evidence=[],
        relationships=[],
        remediation="Apply a secure fix.",
    )


def create_service(
    database_path: Path,
) -> SecurityMemoryPolicyService:
    return SecurityMemoryPolicyService(
        memory_service=SecurityMemoryService(
            store=SQLiteProjectMemoryStore(
                database_path
            )
        ),
        policy_engine=MemoryAwarePolicyEngine(),
    )


def test_records_and_evaluates_new_critical_claim(
    tmp_path: Path,
) -> None:
    repository = create_repository(tmp_path)

    result = create_service(
        tmp_path / "memory.sqlite3"
    ).record_and_evaluate(
        SecurityMemoryPolicyRecordRequest(
            repository_path=str(repository),
            claims=[
                claim(
                    "claim:critical",
                    severity="critical",
                    state="confirmed",
                )
            ],
        ),
        created_at=datetime(
            2026,
            7,
            24,
            12,
            0,
            tzinfo=UTC,
        ),
    )

    assert result.memory.baseline_created is True
    assert result.memory.reconciliation.summary.new == 1
    assert result.policy.decision == "block"
    assert result.policy.blocking_claim_ids == [
        "claim:critical"
    ]


def test_policy_uses_persisted_previous_snapshot(
    tmp_path: Path,
) -> None:
    repository = create_repository(tmp_path)
    database = tmp_path / "memory.sqlite3"

    create_service(database).record_and_evaluate(
        SecurityMemoryPolicyRecordRequest(
            repository_path=str(repository),
            claims=[
                claim(
                    "claim:regression",
                    severity="high",
                    state="verified_fixed",
                )
            ],
        )
    )

    result = create_service(
        database
    ).record_and_evaluate(
        SecurityMemoryPolicyRecordRequest(
            repository_path=str(repository),
            claims=[
                claim(
                    "claim:regression",
                    severity="high",
                    state="confirmed",
                )
            ],
        )
    )

    assert (
        result.memory.reconciliation.summary.reopened
        == 1
    )
    assert result.policy.decision == "block"
    assert result.policy.summary.reopened == 1
    assert (
        result.policy.assessments[0].lifecycle_status
        == "reopened"
    )


def test_empty_project_is_allowed(
    tmp_path: Path,
) -> None:
    repository = create_repository(tmp_path)

    result = create_service(
        tmp_path / "memory.sqlite3"
    ).record_and_evaluate(
        SecurityMemoryPolicyRecordRequest(
            repository_path=str(repository),
            claims=[],
        )
    )

    assert result.policy.decision == "allow"
    assert result.policy.risk_score == 0
    assert result.policy.summary.claims_evaluated == 0
