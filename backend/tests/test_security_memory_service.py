import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegis.schemas.claims import (
    CodeLocation,
    EvidenceItem,
    EvidenceSource,
    SecurityClaim,
)
from aegis.schemas.memory import (
    SecurityMemoryRecordRequest,
)
from aegis.security.security_memory import (
    SecurityMemoryService,
)
from aegis.security.sqlite_memory import (
    SQLiteProjectMemoryStore,
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
    name: str = "project",
) -> Path:
    root = tmp_path / name
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
        "print('initial')\n",
        encoding="utf-8",
    )

    git(root, "add", "app.py")
    git(
        root,
        "commit",
        "-m",
        "Initial revision",
    )

    git(
        root,
        "remote",
        "add",
        "origin",
        (
            "https://github.com/"
            f"lemkyz/{name}.git"
        ),
    )

    return root


def commit_revision(
    root: Path,
    *,
    content: str,
    message: str,
) -> None:
    (root / "app.py").write_text(
        content,
        encoding="utf-8",
    )

    git(root, "add", "app.py")
    git(root, "commit", "-m", message)


def claim(
    claim_id: str,
    *,
    state: str = "supported",
    evidence_ids: list[str] | None = None,
) -> SecurityClaim:
    return SecurityClaim(
        claim_id=claim_id,
        statement=(
            "Untrusted input reaches shell execution."
        ),
        category="command-injection",
        severity="high",
        confidence=0.9,
        state=state,
        cwe=["CWE-78"],
        owasp=["A03:2021"],
        locations=[
            CodeLocation(
                file="app.py",
                line_start=20,
                line_end=24,
            )
        ],
        evidence=[
            EvidenceItem(
                evidence_id=evidence_id,
                source=EvidenceSource(
                    kind="scanner",
                    name="Semgrep",
                    rule_id=(
                        "aegis.python.command-injection."
                        "subprocess-shell"
                    ),
                ),
                summary="Command injection detected.",
                confidence=0.9,
            )
            for evidence_id in (
                evidence_ids
                if evidence_ids is not None
                else ["evidence:scanner:1"]
            )
        ],
        remediation="Disable shell execution.",
    )


def service(
    tmp_path: Path,
    *,
    database_name: str = "memory.sqlite3",
) -> SecurityMemoryService:
    return SecurityMemoryService(
        store=SQLiteProjectMemoryStore(
            tmp_path / database_name
        )
    )


def record(
    memory: SecurityMemoryService,
    root: Path,
    claims: list[SecurityClaim],
    *,
    hour: int,
):
    return memory.record(
        SecurityMemoryRecordRequest(
            repository_path=str(root),
            claims=claims,
        ),
        created_at=datetime(
            2026,
            7,
            24,
            hour,
            0,
            tzinfo=UTC,
        ),
    )


def test_records_first_security_baseline(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    memory = service(tmp_path)

    result = record(
        memory,
        root,
        [claim("claim:one")],
        hour=10,
    )

    assert result.service == (
        "aegis-security-memory-service-v1"
    )
    assert result.baseline_created is True
    assert result.persisted_new_snapshot is True
    assert result.previous_snapshot_id is None
    assert result.project_snapshot_count == 1

    assert result.snapshot.project_id == (
        result.repository.project_id
    )
    assert result.snapshot.revision == (
        result.repository.revision
    )

    assert result.reconciliation.summary.new == 1
    assert (
        result.reconciliation.summary.persistent
        == 0
    )


def test_same_snapshot_recording_is_idempotent(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    memory = service(tmp_path)

    first = record(
        memory,
        root,
        [claim("claim:one")],
        hour=10,
    )

    repeated = record(
        memory,
        root,
        [claim("claim:one")],
        hour=18,
    )

    assert (
        first.snapshot.snapshot_id
        == repeated.snapshot.snapshot_id
    )
    assert repeated.persisted_new_snapshot is False
    assert repeated.baseline_created is False
    assert repeated.project_snapshot_count == 1
    assert repeated.previous_snapshot_id == (
        first.snapshot.snapshot_id
    )
    assert (
        repeated.reconciliation.summary.persistent
        == 1
    )


def test_new_revision_persists_new_snapshot(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    memory = service(tmp_path)

    first = record(
        memory,
        root,
        [claim("claim:one")],
        hour=10,
    )

    commit_revision(
        root,
        content="print('second')\n",
        message="Second revision",
    )

    second = record(
        memory,
        root,
        [claim("claim:one")],
        hour=11,
    )

    assert (
        first.repository.project_id
        == second.repository.project_id
    )
    assert (
        first.repository.revision
        != second.repository.revision
    )
    assert (
        first.snapshot.snapshot_id
        != second.snapshot.snapshot_id
    )

    assert second.persisted_new_snapshot is True
    assert second.baseline_created is False
    assert second.project_snapshot_count == 2
    assert (
        second.reconciliation.summary.persistent
        == 1
    )


def test_state_progression_is_changed(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    memory = service(tmp_path)

    first = record(
        memory,
        root,
        [
            claim(
                "claim:one",
                state="supported",
            )
        ],
        hour=10,
    )

    commit_revision(
        root,
        content="print('confirmed')\n",
        message="Confirmed revision",
    )

    second = record(
        memory,
        root,
        [
            claim(
                "claim:one",
                state="confirmed",
            )
        ],
        hour=11,
    )

    assert second.previous_snapshot_id == (
        first.snapshot.snapshot_id
    )
    assert second.reconciliation.summary.changed == 1
    assert second.reconciliation.deltas[0].status == (
        "changed"
    )
    assert (
        second.reconciliation.deltas[0]
        .previous_state
        == "supported"
    )
    assert (
        second.reconciliation.deltas[0]
        .current_state
        == "confirmed"
    )


def test_absent_claim_is_resolved(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    memory = service(tmp_path)

    record(
        memory,
        root,
        [claim("claim:one")],
        hour=10,
    )

    commit_revision(
        root,
        content="print('fixed')\n",
        message="Apply security fix",
    )

    second = record(
        memory,
        root,
        [],
        hour=11,
    )

    assert second.reconciliation.summary.resolved == 1
    assert second.reconciliation.deltas[0].status == (
        "resolved"
    )


def test_verified_fixed_claim_returning_is_reopened(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    memory = service(tmp_path)

    record(
        memory,
        root,
        [
            claim(
                "claim:one",
                state="verified_fixed",
            )
        ],
        hour=10,
    )

    commit_revision(
        root,
        content="print('vulnerable again')\n",
        message="Reintroduce vulnerability",
    )

    reopened = record(
        memory,
        root,
        [
            claim(
                "claim:one",
                state="supported",
            )
        ],
        hour=11,
    )

    delta = reopened.reconciliation.deltas[0]

    assert reopened.reconciliation.summary.reopened == 1
    assert reopened.reconciliation.summary.new == 0
    assert delta.status == "reopened"
    assert delta.previous_state == "verified_fixed"
    assert delta.current_state == "supported"


def test_evidence_enrichment_is_changed(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    memory = service(tmp_path)

    record(
        memory,
        root,
        [
            claim(
                "claim:one",
                evidence_ids=[
                    "evidence:scanner:1",
                ],
            )
        ],
        hour=10,
    )

    commit_revision(
        root,
        content="print('validated')\n",
        message="Add validation evidence",
    )

    enriched = record(
        memory,
        root,
        [
            claim(
                "claim:one",
                evidence_ids=[
                    "evidence:scanner:1",
                    "evidence:dynamic:1",
                ],
            )
        ],
        hour=11,
    )

    assert enriched.reconciliation.summary.changed == 1
    assert "evidence" in (
        enriched.reconciliation
        .deltas[0]
        .reasons[0]
    )


def test_history_is_newest_first(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    memory = service(tmp_path)

    first = record(
        memory,
        root,
        [claim("claim:one")],
        hour=10,
    )

    commit_revision(
        root,
        content="print('second')\n",
        message="Second",
    )

    second = record(
        memory,
        root,
        [claim("claim:one")],
        hour=11,
    )

    history = memory.history(root)

    assert [
        snapshot.snapshot_id
        for snapshot in history
    ] == [
        second.snapshot.snapshot_id,
        first.snapshot.snapshot_id,
    ]


def test_latest_returns_latest_project_snapshot(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    memory = service(tmp_path)

    record(
        memory,
        root,
        [claim("claim:one")],
        hour=10,
    )

    commit_revision(
        root,
        content="print('latest')\n",
        message="Latest revision",
    )

    latest_record = record(
        memory,
        root,
        [claim("claim:two")],
        hour=11,
    )

    latest = memory.latest(root)

    assert latest is not None
    assert latest.snapshot_id == (
        latest_record.snapshot.snapshot_id
    )


def test_persists_across_service_instances(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    database_path = tmp_path / "memory.sqlite3"

    first_service = SecurityMemoryService(
        store=SQLiteProjectMemoryStore(
            database_path
        )
    )

    first = record(
        first_service,
        root,
        [claim("claim:one")],
        hour=10,
    )

    second_service = SecurityMemoryService(
        store=SQLiteProjectMemoryStore(
            database_path
        )
    )

    latest = second_service.latest(root)

    assert latest is not None
    assert latest.snapshot_id == (
        first.snapshot.snapshot_id
    )


def test_project_histories_remain_isolated(
    tmp_path: Path,
) -> None:
    first_root = repository(
        tmp_path,
        name="project-one",
    )
    second_root = repository(
        tmp_path,
        name="project-two",
    )

    memory = service(tmp_path)

    first = record(
        memory,
        first_root,
        [claim("claim:first")],
        hour=10,
    )
    second = record(
        memory,
        second_root,
        [claim("claim:second")],
        hour=11,
    )

    assert memory.history(first_root) == [
        first.snapshot
    ]
    assert memory.history(second_root) == [
        second.snapshot
    ]


def test_dirty_worktree_revision_creates_new_snapshot(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path)
    memory = service(tmp_path)

    clean = record(
        memory,
        root,
        [claim("claim:one")],
        hour=10,
    )

    (root / "app.py").write_text(
        "print('uncommitted change')\n",
        encoding="utf-8",
    )

    dirty = record(
        memory,
        root,
        [claim("claim:one")],
        hour=11,
    )

    assert clean.repository.dirty is False
    assert dirty.repository.dirty is True
    assert (
        clean.repository.revision
        != dirty.repository.revision
    )
    assert (
        clean.snapshot.snapshot_id
        != dirty.snapshot.snapshot_id
    )
    assert dirty.project_snapshot_count == 2
    assert (
        dirty.reconciliation.summary.persistent
        == 1
    )


def test_rejects_duplicate_request_claim_ids(
    tmp_path: Path,
) -> None:
    duplicate = claim("claim:duplicate")

    with pytest.raises(
        ValidationError,
        match="unique claim_id",
    ):
        SecurityMemoryRecordRequest(
            repository_path=str(tmp_path),
            claims=[
                duplicate,
                duplicate,
            ],
        )


def test_rejects_missing_repository(
    tmp_path: Path,
) -> None:
    memory = service(tmp_path)

    with pytest.raises(
        ValueError,
        match="does not exist",
    ):
        memory.record(
            SecurityMemoryRecordRequest(
                repository_path=str(
                    tmp_path / "missing"
                ),
                claims=[],
            )
        )
