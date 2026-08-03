import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from aegis.schemas.claims import (
    CodeLocation,
    EvidenceItem,
    EvidenceRelationship,
    EvidenceSource,
    SecurityClaim,
)
from aegis.security.memory_snapshot import (
    ProjectSecuritySnapshotBuilder,
)
from aegis.security.sqlite_memory import (
    SQLiteProjectMemoryStore,
)


def claim(
    claim_id: str,
    *,
    state: str = "supported",
) -> SecurityClaim:
    return SecurityClaim(
        claim_id=claim_id,
        statement="A security issue exists.",
        category="command-injection",
        severity="high",
        confidence=0.9,
        state=state,
        cwe=["CWE-78"],
        owasp=["A03:2021"],
        locations=[
            CodeLocation(
                file="src/app.py",
                line_start=20,
                line_end=24,
            )
        ],
        evidence=[
            EvidenceItem(
                evidence_id=(
                    f"evidence:{claim_id}:{state}"
                ),
                source=EvidenceSource(
                    kind="scanner",
                    name="Semgrep",
                    rule_id=(
                        "aegis.python.command-injection."
                        "subprocess-shell"
                    ),
                ),
                summary="Security issue detected.",
                confidence=0.9,
            )
        ],
        remediation="Apply a secure fix.",
    )


def snapshot(
    *,
    project_id: str = "project-one",
    revision: str | None = "abc123",
    claims: list[SecurityClaim] | None = None,
    hour: int = 12,
):
    return ProjectSecuritySnapshotBuilder().build(
        project_id=project_id,
        revision=revision,
        claims=(
            claims
            if claims is not None
            else [claim("claim:one")]
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


def store(
    tmp_path: Path,
) -> SQLiteProjectMemoryStore:
    return SQLiteProjectMemoryStore(
        tmp_path / "memory.sqlite3"
    )


def test_initializes_sqlite_database(
    tmp_path: Path,
) -> None:
    database_path = (
        tmp_path / "memory.sqlite3"
    )

    SQLiteProjectMemoryStore(
        database_path
    )

    assert database_path.is_file()

    with sqlite3.connect(
        database_path
    ) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            )
        }

    assert "memory_metadata" in tables
    assert "security_snapshots" in tables


def test_saves_and_reads_snapshot(
    tmp_path: Path,
) -> None:
    memory = store(tmp_path)
    item = snapshot()

    saved = memory.save_snapshot(item)
    loaded = memory.get_snapshot(
        item.snapshot_id
    )

    assert saved == item
    assert loaded == item


def test_persists_across_store_instances(
    tmp_path: Path,
) -> None:
    database_path = (
        tmp_path / "memory.sqlite3"
    )
    item = snapshot()

    first = SQLiteProjectMemoryStore(
        database_path
    )
    first.save_snapshot(item)

    second = SQLiteProjectMemoryStore(
        database_path
    )

    assert second.get_snapshot(
        item.snapshot_id
    ) == item


def test_missing_snapshot_returns_none(
    tmp_path: Path,
) -> None:
    memory = store(tmp_path)

    assert memory.get_snapshot(
        "snapshot:missing"
    ) is None


def test_duplicate_save_is_idempotent(
    tmp_path: Path,
) -> None:
    memory = store(tmp_path)
    item = snapshot()

    first = memory.save_snapshot(item)
    second = memory.save_snapshot(item)

    assert first == second
    assert memory.count_snapshots(
        item.project_id
    ) == 1


def test_same_identity_preserves_original_timestamp(
    tmp_path: Path,
) -> None:
    memory = store(tmp_path)

    first = snapshot(hour=12)
    repeated = snapshot(hour=18)

    assert (
        first.snapshot_id
        == repeated.snapshot_id
    )
    assert (
        first.created_at
        != repeated.created_at
    )

    stored_first = memory.save_snapshot(first)
    stored_second = memory.save_snapshot(
        repeated
    )

    assert stored_first.created_at == (
        "2026-07-24T12:00:00Z"
    )
    assert stored_second.created_at == (
        "2026-07-24T12:00:00Z"
    )
    assert memory.count_snapshots(
        first.project_id
    ) == 1


def test_latest_snapshot_uses_created_at(
    tmp_path: Path,
) -> None:
    memory = store(tmp_path)

    older = snapshot(
        revision="older",
        hour=9,
    )
    newer = snapshot(
        revision="newer",
        hour=17,
    )

    memory.save_snapshot(newer)
    memory.save_snapshot(older)

    latest = memory.get_latest_snapshot(
        "project-one"
    )

    assert latest is not None
    assert latest.snapshot_id == (
        newer.snapshot_id
    )


def test_latest_snapshot_returns_none_for_unknown_project(
    tmp_path: Path,
) -> None:
    memory = store(tmp_path)

    assert memory.get_latest_snapshot(
        "unknown-project"
    ) is None


def test_list_snapshots_is_newest_first(
    tmp_path: Path,
) -> None:
    memory = store(tmp_path)

    morning = snapshot(
        revision="morning",
        hour=9,
    )
    noon = snapshot(
        revision="noon",
        hour=12,
    )
    evening = snapshot(
        revision="evening",
        hour=18,
    )

    memory.save_snapshot(noon)
    memory.save_snapshot(morning)
    memory.save_snapshot(evening)

    history = memory.list_snapshots(
        "project-one"
    )

    assert [
        item.revision
        for item in history
    ] == [
        "evening",
        "noon",
        "morning",
    ]


def test_list_supports_limit_and_offset(
    tmp_path: Path,
) -> None:
    memory = store(tmp_path)

    for hour in range(1, 6):
        memory.save_snapshot(
            snapshot(
                revision=f"revision-{hour}",
                hour=hour,
            )
        )

    page = memory.list_snapshots(
        "project-one",
        limit=2,
        offset=1,
    )

    assert [
        item.revision
        for item in page
    ] == [
        "revision-4",
        "revision-3",
    ]


def test_project_histories_are_isolated(
    tmp_path: Path,
) -> None:
    memory = store(tmp_path)

    first = snapshot(
        project_id="project-one",
        revision="one",
    )
    second = snapshot(
        project_id="project-two",
        revision="two",
    )

    memory.save_snapshot(first)
    memory.save_snapshot(second)

    assert memory.list_snapshots(
        "project-one"
    ) == [first]

    assert memory.list_snapshots(
        "project-two"
    ) == [second]

    assert memory.count_snapshots(
        "project-one"
    ) == 1
    assert memory.count_snapshots(
        "project-two"
    ) == 1


def test_rejects_empty_snapshot_id(
    tmp_path: Path,
) -> None:
    memory = store(tmp_path)

    with pytest.raises(
        ValueError,
        match="snapshot_id",
    ):
        memory.get_snapshot("   ")


@pytest.mark.parametrize(
    "limit",
    [
        0,
        -1,
        1001,
    ],
)
def test_rejects_invalid_list_limit(
    tmp_path: Path,
    limit: int,
) -> None:
    memory = store(tmp_path)

    with pytest.raises(
        ValueError,
        match="limit",
    ):
        memory.list_snapshots(
            "project-one",
            limit=limit,
        )


def test_rejects_negative_offset(
    tmp_path: Path,
) -> None:
    memory = store(tmp_path)

    with pytest.raises(
        ValueError,
        match="offset",
    ):
        memory.list_snapshots(
            "project-one",
            offset=-1,
        )


def test_rejects_directory_database_path(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ValueError,
        match="not a directory",
    ):
        SQLiteProjectMemoryStore(
            tmp_path
        )


def test_reports_corrupted_snapshot_payload(
    tmp_path: Path,
) -> None:
    memory = store(tmp_path)
    item = snapshot()

    memory.save_snapshot(item)

    with sqlite3.connect(
        memory.database_path
    ) as connection:
        connection.execute(
            """
            UPDATE security_snapshots
            SET payload_json = ?
            WHERE snapshot_id = ?
            """,
            (
                '{"broken": true}',
                item.snapshot_id,
            ),
        )

    with pytest.raises(
        RuntimeError,
        match="invalid or corrupted",
    ):
        memory.get_snapshot(
            item.snapshot_id
        )


def test_rejects_unsupported_schema_version(
    tmp_path: Path,
) -> None:
    database_path = (
        tmp_path / "memory.sqlite3"
    )

    first = SQLiteProjectMemoryStore(
        database_path
    )

    with sqlite3.connect(
        first.database_path
    ) as connection:
        connection.execute(
            """
            UPDATE memory_metadata
            SET value = '999'
            WHERE key = 'schema_version'
            """
        )

    with pytest.raises(
        RuntimeError,
        match="Unsupported",
    ):
        SQLiteProjectMemoryStore(
            database_path
        )


def test_connections_are_closed_after_store_operations(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import sqlite3

    from aegis.security import sqlite_memory

    real_connect = sqlite3.connect
    opened_connections = []

    class TrackingConnection:
        def __init__(self, connection):
            self.connection = connection
            self.closed = False

        @property
        def row_factory(self):
            return self.connection.row_factory

        @row_factory.setter
        def row_factory(self, value):
            self.connection.row_factory = value

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def close(self):
            self.closed = True
            return self.connection.close()

    def tracking_connect(*args, **kwargs):
        wrapped = TrackingConnection(
            real_connect(*args, **kwargs)
        )
        opened_connections.append(wrapped)
        return wrapped

    monkeypatch.setattr(
        sqlite_memory.sqlite3,
        "connect",
        tracking_connect,
    )

    store = SQLiteProjectMemoryStore(
        tmp_path / "memory.sqlite3"
    )

    item = snapshot()

    store.save_snapshot(item)
    store.get_snapshot(item.snapshot_id)
    store.get_latest_snapshot(item.project_id)
    store.list_snapshots(item.project_id)
    store.count_snapshots(item.project_id)

    assert opened_connections
    assert all(
        connection.closed
        for connection in opened_connections
    )


def test_invalid_metadata_schema_version_is_redacted(
    tmp_path: Path,
) -> None:
    import sqlite3

    database_path = tmp_path / "memory.sqlite3"

    SQLiteProjectMemoryStore(database_path)

    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            UPDATE memory_metadata
            SET value = ?
            WHERE key = ?
            """,
            (
                "not-an-integer",
                "schema_version",
            ),
        )

    with pytest.raises(
        RuntimeError,
        match="invalid schema version",
    ):
        SQLiteProjectMemoryStore(database_path)


def _relationship_snapshot(
    *,
    relationships: list[EvidenceRelationship],
):
    base = claim("claim:relationship-identity")
    template = base.evidence[0]

    evidence = [
        template.model_copy(
            deep=True,
            update={
                "evidence_id": "evidence:source",
            },
        ),
        template.model_copy(
            deep=True,
            update={
                "evidence_id": "evidence:target",
            },
        ),
        template.model_copy(
            deep=True,
            update={
                "evidence_id": "evidence:alternate",
            },
        ),
    ]

    item = base.model_copy(
        deep=True,
        update={
            "evidence": evidence,
            "relationships": relationships,
        },
    )

    return snapshot(claims=[item])


@pytest.mark.parametrize(
    "changed_relationship",
    [
        EvidenceRelationship(
            relationship_id="relationship:stable",
            source_evidence_id="evidence:source",
            target_evidence_id="evidence:target",
            kind="supports",
            reason="Updated material reason.",
        ),
        EvidenceRelationship(
            relationship_id="relationship:stable",
            source_evidence_id="evidence:source",
            target_evidence_id="evidence:alternate",
            kind="supports",
            reason="Original material reason.",
        ),
        EvidenceRelationship(
            relationship_id="relationship:stable",
            source_evidence_id="evidence:source",
            target_evidence_id="evidence:target",
            kind="verifies",
            reason="Original material reason.",
        ),
    ],
    ids=[
        "reason",
        "endpoint",
        "kind",
    ],
)
def test_relationship_material_collision_is_rejected(
    tmp_path: Path,
    changed_relationship: EvidenceRelationship,
) -> None:
    memory = store(tmp_path)
    original = _relationship_snapshot(
        relationships=[
            EvidenceRelationship(
                relationship_id="relationship:stable",
                source_evidence_id="evidence:source",
                target_evidence_id="evidence:target",
                kind="supports",
                reason="Original material reason.",
            )
        ],
    )
    changed = _relationship_snapshot(
        relationships=[changed_relationship],
    ).model_copy(
        deep=True,
        update={
            "snapshot_id": original.snapshot_id,
        },
    )

    memory.save_snapshot(original)

    with pytest.raises(
        ValueError,
        match=(
            "snapshot_id collision or inconsistent "
            "snapshot identity"
        ),
    ):
        memory.save_snapshot(changed)

    assert memory.get_snapshot(
        original.snapshot_id
    ) == original
    assert memory.count_snapshots(
        original.project_id
    ) == 1


def test_relationship_order_remains_idempotent_in_sqlite(
    tmp_path: Path,
) -> None:
    memory = store(tmp_path)
    first_relationship = EvidenceRelationship(
        relationship_id="relationship:first",
        source_evidence_id="evidence:source",
        target_evidence_id="evidence:target",
        kind="supports",
        reason="Primary epistemic relationship.",
    )
    second_relationship = EvidenceRelationship(
        relationship_id="relationship:second",
        source_evidence_id="evidence:alternate",
        target_evidence_id="evidence:source",
        kind="derived_from",
        reason="Independent provenance relationship.",
    )

    first = _relationship_snapshot(
        relationships=[
            first_relationship,
            second_relationship,
        ],
    )
    reordered = _relationship_snapshot(
        relationships=[
            second_relationship,
            first_relationship,
        ],
    )

    assert first.snapshot_id == reordered.snapshot_id

    saved = memory.save_snapshot(first)
    repeated = memory.save_snapshot(reordered)

    assert repeated == saved
    assert memory.count_snapshots(
        first.project_id
    ) == 1
