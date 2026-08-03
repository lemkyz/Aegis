from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aegis.schemas.claims import (
    CodeLocation,
    EvidenceItem,
    EvidenceRelationship,
    EvidenceSource,
    SecurityClaim,
)
from aegis.schemas.memory import (
    ProjectSecuritySnapshot,
)
from aegis.security.memory_snapshot import (
    ProjectSecuritySnapshotBuilder,
)


CREATED_AT = datetime(
    2026,
    7,
    24,
    12,
    0,
    0,
    tzinfo=UTC,
)


def claim(
    claim_id: str,
    *,
    state: str = "supported",
    severity: str = "high",
    confidence: float = 0.9,
    evidence_ids: list[str] | None = None,
) -> SecurityClaim:
    return SecurityClaim(
        claim_id=claim_id,
        statement="A security issue exists.",
        category="command-injection",
        severity=severity,
        confidence=confidence,
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
                evidence_id=evidence_id,
                source=EvidenceSource(
                    kind="scanner",
                    name="Semgrep",
                    rule_id=(
                        "aegis.python.command-injection."
                        "subprocess-shell"
                    ),
                ),
                summary="Security issue detected.",
                confidence=confidence,
            )
            for evidence_id in (
                evidence_ids
                if evidence_ids is not None
                else [f"evidence:{claim_id}"]
            )
        ],
        remediation="Apply a secure fix.",
    )


def build(
    *,
    claims: list[SecurityClaim],
    project_id: str = "github.com/lemkyz/aegis",
    revision: str | None = "abc123",
    created_at: datetime = CREATED_AT,
) -> ProjectSecuritySnapshot:
    return ProjectSecuritySnapshotBuilder().build(
        project_id=project_id,
        revision=revision,
        claims=claims,
        created_at=created_at,
    )


def test_builds_project_security_snapshot() -> None:
    snapshot = build(
        claims=[
            claim("claim:one"),
            claim("claim:two"),
        ]
    )

    assert snapshot.snapshot_id.startswith(
        "snapshot:sha256:"
    )
    assert snapshot.schema_version == "1.0"
    assert snapshot.project_id == (
        "github.com/lemkyz/aegis"
    )
    assert snapshot.revision == "abc123"
    assert snapshot.created_at == (
        "2026-07-24T12:00:00Z"
    )
    assert snapshot.claim_count == 2


def test_snapshot_identity_is_deterministic() -> None:
    claims = [
        claim("claim:one"),
        claim("claim:two"),
    ]

    first = build(claims=claims)
    second = build(claims=claims)

    assert first.snapshot_id == second.snapshot_id


def test_snapshot_identity_ignores_claim_order() -> None:
    first = build(
        claims=[
            claim("claim:one"),
            claim("claim:two"),
        ]
    )

    second = build(
        claims=[
            claim("claim:two"),
            claim("claim:one"),
        ]
    )

    assert first.snapshot_id == second.snapshot_id
    assert [
        item.claim_id
        for item in first.claims
    ] == [
        "claim:one",
        "claim:two",
    ]


def test_created_at_does_not_change_snapshot_identity() -> None:
    item = claim("claim:one")

    first = build(
        claims=[item],
        created_at=datetime(
            2026,
            7,
            24,
            12,
            0,
            tzinfo=UTC,
        ),
    )

    second = build(
        claims=[item],
        created_at=datetime(
            2026,
            7,
            25,
            18,
            30,
            tzinfo=UTC,
        ),
    )

    assert first.created_at != second.created_at
    assert first.snapshot_id == second.snapshot_id


@pytest.mark.parametrize(
    ("field", "first_value", "second_value"),
    [
        ("state", "supported", "confirmed"),
        ("severity", "high", "critical"),
        ("confidence", 0.9, 0.99),
    ],
)
def test_material_claim_change_changes_snapshot_identity(
    field: str,
    first_value,
    second_value,
) -> None:
    first_kwargs = {field: first_value}
    second_kwargs = {field: second_value}

    first = build(
        claims=[
            claim(
                "claim:one",
                **first_kwargs,
            )
        ]
    )

    second = build(
        claims=[
            claim(
                "claim:one",
                **second_kwargs,
            )
        ]
    )

    assert first.snapshot_id != second.snapshot_id


def test_evidence_change_changes_snapshot_identity() -> None:
    first = build(
        claims=[
            claim(
                "claim:one",
                evidence_ids=[
                    "evidence:scanner:1",
                ],
            )
        ]
    )

    second = build(
        claims=[
            claim(
                "claim:one",
                evidence_ids=[
                    "evidence:scanner:1",
                    "evidence:dynamic:1",
                ],
            )
        ]
    )

    assert first.snapshot_id != second.snapshot_id


def test_relationship_change_changes_snapshot_identity() -> None:
    evidence_ids = [
        "evidence:scanner:1",
        "evidence:dynamic:1",
    ]
    without_relationship = claim(
        "claim:one",
        evidence_ids=evidence_ids,
    )
    with_relationship = without_relationship.model_copy(
        deep=True,
        update={
            "relationships": [
                EvidenceRelationship(
                    relationship_id=(
                        "relationship:verifies:1"
                    ),
                    source_evidence_id=(
                        "evidence:dynamic:1"
                    ),
                    target_evidence_id=(
                        "evidence:scanner:1"
                    ),
                    kind="corroborates",
                    reason=(
                        "Runtime evidence corroborates "
                        "the scanner result."
                    ),
                )
            ],
        },
    )

    first = build(
        claims=[without_relationship],
    )
    second = build(
        claims=[with_relationship],
    )

    assert first.snapshot_id != second.snapshot_id


def test_revision_changes_snapshot_identity() -> None:
    item = claim("claim:one")

    first = build(
        claims=[item],
        revision="abc123",
    )
    second = build(
        claims=[item],
        revision="def456",
    )

    assert first.snapshot_id != second.snapshot_id


def test_project_changes_snapshot_identity() -> None:
    item = claim("claim:one")

    first = build(
        claims=[item],
        project_id="project-one",
    )
    second = build(
        claims=[item],
        project_id="project-two",
    )

    assert first.snapshot_id != second.snapshot_id


def test_supports_working_tree_snapshot() -> None:
    snapshot = build(
        claims=[],
        revision=None,
    )

    assert snapshot.revision is None
    assert snapshot.claim_count == 0
    assert snapshot.snapshot_id.startswith(
        "snapshot:sha256:"
    )


def test_rejects_duplicate_claim_ids() -> None:
    duplicate = claim("claim:duplicate")

    with pytest.raises(
        ValueError,
        match="unique claim_id",
    ):
        build(
            claims=[
                duplicate,
                duplicate,
            ]
        )


def test_rejects_naive_created_at() -> None:
    with pytest.raises(
        ValueError,
        match="timezone-aware",
    ):
        build(
            claims=[],
            created_at=datetime(
                2026,
                7,
                24,
                12,
                0,
            ),
        )


def test_schema_rejects_wrong_claim_count() -> None:
    with pytest.raises(
        ValidationError,
        match="claim_count",
    ):
        ProjectSecuritySnapshot(
            snapshot_id="snapshot:test",
            project_id="project",
            revision=None,
            created_at="2026-07-24T12:00:00Z",
            claims=[claim("claim:one")],
            claim_count=0,
        )
