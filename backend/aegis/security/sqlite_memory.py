from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import json
import sqlite3
from pathlib import Path
from typing import Any

from aegis.schemas.claims import SecurityClaim
from aegis.schemas.memory import (
    ProjectSecuritySnapshot,
)


class SQLiteProjectMemoryStore:
    """
    Local persistent storage for immutable project-security
    snapshot baselines.

    Snapshot identifiers represent security-relevant content.
    Re-saving the same content is therefore idempotent.
    """

    schema_version = 1

    def __init__(
        self,
        database_path: str | Path,
    ) -> None:
        self.database_path = Path(
            database_path
        ).expanduser()

        if (
            self.database_path.exists()
            and self.database_path.is_dir()
        ):
            raise ValueError(
                "database_path must reference a file, "
                "not a directory"
            )

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._initialize_database()

    def save_snapshot(
        self,
        snapshot: ProjectSecuritySnapshot,
    ) -> ProjectSecuritySnapshot:
        """
        Persist a snapshot exactly once.

        When the same deterministic snapshot identity already
        exists, the original stored baseline is returned.
        """

        payload_json = snapshot.model_dump_json()

        with self._connect() as connection:
            existing_row = connection.execute(
                """
                SELECT payload_json
                FROM security_snapshots
                WHERE snapshot_id = ?
                """,
                (snapshot.snapshot_id,),
            ).fetchone()

            if existing_row is not None:
                existing = self._parse_snapshot(
                    existing_row["payload_json"]
                )

                self._require_matching_identity(
                    existing=existing,
                    incoming=snapshot,
                )

                return existing

            connection.execute(
                """
                INSERT INTO security_snapshots (
                    snapshot_id,
                    project_id,
                    revision,
                    created_at,
                    claim_count,
                    payload_json
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot.snapshot_id,
                    snapshot.project_id,
                    snapshot.revision,
                    snapshot.created_at,
                    snapshot.claim_count,
                    payload_json,
                ),
            )

        return snapshot

    def get_snapshot(
        self,
        snapshot_id: str,
    ) -> ProjectSecuritySnapshot | None:
        normalized_snapshot_id = snapshot_id.strip()

        if not normalized_snapshot_id:
            raise ValueError(
                "snapshot_id must not be empty"
            )

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload_json
                FROM security_snapshots
                WHERE snapshot_id = ?
                """,
                (normalized_snapshot_id,),
            ).fetchone()

        if row is None:
            return None

        return self._parse_snapshot(
            row["payload_json"]
        )

    def get_latest_snapshot(
        self,
        project_id: str,
    ) -> ProjectSecuritySnapshot | None:
        normalized_project_id = (
            self._normalize_project_id(project_id)
        )

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload_json
                FROM security_snapshots
                WHERE project_id = ?
                ORDER BY created_at DESC, snapshot_id DESC
                LIMIT 1
                """,
                (normalized_project_id,),
            ).fetchone()

        if row is None:
            return None

        return self._parse_snapshot(
            row["payload_json"]
        )

    def list_snapshots(
        self,
        project_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ProjectSecuritySnapshot]:
        normalized_project_id = (
            self._normalize_project_id(project_id)
        )

        if limit < 1 or limit > 1_000:
            raise ValueError(
                "limit must be between 1 and 1000"
            )

        if offset < 0:
            raise ValueError(
                "offset must be greater than or equal to 0"
            )

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload_json
                FROM security_snapshots
                WHERE project_id = ?
                ORDER BY created_at DESC, snapshot_id DESC
                LIMIT ? OFFSET ?
                """,
                (
                    normalized_project_id,
                    limit,
                    offset,
                ),
            ).fetchall()

        return [
            self._parse_snapshot(
                row["payload_json"]
            )
            for row in rows
        ]

    def count_snapshots(
        self,
        project_id: str,
    ) -> int:
        normalized_project_id = (
            self._normalize_project_id(project_id)
        )

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) AS snapshot_count
                FROM security_snapshots
                WHERE project_id = ?
                """,
                (normalized_project_id,),
            ).fetchone()

        if row is None:
            return 0

        return int(row["snapshot_count"])

    def _initialize_database(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS memory_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                INSERT INTO memory_metadata (
                    key,
                    value
                )
                VALUES (
                    'schema_version',
                    ?
                )
                ON CONFLICT(key) DO NOTHING
                """,
                (str(self.schema_version),),
            )

            row = connection.execute(
                """
                SELECT value
                FROM memory_metadata
                WHERE key = 'schema_version'
                """
            ).fetchone()

            if row is None:
                raise RuntimeError(
                    "Security-memory schema metadata "
                    "could not be initialized."
                )

            try:
                stored_version = int(
                    row["value"]
                )
            except (
                TypeError,
                ValueError,
            ) as exc:
                raise RuntimeError(
                    "Security-memory database contains "
                    "an invalid schema version."
                ) from exc

            if stored_version != self.schema_version:
                raise RuntimeError(
                    "Unsupported security-memory schema "
                    f"version: {stored_version}"
                )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS security_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    revision TEXT,
                    created_at TEXT NOT NULL,
                    claim_count INTEGER NOT NULL
                        CHECK (claim_count >= 0),
                    payload_json TEXT NOT NULL
                )
                """
            )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_security_snapshots_project_time
                ON security_snapshots (
                    project_id,
                    created_at DESC,
                    snapshot_id DESC
                )
                """
            )

    @contextmanager
    def _connect(
        self,
    ) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self.database_path,
            timeout=10.0,
        )

        try:
            connection.row_factory = sqlite3.Row

            connection.execute(
                "PRAGMA foreign_keys = ON"
            )
            connection.execute(
                "PRAGMA busy_timeout = 10000"
            )

            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _parse_snapshot(
        payload_json: str,
    ) -> ProjectSecuritySnapshot:
        try:
            return (
                ProjectSecuritySnapshot
                .model_validate_json(payload_json)
            )
        except Exception as exc:
            raise RuntimeError(
                "Stored security snapshot is invalid "
                "or corrupted."
            ) from exc

    @staticmethod
    def _normalize_project_id(
        project_id: str,
    ) -> str:
        normalized = (
            project_id
            .strip()
            .replace("\\", "/")
        )

        if not normalized:
            raise ValueError(
                "project_id must not be empty"
            )

        return normalized

    @classmethod
    def _require_matching_identity(
        cls,
        *,
        existing: ProjectSecuritySnapshot,
        incoming: ProjectSecuritySnapshot,
    ) -> None:
        if (
            cls._snapshot_identity(existing)
            != cls._snapshot_identity(incoming)
        ):
            raise ValueError(
                "snapshot_id collision or inconsistent "
                "snapshot identity detected"
            )

    @classmethod
    def _snapshot_identity(
        cls,
        snapshot: ProjectSecuritySnapshot,
    ) -> str:
        identity = {
            "schema_version": snapshot.schema_version,
            "snapshot_id": snapshot.snapshot_id,
            "project_id": snapshot.project_id,
            "revision": snapshot.revision,
            "claims": [
                cls._claim_identity(claim)
                for claim in sorted(
                    snapshot.claims,
                    key=lambda item: item.claim_id,
                )
            ],
        }

        return json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @staticmethod
    def _claim_identity(
        claim: SecurityClaim,
    ) -> dict[str, Any]:
        return {
            "claim_id": claim.claim_id,
            "state": claim.state,
            "severity": claim.severity,
            "confidence": claim.confidence,
            "cwe": sorted(claim.cwe),
            "owasp": sorted(claim.owasp),
            "locations": sorted(
                (
                    location.file,
                    location.line_start,
                    location.line_end,
                    location.symbol or "",
                )
                for location in claim.locations
            ),
            "evidence_ids": sorted(
                evidence.evidence_id
                for evidence in claim.evidence
            ),
            "relationship_ids": sorted(
                relationship.relationship_id
                for relationship
                in claim.relationships
            ),
        }
