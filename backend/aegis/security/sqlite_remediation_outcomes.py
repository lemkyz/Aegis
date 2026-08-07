from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from aegis.schemas.fixes import (
    RemediationLifecycleManifest,
    RemediationLifecycleOutcome,
)


class SQLiteRemediationOutcomeStore:
    """
    Local persistent storage for immutable remediation lifecycle
    manifests and outcomes.

    Manifest IDs and outcome SHA-256 values are immutable identities.
    Re-saving exact content is idempotent. Persisted content that no
    longer matches its stored identity fails closed.
    """

    schema_version = 1

    def __init__(
        self,
        database_path: str | Path,
    ) -> None:
        self.database_path = Path(
            database_path
        ).expanduser()
        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        self._initialize_database()

    def save_outcome(
        self,
        outcome: RemediationLifecycleOutcome,
    ) -> RemediationLifecycleOutcome:
        item = RemediationLifecycleOutcome.model_validate(
            outcome
        )

        with self._connect() as connection:
            return self._save_outcome(
                connection,
                item,
            )

    def get_outcome(
        self,
        outcome_sha256: str,
    ) -> RemediationLifecycleOutcome | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    outcome_sha256,
                    manifest_id,
                    manifest_sha256,
                    payload_json
                FROM remediation_lifecycle_outcomes
                WHERE outcome_sha256 = ?
                """,
                (outcome_sha256,),
            ).fetchone()

        if row is None:
            return None

        return self._parse_outcome(
            row["payload_json"],
            expected_outcome_sha256=(
                row["outcome_sha256"]
            ),
            expected_manifest_id=(
                row["manifest_id"]
            ),
            expected_manifest_sha256=(
                row["manifest_sha256"]
            ),
        )

    def save_manifest(
        self,
        manifest: RemediationLifecycleManifest,
    ) -> RemediationLifecycleManifest:
        item = RemediationLifecycleManifest.model_validate(
            manifest
        )

        with self._connect() as connection:
            return self._save_manifest(
                connection,
                item,
            )

    def get_manifest(
        self,
        manifest_id: str,
    ) -> RemediationLifecycleManifest | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT
                    manifest_id,
                    manifest_sha256,
                    payload_json
                FROM remediation_lifecycle_manifests
                WHERE manifest_id = ?
                """,
                (manifest_id,),
            ).fetchone()

        if row is None:
            return None

        return self._parse_manifest(
            row["payload_json"],
            expected_manifest_id=(
                row["manifest_id"]
            ),
            expected_manifest_sha256=(
                row["manifest_sha256"]
            ),
        )

    def save_lifecycle(
        self,
        manifest: RemediationLifecycleManifest,
        outcome: RemediationLifecycleOutcome,
    ) -> tuple[
        RemediationLifecycleManifest,
        RemediationLifecycleOutcome,
    ]:
        manifest_item = (
            RemediationLifecycleManifest.model_validate(
                manifest
            )
        )
        outcome_item = (
            RemediationLifecycleOutcome.model_validate(
                outcome
            )
        )

        self._require_lifecycle_identity(
            manifest_item,
            outcome_item,
        )

        with self._connect() as connection:
            saved_manifest = self._save_manifest(
                connection,
                manifest_item,
            )
            saved_outcome = self._save_outcome(
                connection,
                outcome_item,
            )

        return (
            saved_manifest,
            saved_outcome,
        )

    def get_lifecycle(
        self,
        outcome_sha256: str,
    ) -> (
        tuple[
            RemediationLifecycleManifest,
            RemediationLifecycleOutcome,
        ]
        | None
    ):
        with self._connect() as connection:
            outcome_row = connection.execute(
                """
                SELECT
                    outcome_sha256,
                    manifest_id,
                    manifest_sha256,
                    payload_json
                FROM remediation_lifecycle_outcomes
                WHERE outcome_sha256 = ?
                """,
                (outcome_sha256,),
            ).fetchone()

            if outcome_row is None:
                return None

            outcome = self._parse_outcome(
                outcome_row["payload_json"],
                expected_outcome_sha256=(
                    outcome_row["outcome_sha256"]
                ),
                expected_manifest_id=(
                    outcome_row["manifest_id"]
                ),
                expected_manifest_sha256=(
                    outcome_row["manifest_sha256"]
                ),
            )

            manifest_row = connection.execute(
                """
                SELECT
                    manifest_id,
                    manifest_sha256,
                    payload_json
                FROM remediation_lifecycle_manifests
                WHERE manifest_id = ?
                """,
                (outcome.manifest_id,),
            ).fetchone()

            if manifest_row is None:
                raise RuntimeError(
                    "Partial remediation lifecycle: "
                    "missing manifest for persisted outcome."
                )

            manifest = self._parse_manifest(
                manifest_row["payload_json"],
                expected_manifest_id=(
                    manifest_row["manifest_id"]
                ),
                expected_manifest_sha256=(
                    manifest_row["manifest_sha256"]
                ),
            )

        try:
            self._require_lifecycle_identity(
                manifest,
                outcome,
            )
        except ValueError as exc:
            raise RuntimeError(
                "Partial remediation lifecycle or "
                "inconsistent lifecycle identity."
            ) from exc

        return (
            manifest,
            outcome,
        )

    @classmethod
    def lifecycle_snapshot_sha256(
        cls,
        manifest: RemediationLifecycleManifest,
        outcome: RemediationLifecycleOutcome
        | None = None,
    ) -> str:
        manifest_item = (
            RemediationLifecycleManifest
            .model_validate(manifest)
        )

        outcome_item = (
            RemediationLifecycleOutcome
            .model_validate(outcome)
            if outcome is not None
            else None
        )

        if outcome_item is not None:
            cls._require_lifecycle_identity(
                manifest_item,
                outcome_item,
            )

        identity = {
            "schema": (
                "remediation-lifecycle-snapshot-v1"
            ),
            "store_schema_version": (
                cls.schema_version
            ),
            "manifest_id": (
                manifest_item.manifest_id
            ),
            "manifest_sha256": (
                manifest_item.manifest_sha256()
            ),
            "outcome_sha256": (
                outcome_item.outcome_sha256()
                if outcome_item is not None
                else None
            ),
        }
        canonical = cls._canonical_json(
            identity
        ).encode("utf-8")

        return hashlib.sha256(
            canonical
        ).hexdigest()

    def get_lifecycle_snapshot_sha256(
        self,
        outcome_sha256: str,
    ) -> str | None:
        lifecycle = self.get_lifecycle(
            outcome_sha256
        )

        if lifecycle is None:
            return None

        manifest, outcome = lifecycle
        return self.lifecycle_snapshot_sha256(
            manifest,
            outcome,
        )

    def _save_outcome(
        self,
        connection: sqlite3.Connection,
        item: RemediationLifecycleOutcome,
    ) -> RemediationLifecycleOutcome:
        outcome_sha256 = item.outcome_sha256()
        payload_json = self._canonical_json(item)

        row = connection.execute(
            """
            SELECT
                outcome_sha256,
                manifest_id,
                manifest_sha256,
                payload_json
            FROM remediation_lifecycle_outcomes
            WHERE outcome_sha256 = ?
            """,
            (outcome_sha256,),
        ).fetchone()

        if row is not None:
            try:
                stored = self._parse_outcome(
                    row["payload_json"],
                    expected_outcome_sha256=(
                        row["outcome_sha256"]
                    ),
                    expected_manifest_id=(
                        row["manifest_id"]
                    ),
                    expected_manifest_sha256=(
                        row["manifest_sha256"]
                    ),
                )
            except RuntimeError as exc:
                raise ValueError(
                    "outcome_sha256 collision or "
                    "inconsistent outcome identity"
                ) from exc

            if (
                stored != item
                or self._canonical_json(stored)
                != payload_json
            ):
                raise ValueError(
                    "outcome_sha256 collision or "
                    "inconsistent outcome identity"
                )

            return stored

        existing_terminal = connection.execute(
            """
            SELECT outcome_sha256
            FROM remediation_lifecycle_outcomes
            WHERE manifest_id = ?
            """,
            (item.manifest_id,),
        ).fetchone()

        if (
            existing_terminal is not None
            and existing_terminal[
                "outcome_sha256"
            ]
            != outcome_sha256
        ):
            raise ValueError(
                "A remediation manifest already has "
                "a different terminal outcome."
            )

        connection.execute(
            """
            INSERT INTO remediation_lifecycle_outcomes (
                outcome_sha256,
                manifest_id,
                manifest_sha256,
                payload_json
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                outcome_sha256,
                item.manifest_id,
                item.manifest_sha256,
                payload_json,
            ),
        )

        return item

    def _save_manifest(
        self,
        connection: sqlite3.Connection,
        item: RemediationLifecycleManifest,
    ) -> RemediationLifecycleManifest:
        manifest_sha256 = item.manifest_sha256()
        payload_json = self._canonical_json(item)

        row = connection.execute(
            """
            SELECT
                manifest_id,
                manifest_sha256,
                payload_json
            FROM remediation_lifecycle_manifests
            WHERE manifest_id = ?
            """,
            (item.manifest_id,),
        ).fetchone()

        if row is not None:
            if row["manifest_sha256"] != (
                manifest_sha256
            ):
                raise ValueError(
                    "manifest_id collision or "
                    "inconsistent manifest identity"
                )

            try:
                stored = self._parse_manifest(
                    row["payload_json"],
                    expected_manifest_id=(
                        row["manifest_id"]
                    ),
                    expected_manifest_sha256=(
                        row["manifest_sha256"]
                    ),
                )
            except RuntimeError as exc:
                raise ValueError(
                    "manifest_id collision or "
                    "inconsistent manifest identity"
                ) from exc

            if (
                stored != item
                or self._canonical_json(stored)
                != payload_json
            ):
                raise ValueError(
                    "manifest_id collision or "
                    "inconsistent manifest identity"
                )

            return stored

        connection.execute(
            """
            INSERT INTO remediation_lifecycle_manifests (
                manifest_id,
                manifest_sha256,
                payload_json
            )
            VALUES (?, ?, ?)
            """,
            (
                item.manifest_id,
                manifest_sha256,
                payload_json,
            ),
        )

        return item

    def _initialize_database(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS
                    remediation_lifecycle_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                """
            )
            connection.execute(
                """
                INSERT INTO remediation_lifecycle_metadata (
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
                FROM remediation_lifecycle_metadata
                WHERE key = 'schema_version'
                """
            ).fetchone()

            if row is None:
                raise RuntimeError(
                    "Remediation lifecycle schema metadata "
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
                    "Remediation lifecycle database "
                    "contains an invalid schema version."
                ) from exc

            if stored_version != self.schema_version:
                raise RuntimeError(
                    "Unsupported remediation lifecycle "
                    f"schema version: {stored_version}"
                )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS
                    remediation_lifecycle_manifests (
                        manifest_id TEXT PRIMARY KEY,
                        manifest_sha256 TEXT NOT NULL,
                        payload_json TEXT NOT NULL
                    )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS
                    remediation_lifecycle_outcomes (
                        outcome_sha256 TEXT PRIMARY KEY,
                        manifest_id TEXT NOT NULL,
                        manifest_sha256 TEXT NOT NULL,
                        payload_json TEXT NOT NULL
                    )
                """
            )
            connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS
                    idx_remediation_outcomes_manifest_unique
                ON remediation_lifecycle_outcomes (
                    manifest_id
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS
                    idx_remediation_outcomes_manifest_hash
                ON remediation_lifecycle_outcomes (
                    manifest_id,
                    manifest_sha256
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
    def _canonical_json(
        value: Any,
    ) -> str:
        if hasattr(value, "model_dump"):
            value = value.model_dump(
                mode="json"
            )

        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    @staticmethod
    def _parse_outcome(
        payload_json: str,
        *,
        expected_outcome_sha256: str,
        expected_manifest_id: str,
        expected_manifest_sha256: str,
    ) -> RemediationLifecycleOutcome:
        try:
            payload = json.loads(payload_json)
            outcome = (
                RemediationLifecycleOutcome
                .model_validate(payload)
            )
        except (
            json.JSONDecodeError,
            TypeError,
            ValidationError,
        ) as exc:
            raise RuntimeError(
                "Invalid remediation lifecycle "
                "outcome payload."
            ) from exc

        if (
            outcome.outcome_sha256()
            != expected_outcome_sha256
            or outcome.manifest_id
            != expected_manifest_id
            or outcome.manifest_sha256
            != expected_manifest_sha256
        ):
            raise RuntimeError(
                "Remediation lifecycle outcome "
                "integrity identity mismatch."
            )

        return outcome

    @staticmethod
    def _parse_manifest(
        payload_json: str,
        *,
        expected_manifest_id: str,
        expected_manifest_sha256: str,
    ) -> RemediationLifecycleManifest:
        try:
            payload = json.loads(payload_json)
            manifest = (
                RemediationLifecycleManifest
                .model_validate(payload)
            )
        except (
            json.JSONDecodeError,
            TypeError,
            ValidationError,
        ) as exc:
            raise RuntimeError(
                "Invalid remediation lifecycle "
                "manifest payload."
            ) from exc

        if (
            manifest.manifest_id
            != expected_manifest_id
            or manifest.manifest_sha256()
            != expected_manifest_sha256
        ):
            raise RuntimeError(
                "Remediation lifecycle manifest "
                "integrity identity mismatch."
            )

        return manifest

    @staticmethod
    def _require_lifecycle_identity(
        manifest: RemediationLifecycleManifest,
        outcome: RemediationLifecycleOutcome,
    ) -> None:
        if (
            manifest.manifest_id
            != outcome.manifest_id
            or manifest.manifest_sha256()
            != outcome.manifest_sha256
        ):
            raise ValueError(
                "Remediation lifecycle manifest/outcome "
                "identity mismatch: manifest_sha256 "
                "must bind the exact immutable manifest."
            )
