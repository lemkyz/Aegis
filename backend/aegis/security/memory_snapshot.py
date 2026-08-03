from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from aegis.schemas.claims import SecurityClaim
from aegis.schemas.memory import (
    ProjectSecuritySnapshot,
)


class ProjectSecuritySnapshotBuilder:
    name = "aegis-project-security-snapshot-v1"

    def build(
        self,
        *,
        project_id: str,
        claims: list[SecurityClaim],
        revision: str | None = None,
        created_at: datetime | None = None,
    ) -> ProjectSecuritySnapshot:
        normalized_project_id = (
            self._normalize_project_id(project_id)
        )
        normalized_revision = (
            self._normalize_revision(revision)
        )

        unique_claims = self._validate_and_sort_claims(
            claims
        )

        snapshot_id = self._snapshot_id(
            project_id=normalized_project_id,
            revision=normalized_revision,
            claims=unique_claims,
        )

        timestamp = (
            created_at
            if created_at is not None
            else datetime.now(UTC)
        )

        if timestamp.tzinfo is None:
            raise ValueError(
                "created_at must be timezone-aware"
            )

        normalized_timestamp = (
            timestamp
            .astimezone(UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )

        return ProjectSecuritySnapshot(
            snapshot_id=snapshot_id,
            project_id=normalized_project_id,
            revision=normalized_revision,
            created_at=normalized_timestamp,
            claims=unique_claims,
            claim_count=len(unique_claims),
        )

    @staticmethod
    def _normalize_project_id(
        value: str,
    ) -> str:
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "project_id must not be empty"
            )

        return normalized.replace("\\", "/")

    @staticmethod
    def _normalize_revision(
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        normalized = value.strip()

        return normalized or None

    @staticmethod
    def _validate_and_sort_claims(
        claims: list[SecurityClaim],
    ) -> list[SecurityClaim]:
        claim_ids = [
            claim.claim_id
            for claim in claims
        ]

        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError(
                "claims must contain unique "
                "claim_id values"
            )

        return sorted(
            claims,
            key=lambda claim: claim.claim_id,
        )

    @classmethod
    def _snapshot_id(
        cls,
        *,
        project_id: str,
        revision: str | None,
        claims: list[SecurityClaim],
    ) -> str:
        identity = {
            "schema": "project-security-snapshot-v1",
            "project_id": project_id,
            "revision": revision or "working-tree",
            "claims": [
                cls._claim_identity(claim)
                for claim in claims
            ],
        }

        payload = json.dumps(
            identity,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        digest = hashlib.sha256(
            payload.encode("utf-8")
        ).hexdigest()

        return f"snapshot:sha256:{digest}"

    @staticmethod
    def _claim_identity(
        claim: SecurityClaim,
    ) -> dict[str, object]:
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
                (
                    relationship.relationship_id,
                    relationship.source_evidence_id,
                    relationship.target_evidence_id,
                    relationship.kind,
                    relationship.reason,
                )
                for relationship in claim.relationships
            ),
        }
