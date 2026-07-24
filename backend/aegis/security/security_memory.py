from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Protocol

from aegis.schemas.memory import (
    ClaimReconciliationRequest,
    ProjectSecuritySnapshot,
    SecurityMemoryRecordRequest,
    SecurityMemoryRecordResponse,
)
from aegis.security.claim_reconciliation import (
    ClaimReconciler,
)
from aegis.security.memory_snapshot import (
    ProjectSecuritySnapshotBuilder,
)
from aegis.security.project_identity import (
    ProjectIdentityResolver,
)


class ProjectMemoryStore(Protocol):
    def save_snapshot(
        self,
        snapshot: ProjectSecuritySnapshot,
    ) -> ProjectSecuritySnapshot:
        ...

    def get_snapshot(
        self,
        snapshot_id: str,
    ) -> ProjectSecuritySnapshot | None:
        ...

    def get_latest_snapshot(
        self,
        project_id: str,
    ) -> ProjectSecuritySnapshot | None:
        ...

    def list_snapshots(
        self,
        project_id: str,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ProjectSecuritySnapshot]:
        ...

    def count_snapshots(
        self,
        project_id: str,
    ) -> int:
        ...


class SecurityMemoryService:
    """
    Application service coordinating project identity,
    immutable snapshots, claim reconciliation and persistence.
    """

    name = "aegis-security-memory-service-v1"

    def __init__(
        self,
        *,
        store: ProjectMemoryStore,
        identity_resolver: (
            ProjectIdentityResolver | None
        ) = None,
        snapshot_builder: (
            ProjectSecuritySnapshotBuilder | None
        ) = None,
        reconciler: ClaimReconciler | None = None,
    ) -> None:
        self.store = store
        self.identity_resolver = (
            identity_resolver
            if identity_resolver is not None
            else ProjectIdentityResolver()
        )
        self.snapshot_builder = (
            snapshot_builder
            if snapshot_builder is not None
            else ProjectSecuritySnapshotBuilder()
        )
        self.reconciler = (
            reconciler
            if reconciler is not None
            else ClaimReconciler()
        )

    def record(
        self,
        request: SecurityMemoryRecordRequest,
        *,
        created_at: datetime | None = None,
    ) -> SecurityMemoryRecordResponse:
        repository_path = Path(
            request.repository_path
        ).expanduser()

        repository = self.identity_resolver.resolve(
            repository_path
        )

        previous_snapshot = (
            self.store.get_latest_snapshot(
                repository.project_id
            )
        )

        current_snapshot = (
            self.snapshot_builder.build(
                project_id=repository.project_id,
                revision=repository.revision,
                claims=request.claims,
                created_at=created_at,
            )
        )

        existing_snapshot = self.store.get_snapshot(
            current_snapshot.snapshot_id
        )

        persisted_snapshot = self.store.save_snapshot(
            current_snapshot
        )

        if (
            persisted_snapshot.project_id
            != repository.project_id
        ):
            raise RuntimeError(
                "Stored snapshot project identity does "
                "not match the resolved repository."
            )

        reconciliation = self.reconciler.reconcile(
            ClaimReconciliationRequest(
                previous_claims=(
                    previous_snapshot.claims
                    if previous_snapshot is not None
                    else []
                ),
                current_claims=(
                    persisted_snapshot.claims
                ),
            )
        )

        snapshot_count = self.store.count_snapshots(
            repository.project_id
        )

        if snapshot_count < 1:
            raise RuntimeError(
                "Security-memory store did not retain "
                "the recorded snapshot."
            )

        return SecurityMemoryRecordResponse(
            service=self.name,
            repository=repository,
            snapshot=persisted_snapshot,
            previous_snapshot_id=(
                previous_snapshot.snapshot_id
                if previous_snapshot is not None
                else None
            ),
            reconciliation=reconciliation,
            baseline_created=(
                previous_snapshot is None
            ),
            persisted_new_snapshot=(
                existing_snapshot is None
            ),
            project_snapshot_count=snapshot_count,
        )

    def latest(
        self,
        repository_path: str | Path,
    ) -> ProjectSecuritySnapshot | None:
        repository = self.identity_resolver.resolve(
            repository_path
        )

        return self.store.get_latest_snapshot(
            repository.project_id
        )

    def history(
        self,
        repository_path: str | Path,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ProjectSecuritySnapshot]:
        repository = self.identity_resolver.resolve(
            repository_path
        )

        return self.store.list_snapshots(
            repository.project_id,
            limit=limit,
            offset=offset,
        )
