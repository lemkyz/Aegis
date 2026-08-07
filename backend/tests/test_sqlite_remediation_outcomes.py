import importlib
import json
import sqlite3
from pathlib import Path

import pytest

from aegis.schemas.fixes import (
    RemediationLifecycleOutcome,
)

from aegis.schemas import fixes as fix_schemas


def _store_type():
    module = importlib.import_module(
        "aegis.security.sqlite_remediation_outcomes"
    )
    store_type = getattr(
        module,
        "SQLiteRemediationOutcomeStore",
        None,
    )
    assert store_type is not None, (
        "Step 48.3 requires "
        "SQLiteRemediationOutcomeStore."
    )
    return store_type


def _outcome(
    *,
    transaction_state: str = "committed",
) -> RemediationLifecycleOutcome:
    return RemediationLifecycleOutcome.model_validate(
        {
            "schema_version": "1.0",
            "manifest_id": (
                "remediation-manifest:"
                + ("a" * 64)
            ),
            "manifest_sha256": "b" * 64,
            "static_verification_sha256": "c" * 64,
            "dynamic_validation_sha256": "d" * 64,
            "unified_verdict": "verified",
            "transaction_state": transaction_state,
            "residual_risk": {
                "claim_id": "claim:test",
                "patch_sha256": "e" * 64,
                "status": "none_identified",
                "reasons": [
                    "No residual risk was identified.",
                ],
            },
        }
    )


def _database_path(
    tmp_path: Path,
) -> Path:
    return tmp_path / "memory.sqlite3"


def _replace_payload(
    database_path: Path,
    *,
    outcome_sha256: str,
    payload_json: str,
) -> None:
    with sqlite3.connect(
        database_path
    ) as connection:
        connection.execute(
            """
            UPDATE remediation_lifecycle_outcomes
            SET payload_json = ?
            WHERE outcome_sha256 = ?
            """,
            (
                payload_json,
                outcome_sha256,
            ),
        )


def test_sqlite_remediation_outcome_store_exists() -> None:
    _store_type()


def test_initializes_remediation_outcome_table(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    database_path = _database_path(tmp_path)

    store_type(database_path)

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

    assert (
        "remediation_lifecycle_outcomes"
        in tables
    )


def test_saves_and_reads_exact_outcome(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    store = store_type(
        _database_path(tmp_path)
    )
    item = _outcome()

    saved = store.save_outcome(item)
    loaded = store.get_outcome(
        item.outcome_sha256()
    )

    assert saved == item
    assert loaded == item
    assert loaded is not None
    assert loaded.outcome_sha256() == (
        item.outcome_sha256()
    )


def test_persists_outcome_across_store_instances(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    database_path = _database_path(tmp_path)
    item = _outcome()

    first = store_type(database_path)
    first.save_outcome(item)

    second = store_type(database_path)
    loaded = second.get_outcome(
        item.outcome_sha256()
    )

    assert loaded == item
    assert loaded is not None
    assert loaded.outcome_sha256() == (
        item.outcome_sha256()
    )


def test_missing_outcome_returns_none(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    store = store_type(
        _database_path(tmp_path)
    )

    assert store.get_outcome(
        "f" * 64
    ) is None


def test_duplicate_outcome_save_is_idempotent(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    database_path = _database_path(tmp_path)
    store = store_type(database_path)
    item = _outcome()

    first = store.save_outcome(item)
    second = store.save_outcome(item)

    assert first == item
    assert second == item

    with sqlite3.connect(
        database_path
    ) as connection:
        count = connection.execute(
            """
            SELECT COUNT(*)
            FROM remediation_lifecycle_outcomes
            WHERE outcome_sha256 = ?
            """,
            (item.outcome_sha256(),),
        ).fetchone()[0]

    assert count == 1


def test_same_identity_with_tampered_content_is_rejected(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    database_path = _database_path(tmp_path)
    store = store_type(database_path)
    item = _outcome()

    store.save_outcome(item)

    changed = item.model_copy(
        deep=True,
        update={
            "transaction_state": "rolled_back",
        },
    )
    assert changed.outcome_sha256() != (
        item.outcome_sha256()
    )

    _replace_payload(
        database_path,
        outcome_sha256=item.outcome_sha256(),
        payload_json=json.dumps(
            changed.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
    )

    with pytest.raises(
        ValueError,
        match=(
            "outcome_sha256 collision|"
            "inconsistent outcome identity"
        ),
    ):
        store.save_outcome(item)


def test_tampered_persisted_outcome_fails_closed_on_reload(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    database_path = _database_path(tmp_path)
    store = store_type(database_path)
    item = _outcome()

    store.save_outcome(item)

    changed = item.model_copy(
        deep=True,
        update={
            "transaction_state": "rolled_back",
        },
    )

    _replace_payload(
        database_path,
        outcome_sha256=item.outcome_sha256(),
        payload_json=json.dumps(
            changed.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
    )

    restarted = store_type(database_path)

    with pytest.raises(
        RuntimeError,
        match=(
            "integrity|digest|tamper|identity"
        ),
    ):
        restarted.get_outcome(
            item.outcome_sha256()
        )


def test_malformed_persisted_outcome_fails_closed(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    database_path = _database_path(tmp_path)
    store = store_type(database_path)
    item = _outcome()

    store.save_outcome(item)

    _replace_payload(
        database_path,
        outcome_sha256=item.outcome_sha256(),
        payload_json="{not-json",
    )

    restarted = store_type(database_path)

    with pytest.raises(
        RuntimeError,
        match=(
            "invalid|malformed|parse|payload"
        ),
    ):
        restarted.get_outcome(
            item.outcome_sha256()
        )


# Step 48.3E lifecycle manifest fixtures.
def manifest_type():
    value = getattr(
        fix_schemas,
        "RemediationLifecycleManifest",
        None,
    )

    assert value is not None, (
        "RemediationLifecycleManifest is not implemented."
    )

    return value

def proposal():
    return fix_schemas.SecureFixProposal(
        claim_id="claim-command-001",
        target_path="app.py",
        expected_file_sha256="a" * 64,
        expected_selection_sha256="b" * 64,
        start_offset=10,
        end_offset=20,
        replacement="safe_call()",
    )

def fix_plan():
    value = proposal()

    return fix_schemas.FixPlan(
        plan_id="fix-plan:claim-command-001",
        proposal=value,
        verification_plan=(
            fix_schemas.FixVerificationPlan(
                plan_id=(
                    "verification-plan:"
                    "claim-command-001"
                ),
                claim_id=value.claim_id,
                patch_sha256=value.patch_sha256(),
                checks=[
                    fix_schemas.FixVerificationCheck(
                        check_id="check:project-tests",
                        kind="project",
                        name="Project tests",
                    ),
                ],
            )
        ),
    )

def applied_patch(
    *,
    claim_id: str = "claim-command-001",
    target_path: str = "app.py",
    patch_sha256: str | None = None,
    before_sha256: str = "a" * 64,
    transaction_state: str = "pending",
):
    plan = fix_plan()

    return fix_schemas.AppliedPatchArtifact.model_validate(
        {
            "handler": "test-secure-fix",
            "transaction_id": "fix:transaction-001",
            "claim_id": claim_id,
            "target_path": target_path,
            "approval_id": "approval:test",
            "patch_sha256": (
                patch_sha256
                if patch_sha256 is not None
                else plan.proposal.patch_sha256()
            ),
            "before_sha256": before_sha256,
            "after_sha256": "c" * 64,
            "changed_characters": 10,
            "policy": {
                "engine": "test-policy",
                "policy_version": "1.0",
                "profile": "balanced",
                "decision": "allow",
                "risk_score": 0,
                "risk_level": "none",
                "blocking_paths": [],
                "review_paths": [],
                "assessments": [],
                "summary": {
                    "files_evaluated": 0,
                    "allowed": 0,
                    "review_required": 0,
                    "blocked": 0,
                    "highest_risk_score": 0,
                    "highest_risk_level": "none",
                    "sensitive_files": 0,
                    "dangerous_patterns": 0,
                    "truncated_files": 0,
                    "binary_files": 0,
                },
                "reasons": [],
            },
            "transaction_state": transaction_state,
            "outputs_redacted": True,
        }
    )

def manifest(**updates):
    plan = fix_plan()
    payload = {
        "manifest_id": (
            "remediation-manifest:"
            "claim-command-001"
        ),
        "fix_plan": plan,
        "fix_plan_sha256": plan.plan_sha256(),
        "applied_patch": applied_patch(),
    }
    payload.update(updates)

    return manifest_type()(**payload)

def _alternate_manifest_same_id():
    original = manifest()
    alternate_plan = original.fix_plan.model_copy(
        deep=True,
        update={
            "plan_id": "fix-plan:alternate",
        },
    )

    return fix_schemas.RemediationLifecycleManifest(
        manifest_id=original.manifest_id,
        fix_plan=alternate_plan,
        fix_plan_sha256=(
            alternate_plan.plan_sha256()
        ),
        applied_patch=original.applied_patch,
    )


def _outcome_for_manifest(
    lifecycle_manifest,
):
    return _outcome().model_copy(
        deep=True,
        update={
            "manifest_id": (
                lifecycle_manifest.manifest_id
            ),
            "manifest_sha256": (
                lifecycle_manifest
                .manifest_sha256()
            ),
        },
    )


def _replace_manifest_payload(
    database_path: Path,
    *,
    manifest_id: str,
    payload_json: str,
) -> None:
    with sqlite3.connect(
        database_path
    ) as connection:
        connection.execute(
            """
            UPDATE remediation_lifecycle_manifests
            SET payload_json = ?
            WHERE manifest_id = ?
            """,
            (
                payload_json,
                manifest_id,
            ),
        )


def test_initializes_remediation_lifecycle_schema_metadata(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    database_path = _database_path(tmp_path)

    store_type(database_path)

    with sqlite3.connect(
        database_path
    ) as connection:
        row = connection.execute(
            """
            SELECT value
            FROM remediation_lifecycle_metadata
            WHERE key = 'schema_version'
            """
        ).fetchone()

    assert row is not None
    assert row[0] == "1"


def test_rejects_unsupported_remediation_lifecycle_schema(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    database_path = _database_path(tmp_path)

    store_type(database_path)

    with sqlite3.connect(
        database_path
    ) as connection:
        connection.execute(
            """
            UPDATE remediation_lifecycle_metadata
            SET value = '999'
            WHERE key = 'schema_version'
            """
        )

    with pytest.raises(
        RuntimeError,
        match=(
            "Unsupported remediation lifecycle "
            "schema version"
        ),
    ):
        store_type(database_path)


def test_manifest_persists_and_reloads_exactly(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    database_path = _database_path(tmp_path)
    store = store_type(database_path)
    item = manifest()

    first = store.save_manifest(item)
    second = store.save_manifest(item)

    restarted = store_type(database_path)
    loaded = restarted.get_manifest(
        item.manifest_id
    )

    assert first == item
    assert second == item
    assert loaded == item
    assert loaded is not None
    assert loaded.manifest_sha256() == (
        item.manifest_sha256()
    )


def test_manifest_id_collision_is_rejected(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    store = store_type(
        _database_path(tmp_path)
    )
    original = manifest()
    changed = _alternate_manifest_same_id()

    assert changed.manifest_id == (
        original.manifest_id
    )
    assert changed.manifest_sha256() != (
        original.manifest_sha256()
    )

    store.save_manifest(original)

    with pytest.raises(
        ValueError,
        match=(
            "manifest_id collision|"
            "inconsistent manifest identity"
        ),
    ):
        store.save_manifest(changed)

    assert store.get_manifest(
        original.manifest_id
    ) == original


def test_tampered_manifest_fails_closed_on_reload(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    database_path = _database_path(tmp_path)
    store = store_type(database_path)
    item = manifest()

    store.save_manifest(item)

    changed = _alternate_manifest_same_id()

    _replace_manifest_payload(
        database_path,
        manifest_id=item.manifest_id,
        payload_json=json.dumps(
            changed.model_dump(mode="json"),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
    )

    restarted = store_type(database_path)

    with pytest.raises(
        RuntimeError,
        match=(
            "manifest.*integrity|"
            "digest.*mismatch|"
            "identity"
        ),
    ):
        restarted.get_manifest(
            item.manifest_id
        )


def test_save_lifecycle_persists_manifest_and_outcome_atomically(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    database_path = _database_path(tmp_path)
    store = store_type(database_path)
    lifecycle_manifest = manifest()
    outcome = _outcome_for_manifest(
        lifecycle_manifest
    )

    saved_manifest, saved_outcome = (
        store.save_lifecycle(
            lifecycle_manifest,
            outcome,
        )
    )

    restarted = store_type(database_path)

    loaded_manifest = restarted.get_manifest(
        lifecycle_manifest.manifest_id
    )
    loaded_outcome = restarted.get_outcome(
        outcome.outcome_sha256()
    )

    assert saved_manifest == lifecycle_manifest
    assert saved_outcome == outcome
    assert loaded_manifest == lifecycle_manifest
    assert loaded_outcome == outcome


def test_save_lifecycle_rejects_partial_identity_mismatch(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    database_path = _database_path(tmp_path)
    store = store_type(database_path)
    lifecycle_manifest = manifest()
    outcome = _outcome_for_manifest(
        lifecycle_manifest
    ).model_copy(
        deep=True,
        update={
            "manifest_sha256": "f" * 64,
        },
    )

    with pytest.raises(
        ValueError,
        match=(
            "manifest.*outcome|"
            "lifecycle.*identity|"
            "manifest_sha256"
        ),
    ):
        store.save_lifecycle(
            lifecycle_manifest,
            outcome,
        )

    assert store.get_manifest(
        lifecycle_manifest.manifest_id
    ) is None
    assert store.get_outcome(
        outcome.outcome_sha256()
    ) is None


def test_get_lifecycle_rejects_partial_persistence(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    database_path = _database_path(tmp_path)
    store = store_type(database_path)
    lifecycle_manifest = manifest()
    outcome = _outcome_for_manifest(
        lifecycle_manifest
    )

    store.save_manifest(
        lifecycle_manifest
    )
    store.save_outcome(outcome)

    with sqlite3.connect(
        database_path
    ) as connection:
        connection.execute(
            """
            DELETE FROM remediation_lifecycle_manifests
            WHERE manifest_id = ?
            """,
            (
                lifecycle_manifest.manifest_id,
            ),
        )

    restarted = store_type(database_path)

    with pytest.raises(
        RuntimeError,
        match=(
            "partial remediation lifecycle|"
            "missing manifest"
        ),
    ):
        restarted.get_lifecycle(
            outcome.outcome_sha256()
        )

def test_manifest_accepts_only_one_terminal_outcome(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    store = store_type(
        _database_path(tmp_path)
    )
    lifecycle_manifest = manifest()
    committed = _outcome_for_manifest(
        lifecycle_manifest
    )
    rolled_back = committed.model_copy(
        deep=True,
        update={
            "transaction_state": "rolled_back",
        },
    )

    assert committed.outcome_sha256() != (
        rolled_back.outcome_sha256()
    )

    store.save_lifecycle(
        lifecycle_manifest,
        committed,
    )

    with pytest.raises(
        ValueError,
        match=(
            "different terminal outcome|"
            "already has"
        ),
    ):
        store.save_outcome(
            rolled_back
        )

    assert store.get_outcome(
        committed.outcome_sha256()
    ) == committed
    assert store.get_outcome(
        rolled_back.outcome_sha256()
    ) is None

def test_pending_lifecycle_snapshot_identity_is_deterministic_across_reload(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    database_path = _database_path(tmp_path)
    store = store_type(database_path)
    lifecycle_manifest = manifest()

    store.save_manifest(
        lifecycle_manifest
    )
    first = store.lifecycle_snapshot_sha256(
        lifecycle_manifest
    )

    restarted = store_type(database_path)
    loaded = restarted.get_manifest(
        lifecycle_manifest.manifest_id
    )

    assert loaded == lifecycle_manifest
    assert loaded is not None
    assert restarted.lifecycle_snapshot_sha256(
        loaded
    ) == first
    assert len(first) == 64


def test_terminal_lifecycle_snapshot_identity_is_deterministic_across_reload(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    database_path = _database_path(tmp_path)
    store = store_type(database_path)
    lifecycle_manifest = manifest()
    outcome = _outcome_for_manifest(
        lifecycle_manifest
    )

    store.save_lifecycle(
        lifecycle_manifest,
        outcome,
    )
    first = store.lifecycle_snapshot_sha256(
        lifecycle_manifest,
        outcome,
    )

    restarted = store_type(database_path)
    loaded = restarted.get_lifecycle(
        outcome.outcome_sha256()
    )

    assert loaded is not None
    loaded_manifest, loaded_outcome = loaded
    assert loaded_manifest == lifecycle_manifest
    assert loaded_outcome == outcome
    assert restarted.lifecycle_snapshot_sha256(
        loaded_manifest,
        loaded_outcome,
    ) == first
    assert (
        restarted.get_lifecycle_snapshot_sha256(
            outcome.outcome_sha256()
        )
        == first
    )


def test_same_lifecycle_content_has_same_snapshot_identity(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    store = store_type(
        _database_path(tmp_path)
    )
    lifecycle_manifest = manifest()
    outcome = _outcome_for_manifest(
        lifecycle_manifest
    )

    first = store.lifecycle_snapshot_sha256(
        lifecycle_manifest,
        outcome,
    )
    second = store.lifecycle_snapshot_sha256(
        lifecycle_manifest.model_copy(
            deep=True
        ),
        outcome.model_copy(
            deep=True
        ),
    )

    assert first == second


def test_lifecycle_snapshot_identity_changes_with_terminal_outcome(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    store = store_type(
        _database_path(tmp_path)
    )
    lifecycle_manifest = manifest()
    committed = _outcome_for_manifest(
        lifecycle_manifest
    )
    rolled_back = committed.model_copy(
        deep=True,
        update={
            "transaction_state": "rolled_back",
        },
    )

    committed_identity = (
        store.lifecycle_snapshot_sha256(
            lifecycle_manifest,
            committed,
        )
    )
    rolled_back_identity = (
        store.lifecycle_snapshot_sha256(
            lifecycle_manifest,
            rolled_back,
        )
    )

    assert committed_identity != (
        rolled_back_identity
    )


def test_lifecycle_snapshot_identity_rejects_mismatched_outcome(
    tmp_path: Path,
) -> None:
    store_type = _store_type()
    store = store_type(
        _database_path(tmp_path)
    )
    lifecycle_manifest = manifest()
    mismatched = _outcome_for_manifest(
        lifecycle_manifest
    ).model_copy(
        deep=True,
        update={
            "manifest_sha256": "f" * 64,
        },
    )

    with pytest.raises(
        ValueError,
        match=(
            "manifest/outcome|"
            "lifecycle.*identity|"
            "manifest_sha256"
        ),
    ):
        store.lifecycle_snapshot_sha256(
            lifecycle_manifest,
            mismatched,
        )
