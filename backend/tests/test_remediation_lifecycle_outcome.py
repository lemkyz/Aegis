import hashlib
import json

import pytest
from pydantic import ValidationError

import aegis.schemas.fixes as fixes_schema
from aegis.schemas.validation import (
    DynamicValidationTaskArtifact,
)


def _outcome_type():
    outcome_type = getattr(
        fixes_schema,
        "RemediationLifecycleOutcome",
        None,
    )
    assert outcome_type is not None, (
        "Step 48.2D requires "
        "RemediationLifecycleOutcome."
    )
    return outcome_type


def _payload(
    *,
    transaction_state: str = "committed",
) -> dict:
    return {
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


def test_remediation_lifecycle_outcome_schema_exists() -> None:
    _outcome_type()


def test_dynamic_validation_artifact_has_deterministic_digest() -> None:
    assert hasattr(
        DynamicValidationTaskArtifact,
        "artifact_sha256",
    ), (
        "Step 48.2D requires a deterministic "
        "DynamicValidationTaskArtifact identity."
    )


def test_remediation_lifecycle_outcome_is_strict_frozen() -> None:
    outcome_type = _outcome_type()

    assert outcome_type.model_config.get(
        "extra"
    ) == "forbid"
    assert outcome_type.model_config.get(
        "strict"
    ) is True
    assert outcome_type.model_config.get(
        "frozen"
    ) is True


def test_remediation_lifecycle_outcome_rejects_pending() -> None:
    outcome_type = _outcome_type()

    with pytest.raises(ValidationError):
        outcome_type.model_validate(
            _payload(
                transaction_state="pending"
            )
        )


def test_remediation_lifecycle_outcome_digest_is_deterministic() -> None:
    outcome_type = _outcome_type()

    first = outcome_type.model_validate(
        _payload()
    )
    second = outcome_type.model_validate(
        first.model_dump(mode="json")
    )

    assert first == second
    assert first.outcome_sha256() == (
        second.outcome_sha256()
    )

    canonical = json.dumps(
        first.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    assert first.outcome_sha256() == (
        hashlib.sha256(canonical).hexdigest()
    )


def test_remediation_lifecycle_outcome_digest_binds_terminal_state() -> None:
    outcome_type = _outcome_type()

    committed = outcome_type.model_validate(
        _payload(
            transaction_state="committed"
        )
    )
    rolled_back = outcome_type.model_validate(
        _payload(
            transaction_state="rolled_back"
        )
    )

    assert committed.outcome_sha256() != (
        rolled_back.outcome_sha256()
    )


@pytest.mark.parametrize(
    "field",
    [
        "manifest_sha256",
        "static_verification_sha256",
        "dynamic_validation_sha256",
    ],
)
def test_remediation_lifecycle_outcome_rejects_invalid_digests(
    field: str,
) -> None:
    outcome_type = _outcome_type()
    payload = _payload()
    payload[field] = "not-a-sha256"

    with pytest.raises(ValidationError):
        outcome_type.model_validate(payload)
