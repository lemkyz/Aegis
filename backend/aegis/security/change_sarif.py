from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import quote

from aegis.schemas.change_policy import (
    ChangeFilePolicyAssessment,
    ChangePolicyCollectionResponse,
)


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://json.schemastore.org/"
    "sarif-2.1.0.json"
)

BLOCK_RULE_ID = "AEGIS-CHANGE-BLOCK"
REVIEW_RULE_ID = "AEGIS-CHANGE-REVIEW"


def assessment_rule_id(
    assessment: ChangeFilePolicyAssessment,
) -> str:
    if assessment.decision == "block":
        return BLOCK_RULE_ID

    if assessment.decision == "review":
        return REVIEW_RULE_ID

    raise ValueError(
        "ALLOW assessments do not produce SARIF results."
    )


def assessment_level(
    assessment: ChangeFilePolicyAssessment,
) -> str:
    if assessment.decision == "block":
        return "error"

    if assessment.decision == "review":
        return "warning"

    raise ValueError(
        "ALLOW assessments do not produce SARIF results."
    )


def artifact_uri(path: str) -> str:
    normalized = path.replace("\\", "/").lstrip("/")

    if not normalized:
        raise ValueError(
            "SARIF artifact path cannot be empty."
        )

    return quote(
        normalized,
        safe="/:@-._~",
    )


def assessment_message(
    assessment: ChangeFilePolicyAssessment,
) -> str:
    if assessment.reasons:
        return "; ".join(assessment.reasons)

    return (
        "The changed file did not satisfy the "
        "configured Aegis security policy."
    )


def assessment_result(
    assessment: ChangeFilePolicyAssessment,
) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "decision": assessment.decision,
        "riskScore": assessment.risk_score,
        "riskLevel": assessment.risk_level,
        "changeStatus": assessment.status,
    }

    if assessment.old_path is not None:
        properties["oldPath"] = assessment.old_path

    return {
        "ruleId": assessment_rule_id(assessment),
        "level": assessment_level(assessment),
        "message": {
            "text": assessment_message(assessment),
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": artifact_uri(
                            assessment.path
                        ),
                        "uriBaseId": "%SRCROOT%",
                    }
                }
            }
        ],
        "properties": properties,
    }


def sarif_rules() -> list[dict[str, Any]]:
    return [
        {
            "id": BLOCK_RULE_ID,
            "name": "AegisChangeBlocked",
            "shortDescription": {
                "text": (
                    "Aegis blocked a security-sensitive "
                    "software change."
                )
            },
            "fullDescription": {
                "text": (
                    "The deterministic Aegis change policy "
                    "found evidence requiring the change "
                    "to be blocked."
                )
            },
            "defaultConfiguration": {
                "level": "error",
            },
            "properties": {
                "precision": "high",
                "security-severity": "9.0",
                "tags": [
                    "security",
                    "aegis",
                    "change-gate",
                ],
            },
        },
        {
            "id": REVIEW_RULE_ID,
            "name": "AegisChangeReviewRequired",
            "shortDescription": {
                "text": (
                    "Aegis requires human review for a "
                    "software change."
                )
            },
            "fullDescription": {
                "text": (
                    "The deterministic Aegis change policy "
                    "found elevated risk evidence requiring "
                    "human review."
                )
            },
            "defaultConfiguration": {
                "level": "warning",
            },
            "properties": {
                "precision": "high",
                "security-severity": "6.0",
                "tags": [
                    "security",
                    "aegis",
                    "change-gate",
                ],
            },
        },
    ]


def build_change_sarif(
    result: ChangePolicyCollectionResponse,
) -> dict[str, Any]:
    sarif_results = [
        assessment_result(assessment)
        for assessment in result.policy.assessments
        if assessment.decision != "allow"
    ]

    invocation = {
        "executionSuccessful": True,
        "properties": {
            "decision": result.policy.decision,
            "riskScore": result.policy.risk_score,
            "riskLevel": result.policy.risk_level,
            "profile": result.policy.profile,
            "mode": result.change_set.mode,
            "changedFiles": (
                result.change_set.file_count
            ),
            "baseRevision": (
                result.change_set.base_revision
            ),
            "headRevision": (
                result.change_set.head_revision
            ),
        },
    }

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Aegis Change Security Gate",
                        "informationUri": (
                            "https://github.com/lemkyz/aegis"
                        ),
                        "semanticVersion": "0.1.0",
                        "rules": sarif_rules(),
                    }
                },
                "automationDetails": {
                    "id": "aegis/change-gate",
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "uri": "file:///",
                    }
                },
                "invocations": [invocation],
                "results": sarif_results,
            }
        ],
    }
