from __future__ import annotations

import hashlib
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


_RULE_METADATA: dict[str, dict[str, str]] = {
    BLOCK_RULE_ID: {
        "name": "AegisChangeBlocked",
        "description": (
            "Aegis blocked a security-sensitive "
            "software change."
        ),
        "level": "error",
        "security_severity": "9.0",
    },
    REVIEW_RULE_ID: {
        "name": "AegisChangeReviewRequired",
        "description": (
            "Aegis requires human review for a "
            "software change."
        ),
        "level": "warning",
        "security_severity": "6.0",
    },
    "AEGIS-SHELL-EXECUTION": {
        "name": "ShellExecution",
        "description": (
            "The change enables shell-based process "
            "execution."
        ),
        "level": "warning",
        "security_severity": "7.0",
    },
    "AEGIS-DYNAMIC-EXECUTION": {
        "name": "DynamicExecution",
        "description": (
            "The change introduces a dangerous dynamic "
            "execution primitive."
        ),
        "level": "warning",
        "security_severity": "7.5",
    },
    "AEGIS-TLS-VERIFICATION-DISABLED": {
        "name": "TlsVerificationDisabled",
        "description": (
            "The change disables TLS certificate "
            "verification."
        ),
        "level": "error",
        "security_severity": "8.5",
    },
    "AEGIS-WORLD-WRITABLE-PERMISSIONS": {
        "name": "WorldWritablePermissions",
        "description": (
            "The change introduces globally writable "
            "permissions."
        ),
        "level": "warning",
        "security_severity": "6.5",
    },
    "AEGIS-WILDCARD-CLOUD-PERMISSIONS": {
        "name": "WildcardCloudPermissions",
        "description": (
            "The change introduces wildcard cloud "
            "permissions."
        ),
        "level": "warning",
        "security_severity": "8.0",
    },
    "AEGIS-HARDCODED-CREDENTIAL": {
        "name": "HardcodedCredential",
        "description": (
            "The change appears to introduce a "
            "hard-coded credential."
        ),
        "level": "error",
        "security_severity": "9.0",
    },
}


def assessment_rule_id(
    assessment: ChangeFilePolicyAssessment,
) -> str:
    if assessment.rule_id is not None:
        return assessment.rule_id

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


def assessment_fingerprint(
    assessment: ChangeFilePolicyAssessment,
) -> str:
    """
    Stable across line movement.

    The current policy engine produces at most one assessment
    for each file. Rule ID plus normalized path therefore forms
    the stable finding identity without tying it to a line.
    """

    identity = "\n".join(
        [
            assessment_rule_id(assessment),
            assessment.path.replace("\\", "/"),
        ]
    )

    return hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()


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

    physical_location: dict[str, Any] = {
        "artifactLocation": {
            "uri": artifact_uri(
                assessment.path
            ),
            "uriBaseId": "%SRCROOT%",
        }
    }

    if assessment.start_line is not None:
        region: dict[str, int] = {
            "startLine": assessment.start_line,
        }

        if assessment.start_column is not None:
            region["startColumn"] = (
                assessment.start_column
            )

        physical_location["region"] = region

    fingerprint = assessment_fingerprint(
        assessment
    )

    return {
        "ruleId": assessment_rule_id(assessment),
        "level": assessment_level(assessment),
        "message": {
            "text": assessment_message(assessment),
        },
        "locations": [
            {
                "physicalLocation": (
                    physical_location
                )
            }
        ],
        "partialFingerprints": {
            "aegisRulePath/v1": fingerprint,
            "primaryLocationLineHash": fingerprint,
        },
        "properties": properties,
    }


def sarif_rule(
    rule_id: str,
) -> dict[str, Any]:
    metadata = _RULE_METADATA.get(
        rule_id,
        {
            "name": rule_id,
            "description": (
                "Aegis detected an elevated-risk "
                "software change."
            ),
            "level": "warning",
            "security_severity": "6.0",
        },
    )

    return {
        "id": rule_id,
        "name": metadata["name"],
        "shortDescription": {
            "text": metadata["description"],
        },
        "fullDescription": {
            "text": metadata["description"],
        },
        "defaultConfiguration": {
            "level": metadata["level"],
        },
        "properties": {
            "precision": "high",
            "security-severity": (
                metadata["security_severity"]
            ),
            "tags": [
                "security",
                "aegis",
                "change-gate",
            ],
        },
    }


def build_change_sarif(
    result: ChangePolicyCollectionResponse,
) -> dict[str, Any]:
    reportable_assessments = [
        assessment
        for assessment in result.policy.assessments
        if assessment.decision != "allow"
    ]

    sarif_results = [
        assessment_result(assessment)
        for assessment in reportable_assessments
    ]

    used_rule_ids = sorted(
        {
            assessment_rule_id(assessment)
            for assessment in reportable_assessments
        }
    )

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
                        "name": (
                            "Aegis Change Security Gate"
                        ),
                        "informationUri": (
                            "https://github.com/lemkyz/aegis"
                        ),
                        "semanticVersion": "0.1.0",
                        "rules": [
                            sarif_rule(rule_id)
                            for rule_id in used_rule_ids
                        ],
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
