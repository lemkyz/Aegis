from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import quote

from aegis.schemas.change_policy import (
    ChangeFilePolicyAssessment,
    ChangePolicyCollectionResponse,
    ChangePolicyFinding,
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
    return (
        "error"
        if assessment.decision == "block"
        else "warning"
    )


def stable_fingerprint(
    *,
    rule_id: str,
    path: str,
    occurrence: int,
) -> str:
    identity = "\n".join(
        [
            rule_id,
            path.replace("\\", "/"),
            str(occurrence),
        ]
    )

    return hashlib.sha256(
        identity.encode("utf-8")
    ).hexdigest()


def physical_location(
    *,
    path: str,
    start_line: int | None,
    start_column: int | None,
) -> dict[str, Any]:
    location: dict[str, Any] = {
        "artifactLocation": {
            "uri": artifact_uri(path),
            "uriBaseId": "%SRCROOT%",
        }
    }

    if start_line is not None:
        region: dict[str, int] = {
            "startLine": start_line,
        }

        if start_column is not None:
            region["startColumn"] = start_column

        location["region"] = region

    return location


def finding_result(
    *,
    assessment: ChangeFilePolicyAssessment,
    finding: ChangePolicyFinding,
    occurrence: int,
) -> dict[str, Any]:
    level = (
        "error"
        if finding.blocking
        else "warning"
    )

    fingerprint = stable_fingerprint(
        rule_id=finding.rule_id,
        path=assessment.path,
        occurrence=occurrence,
    )

    return {
        "ruleId": finding.rule_id,
        "level": level,
        "message": {
            "text": finding.reason,
        },
        "locations": [
            {
                "physicalLocation": physical_location(
                    path=assessment.path,
                    start_line=finding.start_line,
                    start_column=finding.start_column,
                )
            }
        ],
        "partialFingerprints": {
            "aegisRulePathOccurrence/v1": (
                fingerprint
            ),
            "primaryLocationLineHash": fingerprint,
        },
        "properties": {
            "decision": assessment.decision,
            "riskScore": assessment.risk_score,
            "riskLevel": assessment.risk_level,
            "ruleScore": finding.score,
            "blockingRule": finding.blocking,
            "changeStatus": assessment.status,
        },
    }


def generic_assessment_result(
    assessment: ChangeFilePolicyAssessment,
) -> dict[str, Any]:
    rule_id = assessment_rule_id(assessment)

    fingerprint = stable_fingerprint(
        rule_id=rule_id,
        path=assessment.path,
        occurrence=0,
    )

    message = (
        "; ".join(assessment.reasons)
        if assessment.reasons
        else (
            "The changed file did not satisfy the "
            "configured Aegis security policy."
        )
    )

    return {
        "ruleId": rule_id,
        "level": assessment_level(assessment),
        "message": {
            "text": message,
        },
        "locations": [
            {
                "physicalLocation": physical_location(
                    path=assessment.path,
                    start_line=assessment.start_line,
                    start_column=assessment.start_column,
                )
            }
        ],
        "partialFingerprints": {
            "aegisRulePathOccurrence/v1": (
                fingerprint
            ),
            "primaryLocationLineHash": fingerprint,
        },
        "properties": {
            "decision": assessment.decision,
            "riskScore": assessment.risk_score,
            "riskLevel": assessment.risk_level,
            "changeStatus": assessment.status,
        },
    }


def assessment_results(
    assessment: ChangeFilePolicyAssessment,
) -> list[dict[str, Any]]:
    if not assessment.findings:
        return [
            generic_assessment_result(assessment)
        ]

    occurrences: dict[str, int] = {}
    results: list[dict[str, Any]] = []

    for finding in assessment.findings:
        occurrence = occurrences.get(
            finding.rule_id,
            0,
        )
        occurrences[finding.rule_id] = (
            occurrence + 1
        )

        results.append(
            finding_result(
                assessment=assessment,
                finding=finding,
                occurrence=occurrence,
            )
        )

    return results


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
    assessments = [
        assessment
        for assessment in result.policy.assessments
        if assessment.decision != "allow"
    ]

    sarif_results = [
        sarif_result
        for assessment in assessments
        for sarif_result in assessment_results(
            assessment
        )
    ]

    used_rule_ids = sorted(
        {
            item["ruleId"]
            for item in sarif_results
        }
    )

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
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "decision": (
                                result.policy.decision
                            ),
                            "riskScore": (
                                result.policy.risk_score
                            ),
                            "riskLevel": (
                                result.policy.risk_level
                            ),
                            "profile": (
                                result.policy.profile
                            ),
                            "mode": (
                                result.change_set.mode
                            ),
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
                ],
                "results": sarif_results,
            }
        ],
    }
