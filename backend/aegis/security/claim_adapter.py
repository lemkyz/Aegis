import hashlib
import os
import re

from aegis.schemas.analysis import (
    ScannerEvidence,
    SecurityFinding,
)
from aegis.schemas.claims import (
    CodeLocation,
    EvidenceItem,
    EvidenceSource,
    SecurityClaim,
)


def finding_to_claim(
    finding: SecurityFinding,
    *,
    filename: str,
    include_narrative_evidence: bool = True,
) -> SecurityClaim:
    normalized_filename = _normalize_path(filename)
    category = _claim_category(finding)

    locations = _claim_locations(
        finding,
        filename=normalized_filename,
    )

    evidence_items = _evidence_items(
        finding,
        filename=normalized_filename,
        include_narrative_evidence=(
            include_narrative_evidence
        ),
    )

    identity_anchor = _claim_identity_anchor(
        finding,
        filename=normalized_filename,
        category=category,
    )

    claim_id = _stable_id(
        "claim",
        "identity-v2",
        normalized_filename,
        category,
        identity_anchor,
    )

    claim_state, claim_confidence = (
        _claim_state_and_confidence(finding)
    )

    return SecurityClaim(
        claim_id=claim_id,
        statement=finding.summary,
        category=category,
        severity=finding.severity,
        confidence=claim_confidence,
        state=claim_state,
        cwe=finding.cwe,
        owasp=finding.owasp,
        locations=locations,
        evidence=evidence_items,
        remediation=finding.recommended_fix,
        proposed_patch=finding.proposed_patch,
    )


def _claim_state_and_confidence(
    finding: SecurityFinding,
) -> tuple[str, float]:
    baseline_state = (
        "supported"
        if finding.scanner_evidence
        else "suspected"
    )
    primary_confidence = finding.confidence

    if (
        finding.consensus_verdict == "confirmed"
        and finding.consensus_confidence is not None
    ):
        return (
            "confirmed",
            finding.consensus_confidence,
        )

    if finding.consensus_verdict == "disputed":
        verifier_confidence = (
            finding.verifier_confidence
            if finding.verifier_confidence is not None
            else 0.0
        )

        claim_confidence = min(
            primary_confidence,
            max(
                0.0,
                1.0 - verifier_confidence,
            ),
        )

        return (
            "inconclusive",
            claim_confidence,
        )

    if (
        finding.consensus_verdict == "uncertain"
        and finding.consensus_confidence is not None
    ):
        return (
            "inconclusive",
            min(
                primary_confidence,
                finding.consensus_confidence,
            ),
        )

    return (
        baseline_state,
        primary_confidence,
    )


def _evidence_items(
    finding: SecurityFinding,
    *,
    filename: str,
    include_narrative_evidence: bool,
) -> list[EvidenceItem]:
    result: list[EvidenceItem] = []

    scanner_items = sorted(
        finding.scanner_evidence,
        key=lambda evidence: (
            evidence.tool.lower(),
            evidence.rule_id.lower(),
            _normalize_path(evidence.file or filename),
            evidence.line_start,
            evidence.line_end,
            evidence.message,
            evidence.code or "",
        ),
    )

    for evidence in scanner_items:
        location = CodeLocation(
            file=_normalize_path(
                evidence.file or filename,
            ),
            line_start=evidence.line_start,
            line_end=evidence.line_end,
        )

        details: list[str] = []

        if evidence.code:
            details.append(evidence.code)

        if evidence.corroborated_by:
            details.append(
                "Corroborated by: "
                + ", ".join(evidence.corroborated_by)
            )

        if evidence.related_rule_ids:
            details.append(
                "Related rules: "
                + ", ".join(evidence.related_rule_ids)
            )

        result.append(
            EvidenceItem(
                evidence_id=_stable_id(
                    "evidence",
                    "identity-v2",
                    "scanner",
                    _normalize_path(
                        evidence.file or filename
                    ),
                    evidence.tool.lower().strip(),
                    evidence.rule_id.lower().strip(),
                    _location_region(
                        evidence.line_start,
                        evidence.line_end,
                    ),
                    _normalize_code_identity(
                        evidence.code or ""
                    ),
                ),
                source=EvidenceSource(
                    kind="scanner",
                    name=evidence.tool,
                    rule_id=evidence.rule_id,
                ),
                summary=evidence.message,
                confidence=finding.confidence,
                locations=[location],
                details=details,
            )
        )

    if include_narrative_evidence:
        for narrative_index, narrative in enumerate(
            finding.evidence,
        ):
            result.append(
                EvidenceItem(
                    evidence_id=_stable_id(
                        "evidence",
                        "model_review",
                        filename,
                        narrative,
                        str(narrative_index),
                    ),
                    source=EvidenceSource(
                        kind="model_review",
                        name=(
                            finding.primary_model
                            or "Aegis Analysis"
                        ),
                    ),
                    summary=narrative,
                    confidence=finding.confidence,
                    locations=[],
                )
            )

    if (
        include_narrative_evidence
        and finding.verifier_verdict is not None
        and finding.verifier_confidence is not None
    ):
        verifier_details = [
            "Role: verifier",
            f"Verdict: {finding.verifier_verdict}",
        ]

        if finding.verifier_reasoning:
            verifier_details.append(
                "Reasoning: "
                + finding.verifier_reasoning
            )

        verifier_details.extend(
            "Evidence: " + item
            for item in finding.verifier_evidence
        )

        result.append(
            EvidenceItem(
                evidence_id=_stable_id(
                    "evidence",
                    "model_verification",
                    filename,
                    finding.verifier_model or "unknown",
                    finding.verifier_verdict,
                    finding.verifier_reasoning or "",
                ),
                source=EvidenceSource(
                    kind="model_verification",
                    name=(
                        finding.verifier_model
                        or "Aegis Verifier"
                    ),
                ),
                summary=(
                    "Independent verifier marked the "
                    "primary finding as "
                    f"{finding.verifier_verdict}."
                ),
                confidence=finding.verifier_confidence,
                locations=[],
                details=verifier_details,
            )
        )

    if (
        include_narrative_evidence
        and finding.consensus_verdict is not None
        and finding.consensus_confidence is not None
    ):
        consensus_details = [
            "Evaluator: deterministic consensus",
            (
                "Primary model: "
                + (
                    finding.primary_model
                    or "unknown"
                )
            ),
            (
                "Verifier model: "
                + (
                    finding.verifier_model
                    or "unavailable"
                )
            ),
            (
                "Verdict: "
                + finding.consensus_verdict
            ),
        ]

        consensus_details.extend(
            "Reason: " + reason
            for reason in finding.consensus_reasons
        )

        result.append(
            EvidenceItem(
                evidence_id=_stable_id(
                    "evidence",
                    "model_consensus",
                    filename,
                    finding.primary_model or "unknown",
                    finding.verifier_model or "unavailable",
                    finding.consensus_verdict,
                ),
                source=EvidenceSource(
                    kind="model_consensus",
                    name="Aegis Deterministic Consensus",
                ),
                summary=(
                    "Deterministic consensus classified "
                    "the finding as "
                    f"{finding.consensus_verdict}."
                ),
                confidence=finding.consensus_confidence,
                locations=[],
                details=consensus_details,
            )
        )

    return result


def _claim_locations(
    finding: SecurityFinding,
    *,
    filename: str,
) -> list[CodeLocation]:
    unique_locations: dict[
        tuple[str, int, int],
        CodeLocation,
    ] = {}

    for evidence in finding.scanner_evidence:
        location = CodeLocation(
            file=_normalize_path(
                evidence.file or filename,
            ),
            line_start=evidence.line_start,
            line_end=evidence.line_end,
        )

        identity = (
            location.file,
            location.line_start,
            location.line_end,
        )
        unique_locations[identity] = location

    if (
        not unique_locations
        and finding.vulnerable_lines
    ):
        location = CodeLocation(
            file=filename,
            line_start=min(finding.vulnerable_lines),
            line_end=max(finding.vulnerable_lines),
        )

        identity = (
            location.file,
            location.line_start,
            location.line_end,
        )
        unique_locations[identity] = location

    return list(unique_locations.values())


def _claim_category(
    finding: SecurityFinding,
) -> str:
    known_categories = {
        "command-injection",
        "sql-injection",
        "path-traversal",
        "unsafe-deserialization",
        "hardcoded-secret",
        "insecure-randomness",
        "missing-authorization",
        "xss",
    }

    derived_categories = sorted(
        {
            category
            for evidence in finding.scanner_evidence
            if (
                category := _category_from_rule_id(
                    evidence.rule_id,
                )
            )
        }
    )

    for category in derived_categories:
        if category in known_categories:
            return category

    if finding.cwe:
        return _slug(finding.cwe[0])

    if derived_categories:
        return derived_categories[0]

    return _slug(finding.title)


def _category_from_rule_id(
    rule_id: str,
) -> str:
    normalized = rule_id.lower()

    known_categories = (
        "command-injection",
        "sql-injection",
        "path-traversal",
        "unsafe-deserialization",
        "hardcoded-secret",
        "insecure-randomness",
        "missing-authorization",
        "xss",
    )

    for category in known_categories:
        if category in normalized:
            return category

    parts = [
        part
        for part in re.split(
            r"[.:/_]+",
            normalized,
        )
        if part
    ]

    for part in reversed(parts):
        if not re.fullmatch(
            r"b\d+",
            part,
        ):
            return _slug(part)

    return ""


def _normalize_path(
    value: str,
) -> str:
    normalized = os.path.normpath(value)

    if normalized == ".":
        return value

    return normalized.replace("\\", "/")


def _slug(
    value: str,
) -> str:
    normalized = re.sub(
        r"[^a-z0-9]+",
        "-",
        value.lower(),
    )

    return normalized.strip("-") or "security"


def _claim_identity_anchor(
    finding: SecurityFinding,
    *,
    filename: str,
    category: str,
) -> str:
    """
    Stable Identity v2 anchor.

    Narrative fields, scanner messages, confidence values, and
    corroborating scanner additions are intentionally excluded.
    """

    primary = _primary_scanner_evidence(finding)

    if primary is not None:
        evidence_file = _normalize_path(
            primary.file or filename
        )

        code_identity = _normalize_code_identity(
            primary.code or ""
        )

        if not code_identity:
            code_identity = (
                primary.rule_id.lower().strip()
            )

        region = _location_region(
            primary.line_start,
            primary.line_end,
        )

        return "\x1f".join(
            (
                evidence_file,
                category,
                region,
                code_identity,
            )
        )

    if finding.vulnerable_lines:
        line_start = min(finding.vulnerable_lines)
        line_end = max(finding.vulnerable_lines)

        region = _location_region(
            line_start,
            line_end,
        )
    else:
        region = "unknown-region"

    return "\x1f".join(
        (
            filename,
            category,
            region,
            "no-scanner-code",
        )
    )


def _primary_scanner_evidence(
    finding: SecurityFinding,
) -> ScannerEvidence | None:
    if not finding.scanner_evidence:
        return None

    return min(
        finding.scanner_evidence,
        key=lambda evidence: (
            0
            if evidence.rule_id.lower().startswith(
                "aegis."
            )
            else 1,
            0
            if _category_from_rule_id(
                evidence.rule_id
            )
            == _claim_category(finding)
            else 1,
            _normalize_path(
                evidence.file
            ),
            evidence.line_start,
            evidence.line_end,
            evidence.rule_id.lower(),
            evidence.tool.lower(),
        ),
    )


def _location_region(
    line_start: int,
    line_end: int,
) -> str:
    """
    Groups small line movements while keeping distant findings
    separate. A ten-line region is intentionally conservative.
    """

    midpoint = (
        line_start + line_end
    ) // 2

    return f"region-{midpoint // 10}"


def _normalize_code_identity(
    value: str,
) -> str:
    """
    Produces a formatting-insensitive sink signature.

    Whitespace is excluded because indentation and line wrapping
    must not create a new security identity.
    """

    return re.sub(
        r"\s+",
        "",
        value.strip(),
    )


def _stable_id(
    prefix: str,
    *parts: str,
) -> str:
    payload = "\x1f".join(parts)
    digest = hashlib.sha256(
        payload.encode("utf-8"),
    ).hexdigest()

    return f"{prefix}:sha256:{digest}"
