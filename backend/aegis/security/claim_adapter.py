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

    return SecurityClaim(
        claim_id=claim_id,
        statement=finding.summary,
        category=category,
        severity=finding.severity,
        confidence=finding.confidence,
        state=(
            "supported"
            if finding.scanner_evidence
            else "suspected"
        ),
        cwe=finding.cwe,
        owasp=finding.owasp,
        locations=locations,
        evidence=evidence_items,
        remediation=finding.recommended_fix,
        proposed_patch=finding.proposed_patch,
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
                        name="Aegis Analysis",
                    ),
                    summary=narrative,
                    confidence=finding.confidence,
                    locations=[],
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
