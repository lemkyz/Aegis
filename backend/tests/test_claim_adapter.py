from aegis.schemas.analysis import (
    ScannerEvidence,
    SecurityFinding,
)
from aegis.security.claim_adapter import (
    finding_to_claim,
)


def make_scanner_evidence(
    *,
    tool: str = "Semgrep",
    rule_id: str = (
        "aegis.python.command-injection.subprocess-shell"
    ),
    file: str = "app.py",
    line_start: int = 8,
    line_end: int = 12,
) -> ScannerEvidence:
    return ScannerEvidence(
        tool=tool,
        rule_id=rule_id,
        message=(
            "Untrusted input reaches subprocess.run "
            "with shell execution enabled."
        ),
        severity="ERROR",
        file=file,
        line_start=line_start,
        line_end=line_end,
        code="subprocess.run(command, shell=True)",
        cwe=["CWE-78"],
        owasp=["A03:2021"],
    )


def make_finding(
    *,
    scanner_evidence: list[ScannerEvidence] | None = None,
    narrative_evidence: list[str] | None = None,
) -> SecurityFinding:
    scanner_items = (
        scanner_evidence
        if scanner_evidence is not None
        else [make_scanner_evidence()]
    )

    return SecurityFinding(
        title="Command Injection Subprocess Shell",
        severity="high",
        confidence=0.91,
        summary=(
            "Untrusted input may reach a shell command."
        ),
        evidence=(
            narrative_evidence
            if narrative_evidence is not None
            else [
                "The command contains attacker-controlled input.",
            ]
        ),
        scanner_evidence=scanner_items,
        cwe=["CWE-78"],
        owasp=["A03:2021"],
        vulnerable_lines=[8, 9, 10, 11, 12],
        false_positive_notes=[],
        recommended_fix=(
            "Pass arguments as a list and disable shell execution."
        ),
        proposed_patch=(
            'subprocess.run(["printf", "%s", user_input], '
            "shell=False)"
        ),
    )


def test_adapter_creates_canonical_claim() -> None:
    claim = finding_to_claim(
        make_finding(),
        filename="app.py",
    )

    assert claim.claim_id.startswith("claim:sha256:")
    assert claim.statement == (
        "Untrusted input may reach a shell command."
    )
    assert claim.category == "command-injection"
    assert claim.severity == "high"
    assert claim.confidence == 0.91
    assert claim.state == "supported"
    assert claim.cwe == ["CWE-78"]
    assert claim.owasp == ["A03:2021"]
    assert claim.remediation == (
        "Pass arguments as a list and disable shell execution."
    )
    assert claim.proposed_patch is not None


def test_adapter_creates_scanner_and_narrative_evidence() -> None:
    claim = finding_to_claim(
        make_finding(),
        filename="app.py",
    )

    assert len(claim.evidence) == 2

    scanner = claim.evidence[0]
    narrative = claim.evidence[1]

    assert scanner.source.kind == "scanner"
    assert scanner.source.name == "Semgrep"
    assert scanner.source.rule_id == (
        "aegis.python.command-injection.subprocess-shell"
    )
    assert scanner.locations[0].file == "app.py"
    assert scanner.locations[0].line_start == 8
    assert scanner.locations[0].line_end == 12

    assert narrative.source.kind == "model_review"
    assert narrative.summary == (
        "The command contains attacker-controlled input."
    )


def test_adapter_is_deterministic() -> None:
    finding = make_finding()

    first = finding_to_claim(
        finding,
        filename="./src/../app.py",
    )
    second = finding_to_claim(
        finding,
        filename="app.py",
    )

    assert first.claim_id == second.claim_id

    first_evidence_ids = [
        evidence.evidence_id
        for evidence in first.evidence
    ]
    second_evidence_ids = [
        evidence.evidence_id
        for evidence in second.evidence
    ]

    assert first_evidence_ids == second_evidence_ids


def test_adapter_handles_multiple_scanner_items() -> None:
    semgrep = make_scanner_evidence()
    bandit = make_scanner_evidence(
        tool="Bandit",
        rule_id="bandit.python.B602",
    )

    claim = finding_to_claim(
        make_finding(
            scanner_evidence=[semgrep, bandit],
            narrative_evidence=[],
        ),
        filename="app.py",
    )

    assert len(claim.evidence) == 2
    assert {
        evidence.source.name
        for evidence in claim.evidence
    } == {"Semgrep", "Bandit"}

    assert len(claim.locations) == 1


def test_adapter_uses_vulnerable_lines_without_scanner_evidence() -> None:
    finding = make_finding(
        scanner_evidence=[],
        narrative_evidence=["AI identified a risky data flow."],
    )

    claim = finding_to_claim(
        finding,
        filename="app.py",
    )

    assert claim.state == "suspected"
    assert claim.category == "cwe-78"
    assert len(claim.locations) == 1
    assert claim.locations[0].line_start == 8
    assert claim.locations[0].line_end == 12
    assert claim.evidence[0].source.kind == "model_review"


def test_adapter_does_not_duplicate_locations() -> None:
    first = make_scanner_evidence(
        tool="Semgrep",
        rule_id=(
            "aegis.python.command-injection.subprocess-shell"
        ),
    )
    second = make_scanner_evidence(
        tool="Bandit",
        rule_id="bandit.python.B602",
    )

    claim = finding_to_claim(
        make_finding(
            scanner_evidence=[first, second],
            narrative_evidence=[],
        ),
        filename="app.py",
    )

    assert len(claim.locations) == 1


def test_adapter_identity_ignores_scanner_order() -> None:
    semgrep = make_scanner_evidence(
        tool="Semgrep",
        rule_id=(
            "aegis.python.command-injection.subprocess-shell"
        ),
    )
    bandit = make_scanner_evidence(
        tool="Bandit",
        rule_id="bandit.python.B602",
    )

    first = finding_to_claim(
        make_finding(
            scanner_evidence=[semgrep, bandit],
            narrative_evidence=[],
        ),
        filename="app.py",
    )
    second = finding_to_claim(
        make_finding(
            scanner_evidence=[bandit, semgrep],
            narrative_evidence=[],
        ),
        filename="app.py",
    )

    assert first.claim_id == second.claim_id
    assert first.category == second.category

    assert {
        item.evidence_id
        for item in first.evidence
    } == {
        item.evidence_id
        for item in second.evidence
    }


def test_adapter_category_uses_known_rule_family_from_any_scanner() -> None:
    generic = make_scanner_evidence(
        tool="Bandit",
        rule_id="bandit.python.B602",
    )
    specific = make_scanner_evidence(
        tool="Semgrep",
        rule_id=(
            "aegis.python.command-injection.subprocess-shell"
        ),
    )

    claim = finding_to_claim(
        make_finding(
            scanner_evidence=[generic, specific],
            narrative_evidence=[],
        ),
        filename="app.py",
    )

    assert claim.category == "command-injection"


def test_adapter_can_exclude_narrative_evidence() -> None:
    claim = finding_to_claim(
        make_finding(),
        filename="app.py",
        include_narrative_evidence=False,
    )

    assert len(claim.evidence) == 1
    assert claim.evidence[0].source.kind == "scanner"
    assert all(
        evidence.source.kind != "model_review"
        for evidence in claim.evidence
    )
