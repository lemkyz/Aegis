import pytest

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


def test_adapter_creates_separate_model_audit_evidence() -> None:
    finding = make_finding()

    finding.primary_model = "fake/primary"
    finding.verifier_model = "fake/verifier"
    finding.verifier_verdict = "supported"
    finding.verifier_confidence = 0.94
    finding.verifier_reasoning = (
        "The source confirms the unsafe shell flow."
    )
    finding.verifier_evidence = [
        "subprocess.run(command, shell=True)",
    ]
    finding.consensus_verdict = "confirmed"
    finding.consensus_confidence = 0.925
    finding.consensus_reasons = [
        "The independent verifier supports the finding.",
    ]

    claim = finding_to_claim(
        finding,
        filename="app.py",
    )

    evidence_by_kind = {
        item.source.kind: item
        for item in claim.evidence
    }

    assert set(evidence_by_kind) == {
        "scanner",
        "model_review",
        "model_verification",
        "model_consensus",
    }

    primary = evidence_by_kind["model_review"]
    verifier = evidence_by_kind["model_verification"]
    consensus = evidence_by_kind["model_consensus"]

    assert primary.source.name == "fake/primary"

    assert verifier.source.name == "fake/verifier"
    assert verifier.confidence == 0.94
    assert "Verdict: supported" in verifier.details
    assert any(
        detail.startswith("Reasoning:")
        for detail in verifier.details
    )

    assert consensus.source.name == (
        "Aegis Deterministic Consensus"
    )
    assert consensus.confidence == 0.925
    assert "Primary model: fake/primary" in (
        consensus.details
    )
    assert "Verifier model: fake/verifier" in (
        consensus.details
    )
    assert "Verdict: confirmed" in consensus.details


def test_model_audit_metadata_does_not_change_claim_identity() -> None:
    baseline = make_finding()
    audited = make_finding()

    audited.primary_model = "fake/primary"
    audited.verifier_model = "fake/verifier"
    audited.verifier_verdict = "supported"
    audited.verifier_confidence = 0.94
    audited.verifier_reasoning = "Supported."
    audited.consensus_verdict = "confirmed"
    audited.consensus_confidence = 0.925
    audited.consensus_reasons = [
        "Independent support.",
    ]

    baseline_claim = finding_to_claim(
        baseline,
        filename="app.py",
    )
    audited_claim = finding_to_claim(
        audited,
        filename="app.py",
    )

    assert baseline_claim.claim_id == audited_claim.claim_id


def test_scanner_only_claim_has_no_model_audit_evidence() -> None:
    finding = make_finding(
        narrative_evidence=[],
    )

    claim = finding_to_claim(
        finding,
        filename="app.py",
        include_narrative_evidence=False,
    )

    assert {
        item.source.kind
        for item in claim.evidence
    } == {"scanner"}


def test_confirmed_consensus_confirms_claim() -> None:
    finding = make_finding()
    finding.consensus_verdict = "confirmed"
    finding.consensus_confidence = 0.93

    claim = finding_to_claim(
        finding,
        filename="app.py",
    )

    assert claim.state == "confirmed"
    assert claim.confidence == 0.93


def test_disputed_consensus_marks_claim_inconclusive() -> None:
    finding = make_finding()
    finding.consensus_verdict = "disputed"
    finding.consensus_confidence = 0.95
    finding.verifier_confidence = 0.95

    claim = finding_to_claim(
        finding,
        filename="app.py",
    )

    assert claim.state == "inconclusive"
    assert claim.confidence == pytest.approx(
        0.05
    )


def test_uncertain_consensus_marks_claim_inconclusive() -> None:
    finding = make_finding()
    finding.consensus_verdict = "uncertain"
    finding.consensus_confidence = 0.61

    claim = finding_to_claim(
        finding,
        filename="app.py",
    )

    assert claim.state == "inconclusive"
    assert claim.confidence == 0.61


def test_unverified_consensus_preserves_scanner_support() -> None:
    finding = make_finding()
    finding.consensus_verdict = "unverified"
    finding.consensus_confidence = 0.70

    claim = finding_to_claim(
        finding,
        filename="app.py",
    )

    assert claim.state == "supported"
    assert claim.confidence == 0.91


def test_unverified_model_only_claim_remains_suspected() -> None:
    finding = make_finding(
        scanner_evidence=[],
    )
    finding.consensus_verdict = "unverified"
    finding.consensus_confidence = 0.70

    claim = finding_to_claim(
        finding,
        filename="app.py",
    )

    assert claim.state == "suspected"
    assert claim.confidence == 0.91


def test_disputed_claim_is_not_automatically_false_positive() -> None:
    finding = make_finding()
    finding.consensus_verdict = "disputed"
    finding.verifier_confidence = 0.99

    claim = finding_to_claim(
        finding,
        filename="app.py",
    )

    assert claim.state == "inconclusive"
    assert claim.state != "false_positive"
