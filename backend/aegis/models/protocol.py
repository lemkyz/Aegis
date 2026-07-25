from typing import Protocol

from aegis.schemas.analysis import (
    ScannerEvidence,
    SecurityFinding,
)
from aegis.schemas.model_verification import (
    VerifierReviewResult,
)


class SecurityModelClient(Protocol):
    model: str

    async def analyze_security(
        self,
        *,
        code: str,
        language: str,
        filename: str,
        scanner_evidence: list[ScannerEvidence],
    ) -> list[SecurityFinding]:
        """Return security findings for the supplied evidence."""
        ...


class SecurityVerifierClient(Protocol):
    model: str

    async def verify_findings(
        self,
        *,
        code: str,
        language: str,
        filename: str,
        scanner_evidence: list[ScannerEvidence],
        primary_findings: list[SecurityFinding],
    ) -> "VerifierReviewResult":
        """Independently verify primary model findings."""
        ...
