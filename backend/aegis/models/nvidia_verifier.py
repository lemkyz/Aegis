import json
from typing import Any

from openai import AsyncOpenAI

from aegis.config.settings import get_settings
from aegis.schemas.analysis import (
    ScannerEvidence,
    SecurityFinding,
)
from aegis.schemas.model_verification import (
    FindingVerification,
    VerifierReviewResult,
)


class NvidiaVerifierClient:
    def __init__(self) -> None:
        settings = get_settings()

        self.model = (
            settings.nvidia_verifier_model
            or settings.nvidia_model
        )
        self.client = AsyncOpenAI(
            api_key=settings.nvidia_api_key,
            base_url=settings.nvidia_base_url,
            timeout=settings.ai_request_timeout_seconds,
            max_retries=settings.ai_max_retries,
        )

    async def verify_findings(
        self,
        *,
        code: str,
        language: str,
        filename: str,
        scanner_evidence: list[ScannerEvidence],
        primary_findings: list[SecurityFinding],
    ) -> VerifierReviewResult:
        system_prompt = """
You are Aegis Independent Security Verifier.

Review primary-model security findings independently against
the source code and deterministic scanner evidence.

Rules:
- Do not assume the primary model is correct.
- Do not rewrite or improve the primary answer.
- Verify each finding separately.
- Use "supported" only when evidence establishes the issue.
- Use "refuted" when the finding is contradicted by code behavior.
- Use "uncertain" when evidence is insufficient.
- Do not invent vulnerabilities.
- Return only valid JSON.
- Do not use Markdown code fences.
- Do not provide offensive instructions.

Return exactly this JSON structure:

{
  "verifications": [
    {
      "finding_index": 0,
      "verdict": "supported | refuted | uncertain",
      "confidence": 0.0,
      "reasoning": "string",
      "evidence": ["string"]
    }
  ]
}
""".strip()

        scanner_json = json.dumps(
            [
                item.model_dump()
                for item in scanner_evidence
            ],
            ensure_ascii=False,
            indent=2,
        )

        findings_json = json.dumps(
            [
                item.model_dump()
                for item in primary_findings
            ],
            ensure_ascii=False,
            indent=2,
        )

        user_prompt = f"""
Filename: {filename}
Language: {language}

Deterministic scanner evidence:

{scanner_json}

Primary-model findings:

{findings_json}

Source code:

--- BEGIN SOURCE CODE ---
{code}
--- END SOURCE CODE ---
""".strip()

        response = await self.client.chat.completions.create(
            model=self.model,
            temperature=0.0,
            max_tokens=1200,
            messages=[
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
        )

        content = response.choices[0].message.content

        if not content:
            raise RuntimeError(
                "The verifier model returned an empty response."
            )

        try:
            parsed: dict[str, Any] = json.loads(content)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "The verifier model returned invalid JSON: "
                f"{content[:500]}"
            ) from exc

        raw_verifications = parsed.get(
            "verifications",
            [],
        )

        verifications = [
            FindingVerification.model_validate(item)
            for item in raw_verifications
        ]

        return VerifierReviewResult(
            model=self.model,
            status="completed",
            verifications=verifications,
        )
