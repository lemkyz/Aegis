import json
from typing import Any

from aegis.config.settings import Settings, get_settings
from aegis.models.openai_compatible import (
    OpenAICompatibleTransport,
)
from aegis.models.provider_config import (
    resolve_model_endpoint,
)
from aegis.models.request_policy import (
    resolve_model_request_config,
)
from aegis.utils.text import strip_markdown_code_fence
from aegis.schemas.analysis import ScannerEvidence, SecurityFinding


class OpenAICompatibleSecurityModelClient:
    def __init__(
        self,
        settings: Settings | None = None,
    ) -> None:
        resolved_settings = settings or get_settings()
        endpoint = resolve_model_endpoint(
            resolved_settings,
            role="primary",
        )
        request_config = resolve_model_request_config(
            resolved_settings,
            role="primary",
        )

        self.provider = endpoint.provider
        self.model = endpoint.model
        self.request_config = request_config
        self.transport = OpenAICompatibleTransport(
            api_key=endpoint.api_key,
            base_url=endpoint.base_url,
            timeout_seconds=(
                request_config.timeout_seconds
            ),
            max_retries=request_config.max_retries,
        )

        # Backward-compatible access for existing integrations and
        # tests that inspect the underlying OpenAI-compatible client.
        self.client = self.transport.client

    async def analyze_security(
        self,
        *,
        code: str,
        language: str,
        filename: str,
        scanner_evidence: list[ScannerEvidence],
    ) -> list[SecurityFinding]:
        system_prompt = """
You are Aegis Security Reviewer.

Analyze source code defensively using both the source code and
deterministic scanner evidence.

Rules:
- Do not invent vulnerabilities.
- Scanner results are evidence, not absolute truth.
- Identify false positives where appropriate.
- Tie conclusions to exact code behavior.
- Return only valid JSON.
- Do not use Markdown code fences.
- Do not provide instructions for attacking unauthorized systems.
- Preserve relevant scanner evidence in each final finding.

Return exactly this JSON structure:

{
  "findings": [
    {
      "title": "string",
      "severity": "info | low | medium | high | critical",
      "confidence": 0.0,
      "summary": "string",
      "evidence": ["string"],
      "scanner_evidence": [
        {
          "tool": "string",
          "rule_id": "string",
          "message": "string",
          "severity": "string",
          "file": "string",
          "line_start": 1,
          "line_end": 1,
          "code": "string or null"
        }
      ],
      "cwe": ["CWE-123"],
      "owasp": ["A01:2021"],
      "vulnerable_lines": [1],
      "false_positive_notes": ["string"],
      "recommended_fix": "string",
      "proposed_patch": "string or null"
    }
  ]
}

If no meaningful vulnerability exists, return:

{"findings": []}
""".strip()

        scanner_json = json.dumps(
            [item.model_dump() for item in scanner_evidence],
            ensure_ascii=False,
            indent=2,
        )

        user_prompt = f"""
Filename: {filename}
Language: {language}

Deterministic scanner evidence:

{scanner_json}

Important secret-handling rules:

- Values such as <AEGIS_REDACTED_SECRET_1> are protected placeholders.
- Never attempt to reconstruct, guess, repeat, or transform their original values.
- Do not preserve a redacted placeholder inside proposed_patch.
- When remediating a hardcoded secret, replace it with an environment variable,
  secret-manager lookup, or another secure runtime configuration mechanism.
- Do not include credentials, tokens, private keys, or authorization values
  in summaries, evidence, recommendations, or patches.

Analyze the following source code and determine whether each
scanner result represents a genuine vulnerability.

--- BEGIN SOURCE CODE ---
{code}
--- END SOURCE CODE ---
""".strip()

        response = await self.transport.create_chat_completion(
            model=self.model,
            temperature=0.1,
            max_tokens=self.request_config.max_tokens,
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
            raise RuntimeError("The model returned an empty response.")

        try:
            parsed: dict[str, Any] = json.loads(content)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"The model returned invalid JSON: {content[:500]}"
            ) from exc

        raw_findings = parsed.get("findings", [])

        validated_findings: list[SecurityFinding] = []

        for finding in raw_findings:
            validated = SecurityFinding.model_validate(finding)

            validated.proposed_patch = strip_markdown_code_fence(
                validated.proposed_patch
            )

            validated_findings.append(validated)

        return validated_findings