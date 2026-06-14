import json
import logging
import os
from typing import Any, Dict

from pydantic import BaseModel, Field

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover - resolved when requirements are installed
    OpenAI = None  # type: ignore[misc,assignment]


logger = logging.getLogger("aether.remediation_agent")


class RemediationPayload(BaseModel):
    vuln_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    vulnerable_code_analysis: str = Field(min_length=24)
    secure_refactor: str = Field(min_length=24)
    language: str = Field(default="text", min_length=1)
    summary: str = Field(min_length=12)

    def render_provided_solution(self) -> str:
        return (
            "Vulnerable Code Analysis:\n"
            f"{self.vulnerable_code_analysis}\n\n"
            "Secure Refactor:\n"
            f"{self.secure_refactor}"
        )


class RemediationAgent:
    def __init__(self) -> None:
        self.api_key = os.getenv("NVIDIA_API_KEY") or os.getenv("API_KEY")
        self.client = None
        if OpenAI is not None and self.api_key:
            self.client = OpenAI(
                base_url="https://integrate.api.nvidia.com/v1",
                api_key=self.api_key,
            )

    def _fallback_payload(self, finding: Dict[str, Any], evidence_snippet: str) -> RemediationPayload:
        category = str(finding.get("category", "")).lower()
        title = str(finding.get("title", "Generated Remediation"))
        vuln_id = str(finding.get("id", title))
        detail = str(finding.get("detail", "Review the unsafe control path and apply a server-side fix."))
        attack_vector = str(finding.get("attack_vector", "unspecified vector"))
        if "injection" in category or "sql" in title.lower() or "query" in detail.lower():
            return RemediationPayload(
                vuln_id=vuln_id,
                title=title,
                language="python",
                vulnerable_code_analysis=(
                    "The request handler appears to mix user-controlled input into a database query path. "
                    "That pattern allows the input surface to alter SQL structure instead of staying in data position. "
                    f"Evidence from the validation lane: {evidence_snippet or attack_vector}."
                ),
                secure_refactor=(
                    "cursor.execute(\n"
                    '    "SELECT id, email FROM users WHERE email = %s",\n'
                    "    (user_email,),\n"
                    ")\n"
                    "# Validate and normalize user_email before query execution."
                ),
                summary="Replace string-built SQL with a parameterized query and validate the user input before execution.",
            )

        return RemediationPayload(
            vuln_id=vuln_id,
            title=title,
            language="text",
            vulnerable_code_analysis=(
                "The validation lane confirmed a production-relevant control weakness. "
                f"The current flow leaves {attack_vector or 'the affected surface'} without sufficient server-side enforcement. "
                f"Observed evidence: {evidence_snippet or detail}."
            ),
            secure_refactor=(
                "1. Centralize the trust boundary in server-side code.\n"
                "2. Reject unsafe client-controlled assertions.\n"
                "3. Add automated regression coverage for the confirmed exploit path."
            ),
            summary="Apply a server-side control fix and add a regression test for the validated exploit path.",
        )

    def _build_prompt(self, finding: Dict[str, Any], evidence_snippet: str) -> str:
        return f"""
You are AETHER's remediation specialist. Generate a production-ready security patch package.

Finding JSON:
{json.dumps(finding)}

Evidence snippet:
{evidence_snippet}

Return raw JSON only in this exact shape:
{{
  "vuln_id": "...",
  "title": "...",
  "vulnerable_code_analysis": "...",
  "secure_refactor": "...",
  "language": "...",
  "summary": "..."
}}

Rules:
- Explain the root cause in `vulnerable_code_analysis`.
- Put a production-ready patch in `secure_refactor`.
- If the issue resembles SQL injection, the refactor must use parameterized queries.
- Keep the explanation concrete and implementation-facing.
- Do not mention prompts, schemas, or that you are an AI system.
""".strip()

    def generate(self, finding: Dict[str, Any], evidence_snippet: str) -> RemediationPayload:
        fallback = self._fallback_payload(finding, evidence_snippet)
        if self.client is None:
            logger.info("Lambo-dark remediation fallback engaged for %s", finding.get("id"))
            return fallback

        try:
            response = self.client.chat.completions.create(
                model="nvidia/llama-3.3-nemotron-super-49b-v1.5",
                messages=[
                    {
                        "role": "user",
                        "content": self._build_prompt(finding, evidence_snippet),
                    }
                ],
                temperature=0.2,
            )
            content = response.choices[0].message.content if response.choices else ""
            cleaned = str(content or "").strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.strip("`")
                cleaned = cleaned.removeprefix("json").strip()
            parsed = json.loads(cleaned)
            payload = RemediationPayload.model_validate(parsed)
            if "injection" in str(finding.get("category", "")).lower() and "%s" not in payload.secure_refactor:
                logger.warning("Nemotron remediation skipped because the SQLi patch was not parameterized for %s", finding.get("id"))
                return fallback
            return payload
        except Exception as error:
            logger.warning("Lambo-dark remediation fallback engaged after Nemotron failure for %s: %s", finding.get("id"), error)
            return fallback
