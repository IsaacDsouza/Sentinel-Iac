import json

import structlog
from pydantic import BaseModel, ValidationError

from sentinel.enrich.llm import call_llm, wrap_iac_content
from sentinel.models import Finding

logger = structlog.get_logger(__name__)


class PrioritizeResult(BaseModel):
    priority_score: int
    rationale: str


async def prioritize_finding(finding: Finding, iac_context: str) -> tuple[int, str]:
    prompt = _build_prioritize_prompt(finding, iac_context)
    response = call_llm(prompt, max_tokens=2048)

    if not response:
        return 50, "Default priority (LLM call failed)"

    import re

    # Try to extract JSON block and sanitize unescaped newlines
    match = re.search(r"\{.*\}", response, re.DOTALL)
    raw = match.group() if match else response
    sanitized = raw.replace("\n", " ").replace("\r", "")

    try:
        parsed = json.loads(sanitized)
        result = PrioritizeResult(**parsed)
        score = max(0, min(100, result.priority_score))
        return score, result.rationale
    except (json.JSONDecodeError, ValidationError):
        # Fallback: try to extract score and rationale from free text
        score_match = re.search(
            r"(?:priority[ _]?score|score)\s*[:\-]?\s*(\d{1,3})", response, re.IGNORECASE
        )
        score = max(0, min(100, int(score_match.group(1)))) if score_match else 50
        rationale = "Auto-extracted"
        logger.error("prioritize_parse_failed", error="fallback_used", response=response[:200])
        return score, rationale


def _build_prioritize_prompt(finding: Finding, iac_context: str) -> str:
    from sentinel.enrich.llm import PRIORITIZE_PROMPT

    return PRIORITIZE_PROMPT.format(
        rule_id=finding.rule_id,
        severity=finding.severity.value
        if hasattr(finding.severity, "value")
        else str(finding.severity),
        title=finding.title,
        description=finding.raw_description,
        resource=finding.resource,
        iac_context=wrap_iac_content(iac_context),
    )
