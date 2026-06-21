import json

import structlog
from pydantic import BaseModel, ValidationError

from sentinel.enrich.llm import call_llm, wrap_iac_content
from sentinel.models import Finding

logger = structlog.get_logger(__name__)


class ExplanationResult(BaseModel):
    explanation: str
    summary: str


def _build_explain_prompt(finding: Finding, iac_context: str) -> str:
    from sentinel.enrich.llm import EXPLAIN_PROMPT

    return EXPLAIN_PROMPT.format(
        rule_id=finding.rule_id,
        severity=finding.severity.value
        if hasattr(finding.severity, "value")
        else str(finding.severity),
        resource=finding.resource,
        title=finding.title,
        description=finding.raw_description,
        file_path=finding.file_path,
        line=finding.line,
        iac_context=wrap_iac_content(iac_context),
    )


async def explain_finding(finding: Finding, iac_context: str) -> str | None:
    prompt = _build_explain_prompt(finding, iac_context)
    response = call_llm(prompt, max_tokens=2048)

    if not response:
        return None

    import re

    match = re.search(r"\{.*\}", response, re.DOTALL)
    raw = match.group() if match else response
    sanitized = raw.replace("\n", " ").replace("\r", "")

    try:
        parsed = json.loads(sanitized)
        result = ExplanationResult(**parsed)
        return result.explanation
    except (json.JSONDecodeError, ValidationError) as e:
        logger.error("explain_parse_failed", error=str(e), response=response[:200])
        return None
