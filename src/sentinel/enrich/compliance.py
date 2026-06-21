import json

import structlog
from pydantic import BaseModel, ValidationError

from sentinel.enrich.llm import call_llm
from sentinel.models import ComplianceControl, Finding

logger = structlog.get_logger(__name__)


class MappedControl(BaseModel):
    control_id: str
    relevance_score: float
    citation: str


class ComplianceResult(BaseModel):
    mapped_controls: list[MappedControl]


async def map_compliance(
    finding: Finding,
    candidate_controls: list[ComplianceControl],
) -> list[ComplianceControl]:
    candidates_text = "\n".join(
        f"- {c.control_id} ({c.framework}): {c.citation}" for c in candidate_controls
    )

    prompt = _build_compliance_prompt(finding, candidates_text)
    response = call_llm(prompt, max_tokens=8192)

    if not response:
        return []
    import re

    match = re.search(r"\{.*\}", response, re.DOTALL)
    raw_obj = match.group() if match else response
    sanitized = raw_obj.replace("\n", " ").replace("\r", "")

    try:
        parsed = json.loads(sanitized)
        result = ComplianceResult(**parsed)

        return [
            ComplianceControl(
                control_id=m.control_id,
                framework=candidate_controls[0].framework
                if candidate_controls
                else "NIST SP 800-53",
                relevance_score=m.relevance_score,
                citation=m.citation,
            )
            for m in result.mapped_controls
        ]
    except (json.JSONDecodeError, ValidationError) as e:
        logger.error("compliance_parse_failed", error=str(e), response=response[:200])
        return []


def _build_compliance_prompt(finding: Finding, candidates_text: str) -> str:
    from sentinel.enrich.llm import COMPLIANCE_PROMPT

    return COMPLIANCE_PROMPT.format(
        title=finding.title,
        description=finding.raw_description,
        candidate_controls=candidates_text,
    )
