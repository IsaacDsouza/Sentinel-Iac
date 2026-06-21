import asyncio

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.enrich.batcher import TokenBudgetBatcher
from sentinel.enrich.compliance import map_compliance
from sentinel.enrich.explain import explain_finding
from sentinel.enrich.prioritize import prioritize_finding
from sentinel.models import ComplianceControl, Enrichment, Finding

logger = structlog.get_logger(__name__)


async def run_enrichment(
    findings: list[Finding],
    file_contents: dict[str, str] | None = None,
    db: AsyncSession | None = None,
) -> list[Finding]:
    """Run the full enrichment pipeline on findings.

    Parameters
    ----------
    findings :
        Findings to enrich.
    file_contents :
        Mapping of file paths to their source text for context.
    db :
        Optional async DB session. When provided, RAG compliance retrieval
        fetches relevant NIST 800-53 controls as candidates for
        ``map_compliance``. When ``None`` (CLI mode), compliance mapping
        runs without candidate controls.
    """
    if not findings:
        return findings

    file_contents = file_contents or {}
    batcher = TokenBudgetBatcher()
    batches = batcher.batch(findings)

    enriched: list[Finding] = []

    for batch_num, batch in enumerate(batches, 1):
        logger.info("enriching_batch", batch=batch_num, size=len(batch))

        for finding in batch:
            iac_context = file_contents.get(finding.file_path, "")

            explanation = await explain_finding(finding, iac_context)
            await asyncio.sleep(1)

            candidate_controls: list[ComplianceControl] = []
            if db is not None:
                try:
                    from sentinel.rag.retrieve import retrieve

                    matches = await retrieve(finding.title, db, top_k=5)
                    candidate_controls = [
                        ComplianceControl(
                            control_id=m.control_id,
                            framework=m.framework,
                            relevance_score=m.score,
                            citation=m.text[:200],
                        )
                        for m in matches
                    ]
                except Exception:
                    logger.warning("rag_retrieval_failed", exc_info=True)

            controls = await map_compliance(finding, candidate_controls)
            await asyncio.sleep(1)
            priority_score, priority_rationale = await prioritize_finding(finding, iac_context)

            if explanation or controls or priority_rationale:
                finding.enrichment = Enrichment(
                    explanation=explanation or "No explanation available",
                    compliance_controls=controls,
                    priority_score=priority_score,
                    priority_rationale=priority_rationale,
                )

            enriched.append(finding)

    logger.info("enrichment_complete", total=len(enriched))
    return enriched
