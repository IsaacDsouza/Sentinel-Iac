from sentinel.models import Enrichment, Finding, Remediation, Severity


def sarif_result_to_finding(result: dict[str, object]) -> Finding:
    sentinel_id = str(result.get("sentinel_id", ""))
    rule_id = str(result.get("ruleId", "unknown"))
    source = str(result.get("source_engine", "unknown"))
    level = str(result.get("level", "warning"))

    message = result.get("message", {})
    title = str(message.get("text", "")) if isinstance(message, dict) else ""
    raw = str(result.get("raw_description", title))

    locations = result.get("locations", [])
    if isinstance(locations, list) and len(locations) > 0:
        loc = locations[0]
        if isinstance(loc, dict):
            phys = loc.get("physicalLocation", {})
            if isinstance(phys, dict):
                artifact = phys.get("artifactLocation", {})
                region = phys.get("region", {})
            else:
                artifact = {}
                region = {}
        else:
            artifact = {}
            region = {}
    else:
        artifact = {}
        region = {}

    file_path = str(artifact.get("uri", "unknown")) if isinstance(artifact, dict) else "unknown"
    line = int(region.get("startLine", 0)) if isinstance(region, dict) else 0

    resource = str(result.get("resource", "unknown"))

    severity_map = {
        "critical": Severity.critical,
        "high": Severity.high,
        "error": Severity.high,
        "medium": Severity.medium,
        "warning": Severity.medium,
        "low": Severity.low,
        "info": Severity.info,
        "note": Severity.info,
    }
    severity = severity_map.get(level, Severity.medium)

    enrichment_raw = result.get("enrichment")
    enrichment: Enrichment | None = None
    if isinstance(enrichment_raw, dict):
        enrichment = Enrichment(**enrichment_raw)
    elif isinstance(enrichment_raw, Enrichment):
        enrichment = enrichment_raw

    remediation_raw = result.get("remediation")
    remediation: Remediation | None = None
    if isinstance(remediation_raw, dict):
        remediation = Remediation(**remediation_raw)

    return Finding(
        id=sentinel_id,
        rule_id=rule_id,
        engine=source,
        severity=severity,
        resource=resource,
        file_path=file_path,
        line=line,
        title=title,
        raw_description=raw,
        enrichment=enrichment,
        remediation=remediation,
    )


def finding_to_enriched_sarif(finding: Finding) -> dict[str, object]:
    result: dict[str, object] = {
        "sentinel_id": finding.id,
        "ruleId": finding.rule_id,
        "source_engine": finding.engine,
        "level": finding.severity.value,
        "resource": finding.resource,
        "message": {"text": finding.title},
        "raw_description": finding.raw_description,
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": {"startLine": finding.line},
                }
            }
        ],
    }

    if finding.enrichment:
        result["enrichment"] = {
            "explanation": finding.enrichment.explanation,
            "compliance_controls": [
                {
                    "control_id": c.control_id,
                    "framework": c.framework,
                    "relevance_score": c.relevance_score,
                    "citation": c.citation,
                }
                for c in finding.enrichment.compliance_controls
            ],
            "priority_score": finding.enrichment.priority_score,
            "priority_rationale": finding.enrichment.priority_rationale,
        }

    if finding.remediation:
        result["remediation"] = {
            "patch_diff": finding.remediation.patch_diff,
            "validated": finding.remediation.validated,
            "validation_log": finding.remediation.validation_log,
        }

    return result
