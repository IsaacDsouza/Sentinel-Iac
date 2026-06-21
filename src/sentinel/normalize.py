import hashlib
from pathlib import Path

from sentinel.scanners import ScanResult
from sentinel.scanners.equivalences import find_equivalent


def compute_finding_id(rule_id: str, file_path: str, line: int, resource: str) -> str:
    raw = f"{rule_id}|{file_path}|{line}|{resource}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def extract_findings(scan_result: ScanResult) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    sarif = scan_result.sarif_document
    runs = sarif.get("runs", [])
    if not isinstance(runs, list):
        return findings

    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results", [])
        if not isinstance(results, list):
            continue
        findings.extend(results)
    return findings


def normalize(scan_results: list[ScanResult]) -> dict[str, object]:
    all_findings: list[dict[str, object]] = []
    seen_ids: set[str] = set()

    for result in scan_results:
        findings = extract_findings(result)
        for finding in findings:
            rule_id = str(finding.get("ruleId", "unknown"))
            locations = finding.get("locations", [])
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

            file_path = (
                str(artifact.get("uri", "unknown")) if isinstance(artifact, dict) else "unknown"
            )
            line = int(region.get("startLine", 0)) if isinstance(region, dict) else 0

            logical = finding.get("logicalLocations")
            if isinstance(logical, list) and len(logical) > 0:
                resource = str(logical[0].get("fullyQualifiedName", ""))
            else:
                resource = str(finding.get("resource", ""))

            finding_id = compute_finding_id(rule_id, file_path, line, resource)

            if finding_id in seen_ids:
                continue

            equivalents = find_equivalent(rule_id)
            is_duplicate = False
            for eq in equivalents:
                eq_id = compute_finding_id(eq, file_path, line, resource)
                if eq_id in seen_ids:
                    is_duplicate = True
                    break

            if is_duplicate:
                continue

            seen_ids.add(finding_id)
            finding["sentinel_id"] = finding_id
            finding["source_engine"] = result.engine
            all_findings.append(finding)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "sentinel-iac", "version": "0.1.0"}},
                "results": all_findings,
                "artifacts": [
                    {"location": {"uri": str(p)}} for p in _get_target_files(scan_results)
                ],
            }
        ],
    }


def _get_target_files(scan_results: list[ScanResult]) -> set[Path]:
    files: set[Path] = set()
    for result in scan_results:
        for finding in extract_findings(result):
            locations = finding.get("locations", [])
            if isinstance(locations, list) and len(locations) > 0:
                loc = locations[0]
                if isinstance(loc, dict):
                    phys = loc.get("physicalLocation", {})
                    if isinstance(phys, dict):
                        artifact = phys.get("artifactLocation", {})
                        if isinstance(artifact, dict):
                            uri = artifact.get("uri", "")
                            if uri:
                                files.add(Path(str(uri)))
    return files
