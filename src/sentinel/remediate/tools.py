import json
import tempfile
from pathlib import Path

from sentinel.models import Finding
from sentinel.scanners import SCANNERS, ScanResult


def tool_read_file(target_path: Path, file_path: str) -> str:
    full_path = target_path / file_path
    if not full_path.exists():
        return f"Error: file {file_path} not found"
    try:
        return full_path.read_text()
    except Exception as e:
        return f"Error reading file: {e}"


def tool_get_finding_context(finding: Finding) -> str:
    return json.dumps(
        {
            "id": finding.id,
            "rule_id": finding.rule_id,
            "engine": finding.engine,
            "severity": finding.severity.value
            if hasattr(finding.severity, "value")
            else str(finding.severity),
            "resource": finding.resource,
            "file_path": finding.file_path,
            "line": finding.line,
            "title": finding.title,
            "description": finding.raw_description,
        },
        indent=2,
    )


class PatchValidator:
    def __init__(self, target_path: Path, finding_rule_id: str) -> None:
        self.target_path = target_path
        self.finding_rule_id = finding_rule_id

    def validate(self, patched_content: str, file_path: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            target_file = tmp / file_path
            target_file.parent.mkdir(parents=True, exist_ok=True)
            target_file.write_text(patched_content)

            results = self._run_scanners_on(tmp)
            still_present = self._rule_still_present(results)

            if not still_present:
                return {
                    "valid": True,
                    "message": "Patch resolved the finding and config is valid",
                }

            msg = f"Patch did not resolve rule {self.finding_rule_id}"
            return {
                "valid": False,
                "message": msg,
                "remaining_findings": results,
            }

    def _rule_still_present(self, results: list[dict[str, object]]) -> bool:
        for r in results:
            raw_id = r.get("ruleId", "")
            if (
                isinstance(raw_id, str) and raw_id
                and (raw_id == self.finding_rule_id or self.finding_rule_id in raw_id)
            ):
                return True
            props = r.get("properties", {})
            if isinstance(props, dict):
                for key in ("id", "rule", "check_name", "policy"):
                    val = props.get(key, "")
                    if isinstance(val, str) and self.finding_rule_id in val:
                        return True
        return False

    def _run_scanners_on(self, path: Path) -> list[dict[str, object]]:
        all_results: list[dict[str, object]] = []
        for scanner_cls in SCANNERS:
            scanner = scanner_cls()
            if not scanner.is_available():
                continue
            try:
                scan_result = scanner.scan(path)
                findings = self._extract_results(scan_result)
                all_results.extend(findings)
            except Exception:
                continue
        return all_results

    def _extract_results(self, scan_result: ScanResult) -> list[dict[str, object]]:
        findings: list[dict[str, object]] = []
        sarif = scan_result.sarif_document
        runs = sarif.get("runs", [])
        if not isinstance(runs, list):
            return findings
        for run in runs:
            if not isinstance(run, dict):
                continue
            results = run.get("results", [])
            if isinstance(results, list):
                findings.extend(results)
        return findings
