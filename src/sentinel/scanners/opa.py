import json
from pathlib import Path

from sentinel.scanners.base import Scanner, ScanResult
from sentinel.scanners.docker_runner import best_effort_run

IMAGE = "openpolicyagent/conftest:latest"


class OpaScanner(Scanner):
    engine = "opa-conftest"

    def is_available(self) -> bool:
        return True

    def scan(self, target_path: Path) -> ScanResult:
        result = best_effort_run(
            image=IMAGE,
            command=["test", "--output", "json", "--all-namespaces", "{SCAN_DIR}"],
            binary="conftest",
            local_args=["test", "--output", "json", "--all-namespaces", "{SCAN_DIR}"],
            target_path=target_path,
        )

        errors: list[str] = []
        if result.stderr:
            errors.append(result.stderr)

        findings: list[dict[str, object]] = []
        if result.stdout.strip():
            try:
                parsed = json.loads(result.stdout)
                findings = parsed if isinstance(parsed, list) else [parsed]
            except json.JSONDecodeError:
                errors.append("Failed to parse conftest JSON output")

        runs = []
        if findings:
            sarif_results = []
            for f in findings:
                sarif_results.append(
                    {
                        "ruleId": str(f.get("filename", "unknown")),
                        "level": "error",
                        "message": {"text": str(f.get("warnings", f.get("message", "")))},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": str(f.get("filename", "unknown"))},
                                }
                            }
                        ],
                    }
                )
            runs.append(
                {
                    "tool": {"driver": {"name": "conftest", "version": "latest"}},
                    "results": sarif_results,
                    "artifacts": [],
                }
            )

        return ScanResult(
            engine=self.engine,
            sarif_document={
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": runs,
            },
            raw_output=result.stdout,
            errors=errors,
        )
