import json
from pathlib import Path

from sentinel.scanners.base import Scanner, ScanResult
from sentinel.scanners.docker_runner import best_effort_run

IMAGE = "hadolint/hadolint:latest"


class HadolintScanner(Scanner):
    engine = "hadolint"

    def is_available(self) -> bool:
        return True

    def scan(self, target_path: Path) -> ScanResult:
        result = best_effort_run(
            image=IMAGE,
            command=["hadolint", "--format", "json", "{SCAN_DIR}/Dockerfile"],
            binary="hadolint",
            local_args=["--format", "json", "{SCAN_DIR}/Dockerfile"],
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
                errors.append("Failed to parse hadolint JSON output")

        runs = []
        if findings:
            sarif_results = []
            for f in findings:
                sarif_results.append(
                    {
                        "ruleId": str(f.get("code", "unknown")),
                        "level": "error" if f.get("level") == "error" else "warning",
                        "message": {"text": str(f.get("message", ""))},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": str(f.get("file", "Dockerfile"))},
                                    "region": {"startLine": int(str(f.get("line", "1")))},
                                }
                            }
                        ],
                    }
                )
            runs.append(
                {
                    "tool": {"driver": {"name": "hadolint", "version": "latest"}},
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
