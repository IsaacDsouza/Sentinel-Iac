import json
from pathlib import Path

from sentinel.scanners.base import Scanner, ScanResult
from sentinel.scanners.docker_runner import best_effort_run

IMAGE = "aquasec/trivy:latest"


class TrivyScanner(Scanner):
    engine = "trivy"

    def is_available(self) -> bool:
        return True

    def scan(self, target_path: Path) -> ScanResult:
        result = best_effort_run(
            image=IMAGE,
            command=[
                "config",
                "--format",
                "sarif",
                "{SCAN_DIR}",
            ],
            binary="trivy",
            local_args=["config", "--format", "sarif", "-o", "/tmp/trivy-out.sarif", "{SCAN_DIR}"],
            target_path=target_path,
            read_only=False,
            network_enabled=True,
        )

        errors: list[str] = []
        if result.stderr:
            errors.append(result.stderr)

        if result.returncode not in (0, 1):
            return ScanResult(
                engine=self.engine,
                sarif_document={"version": "2.1.0", "runs": []},
                raw_output=result.stdout,
                errors=errors,
            )

        try:
            sarif = json.loads(result.stdout) if result.stdout else {"version": "2.1.0", "runs": []}
        except json.JSONDecodeError:
            sarif = {"version": "2.1.0", "runs": []}
            errors.append("Failed to parse SARIF output")

        return ScanResult(
            engine=self.engine,
            sarif_document=sarif,
            raw_output=result.stdout,
            errors=errors,
        )
