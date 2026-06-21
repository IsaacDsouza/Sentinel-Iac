import json
import tempfile
from pathlib import Path

from sentinel.scanners.base import Scanner, ScanResult
from sentinel.scanners.docker_runner import _docker_available, best_effort_run

IMAGE = "bridgecrew/checkov:latest"
_SARIF_EMPTY: dict[str, object] = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "version": "2.1.0",
    "runs": [],
}


class CheckovScanner(Scanner):
    engine = "checkov"

    def is_available(self) -> bool:
        return True

    def _run_checkov(self, target_path: Path) -> tuple[str, int, list[str]]:
        errors: list[str] = []
        if _docker_available():
            with tempfile.TemporaryDirectory() as tmpdir:
                result = best_effort_run(
                    image=IMAGE,
                    command=[
                        "--directory", "{SCAN_DIR}",
                        "--output", "sarif",
                        "--output-file-path", "/tmp/out",
                    ],
                    binary="checkov",
                    local_args=["--directory", "{SCAN_DIR}", "--output", "sarif", "--compact"],
                    target_path=target_path,
                    read_only=False,
                    extra_mounts=[(tmpdir, "/tmp/out")],
                )
                if result.stderr:
                    errors.append(result.stderr)
                sarif_file = Path(tmpdir) / "results_sarif.sarif"
                if sarif_file.exists():
                    return sarif_file.read_text(), 0, errors
                return result.stdout, result.returncode, errors
        result = best_effort_run(
            image=IMAGE,
            command=["--directory", "{SCAN_DIR}", "--output", "sarif", "--compact"],
            binary="checkov",
            local_args=["--directory", "{SCAN_DIR}", "--output", "sarif", "--compact"],
            target_path=target_path,
        )
        errors = [result.stderr] if result.stderr else []
        return result.stdout, result.returncode, errors

    def scan(self, target_path: Path) -> ScanResult:
        stdout, returncode, errors = self._run_checkov(target_path)

        if returncode not in (0, 1):
            return ScanResult(
                engine=self.engine,
                sarif_document=_SARIF_EMPTY,
                raw_output=stdout,
                errors=errors,
            )

        try:
            sarif = json.loads(stdout)
        except json.JSONDecodeError:
            return ScanResult(
                engine=self.engine,
                sarif_document=_SARIF_EMPTY,
                raw_output=stdout,
                errors=["Failed to parse SARIF output"],
            )

        return ScanResult(
            engine=self.engine,
            sarif_document=sarif,
            raw_output=stdout,
        )
