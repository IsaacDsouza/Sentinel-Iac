from pathlib import Path

from sentinel.scanners.base import Scanner, ScanResult
from sentinel.scanners.docker_runner import _docker_available, best_effort_run, run_docker_container

IMAGE = "zegl/kube-score:latest"


class KubeScoreScanner(Scanner):
    engine = "kube-score"

    def is_available(self) -> bool:
        return True

    def _yaml_files(self, target_path: Path) -> list[Path]:
        files: list[Path] = []
        if target_path.is_dir():
            for p in sorted(target_path.rglob("*")):
                if p.suffix in (".yaml", ".yml"):
                    files.append(p)
        elif target_path.suffix in (".yaml", ".yml"):
            files.append(target_path)
        return files

    def _container_path(self, host_path: Path, target_path: Path) -> str:
        rel = host_path.relative_to(target_path)
        return f"/scan/{rel.as_posix()}"

    def scan(self, target_path: Path) -> ScanResult:
        yaml_files = self._yaml_files(target_path)
        if not yaml_files:
            return ScanResult(
                engine=self.engine,
                sarif_document={"$schema": "...", "version": "2.1.0", "runs": []},
                raw_output="",
                errors=["No YAML files found to scan"],
            )

        errors: list[str] = []
        stdout = ""

        if _docker_available():
            container_paths = [self._container_path(f, target_path) for f in yaml_files]
            result = run_docker_container(IMAGE, ["score", *container_paths], target_path)
            if result.stderr:
                errors.append(result.stderr)
            stdout = result.stdout
        else:
            local_paths = [str(f) for f in yaml_files]
            result = best_effort_run(
                image=IMAGE,
                command=["score"],
                binary="kube-score",
                local_args=["score", *local_paths],
                target_path=target_path,
            )
            if result.stderr:
                errors.append(result.stderr)
            stdout = result.stdout

        runs = []
        if stdout:
            runs.append(
                {
                    "tool": {"driver": {"name": "kube-score", "version": "latest"}},
                    "results": self._parse_text_output(stdout),
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
            raw_output=stdout,
            errors=errors,
        )

    def _parse_text_output(self, text: str) -> list[dict[str, object]]:
        results: list[dict[str, object]] = []
        for line in text.splitlines():
            if ":" in line and ("FAIL" in line or "WARN" in line):
                parts = line.split(":", 1)
                results.append(
                    {
                        "ruleId": f"kube-score-{parts[0].strip().replace(' ', '-').lower()}",
                        "level": "error" if "FAIL" in line else "warning",
                        "message": {"text": parts[1].strip()},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "unknown"}}}
                        ],
                    }
                )
        return results
