import json
from pathlib import Path

import structlog
import typer
from rich.console import Console
from rich.table import Table

from sentinel.normalize import normalize
from sentinel.rag.cli import app as rag_app
from sentinel.remediate.agent import _apply_diff
from sentinel.scanners import SCANNERS, ScanResult

app = typer.Typer(
    name="sentinel",
    help="AI-Augmented IaC Misconfiguration Scanner & Auto-Remediator",
    no_args_is_help=True,
)

logger = structlog.get_logger(__name__)
console = Console()


def _read_scan_files(target_path: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for ext in ("*.tf", "*.yaml", "*.yml", "*.json", "Dockerfile"):
        if ext == "Dockerfile":
            candidates = list(target_path.rglob("Dockerfile"))
            for c in candidates:
                try:
                    rel = str(c.relative_to(target_path))
                    files[rel] = c.read_text()
                except Exception:
                    pass
        else:
            for p in target_path.rglob(ext):
                try:
                    rel = str(p.relative_to(target_path))
                    files[rel] = p.read_text()
                except Exception:
                    pass
    return files


def _version_callback(value: bool) -> None:
    if value:
        from importlib.metadata import version

        v = version("sentinel-iac")
        typer.echo(f"sentinel-iac v{v}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version and exit", callback=_version_callback
    ),
) -> None:
    pass


def _run_scanners(target_path: Path) -> list[ScanResult]:
    results: list[ScanResult] = []
    for scanner_cls in SCANNERS:
        scanner = scanner_cls()
        logger.info("running_scanner", engine=scanner.engine)
        if not scanner.is_available():
            logger.warning("scanner_not_available", engine=scanner.engine)
            continue
        try:
            result = scanner.scan(target_path)
            if result.errors:
                for err in result.errors:
                    logger.warning("scanner_error", engine=scanner.engine, error=err)
            results.append(result)
        except Exception as e:
            logger.error("scanner_failed", engine=scanner.engine, error=str(e))
    return results


def _display_results_table(all_findings: list[dict[str, object]]) -> None:
    if not all_findings:
        console.print("[green]No findings detected.[/green]")
        return

    table = Table(title="Security Findings")
    table.add_column("Severity", style="bold")
    table.add_column("Engine")
    table.add_column("Rule ID")
    table.add_column("File")
    table.add_column("Line")
    table.add_column("Message")

    severity_color = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "white",
        "error": "red",
        "warning": "yellow",
        "note": "blue",
    }

    for f in all_findings:
        level = str(f.get("level", "warning"))
        rule_id = str(f.get("ruleId", "unknown"))
        msg_obj = f.get("message")
        message = str(msg_obj.get("text", "")) if isinstance(msg_obj, dict) else ""
        source = str(f.get("source_engine", "unknown"))

        locations = f.get("locations", [])
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

        file_uri = str(artifact.get("uri", "unknown")) if isinstance(artifact, dict) else "unknown"
        line_num = str(region.get("startLine", "")) if isinstance(region, dict) else ""

        color = severity_color.get(level, "white")
        table.add_row(
            f"[{color}]{level}[/{color}]",
            source,
            rule_id,
            file_uri,
            line_num,
            message,
        )

    console.print(table)
    console.print(f"\n[bold]Total:[/bold] {len(all_findings)} finding(s)")


@app.command()
def scan(
    path: str = typer.Argument(".", help="Path to scan"),
    enrich: bool = typer.Option(False, "--enrich", help="Run LLM enrichment pipeline"),
    output: str | None = typer.Option(None, "--output", "-o", help="Output SARIF file path"),
) -> None:
    target_path = Path(path).resolve()
    if not target_path.exists():
        console.print(f"[red]Error: path '{path}' does not exist[/red]")
        raise typer.Exit(code=1)

    logger.info("scan_started", path=str(target_path), enrich=enrich)

    scan_results = _run_scanners(target_path)
    normalized = normalize(scan_results)

    runs_obj = normalized.get("runs", [])
    runs: list[dict[str, object]] = runs_obj if isinstance(runs_obj, list) else []
    all_findings: list[dict[str, object]] = []
    for run in runs:
        if isinstance(run, dict):
            results = run.get("results", [])
            if isinstance(results, list):
                all_findings.extend(results)

    if enrich and all_findings:
        import asyncio

        from sentinel.enrich.converter import (
            finding_to_enriched_sarif,
            sarif_result_to_finding,
        )
        from sentinel.enrich.pipeline import run_enrichment

        file_contents = _read_scan_files(target_path)
        findings_models = [sarif_result_to_finding(f) for f in all_findings]
        enriched = asyncio.run(run_enrichment(findings_models, file_contents))
        all_findings = [finding_to_enriched_sarif(f) for f in enriched]

        artifacts: list[dict[str, object]] = []
        if runs:
            first_run = runs[0]
            first_artifacts = first_run.get("artifacts", [])
            if isinstance(first_artifacts, list):
                artifacts = first_artifacts

        normalized["runs"] = [
            {
                "tool": {"driver": {"name": "sentinel-iac", "version": "0.1.0"}},
                "results": all_findings,
                "artifacts": artifacts,
            }
        ]

    _display_results_table(all_findings)

    output_path = output or "results.sarif"
    with open(output_path, "w") as f:
        json.dump(normalized, f, indent=2)
    console.print(f"\nSARIF results written to [bold]{output_path}[/bold]")


@app.command()
def fix(
    path: str = typer.Argument(".", help="Path to scan and fix"),
    write: bool = typer.Option(False, "--write", help="Apply remediation patches"),
) -> None:
    target_path = Path(path).resolve()
    if not target_path.exists():
        console.print(f"[red]Error: path '{path}' does not exist[/red]")
        raise typer.Exit(code=1)

    from sentinel.config import get_config
    from sentinel.enrich.converter import sarif_result_to_finding

    cfg = get_config()
    if not cfg.openai_api_key:
        console.print("[red]Error: OPENAI_API_KEY is required for remediation[/red]")
        raise typer.Exit(code=1)

    logger.info("fix_started", path=str(target_path), write=write)

    scan_results = _run_scanners(target_path)
    normalized = normalize(scan_results)

    runs_obj = normalized.get("runs", [])
    runs_list: list[dict[str, object]] = runs_obj if isinstance(runs_obj, list) else []
    all_findings_sarif: list[dict[str, object]] = []
    for run in runs_list:
        if isinstance(run, dict):
            results = run.get("results", [])
            if isinstance(results, list):
                all_findings_sarif.extend(results)

    if not all_findings_sarif:
        console.print("[green]No findings to remediate[/green]")
        return

    findings = [sarif_result_to_finding(f) for f in all_findings_sarif]

    from sentinel.remediate.agent import remediate_finding

    table = Table(title="Remediation Results")
    table.add_column("Finding ID")
    table.add_column("Rule")
    table.add_column("Validated")
    table.add_column("Iterations")
    table.add_column("Log")

    for finding in findings:
        console.print(f"\n[bold]Remediating:[/bold] {finding.rule_id} ({finding.title})")
        result = remediate_finding(finding, target_path)

        status = "[green]Yes[/green]" if result.validated else "[red]No[/red]"
        table.add_row(
            finding.id,
            finding.rule_id,
            status,
            str(result.iterations),
            result.validation_log[:80] if result.validation_log else "",
        )

        if result.validated and write:
            file_path = target_path / finding.file_path
            if file_path.exists():
                if result.patch_content:
                    file_path.write_text(result.patch_content)
                    console.print(f"  [green]Applied patch to {finding.file_path}[/green]")
                elif result.patch_diff:
                    patched = _apply_diff(file_path.read_text(), result.patch_diff)
                    if patched:
                        file_path.write_text(patched)
                        console.print(f"  [green]Applied patch to {finding.file_path}[/green]")

    console.print()
    console.print(table)


@app.command()
def eval_report(
    golden: str = typer.Option(
        "evals/golden.yaml", "--golden", "-g", help="Path to golden YAML"
    ),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Output markdown file path"
    ),
    pdf: bool = typer.Option(False, "--pdf", help="Also generate PDF report"),
) -> None:
    """Run eval harness and generate a report."""
    from sentinel.eval_report import run_and_report

    run_and_report(golden_path=golden, output=output, pdf=pdf)


app.add_typer(rag_app, name="rag", help="RAG compliance catalog commands")

if __name__ == "__main__":
    app()
