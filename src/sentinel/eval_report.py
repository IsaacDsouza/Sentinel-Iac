from __future__ import annotations

import contextlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
import yaml
from rich.console import Console

from sentinel.normalize import normalize
from sentinel.scanners import SCANNERS

logger = structlog.get_logger(__name__)
console = Console()


def load_golden(path: str | Path = "evals/golden.yaml") -> dict[str, Any]:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def run_eval(golden_path: str | Path = "evals/golden.yaml") -> dict[str, Any]:
    golden = load_golden(golden_path)
    results: dict[str, Any] = {
        "fixtures": [],
        "overall": {"detection_recall": 0.0},
        "scanner_stats": {},
    }
    total_expected = 0
    total_detected = 0
    all_detected_rules: set[str] = set()

    for fixture in golden.get("fixtures", []):
        fixture_path = Path(fixture["path"])
        expected = fixture.get("expected", [])
        total_expected += len(expected)

        scan_results = []
        for scanner_cls in SCANNERS:
            scanner = scanner_cls()
            if scanner.is_available():
                with contextlib.suppress(Exception):
                    raw = scanner.scan(fixture_path)
                    scan_results.append(raw)
                    engine = raw.engine
                    sarif = raw.sarif_document if isinstance(raw.sarif_document, dict) else {}
                    runs = sarif.get("runs", [])
                    count = 0
                    if isinstance(runs, list):
                        for run in runs:
                            if isinstance(run, dict):
                                count += len(run.get("results", []))
                    results["scanner_stats"][engine] = (
                        results["scanner_stats"].get(engine, 0) + count
                    )

        normalized = normalize(scan_results)
        detected = _extract_all_rules(normalized)
        all_detected_rules.update(detected)

        matched = sum(1 for e in expected if e["rule_id"] in detected)
        recall = matched / len(expected) if expected else 1.0
        total_detected += matched

        fixture_result: dict[str, Any] = {
            "name": fixture["name"],
            "expected": len(expected),
            "detected": matched,
            "recall": recall,
            "missing": [e for e in expected if e["rule_id"] not in detected],
            "all_detected": sorted(detected),
        }
        results["fixtures"].append(fixture_result)

    results["overall"]["detection_recall"] = (
        total_detected / total_expected if total_expected else 1.0
    )
    results["overall"]["total_expected"] = total_expected
    results["overall"]["total_detected"] = total_detected
    results["overall"]["total_findings"] = len(all_detected_rules)
    return results


def _extract_all_rules(normalized: dict[str, Any]) -> set[str]:
    rules: set[str] = set()
    runs = normalized.get("runs", [])
    if not isinstance(runs, list):
        return rules
    for run in runs:
        if not isinstance(run, dict):
            continue
        results = run.get("results", [])
        if not isinstance(results, list):
            continue
        for r in results:
            if isinstance(r, dict):
                rule_id = r.get("ruleId")
                if rule_id:
                    rules.add(str(rule_id))
    return rules


def generate_markdown(results: dict[str, Any]) -> str:
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    overall = results["overall"]
    threshold = 0.8
    passed = overall["detection_recall"] >= threshold

    lines: list[str] = []
    lines.append("# Sentinel IaC Eval Report\n")
    lines.append(f"**Generated:** {now}\n")
    lines.append(f"**Threshold:** >= {threshold:.0%} recall\n")

    lines.append("## Summary\n")
    lines.append("| Fixture | Expected | Detected | Recall | Status |")
    lines.append("|---------|----------|----------|--------|--------|")
    for fx in results["fixtures"]:
        status = "PASS" if fx["recall"] >= threshold else "FAIL"
        lines.append(
            f"| {fx['name']} | {fx['expected']} | {fx['detected']} | "
            f"{fx['recall']:.1%} | {status} |"
        )
    overall_status = "PASS" if passed else "FAIL"
    lines.append(
        f"| **Overall** | **{overall['total_expected']}** | "
        f"**{overall['total_detected']}** | "
        f"**{overall['detection_recall']:.1%}** | **{overall_status}** |"
    )
    lines.append("")

    lines.append(
        f"**Total raw findings across all scanners:** {overall['total_findings']}\n"
    )

    lines.append("## Details\n")
    for fx in results["fixtures"]:
        status = "PASS" if fx["recall"] >= threshold else "FAIL"
        lines.append(f"### {fx['name']} ({status}) — {fx['recall']:.1%}\n")
        lines.append(f"- **Expected:** {fx['expected']} rules")
        lines.append(f"- **Detected:** {fx['detected']} rules")
        lines.append(f"- **Recall:** {fx['recall']:.1%}\n")

        if fx["all_detected"]:
            lines.append("**Detected rules:**\n")
            for rid in fx["all_detected"]:
                lines.append(f"- `{rid}`")

        if fx["missing"]:
            lines.append("\n**Missing rules:**\n")
            for m in fx["missing"]:
                lines.append(
                    f"- `{m['rule_id']}` ({m['severity']}) — "
                    f"{m.get('resource', '')}"
                )
        lines.append("")

    lines.append("## Scanner Breakdown\n")
    stats = results.get("scanner_stats", {})
    lines.append("| Engine | Findings |")
    lines.append("|--------|----------|")
    for engine, count in sorted(stats.items()):
        lines.append(f"| {engine} | {count} |")
    lines.append("")

    lines.append("---\n")
    passed_str = (
        f"**Result: PASS** — recall {overall['detection_recall']:.1%} "
        f"\u2265 {threshold:.0%}"
    )
    failed_str = (
        f"**Result: FAIL** — recall {overall['detection_recall']:.1%} "
        f"< {threshold:.0%}"
    )
    lines.append(passed_str if passed else failed_str)
    lines.append("")

    return "\n".join(lines)


def generate_pdf(markdown_text: str, output_path: str | Path) -> None:
    try:
        from fpdf import FPDF
    except ImportError:
        logger.error("fpdf2 not installed; install with: pip install fpdf2")
        return

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    for line in markdown_text.split("\n"):
        if line.startswith("# "):
            pdf.set_font("Helvetica", "B", 18)
            pdf.cell(0, 10, line[2:], new_x="LMARGIN", new_y="NEXT")
            pdf.ln(4)
        elif line.startswith("## "):
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 8, line[3:], new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
        elif line.startswith("### "):
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(0, 7, line[4:], new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)
        elif line.startswith("| "):
            cells = [c.strip() for c in line.split("|")[1:-1]]
            for cell in cells:
                pdf.set_font("Courier", "", 8)
                pdf.cell(40, 5, cell[:60], border=1)
            pdf.ln()
        else:
            pdf.set_font("Helvetica", "", 10)
            text = line.strip()
            if text.startswith("- `"):
                text = "  " + text
            pdf.cell(0, 5, text[:120], new_x="LMARGIN", new_y="NEXT")

    pdf.output(str(output_path))
    console.print(f"[green]PDF report written to {output_path}[/green]")


def print_report(results: dict[str, Any]) -> None:
    overall = results["overall"]
    threshold = 0.8
    console.print("\n[bold]=== Sentinel IaC Eval Report ===[/bold]\n")
    for fx in results["fixtures"]:
        status = "[green]PASS[/green]" if fx["recall"] >= threshold else "[red]FAIL[/red]"
        console.print(
            f"  [{status}] {fx['name']}: {fx['detected']}/{fx['expected']} "
            f"detected ({fx['recall']:.1%})"
        )
        if fx["missing"]:
            missing_ids = ", ".join(m["rule_id"] for m in fx["missing"])
            console.print(f"         [yellow]Missing: {missing_ids}[/yellow]")

    console.print(
        f"\n  Overall detection recall: {overall['detection_recall']:.1%}"
    )
    console.print(f"  Threshold: >= {threshold:.0%}")
    passed = overall["detection_recall"] >= threshold
    status_text = "[green]PASS[/green]" if passed else "[red]FAIL[/red]"
    console.print(f"\n  Overall: {status_text}")


def run_and_report(
    golden_path: str | Path = "evals/golden.yaml",
    output: str | None = None,
    pdf: bool = False,
) -> dict[str, Any]:
    results = run_eval(golden_path)

    print_report(results)

    if output:
        md = generate_markdown(results)
        out_path = Path(output)
        out_path.write_text(md)
        console.print(f"[green]Markdown report written to {out_path}[/green]")

        if pdf:
            pdf_path = out_path.with_suffix(".pdf")
            generate_pdf(md, pdf_path)

    return results
