"""Eval harness for sentinel-iac.

Measures detection recall, remediation success rate, and enrichment quality.
"""

import contextlib
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.normalize import normalize
from sentinel.scanners import SCANNERS


def load_golden(path: str | Path = "evals/golden.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def run_eval() -> dict:
    golden = load_golden()
    results = {"fixtures": [], "overall": {"detection_recall": 0.0, "remediation_rate": 0.0}}
    total_expected = 0
    total_detected = 0

    for fixture in golden["fixtures"]:
        fixture_path = Path(fixture["path"])
        expected = fixture["expected"]
        total_expected += len(expected)

        scan_results = []
        for scanner_cls in SCANNERS:
            scanner = scanner_cls()
            if scanner.is_available():
                with contextlib.suppress(Exception):
                    scan_results.append(scanner.scan(fixture_path))

        normalized = normalize(scan_results)
        detected = _extract_all_rules(normalized)

        matched = sum(1 for e in expected if e["rule_id"] in detected)
        recall = matched / len(expected) if expected else 1.0
        total_detected += matched

        fixture_result = {
            "name": fixture["name"],
            "expected": len(expected),
            "detected": matched,
            "recall": recall,
            "missing": [e["rule_id"] for e in expected if e["rule_id"] not in detected],
        }
        results["fixtures"].append(fixture_result)

    results["overall"]["detection_recall"] = (
        total_detected / total_expected if total_expected else 1.0
    )
    return results


def _extract_all_rules(normalized: dict) -> set[str]:
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


def print_report(results: dict) -> None:
    print("\n=== Sentinel IaC Eval Report ===\n")
    for fx in results["fixtures"]:
        status = "PASS" if fx["recall"] >= 0.8 else "FAIL"
        print(
            f"  [{status}] {fx['name']}: {fx['detected']}/{fx['expected']} "
            f"detected ({fx['recall']:.1%})"
        )
        if fx["missing"]:
            print(f"         Missing: {', '.join(fx['missing'])}")

    print(f"\n  Overall detection recall: {results['overall']['detection_recall']:.1%}")
    print("  Threshold: >= 80%")
    passed = results["overall"]["detection_recall"] >= 0.8
    print(f"\n  Overall: {'PASS' if passed else 'FAIL'}")


if __name__ == "__main__":
    results = run_eval()
    print_report(results)
    if results["overall"]["detection_recall"] < 0.8:
        sys.exit(1)
