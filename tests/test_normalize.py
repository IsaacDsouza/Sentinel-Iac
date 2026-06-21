from sentinel.normalize import compute_finding_id, extract_findings, normalize
from sentinel.scanners import ScanResult
from sentinel.scanners.equivalences import find_equivalent


def _make_sarif_result(rule_id: str, file_uri: str, line: int = 1, resource: str = "") -> dict:
    result: dict = {
        "ruleId": rule_id,
        "level": "error",
        "message": {"text": f"Test finding for {rule_id}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }
    if resource:
        result["resource"] = resource
    return result


def _make_sarif_doc(results: list[dict]) -> dict:
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "test", "version": "1.0"}},
                "results": results,
                "artifacts": [],
            }
        ],
    }


def test_compute_finding_id_is_stable() -> None:
    id1 = compute_finding_id("CKV_AWS_18", "main.tf", 10, "aws_s3_bucket.b")
    id2 = compute_finding_id("CKV_AWS_18", "main.tf", 10, "aws_s3_bucket.b")
    assert id1 == id2
    assert len(id1) == 16


def test_compute_finding_id_changes_with_input() -> None:
    id1 = compute_finding_id("CKV_AWS_18", "main.tf", 10, "aws_s3_bucket.b")
    id2 = compute_finding_id("CKV_AWS_19", "main.tf", 10, "aws_s3_bucket.b")
    assert id1 != id2


def test_extract_findings_empty() -> None:
    result = ScanResult(
        engine="test",
        sarif_document={"version": "2.1.0", "runs": []},
    )
    assert extract_findings(result) == []


def test_extract_findings_returns_results() -> None:
    findings = [_make_sarif_result("CKV_AWS_18", "main.tf")]
    doc = _make_sarif_doc(findings)
    result = ScanResult(engine="test", sarif_document=doc)
    extracted = extract_findings(result)
    assert len(extracted) == 1
    assert extracted[0]["ruleId"] == "CKV_AWS_18"


def test_normalize_merges_multiple_engines() -> None:
    r1 = ScanResult(
        engine="checkov",
        sarif_document=_make_sarif_doc(
            [_make_sarif_result("CKV_AWS_18", "main.tf", 10, "s3_bucket")]
        ),
    )
    r2 = ScanResult(
        engine="trivy",
        sarif_document=_make_sarif_doc(
            [_make_sarif_result("AVD-AWS-0089", "main.tf", 10, "s3_bucket")]
        ),
    )
    normalized = normalize([r1, r2])
    runs = normalized.get("runs", [])
    assert isinstance(runs, list)
    results = runs[0].get("results", []) if runs else []
    assert isinstance(results, list)
    assert len(results) >= 1


def test_normalize_dedup_exact() -> None:
    finding = _make_sarif_result("CKV_AWS_18", "main.tf", 10, "s3_bucket")
    r = ScanResult(
        engine="checkov",
        sarif_document=_make_sarif_doc([finding, finding]),
    )
    normalized = normalize([r])
    runs = normalized.get("runs", [])
    assert isinstance(runs, list)
    results = runs[0].get("results", []) if runs else []
    assert isinstance(results, list)
    assert len(results) == 1


def test_find_equivalent_returns_set() -> None:
    equiv = find_equivalent("CKV_AWS_18")
    assert "AVD-AWS-0089" in equiv


def test_find_equivalent_reverse_lookup() -> None:
    equiv = find_equivalent("AVD-AWS-0089")
    assert "CKV_AWS_18" in equiv
