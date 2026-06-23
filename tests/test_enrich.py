import pytest

from sentinel.enrich.batcher import TokenBudgetBatcher
from sentinel.enrich.converter import sarif_result_to_finding
from sentinel.enrich.pipeline import run_enrichment
from sentinel.models import Finding, Severity


def _make_sarif_result(
    rule_id: str = "CKV_AWS_18",
    file_uri: str = "main.tf",
    line: int = 10,
    resource: str = "aws_s3_bucket.b",
    level: str = "high",
    msg: str = "S3 bucket has public read ACL",
) -> dict[str, object]:
    return {
        "sentinel_id": f"hash_{rule_id}",
        "ruleId": rule_id,
        "source_engine": "checkov",
        "level": level,
        "resource": resource,
        "message": {"text": msg},
        "raw_description": msg,
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_uri},
                    "region": {"startLine": line},
                }
            }
        ],
    }


def test_sarif_result_to_finding() -> None:
    sarif = _make_sarif_result()
    finding = sarif_result_to_finding(sarif)
    assert finding.rule_id == "CKV_AWS_18"
    assert finding.file_path == "main.tf"
    assert finding.line == 10
    assert finding.resource == "aws_s3_bucket.b"
    assert finding.severity == Severity.high
    assert finding.engine == "checkov"


def test_sarif_result_to_finding_defaults() -> None:
    sarif: dict[str, object] = {}
    finding = sarif_result_to_finding(sarif)
    assert finding.rule_id == "unknown"
    assert finding.file_path == "unknown"


def test_batcher_single_finding() -> None:
    batcher = TokenBudgetBatcher(budget=100_000)
    findings = [
        Finding(
            id="1",
            rule_id="CKV_AWS_18",
            engine="checkov",
            severity=Severity.high,
            resource="s3_bucket",
            file_path="main.tf",
            line=10,
            title="Test",
            raw_description="A" * 100,
        )
    ]
    batches = batcher.batch(findings)
    assert len(batches) == 1
    assert len(batches[0]) == 1


def test_batcher_splits_budget() -> None:
    batcher = TokenBudgetBatcher(budget=50)
    findings = [
        Finding(
            id=str(i),
            rule_id=f"RULE_{i}",
            engine="checkov",
            severity=Severity.medium,
            resource=f"res_{i}",
            file_path="main.tf",
            line=i,
            title=f"Finding {i}",
            raw_description="X" * 200,
        )
        for i in range(5)
    ]
    batches = batcher.batch(findings)
    assert len(batches) >= 2


@pytest.mark.asyncio
async def test_enrichment_no_api_key() -> None:
    from sentinel.config import get_config

    cfg = get_config()
    cfg.openai_api_key = ""

    findings = [
        Finding(
            id="1",
            rule_id="CKV_AWS_18",
            engine="checkov",
            severity=Severity.high,
            resource="s3_bucket",
            file_path="main.tf",
            line=10,
            title="Test",
            raw_description="Test finding",
        )
    ]
    result = await run_enrichment(findings, {"main.tf": 'resource "aws_s3_bucket" "b" {}'})
    assert len(result) == 1


def test_converter_roundtrip() -> None:
    sarif = _make_sarif_result()
    finding = sarif_result_to_finding(sarif)
    assert finding.id == "hash_CKV_AWS_18"
    assert finding.title == "S3 bucket has public read ACL"
