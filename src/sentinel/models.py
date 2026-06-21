from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class ComplianceControl(BaseModel):
    control_id: str
    framework: str
    relevance_score: float
    citation: str


class Enrichment(BaseModel):
    explanation: str
    compliance_controls: list[ComplianceControl]
    priority_score: int
    priority_rationale: str


class Remediation(BaseModel):
    patch_diff: str
    validated: bool
    validation_log: str


class Finding(BaseModel):
    id: str
    rule_id: str
    engine: str
    severity: Severity
    resource: str
    file_path: str
    line: int
    title: str
    raw_description: str
    enrichment: Enrichment | None = None
    remediation: Remediation | None = None


class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class Scan(BaseModel):
    id: str
    created_at: datetime
    target_path: str
    commit_sha: str | None = None
    findings: list[Finding]
    summary: ScanSummary
