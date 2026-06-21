from __future__ import annotations

import asyncio
import json
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ScanJob:
    scan_id: str
    target_path: str
    enrich: bool = False


class ScanQueue:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[ScanJob] = asyncio.Queue()
        self._events: dict[str, list[dict[str, Any]]] = {}

    async def enqueue(self, job: ScanJob) -> None:
        self._events[job.scan_id] = []
        asyncio.create_task(self._wrap_process(job))

    async def _wrap_process(self, job: ScanJob) -> None:
        try:
            await self._process(job)
        except Exception:
            logger.error("scan_job_crashed", scan_id=job.scan_id, error=traceback.format_exc())
            self._push(job.scan_id, {"type": "error", "message": traceback.format_exc()})

    def get_events(self, scan_id: str) -> list[dict[str, Any]]:
        return self._events.get(scan_id, [])

    def _push(self, scan_id: str, event: dict[str, Any]) -> None:
        if scan_id in self._events:
            self._events[scan_id].append(event)

    async def _process(self, job: ScanJob) -> None:
        from sentinel.enrich.converter import sarif_result_to_finding
        from sentinel.normalize import normalize
        from sentinel.scanners import SCANNERS

        logger.info("scan_job_started", scan_id=job.scan_id, path=job.target_path)
        self._push(job.scan_id, {"type": "scan_started", "path": job.target_path})

        target = Path(job.target_path)
        if not target.exists():
            self._push(job.scan_id, {"type": "error", "message": "Path not found"})
            return

        async def _run_scanner(scanner_cls: Any) -> Any:
            scanner = scanner_cls()
            if not scanner.is_available():
                return None
            self._push(job.scan_id, {"type": "scanner_started", "engine": scanner.engine})
            try:
                raw = await asyncio.to_thread(scanner.scan, target)
                sarif_doc = raw.sarif_document if isinstance(raw.sarif_document, dict) else {}
                sarif_runs = sarif_doc.get("runs", [])
                if isinstance(sarif_runs, list):
                    count = sum(len(r.get("results", [])) for r in sarif_runs)
                else:
                    count = 0
                self._push(job.scan_id, {
                    "type": "scanner_completed", "engine": scanner.engine, "findings": count,
                })
                return raw
            except Exception as e:
                self._push(job.scan_id, {
                    "type": "scanner_error", "engine": scanner.engine, "error": str(e),
                })
                return None

        results = await asyncio.gather(*[_run_scanner(cls) for cls in SCANNERS])
        scan_results = [r for r in results if r is not None]

        normalized = normalize(scan_results)
        norm_runs = normalized.get("runs", [])
        if isinstance(norm_runs, list):
            total = sum(len(r.get("results", [])) for r in norm_runs)
        else:
            total = 0
        self._push(job.scan_id, {"type": "normalized", "total_findings": total})

        findings: list[dict[str, Any]] = []
        if isinstance(norm_runs, list):
            for run in norm_runs:
                if not isinstance(run, dict):
                    continue
                for r in run.get("results", []):
                    if isinstance(r, dict):
                        finding = sarif_result_to_finding(r)
                        findings.append({
                            "id": f"{job.scan_id}-{finding.id}",
                            "rule_id": finding.rule_id,
                            "severity": finding.severity,
                            "title": finding.title,
                            "file_path": finding.file_path,
                            "line": finding.line,
                            "resource": finding.resource,
                        })

        self._push(job.scan_id, {"type": "findings_ready", "count": len(findings)})

        try:
            from sentinel.rag.db import get_session_factory
            from sentinel.rag.models import Base, FindingRecord, ScanRecord

            summary = {
                "total": total,
                "engines": [r.engine for r in scan_results],
                "severity_counts": _count_by_severity(normalized),
            }

            factory = get_session_factory()
            async with factory() as session:
                await session.run_sync(lambda s: Base.metadata.create_all(s.bind))  # type: ignore[arg-type]
                scan_record = await session.get(ScanRecord, job.scan_id)
                if scan_record:
                    scan_record.summary_json = json.dumps(summary)
                else:
                    scan_record = ScanRecord(
                        id=job.scan_id,
                        target_path=job.target_path,
                        summary_json=json.dumps(summary),
                    )
                    session.add(scan_record)
                for f in findings:
                    session.add(FindingRecord(
                        id=f["id"],
                        scan_id=job.scan_id,
                        rule_id=f["rule_id"],
                        engine="",
                        severity=f["severity"],
                        resource=f.get("resource", ""),
                        file_path=f["file_path"],
                        line=f["line"],
                        title=f["title"],
                        raw_description="",
                    ))
                await session.commit()
        except Exception as e:
            self._push(job.scan_id, {"type": "error", "message": f"DB persist failed: {e}"})

        self._push(job.scan_id, {"type": "scan_completed"})
        logger.info("scan_job_completed", scan_id=job.scan_id)


SEVERITY_LEVEL_MAP: dict[str, str] = {
    "critical": "critical", "high": "high", "error": "high",
    "medium": "medium", "warning": "medium",
    "low": "low", "info": "note", "note": "note",
}

def _count_by_severity(normalized: dict[str, Any]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "note": 0}
    runs = normalized.get("runs", [])
    if not isinstance(runs, list):
        return counts
    for run in runs:
        if not isinstance(run, dict):
            continue
        for r in run.get("results", []):
            if not isinstance(r, dict):
                continue
            level = str(r.get("level", "note")).lower()
            sev = SEVERITY_LEVEL_MAP.get(level, "note")
            if sev in counts:
                counts[sev] += 1
    return counts
