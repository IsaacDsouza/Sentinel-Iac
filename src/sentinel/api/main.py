from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from sentinel.rag.db import get_session
from sentinel.rag.models import FindingRecord, ScanRecord

from .sse import event_generator
from .worker import ScanJob, ScanQueue

API_KEY_HEADER = "X-API-Key"

scan_queue = ScanQueue()


def verify_api_key(api_key: str | None = Header(None, alias=API_KEY_HEADER)) -> None:
    from sentinel.config import get_config

    cfg = get_config()
    if not cfg.api_key:
        return
    if api_key != cfg.api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")


class ScanRequest(BaseModel):
    target_path: str
    enrich: bool = False


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    from sentinel.config import get_config
    engine = create_async_engine(get_config().database_url)
    from sentinel.rag.models import Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()
    yield


app = FastAPI(
    title="Sentinel IaC API",
    version="0.1.0",
    lifespan=lifespan,
    dependencies=[Depends(verify_api_key)],
)


@app.get("/health")
async def health() -> dict[str, object]:
    return {"status": "ok"}


@app.post("/scans")
async def trigger_scan(
    req: ScanRequest,
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> dict[str, object]:
    scan_id = str(uuid.uuid4())[:8]
    existing = await db.get(ScanRecord, scan_id)
    if not existing:
        db.add(ScanRecord(
            id=scan_id,
            target_path=req.target_path,
            summary_json="{}",
        ))
        await db.commit()
    job = ScanJob(scan_id=scan_id, target_path=req.target_path, enrich=req.enrich)
    await scan_queue.enqueue(job)
    return {"scan_id": scan_id, "status": "pending"}


@app.get("/scans/{scan_id}/events")
async def scan_events(scan_id: str) -> StreamingResponse:
    return StreamingResponse(
        event_generator(scan_id, scan_queue),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/scans")
async def list_scans(
    limit: int = 20,
    offset: int = 0,
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> dict[str, object]:
    result = await db.execute(
        select(ScanRecord).order_by(ScanRecord.created_at.desc()).offset(offset).limit(limit)
    )
    scans = result.scalars().all()
    return {
        "scans": [
            {
                "id": s.id,
                "target_path": s.target_path,
                "created_at": s.created_at.isoformat() if s.created_at else "",
                "summary": s.summary_json,
            }
            for s in scans
        ]
    }


@app.get("/scans/{scan_id}")
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> dict[str, object]:
    result = await db.execute(select(ScanRecord).where(ScanRecord.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_result = await db.execute(
        select(FindingRecord).where(FindingRecord.scan_id == scan_id)
    )
    findings = findings_result.scalars().all()

    return {
        "id": scan.id,
        "target_path": scan.target_path,
        "created_at": scan.created_at.isoformat() if scan.created_at else "",
        "summary": scan.summary_json,
        "findings": [
            {
                "id": f.id,
                "rule_id": f.rule_id,
                "severity": f.severity,
                "title": f.title,
                "file_path": f.file_path,
                "line": f.line,
                "explanation": f.explanation,
                "priority_score": f.priority_score,
                "patch_diff": f.patch_diff,
                "validated": f.validated,
            }
            for f in findings
        ],
    }


@app.get("/findings")
async def list_findings(
    scan_id: str | None = None,
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> dict[str, object]:
    query = select(FindingRecord)
    if scan_id:
        query = query.where(FindingRecord.scan_id == scan_id)
    if severity:
        query = query.where(FindingRecord.severity == severity)
    query = query.offset(offset).limit(limit)
    result = await db.execute(query)
    findings = result.scalars().all()
    return {
        "findings": [
            {
                "id": f.id,
                "scan_id": f.scan_id,
                "rule_id": f.rule_id,
                "engine": f.engine,
                "severity": f.severity,
                "title": f.title,
                "file_path": f.file_path,
                "line": f.line,
                "explanation": f.explanation,
                "priority_score": f.priority_score,
                "validated": f.validated,
            }
            for f in findings
        ]
    }


@app.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_session),  # noqa: B008
) -> dict[str, object]:
    result = await db.execute(select(ScanRecord))
    scans = result.scalars().all()

    total_findings = 0
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    findings_over_time: dict[str, int] = {}

    for scan in scans:
        try:
            import json
            summary = json.loads(scan.summary_json) if isinstance(scan.summary_json, str) else {}
            counts = summary.get("severity_counts", {})
            for sev, cnt in counts.items():
                severity_counts[sev] = severity_counts.get(sev, 0) + cnt
            total_findings += summary.get("total", 0)

            day = scan.created_at.strftime("%Y-%m-%d") if scan.created_at else ""
            if day:
                findings_over_time[day] = findings_over_time.get(day, 0) + summary.get("total", 0)
        except Exception:
            pass

    return {
        "total_scans": len(scans),
        "total_findings": total_findings,
        "severity_counts": severity_counts,
        "findings_over_time": findings_over_time,
    }
