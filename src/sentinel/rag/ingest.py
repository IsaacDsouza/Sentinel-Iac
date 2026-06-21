import json
from pathlib import Path

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.rag.embeddings import EmbeddingProvider
from sentinel.rag.models import ControlChunk

logger = structlog.get_logger(__name__)

CATALOG_PATH = Path(__file__).resolve().parents[3] / "data" / "nist800-53.json"


async def ingest_catalog(db: AsyncSession, catalog_path: str | Path | None = None) -> int:
    path = Path(catalog_path) if catalog_path else CATALOG_PATH
    with open(path) as f:
        controls = json.load(f)

    embedder = EmbeddingProvider()
    count = 0

    for ctrl in controls:
        text = f"{ctrl['title']}: {ctrl['description']}"
        chunk = ControlChunk(
            framework=ctrl.get("framework", "NIST SP 800-53"),
            control_id=ctrl["control_id"],
            family=ctrl.get("family", ""),
            title=ctrl["title"],
            text=text,
        )

        existing = await db.execute(
            select(ControlChunk).where(ControlChunk.control_id == ctrl["control_id"])
        )
        if existing.scalar_one_or_none():
            continue

        [embedding] = await embedder.embed([text])
        chunk.embedding = _float_list_to_bytes(embedding)
        db.add(chunk)
        count += 1

    await db.commit()
    logger.info("catalog_ingested", count=count, path=str(path))
    return count


def _float_list_to_bytes(floats: list[float]) -> bytes:
    import struct

    return struct.pack(f"{len(floats)}f", *floats)


def _bytes_to_float_list(data: bytes) -> list[float]:
    import struct

    return list(struct.unpack(f"{len(data) // 4}f", data))
