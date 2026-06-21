import math

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.rag.embeddings import EmbeddingProvider
from sentinel.rag.ingest import _bytes_to_float_list
from sentinel.rag.models import ControlChunk


class ControlMatch:
    def __init__(
        self, control_id: str, framework: str, title: str, text: str, score: float
    ) -> None:
        self.control_id = control_id
        self.framework = framework
        self.title = title
        self.text = text
        self.score = score


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    return dot / (na * nb) if na > 0 and nb > 0 else 0.0


async def retrieve(
    query: str,
    db: AsyncSession,
    top_k: int = 5,
) -> list[ControlMatch]:
    embedder = EmbeddingProvider()
    [query_embedding] = await embedder.embed([query])

    result = await db.execute(select(ControlChunk))
    chunks = result.scalars().all()

    scored: list[tuple[float, ControlChunk]] = []
    for chunk in chunks:
        if chunk.embedding:
            chunk_embedding = _bytes_to_float_list(chunk.embedding)
            score = _cosine_similarity(query_embedding, chunk_embedding)
            scored.append((score, chunk))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [
        ControlMatch(
            control_id=chunk.control_id,
            framework=chunk.framework,
            title=chunk.title,
            text=chunk.text,
            score=score,
        )
        for score, chunk in scored[:top_k]
    ]
