import pytest

from sentinel.rag.embeddings import EmbeddingProvider


@pytest.mark.asyncio
async def test_embedding_returns_vectors() -> None:
    provider = EmbeddingProvider()
    result = await provider.embed(["hello world"])
    assert len(result) == 1
    assert len(result[0]) == 384
    assert all(isinstance(v, float) for v in result[0])


@pytest.mark.asyncio
async def test_embedding_deterministic() -> None:
    provider = EmbeddingProvider()
    r1 = await provider.embed(["same text"])
    r2 = await provider.embed(["same text"])
    assert r1[0] == r2[0]


@pytest.mark.asyncio
async def test_embedding_different_texts() -> None:
    provider = EmbeddingProvider()
    await provider.embed(["S3 bucket public access"])
    r2 = await provider.embed(["IAM least privilege"])
    assert isinstance(r2, list)
    assert isinstance(r2[0], list)
