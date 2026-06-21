import asyncio
from typing import Any, cast

import httpx

from sentinel.config import get_config


class EmbeddingProvider:
    def __init__(self, model: str | None = None, api_key: str | None = None) -> None:
        config = get_config()
        self.model = model or config.embedding_model
        self.api_key = api_key or config.embedding_api_key
        self._model_instance: Any = None

    async def embed(self, texts: list[str]) -> list[list[float]]:
        if self.model.startswith("voyage") and self.api_key:
            return await self._voyage_embed(texts)
        return await self._sentence_embed(texts)

    async def _sentence_embed(self, texts: list[str]) -> list[list[float]]:
        if self._model_instance is None:
            self._model_instance = await asyncio.to_thread(self._load_model)
        result = await asyncio.to_thread(
            self._model_instance.encode, texts, show_progress_bar=False
        )
        return cast(list[list[float]], result.tolist())

    def _load_model(self) -> Any:
        from sentence_transformers import SentenceTransformer

        return SentenceTransformer(self.model)

    async def _voyage_embed(self, texts: list[str]) -> list[list[float]]:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                "https://api.voyageai.com/v1/embeddings",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"model": self.model, "input": texts},
            )
            resp.raise_for_status()
            data = resp.json()
            return [d["embedding"] for d in data["data"]]
