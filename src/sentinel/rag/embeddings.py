import asyncio
from typing import Any, cast

from sentinel.config import get_config


class EmbeddingProvider:
    def __init__(self, model: str | None = None) -> None:
        config = get_config()
        self.model = model or config.embedding_model
        self._model_instance: Any = None

    async def embed(self, texts: list[str]) -> list[list[float]]:
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
