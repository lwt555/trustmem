"""Embedding backend abstraction + concrete implementations."""
from __future__ import annotations

import hashlib
import os
import random
from abc import ABC, abstractmethod


class EmbeddingBackend(ABC):
    """Abstract embedding backend for semantic memory search."""

    @abstractmethod
    def embed(self, text: str) -> list[float]:
        """Embed a single text into a vector."""
        ...

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Embed multiple texts. Default loops over embed()."""
        return [self.embed(t) for t in texts]

    @property
    @abstractmethod
    def dimension(self) -> int:
        """Dimension of the embedding vectors."""
        ...


class StubEmbeddingBackend(EmbeddingBackend):
    """Stub backend using deterministic hash-based vectors. For demos/tests."""

    def __init__(self, dimension: int = 256) -> None:
        self._dim = dimension

    def embed(self, text: str) -> list[float]:
        h = hashlib.sha256(text.encode()).digest()
        rng = random.Random(int.from_bytes(h[:8], "big"))
        return [rng.uniform(-1.0, 1.0) for _ in range(self._dim)]

    @property
    def dimension(self) -> int:
        return self._dim


class ClaudeEmbeddingBackend(EmbeddingBackend):
    """Embedding backend using Anthropic Embeddings API."""

    def __init__(self, model: str = "claude-embedding-20260210") -> None:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set")
        import anthropic
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model
        self._dim = 256  # Claude embedding dimension

    def embed(self, text: str) -> list[float]:
        resp = self._client.embeddings.create(
            model=self._model,
            input=text,
        )
        return resp.embeddings[0].values if resp.embeddings else []

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        resp = self._client.embeddings.create(
            model=self._model,
            input=texts,
        )
        return [e.values for e in resp.embeddings] if resp.embeddings else []

    @property
    def dimension(self) -> int:
        return self._dim


class OpenAIEmbeddingBackend(EmbeddingBackend):
    """Embedding backend using OpenAI Embeddings API."""

    def __init__(self, model: str = "text-embedding-3-small") -> None:
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")
        import openai
        self._client = openai.OpenAI(api_key=api_key)
        self._model = model
        self._dim = 1536  # text-embedding-3-small dimension

    def embed(self, text: str) -> list[float]:
        resp = self._client.embeddings.create(model=self._model, input=text)
        return resp.data[0].embedding if resp.data else []

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        resp = self._client.embeddings.create(model=self._model, input=texts)
        return [e.embedding for e in resp.data] if resp.data else []

    @property
    def dimension(self) -> int:
        return self._dim


def create_embedding_backend() -> EmbeddingBackend:
    backend_name = os.environ.get("TRUSTMEM_LLM_BACKEND", "claude").lower()
    try:
        if backend_name == "openai":
            return OpenAIEmbeddingBackend()
        else:
            return ClaudeEmbeddingBackend()
    except (ValueError, ImportError):
        return StubEmbeddingBackend()
