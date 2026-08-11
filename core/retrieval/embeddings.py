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
    """Embedding backend using OpenAI-compatible Embeddings API."""

    def __init__(self, model: str = "text-embedding-3-small",
                 base_url: str | None = None,
                 api_key_env: str = "OPENAI_API_KEY") -> None:
        api_key = os.environ.get(api_key_env, "")
        if not api_key:
            raise ValueError(f"{api_key_env} environment variable not set")
        import openai
        kwargs: dict = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        self._client = openai.OpenAI(**kwargs)
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


class BGEEmbeddingBackend(EmbeddingBackend):
    """Local BGE model for Chinese-optimized embeddings via sentence-transformers.

    Uses BAAI/bge-small-zh-v1.5 (512-dim) by default. Set TRUSTMEM_EMBEDDING_MODEL
    to use a different model. Set HF_ENDPOINT for Chinese users (hf-mirror.com).
    """

    def __init__(self, model_name: str | None = None) -> None:
        from sentence_transformers import SentenceTransformer
        self._model_name = model_name or os.environ.get(
            "TRUSTMEM_EMBEDDING_MODEL", "BAAI/bge-small-zh-v1.5")
        self._model = SentenceTransformer(self._model_name)
        self._dim = self._model.get_sentence_embedding_dimension()

    def embed(self, text: str) -> list[float]:
        return self._model.encode(text, normalize_embeddings=True).tolist()

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        embeddings = self._model.encode(texts, normalize_embeddings=True)
        return [e.tolist() for e in embeddings]

    @property
    def dimension(self) -> int:
        return self._dim


def create_embedding_backend() -> EmbeddingBackend:
    backend_name = os.environ.get("TRUSTMEM_LLM_BACKEND", "claude").lower()
    embedding_override = os.environ.get("TRUSTMEM_EMBEDDING_BACKEND", "").lower()

    # explicit override takes priority
    if embedding_override:
        return _make_embedding_backend(embedding_override)

    # pair with LLM backend: deepseek → bge (local Chinese embedding)
    if backend_name == "deepseek":
        try:
            return BGEEmbeddingBackend()
        except (ImportError, Exception):
            return StubEmbeddingBackend(dimension=512)

    return _make_embedding_backend(backend_name)


def _make_embedding_backend(name: str) -> EmbeddingBackend:
    try:
        if name == "openai":
            return OpenAIEmbeddingBackend()
        elif name == "bge":
            return BGEEmbeddingBackend()
        else:
            return ClaudeEmbeddingBackend()
    except (ValueError, ImportError):
        return StubEmbeddingBackend()
