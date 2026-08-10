"""TrustMem retrieval layer — FAISS vector search + PDP filtering."""
from .embeddings import (EmbeddingBackend, StubEmbeddingBackend,
                         ClaudeEmbeddingBackend, OpenAIEmbeddingBackend,
                         create_embedding_backend)
from .faiss_index import FAISSIndex
from .search_engine import SearchEngine
