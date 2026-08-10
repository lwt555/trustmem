"""Tests for FAISS index and embedding backends."""
import pytest

from core.retrieval.embeddings import (
    StubEmbeddingBackend, EmbeddingBackend,
)
from core.retrieval.faiss_index import FAISSIndex, SearchHit


class TestStubEmbeddingBackend:
    @pytest.fixture
    def emb(self):
        return StubEmbeddingBackend(dimension=128)

    def test_embed_returns_correct_dimension(self, emb):
        vec = emb.embed("test text")
        assert len(vec) == 128
        assert all(-1.0 <= v <= 1.0 for v in vec)

    def test_embed_is_deterministic(self, emb):
        v1 = emb.embed("hello world")
        v2 = emb.embed("hello world")
        assert v1 == v2

    def test_embed_different_texts_different_vectors(self, emb):
        v1 = emb.embed("hello")
        v2 = emb.embed("world")
        assert v1 != v2

    def test_embed_batch(self, emb):
        texts = ["a", "b", "c"]
        vecs = emb.embed_batch(texts)
        assert len(vecs) == 3
        assert all(len(v) == 128 for v in vecs)


class TestFAISSIndex:
    @pytest.fixture
    def index(self):
        return FAISSIndex(dimension=128)

    @pytest.fixture
    def emb(self):
        return StubEmbeddingBackend(dimension=128)

    def test_add_and_search(self, index, emb):
        e1 = emb.embed("Python programming language")
        e2 = emb.embed("Java programming language")
        index.add("doc-1", e1)
        index.add("doc-2", e2)

        assert index.size == 2

        hits = index.search(emb.embed("Python code"), top_k=2)
        assert len(hits) > 0
        assert hits[0].chunk_id in ("doc-1", "doc-2")

    def test_search_returns_scores(self, index, emb):
        index.add("a", emb.embed("hello world"))
        hits = index.search(emb.embed("hello world"), top_k=1)
        assert len(hits) == 1
        assert hits[0].score > 0

    def test_remove(self, index, emb):
        index.add("doc-1", emb.embed("test"))
        assert index.size == 1
        index.remove("doc-1")
        assert index.size == 0

    def test_clear(self, index, emb):
        index.add("a", emb.embed("a"))
        index.add("b", emb.embed("b"))
        index.clear()
        assert index.size == 0

    def test_search_empty_index(self, index, emb):
        hits = index.search(emb.embed("query"), top_k=10)
        assert len(hits) == 0

    def test_wrong_dimension_raises(self, index):
        with pytest.raises(ValueError):
            index.add("x", [0.5])

    def test_save_load(self, index, emb, tmp_path):
        index.add("a", emb.embed("hello"))
        path = str(tmp_path / "faiss.pkl")
        index.save(path)

        index2 = FAISSIndex(dimension=128)
        index2.load(path)
        assert index2.size == 1
        hits = index2.search(emb.embed("hello"), top_k=1)
        assert hits[0].chunk_id == "a"

    def test_brute_force_fallback(self, emb):
        """Test works even without faiss installed."""
        idx = FAISSIndex(dimension=128)
        idx.add("a", emb.embed("test A"))
        idx.add("b", emb.embed("test B"))
        hits = idx.search(emb.embed("test A"), top_k=1)
        assert len(hits) == 1
        assert hits[0].chunk_id in ("a", "b")
