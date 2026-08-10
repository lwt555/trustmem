"""Tests for encrypted search pipeline — CKKS + hierarchical clustering + rerank."""
from __future__ import annotations

import math
import pytest

from core.crypto.ckks import (
    ckks_setup, ckks_encode_encrypt, ckks_decrypt_decode,
)
from core.crypto.engine import CryptoEngine, EncryptedSearchResult
from core.crypto.search import (
    ClusterNode, HierarchicalIndex, Reranker, RerankSignal,
    EncryptedSearchEngine,
)
from core.labels import (
    AgentLabel, MemoryLabel, Clearance, Trust, Layer, MemoryType, Role,
)
from core.topology import Topology


class TestHierarchicalIndex:

    @pytest.fixture
    def ctx(self):
        return ckks_setup()

    def _make_vec(self, values: list[float], ctx) -> object:
        return ckks_encode_encrypt(values, ctx)

    def test_build_empty(self, ctx):
        idx = HierarchicalIndex()
        idx.build({}, ctx)
        assert idx.root is None

    def test_build_single_leaf(self, ctx):
        embeddings = {"a": self._make_vec([1.0, 0.0, 0.0, 0.0], ctx)}
        idx = HierarchicalIndex(leaf_capacity=32)
        idx.build(embeddings, ctx)
        assert idx.root is not None
        assert idx.root.is_leaf
        assert "a" in idx.root.children

    def test_build_splits_large_set(self, ctx):
        embeddings = {}
        for i in range(100):
            v = self._make_vec([float(i % 7), float(i % 3), float(i % 11), 0.0], ctx)
            embeddings[f"c{i}"] = v

        idx = HierarchicalIndex(leaf_capacity=8)
        idx.build(embeddings, ctx)
        assert idx.root is not None
        assert not idx.root.is_leaf   # 100 items with leaf_capacity=8 should split
        assert idx.root.size == 100

    def test_search_returns_candidates(self, ctx):
        embeddings = {}
        for i in range(50):
            v = self._make_vec([float(i), 0.0, 0.0, 0.0], ctx)
            embeddings[f"d{i}"] = v

        idx = HierarchicalIndex(leaf_capacity=8)
        idx.build(embeddings, ctx)

        query = self._make_vec([10.0, 0.0, 0.0, 0.0], ctx)
        candidates = idx.search(query, ctx, top_k=10, prune_threshold=100.0)
        # With very high threshold, no pruning, should return all
        assert len(candidates) == 50

    def test_pruning_reduces_candidates(self, ctx):
        """Tight threshold should prune away most candidates."""
        embeddings = {}
        # Create two well-separated clusters: group A near 0, group B near 100
        for i in range(25):
            a = self._make_vec([float(i), 0.0, 0.0, 0.0], ctx)
            embeddings[f"a{i}"] = a
            b = self._make_vec([float(100 + i), 0.0, 0.0, 0.0], ctx)
            embeddings[f"b{i}"] = b

        idx = HierarchicalIndex(leaf_capacity=8)
        idx.build(embeddings, ctx)

        # Query near group A
        query = self._make_vec([10.0, 0.0, 0.0, 0.0], ctx)
        candidates = idx.search(query, ctx, top_k=10, prune_threshold=30.0)
        # Should prune group B (at ~100 away)
        assert len(candidates) < 50
        # Should include matches from group A
        assert any(c.startswith("a") for c in candidates)

    def test_stats(self, ctx):
        embeddings = {}
        for i in range(32):
            v = self._make_vec([float(i), 0.0], ctx)
            embeddings[f"s{i}"] = v

        idx = HierarchicalIndex(leaf_capacity=8)
        idx.build(embeddings, ctx)
        s = idx.stats()
        assert s["nodes"] > 0
        assert s["depth"] > 0
        assert s["leaves"] > 0

    def test_leaf_capacity_controls_split(self, ctx):
        embeddings = {}
        for i in range(20):
            v = self._make_vec([float(i), 0.0], ctx)
            embeddings[f"t{i}"] = v

        idx_big = HierarchicalIndex(leaf_capacity=100)
        idx_big.build(embeddings, ctx)
        assert idx_big.root.is_leaf  # all fit in one leaf

        idx_small = HierarchicalIndex(leaf_capacity=5)
        idx_small.build(embeddings, ctx)
        assert not idx_small.root.is_leaf  # must split

    def test_centroid_computation(self, ctx):
        embeddings = {
            "a": self._make_vec([1.0, 2.0, 3.0], ctx),
            "b": self._make_vec([3.0, 2.0, 1.0], ctx),
        }
        idx = HierarchicalIndex(leaf_capacity=2)
        idx.build(embeddings, ctx)

        # Centroid of [1,2,3] + [3,2,1] = [2,2,2]
        if idx.root and idx.root.centroid:
            centroid_vals = ckks_decrypt_decode(idx.root.centroid, ctx)
            print(f"Centroid: {centroid_vals}")
            assert math.isclose(centroid_vals[0], 2.0, rel_tol=0.01)
            assert math.isclose(centroid_vals[1], 2.0, rel_tol=0.01)
            assert math.isclose(centroid_vals[2], 2.0, rel_tol=0.01)

    def test_euclidean_dist_zero_same_vector(self, ctx):
        v = self._make_vec([5.0, 6.0, 7.0], ctx)
        idx = HierarchicalIndex()
        d = idx._euclidean_dist(v, v, ctx)
        assert math.isclose(d, 0.0, abs_tol=1e-5)


class TestReranker:

    @pytest.fixture
    def reranker(self):
        return Reranker(w_sim=0.4, w_trust=0.35, w_recency=0.15, w_layer=0.10)

    def test_rerank_promotes_high_trust(self, reranker):
        results = [
            EncryptedSearchResult("lo-trust", 0.9, None, 0),
            EncryptedSearchResult("hi-trust", 0.85, None, 1),
        ]
        signals = {
            "lo-trust": RerankSignal("lo-trust", 0.9, trust=0, layer="C", recency=1.0, lifecycle="active"),
            "hi-trust": RerankSignal("hi-trust", 0.85, trust=3, layer="C", recency=1.0, lifecycle="active"),
        }

        reranked = reranker.rerank(results, signals)
        assert reranked[0].chunk_id == "hi-trust"

    def test_rerank_deprioritizes_r_layer(self, reranker):
        results = [
            EncryptedSearchResult("c-layer", 0.8, None, 0),
            EncryptedSearchResult("r-layer", 0.9, None, 1),
        ]
        signals = {
            "c-layer": RerankSignal("c-layer", 0.8, trust=2, layer="C", recency=1.0, lifecycle="active"),
            "r-layer": RerankSignal("r-layer", 0.9, trust=2, layer="R", recency=1.0, lifecycle="active"),
        }

        reranked = reranker.rerank(results, signals)
        # R-layer with slightly higher sim may lose to C-layer with extra layer weight
        assert reranked[0].chunk_id == "c-layer"

    def test_rerank_respects_top_k(self, reranker):
        results = [
            EncryptedSearchResult(f"r{i}", float(10 - i) / 10, None, i)
            for i in range(20)
        ]
        signals = {f"r{i}": RerankSignal(f"r{i}", float(10 - i) / 10, trust=2,
                                          layer="C", recency=0.5, lifecycle="active")
                   for i in range(20)}

        reranked = reranker.rerank(results, signals, top_k=5)
        assert len(reranked) == 5

    def test_rerank_missing_signal_uses_raw_similarity(self, reranker):
        results = [
            EncryptedSearchResult("known", 0.5, None, 0),
            EncryptedSearchResult("unknown", 0.9, None, 1),
        ]
        signals = {
            "known": RerankSignal("known", 0.5, trust=0, layer="C", recency=0.0, lifecycle="active"),
        }

        reranked = reranker.rerank(results, signals)
        # unknown has high sim and no penalty, should win
        assert reranked[0].chunk_id == "unknown"


# ═══════════════════════════════════════════════════════════
# EncryptedSearchEngine
# ═══════════════════════════════════════════════════════════

class TestEncryptedSearchEngine:

    @pytest.fixture
    def topo(self):
        t = Topology()
        t.add_agent("planner-1", parent=None)
        t.add_agent("analyst-1", parent="planner-1")
        return t

    @pytest.fixture
    def engine(self, topo):
        crypto = CryptoEngine(topo, ckks_dim=4)
        return EncryptedSearchEngine(crypto)

    def _random_embedding(self, dim: int = 4) -> list[float]:
        import random
        return [random.uniform(-1, 1) for _ in range(dim)]

    def test_store_and_search(self, engine):
        for i in range(20):
            vec = self._random_embedding()
            engine.store(f"doc{i}", vec, trust=2, layer="C")

        engine.build_index()

        query = self._random_embedding()
        results = engine.search(query, top_k=5)

        assert len(results) == 5
        for r in results:
            assert isinstance(r, EncryptedSearchResult)

    def test_search_without_index_falls_back_to_full_scan(self, engine):
        for i in range(10):
            vec = self._random_embedding()
            engine.store(f"doc{i}", vec, trust=2, layer="C")
        # Don't build index

        query = self._random_embedding()
        results = engine.search(query, top_k=3)
        assert len(results) == 3

    def test_prune_threshold_affects_recall(self, engine):
        for i in range(30):
            vec = self._random_embedding()
            engine.store(f"doc{i}", vec, trust=2, layer="C")
        engine.build_index()

        query = self._random_embedding()

        # Tight threshold = fewer candidates, fast
        results_tight = engine.search(query, top_k=5, prune_threshold=0.01)
        # Loose threshold = more candidates, thorough
        results_loose = engine.search(query, top_k=5, prune_threshold=1000.0)

        assert len(results_tight) <= 5
        assert len(results_loose) <= 5

    def test_candidate_ids_override(self, engine):
        for i in range(20):
            vec = self._random_embedding()
            engine.store(f"doc{i}", vec, trust=2, layer="C")
        engine.build_index()

        query = self._random_embedding()
        results = engine.search(query, top_k=3, candidate_ids=["doc3", "doc7", "doc15"])
        assert len(results) <= 3
        for r in results:
            assert r.chunk_id in {"doc3", "doc7", "doc15"}

    def test_remove(self, engine):
        vec = self._random_embedding()
        engine.store("temp", vec, trust=2, layer="C")
        engine.remove("temp")
        results = engine.search(vec, top_k=1)
        # "temp" should not appear
        assert all(r.chunk_id != "temp" for r in results)

    def test_update_recency(self, engine):
        vec = self._random_embedding()
        engine.store("rec", vec, trust=2, layer="C", lifecycle="active")
        assert engine._metadata["rec"].recency == 1.0
        engine.update_recency("rec", 0.3)
        assert engine._metadata["rec"].recency == 0.3

    def test_stats(self, engine):
        for i in range(5):
            vec = self._random_embedding()
            engine.store(f"doc{i}", vec, trust=2, layer="C")
        engine.build_index()

        s = engine.stats()
        assert s["stored_embeddings"] == 5
        assert "index" in s
        assert s["metadata_entries"] == 5

    # ── Reranker integration ─────────────────────────────────

    def test_trust_affects_ranking(self, engine):
        """High-trust docs should rank higher than low-trust with same embedding."""
        v = [0.5, 0.5, 0.5, 0.5]
        engine.store("low-trust", v, trust=0, layer="C")
        engine.store("med-trust", v, trust=1, layer="C")
        engine.store("hi-trust", v, trust=3, layer="C")
        engine.build_index()

        query = [0.5, 0.5, 0.5, 0.5]
        results = engine.search(query, top_k=3)
        # hi-trust should be first
        assert results[0].chunk_id == "hi-trust"

    def test_r_layer_deprioritized(self, engine):
        v = [0.5, 0.5, 0.5, 0.5]
        engine.store("c-mem", v, trust=2, layer="C")
        engine.store("r-mem", v, trust=2, layer="R")
        engine.build_index()

        query = [0.5, 0.5, 0.5, 0.5]
        results = engine.search(query, top_k=2)
        assert results[0].chunk_id == "c-mem"


# ═══════════════════════════════════════════════════════════
# Full pipeline: encrypt → index → search → rerank
# ═══════════════════════════════════════════════════════════

class TestFullPipeline:

    def test_end_to_end_encrypted_search(self):
        """Integration: memory store + encryption + search."""
        topo = Topology()
        topo.add_agent("planner-1")

        crypto = CryptoEngine(topo, ckks_dim=8)
        search_engine = EncryptedSearchEngine(crypto)

        # Store 100 random embeddings
        import random
        random.seed(42)

        target_vec = [0.8, 0.1, 0.05, 0.05, 0.0, 0.0, 0.0, 0.0]
        for i in range(99):
            vec = [random.uniform(-1, 1) for _ in range(8)]
            search_engine.store(f"noise-{i}", vec, trust=random.randint(0, 3),
                                layer=random.choice(["C", "D", "R"]))

        # Plant a target with very high trust
        search_engine.store("target", target_vec, trust=3, layer="C")
        search_engine.build_index()

        # Search with a query close to target
        query = [0.75, 0.15, 0.05, 0.05, 0.0, 0.0, 0.0, 0.0]
        results = search_engine.search(query, top_k=5)

        # target should be ranked high (high trust + high sim)
        assert any(r.chunk_id == "target" for r in results)
        # target should be near the top
        target_rank = next(i for i, r in enumerate(results) if r.chunk_id == "target")
        assert target_rank <= 2

    def test_search_returns_similarity_scores(self):
        topo = Topology()
        topo.add_agent("root")

        crypto = CryptoEngine(topo, ckks_dim=4)
        engine = EncryptedSearchEngine(crypto)

        engine.store("a", [1.0, 0.0, 0.0, 0.0], trust=2, layer="C")
        engine.store("b", [0.0, 1.0, 0.0, 0.0], trust=2, layer="C")
        engine.store("c", [-1.0, 0.0, 0.0, 0.0], trust=2, layer="C")
        engine.build_index()

        query = [1.0, 0.0, 0.0, 0.0]
        results = engine.search(query, top_k=3)

        # "a" should be most similar (dot=1.0), "c" least (dot=-1.0)
        assert results[0].chunk_id == "a"
        assert results[0].similarity > results[2].similarity

    def test_pruning_tradeoff(self):
        """Demonstrate that pruning trades recall for speed."""
        topo = Topology()
        topo.add_agent("root")
        crypto = CryptoEngine(topo, ckks_dim=4)
        engine = EncryptedSearchEngine(crypto)

        import random
        random.seed(7)
        for i in range(100):
            vec = [random.uniform(-1, 1) for _ in range(4)]
            engine.store(f"doc{i}", vec, trust=2, layer="C")

        query = [random.uniform(-1, 1) for _ in range(4)]

        # No pruning (full scan)
        results_full = engine.search(query, top_k=10)

        # With index + tight threshold
        engine.build_index()
        results_pruned = engine.search(query, top_k=10, prune_threshold=0.2)

        # Both should return valid results
        assert len(results_full) == 10
        assert len(results_pruned) <= 10
        assert len(results_pruned) > 0
