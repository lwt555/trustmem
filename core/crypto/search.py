"""
Encrypted semantic search with hierarchical clustering and client-side reranking.

Pipeline:
  1. Server: Hierarchical cluster pruning on encrypted embeddings
  2. Server: CKKS inner product on surviving candidates
  3. Client: Decrypt scores + multi-factor rerank (trust, recency, layer)

This keeps the server blind to query intent while achieving sub-linear scaling.
"""
from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Sequence

from .ckks import (
    CKKSContext, CKKSEncryptedVector,
    ckks_encode_encrypt, ckks_decrypt_decode,
    ckks_inner_product, ckks_sub, ckks_sum, ckks_square, ckks_add,
)
from .engine import CryptoEngine, EncryptedSearchResult


# ──────────────────────────────────────────────────────────────
# Hierarchical Clustering Index
# ──────────────────────────────────────────────────────────────

@dataclass
class ClusterNode:
    """Node in the hierarchical clustering tree."""
    centroid: CKKSEncryptedVector | None   # None for leaves
    radius: float                          # max dist from centroid to members
    children: list[str] = field(default_factory=list)    # chunk_ids at leaf
    left: "ClusterNode | None" = None
    right: "ClusterNode | None" = None
    size: int = 0

    @property
    def is_leaf(self) -> bool:
        return self.left is None and self.right is None


class HierarchicalIndex:
    """
    Bottom-up agglomerative clustering on encrypted embeddings.

    Builds a binary tree where each internal node stores an encrypted centroid.
    Search prunes branches whose centroid-to-query distance exceeds a threshold.
    """

    def __init__(self, branching: int = 2, leaf_capacity: int = 32) -> None:
        self.branching = branching
        self.leaf_capacity = leaf_capacity
        self.root: ClusterNode | None = None
        self._chunk_map: dict[str, ClusterNode] = {}   # chunk_id -> leaf node

    # ── Build ────────────────────────────────────────────────

    def build(self, embeddings: dict[str, CKKSEncryptedVector],
              ctx: CKKSContext) -> None:
        """Build the clustering tree from a set of encrypted embeddings."""
        if not embeddings:
            return

        items = list(embeddings.items())
        self.root = self._build_recursive(items, ctx)

    def _build_recursive(
        self, items: list[tuple[str, CKKSEncryptedVector]], ctx: CKKSContext,
    ) -> ClusterNode:
        if len(items) <= self.leaf_capacity:
            centroid = self._compute_centroid([v for _, v in items], ctx)
            radius = self._max_distance(centroid, [v for _, v in items], ctx)
            node = ClusterNode(
                centroid=centroid, radius=radius,
                children=[cid for cid, _ in items], size=len(items),
            )
            for cid in node.children:
                self._chunk_map[cid] = node
            return node

        # k-means-like split into two groups
        left_items, right_items = self._split(items, ctx)

        left = self._build_recursive(left_items, ctx)
        right = self._build_recursive(right_items, ctx)

        all_centroids = []
        if left.centroid:
            all_centroids.append(left.centroid)
        if right.centroid:
            all_centroids.append(right.centroid)

        centroid = self._compute_centroid(all_centroids, ctx) if all_centroids else None

        # Radius: max distance to any leaf centroid
        radius = 0.0
        for v in [left.centroid, right.centroid]:
            if v and centroid:
                d = self._euclidean_dist(centroid, v, ctx)
                if d > radius:
                    radius = d
        radius = max(radius, left.radius, right.radius)

        return ClusterNode(
            centroid=centroid, radius=radius,
            children=[], left=left, right=right,
            size=len(items),
        )

    def _split(self, items: list[tuple[str, CKKSEncryptedVector]],
               ctx: CKKSContext) -> tuple[list, list]:
        """Simple random-projection split. Encrypted, so can't use plaintext k-means."""
        # Pick two random seeds
        idx_a = random.randrange(len(items))
        idx_b = random.randrange(len(items))
        if idx_b == idx_a:
            idx_b = (idx_a + 1) % len(items)

        _, seed_a = items[idx_a]
        _, seed_b = items[idx_b]

        left, right = [], []
        for cid, vec in items:
            da = self._euclidean_sq(vec, seed_a, ctx)
            db = self._euclidean_sq(vec, seed_b, ctx)
            if da <= db:
                left.append((cid, vec))
            else:
                right.append((cid, vec))

        # Avoid degenerate split
        if not left:
            mid = len(right) // 2
            left = right[:mid]
            right = right[mid:]
        elif not right:
            mid = len(left) // 2
            right = left[mid:]
            left = left[:mid]

        return left, right

    # ── Search ────────────────────────────────────────────────

    def search(self, query: CKKSEncryptedVector,
               ctx: CKKSContext, top_k: int = 10,
               prune_threshold: float = 0.3) -> list[str]:
        """
        Pruned hierarchical search. Returns candidate chunk_ids.

        The prune_threshold controls aggressiveness: higher = more pruning,
        but may miss relevant results. 0.3 is a good default for cosine space.
        """
        if self.root is None:
            return []

        candidates: list[str] = []
        self._search_node(query, self.root, ctx, prune_threshold, candidates, top_k)
        return candidates

    def _search_node(self, query: CKKSEncryptedVector, node: ClusterNode,
                     ctx: CKKSContext, threshold: float,
                     out: list[str], top_k: int) -> None:
        if node.is_leaf:
            out.extend(node.children)
            return

        # Check which child centroids are close enough
        scored: list[tuple[float, ClusterNode]] = []
        for child in (node.left, node.right):
            if child is None or child.centroid is None:
                continue
            dist = self._euclidean_dist(query, child.centroid, ctx)
            # Prune if centroid is too far
            if dist <= threshold + child.radius:
                scored.append((dist, child))

        # Search closest first (best-first), collect from all qualifying children
        scored.sort(key=lambda x: x[0])
        for _, child in scored:
            self._search_node(query, child, ctx, threshold, out, top_k)

    # ── Distance helpers ──────────────────────────────────────

    def _compute_centroid(self, vectors: list[CKKSEncryptedVector],
                          ctx: CKKSContext) -> CKKSEncryptedVector:
        """Compute element-wise mean of encrypted vectors."""
        if not vectors:
            raise ValueError("Empty vector list")

        # Sum all vectors homomorphically
        acc = vectors[0]
        for v in vectors[1:]:
            acc = ckks_add(acc, v, ctx)

        # Divide by count (scale by 1/n)
        n = len(vectors)
        scalar = 1.0 / n
        from .ckks import ckks_scale
        return ckks_scale(acc, scalar, ctx)

    def _euclidean_sq(self, a: CKKSEncryptedVector, b: CKKSEncryptedVector,
                      ctx: CKKSContext) -> float:
        """Compute squared Euclidean distance (decrypted)."""
        diff = ckks_sub(a, b, ctx)
        sq = ckks_square(diff, ctx)
        s = ckks_sum(sq, ctx)
        vals = ckks_decrypt_decode(s, ctx)
        return float(vals[0]) if vals else 0.0

    def _euclidean_dist(self, a: CKKSEncryptedVector, b: CKKSEncryptedVector,
                        ctx: CKKSContext) -> float:
        return math.sqrt(max(0.0, self._euclidean_sq(a, b, ctx)))

    def _max_distance(self, centroid: CKKSEncryptedVector | None,
                      vectors: list[CKKSEncryptedVector],
                      ctx: CKKSContext) -> float:
        if centroid is None or not vectors:
            return 0.0
        return max(self._euclidean_dist(centroid, v, ctx) for v in vectors)

    # ── Stats ─────────────────────────────────────────────────

    def stats(self) -> dict:
        if self.root is None:
            return {"nodes": 0, "depth": 0, "leaves": 0}

        def _count(n: ClusterNode) -> tuple[int, int, int]:
            if n.is_leaf:
                return 1, 1, 1
            ln, ld, ll = _count(n.left) if n.left else (0, 0, 0)
            rn, rd, rl = _count(n.right) if n.right else (0, 0, 0)
            return 1 + ln + rn, 1 + max(ld, rd), ll + rl

        nodes, depth, leaves = _count(self.root)
        return {"nodes": nodes, "depth": depth, "leaves": leaves}


# ──────────────────────────────────────────────────────────────
# Client-side Reranker
# ──────────────────────────────────────────────────────────────

@dataclass
class RerankSignal:
    """Per-chunk metadata for client-side reranking."""
    chunk_id: str
    similarity: float              # encrypted inner product score
    trust: int                     # provenance_trust (T0-T3)
    layer: str                     # D/C/R
    recency: float                 # normalized recency score 0-1
    lifecycle: str                 # active/archived/revoked


class Reranker:
    """
    Multi-factor reranker. After server returns top candidates by encrypted
    similarity, the client re-ranks using plaintext metadata signals.

    Default weights balance semantic relevance with trust and recency.
    """

    def __init__(self, w_sim: float = 0.40, w_trust: float = 0.35,
                 w_recency: float = 0.15, w_layer: float = 0.10) -> None:
        total = w_sim + w_trust + w_recency + w_layer
        self.w_sim = w_sim / total
        self.w_trust = w_trust / total
        self.w_recency = w_recency / total
        self.w_layer = w_layer / total

    def rerank(self, results: list[EncryptedSearchResult],
               signals: dict[str, RerankSignal],
               top_k: int = 10) -> list[EncryptedSearchResult]:
        """
        Re-rank search results using metadata signals.

        signals dict is keyed by chunk_id. Results without signals keep
        their raw similarity rank.
        """
        scored: list[tuple[float, EncryptedSearchResult]] = []

        for r in results:
            sig = signals.get(r.chunk_id)
            if sig is None:
                scored.append((r.similarity, r))
                continue

            # Normalize similarity to 0-1 (already cosine-like)
            sim_norm = max(0.0, min(1.0, (r.similarity + 1.0) / 2.0))

            # Trust: T3 = 1.0, T0 = 0.0
            trust_norm = sig.trust / 3.0

            # Layer bonus: C layer gets slight boost (most useful), R layer penalty
            layer_score = {"C": 0.8, "D": 0.6, "R": 0.3}.get(sig.layer, 0.5)

            score = (self.w_sim * sim_norm +
                     self.w_trust * trust_norm +
                     self.w_recency * sig.recency +
                     self.w_layer * layer_score)

            scored.append((score, r))

        scored.sort(key=lambda x: x[0], reverse=True)
        reranked = [r for _, r in scored[:top_k]]
        for i, r in enumerate(reranked):
            r.rank = i
        return reranked


# ──────────────────────────────────────────────────────────────
# Search Engine (orchestrates index + CryptoEngine + reranker)
# ──────────────────────────────────────────────────────────────

class EncryptedSearchEngine:
    """
    Full encrypted search pipeline.

    Onboarding:
      1. Register agent with CryptoEngine (attribute key)
      2. Store embeddings via store_embedding()
      3. Build index

    Query:
      1. encrypt_query(vec) → insert into pipeline
      2. search(query) → prune with HierarchicalIndex → CKKS inner product
      3. collect RerankSignal from DB → reranker.rerank()
      4. return top_k with decrypted scores
    """

    def __init__(self, crypto_engine: CryptoEngine,
                 reranker: Reranker | None = None) -> None:
        self.crypto = crypto_engine
        self.index = HierarchicalIndex()
        self.reranker = reranker or Reranker()

        # Metadata registry (in production, fetched from DB)
        self._metadata: dict[str, RerankSignal] = {}

    # ── Index management ──────────────────────────────────────

    def build_index(self) -> None:
        """Build/reindex the hierarchical clustering tree."""
        self.index.build(self.crypto._memory_vectors, self.crypto.ckks_ctx)

    def rebuild(self) -> None:
        """Force full rebuild."""
        self.index = HierarchicalIndex()
        self.build_index()

    # ── Embedding management ──────────────────────────────────

    def store(self, chunk_id: str, embedding: list[float],
              trust: int, layer: str, lifecycle: str = "active") -> None:
        """Store an embedding with metadata for reranking."""
        enc = self.crypto.encrypt_embedding(embedding)
        self.crypto.store_embedding(chunk_id, enc)

        self._metadata[chunk_id] = RerankSignal(
            chunk_id=chunk_id,
            similarity=0.0,
            trust=trust,
            layer=layer,
            recency=1.0,    # just stored = most recent
            lifecycle=lifecycle,
        )

    def remove(self, chunk_id: str) -> None:
        self.crypto.remove_embedding(chunk_id)
        self._metadata.pop(chunk_id, None)

    def update_recency(self, chunk_id: str, recency: float) -> None:
        """Update recency score (e.g., based on last access time)."""
        if chunk_id in self._metadata:
            self._metadata[chunk_id].recency = max(0.0, min(1.0, recency))

    # ── Search ────────────────────────────────────────────────

    def search(self, query_vec: list[float], top_k: int = 10,
               prune_threshold: float = 0.3,
               candidate_ids: list[str] | None = None,
               ) -> list[EncryptedSearchResult]:
        """
        Full encrypted search pipeline:
          1. Encrypt query vector
          2. Hierarchical pruning (optional, via candidate_ids override)
          3. CKKS inner product on survivors
          4. Client-side rerank

        Set prune_threshold higher for faster but coarser search.
        """
        t0 = time.perf_counter()

        # 1. Encrypt query
        enc_query = self.crypto.encrypt_query(query_vec)

        # 2. Hierarchical pruning
        if candidate_ids is None and self.index.root is not None:
            pruned = self.index.search(enc_query, self.crypto.ckks_ctx,
                                       top_k, prune_threshold)
            if pruned:
                candidate_ids = pruned

        # 3. CKKS inner product search
        results = self.crypto.search_similar(enc_query, top_k=max(top_k * 3, 30),
                                             candidate_ids=candidate_ids)

        # 4. Rerank
        results = self.reranker.rerank(results, self._metadata, top_k)

        elapsed_ms = (time.perf_counter() - t0) * 1000

        return results

    # ── Stats ─────────────────────────────────────────────────

    def stats(self) -> dict:
        base = self.crypto.stats()
        base["index"] = self.index.stats()
        base["metadata_entries"] = len(self._metadata)
        return base
