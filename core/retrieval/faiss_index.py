"""FAISS index wrapper for vector storage and similarity search."""
from __future__ import annotations

import logging
import os
import pickle
from dataclasses import dataclass

_log = logging.getLogger(__name__)


@dataclass
class SearchHit:
    chunk_id: str
    score: float


class FAISSIndex:
    """FAISS-backed vector index for memory embeddings.

    Uses IndexFlatIP (inner product) for exact search.
    Falls back to an in-memory brute-force implementation if faiss-cpu is not installed.
    """

    def __init__(self, dimension: int) -> None:
        self._dim = dimension
        self._id_to_chunk: dict[int, str] = {}
        self._chunk_to_id: dict[str, int] = {}
        self._next_id = 0
        self._vectors: dict[int, list[float]] = {}
        self._index: object | None = None
        self._init_faiss()

    def _init_faiss(self) -> None:
        try:
            import faiss
            self._index = faiss.IndexFlatIP(self._dim)
        except ImportError:
            self._index = None

    def add(self, chunk_id: str, embedding: list[float]) -> None:
        if len(embedding) != self._dim:
            raise ValueError(f"Embedding dim {len(embedding)} != {self._dim}")

        if chunk_id in self._chunk_to_id:
            self.remove(chunk_id)

        idx = self._next_id
        self._next_id += 1
        self._chunk_to_id[chunk_id] = idx
        self._id_to_chunk[idx] = chunk_id
        self._vectors[idx] = list(embedding)

        if self._index is not None:
            import numpy as np
            vec_arr = np.array([embedding], dtype=np.float32)
            self._index.add(vec_arr)

    def remove(self, chunk_id: str) -> None:
        idx = self._chunk_to_id.pop(chunk_id, None)
        if idx is not None:
            self._id_to_chunk.pop(idx, None)
            self._vectors.pop(idx, None)

    def search(self, query_embedding: list[float], top_k: int = 10) -> list[SearchHit]:
        if len(query_embedding) != self._dim:
            raise ValueError(f"Query dim {len(query_embedding)} != {self._dim}")

        if self._index is not None and len(self._vectors) > 0:
            import numpy as np
            q = np.array([query_embedding], dtype=np.float32)
            try:
                import faiss
                scores, indices = self._index.search(q, min(top_k, self._index.ntotal))
                hits = []
                for score, idx in zip(scores[0], indices[0]):
                    if idx < 0:
                        continue
                    cid = self._id_to_chunk.get(int(idx))
                    if cid:
                        hits.append(SearchHit(cid, float(score)))
                return hits
            except Exception:
                _log.debug("FAISS search failed, falling back to brute-force",
                          exc_info=True)

        return self._brute_force(query_embedding, top_k)

    def _brute_force(self, query: list[float], top_k: int) -> list[SearchHit]:
        scores: list[tuple[str, float]] = []
        for idx, vec in self._vectors.items():
            cid = self._id_to_chunk.get(idx)
            if cid is None:
                continue
            score = sum(a * b for a, b in zip(query, vec))
            scores.append((cid, score))
        scores.sort(key=lambda x: x[1], reverse=True)
        return [SearchHit(cid, s) for cid, s in scores[:top_k]]

    def save(self, path: str) -> None:
        data = {
            "dim": self._dim,
            "next_id": self._next_id,
            "id_to_chunk": self._id_to_chunk,
            "chunk_to_id": self._chunk_to_id,
            "vectors": self._vectors,
        }
        with open(path, "wb") as f:
            pickle.dump(data, f)

    def load(self, path: str) -> None:
        with open(path, "rb") as f:
            data = pickle.load(f)
        self._dim = data["dim"]
        self._next_id = data["next_id"]
        self._id_to_chunk = data["id_to_chunk"]
        self._chunk_to_id = data["chunk_to_id"]
        self._vectors = data["vectors"]
        self._init_faiss()
        if self._index is not None:
            import numpy as np
            for idx in sorted(self._vectors.keys()):
                vec_arr = np.array([self._vectors[idx]], dtype=np.float32)
                self._index.add(vec_arr)

    @property
    def size(self) -> int:
        return len(self._vectors)

    def clear(self) -> None:
        self._id_to_chunk.clear()
        self._chunk_to_id.clear()
        self._vectors.clear()
        self._init_faiss()
