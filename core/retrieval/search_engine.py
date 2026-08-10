"""Semantic search engine — embed → FAISS → PDP filter → return allowed results."""
from __future__ import annotations

from dataclasses import dataclass, field

from core.labels import AgentLabel, MemoryLabel, Trust
from core.pdp import PDP, Decision, Check
from core.session import Session

from .embeddings import EmbeddingBackend
from .faiss_index import FAISSIndex


@dataclass
class SearchResult:
    chunk_id: str
    score: float
    memory: MemoryLabel | None = None
    decision: Decision | None = None
    allowed: bool = False
    checks: list[Check] = field(default_factory=list)


class MemoryStoreProto:
    """Protocol for memory store — duck-typing compatible with existing stores."""
    def get(self, chunk_id: str) -> MemoryLabel | None: ...  # noqa: E704


class SearchEngine:
    """Full semantic search pipeline: embed → FAISS → PDP filter.

    Only returns memories that pass PDP can_read checks for the given agent.
    """

    def __init__(
        self,
        embedding: EmbeddingBackend,
        index: FAISSIndex,
        pdp: PDP,
        agent: AgentLabel,
        session: Session,
        mem_store,
    ) -> None:
        self._embedding = embedding
        self._index = index
        self._pdp = pdp
        self._agent = agent
        self._session = session
        self._mem_store = mem_store

    def index_memory(self, chunk_id: str, content: str) -> None:
        vec = self._embedding.embed(content)
        self._index.add(chunk_id, vec)

    def remove_memory(self, chunk_id: str) -> None:
        self._index.remove(chunk_id)

    def search(self, query: str, top_k: int = 10,
               scope=None) -> list[SearchResult]:
        query_vec = self._embedding.embed(query)
        hits = self._index.search(query_vec, top_k=min(top_k, 100))

        results: list[SearchResult] = []
        for hit in hits:
            mem = self._mem_store.get(hit.chunk_id)
            if mem is None:
                continue

            if scope is not None:
                decision = self._pdp.can_read_scoped(
                    self._agent, mem, self._session, scope)
            else:
                decision = self._pdp.can_read(
                    self._agent, mem, self._session)

            allowed = decision.verdict.value == "ALLOW"

            results.append(SearchResult(
                chunk_id=hit.chunk_id,
                score=hit.score,
                memory=mem,
                decision=decision,
                allowed=allowed,
                checks=list(decision.checks),
            ))

        # ALLOW first, then by score
        results.sort(key=lambda r: (not r.allowed, -r.score))
        return results

    @property
    def index_size(self) -> int:
        return self._index.size
