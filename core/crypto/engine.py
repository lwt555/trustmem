"""
Unified crypto engine — ties CP-ABE and CKKS to the label/PDP system.

This is the single entry point for:
  - Encrypting memory at write time (CP-ABE policy from MemoryLabel)
  - Decrypting memory at read time (attribute key check)
  - Encrypted vector search (CKKS inner product + reranking)
"""
from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Sequence

from core.labels import AgentLabel, MemoryLabel, Trust
from core.policy import agent_attributes, policy_from_label
from core.topology import Topology

from .abe import (
    ABEMasterKey, ABEPublicKey, ABEAttributeKey, Ciphertext,
    abe_setup, abe_issue_key, abe_encrypt, abe_decrypt, policy_satisfied,
    ENFORCEMENT,
)
from .ckks import (
    CKKSContext, CKKSEncryptedVector,
    ckks_setup, ckks_encode_encrypt, ckks_decrypt_decode,
    ckks_inner_product, ctx_id,
)


# ──────────────────────────────────────────────────────────────
# Search result
# ──────────────────────────────────────────────────────────────

@dataclass
class EncryptedSearchResult:
    """Result from an encrypted semantic search."""
    chunk_id: str
    similarity: float          # decrypted cosine similarity
    encrypted_score: CKKSEncryptedVector
    rank: int = -1


# ──────────────────────────────────────────────────────────────
# Crypto Engine
# ──────────────────────────────────────────────────────────────

class CryptoEngine:
    """
    Manages the full crypto lifecycle for a TrustMem deployment.

    One CryptoEngine per deployment — it holds the master key and CKKS context.
    In production, the master key would live in an HSM or KMS.
    """

    def __init__(self, topo: Topology, ckks_dim: int = 256) -> None:
        self.topo = topo
        self.ckks_dim = ckks_dim

        # Initialize ABE authority
        self.abe_mk, self.abe_pk = abe_setup()

        # Initialize CKKS context
        self.ckks_ctx = ckks_setup(poly_modulus_degree=max(8192, ckks_dim * 32))

        # Registry
        self._agent_keys: dict[str, ABEAttributeKey] = {}     # agent_id -> attribute key
        self._memory_vectors: dict[str, CKKSEncryptedVector] = {}  # chunk_id -> encrypted embedding

        # Audit log
        self._decrypt_log: list[dict] = []
        self._search_log: list[dict] = []

    # ── Agent key management ──────────────────────────────────

    def register_agent(self, agent: AgentLabel) -> ABEAttributeKey:
        """Issue attribute key for an agent. Called on agent onboarding."""
        attrs = agent_attributes(agent, self.topo)
        key = abe_issue_key(self.abe_mk, agent.agent_id, attrs, agent.epoch)
        self._agent_keys[agent.agent_id] = key
        return key

    def revoke_agent(self, agent_id: str) -> None:
        """Revoke an agent's key. New epoch key must be re-issued."""
        self._agent_keys.pop(agent_id, None)

    def get_agent_key(self, agent_id: str) -> ABEAttributeKey | None:
        return self._agent_keys.get(agent_id)

    # ── Memory encryption / decryption ────────────────────────

    def encrypt_memory(self, content: str, mem_label: MemoryLabel) -> Ciphertext:
        """
        Encrypt memory content with CP-ABE policy derived from the label.

        This is the write path: content in -> Ciphertext out -> store in DB.
        """
        policy = policy_from_label(mem_label, self.topo)
        return abe_encrypt(self.abe_pk, content, policy)

    def encrypt_content(self, content: str, policy: str) -> Ciphertext:
        """Encrypt with an explicit policy string."""
        return abe_encrypt(self.abe_pk, content, policy)

    def decrypt_memory(self, agent: AgentLabel, ct: Ciphertext | bytes | None) -> tuple[bytes | None, str]:
        """
        Attempt to decrypt a CP-ABE ciphertext using the agent's attribute key.

        Accepts either a Ciphertext object or its serialized bytes form
        (as persisted by the memory store). Returns (plaintext_bytes, audit_reason).
        """
        if ct is None:
            return b"[stub-plaintext]", "[STUB] no ciphertext (demo mode)"
        if isinstance(ct, (bytes, bytearray)):
            ct = Ciphertext.from_bytes(bytes(ct))
        key = self._agent_keys.get(agent.agent_id)
        if key is None:
            reason = f"[DENY] Agent {agent.agent_id} 未注册属性密钥"
            self._log_decrypt(agent.agent_id, ct.policy, False, reason)
            return None, reason

        # Verify epoch match — stale keys can't decrypt
        if key.epoch < agent.epoch:
            reason = f"[DENY] 密钥 epoch={key.epoch} 落后于 agent epoch={agent.epoch}"
            self._log_decrypt(agent.agent_id, ct.policy, False, reason)
            return None, reason

        ok, check_reason = policy_satisfied(ct.policy, key.attributes), ""
        if not ok:
            check_reason = f"[DENY] 属性不满足策略: {ct.policy}"
            self._log_decrypt(agent.agent_id, ct.policy, False, check_reason)
            return None, check_reason

        plain = abe_decrypt(key, ct)
        if plain is None:
            check_reason = "[DENY] 解密失败（策略不满足或密钥不匹配）"
            self._log_decrypt(agent.agent_id, ct.policy, False, check_reason)
            return None, check_reason

        self._log_decrypt(agent.agent_id, ct.policy, True, "[ALLOW] 解密成功")
        return plain, "[ALLOW] 解密成功"

    def _log_decrypt(self, agent_id: str, policy: str, allowed: bool, reason: str) -> None:
        self._decrypt_log.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "policy": policy,
            "allowed": allowed,
            "reason": reason,
        })

    # ── CKKS encrypted search ─────────────────────────────────

    def encrypt_embedding(self, vec: Sequence[float]) -> CKKSEncryptedVector:
        """Encrypt an embedding vector for storage."""
        if len(vec) != self.ckks_dim:
            raise ValueError(f"Embedding dimension {len(vec)} != {self.ckks_dim}")
        return ckks_encode_encrypt(vec, self.ckks_ctx)

    def encrypt_query(self, vec: Sequence[float]) -> CKKSEncryptedVector:
        """Encrypt a query embedding for encrypted search."""
        if len(vec) != self.ckks_dim:
            raise ValueError(f"Query dimension {len(vec)} != {self.ckks_dim}")
        return ckks_encode_encrypt(vec, self.ckks_ctx)

    def store_embedding(self, chunk_id: str, enc_vec: CKKSEncryptedVector) -> None:
        """Register an encrypted embedding for a memory chunk."""
        self._memory_vectors[chunk_id] = enc_vec

    def remove_embedding(self, chunk_id: str) -> None:
        self._memory_vectors.pop(chunk_id, None)

    def search_similar(
        self, query: CKKSEncryptedVector, top_k: int = 10,
        candidate_ids: list[str] | None = None,
    ) -> list[EncryptedSearchResult]:
        """
        Encrypted semantic search: compute inner product of encrypted query
        against all stored encrypted embeddings, then rerank by decrypted scores.

        In production, the inner product computation happens server-side on
        ciphertexts — the server never sees the query or the scores in plaintext.
        """
        t0 = time.perf_counter()

        ids = candidate_ids if candidate_ids is not None else list(self._memory_vectors.keys())
        raw: list[tuple[str, float, CKKSEncryptedVector]] = []

        for cid in ids:
            enc_vec = self._memory_vectors.get(cid)
            if enc_vec is None:
                continue
            enc_score = ckks_inner_product(query, enc_vec, self.ckks_ctx)
            score_vals = ckks_decrypt_decode(enc_score, self.ckks_ctx)
            cosine = float(score_vals[0]) if score_vals else 0.0
            raw.append((cid, cosine, enc_score))

        # Sort by similarity descending
        raw.sort(key=lambda x: x[1], reverse=True)
        top = raw[:top_k]

        elapsed_ms = (time.perf_counter() - t0) * 1000
        self._search_log.append({
            "ts": datetime.now(timezone.utc).isoformat(),
            "top_k": top_k,
            "candidates": len(ids),
            "returned": len(top),
            "elapsed_ms": elapsed_ms,
        })

        return [
            EncryptedSearchResult(chunk_id=cid, similarity=score, encrypted_score=es, rank=i)
            for i, (cid, score, es) in enumerate(top)
        ]

    @property
    def decrypt_log(self) -> list[dict]:
        return list(self._decrypt_log)

    @property
    def search_log(self) -> list[dict]:
        return list(self._search_log)

    def stats(self) -> dict:
        return {
            "registered_agents": len(self._agent_keys),
            "stored_embeddings": len(self._memory_vectors),
            "ckks_dimension": self.ckks_dim,
            "ckks_context_id": ctx_id(self.ckks_ctx),
            "total_decrypts": len(self._decrypt_log),
            "total_searches": len(self._search_log),
            "abe_enforcement": ENFORCEMENT,
        }
