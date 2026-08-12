"""
CryptoClient — 解密账本（F-12）。

"先判决，后解密"从"代码是这么写的"变成"没有 ALLOW 裁决凭证就解不了密"。
每次解密都必须携带 decision_id，且该 id 必须已登记为 ALLOW。
解密调用次数 == ALLOW 数，是答辩现场可复现的硬证据（验收清单第 7 条）。
"""
from __future__ import annotations

from dataclasses import dataclass, field


class DecisionLedger:
    """裁决凭证登记表。只有显式 register 的 decision_id 才允许解密。"""

    def __init__(self) -> None:
        self._allowed: dict[str, str] = {}   # decision_id -> chunk_id

    def record(self, decision_id: str, chunk_id: str) -> None:
        self._allowed[decision_id] = chunk_id

    def is_allowed(self, decision_id: str) -> bool:
        return decision_id in self._allowed


class CryptoClient:
    """包装 crypto engine，强制"先判决后解密"。

    - `decrypt` 要求 decision_id 已在 ledger 中登记为 ALLOW，否则 PermissionError。
    - `decrypt_count` 即 ALLOW 且实际走到解密的次数，用于演示。
    """

    def __init__(self, engine) -> None:
        self._engine = engine
        self._ledger = DecisionLedger()
        self._decrypt_count = 0
        self.decrypted_ids: set[str] = set()

    def record_allow(self, decision_id: str, chunk_id: str) -> None:
        self._ledger.record(decision_id, chunk_id)

    def is_allowed(self, decision_id: str) -> bool:
        return self._ledger.is_allowed(decision_id)

    def decrypt(self, agent, ct_bytes, decision_id: str):
        if not self._ledger.is_allowed(decision_id):
            raise PermissionError("无 ALLOW 裁决凭证，拒绝解密")
        self._decrypt_count += 1
        result = self._engine.decrypt_memory(agent, ct_bytes)
        # result may be (plaintext, reason) tuple
        return result

    def reset_count(self) -> None:
        self._decrypt_count = 0
        self.decrypted_ids.clear()

    @property
    def decrypt_count(self) -> int:
        return self._decrypt_count
