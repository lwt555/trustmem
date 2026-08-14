"""
人工背书门组件 (Human Endorser)
================================
把「背书门」（core/upgrader.py 的 TR11–TR14）接到真实运行链路上的唯一入口。

背书门是 Biba 模型里**唯一被允许打破单调下降**的特权组件。这里的职责是：
  1. 用「人」的私钥对研判结论的 chunk_id 做 ECDSA 签名（F-14：不可抵赖）
  2. 以 HUMAN 证据调用 upgrader.try_upgrade —— T1 直升 T3
  3. 把提升出的新版本 chunk（upgraded_from 指向原件）落库，原件不动（F-19）

结果：executor 读到的是 T3 的背书结论，而非 T1 的原始研判。这就是
「双门」演示的第一道门 —— 背书门；第二道门是 can_invoke 的 HITL（CONFIRM）。
"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .labels import MemoryLabel
from .upgrader import Upgrader, Evidence, EvidenceType, UpgradeResult
from ifc import writer_sign


class HumanEndorser:
    """背书门：人持私钥签名 → HUMAN 证据直升 T3 → 新 chunk 落库。"""

    def __init__(self, mem_store) -> None:
        self._upgrader = Upgrader()
        self._mem_store = mem_store
        # 人的密钥对：私钥只在本组件内，公钥用于验签。
        self._priv, self._pub = writer_sign.generate_keypair()

    def _sign(self, chunk_id: str) -> str:
        sig = self._priv.sign(chunk_id.encode(), ec.ECDSA(hashes.SHA256()))
        return sig.hex()

    def _verify(self, signature: str, chunk_id: str) -> bool:
        try:
            self._pub.verify(bytes.fromhex(signature), chunk_id.encode(),
                             ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def endorse(self, mem: MemoryLabel, ct_bytes: bytes) -> UpgradeResult | None:
        """对一条研判结论做人工背书。成功返回 UpgradeResult（含 T3 新版 chunk），
        落库后返回；失败（验签不过 / 证据不足）返回 None。

        原件不动，仅新增 upgraded_from 指向原件的 T3 版本（F-19）。
        """
        ev = Evidence(etype=EvidenceType.HUMAN,
                      human_signature=self._sign(mem.chunk_id))
        result = self._upgrader.try_upgrade(mem, ev, sig_verifier=self._verify)
        if not result.applied:
            return None
        self._mem_store.put(result.new_chunk, ct_bytes)
        return result
