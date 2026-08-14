"""F-12 验收：先判决后解密 —— decrypt 调用次数 == ALLOW 数。

解密必须携带 decision_id，且该 id 已登记为 ALLOW，否则 PermissionError。
HIDE / DENY 的记忆块从未被解密。
"""
from __future__ import annotations

import pytest

from core.labels import (AgentLabel, MemoryLabel, Clearance, Trust, Layer,
                         MemoryType, Role, TaskScope)
from core.session import Session
from core.topology import Topology
from core.pdp import PDP
from core.verdict import Verdict
from core.pipeline import ReadPipeline
from core.varstore import VarStore
from ifc.crypto_client import CryptoClient, DecisionLedger


def _agent(**kw) -> AgentLabel:
    defaults = dict(agent_id="analyst", role=Role.ANALYST,
                    clearance=Clearance.L2_SENSITIVE, trust_intrinsic=Trust.T2_MEDIUM,
                    task_domain={"task-x"}, collab_group={"grp"})
    return AgentLabel(**(defaults | kw))


def _mem(**kw) -> MemoryLabel:
    defaults = dict(chunk_id="m", sensitivity=Clearance.L2_SENSITIVE,
                    provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                    memory_type=MemoryType.INTEL, owner_agent="owner",
                    task_binding="task-x", collab_group={"grp"})
    return MemoryLabel(**(defaults | kw))


class _StubEngine:
    """真实 CP-ABE 的替身：只验证 decrypt 是否被调用，返回固定明文。"""

    def __init__(self):
        self.calls = 0

    def decrypt_memory(self, agent, ct_bytes):
        self.calls += 1
        return b"decrypted-content", "[ALLOW] 解密成功"


class _MemStore:
    def __init__(self, mems: dict[str, MemoryLabel]):
        self._m = mems

    def get(self, cid):
        return self._m.get(cid)

    def get_ciphertext(self, cid):
        return b"ct-bytes" if cid in self._m else None


class _Audit:
    def log(self, d):
        pass


# ── CryptoClient 单元 ──────────────────────────────────────────

def test_F12_decrypt_without_decision_id_is_refused():
    engine = _StubEngine()
    client = CryptoClient(engine)
    with pytest.raises(PermissionError):
        client.decrypt(object(), b"ct", "forged-id")
    assert engine.calls == 0, "未登记裁决凭证不得触发底层解密"


def test_F12_ledger_gates_decrypt():
    client = CryptoClient(_StubEngine())
    client.record_allow("dec-1", "m1")
    assert client.is_allowed("dec-1")
    assert not client.is_allowed("dec-2")
    client.decrypt(object(), b"ct", "dec-1")  # 不抛
    assert client.decrypt_count == 1


# ── ReadPipeline 集成 ─────────────────────────────────────────

def test_F12_decrypt_count_equals_allow_count():
    engine = _StubEngine()
    client = CryptoClient(engine)
    pdp = PDP(Topology())
    agent = _agent()

    allow_mem = _mem(chunk_id="allow")
    hide_mem = _mem(chunk_id="hide", sensitivity=Clearance.L3_SECRET)  # 需 scope 隐藏
    deny_mem = _mem(chunk_id="deny", sensitivity=Clearance.L3_SECRET)

    store = _MemStore({allow_mem.chunk_id: allow_mem, deny_mem.chunk_id: deny_mem})
    pipe = ReadPipeline(pdp, engine, store, _Audit(), VarStore(), client)
    sess = Session.start("s", agent, "task-x")

    # ALLOW：analyst 读自己密级内的 L2 记忆
    r1 = pipe.read(agent=agent, session=sess, chunk_id=allow_mem.chunk_id,
                   scope=TaskScope("task-x", Clearance.L3_SECRET, Trust.T0_UNTRUSTED))
    assert r1.decision.verdict is Verdict.ALLOW
    assert r1.plaintext == b"decrypted-content"
    assert client.decrypt_count == 1

    # DENY：读 L3 记忆（硬拒绝），不得解密
    r2 = pipe.read(agent=agent, session=sess, chunk_id=deny_mem.chunk_id,
                   scope=TaskScope("task-x", Clearance.L3_SECRET, Trust.T0_UNTRUSTED))
    assert r2.decision.verdict is Verdict.DENY
    assert r2.plaintext is None
    assert client.decrypt_count == 1, "DENY 不得触发解密"
    assert engine.calls == 1


def test_F12_hidden_chunks_never_decrypted():
    from core.labels import TaskScope
    engine = _StubEngine()
    client = CryptoClient(engine)
    pdp = PDP(Topology())
    agent = _agent()

    hide_mem = _mem(chunk_id="hide", sensitivity=Clearance.L2_SENSITIVE)
    store = _MemStore({hide_mem.chunk_id: hide_mem})
    pipe = ReadPipeline(pdp, engine, store, _Audit(), VarStore(), client)
    sess = Session.start("s", agent, "task-x")

    r = pipe.read(agent=agent, session=sess, chunk_id=hide_mem.chunk_id,
                  scope=TaskScope("t", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED))
    assert r.decision.verdict is Verdict.HIDE
    assert r.plaintext is None
    assert client.decrypt_count == 0, "HIDE 记忆块从未被解密"
    assert engine.calls == 0
