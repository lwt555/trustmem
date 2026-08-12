"""F-09 验收：I13 任务区间单调收紧 + scope_hash 链上承诺校验。"""
from __future__ import annotations

import pytest

from core.labels import Clearance, Trust, IngestMode, TaskScope
from core.merkle import MerkleStore
from core.task_scope import commit_scope, verify_scope_against_chain


def _scope(c=Clearance.L3_SECRET, t=Trust.T0_UNTRUSTED) -> TaskScope:
    return TaskScope("t", c, t, IngestMode.LEARN)


# ── 单元：widen 永远抛异常 ─────────────────────────────────────

def test_F09_widen_always_raises():
    scope = _scope()
    with pytest.raises(PermissionError):
        scope.widen(Clearance.L3_SECRET, Trust.T0_UNTRUSTED, scope.scope_hash)


# ── 单元：narrow 只能收紧 ─────────────────────────────────────

def test_F09_narrow_only_tightens():
    scope = _scope(Clearance.L2_SENSITIVE, Trust.T1_LOW)
    tighter = scope.narrow(Clearance.L1_INTERNAL, Trust.T3_HIGH)
    assert tighter.c_ctx_max <= scope.c_ctx_max
    assert tighter.t_ctx_min >= scope.t_ctx_min
    # lineage：parent_hash 指向原清单
    assert tighter.parent_hash == scope.scope_hash
    assert tighter.scope_hash != scope.scope_hash

    with pytest.raises(PermissionError):
        scope.narrow(Clearance.L3_SECRET, Trust.T0_UNTRUSTED)  # c 变大 → 拒绝
    with pytest.raises(PermissionError):
        scope.narrow(Clearance.L1_INTERNAL, Trust.T0_UNTRUSTED)  # t 变小 → 拒绝


# ── 模块：scope_hash 与链上承诺对拍 ────────────────────────────

def test_F09_scope_hash_chain_verification():
    store = MerkleStore()
    scope = _scope()
    assert not verify_scope_against_chain(scope, store)  # 未上链
    commit_scope(scope, store)
    assert verify_scope_against_chain(scope, store)  # 已上链

    # narrow 后 lineage 仍可校验（parent_hash 指向已承诺清单）
    narrower = scope.narrow(Clearance.L1_INTERNAL, Trust.T1_LOW)
    assert verify_scope_against_chain(narrower, store)

    # 伪造 hash → 拒绝
    forged = _scope()
    forged.scope_hash = "deadbeef" * 2
    forged.parent_hash = ""
    assert not verify_scope_against_chain(forged, store)


# ── 集成：读管线对伪造 scope 全 DENY ───────────────────────────

def test_F09_scope_hash_mismatch_denies_everything():
    from core.labels import AgentLabel, Role, MemoryType, Layer, MemoryLabel
    from core.session import Session
    from core.pdp import PDP
    from core.topology import Topology
    from core.pipeline import ReadPipeline
    from core.verdict import Verdict

    class _Store:
        def get(self, chunk_id):
            return None
        def get_ciphertext(self, chunk_id):
            return None
        def put(self, mem, ciphertext=None):
            pass
        def list_by_task(self, task_id):
            return []

    class _Audit:
        def __init__(self):
            self.events = []
        def log(self, decision):
            self.events.append(decision)

    topo = Topology()
    topo.add_agent("a")
    agent = AgentLabel("a", Role.ANALYST, Clearance.L2_SENSITIVE, Trust.T2_MEDIUM,
                       task_domain={"t"}, epoch=1)
    sess = Session.start("s1", agent, "t")

    anchor = MerkleStore()
    good = TaskScope("t", Clearance.L3_SECRET, Trust.T0_UNTRUSTED)
    commit_scope(good, anchor)

    forged = TaskScope("t", Clearance.L3_SECRET, Trust.T0_UNTRUSTED)
    forged.scope_hash = "deadbeef" * 2

    pipe = ReadPipeline(PDP(topo), None, _Store(), _Audit())
    r = pipe.read(agent=agent, session=sess, chunk_id="mem-x", scope=forged, anchor=anchor)
    assert r.decision.verdict is Verdict.DENY
    assert r.denied_by == "ScopeCommitMismatch"
