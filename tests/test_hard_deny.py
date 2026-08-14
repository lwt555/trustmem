"""F-01 验收：无读上是硬拒绝（DENY），不可 HIDE，不产生 VarHandle。

硬拒绝规则集 HARD_DENY_RULES 命中即无条件 DENY 且 hideable=False：
BLP-SimpleSecurity / NeedToKnow / CognitiveLayer / TTL / Epoch / Lifecycle。
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from core.labels import (AgentLabel, MemoryLabel, Clearance, Trust, Layer,
                         MemoryType, Role, TaskScope)
from core.session import Session
from core.topology import Topology
from core.pdp import PDP
from core.verdict import Verdict


def _agent(**kw) -> AgentLabel:
    defaults = dict(agent_id="a", role=Role.ANALYST, clearance=Clearance.L2_SENSITIVE,
                    trust_intrinsic=Trust.T2_MEDIUM, task_domain={"task-x"},
                    collab_group={"grp"})
    return AgentLabel(**(defaults | kw))


def _mem(**kw) -> MemoryLabel:
    defaults = dict(chunk_id="m", sensitivity=Clearance.L2_SENSITIVE,
                    provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                    memory_type=MemoryType.INTEL, owner_agent="owner",
                    task_binding="task-x", collab_group={"grp"})
    return MemoryLabel(**(defaults | kw))


def test_F01_no_read_up_is_hard_deny():
    pdp = PDP(Topology())
    low = _agent(agent_id="low", clearance=Clearance.L0_PUBLIC)
    mem = _mem(sensitivity=Clearance.L3_SECRET)
    sess = Session.start("s", low, "task-x")
    d = pdp.can_read(low, mem, sess)
    assert d.verdict is Verdict.DENY
    assert d.hideable is False
    assert d.denied_by == "BLP-SimpleSecurity"


def test_F01_need_to_know_is_hard_deny():
    pdp = PDP(Topology())
    agent = _agent(agent_id="a", clearance=Clearance.L3_SECRET)  # 密级够，但 task 不符
    mem = _mem(sensitivity=Clearance.L2_SENSITIVE, task_binding="other-task")
    sess = Session.start("s", agent, "task-x")
    d = pdp.can_read(agent, mem, sess)
    assert d.verdict is Verdict.DENY
    assert d.hideable is False
    assert d.denied_by == "NeedToKnow"


def test_F01_cognitive_layer_is_hard_deny():
    topo = Topology()
    topo.add_agent("planner")
    topo.add_agent("child", parent="planner")
    pdp = PDP(topo)
    # child 读 planner 的 R 层思考（非 ancestor）→ CognitiveLayer 拒
    child = _agent(agent_id="child", clearance=Clearance.L3_SECRET)
    mem = _mem(owner_agent="planner", layer=Layer.REASONING,
               sensitivity=Clearance.L2_SENSITIVE)
    sess = Session.start("s", child, "task-x")
    d = pdp.can_read(child, mem, sess)
    assert d.verdict is Verdict.DENY
    assert d.hideable is False
    assert d.denied_by == "CognitiveLayer"


def test_F01_ttl_epoch_lifecycle_are_hard_deny():
    pdp = PDP(Topology())
    agent = _agent(agent_id="a", clearance=Clearance.L3_SECRET)

    # TTL：主客体均需在窗口内
    expired = _agent(agent_id="a", clearance=Clearance.L3_SECRET,
                     ttl_start=datetime.now(timezone.utc) - timedelta(days=3),
                     ttl_end=datetime.now(timezone.utc) - timedelta(days=2))
    sess = Session.start("s", expired, "task-x")
    d = pdp.can_read(expired, _mem(sensitivity=Clearance.L2_SENSITIVE), sess)
    assert d.verdict is Verdict.DENY and d.denied_by == "TTL"

    # Epoch：主体版本落后客体
    agent_old = _agent(agent_id="a", clearance=Clearance.L3_SECRET, epoch=1)
    sess2 = Session.start("s2", agent_old, "task-x")
    d2 = pdp.can_read(agent_old, _mem(sensitivity=Clearance.L2_SENSITIVE, epoch=2),
                      sess2, epoch_current=2)
    assert d2.verdict is Verdict.DENY and d2.denied_by == "Epoch"

    # Lifecycle：revoked 客体
    sess3 = Session.start("s3", agent, "task-x")
    d3 = pdp.can_read(agent, _mem(sensitivity=Clearance.L2_SENSITIVE,
                                  lifecycle="revoked"), sess3)
    assert d3.verdict is Verdict.DENY and d3.denied_by == "Lifecycle"


def test_F01_hard_deny_creates_no_var_handle():
    """硬拒绝不可 HIDE：ReadPipeline 不得创建 #var# 句柄。"""
    from core.pipeline import ReadPipeline
    from core.varstore import VarStore

    pdp = PDP(Topology())
    low = _agent(agent_id="low", clearance=Clearance.L0_PUBLIC)
    mem = _mem(sensitivity=Clearance.L3_SECRET)

    class MemStore:
        def get(self, cid):
            return mem if cid == mem.chunk_id else None

    class Audit:
        def log(self, d):
            pass

    var_store = VarStore()
    pipe = ReadPipeline(pdp, None, MemStore(), Audit(), var_store)
    sess = Session.start("s", low, "task-x")
    r = pipe.read(agent=low, session=sess, chunk_id=mem.chunk_id,
                  scope=TaskScope("task-x", Clearance.L3_SECRET, Trust.T0_UNTRUSTED))
    assert r.decision.verdict is Verdict.DENY
    assert r.var_handle is None
    assert var_store.count == 0
