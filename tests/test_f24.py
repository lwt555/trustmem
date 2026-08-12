"""F-24 验收：控制流预算只有一套，挂在 Session 上（4 bit 封顶）。"""
from __future__ import annotations

from core.labels import (AgentLabel, Clearance, Trust, Role)
from core.session import Session, SessionStore, AbsorbMode
from core.varstore import VarStore, VarHandle


def _agent(trust=Trust.T3_HIGH) -> AgentLabel:
    return AgentLabel("a", Role.ANALYST, Clearance.L3_SECRET, trust,
                      task_domain={"t"}, collab_group={"g"}, epoch=1)


def _store_handle() -> tuple[VarStore, str]:
    vs = VarStore()
    vs.store(VarHandle(var_id="var-1", chunk_id="chunk-1", reason="test",
                       source_trust=Trust.T0_UNTRUSTED,
                       sensitivity=Clearance.L0_PUBLIC))
    return vs, "var-1"


def test_F24_single_budget_of_four_bits():
    assert Session.CAPACITY_BUDGET_BITS == 4.0
    vs, vid = _store_handle()
    sess = Session.start("s", _agent(), "t")
    n = 0
    while vs.expand(vid, "bool", sess=sess).mode is AbsorbMode.BOUNDED:
        n += 1
    assert n == 4
    assert sess.capacity_used_bits == 4.0


def test_F24_budget_survives_delegate():
    vs, vid = _store_handle()
    parent = Session.start("p", _agent(), "t")
    store = SessionStore()
    store._s[("p", "a")] = parent
    vs.expand(vid, "bool", sess=parent)  # 用掉 1 bit
    child_agent = _agent(Trust.T1_LOW)
    child = store.delegate("p", child_agent, "t")
    assert child.capacity_used_bits == 1.0


def test_F24_budget_not_resettable_mid_session():
    sess = Session.start("s", _agent(), "t")
    sess.consume_bits(2.0)
    used = sess.capacity_used_bits
    assert used == 2.0
    # 没有中途重置入口：reset_ctl 已删除
    assert not hasattr(SessionStore, "reset_ctl")
    assert sess.capacity_used_bits >= used


def test_F24_no_second_budget_exists():
    assert not hasattr(SessionStore, "_capacity_budget"), "双预算已合并"
    assert not hasattr(VarStore, "_budget_remaining"), "VarStore 独立预算已移除"
