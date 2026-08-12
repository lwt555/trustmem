"""F-06 验收：受限/无界展开语义方向正确（TR3/TR4 + I11 预算耗尽退化）。

受限展开（容量 ≤ 4 bit）：t_eff 照常下降，t_eff_ctl 不变。
无界展开（容量 > 阈值 或 预算耗尽）：两者同降。
"""
from __future__ import annotations

import pytest

from core.labels import (AgentLabel, MemoryLabel, Clearance, Trust, Layer,
                         MemoryType, Role)
from core.session import Session, AbsorbMode
from core.topology import Topology
from core.pdp import PDP
from core.varstore import VarStore, VarHandle


def _agent() -> AgentLabel:
    return AgentLabel(agent_id="executor", role=Role.EXECUTOR,
                      clearance=Clearance.L3_SECRET, trust_intrinsic=Trust.T3_HIGH,
                      task_domain={"task-x"}, collab_group={"grp"},
                      tool_scope={"firewall_block"})


def _store_handle() -> tuple[VarStore, str]:
    vs = VarStore()
    vs.store(VarHandle(var_id="var-1", chunk_id="chunk-1", reason="test",
                       source_trust=Trust.T0_UNTRUSTED, sensitivity=Clearance.L0_PUBLIC))
    return vs, "var-1"


def test_F06_bounded_expand_lowers_t_eff_only():
    vs, vid = _store_handle()
    sess = Session.start("s", _agent(), "task-x")
    before_t, before_ctl = sess.t_eff, sess.t_eff_ctl
    assert before_t == Trust.T3_HIGH and before_ctl == Trust.T3_HIGH

    r = vs.expand(vid, "bool", sess=sess)  # 1 bit ≤ 4 → BOUNDED
    assert r.mode is AbsorbMode.BOUNDED
    assert sess.t_eff < before_t, "TR3: t_eff 必须照实下降"
    assert sess.t_eff_ctl == before_ctl, "TR3: t_eff_ctl 必须不变"


def test_F06_unbounded_expand_lowers_both():
    vs, vid = _store_handle()
    sess = Session.start("s", _agent(), "task-x")
    before_ctl = sess.t_eff_ctl
    r = vs.expand(vid, "string", sess=sess)  # inf > 4 → FULL
    assert r.mode is AbsorbMode.FULL
    assert sess.t_eff_ctl < before_ctl, "TR4: 无界展开两个都降"


def test_F06_exhausted_budget_degrades_to_unbounded():
    vs, vid = _store_handle()
    sess = Session.start("s", _agent(), "task-x")
    for _ in range(4):
        vs.expand(vid, "bool", sess=sess)  # 用尽 4 bit
    before_ctl = sess.t_eff_ctl
    assert before_ctl == Trust.T3_HIGH  # 前 4 次都是 BOUNDED，ctl 没动
    r = vs.expand(vid, "bool", sess=sess)  # 第 5 次：预算耗尽 → 退化 FULL
    assert r.mode is AbsorbMode.FULL
    assert sess.t_eff_ctl < before_ctl, "I11: 超支后受限展开退化为无界"


def test_F06_dd_task_completable():
    """DD 类任务必须在 4 bit 内完成，且完成后仍能调高危工具。"""
    vs, vid = _store_handle()
    agent = _agent()
    sess = Session.start("s", agent, "task-x")
    vs.expand(vid, "bool", sess=sess)  # BOUNDED：t_eff_ctl 保持 T3
    sess.add_hitl("fp")
    pdp = PDP(Topology())
    d = pdp.can_invoke(agent, sess, "firewall_block", "fp")
    assert d.allowed, f"隔离 LLM 不得使高危工具失格。denied_by={d.denied_by}"
