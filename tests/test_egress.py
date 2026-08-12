"""F-02 验收：出口约束方向正确 —— allow(egress) iff c_eff ⊑ readers(接收方)。

修复前是 `agent.clearance >= readers`（方向反了，从不拦截）。
修复后是 `sess.c_eff <= readers`，并独立检查参数标签密级。
"""
from __future__ import annotations

import pytest

from core.labels import (AgentLabel, MemoryLabel, Clearance, Trust, Layer,
                         MemoryType, Role)
from core.session import Session, AbsorbMode
from core.topology import Topology
from core.pdp import PDP
from core.verdict import Verdict


def _analyst() -> AgentLabel:
    return AgentLabel(agent_id="analyst", role=Role.ANALYST,
                      clearance=Clearance.L2_SENSITIVE, trust_intrinsic=Trust.T2_MEDIUM,
                      task_domain={"task-x"}, collab_group={"grp"},
                      tool_scope={"web_search"})


def _pdp() -> PDP:
    return PDP(Topology())


def test_F02_high_watermark_blocks_public_egress():
    """读过 L3 内容后 c_eff=L3，调用 web_search(readers=L0) 必须被 Flow-Egress 拦。"""
    pdp = _pdp()
    agent = _analyst()
    sess = Session.start("s", agent, "task-x")
    sess.absorb("secret", Clearance.L3_SECRET, Trust.T3_HIGH)  # c_eff -> L3
    assert sess.c_eff == Clearance.L3_SECRET

    d = pdp.can_invoke(agent, sess, "web_search", "egress-query")
    assert d.verdict is Verdict.DENY
    assert d.denied_by == "Flow-Egress"


def test_F02_low_watermark_allows_egress():
    """c_eff 未超 readers → 出口放行。"""
    pdp = _pdp()
    agent = _analyst()
    sess = Session.start("s", agent, "task-x")
    d = pdp.can_invoke(agent, sess, "web_search", "egress-query")
    assert d.allowed, f"c_eff={sess.c_eff} 应允许 web_search，denied_by={d.denied_by}"


def test_F02_direction_is_correct_not_clearance_based():
    """反例：旧代码 agent.clearance(L2) >= readers(L0) 会误放行，新代码按 c_eff 拦。"""
    pdp = _pdp()
    agent = _analyst()  # clearance=L2 >= L0，但 c_eff 被抬到 L3
    sess = Session.start("s", agent, "task-x")
    sess.absorb("secret", Clearance.L3_SECRET, Trust.T3_HIGH)
    d = pdp.can_invoke(agent, sess, "web_search", "e")
    assert d.verdict is Verdict.DENY and d.denied_by == "Flow-Egress"


def test_F02_param_label_checked_independently():
    """上下文干净(c_eff=L0)，但参数标签带 L3 → Flow-Egress-Args 独立拦截。"""
    pdp = _pdp()
    agent = _analyst()
    sess = Session.start("s", agent, "task-x")
    arg = MemoryLabel(chunk_id="arg-l3", sensitivity=Clearance.L3_SECRET,
                      provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                      memory_type=MemoryType.INTEL, owner_agent="x",
                      task_binding="task-x")
    d = pdp.can_invoke(agent, sess, "web_search", "e", arg_labels=[arg])
    assert d.verdict is Verdict.DENY
    assert d.denied_by == "Flow-Egress-Args"
