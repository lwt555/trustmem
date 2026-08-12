"""F-03 验收：P-T 门查的是 t_eff_ctl，不是 t_eff。

修复前 P-T 门读 t_eff，导致修补 P3（LLM 隔离水位）作废。
修复后 can_write / can_invoke 的完整性门都读 t_eff_ctl。
"""
from __future__ import annotations

import pytest

from core.labels import (AgentLabel, MemoryLabel, Clearance, Trust, Layer,
                         MemoryType, Role, WriteOp)
from core.session import Session, AbsorbMode
from core.topology import Topology
from core.pdp import PDP
from core.verdict import Verdict


def _analyst() -> AgentLabel:
    return AgentLabel(agent_id="analyst", role=Role.ANALYST,
                      clearance=Clearance.L2_SENSITIVE, trust_intrinsic=Trust.T2_MEDIUM,
                      task_domain={"task-x"}, collab_group={"grp"},
                      tool_scope={"file_write"})


def _pdp() -> PDP:
    return PDP(Topology())


def test_F03_write_gate_uses_teff_ctl_not_teff():
    """BOUNDED 展开只降 t_eff、t_eff_ctl 不变 → P-T 门仍应通过（隔离有效）。"""
    pdp = _pdp()
    agent = _analyst()
    sess = Session.start("s", agent, "task-x")
    sess.absorb("dirty", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED,
                mode=AbsorbMode.BOUNDED)
    assert sess.t_eff == Trust.T0_UNTRUSTED
    assert sess.t_eff_ctl == Trust.T2_MEDIUM  # 隔离水位没动

    d, _ = pdp.can_write(agent, sess, Clearance.L2_SENSITIVE, Layer.CONCLUSION,
                         [], WriteOp.INFER)
    pt = next(c for c in d.checks if c.rule == "P-T-ControlFlow")
    assert pt.passed, f"P-T 门应看 t_eff_ctl(T2)，不是 t_eff(T0)。detail={pt.detail}"


def test_F03_write_gate_blocks_when_ctl_dropped():
    """FULL 展开同降 t_eff_ctl → P-T 门拒绝写回。"""
    pdp = _pdp()
    agent = _analyst()
    sess = Session.start("s", agent, "task-x")
    sess.absorb("dirty", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED,
                mode=AbsorbMode.FULL)
    assert sess.t_eff_ctl == Trust.T0_UNTRUSTED

    d, _ = pdp.can_write(agent, sess, Clearance.L2_SENSITIVE, Layer.CONCLUSION,
                         [], WriteOp.INFER)
    assert d.verdict is Verdict.DENY
    assert d.denied_by == "P-T-ControlFlow"


def test_F03_invoke_gate_uses_teff_ctl():
    """can_invoke 的 P-T 门同样读 t_eff_ctl。file_write 需要 T3。"""
    pdp = _pdp()
    agent = _analyst()  # t_eff_ctl 初始 T2 < file_write 所需 T3
    sess = Session.start("s", agent, "task-x")
    d = pdp.can_invoke(agent, sess, "file_write", "write:/tmp/x")
    assert d.verdict is Verdict.DENY
    assert d.denied_by == "P-T-ControlFlow"

    # 用 T3 主体即可通过（工具门槛由 t_eff_ctl 决定）
    hi = AgentLabel(agent_id="executor", role=Role.EXECUTOR,
                    clearance=Clearance.L3_SECRET, trust_intrinsic=Trust.T3_HIGH,
                    task_domain={"task-x"}, collab_group={"grp"},
                    tool_scope={"file_write"})
    sess2 = Session.start("s2", hi, "task-x")
    d2 = pdp.can_invoke(hi, sess2, "file_write", "write:/tmp/x")
    pt = next(c for c in d2.checks if c.rule == "P-T-ControlFlow")
    assert pt.passed, f"T3 主体应通过 P-T 门。detail={pt.detail}"
