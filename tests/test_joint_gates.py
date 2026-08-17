"""步骤 9.3 核验 —— 联合态势研判场景六道门端到端。

全部在 joint 场景下运行（显式构造 joint 的 agents/scope，不依赖环境变量）。

六条断言：
  1. external 读 security 的 L3 记忆 → DENY，denied_by == "BLP-SimpleSecurity"（门①）
  2. M237（T1）在 RISKLEVEL 任务下被读 → HIDE，denied_by == "TaskScope-T"，
     会话水位无变化（门③a）
  3. M237 在 THREATRPT（consult_below=T2）下被读 → HIDE 且进入 sess.consulted；
     同任务读 EW-004（T3）→ ALLOW 原文可读（门③b 对照）
  4. 把 M237 放进 input_mems 写回 → DENY，denied_by == "Provenance-NoConsult"
  5. external 读入 L1 摘要（c_eff 升至 L1）后调用 xdomain_forward → DENY，
     denied_by == "Flow-Egress"（门④）；c_eff 为 L0 时调用同一工具 → ALLOW（对照）
  6. planner 读入 T2/T3 下游结论后调用 risk_level_publish → CONFIRM，
     denied_by == "HumanInTheLoop"（人在环门）；provenance 中混入 T1 记忆后 →
     DENY，denied_by == "P-T-Provenance"
"""
from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.labels import (
    MemoryLabel, Clearance, Trust, Layer, MemoryType, WriteOp,
)
from core.pdp import PDP
from core.verdict import Verdict
from core.session import Session, AbsorbMode

from scenarios.joint.setup import (
    build_agents, build_topology, load_task, JOINT_TASK, GROUP_JOINT,
)

AGENTS = build_agents()
TOPO = build_topology()


def _pdp() -> PDP:
    return PDP(TOPO)


def _mem(chunk_id: str, sensitivity: Clearance, trust: Trust, owner: str,
         mtype: MemoryType = MemoryType.INTEL) -> MemoryLabel:
    return MemoryLabel(
        chunk_id=chunk_id, sensitivity=sensitivity, provenance_trust=trust,
        layer=Layer.CONCLUSION, memory_type=mtype, owner_agent=owner,
        task_binding=JOINT_TASK, collab_group={GROUP_JOINT},
    )


def test_1_external_read_security_l3_denied_blp():
    """门①：external(L1) 读 security 的 L3 记忆 → DENY BLP-SimpleSecurity。"""
    pdp = _pdp()
    external = AGENTS["external"]
    sess = Session.start("g1", external, JOINT_TASK)
    sec_mem = _mem("SEC-001", Clearance.L3_SECRET, Trust.T3_HIGH, "security")

    d = pdp.can_read_scoped(external, sec_mem, sess, load_task("JOINT-2026-RISKLEVEL").scope)

    assert d.verdict == Verdict.DENY, f"expected DENY: {d.explain()}"
    assert d.denied_by == "BLP-SimpleSecurity", f"expected BLP-SimpleSecurity, got {d.denied_by}"


def test_2_m237_risklevel_hide_task_scope_t():
    """门③a：M237(T1) 在 RISKLEVEL(t_ctx_min=T2) 下 → HIDE TaskScope-T，水位不变。"""
    pdp = _pdp()
    planner = AGENTS["planner"]
    sess = Session.start("g2", planner, JOINT_TASK)
    m237 = _mem("M237", Clearance.L1_INTERNAL, Trust.T1_LOW, "external")

    c_before, t_before = sess.c_eff, sess.t_eff_ctl
    d = pdp.can_read_scoped(planner, m237, sess, load_task("JOINT-2026-RISKLEVEL").scope)

    assert d.verdict == Verdict.HIDE, f"expected HIDE: {d.explain()}"
    assert d.denied_by == "TaskScope-T", f"expected TaskScope-T, got {d.denied_by}"
    assert sess.c_eff == c_before and sess.t_eff_ctl == t_before, "HIDE 不应改变会话水位"


def test_3_threatrpt_consult_below_m237_hide_ew004_allow():
    """门③b：THREATRPT(consult_below=T2) 下 M237(T1) → HIDE+consulted，EW-004(T3) → ALLOW。"""
    pdp = _pdp()
    planner = AGENTS["planner"]
    sess = Session.start("g3", planner, JOINT_TASK)
    scope = load_task("JOINT-2026-THREATRPT").scope
    m237 = _mem("M237", Clearance.L1_INTERNAL, Trust.T1_LOW, "external")
    ew004 = _mem("EW-004", Clearance.L2_SENSITIVE, Trust.T3_HIGH, "ew")

    d1 = pdp.can_read_scoped(planner, m237, sess, scope)
    assert d1.verdict == Verdict.HIDE, f"T1 < consult_below=T2 应 HIDE: {d1.explain()}"
    assert "M237" in sess.consulted, "低于 consult_below 应进入 consulted"

    d2 = pdp.can_read_scoped(planner, ew004, sess, scope)
    assert d2.verdict == Verdict.ALLOW, f"T3 ≥ consult_below=T2 应 ALLOW: {d2.explain()}"


def test_4_m237_writeback_denied_no_consult():
    """把被 CONSULT 的 M237 放进 input_mems 写回 → DENY Provenance-NoConsult。"""
    pdp = _pdp()
    planner = AGENTS["planner"]
    sess = Session.start("g4", planner, JOINT_TASK)
    scope = load_task("JOINT-2026-THREATRPT").scope
    m237 = _mem("M237", Clearance.L1_INTERNAL, Trust.T1_LOW, "external")

    d = pdp.can_read_scoped(planner, m237, sess, scope)
    assert d.verdict == Verdict.HIDE and "M237" in sess.consulted

    dw, _ = pdp.can_write(planner, sess, Clearance.L1_INTERNAL, Layer.CONCLUSION,
                          [m237], WriteOp.INFER, output_text="写回被 CONSULT 的毒转报")
    assert dw.verdict == Verdict.DENY
    assert dw.denied_by == "Provenance-NoConsult", f"expected Provenance-NoConsult, got {dw.denied_by}"


def test_5_external_xdomain_forward_flow_egress():
    """门④：external 读入 L1 摘要后 c_eff=L1 → xdomain_forward DENY Flow-Egress；
    c_eff=L0 时 ALLOW（对照）。"""
    pdp = _pdp()
    external = AGENTS["external"]

    sess = Session.start("g5", external, JOINT_TASK)
    sess.absorb("summary", Clearance.L1_INTERNAL, Trust.T1_LOW, mode=AbsorbMode.FULL)
    assert sess.c_eff == Clearance.L1_INTERNAL

    d = pdp.can_invoke(external, sess, "xdomain_forward", "forward:summary")
    assert d.verdict == Verdict.DENY, f"c_eff=L1 流向公开信道应 DENY: {d.explain()}"
    assert d.denied_by == "Flow-Egress", f"expected Flow-Egress, got {d.denied_by}"

    sess2 = Session.start("g5b", external, JOINT_TASK)  # c_eff = L0
    d2 = pdp.can_invoke(external, sess2, "xdomain_forward", "forward:summary")
    assert d2.verdict == Verdict.ALLOW, f"c_eff=L0 应 ALLOW: {d2.explain()}"


def test_6_planner_risk_level_publish_hitl():
    """人在环门：planner 读入 T2/T3 结论后 risk_level_publish → CONFIRM HumanInTheLoop；
    混入 T1 provenance → DENY P-T-Provenance。"""
    pdp = _pdp()
    planner = AGENTS["planner"]
    sess = Session.start("g6", planner, JOINT_TASK)
    c2 = _mem("C2", Clearance.L2_SENSITIVE, Trust.T2_MEDIUM, "situation")
    c3 = _mem("C3", Clearance.L2_SENSITIVE, Trust.T3_HIGH, "ew")
    t1 = _mem("M237", Clearance.L1_INTERNAL, Trust.T1_LOW, "external")

    # 读入下游结论（T3 不拉低 planner 的 T2 控制流水位）
    sess.absorb("C3", c3.sensitivity, c3.provenance_trust, mode=AbsorbMode.FULL)
    assert sess.t_eff_ctl == Trust.T2_MEDIUM

    d = pdp.can_invoke(planner, sess, "risk_level_publish", "publish:risklevel",
                       provenance=[c2, c3])
    assert d.verdict == Verdict.CONFIRM, f"expected CONFIRM: {d.explain()}"
    assert d.denied_by == "HumanInTheLoop", f"expected HumanInTheLoop, got {d.denied_by}"

    d2 = pdp.can_invoke(planner, sess, "risk_level_publish", "publish:risklevel",
                        provenance=[c2, c3, t1])
    assert d2.verdict == Verdict.DENY, f"混入 T1 应 DENY: {d2.explain()}"
    assert d2.denied_by == "P-T-Provenance", f"expected P-T-Provenance, got {d2.denied_by}"
