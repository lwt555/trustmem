"""步骤 8 核验 —— 读取语义从任务级细化到记忆级（consult_below）。

四条断言：
  1. 回归保护：consult_below 取默认值时，读取行为与改动前一致（T1 记忆在
     t_ctx_min=T0 的任务下为 ALLOW）
  2. consult_below=T2 时，T1 记忆 → HIDE，产生 VarHandle，且 chunk_id in sess.consulted
  3. consult_below=T2 时，T3 记忆 → ALLOW，原文可读
  4. 把被 CONSULT 的 chunk 放进 input_mems 写回 → DENY，denied_by == "Provenance-NoConsult"
"""
from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.labels import (
    AgentLabel, MemoryLabel, Clearance, Trust, Layer, Role, MemoryType, WriteOp,
    IngestMode, TaskScope,
)
from core.pdp import PDP
from core.verdict import Verdict
from core.session import Session
from core.topology import Topology


def _agent() -> AgentLabel:
    return AgentLabel(agent_id="planner", role=Role.PLANNER,
                      clearance=Clearance.L3_SECRET, trust_intrinsic=Trust.T2_MEDIUM,
                      task_domain={"JOINT-2026"}, collab_group={"joint-ops"})


def _mem(chunk_id: str, trust: Trust) -> MemoryLabel:
    return MemoryLabel(chunk_id=chunk_id, sensitivity=Clearance.L1_INTERNAL,
                       provenance_trust=trust, layer=Layer.CONCLUSION,
                       memory_type=MemoryType.INTEL, owner_agent="security",
                       task_binding="JOINT-2026", collab_group={"joint-ops"})


def _pdp() -> PDP:
    topo = Topology()
    topo.add_agent("planner")
    return PDP(topo)


def _scope(consult_below: Trust = Trust.T0_UNTRUSTED) -> TaskScope:
    return TaskScope(task_id="JOINT-2026-THREATRPT", c_ctx_max=Clearance.L3_SECRET,
                     t_ctx_min=Trust.T0_UNTRUSTED, ingest=IngestMode.LEARN,
                     consult_below=consult_below)


def test_1_regression_default_consult_below_allows_t1():
    """consult_below 默认值（T0）时，T1 记忆在 t_ctx_min=T0 任务下为 ALLOW。"""
    pdp = _pdp()
    agent = _agent()
    sess = Session.start("sess-r1", agent, "JOINT-2026-THREATRPT")
    mem = _mem("M-T1", Trust.T1_LOW)

    d = pdp.can_read_scoped(agent, mem, sess, _scope())

    assert d.verdict == Verdict.ALLOW, f"默认 consult_below 应 ALLOW: {d.explain()}"
    assert "M-T1" not in sess.consulted


def test_2_consult_below_t2_hides_t1():
    """consult_below=T2 时，T1 记忆 → HIDE（VarHandle），且进入 sess.consulted。"""
    pdp = _pdp()
    agent = _agent()
    sess = Session.start("sess-r2", agent, "JOINT-2026-THREATRPT")
    mem = _mem("M-T1", Trust.T1_LOW)

    d = pdp.can_read_scoped(agent, mem, sess, _scope(consult_below=Trust.T2_MEDIUM))

    assert d.verdict == Verdict.HIDE, f"T1 < consult_below=T2 应 HIDE: {d.explain()}"
    assert d.hideable, "HIDE 应产生 VarHandle（hideable）"
    assert "M-T1" in sess.consulted, "低于 consult_below 的读取应计入 consulted"


def test_3_consult_below_t2_allows_t3():
    """consult_below=T2 时，T3 记忆 → ALLOW，原文可读。"""
    pdp = _pdp()
    agent = _agent()
    sess = Session.start("sess-r3", agent, "JOINT-2026-THREATRPT")
    mem = _mem("EW-004", Trust.T3_HIGH)

    d = pdp.can_read_scoped(agent, mem, sess, _scope(consult_below=Trust.T2_MEDIUM))

    assert d.verdict == Verdict.ALLOW, f"T3 ≥ consult_below=T2 应 ALLOW: {d.explain()}"
    assert "EW-004" not in sess.consulted


def test_4_consulted_chunk_writeback_denied():
    """被 CONSULT 的 chunk 放进 input_mems 写回 → DENY，denied_by == Provenance-NoConsult。"""
    pdp = _pdp()
    agent = _agent()
    sess = Session.start("sess-r4", agent, "JOINT-2026-THREATRPT")
    mem = _mem("M-T1", Trust.T1_LOW)

    # 先经 consult_below 触发 CONSULT 记账
    d = pdp.can_read_scoped(agent, mem, sess, _scope(consult_below=Trust.T2_MEDIUM))
    assert d.verdict == Verdict.HIDE and "M-T1" in sess.consulted

    dw, _ = pdp.can_write(agent, sess, Clearance.L1_INTERNAL, Layer.CONCLUSION,
                          [mem], WriteOp.INFER, output_text="写回被 CONSULT 的内容")
    assert dw.denied_by == "Provenance-NoConsult", f"expected Provenance-NoConsult, got {dw.denied_by}"
    assert dw.verdict == Verdict.DENY
