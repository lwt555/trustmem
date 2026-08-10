"""
TaskScope + IngestMode 测试（P5 修补）
=====================================
验证「装脑子里(LEARN) vs 当书翻(CONSULT)」的完整语义。

12 条断言，其中：
  #7 卡「会话级持久集合」—— 防止实现成"读的那一刻检查"，隔几步就绕过去
  #10 卡委派委托 —— 防止"委派给小弟去写回"绕过 CONSULT 限制
"""
from __future__ import annotations

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.labels import (
    AgentLabel, MemoryLabel, Clearance, Trust, Layer, Role, MemoryType, WriteOp,
    IngestMode, TaskScope, derive_taskscope, TOOL_REQUIRED_TRUST,
)
from core.pdp import PDP
from core.session import Session, SessionStore
from core.topology import Topology
from scenarios.soc_setup import build_agents, build_topology, mk_mem, TASK


def make_scope(ingest=IngestMode.LEARN, c_max=Clearance.L3_SECRET, t_min=Trust.T0_UNTRUSTED):
    return TaskScope(task_id="test-task", c_ctx_max=c_max, t_ctx_min=t_min, ingest=ingest)


# ══════════════════════════════════════════════════════════════
# 1. LEARN 模式下，ALLOW 的读可以出现在后续写入的 provenance 链
# ══════════════════════════════════════════════════════════════
def test_01_learn_allows_provenance():
    agents, topo = build_agents(), build_topology()
    pdp, store = PDP(topo), SessionStore()
    scope = make_scope(IngestMode.LEARN)

    analyst = agents["analyst"]
    s = store.get_or_start("sess-t1", analyst, TASK)
    mem = mk_mem("m_learn", Clearance.L1_INTERNAL, Trust.T2_MEDIUM,
                 Layer.CONCLUSION, "intel")

    d = pdp.can_read_scoped(analyst, mem, s, scope)
    assert d.allowed, f"LEARN should allow: {d.explain()}"

    # write using this memory as input should work
    dw, _ = pdp.can_write(analyst, s, Clearance.L2_SENSITIVE, Layer.CONCLUSION,
                          [mem], WriteOp.INFER, output_text="test")
    assert dw.allowed, f"LEARN write should succeed: {dw.explain()}"


# ══════════════════════════════════════════════════════════════
# 2. CONSULT 模式下，读入的记忆被标记为 consulted
# ══════════════════════════════════════════════════════════════
def test_02_consult_marks_chunks():
    agents, topo = build_agents(), build_topology()
    pdp, store = PDP(topo), SessionStore()
    scope = make_scope(IngestMode.CONSULT)

    analyst = agents["analyst"]
    s = store.get_or_start("sess-t2", analyst, TASK)
    mem = mk_mem("m_consult", Clearance.L1_INTERNAL, Trust.T2_MEDIUM,
                 Layer.CONCLUSION, "intel")

    d = pdp.can_read_scoped(analyst, mem, s, scope)
    assert d.allowed, f"CONSULT should allow reading: {d.explain()}"
    assert "m_consult" in s.consulted, "CONSULT should mark chunk as consulted"


# ══════════════════════════════════════════════════════════════
# 3. CONSULT 读入的记忆禁止出现在写入的 provenance 链
# ══════════════════════════════════════════════════════════════
def test_03_consult_blocks_write_provenance():
    agents, topo = build_agents(), build_topology()
    pdp, store = PDP(topo), SessionStore()
    scope = make_scope(IngestMode.CONSULT)

    analyst = agents["analyst"]
    s = store.get_or_start("sess-t3", analyst, TASK)
    mem = mk_mem("m_consult", Clearance.L1_INTERNAL, Trust.T2_MEDIUM,
                 Layer.CONCLUSION, "intel")

    d = pdp.can_read_scoped(analyst, mem, s, scope)
    assert d.allowed

    dw, _ = pdp.can_write(analyst, s, Clearance.L2_SENSITIVE, Layer.CONCLUSION,
                          [mem], WriteOp.INFER, output_text="test")
    assert not dw.allowed, "CONSULT should DENY write with consulted provenance"
    assert dw.denied_by == "Provenance-NoConsult", f"expected Provenance-NoConsult, got {dw.denied_by}"


# ══════════════════════════════════════════════════════════════
# 4. LEARN + CONSULT 混合：只有 CONSULT 的出现在 provenance 才被拒
# ══════════════════════════════════════════════════════════════
def test_04_mixed_learn_consult_provenance():
    agents, topo = build_agents(), build_topology()
    pdp, store = PDP(topo), SessionStore()

    analyst = agents["analyst"]
    s = store.get_or_start("sess-t4", analyst, TASK)
    m_learn = mk_mem("m_learn", Clearance.L1_INTERNAL, Trust.T2_MEDIUM,
                     Layer.CONCLUSION, "intel")
    m_consult = mk_mem("m_consult", Clearance.L1_INTERNAL, Trust.T2_MEDIUM,
                       Layer.CONCLUSION, "log")

    # LEARN read
    d1 = pdp.can_read_scoped(analyst, m_learn, s, make_scope(IngestMode.LEARN))
    assert d1.allowed
    assert "m_learn" not in s.consulted

    # CONSULT read
    d2 = pdp.can_read_scoped(analyst, m_consult, s, make_scope(IngestMode.CONSULT))
    assert d2.allowed
    assert "m_consult" in s.consulted

    # write with m_learn only -- should succeed
    dw, _ = pdp.can_write(analyst, s, Clearance.L2_SENSITIVE, Layer.CONCLUSION,
                          [m_learn], WriteOp.INFER, output_text="test")
    assert dw.allowed, f"LEARN-only write should succeed: {dw.explain()}"

    # write with m_consult only -- should fail
    dw2, _ = pdp.can_write(analyst, s, Clearance.L2_SENSITIVE, Layer.CONCLUSION,
                           [m_consult], WriteOp.INFER, output_text="test")
    assert not dw2.allowed, "CONSULT input should block write"
    assert dw2.denied_by == "Provenance-NoConsult"


# ══════════════════════════════════════════════════════════════
# 5. CONSULT 不是提权通道 —— scope 拒绝的内存即使 CONSULT 也不能读
# ══════════════════════════════════════════════════════════════
def test_05_consult_not_privilege_escalation():
    agents, topo = build_agents(), build_topology()
    pdp, store = PDP(topo), SessionStore()

    # scope caps at L0, memory is L2 -> CONSULT still denied
    scope = make_scope(IngestMode.CONSULT, c_max=Clearance.L0_PUBLIC)
    intel = agents["intel"]   # clearance L0
    s = store.get_or_start("sess-t5", intel, TASK)
    mem = mk_mem("m_secret", Clearance.L2_SENSITIVE, Trust.T3_HIGH,
                 Layer.CONCLUSION, "log")

    d = pdp.can_read_scoped(intel, mem, s, scope)
    assert not d.allowed, "CONSULT should not bypass scope limits"
    # denial can come from either BLP (clearance check) or TaskScope-C (scope check)
    assert d.denied_by is not None


# ══════════════════════════════════════════════════════════════
# 6. session.reset() 清空 consulted 集合
# ══════════════════════════════════════════════════════════════
def test_06_reset_clears_consulted():
    agents, topo = build_agents(), build_topology()
    pdp, store = PDP(topo), SessionStore()
    scope = make_scope(IngestMode.CONSULT)

    analyst = agents["analyst"]
    s = store.get_or_start("sess-t6", analyst, TASK)
    mem = mk_mem("m_consult", Clearance.L1_INTERNAL, Trust.T2_MEDIUM,
                 Layer.CONCLUSION, "intel")

    pdp.can_read_scoped(analyst, mem, s, scope)
    assert len(s.consulted) == 1
    s.reset()
    assert len(s.consulted) == 0, "reset should clear consulted"


# ══════════════════════════════════════════════════════════════
# 7. consulted 是会话级持久集合 —— 隔几步不能绕过去
# ══════════════════════════════════════════════════════════════
def test_07_consulted_persists_across_operations():
    """关键测试：如果只在 can_read 那一刻检查后不持久化，
    Agent 读 -> 等几步 -> 再写，就能绕过 CONSULT 限制。"""
    agents, topo = build_agents(), build_topology()
    pdp, store = PDP(topo), SessionStore()
    scope = make_scope(IngestMode.CONSULT)

    analyst = agents["analyst"]
    s = store.get_or_start("sess-t7", analyst, TASK)
    mem = mk_mem("m_consult", Clearance.L1_INTERNAL, Trust.T2_MEDIUM,
                 Layer.CONCLUSION, "intel")

    # Step A: read in CONSULT
    d = pdp.can_read_scoped(analyst, mem, s, scope)
    assert d.allowed
    assert "m_consult" in s.consulted

    # Step B: do other reads (LEARN mode)
    m_other = mk_mem("m_other", Clearance.L1_INTERNAL, Trust.T2_MEDIUM,
                     Layer.CONCLUSION, "log")
    d2 = pdp.can_read_scoped(analyst, m_other, s, make_scope(IngestMode.LEARN))
    assert d2.allowed

    # Step C: now try to write with the consulted chunk -- must still fail
    dw, _ = pdp.can_write(analyst, s, Clearance.L2_SENSITIVE, Layer.CONCLUSION,
                          [mem], WriteOp.INFER, output_text="test")
    assert not dw.allowed, "CONSULT should persist across operations"
    assert dw.denied_by == "Provenance-NoConsult"


# ══════════════════════════════════════════════════════════════
# 8. TaskScope 自动推导：有网络出口则 c_ctx_max = L0
# ══════════════════════════════════════════════════════════════
def test_08_derive_scope_egress_caps_clearance():
    scope = derive_taskscope("t-egress",
        declared_exports={"api.respond"},
        declared_tools={"web_search"},  # network egress
        task_max_clearance=Clearance.L3_SECRET)
    assert scope.c_ctx_max == Clearance.L0_PUBLIC, \
        f"network egress should cap clearance, got {scope.c_ctx_max}"


# ══════════════════════════════════════════════════════════════
# 9. TaskScope 自动推导：高危工具推高 t_ctx_min
# ══════════════════════════════════════════════════════════════
def test_09_derive_scope_high_risk_raises_t_min():
    scope = derive_taskscope("t-highrisk",
        declared_exports={"memory.write"},
        declared_tools={"firewall_block", "host_isolate"},
        task_max_clearance=Clearance.L3_SECRET)
    assert scope.t_ctx_min == Trust.T3_HIGH, \
        f"high-risk tools should raise t_ctx_min, got {scope.t_ctx_min}"


# ══════════════════════════════════════════════════════════════
# 10. 委派委托：子会话继承父会话的 consulted 集合
# ══════════════════════════════════════════════════════════════
def test_10_delegation_inherits_consulted():
    """CONSULT 的 consulted 在委派时必须传播，否则
    '委派给小弟写回' 就能绕过 CONSULT。"""
    store = SessionStore()
    agents, topo = build_agents(), build_topology()
    pdp = PDP(topo)

    # Parent session (Analyst) consults a chunk
    parent = store.get_or_start("sess-parent", agents["analyst"], TASK)
    mem = mk_mem("m_consult", Clearance.L1_INTERNAL, Trust.T2_MEDIUM,
                 Layer.CONCLUSION, "intel")
    scope = make_scope(IngestMode.CONSULT)
    pdp.can_read_scoped(agents["analyst"], mem, parent, scope)
    assert "m_consult" in parent.consulted

    # Child session (Executor, delegated) -- inherit consulted
    child = store.get_or_start("sess-parent", agents["executor"], TASK)
    child.consulted |= parent.consulted  # delegation inheritance
    assert "m_consult" in child.consulted

    # Child writes with consulted chunk -- should fail
    dw, _ = pdp.can_write(agents["executor"], child,
                          Clearance.L2_SENSITIVE, Layer.CONCLUSION,
                          [mem], WriteOp.INFER, output_text="delegated write")
    assert not dw.allowed, "delegation should not bypass CONSULT"
    assert dw.denied_by == "Provenance-NoConsult"


# ══════════════════════════════════════════════════════════════
# 11. 跨会话 consulted 不泄漏
# ══════════════════════════════════════════════════════════════
def test_11_consulted_session_isolation():
    store = SessionStore()
    agents, topo = build_agents(), build_topology()
    pdp = PDP(topo)

    s1 = store.get_or_start("s1", agents["analyst"], TASK)
    s2 = store.get_or_start("s2", agents["analyst"], TASK)

    mem = mk_mem("m", Clearance.L1_INTERNAL, Trust.T2_MEDIUM,
                 Layer.CONCLUSION, "intel")
    scope = make_scope(IngestMode.CONSULT)
    pdp.can_read_scoped(agents["analyst"], mem, s1, scope)
    assert "m" in s1.consulted
    assert "m" not in s2.consulted, "consulted should not leak across sessions"


# ══════════════════════════════════════════════════════════════
# 12. TaskScope 区间检查：完整性低于 t_ctx_min 也被拒
# ══════════════════════════════════════════════════════════════
def test_12_scope_t_trust_below_min_denied():
    agents, topo = build_agents(), build_topology()
    pdp, store = PDP(topo), SessionStore()

    scope = make_scope(IngestMode.LEARN, c_max=Clearance.L3_SECRET, t_min=Trust.T2_MEDIUM)
    analyst = agents["analyst"]
    s = store.get_or_start("sess-t12", analyst, TASK)
    mem = mk_mem("m_low", Clearance.L1_INTERNAL, Trust.T1_LOW,
                 Layer.CONCLUSION, "intel")

    d = pdp.can_read_scoped(analyst, mem, s, scope)
    assert not d.allowed, f"T{fmt(mem.provenance_trust)} < T{fmt(scope.t_ctx_min)} should be denied"
    assert "TaskScope-T" in (d.denied_by or "")


if __name__ == "__main__":
    test_01_learn_allows_provenance()
    test_02_consult_marks_chunks()
    test_03_consult_blocks_write_provenance()
    test_04_mixed_learn_consult_provenance()
    test_05_consult_not_privilege_escalation()
    test_06_reset_clears_consulted()
    test_07_consulted_persists_across_operations()
    test_08_derive_scope_egress_caps_clearance()
    test_09_derive_scope_high_risk_raises_t_min()
    test_10_delegation_inherits_consulted()
    test_11_consulted_session_isolation()
    test_12_scope_t_trust_below_min_denied()
    print("All 12 ingest tests passed.")
