"""§4 抽查补齐：委派继承、区间防篡改、budget 序列、declassify + NoWriteDown"""
from __future__ import annotations

from core.labels import (AgentLabel, Trust, Role, Clearance, Layer,
                         MemoryType, MemoryLabel, WriteOp, IngestMode, TaskScope)
from core.session import Session, SessionStore
from core.topology import Topology
from core.pdp import PDP


def _agent(**kw) -> AgentLabel:
    """测试用 AgentLabel 工厂，减少重复构造。"""
    defaults = dict(agent_id="analyst", role=Role.ANALYST,
                    clearance=Clearance.L2_SENSITIVE, trust_intrinsic=Trust.T2_MEDIUM,
                    task_domain={"task_A"}, collab_group={"grp_soc"})
    return AgentLabel(**(defaults | kw))


def _planner(**kw) -> AgentLabel:
    defaults = dict(agent_id="planner", role=Role.PLANNER,
                    clearance=Clearance.L3_SECRET, trust_intrinsic=Trust.T3_HIGH,
                    task_domain={"task_x"}, collab_group={"soc"})
    return AgentLabel(**(defaults | kw))


# ══════════════════════════════════════════════════════════════
# §4 #5: 委派继承 — consulted 必须继承，否则 I14 被绕开
# ══════════════════════════════════════════════════════════════
def test_s4_5_delegate_inherits_consulted():
    """父会话 CONSULT 脏情报 → delegate 子会话 → 子会话写回 → DENY."""
    topo = Topology()
    pdp = PDP(topo)
    store = SessionStore()
    agent = _agent()

    # 父会话 CONSULT 一条脏情报
    parent_sess = store.get_or_start("parent_sess", agent, "task_A")
    scope_consult = TaskScope(task_id="task_A", c_ctx_max=Clearance.L2_SENSITIVE,
                              t_ctx_min=Trust.T0_UNTRUSTED, ingest=IngestMode.CONSULT)
    m_dirty = MemoryLabel(chunk_id="dirty_intel", sensitivity=Clearance.L0_PUBLIC,
                          provenance_trust=Trust.T1_LOW, layer=Layer.CONCLUSION,
                          memory_type=MemoryType.INTEL, owner_agent="intel",
                          task_binding="task_A", collab_group={"grp_soc"})
    pdp.can_read_scoped(agent, m_dirty, parent_sess, scope_consult)
    assert m_dirty.chunk_id in parent_sess.consulted

    # delegate 子会话
    child_sess = store.delegate("parent_sess", agent, "task_sub", "child_sess")
    assert m_dirty.chunk_id in child_sess.consulted, \
        "子会话必须继承 consulted 集合，否则 I14 被绕开"

    # 子会话尝试写回
    d_write, decay = pdp.can_write(agent, child_sess, Clearance.L0_PUBLIC,
                                    Layer.CONCLUSION, [m_dirty], WriteOp.INFER)
    assert d_write.verdict.value == "DENY", \
        f"#5 FAIL: delegate 后 I14 被绕开。verdict={d_write.verdict.value}"
    assert d_write.denied_by == "Provenance-NoConsult", \
        f"#5 FAIL: denied_by={d_write.denied_by}, 期望 Provenance-NoConsult"

    # 也检查 c_eff / t_eff 继承
    assert child_sess.c_eff == parent_sess.c_eff, "c_eff 必须继承"
    assert child_sess.t_eff == parent_sess.t_eff, "t_eff 必须继承"
    assert child_sess.t_eff_ctl == parent_sess.t_eff_ctl, "t_eff_ctl 必须继承"
    print(f"  #5: delegate 继承 verified — consulted={len(child_sess.consulted)}, "
          f"c_eff={child_sess.c_eff.name}, t_eff={child_sess.t_eff.name}")


# ══════════════════════════════════════════════════════════════
# §4 #6: 区间防篡改 — widen() 必须 hash-verified
# ══════════════════════════════════════════════════════════════
def test_s4_6_widen_hash_protection():
    """widen() 用正确 hash → 成功；用错误 hash → 抛异常；缩小区间 → 抛异常."""
    scope = TaskScope(task_id="task_x", c_ctx_max=Clearance.L1_INTERNAL,
                      t_ctx_min=Trust.T1_LOW)
    real_hash = scope.scope_hash
    assert real_hash, "TaskScope 必须有 scope_hash"

    # 正确 hash → 扩展成功
    wider = scope.widen(Clearance.L2_SENSITIVE, Trust.T0_UNTRUSTED, real_hash)
    assert wider.c_ctx_max == Clearance.L2_SENSITIVE
    assert wider.t_ctx_min == Trust.T0_UNTRUSTED
    print(f"  #6a: widen with correct hash OK — c_max L1→L2, t_min T1→T0")

    # 错误 hash → 抛异常
    try:
        scope.widen(Clearance.L2_SENSITIVE, Trust.T0_UNTRUSTED,
                    claimed_hash="deadbeef00000000")
        assert False, "错误 hash 未拒绝"
    except ValueError as e:
        assert "hash mismatch" in str(e).lower(), f"期望 hash mismatch，实际: {e}"
    print(f"  #6b: wrong hash rejected")

    # 缩小 c_ctx_max → 抛异常
    try:
        scope.widen(Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED, real_hash)
        assert False, "缩小 c_ctx_max 未拒绝"
    except ValueError as e:
        pass
    print(f"  #6c: shrink c_ctx_max rejected")

    # 缩小 t_ctx_min（即提高门槛）→ 抛异常
    try:
        scope.widen(Clearance.L2_SENSITIVE, Trust.T2_MEDIUM, real_hash)
        assert False, "缩小 t_ctx_min 未拒绝"
    except ValueError as e:
        pass
    print(f"  #6d: shrink t_ctx_min rejected")


# ══════════════════════════════════════════════════════════════
# §4 #7: t_eff vs t_eff_ctl 分离
# ══════════════════════════════════════════════════════════════
def test_s4_7_teff_vs_teff_ctl_separation():
    """受限查询只降 t_eff_ctl，不降 t_eff。两个必须分离."""
    agent = _agent()
    sess = Session.start("s7", agent, "task_x")
    assert sess.t_eff == Trust.T2_MEDIUM
    assert sess.t_eff_ctl == Trust.T2_MEDIUM

    # 模拟受限查询：读 T0 情报 → t_eff 降
    sess.absorb("low_trust_chunk", Trust.T0_UNTRUSTED)
    assert sess.t_eff == Trust.T0_UNTRUSTED, "t_eff 读取 T0 后应降为 T0"

    # t_eff_ctl 只在显式调用 degrade_ctl() 后才降
    # absorb 不应自动降 t_eff_ctl——否则隔离 LLM 成摆设
    assert sess.t_eff_ctl == Trust.T2_MEDIUM, \
        f"t_eff_ctl 不应因普通读而降低。实际={sess.t_eff_ctl.name}。若降低则 DD 类任务全废"
    print(f"  #7a: t_eff_ctl stays T2_MEDIUM after read → 分离有效")

    # 受限查询明确调用 degrade_ctl
    sess.degrade_ctl(Trust.T0_UNTRUSTED)
    assert sess.t_eff_ctl == Trust.T0_UNTRUSTED
    assert sess.t_eff == Trust.T0_UNTRUSTED
    print(f"  #7b: degrade_ctl(T0) applied — both at T0")

    # reset 后恢复
    sess.reset()
    assert sess.t_eff_ctl == Trust.T2_MEDIUM
    assert sess.t_eff == Trust.T2_MEDIUM
    print(f"  #7c: reset restores both")


# ══════════════════════════════════════════════════════════════
# §4 #8: 4 bit 预算全会话共享 — 不因 delegate 而重置
# ══════════════════════════════════════════════════════════════
def test_s4_8_capacity_budget_persists_across_delegate():
    """预算跨 delegate 不重置。用尽后拒绝新的受限查询."""
    agent = _agent()
    store = SessionStore()

    # 父会话消耗预算
    store.get_or_start("parent", agent, "task_A")
    # 默认预算 16.0，连续消耗 5 次
    for i in range(5):
        ok = store.consume_ctl("parent", cost=1.0, source_trust=Trust.T1_LOW)
        assert ok, f"第 {i+1} 次 consume_ctl 应成功"

    parent_used = store._capacity_used["parent"]
    assert parent_used == 5.0
    print(f"  #8a: parent consumed 5.0/16.0 budget")

    # delegate 子会话 — 预算必须继承，不许重置
    child_sess = store.delegate("parent", agent, "task_sub", "child")
    assert store._capacity_used.get("child", 0.0) == 5.0, \
        f"子会话预算应继承 5.0，实际={store._capacity_used.get('child', 0.0)}"
    assert store._capacity_budget.get("child", 0.0) == 16.0
    print(f"  #8b: child inherited budget 5.0/16.0 after delegate")

    # 子会话继续消耗直到耗尽
    for i in range(11):  # 5 + 11 = 16
        ok = store.consume_ctl("child", cost=1.0)
        if i < 11:
            assert ok, f"子会话第 {i+1} 次应成功 (共 {5+1+i})"
    # 第 17 次应拒绝
    exhausted = store.consume_ctl("child", cost=1.0)
    assert not exhausted, "预算耗尽后应拒绝"
    print(f"  #8c: budget exhausted after 16 uses — 第 17 次拒绝")


# ══════════════════════════════════════════════════════════════
# §4 #10: declassify 一律要人签 — AUTO_POLICY=once 下也不例外
# ══════════════════════════════════════════════════════════════
def test_s4_10_declassify_requires_hitl():
    """即使允许降密写入 D 层，无 HITL 记录时必须拒绝."""
    topo = Topology()
    pdp = PDP(topo)
    planner = _planner()
    # 给 planner 加下级，让 D 层写入合法
    topo.add_agent("executor", parent="planner")

    sess = Session.start("s10", planner, "task_x")

    # 尝试降密写入 D 层，declassify_approved=True 但无 HITL 记录
    d, _ = pdp.can_write(planner, sess, Clearance.L0_PUBLIC, Layer.DIRECTIVE,
                         [], WriteOp.VERBATIM, declassify_approved=True,
                         output_text="classified directive")
    assert not d.allowed, \
        f"#10 FAIL: declassify_approved=True 但无 HITL → 应 DENY，实际={d.verdict.value}"
    failed_rules = {c.rule for c in d.checks if not c.passed}
    print(f"  #10a: declassify without HITL → DENY. failed_rules={failed_rules}")

    # 有 HITL 记录 → 允许
    fp = f"declassify:{planner.agent_id}:L0"
    sess.add_hitl(fp)
    d2, _ = pdp.can_write(planner, sess, Clearance.L0_PUBLIC, Layer.DIRECTIVE,
                          [], WriteOp.VERBATIM, declassify_approved=True,
                          output_text="classified directive")
    assert d2.allowed, \
        f"#10 FAIL: declassify_approved + HITL → 应 ALLOW，实际={d2.verdict.value}"
    print(f"  #10b: declassify with HITL record → ALLOW")


# ══════════════════════════════════════════════════════════════
# §4 #11B: NoWriteDown 标签验证 — A11 风格双规则日志
# ══════════════════════════════════════════════════════════════
def test_s4_11b_nowritedown_label_in_write_denial():
    """BLP-Star 写降密拒绝时 denied_by 必须含 NoWriteDown 前缀."""
    topo = Topology()
    pdp = PDP(topo)
    planner = _planner()
    sess = Session.start("s11b", planner, "task_x")

    # L3 → L0 写降密，gap=3 > 2 → 应 DENY + NoWriteDown
    d, decay = pdp.can_write(planner, sess, Clearance.L0_PUBLIC, Layer.CONCLUSION,
                             [], WriteOp.VERBATIM)
    assert not d.allowed
    assert d.denied_by and d.denied_by.startswith("NoWriteDown"), \
        f"#11b FAIL: denied_by 应以 NoWriteDown 开头，实际={d.denied_by}"
    # 内部规则名也应出现
    assert "BLP-Star" in d.denied_by, \
        f"#11b FAIL: denied_by 应包含 BLP-Star，实际={d.denied_by}"
    print(f"  #11b: NoWriteDown label verified — denied_by={d.denied_by}")


# ══════════════════════════════════════════════════════════════
# §4 #11C: C-Eff-WriteDown 也应有 NoWriteDown 标签
# ══════════════════════════════════════════════════════════════
def test_s4_11c_ceff_writedown_has_nowritedown_label():
    """C-Eff 写降密拒绝时 denied_by 也含 NoWriteDown 前缀."""
    from core.labels import MemoryLabel, MemoryType

    topo = Topology()
    pdp = PDP(topo)
    planner = _planner()
    sess = Session.start("s11c", planner, "task_x")

    # 先读 L3 内容 → c_eff 升到 L3
    m_l3 = MemoryLabel(chunk_id="top_secret", sensitivity=Clearance.L3_SECRET,
                       provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                       memory_type=MemoryType.INTEL, owner_agent="admin",
                       task_binding="task_x", collab_group={"soc"})
    pdp.can_read(planner, m_l3, sess)
    assert sess.c_eff == Clearance.L3_SECRET

    # 尝试写 L0 内容 → C-Eff-WriteDown 应拒绝 + NoWriteDown
    d, _ = pdp.can_write(planner, sess, Clearance.L0_PUBLIC, Layer.CONCLUSION,
                         [], WriteOp.VERBATIM)
    assert not d.allowed, f"C-Eff 写降密应拒绝，实际={d.verdict.value}"
    assert d.denied_by and d.denied_by.startswith("NoWriteDown"), \
        f"#11c FAIL: C-Eff 写降密的 denied_by 应以 NoWriteDown 开头，实际={d.denied_by}"
    assert "C-Eff-WriteDown" in d.denied_by, \
        f"#11c FAIL: denied_by 应包含 C-Eff-WriteDown，实际={d.denied_by}"
    print(f"  #11c: C-Eff NoWriteDown verified — denied_by={d.denied_by}")


# ══════════════════════════════════════════════════════════════
# §4 #7B: consume_ctl() → degrade_ctl() 集成路径
# ══════════════════════════════════════════════════════════════
def test_s4_7b_budget_exhaustion_degrades_teff_ctl():
    """consume_ctl 耗尽预算时通过 source_trust 联动降解 t_eff_ctl."""
    agent = _agent()
    store = SessionStore()

    sess = store.get_or_start("s7b", agent, "task_x")
    assert sess.t_eff_ctl == Trust.T2_MEDIUM

    # 通过 consume_ctl (而非直接 degrade_ctl) 消耗预算
    for i in range(5):
        ok = store.consume_ctl("s7b", cost=1.0, source_trust=Trust.T1_LOW)
        assert ok, f"第 {i+1} 次 consume_ctl 应成功"
        assert sess.t_eff_ctl == Trust.T1_LOW, \
            f"consume_ctl with source_trust=T1 应降解 t_eff_ctl，实际={sess.t_eff_ctl.name}"

    # 继续用更低的 source_trust → t_eff_ctl 继续降
    for i in range(3):
        ok = store.consume_ctl("s7b", cost=1.0, source_trust=Trust.T0_UNTRUSTED)
        assert ok
    assert sess.t_eff_ctl == Trust.T0_UNTRUSTED, \
        f"consume_ctl with source_trust=T0 后 t_eff_ctl 应=T0，实际={sess.t_eff_ctl.name}"
    print(f"  #7b: consume_ctl → degrade_ctl integration verified — "
          f"t_eff_ctl={sess.t_eff_ctl.name}, used={store._capacity_used['s7b']}")
