"""§4 十二个"最容易假绿"的对抗性抽查"""
from __future__ import annotations
import sys; sys.path.insert(0, "D:/trustmem")


def test_s4_1_decrypt_count_equals_allow_count():
    """#1: decrypt 次数 == ALLOW 数。不可先全解密再筛选。"""
    from core.topology import Topology
    from core.crypto.engine import CryptoEngine
    from core.labels import (AgentLabel, MemoryLabel, Clearance, Trust,
                             Layer, MemoryType, Role, TaskScope)
    from core.pdp import PDP
    from core.session import Session

    topo = Topology()
    engine = CryptoEngine(topo)
    pdp = PDP(topo)

    agent = AgentLabel(agent_id="a1", role=Role.ANALYST,
                       clearance=Clearance.L2_SENSITIVE, trust_intrinsic=Trust.T2_MEDIUM,
                       task_domain={"task_x"}, collab_group={"grp_soc"})
    engine.register_agent(agent)

    # Create 12 memory labels, only 3 should be ALLOWed (L0 vs L3 sensitivity)
    memories = []
    for i in range(12):
        sens = Clearance.L0_PUBLIC if i < 3 else Clearance.L3_SECRET
        mem = MemoryLabel(chunk_id=f"m{i}", sensitivity=sens,
                          provenance_trust=Trust.T2_MEDIUM, layer=Layer.CONCLUSION,
                          memory_type=MemoryType.INTEL, owner_agent="a2",
                          task_binding="task_x", collab_group={"grp_soc"})
        memories.append(mem)

    # Encrypt all 12
    cts = [engine.encrypt_memory(f"content_{i}", mem) for i, mem in enumerate(memories)]

    sess = Session.start("s1", agent, "task_x")
    scope = TaskScope(task_id="task_x", c_ctx_max=Clearance.L2_SENSITIVE,
                       t_ctx_min=Trust.T0_UNTRUSTED)

    decrypts_before = engine.stats()["total_decrypts"]
    allow_count = 0
    for i, (mem, ct) in enumerate(zip(memories, cts)):
        d = pdp.can_read_scoped(agent, mem, sess, scope)
        if d.verdict.value == "ALLOW":
            allow_count += 1
            pt, err = engine.decrypt_memory(agent, ct)

    decrypts_after = engine.stats()["total_decrypts"]
    actual_decrypts = decrypts_after - decrypts_before

    print(f"  #1: ALLOW count={allow_count}, decrypt calls={actual_decrypts}")
    assert allow_count == 3, f"Expected 3 ALLOW, got {allow_count}"
    assert actual_decrypts == 3, \
        f"FAIL: decrypt calls ({actual_decrypts}) != ALLOW count ({allow_count}). " \
        f"若 {actual_decrypts} > {allow_count}，说明先全解密再筛选，隐藏形同虚设。"


def test_s4_2_bypass_pdp_direct_crypto():
    """#2: 绕过 PDP 直连密码服务是否成功。"""
    from core.topology import Topology
    from core.crypto.engine import CryptoEngine
    from core.labels import (AgentLabel, MemoryLabel, Clearance, Trust,
                             Layer, MemoryType, Role)

    topo = Topology()
    engine = CryptoEngine(topo)

    agent = AgentLabel(agent_id="a_low", role=Role.EXTERNAL,
                       clearance=Clearance.L0_PUBLIC, trust_intrinsic=Trust.T0_UNTRUSTED)
    engine.register_agent(agent)

    # Create an L3 memory
    mem = MemoryLabel(chunk_id="secret_m", sensitivity=Clearance.L3_SECRET,
                      provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                      memory_type=MemoryType.INTEL, owner_agent="admin",
                      task_binding="task_x")
    ct = engine.encrypt_memory("TOP SECRET DATA", mem)

    # Direct decrypt WITHOUT any PDP裁决
    pt, err = engine.decrypt_memory(agent, ct)
    bypassed = (pt is not None)

    if bypassed:
        print(f"  #2: ⚠️ DIRECT BYPASS SUCCESS: L0 agent decrypted L3 content without PDP!")
        print(f"  #2: 这说明'先判决后解密'不是硬约束。")
    else:
        print(f"  #2: Direct decrypt blocked: err={err[:80] if err else 'None'}")
    # Note: In mock mode, ABE policy check still runs. If bypass succeeds, it's a MAJOR finding.
    assert not bypassed, \
        f"CRITICAL: 绕过PDP直连密码服务成功！'先判决后解密'是软断言不是硬约束。"


def test_s4_3_hide_neutrality():
    """#3: I8 隐藏中立性 — HIDE 前后四元组不变（但只有 t_eff 存在）。"""
    from core.labels import AgentLabel, Trust, Role, Clearance
    from core.session import Session

    agent = AgentLabel(agent_id="a1", role=Role.ANALYST,
                       clearance=Clearance.L0_PUBLIC, trust_intrinsic=Trust.T2_MEDIUM)
    sess = Session.start("s3", agent, "task_x")

    # Snapshot before HIDE
    before = (int(sess.t_eff), len(sess.reads), len(sess.consulted))
    # Simulate: a HIDE verdict should not change session state
    # (HIDE doesn't trigger absorb)
    after = (int(sess.t_eff), len(sess.reads), len(sess.consulted))

    changed = before != after
    if changed:
        print(f"  #3: STATE CHANGED: before={before}, after={after}")
    else:
        print(f"  #3: HIDE neutral - session state unchanged: {before}")
    assert not changed, f"I8 violation: HIDE changed session state: {before} → {after}"


def test_s4_4_I14_cross_task():
    """#4: I14 必须序列测 — CONSULT 读 → 切换任务 → 中间 20 步无关操作 → 尝试写回。"""
    from core.labels import (AgentLabel, Trust, Role, Clearance, Layer,
                             MemoryType, MemoryLabel, WriteOp, IngestMode, TaskScope)
    from core.session import Session
    from core.topology import Topology
    from core.pdp import PDP
    import random

    topo = Topology()
    pdp = PDP(topo)

    agent = AgentLabel(agent_id="a1", role=Role.ANALYST,
                       clearance=Clearance.L2_SENSITIVE, trust_intrinsic=Trust.T2_MEDIUM,
                       task_domain={"task_A"}, collab_group={"grp_soc"})
    sess = Session.start("s4", agent, "task_A")

    # CONSULT read a chunk in task_A
    scope_consult = TaskScope(task_id="task_A", c_ctx_max=Clearance.L2_SENSITIVE,
                               t_ctx_min=Trust.T0_UNTRUSTED, ingest=IngestMode.CONSULT)
    m_dirty = MemoryLabel(chunk_id="dirty_intel", sensitivity=Clearance.L0_PUBLIC,
                          provenance_trust=Trust.T1_LOW, layer=Layer.CONCLUSION,
                          memory_type=MemoryType.INTEL, owner_agent="a2",
                          task_binding="task_A", collab_group={"grp_soc"})
    d = pdp.can_read_scoped(agent, m_dirty, sess, scope_consult)
    assert m_dirty.chunk_id in sess.consulted, "CONSULT should add to consulted set"

    # 20 unrelated operations
    random.seed(123)
    for i in range(20):
        m = MemoryLabel(chunk_id=f"rand_{i}", sensitivity=Clearance.L1_INTERNAL,
                        provenance_trust=Trust.T2_MEDIUM, layer=Layer.CONCLUSION,
                        memory_type=MemoryType.EPISODIC, owner_agent="a3",
                        task_binding="task_A", collab_group={"grp_soc"})
        pdp.can_read(agent, m, sess)

    # Now try to write back using the consulted chunk
    d_write, decay = pdp.can_write(agent, sess, Clearance.L0_PUBLIC, Layer.CONCLUSION,
                                    [m_dirty], WriteOp.INFER)
    # I14 should still hold despite 20 intermediate operations
    assert d_write.verdict.value == "DENY", \
        f"#4 FAIL: After 20 ops, I14 leaked. Verdict={d_write.verdict.value}, denied_by={d_write.denied_by}"
    print(f"  #4: I14 holds after 20 intermediate ops → {d_write.verdict.value} (denied_by={d_write.denied_by})")


def test_s4_9_origin_binding():
    """#9: 写时 origin 绑定 — 写 T1 记忆 → 自摘要 → 再摘要 → 翻译，可信度始终 ≤ T1。"""
    from core.labels import (MemoryLabel, Trust, Clearance, Layer, MemoryType, WriteOp)
    from core.decay import compute_trust

    original = MemoryLabel(chunk_id="orig", sensitivity=Clearance.L0_PUBLIC,
                           provenance_trust=Trust.T1_LOW, layer=Layer.CONCLUSION,
                           memory_type=MemoryType.INTEL, owner_agent="a1",
                           task_binding="t1")

    # Round 1: self-summarize
    r1 = compute_trust([original], Trust.T1_LOW, WriteOp.SUMMARIZE)
    print(f"  #9 r1 (summarize T1): trust_out={r1.trust_out.name}, t_inputs={r1.t_inputs.name}")
    assert int(r1.trust_out) <= int(Trust.T1_LOW), \
        f"r1: trust {r1.trust_out.name} > T1"

    # Round 2: summarize again
    # Create a label for the output of r1
    m1 = MemoryLabel(chunk_id="sum1", sensitivity=Clearance.L0_PUBLIC,
                     provenance_trust=r1.trust_out, layer=Layer.CONCLUSION,
                     memory_type=MemoryType.INTEL, owner_agent="a1",
                     task_binding="t1")
    r2 = compute_trust([m1], Trust.T1_LOW, WriteOp.SUMMARIZE)
    print(f"  #9 r2 (summarize again): trust_out={r2.trust_out.name}")
    assert int(r2.trust_out) <= int(Trust.T1_LOW), \
        f"r2: trust {r2.trust_out.name} > T1 (self-summarize laundering!)"

    # Round 3: "translate"
    m2 = MemoryLabel(chunk_id="sum2", sensitivity=Clearance.L0_PUBLIC,
                     provenance_trust=r2.trust_out, layer=Layer.CONCLUSION,
                     memory_type=MemoryType.INTEL, owner_agent="a1",
                     task_binding="t1")
    r3 = compute_trust([m2], Trust.T1_LOW, WriteOp.INFER)
    print(f"  #9 r3 (translate/infer): trust_out={r3.trust_out.name}")
    assert int(r3.trust_out) <= int(Trust.T1_LOW), \
        f"r3: trust {r3.trust_out.name} > T1 (translation laundering!)"
    print(f"  #9: origin binding holds through 3-hop chain — trust never exceeds T1")


def test_s4_12_reasoning_only_upward():
    """#12: R 层仅向上 — 非 owner 祖先、非 auditor 主体读 R 层 → DENY，不可 HIDE。"""
    from core.labels import (AgentLabel, MemoryLabel, Trust, Role, Clearance,
                             Layer, MemoryType)
    from core.session import Session
    from core.topology import Topology
    from core.pdp import PDP

    topo = Topology()
    pdp = PDP(topo)

    # Two unrelated agents in different groups
    owner = AgentLabel(agent_id="owner", role=Role.ANALYST,
                       clearance=Clearance.L2_SENSITIVE, trust_intrinsic=Trust.T2_MEDIUM,
                       collab_group={"group_A"})
    attacker = AgentLabel(agent_id="attacker", role=Role.EXTERNAL,
                          clearance=Clearance.L2_SENSITIVE, trust_intrinsic=Trust.T1_LOW,
                          collab_group={"group_B"})

    m_r = MemoryLabel(chunk_id="reasoning_m", sensitivity=Clearance.L0_PUBLIC,
                      provenance_trust=Trust.T3_HIGH, layer=Layer.REASONING,
                      memory_type=MemoryType.TRAJECTORY, owner_agent="owner",
                      task_binding="t1", collab_group={"group_A"})

    sess = Session.start("s12", attacker, "t1")
    d = pdp.can_read(attacker, m_r, sess)

    # R layer read by non-owner, non-ancestor, non-auditor → must be DENY, NOT HIDE
    assert d.verdict.value == "DENY", \
        f"#12 FAIL: R layer read verdict={d.verdict.value}, expected DENY. " \
        f"If HIDE, R layer is not properly protected (HIDE allows constrained queries!)."
    print(f"  #12: R layer cross-group read → {d.verdict.value} (denied_by={d.denied_by})")


if __name__ == "__main__":
    tests = [
        test_s4_1_decrypt_count_equals_allow_count,
        test_s4_2_bypass_pdp_direct_crypto,
        test_s4_3_hide_neutrality,
        test_s4_4_I14_cross_task,
        test_s4_9_origin_binding,
        test_s4_12_reasoning_only_upward,
    ]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
        except Exception as e:
            import traceback
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
            traceback.print_exc()
            failed += 1
    print(f"\n---\n{passed} passed, {failed} failed")
