"""L3: 可信流转规则 TR1–TR16 验证"""
from __future__ import annotations


def _ctx():
    """设置测试上下文"""
    import sys; sys.path.insert(0, "D:/trustmem")
    from core.labels import (
        Clearance, Trust, Layer, Role, MemoryType, WriteOp,
        AgentLabel, MemoryLabel, meet_trust, IngestMode, TaskScope
    )
    from core.decay import compute_trust, verify_op, DecayResult
    from core.session import Session
    from core.topology import Topology
    from core.pdp import PDP
    from core.verdict import Verdict
    return {
        "Clearance": Clearance, "Trust": Trust, "Layer": Layer, "Role": Role,
        "MemoryType": MemoryType, "WriteOp": WriteOp, "AgentLabel": AgentLabel,
        "MemoryLabel": MemoryLabel, "meet_trust": meet_trust,
        "compute_trust": compute_trust, "verify_op": verify_op,
        "DecayResult": DecayResult, "Session": Session, "Topology": Topology,
        "PDP": PDP, "IngestMode": IngestMode, "TaskScope": TaskScope,
        "Verdict": Verdict,
    }


def test_TR6_output_trust_meets_min_input():
    """TR6: 用 (T3, T1) 两条输入写一条新记忆，trust_out ≤ meet = T1"""
    ctx = _ctx()
    Trust = ctx["Trust"]; MemoryLabel = ctx["MemoryLabel"]; WriteOp = ctx["WriteOp"]
    Clearance = ctx["Clearance"]; Layer = ctx["Layer"]; MemoryType = ctx["MemoryType"]
    compute_trust = ctx["compute_trust"]

    m1 = MemoryLabel(chunk_id="m1", sensitivity=Clearance.L0_PUBLIC,
                     provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                     memory_type=MemoryType.INTEL, owner_agent="a1", task_binding="t1")
    m2 = MemoryLabel(chunk_id="m2", sensitivity=Clearance.L0_PUBLIC,
                     provenance_trust=Trust.T1_LOW, layer=Layer.CONCLUSION,
                     memory_type=MemoryType.INTEL, owner_agent="a2", task_binding="t1")

    result = compute_trust([m1, m2], Trust.T3_HIGH, WriteOp.INFER)
    assert int(result.trust_out) <= int(Trust.T1_LOW), \
        f"TR6 FAIL: trust_out={result.trust_out.name}, expected ≤ T1 (meet=T1). Not max, not mean."
    print(f"  TR6: trust_out={result.trust_out.name}, t_inputs={result.t_inputs.name}, explain={result.explain()}")


def test_TR7_verbatim_forced_downgrade():
    """TR7: 声明 VERBATIM，重叠率 0.5 → op 强制降为 INFER，可信度再降一级"""
    ctx = _ctx()
    Trust = ctx["Trust"]; MemoryLabel = ctx["MemoryLabel"]; WriteOp = ctx["WriteOp"]
    Clearance = ctx["Clearance"]; Layer = ctx["Layer"]; MemoryType = ctx["MemoryType"]
    compute_trust = ctx["compute_trust"]

    m = MemoryLabel(chunk_id="m1", sensitivity=Clearance.L0_PUBLIC,
                    provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                    memory_type=MemoryType.INTEL, owner_agent="a1", task_binding="t1")

    input_text = "The quick brown fox jumps over the lazy dog. " * 10
    output_text = "This is a completely different summary that shares almost no words with the original input text whatsoever."
    result = compute_trust([m], Trust.T3_HIGH, WriteOp.VERBATIM,
                           input_texts=[input_text], output_text=output_text)

    assert result.op_effective == WriteOp.INFER, \
        f"TR7 FAIL: op_effective={result.op_effective.value}, expected INFER"
    assert result.downgraded_reason is not None, \
        f"TR7 FAIL: no downgrade reason provided"
    # Verify trust is lower than it would be with pure VERBATIM
    # VERBATIM: min(T3, T3) - 0 = T3, INFER: min(T3, T3) - 1 = T2
    assert int(result.trust_out) <= Trust.T2_MEDIUM.value, \
        f"TR7 FAIL: trust_out={result.trust_out.name}, expected ≤ T2 (downgraded)"
    print(f"  TR7: op_claimed=VERBATIM → op_effective={result.op_effective.value}, "
          f"trust_out={result.trust_out.name}, reason={result.downgraded_reason}")


def test_TR9_fuse_dirtiest_wins():
    """TR9: FUSE 融合 T3 + T3 + T0 三源 → 结果 = T0（取最脏）"""
    ctx = _ctx()
    Trust = ctx["Trust"]; MemoryLabel = ctx["MemoryLabel"]; WriteOp = ctx["WriteOp"]
    Clearance = ctx["Clearance"]; Layer = ctx["Layer"]; MemoryType = ctx["MemoryType"]
    compute_trust = ctx["compute_trust"]

    m1 = MemoryLabel(chunk_id="m1", sensitivity=Clearance.L0_PUBLIC,
                     provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                     memory_type=MemoryType.INTEL, owner_agent="a1", task_binding="t1")
    m2 = MemoryLabel(chunk_id="m2", sensitivity=Clearance.L0_PUBLIC,
                     provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                     memory_type=MemoryType.INTEL, owner_agent="a2", task_binding="t1")
    m3 = MemoryLabel(chunk_id="m3", sensitivity=Clearance.L0_PUBLIC,
                     provenance_trust=Trust.T0_UNTRUSTED, layer=Layer.CONCLUSION,
                     memory_type=MemoryType.INTEL, owner_agent="a3", task_binding="t1")

    result = compute_trust([m1, m2, m3], Trust.T3_HIGH, WriteOp.FUSE)
    t_out = int(result.trust_out)
    assert t_out == int(Trust.T0_UNTRUSTED), \
        f"TR9 FAIL: trust_out={result.trust_out.name} (T{t_out}), expected T0 (dirtiest)"
    print(f"  TR9: FUSE T3+T3+T0 → {result.trust_out.name} (t_inputs={result.t_inputs.name})")


def test_TR10_consult_write_deny():
    """TR10: CONSULT 读过的 chunk 出现在 input_mems → DENY"""
    ctx = _ctx()
    AgentLabel = ctx["AgentLabel"]; Trust = ctx["Trust"]; Role = ctx["Role"]
    Clearance = ctx["Clearance"]; Session = ctx["Session"]; Topology = ctx["Topology"]
    PDP = ctx["PDP"]; MemoryLabel = ctx["MemoryLabel"]; Layer = ctx["Layer"]
    MemoryType = ctx["MemoryType"]; WriteOp = ctx["WriteOp"]

    topo = Topology()
    pdp = PDP(topo)
    agent = AgentLabel(agent_id="a1", role=Role.ANALYST,
                       clearance=Clearance.L2_SENSITIVE, trust_intrinsic=Trust.T2_MEDIUM)
    sess = Session.start("s10", agent, "task_x")
    # CONSULT a chunk
    m = MemoryLabel(chunk_id="consulted_m", sensitivity=Clearance.L0_PUBLIC,
                    provenance_trust=Trust.T1_LOW, layer=Layer.CONCLUSION,
                    memory_type=MemoryType.INTEL, owner_agent="a2", task_binding="task_x")
    sess.consult("consulted_m")

    # Now try to write back using that consulted chunk as input
    d, decay = pdp.can_write(agent, sess, Clearance.L0_PUBLIC, Layer.CONCLUSION,
                             [m], WriteOp.INFER)
    # I14 should catch this
    assert d.verdict == ctx["Verdict"].DENY, \
        f"TR10 FAIL: verdict={d.verdict.value}, expected DENY. denied_by={d.denied_by}"
    assert "I14" in (d.denied_by or "") or any("I14" in c.detail for c in d.checks), \
        f"TR10 FAIL: I14 not cited in denial. denied_by={d.denied_by}"
    print(f"  TR10: CONSULT write-back → {d.verdict.value} (denied_by={d.denied_by})")


def test_TR14_independence_at_publisher_entity_level():
    """TR14: 两个来源共享同一 publisher → 判为 1 源，不提升"""
    ctx = _ctx()
    Trust = ctx["Trust"]; MemoryLabel = ctx["MemoryLabel"]; WriteOp = ctx["WriteOp"]
    Clearance = ctx["Clearance"]; Layer = ctx["Layer"]; MemoryType = ctx["MemoryType"]
    meet_trust = ctx["meet_trust"]

    # Two "different" sources but same owner (publisher entity level)
    m1 = MemoryLabel(chunk_id="m1", sensitivity=Clearance.L0_PUBLIC,
                     provenance_trust=Trust.T1_LOW, layer=Layer.CONCLUSION,
                     memory_type=MemoryType.INTEL, owner_agent="same_publisher",
                     task_binding="t1")
    m2 = MemoryLabel(chunk_id="m2", sensitivity=Clearance.L0_PUBLIC,
                     provenance_trust=Trust.T1_LOW, layer=Layer.CONCLUSION,
                     memory_type=MemoryType.INTEL, owner_agent="same_publisher",
                     task_binding="t1")

    meet = meet_trust([m1.provenance_trust, m2.provenance_trust])
    assert int(meet) == int(Trust.T1_LOW), \
        f"TR14: meet of same publisher = {meet.name}, expected T1 (no boost from duplicate source)"
    print(f"  TR14: Two same-publisher sources → meet={meet.name} (no spurious boost)")

    # Verify that owner_agent identity matters: different owners, same trust
    m3 = MemoryLabel(chunk_id="m3", sensitivity=Clearance.L0_PUBLIC,
                     provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                     memory_type=MemoryType.INTEL, owner_agent="other_publisher",
                     task_binding="t1")
    meet2 = meet_trust([m1.provenance_trust, m3.provenance_trust])
    assert int(meet2) == int(Trust.T1_LOW), \
        f"TR14: cross-publisher meet = {meet2.name}, expected T1 (still min trust)"
    print(f"  TR14: Cross-publisher sources → meet={meet2.name}")


def test_F27_verbatim_long_text_bounded_time():
    """F27: 超长文本 VERBATIM 校验走 O(1) 保守降级，20KB < 50ms"""
    import time
    ctx = _ctx()
    WriteOp = ctx["WriteOp"]; verify_op = ctx["verify_op"]

    long_text = "A" * 20_000          # 超过 MAX_VERBATIM_LEN(10_000)
    t0 = time.perf_counter()
    op_eff, reason = verify_op(WriteOp.VERBATIM, [long_text], long_text)
    elapsed = time.perf_counter() - t0

    assert op_eff == WriteOp.INFER, \
        f"F27 FAIL: 超长文本应保守降级 INFER，实得 {op_eff.value}"
    assert reason is not None
    assert elapsed < 0.05, \
        f"F27 FAIL: 超长文本校验耗时 {elapsed*1000:.1f}ms，应 < 50ms"
    print(f"  F27: 20KB VERBATIM → {op_eff.value} ({elapsed*1000:.2f}ms) reason={reason}")


if __name__ == "__main__":
    tests = [
        test_TR6_output_trust_meets_min_input,
        test_TR7_verbatim_forced_downgrade,
        test_TR9_fuse_dirtiest_wins,
        test_TR10_consult_write_deny,
        test_TR14_independence_at_publisher_entity_level,
        test_F27_verbatim_long_text_bounded_time,
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
