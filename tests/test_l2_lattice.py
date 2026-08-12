"""L2: 标签格与三水位验证"""
from __future__ import annotations

# These tests are read-only verification — no business logic modified.

def test_clearance_ordering():
    """Clearance 偏序: c1 <= c2"""
    from core.labels import Clearance
    levels = list(Clearance)
    for c1 in levels:
        for c2 in levels:
            expected = int(c1) <= int(c2)
            actual = c1 <= c2
            assert actual == expected, f"Clearance ordering failed: {c1} <= {c2} expected {expected}, got {actual}"

def test_trust_ordering():
    """Trust 偏序: t1 >= t2"""
    from core.labels import Trust
    levels = list(Trust)
    for t1 in levels:
        for t2 in levels:
            expected = int(t1) >= int(t2)
            actual = t1 >= t2
            assert actual == expected, f"Trust ordering failed: {t1} >= {t2} expected {expected}, got {actual}"

def test_partial_order_4x4x4x4():
    """穷举 256 组 (c1,t1) ⊑ (c2,t2) iff c1≤c2 and t1≥t2"""
    from core.labels import Clearance, Trust
    cl = list(Clearance)
    tl = list(Trust)
    errors = []
    for c1 in cl:
        for t1 in tl:
            for c2 in cl:
                for t2 in tl:
                    expected = (int(c1) <= int(c2)) and (int(t1) >= int(t2))
                    actual = (c1 <= c2) and (t1 >= t2)
                    if expected != actual:
                        errors.append(f"({c1},{t1}) ⊑ ({c2},{t2}): expected {expected}, got {actual}")
    assert len(errors) == 0, f"Partial order failures ({len(errors)}):\n" + "\n".join(errors[:10])

def test_join_operation():
    """join = (max(c1,c2), min(t1,t2))"""
    from core.labels import Clearance, Trust, meet_trust
    cl = list(Clearance)
    tl = list(Trust)
    errors = []
    for c1 in cl:
        for c2 in cl:
            expected_c = max(int(c1), int(c2))
            actual_c = max(c1, c2)
            if int(actual_c) != expected_c:
                errors.append(f"max({c1},{c2}) expected c={expected_c}, got {int(actual_c)}")
    for t1 in tl:
        for t2 in tl:
            expected_t = min(int(t1), int(t2))
            actual_t = meet_trust([t1, t2])
            if int(actual_t) != expected_t:
                errors.append(f"min({t1},{t2}) expected t={expected_t}, got {int(actual_t)}")
    assert len(errors) == 0, f"Join failures ({len(errors)}):\n" + "\n".join(errors[:10])

def test_bottom_top():
    """⊥ = (L0,T3), ⊤ = (L3,T0)"""
    from core.labels import Clearance, Trust
    cl = list(Clearance)
    tl = list(Trust)
    # bottom: lowest clearance, highest trust = can read nothing secret, but most trusted
    bottom_c = min(cl)
    bottom_t = max(tl)
    assert bottom_c == Clearance.L0_PUBLIC, f"⊥ clearance expected L0, got {bottom_c}"
    assert bottom_t == Trust.T3_HIGH, f"⊥ trust expected T3, got {bottom_t}"
    # top: highest clearance, lowest trust = can read everything, but least trusted
    top_c = max(cl)
    top_t = min(tl)
    assert top_c == Clearance.L3_SECRET, f"⊤ clearance expected L3, got {top_c}"
    assert top_t == Trust.T0_UNTRUSTED, f"⊤ trust expected T0, got {top_t}"

def test_t_eff_monotonicity():
    """连续 absorb 20 条随机记忆，t_eff 单调不增"""
    import random
    from core.labels import AgentLabel, Trust, Role, Clearance
    from core.session import Session

    random.seed(42)
    agent = AgentLabel(agent_id="a_test", role=Role.ANALYST,
                       clearance=Clearance.L2_SENSITIVE, trust_intrinsic=Trust.T3_HIGH)
    sess = Session.start("sess_test", agent, "task_test")
    prev = int(sess.t_eff)
    history = [prev]
    trusts = list(Trust)
    for i in range(20):
        t = random.choice(trusts)
        sess.absorb(f"chunk_{i}", Clearance.L0_PUBLIC, t)
        curr = int(sess.t_eff)
        history.append(curr)
        assert curr <= prev, f"Step {i}: t_eff went from {prev} to {curr} (not monotonically non-increasing)"
        prev = curr
    print(f"  t_eff trajectory: {history}")

def test_reset_restores_t_intrinsic():
    """reset() 后复位到 t_intrinsic"""
    from core.labels import AgentLabel, Trust, Role, Clearance
    from core.session import Session

    agent = AgentLabel(agent_id="a_test", role=Role.ANALYST,
                       clearance=Clearance.L2_SENSITIVE, trust_intrinsic=Trust.T3_HIGH)
    sess = Session.start("sess_test", agent, "task_test")
    sess.absorb("chunk_dirty", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED)
    assert sess.t_eff == Trust.T0_UNTRUSTED
    sess.reset()
    assert sess.t_eff == Trust.T3_HIGH, f"Reset: expected T3, got {sess.t_eff}"
    assert len(sess.reads) == 0, f"reads not cleared after reset"
    assert len(sess.consulted) == 0, f"consulted not cleared after reset"

def test_c_eff_present():
    """验证: c_eff 机密性高水位存在且功能正确"""
    from core.labels import AgentLabel, Trust, Role, Clearance
    from core.session import Session
    agent = AgentLabel(agent_id="a_test", role=Role.ANALYST,
                       clearance=Clearance.L2_SENSITIVE, trust_intrinsic=Trust.T3_HIGH)
    sess = Session.start("sess_c", agent, "task_test")
    assert sess.c_eff == Clearance.L0_PUBLIC, f"Initial c_eff should be L0, got {sess.c_eff}"
    sess.absorb("chunk_l2", Clearance.L2_SENSITIVE, Trust.T3_HIGH)
    assert sess.c_eff == Clearance.L2_SENSITIVE, f"After absorb(L2), c_eff should be L2, got {sess.c_eff}"
    sess.absorb("chunk_l1", Clearance.L1_INTERNAL, Trust.T3_HIGH)
    assert sess.c_eff == Clearance.L2_SENSITIVE, f"c_eff should be monotonic (max), got {sess.c_eff}"
    sess.reset()
    assert sess.c_eff == Clearance.L0_PUBLIC, f"After reset, c_eff should be L0, got {sess.c_eff}"


def test_t_eff_ctl_present():
    """验证: t_eff_ctl LLM 隔离水位存在且功能正确"""
    from core.labels import AgentLabel, Trust, Role, Clearance
    from core.session import Session
    agent = AgentLabel(agent_id="a_test", role=Role.ANALYST,
                       clearance=Clearance.L2_SENSITIVE, trust_intrinsic=Trust.T3_HIGH)
    sess = Session.start("sess_ctl", agent, "task_test")
    assert sess.t_eff_ctl == Trust.T3_HIGH, f"Initial t_eff_ctl should be T3, got {sess.t_eff_ctl}"
    sess.absorb("chunk_t1", Clearance.L0_PUBLIC, Trust.T1_LOW)  # FULL → t_eff_ctl ↓
    assert sess.t_eff_ctl == Trust.T1_LOW, f"After FULL absorb(T1), t_eff_ctl should be T1, got {sess.t_eff_ctl}"
    sess.absorb("chunk_t0", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED)
    assert sess.t_eff_ctl == Trust.T0_UNTRUSTED, f"After FULL absorb(T0), t_eff_ctl should be T0, got {sess.t_eff_ctl}"
    sess.reset()
    assert sess.t_eff_ctl == Trust.T3_HIGH, f"After reset, t_eff_ctl should be T3, got {sess.t_eff_ctl}"

if __name__ == "__main__":
    tests = [
        test_clearance_ordering, test_trust_ordering, test_partial_order_4x4x4x4,
        test_join_operation, test_bottom_top, test_t_eff_monotonicity,
        test_reset_restores_t_intrinsic, test_c_eff_present, test_t_eff_ctl_present,
    ]
    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR {t.__name__}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n---\n{passed} passed, {failed} failed")
