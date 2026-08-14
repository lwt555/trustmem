"""Tests for HIDE path: Verdict enum, VarStore, ControlFlowBudget, IsolatedLLM, PDP HIDE, Pipeline integration."""
from __future__ import annotations

import pytest

from core.verdict import Verdict
from core.varstore import VarStore, VarHandle
from core.isolated_llm import (
    ControlFlowBudget, ConstrainedAnswer, StubIsolatedLLM,
)
from core.labels import (
    AgentLabel, MemoryLabel, Clearance, Trust, Layer, MemoryType,
    WriteOp, Role, TaskScope, IngestMode,
)
from core.session import Session
from core.pdp import PDP, Decision, Check
from core.topology import Topology
from core.pipeline import WritePipeline, ReadPipeline, WriteResult, ReadResult
from core.crypto.engine import CryptoEngine


# ══════════════════════════════════════════════════════════════
# Verdict
# ══════════════════════════════════════════════════════════════

class TestVerdict:
    def test_allow_is_accessible(self):
        assert Verdict.ALLOW.is_accessible
        assert Verdict.ALLOW.can_read_content
        assert not Verdict.ALLOW.is_blocked

    def test_hide_is_accessible_but_cannot_read(self):
        assert Verdict.HIDE.is_accessible
        assert not Verdict.HIDE.can_read_content
        assert not Verdict.HIDE.is_blocked

    def test_confirm_is_accessible(self):
        assert Verdict.CONFIRM.is_accessible
        assert not Verdict.CONFIRM.can_read_content
        assert not Verdict.CONFIRM.is_blocked

    def test_deny_is_blocked(self):
        assert not Verdict.DENY.is_accessible
        assert not Verdict.DENY.can_read_content
        assert Verdict.DENY.is_blocked

    def test_verdict_str_value(self):
        assert Verdict.ALLOW.value == "ALLOW"
        assert Verdict.HIDE.value == "HIDE"


# ══════════════════════════════════════════════════════════════
# VarStore
# ══════════════════════════════════════════════════════════════

class TestVarStore:

    @pytest.fixture
    def store(self):
        return VarStore()

    def test_store_and_get(self, store):
        h = VarHandle(var_id="var-abc", chunk_id="mem-1", reason="BLP-SimpleSecurity")
        store.store(h)
        assert store.get("var-abc") is h

    def test_resolve_by_chunk(self, store):
        h = VarHandle(var_id="var-xyz", chunk_id="mem-99",
                      reason="TaskScope-C")
        store.store(h)
        assert store.resolve("mem-99") is h

    def test_get_missing(self, store):
        assert store.get("nonexistent") is None

    def test_list_all(self, store):
        for i in range(3):
            store.store(VarHandle(var_id=f"var-{i}", chunk_id=f"mem-{i}",
                                  reason="BLP-SimpleSecurity"))
        assert len(store.list_all()) == 3

    def test_list_by_reason(self, store):
        store.store(VarHandle("var-a", "mem-a", "BLP-SimpleSecurity"))
        store.store(VarHandle("var-b", "mem-b", "TaskScope-C"))
        store.store(VarHandle("var-c", "mem-c", "BLP-SimpleSecurity"))

        blp_list = store.list_by_reason("BLP-SimpleSecurity")
        assert len(blp_list) == 2
        assert all(h.reason == "BLP-SimpleSecurity" for h in blp_list)

    def test_remove(self, store):
        h = VarHandle("var-del", "mem-del", "Test")
        store.store(h)
        store.remove("var-del")
        assert store.get("var-del") is None
        assert store.resolve("mem-del") is None

    def test_remove_missing(self, store):
        store.remove("no-exist")  # should not raise

    def test_clear(self, store):
        store.store(VarHandle("var-1", "mem-1", "Test"))
        store.store(VarHandle("var-2", "mem-2", "Test"))
        store.clear()
        assert store.count == 0
        assert len(store.list_all()) == 0

    def test_new_id_format(self):
        vid = VarStore.new_id()
        assert vid.startswith("var-")
        assert len(vid) == 12  # var- + 8 hex

    def test_placeholder_format(self):
        h = VarHandle("var-abc12345", "mem-x", "BLP-SimpleSecurity")
        assert h.placeholder == "#var-abc12345#"

    def test_describe_includes_reason(self):
        h = VarHandle("var-desc", "mem-d", "BLP-SimpleSecurity",
                      constraint_types=["bool"],
                      metadata={"sensitivity": "L2", "trust": "T1"})
        desc = h.describe()
        assert "#var-desc#" in desc
        assert "BLP-SimpleSecurity" in desc
        assert "bool" in desc
        assert "L2" in desc

    def test_count(self, store):
        assert store.count == 0
        store.store(VarHandle("v1", "m1", "R"))
        assert store.count == 1

    def test_stats_by_reason(self, store):
        store.store(VarHandle("v1", "m1", "BLP-SimpleSecurity"))
        store.store(VarHandle("v2", "m2", "BLP-SimpleSecurity"))
        store.store(VarHandle("v3", "m3", "CognitiveLayer"))
        s = store.stats()
        assert s["total"] == 3
        assert s["by_reason"]["BLP-SimpleSecurity"] == 2
        assert s["by_reason"]["CognitiveLayer"] == 1


# ══════════════════════════════════════════════════════════════
# ControlFlowBudget
# ══════════════════════════════════════════════════════════════

class TestControlFlowBudget:

    @pytest.fixture
    def budget(self):
        return ControlFlowBudget()

    def test_initial_state(self, budget):
        assert budget.remaining == 4.0
        assert budget.query_count == 0
        assert not budget.is_exhausted

    def test_consume_decrements(self, budget):
        assert budget.consume(1.0)
        assert budget.remaining == 3.0
        assert budget.query_count == 1

    def test_consume_until_exhausted(self, budget):
        for i in range(4):
            assert budget.consume(1.0), f"Query {i+1} should succeed"
        assert budget.is_exhausted
        assert budget.remaining == 0.0
        assert not budget.consume(1.0)

    def test_consume_fractional(self, budget):
        assert budget.consume(0.5)
        assert budget.remaining == 3.5
        assert not budget.is_exhausted

    def test_consume_insufficient_fails(self, budget):
        assert budget.consume(3.9)
        assert not budget.consume(1.0)
        assert budget.is_exhausted

    def test_reset(self, budget):
        budget.consume(4.0)
        assert budget.is_exhausted
        budget.reset()
        assert budget.remaining == 4.0
        assert budget.query_count == 0
        assert not budget.is_exhausted

    def test_custom_max_bits(self):
        b = ControlFlowBudget(max_bits=2.0)
        assert b.consume(1.0)
        assert b.consume(1.0)
        assert not b.consume(1.0)

    def test_stats(self, budget):
        budget.consume(1.5)
        s = budget.stats()
        assert s["max_bits"] == 4.0
        assert s["remaining"] == 2.5
        assert s["query_count"] == 1
        assert not s["exhausted"]

    def test_consume_exact_exhausts(self, budget):
        assert budget.consume(4.0)
        assert budget.is_exhausted
        assert budget.remaining == 0.0

    def test_consume_after_exhausted(self, budget):
        budget.consume(4.0)
        assert not budget.consume(0.01)  # tiny cost still fails


# ══════════════════════════════════════════════════════════════
# StubIsolatedLLM
# ══════════════════════════════════════════════════════════════

class TestStubIsolatedLLM:

    @pytest.fixture
    def var_store(self):
        return VarStore()

    @pytest.fixture
    def llm(self, var_store):
        return StubIsolatedLLM(var_store)

    def _register(self, llm, var_store, vid, cid, reason, content):
        h = VarHandle(vid, cid, reason)
        var_store.store(h)
        llm.register_content(vid, content)

    def test_query_bool_returns_answer(self, llm, var_store):
        self._register(llm, var_store, "var-1", "mem-1", "BLP",
                       "threat level is elevated and critical")
        ans = llm.query_bool("var-1", "is the threat level elevated?")
        assert ans.answer is True
        assert ans.answer_type == "bool"

    def test_query_bool_false(self, llm, var_store):
        self._register(llm, var_store, "var-2", "mem-2", "BLP",
                       "the system is safe and normal")
        ans = llm.query_bool("var-2", "is the threat level elevated?")
        assert ans.answer is False

    def test_query_enum_picks_best_match(self, llm, var_store):
        self._register(llm, var_store, "var-3", "mem-3", "BLP",
                       "the attack type is phishing")
        ans = llm.query_enum("var-3", "what type of attack?",
                            ["phishing", "malware", "ddos"])
        assert ans.answer == "phishing"

    def test_query_number_extracts_from_content(self, llm, var_store):
        self._register(llm, var_store, "var-4", "mem-4", "BLP",
                       "confidence score: 0.85 out of 1.0")
        ans = llm.query_number("var-4", "what is the confidence?")
        assert 0.0 <= ans.answer <= 100.0

    def test_query_consumes_budget(self, llm, var_store):
        self._register(llm, var_store, "var-b", "mem-b", "BLP", "content")
        assert llm.budget.remaining == 4.0
        llm.query_bool("var-b", "question?")
        assert llm.budget.remaining == 3.0

    def test_unknown_var_id_raises(self, llm):
        with pytest.raises(KeyError):
            llm.query_bool("nonexistent", "question?")

    def test_disallowed_query_type_raises(self, llm, var_store):
        h = VarHandle("var-dt", "mem-dt", "BLP", constraint_types=["bool"])  # only bool
        var_store.store(h)
        llm.register_content("var-dt", "content")
        with pytest.raises(ValueError, match="not allowed"):
            llm.query_number("var-dt", "how many?")

    def test_budget_exhaustion_blocks_query(self, llm, var_store):
        self._register(llm, var_store, "var-ex", "mem-ex", "BLP", "content")
        # Consume all budget first
        llm.budget.consume(4.0)
        ans = llm.query_bool("var-ex", "is it safe?")
        assert ans.budget_consumed == 0
        assert ans.answer is None

    def test_query_log_accumulates(self, llm, var_store):
        self._register(llm, var_store, "v1", "m1", "BLP", "critical alert")
        self._register(llm, var_store, "v2", "m2", "BLP", "normal status")
        llm.query_bool("v1", "critical?")
        llm.query_bool("v2", "normal?")
        assert len(llm._query_log) == 2

    def test_reset_budget(self, llm, var_store):
        self._register(llm, var_store, "vr", "mr", "BLP", "data")
        llm.budget.consume(4.0)
        assert llm.budget.is_exhausted
        llm.reset_budget()
        assert llm.budget.remaining == 4.0
        assert not llm.budget.is_exhausted

    def test_stats(self, llm, var_store):
        self._register(llm, var_store, "vs", "ms", "BLP", "stats test")
        llm.query_bool("vs", "test?")
        s = llm.stats()
        assert s["content_count"] == 1
        assert s["query_log_size"] == 1
        assert "budget" in s

    def test_query_enum_defaults_to_first(self, llm, var_store):
        """When no options match content, returns first option."""
        self._register(llm, var_store, "ve", "me", "BLP", "unrelated content")
        ans = llm.query_enum("ve", "choose one:", ["alpha", "beta", "gamma"])
        assert ans.answer == "alpha"


# ══════════════════════════════════════════════════════════════
# PDP HIDE Decisions
# ══════════════════════════════════════════════════════════════

class TestPDPHideDecisions:

    @pytest.fixture
    def topo(self):
        t = Topology()
        t.add_agent("planner-1")
        t.add_agent("analyst-1", parent="planner-1")
        t.add_agent("retriever-1", parent="planner-1")
        return t

    @pytest.fixture
    def pdp(self, topo):
        return PDP(topo)

    def test_blp_failure_returns_hard_deny(self, pdp):
        """BLP 失败是无读上硬拒绝（F-01），不可 HIDE."""
        agent = AgentLabel("analyst-1", Role.ANALYST, Clearance.L1_INTERNAL,
                           Trust.T2_MEDIUM, task_domain={"task-1"},
                           collab_group={"sec"}, epoch=1)
        mem = MemoryLabel("mem-h", Clearance.L3_SECRET, Trust.T2_MEDIUM,
                          Layer.CONCLUSION, MemoryType.INTEL, "retriever-1",
                          "task-1", collab_group={"sec"}, epoch=1)
        sess = Session.start("s", agent, "task-1")
        d = pdp.can_read(agent, mem, sess)
        assert d.verdict == Verdict.DENY
        assert not d.allowed
        assert d.hideable is False
        assert d.denied_by == "BLP-SimpleSecurity"

    def test_need_to_know_failure_returns_deny(self, pdp):
        """NeedToKnow failure is DENY (wrong task, no access)."""
        agent = AgentLabel("analyst-1", Role.ANALYST, Clearance.L3_SECRET,
                           Trust.T2_MEDIUM, task_domain={"task-1"},
                           collab_group={"sec"}, epoch=1)
        mem = MemoryLabel("mem-n", Clearance.L0_PUBLIC, Trust.T2_MEDIUM,
                          Layer.CONCLUSION, MemoryType.INTEL, "retriever-1",
                          "other-task", collab_group={"sec"}, epoch=1)
        sess = Session.start("s", agent, "task-1")
        d = pdp.can_read(agent, mem, sess)
        assert d.verdict == Verdict.DENY
        assert d.denied_by == "NeedToKnow"

    def test_ttl_failure_returns_deny(self, pdp):
        """TTL expiry is DENY."""
        from datetime import datetime, timedelta, timezone
        past = datetime.now(timezone.utc) - timedelta(days=30)
        agent = AgentLabel("analyst-1", Role.ANALYST, Clearance.L3_SECRET,
                           Trust.T2_MEDIUM, task_domain={"task-1"},
                           collab_group={"sec"}, epoch=1,
                           ttl_end=past)
        mem = MemoryLabel("mem-t", Clearance.L0_PUBLIC, Trust.T2_MEDIUM,
                          Layer.CONCLUSION, MemoryType.INTEL, "retriever-1",
                          "task-1", collab_group={"sec"}, epoch=1)
        sess = Session.start("s", agent, "task-1")
        d = pdp.can_read(agent, mem, sess)
        assert d.verdict == Verdict.DENY
        assert d.denied_by == "TTL"

    def test_allow_returns_allow(self, pdp):
        """All checks pass → ALLOW."""
        agent = AgentLabel("analyst-1", Role.ANALYST, Clearance.L2_SENSITIVE,
                           Trust.T2_MEDIUM, task_domain={"task-1"},
                           collab_group={"sec"}, epoch=1)
        mem = MemoryLabel("mem-a", Clearance.L1_INTERNAL, Trust.T2_MEDIUM,
                          Layer.CONCLUSION, MemoryType.INTEL, "analyst-1",
                          "task-1", collab_group={"sec"}, epoch=1)
        sess = Session.start("s", agent, "task-1")
        d = pdp.can_read(agent, mem, sess)
        assert d.verdict == Verdict.ALLOW
        assert d.allowed

    def test_write_decisions_use_deny_or_allow_only(self, pdp):
        """Write decisions only use ALLOW or DENY."""
        agent = AgentLabel("analyst-1", Role.ANALYST, Clearance.L2_SENSITIVE,
                           Trust.T2_MEDIUM, task_domain={"task-1"},
                           collab_group={"sec"}, epoch=1)
        sess = Session.start("s", agent, "task-1")
        d, _ = pdp.can_write(agent, sess, Clearance.L1_INTERNAL, Layer.CONCLUSION,
                             [], WriteOp.VERBATIM)
        assert d.verdict == Verdict.ALLOW
        assert d.allowed

    def test_scoped_read_task_scope_c_hide(self, pdp):
        """TaskScope-C failure returns HIDE."""
        agent = AgentLabel("analyst-1", Role.ANALYST, Clearance.L2_SENSITIVE,
                           Trust.T2_MEDIUM, task_domain={"task-1"},
                           collab_group={"sec"}, epoch=1)
        mem = MemoryLabel("mem-s", Clearance.L2_SENSITIVE, Trust.T2_MEDIUM,
                          Layer.CONCLUSION, MemoryType.INTEL, "retriever-1",
                          "task-1", collab_group={"sec"}, epoch=1)
        sess = Session.start("s", agent, "task-1")
        scope = TaskScope("task-1", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED)
        d = pdp.can_read_scoped(agent, mem, sess, scope)
        assert d.verdict == Verdict.HIDE
        assert d.denied_by == "TaskScope-C"

    def test_scoped_read_task_scope_t_hide(self, pdp):
        """TaskScope-T 跌破可信下限 → HIDE（F-07）。"""
        agent = AgentLabel("analyst-1", Role.ANALYST, Clearance.L2_SENSITIVE,
                           Trust.T2_MEDIUM, task_domain={"task-1"},
                           collab_group={"sec"}, epoch=1)
        mem = MemoryLabel("mem-st", Clearance.L1_INTERNAL, Trust.T2_MEDIUM,
                          Layer.CONCLUSION, MemoryType.INTEL, "retriever-1",
                          "task-1", collab_group={"sec"}, epoch=1)
        sess = Session.start("s", agent, "task-1")
        scope = TaskScope("task-1", Clearance.L3_SECRET, Trust.T3_HIGH)
        d = pdp.can_read_scoped(agent, mem, sess, scope)
        assert d.verdict == Verdict.HIDE
        assert d.denied_by == "TaskScope-T"

    def test_decision_explain_shows_verdict(self, pdp):
        agent = AgentLabel("analyst-1", Role.ANALYST, Clearance.L2_SENSITIVE,
                           Trust.T2_MEDIUM, task_domain={"task-1"},
                           collab_group={"sec"}, epoch=1)
        mem = MemoryLabel("mem-ex", Clearance.L1_INTERNAL, Trust.T2_MEDIUM,
                          Layer.CONCLUSION, MemoryType.INTEL, "analyst-1",
                          "task-1", collab_group={"sec"}, epoch=1)
        sess = Session.start("s", agent, "task-1")
        d = pdp.can_read(agent, mem, sess)
        explanation = d.explain()
        assert "ALLOW" in explanation


# ══════════════════════════════════════════════════════════════
# Pipeline HIDE Integration
# ══════════════════════════════════════════════════════════════

class StubMemoryStore:
    def __init__(self):
        self._data: dict[str, MemoryLabel] = {}

    def put(self, mem: MemoryLabel):
        self._data[mem.chunk_id] = mem

    def get(self, chunk_id: str) -> MemoryLabel | None:
        return self._data.get(chunk_id)

    def list_by_task(self, task_id: str) -> list[MemoryLabel]:
        return [m for m in self._data.values() if m.task_binding == task_id]


class StubAuditStore:
    def __init__(self):
        self.events: list[Decision] = []

    def log(self, decision: Decision):
        self.events.append(decision)


class StubCryptoEngine:
    def __init__(self, topo: Topology):
        self._engine = CryptoEngine(topo)

    def register(self, agent: AgentLabel):
        self._engine.register_agent(agent)

    def encrypt_memory(self, content: str, mem_label: MemoryLabel) -> object:
        return self._engine.encrypt_memory(content, mem_label)

    def decrypt_memory(self, agent: AgentLabel, ct: object) -> tuple[bytes | None, str]:
        if ct is None:
            return b"<decrypted content>", "[ALLOW] 解密成功 (stub)"
        return self._engine.decrypt_memory(agent, ct)


class TestPipelineHideIntegration:

    @pytest.fixture
    def topo(self):
        t = Topology()
        t.add_agent("planner-1")
        t.add_agent("analyst-1", parent="planner-1")
        t.add_agent("retriever-1", parent="planner-1")
        return t

    @pytest.fixture
    def pdp(self, topo):
        return PDP(topo)

    @pytest.fixture
    def mem_store(self):
        return StubMemoryStore()

    @pytest.fixture
    def audit_store(self):
        return StubAuditStore()

    @pytest.fixture
    def crypto(self, topo):
        c = StubCryptoEngine(topo)
        for agent_id, role, clearance, trust in [
            ("planner-1", Role.PLANNER, Clearance.L3_SECRET, Trust.T3_HIGH),
            ("analyst-1", Role.ANALYST, Clearance.L2_SENSITIVE, Trust.T2_MEDIUM),
            ("retriever-1", Role.RETRIEVER, Clearance.L1_INTERNAL, Trust.T2_MEDIUM),
        ]:
            agent = AgentLabel(agent_id=agent_id, role=role, clearance=clearance,
                               trust_intrinsic=trust, task_domain={"task-1"},
                               collab_group={"sec"}, epoch=1)
            c.register(agent)
        return c

    @pytest.fixture
    def read_pipe(self, pdp, crypto, mem_store, audit_store):
        return ReadPipeline(pdp, crypto, mem_store, audit_store)

    @pytest.fixture
    def analyst(self):
        return AgentLabel("analyst-1", Role.ANALYST, Clearance.L2_SENSITIVE,
                          Trust.T2_MEDIUM, task_domain={"task-1"},
                          collab_group={"sec"}, epoch=1)

    @pytest.fixture
    def executor(self):
        return AgentLabel("executor-1", Role.EXECUTOR, Clearance.L1_INTERNAL,
                          Trust.T1_LOW, task_domain={"task-1"},
                          collab_group={"sec"}, epoch=1)

    def test_read_l3_memory_as_l1_returns_hide(self, read_pipe, executor, mem_store):
        """L1 executor reading beyond-scope memory gets HIDE with VarHandle."""
        mem = MemoryLabel("secret-42", Clearance.L1_INTERNAL, Trust.T3_HIGH,
                          Layer.CONCLUSION, MemoryType.INTEL, "analyst-1",
                          "task-1", collab_group={"sec"}, epoch=1)
        mem_store.put(mem)
        sess = Session.start("s", executor, "task-1")
        scope = TaskScope("task-1", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED)
        result = read_pipe.read(agent=executor, session=sess, chunk_id="secret-42",
                                scope=scope)

        assert not result.allowed
        assert result.hidden
        assert result.var_handle is not None
        assert result.var_handle.reason == "TaskScope-C"
        assert "var-" in result.var_handle.var_id

    def test_hide_creates_var_handle_in_store(self, read_pipe, executor, mem_store):
        """HIDE result registers handle in VarStore."""
        mem = MemoryLabel("sensitive", Clearance.L1_INTERNAL, Trust.T3_HIGH,
                          Layer.CONCLUSION, MemoryType.INTEL, "analyst-1",
                          "task-1", collab_group={"sec"}, epoch=1)
        mem_store.put(mem)
        sess = Session.start("s", executor, "task-1")
        scope = TaskScope("task-1", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED)
        result = read_pipe.read(agent=executor, session=sess, chunk_id="sensitive",
                                scope=scope)

        assert result.hidden
        stored = read_pipe.var_store.get(result.var_handle.var_id)
        assert stored is result.var_handle
        assert stored.chunk_id == "sensitive"

    def test_hide_audits_decision(self, read_pipe, executor, mem_store, audit_store):
        """HIDE decisions are audited."""
        mem = MemoryLabel("audit-h", Clearance.L1_INTERNAL, Trust.T3_HIGH,
                          Layer.CONCLUSION, MemoryType.INTEL, "analyst-1",
                          "task-1", collab_group={"sec"}, epoch=1)
        mem_store.put(mem)
        sess = Session.start("s", executor, "task-1")
        scope = TaskScope("task-1", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED)
        read_pipe.read(agent=executor, session=sess, chunk_id="audit-h", scope=scope)

        assert len(audit_store.events) == 1
        assert audit_store.events[0].verdict == Verdict.HIDE

    def test_hide_metadata_visible(self, read_pipe, executor, mem_store):
        """HIDE result exposes metadata in the var_handle."""
        mem = MemoryLabel("meta-1", Clearance.L1_INTERNAL, Trust.T3_HIGH,
                          Layer.CONCLUSION, MemoryType.INTEL, "analyst-1",
                          "task-1", collab_group={"sec"}, epoch=1)
        mem_store.put(mem)
        sess = Session.start("s", executor, "task-1")
        scope = TaskScope("task-1", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED)
        result = read_pipe.read(agent=executor, session=sess, chunk_id="meta-1",
                                scope=scope)

        meta = result.var_handle.metadata
        assert meta["sensitivity"] is not None
        assert meta["trust"] is not None
        assert meta["layer"] == "C"

    def test_hide_explain_output(self, read_pipe, executor, mem_store):
        mem = MemoryLabel("explain-h", Clearance.L1_INTERNAL, Trust.T3_HIGH,
                          Layer.CONCLUSION, MemoryType.INTEL, "analyst-1",
                          "task-1", collab_group={"sec"}, epoch=1)
        mem_store.put(mem)
        sess = Session.start("s", executor, "task-1")
        scope = TaskScope("task-1", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED)
        result = read_pipe.read(agent=executor, session=sess, chunk_id="explain-h",
                                scope=scope)

        explanation = result.explain()
        assert "HIDE" in explanation
        assert result.var_handle.var_id in explanation

    def test_normal_read_still_works(self, read_pipe, analyst, mem_store):
        """HIDE pipeline integration doesn't break normal ALLOW reads."""
        mem = MemoryLabel("normal", Clearance.L1_INTERNAL, Trust.T2_MEDIUM,
                          Layer.CONCLUSION, MemoryType.INTEL, "analyst-1",
                          "task-1", collab_group={"sec"}, epoch=1)
        mem_store.put(mem)
        sess = Session.start("s", analyst, "task-1")
        scope = TaskScope("task-1", Clearance.L3_SECRET, Trust.T0_UNTRUSTED)
        result = read_pipe.read(agent=analyst, session=sess, chunk_id="normal",
                                scope=scope)

        assert result.allowed
        assert not result.hidden
        assert result.var_handle is None

    def test_var_store_accumulates_multiple_hides(self, read_pipe, executor, mem_store):
        """Multiple HIDE reads create distinct handles."""
        for i in range(3):
            mem = MemoryLabel(f"hide-{i}", Clearance.L1_INTERNAL, Trust.T3_HIGH,
                              Layer.CONCLUSION, MemoryType.INTEL, "analyst-1",
                              "task-1", collab_group={"sec"}, epoch=1)
            mem_store.put(mem)

        sess = Session.start("s", executor, "task-1")
        scope = TaskScope("task-1", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED)
        for i in range(3):
            result = read_pipe.read(agent=executor, session=sess, chunk_id=f"hide-{i}",
                                    scope=scope)
            assert result.hidden
            assert result.var_handle.chunk_id == f"hide-{i}"

        assert read_pipe.var_store.count == 3
        all_handles = read_pipe.var_store.list_all()
        chunk_ids = {h.chunk_id for h in all_handles}
        assert chunk_ids == {"hide-0", "hide-1", "hide-2"}


# ══════════════════════════════════════════════════════════════
# End-to-End: Write → HIDE → Constrained Query
# ══════════════════════════════════════════════════════════════

class TestEndToEndHidePath:

    @pytest.fixture
    def topo(self):
        t = Topology()
        t.add_agent("planner-1")
        t.add_agent("analyst-1", parent="planner-1")
        t.add_agent("retriever-1", parent="planner-1")
        return t

    def test_full_hide_workflow(self, topo):
        """Complete HIDE flow:
        1. Planner writes L3 memory
        2. Retriever (L1) reads → HIDE
        3. Retriever uses IsolatedLLM to query #var#
        """
        # Setup
        pdp = PDP(topo)
        mem_store = StubMemoryStore()
        audit_store = StubAuditStore()
        crypto = StubCryptoEngine(topo)

        # Register agents
        planner = AgentLabel("planner-1", Role.PLANNER, Clearance.L3_SECRET,
                             Trust.T3_HIGH, task_domain={"task-1"},
                             collab_group={"sec"}, epoch=1)
        retriever = AgentLabel("retriever-1", Role.RETRIEVER, Clearance.L1_INTERNAL,
                               Trust.T2_MEDIUM, task_domain={"task-1"},
                               collab_group={"sec"}, epoch=1)
        crypto.register(planner)
        crypto.register(retriever)

        # Read pipeline with VarStore
        read_pipe = ReadPipeline(pdp, crypto, mem_store, audit_store)
        var_store = read_pipe.var_store

        # 1. Store L1 memory (simulating a planner write)
        mem = MemoryLabel("top-secret-1", Clearance.L1_INTERNAL, Trust.T3_HIGH,
                          Layer.CONCLUSION, MemoryType.INTEL, "planner-1",
                          "task-1", collab_group={"sec"}, epoch=1)
        mem_store.put(mem)

        # 2. Retriever tries to read under a scope capped at L0 → gets HIDE
        sess = Session.start("s", retriever, "task-1")
        scope = TaskScope("task-1", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED)
        result = read_pipe.read(agent=retriever, session=sess, chunk_id="top-secret-1",
                                scope=scope)

        assert result.hidden
        assert result.var_handle is not None
        var_id = result.var_handle.var_id

        # 3. Use IsolatedLLM to query the hidden content
        isolated_llm = StubIsolatedLLM(var_store)
        isolated_llm.register_content(var_id, "The threat level is CRITICAL: confirmed phishing attack")

        ans = isolated_llm.query_bool(var_id, "is this a phishing attack?")
        assert ans.answer is True
        assert ans.budget_consumed == 1.0

        ans2 = isolated_llm.query_enum(var_id, "what is the threat level?",
                                       ["low", "medium", "high", "critical"])
        assert ans2.answer == "critical"

    def test_hide_then_budget_exhausted(self, topo):
        """Budget exhaustion prevents further queries after 4."""
        pdp = PDP(topo)
        mem_store = StubMemoryStore()
        audit_store = StubAuditStore()
        crypto = StubCryptoEngine(topo)

        retriever = AgentLabel("retriever-1", Role.RETRIEVER, Clearance.L1_INTERNAL,
                               Trust.T2_MEDIUM, task_domain={"task-1"},
                               collab_group={"sec"}, epoch=1)
        crypto.register(retriever)

        read_pipe = ReadPipeline(pdp, crypto, mem_store, audit_store)
        var_store = read_pipe.var_store

        mem = MemoryLabel("secret", Clearance.L1_INTERNAL, Trust.T3_HIGH,
                          Layer.CONCLUSION, MemoryType.INTEL, "planner-1",
                          "task-1", collab_group={"sec"}, epoch=1)
        mem_store.put(mem)

        sess = Session.start("s", retriever, "task-1")
        scope = TaskScope("task-1", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED)
        result = read_pipe.read(agent=retriever, session=sess, chunk_id="secret",
                                scope=scope)
        var_id = result.var_handle.var_id

        isolated_llm = StubIsolatedLLM(var_store)
        isolated_llm.register_content(var_id, "data with info: 1, 2, 3, 4, 5")

        # Use all 4 queries
        for i in range(4):
            ans = isolated_llm.query_bool(var_id, f"query {i}?")
            assert ans.budget_consumed == 1.0

        # 5th query blocked
        ans5 = isolated_llm.query_bool(var_id, "query 5?")
        assert ans5.budget_consumed == 0
        assert ans5.answer is None
        assert isolated_llm.budget.is_exhausted
