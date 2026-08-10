"""Tests for LangGraph orchestration — SOCGraph and SimpleSOCRunner."""
import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock

from core.labels import (
    AgentLabel, Clearance, Trust, Layer, Role,
)
from core.topology import Topology
from core.pdp import PDP
from core.session import Session, SessionStore
from core.varstore import VarStore
from core.pipeline import WritePipeline, ReadPipeline
from core.merkle import MerkleAuditStore
from core.crypto.engine import CryptoEngine
from core.llm.stub import StubLLMBackend
from core.agent.builder import AgentBuilder
from core.agent.tools import ToolRegistry
from core.graph.soc_graph import SimpleSOCRunner
from core.graph.streams import GraphEvent, GraphEventType


@pytest.fixture
def topo():
    t = Topology()
    t.add_agent("planner")
    for child in ("intel", "log", "analyst", "executor"):
        t.add_agent(child, parent="planner")
    t.add_agent("auditor")
    return t


@pytest.fixture
def pdp(topo):
    return PDP(topo)


@pytest.fixture
def crypto(topo):
    return CryptoEngine(topo)


@pytest.fixture
def mem_store():
    class MemStore:
        def __init__(self):
            self._m = {}
        def put(self, mem):
            self._m[mem.chunk_id] = mem
        def get(self, cid):
            return self._m.get(cid)
        def list_active(self):
            return list(self._m.values())
        def list_by_task(self, tid):
            return [m for m in self._m.values() if m.task_binding == tid]
    return MemStore()


@pytest.fixture
def audit():
    return MerkleAuditStore(block_size=64)


@pytest.fixture
def var_store():
    return VarStore()


def _make_agent(agent_id, role, clearance, trust, topo):
    return AgentLabel(
        agent_id, role, clearance, trust,
        task_domain={"TASK-1"}, collab_group={"soc"},
        tool_scope=set(), epoch=1,
        ttl_start=datetime.utcnow(),
        ttl_end=datetime.utcnow() + timedelta(days=1),
    )


def _build_runtimes(topo, pdp, crypto, mem_store, audit, var_store, session_store):
    llm = StubLLMBackend()
    builder = AgentBuilder(llm, pdp,
        WritePipeline(pdp, crypto, mem_store, audit, MagicMock()),
        ReadPipeline(pdp, crypto, mem_store, audit, var_store),
        var_store, topo, session_store)

    agents_labels = {
        "planner": _make_agent("planner", Role.PLANNER, Clearance.L3_SECRET, Trust.T3_HIGH, topo),
        "intel": _make_agent("intel", Role.EXTERNAL, Clearance.L0_PUBLIC, Trust.T1_LOW, topo),
        "log": _make_agent("log", Role.RETRIEVER, Clearance.L2_SENSITIVE, Trust.T3_HIGH, topo),
        "analyst": _make_agent("analyst", Role.ANALYST, Clearance.L2_SENSITIVE, Trust.T2_MEDIUM, topo),
        "executor": _make_agent("executor", Role.EXECUTOR, Clearance.L3_SECRET, Trust.T3_HIGH, topo),
        "auditor": _make_agent("auditor", Role.AUDITOR, Clearance.L3_SECRET, Trust.T3_HIGH, topo),
    }

    runtimes = {}
    for aid, alabel in agents_labels.items():
        rt = builder.build(alabel, f"You are {aid}.", ToolRegistry(),
                          session_id=f"graph-sess", task_id="TASK-1")
        runtimes[aid] = rt
    return runtimes


class TestSimpleSOCRunner:
    @pytest.fixture
    def runner(self, topo, pdp, crypto, mem_store, audit, var_store):
        session_store = SessionStore()
        runtimes = _build_runtimes(topo, pdp, crypto, mem_store, audit, var_store, session_store)
        return SimpleSOCRunner(runtimes, pdp, topo, session_store)

    def test_stream_produces_events(self, runner):
        events = list(runner.stream("Test SOC incident"))
        assert len(events) > 0

    def test_graph_done_at_end(self, runner):
        events = list(runner.stream("Test task"))
        assert events[-1].event_type == GraphEventType.GRAPH_DONE

    def test_all_phases_traversed(self, runner):
        events = list(runner.stream("Test task"))
        visited = {e.agent_id for e in events
                  if e.event_type == GraphEventType.NODE_START}
        expected = {"planner", "intel", "log", "analyst", "executor", "auditor"}
        assert visited == expected

    def test_events_are_graph_events(self, runner):
        events = list(runner.stream("Test"))
        for e in events:
            assert isinstance(e, GraphEvent)
            assert isinstance(e.to_dict(), dict)


class TestGraphEvent:
    def test_graph_event_to_dict(self):
        evt = GraphEvent(GraphEventType.NODE_START, "planner",
                        {"phase": "plan"})
        d = evt.to_dict()
        assert d["event_type"] == "node_start"
        assert d["agent_id"] == "planner"
        assert d["payload"] == {"phase": "plan"}

    def test_all_event_types_serializable(self):
        for et in GraphEventType:
            evt = GraphEvent(et, "test", {})
            d = evt.to_dict()
            assert "event_type" in d
