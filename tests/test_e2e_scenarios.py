"""End-to-end scenario tests — full SOC graph with mock LLM backends."""
import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock

from core.labels import (
    AgentLabel, Clearance, Trust, Layer, Role,
)
from core.topology import Topology
from core.pdp import PDP
from core.session import SessionStore
from core.varstore import VarStore
from core.pipeline import WritePipeline, ReadPipeline
from core.merkle import MerkleAuditStore
from core.crypto.engine import CryptoEngine
from core.llm.stub import StubLLMBackend
from core.agent.builder import AgentBuilder
from core.agent.tools import ToolRegistry
from core.graph.soc_graph import SimpleSOCRunner
from core.graph.streams import GraphEventType

from scenarios import soc_scenario1, soc_scenario2, soc_scenario3


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


def _make_agent(agent_id, role, clearance, trust):
    return AgentLabel(
        agent_id, role, clearance, trust,
        task_domain={"TASK-1"}, collab_group={"soc"},
        tool_scope=set(), epoch=1,
        ttl_start=datetime.utcnow(),
        ttl_end=datetime.utcnow() + timedelta(days=1),
    )


def _build_runtimes(topo, pdp, crypto, mem_store, audit, var_store):
    llm = StubLLMBackend()
    session_store = SessionStore()
    builder = AgentBuilder(llm, pdp,
        WritePipeline(pdp, crypto, mem_store, audit, MagicMock()),
        ReadPipeline(pdp, crypto, mem_store, audit, var_store),
        var_store, topo, session_store)

    agents_labels = {
        "planner": _make_agent("planner", Role.PLANNER, Clearance.L3_SECRET, Trust.T3_HIGH),
        "intel": _make_agent("intel", Role.EXTERNAL, Clearance.L0_PUBLIC, Trust.T1_LOW),
        "log": _make_agent("log", Role.RETRIEVER, Clearance.L2_SENSITIVE, Trust.T3_HIGH),
        "analyst": _make_agent("analyst", Role.ANALYST, Clearance.L2_SENSITIVE, Trust.T2_MEDIUM),
        "executor": _make_agent("executor", Role.EXECUTOR, Clearance.L3_SECRET, Trust.T3_HIGH),
        "auditor": _make_agent("auditor", Role.AUDITOR, Clearance.L3_SECRET, Trust.T3_HIGH),
    }

    runtimes = {}
    for aid, alabel in agents_labels.items():
        rt = builder.build(alabel, f"You are {aid}.", ToolRegistry(),
                          session_id=f"e2e-sess", task_id="TASK-1")
        runtimes[aid] = rt
    return runtimes, session_store


class TestScenario1ThreatIntel:
    @pytest.fixture
    def runner(self, topo, pdp, crypto, mem_store, audit, var_store):
        runtimes, session_store = _build_runtimes(
            topo, pdp, crypto, mem_store, audit, var_store)
        return SimpleSOCRunner(runtimes, pdp, topo, session_store)

    def test_stream_completes(self, runner):
        events = list(runner.stream(soc_scenario1.TASK_INSTRUCTION))
        assert len(events) > 0
        assert events[-1].event_type == GraphEventType.GRAPH_DONE

    def test_all_six_agents_visited(self, runner):
        events = list(runner.stream(soc_scenario1.TASK_INSTRUCTION))
        starts = {e.agent_id for e in events
                 if e.event_type == GraphEventType.NODE_START}
        assert starts == {"planner", "intel", "log", "analyst", "executor", "auditor"}


class TestScenario2IncidentResponse:
    @pytest.fixture
    def runner(self, topo, pdp, crypto, mem_store, audit, var_store):
        runtimes, session_store = _build_runtimes(
            topo, pdp, crypto, mem_store, audit, var_store)
        return SimpleSOCRunner(runtimes, pdp, topo, session_store)

    def test_stream_completes(self, runner):
        events = list(runner.stream(soc_scenario2.TASK_INSTRUCTION))
        assert events[-1].event_type == GraphEventType.GRAPH_DONE

    def test_all_six_agents_visited(self, runner):
        events = list(runner.stream(soc_scenario2.TASK_INSTRUCTION))
        starts = {e.agent_id for e in events
                 if e.event_type == GraphEventType.NODE_START}
        assert starts == {"planner", "log", "intel", "analyst", "executor", "auditor"}


class TestScenario3EchoLeak:
    @pytest.fixture
    def runner(self, topo, pdp, crypto, mem_store, audit, var_store):
        runtimes, session_store = _build_runtimes(
            topo, pdp, crypto, mem_store, audit, var_store)
        return SimpleSOCRunner(runtimes, pdp, topo, session_store)

    def test_stream_completes(self, runner):
        events = list(runner.stream(soc_scenario3.TASK_INSTRUCTION))
        assert events[-1].event_type == GraphEventType.GRAPH_DONE

    def test_all_six_agents_visited(self, runner):
        events = list(runner.stream(soc_scenario3.TASK_INSTRUCTION))
        starts = {e.agent_id for e in events
                 if e.event_type == GraphEventType.NODE_START}
        assert starts == {"planner", "intel", "log", "analyst", "executor", "auditor"}


class TestABComparison:
    @pytest.fixture
    def runner(self, topo, pdp, crypto, mem_store, audit, var_store):
        runtimes, session_store = _build_runtimes(
            topo, pdp, crypto, mem_store, audit, var_store)
        return SimpleSOCRunner(runtimes, pdp, topo, session_store)

    def test_scenario_with_protection_produces_events(self, runner):
        events = list(runner.stream(soc_scenario3.TASK_INSTRUCTION))
        memory_writes = [e for e in events
                        if e.event_type == GraphEventType.MEMORY_WRITE]
        assert len(memory_writes) > 0

    def test_graph_completes_for_all_scenarios(self, runner):
        for scenario in [soc_scenario1, soc_scenario2, soc_scenario3]:
            events = list(runner.stream(scenario.TASK_INSTRUCTION))
            assert events[-1].event_type == GraphEventType.GRAPH_DONE, \
                f"Scenario {scenario.__name__} failed to complete"
