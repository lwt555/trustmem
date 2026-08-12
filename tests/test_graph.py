"""Tests for LangGraph orchestration — SOCGraph and SimpleSOCRunner."""
import pytest
from datetime import datetime, timezone, timedelta

from core.topology import Topology
from core.pdp import PDP
from core.session import Session, SessionStore
from core.varstore import VarStore
from core.pipeline import WritePipeline, ReadPipeline
from core.merkle import MerkleAuditStore
from core.crypto.engine import CryptoEngine
from core.graph.soc_graph import SimpleSOCRunner
from core.graph.streams import GraphEvent, GraphEventType

from tests.helpers import build_test_runtimes


class TestSimpleSOCRunner:
    @pytest.fixture
    def runner(self, topo, pdp, crypto, mem_store, audit, var_store):
        session_store = SessionStore()
        runtimes, _ = build_test_runtimes(topo, pdp, crypto, mem_store, audit, var_store, session_store, session_id="graph-sess")
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
