"""End-to-end scenario tests — full SOC graph with mock LLM backends."""
import pytest

from core.graph.soc_graph import SimpleSOCRunner
from core.graph.streams import GraphEventType

from scenarios import soc_scenario1, soc_scenario2, soc_scenario3
from tests.helpers import build_test_runtimes


class TestScenario1ThreatIntel:
    @pytest.fixture
    def runner(self, topo, pdp, crypto, mem_store, audit, var_store):
        runtimes, session_store = build_test_runtimes(
            topo, pdp, crypto, mem_store, audit, var_store, session_id="e2e-sess")
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
        runtimes, session_store = build_test_runtimes(
            topo, pdp, crypto, mem_store, audit, var_store, session_id="e2e-sess")
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
        runtimes, session_store = build_test_runtimes(
            topo, pdp, crypto, mem_store, audit, var_store, session_id="e2e-sess")
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
        runtimes, session_store = build_test_runtimes(
            topo, pdp, crypto, mem_store, audit, var_store, session_id="e2e-sess")
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
