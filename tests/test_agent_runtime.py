"""Tests for Agent runtime — ToolRegistry, MemoryProxy, AgentRuntime."""
import pytest
from datetime import datetime, timezone, timedelta

from core.labels import (
    MemoryLabel, Clearance, Trust, Layer, Role, MemoryType,
    WriteOp, TaskScope, IngestMode, fmt,
)
from core.session import Session, SessionStore
from core.verdict import Verdict
from core.pipeline import WritePipeline, ReadPipeline
from core.isolated_llm import StubIsolatedLLM, ControlFlowBudget
from core.agent.tools import ToolRegistry, ToolDefinition, ToolResult
from core.agent.memory_proxy import MemoryProxy
from core.agent.runtime import AgentRuntime, AgentStep
from core.agent.builder import AgentBuilder
from unittest.mock import MagicMock

from core.llm.stub import StubLLMBackend

from tests.helpers import make_agent_label


@pytest.fixture
def agent_label():
    return make_agent_label("analyst", Role.ANALYST, Clearance.L2_SENSITIVE, Trust.T2_MEDIUM)


@pytest.fixture
def session(agent_label):
    return Session.start("sess-1", agent_label, "TASK-1")


class TestToolRegistry:
    def test_register_and_get(self):
        reg = ToolRegistry()
        reg.register(ToolDefinition("test", "desc", {}, Trust.T2_MEDIUM))
        assert reg.get("test") is not None
        assert reg.get("test").required_trust == Trust.T2_MEDIUM

    def test_register_builtin(self):
        reg = ToolRegistry()
        reg.register_builtin("web_search", "search web", {})
        t = reg.get("web_search")
        assert t is not None
        assert t.required_trust == Trust.T0_UNTRUSTED

    def test_execute_stub(self):
        reg = ToolRegistry()
        reg.register_builtin("web_search", "search web", {})
        result = reg.execute("web_search", {"query": "test"})
        assert result.success
        assert "test" in result.output or "STUB" in result.output

    def test_for_trust(self):
        reg = ToolRegistry()
        reg.register_builtin("web_search", "search", {})
        reg.register_builtin("firewall_block", "block", {})
        t3_tools = reg.for_trust(Trust.T3_HIGH)
        assert len(t3_tools) >= 1

    def test_tool_schemas(self):
        reg = ToolRegistry()
        reg.register_builtin("web_search", "search", {"type": "object", "properties": {}})
        schemas = reg.to_anthropic_schema()
        assert len(schemas) == 1
        assert schemas[0]["name"] == "web_search"


class TestAgentRuntime:
    @pytest.fixture
    def runtime(self, agent_label, pdp, crypto, mem_store, audit, var_store, session):
        llm = StubLLMBackend()
        builder = AgentBuilder(
            llm=llm, pdp=pdp,
            write_pipeline=WritePipeline(pdp, crypto, mem_store, audit, MagicMock()),
            read_pipeline=ReadPipeline(pdp, crypto, mem_store, audit, var_store),
            var_store=var_store, topo=pdp.topo,
            session_store=SessionStore(),
        )
        return builder.build(agent_label, "You are a test agent.", session_id="sess-1")

    def test_build_creates_runtime(self, runtime):
        assert isinstance(runtime, AgentRuntime)
        assert runtime.agent.agent_id == "analyst"

    def test_stream_produces_steps(self, runtime):
        steps = list(runtime.stream("Test task", max_turns=1))
        assert len(steps) >= 1
        assert steps[-1].step_type in ("report", "thought")

    def test_task_returns_string(self, runtime):
        result = runtime.task("Test task", max_turns=1)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_reset_clears_state(self, runtime):
        runtime.task("Test", max_turns=1)
        runtime.reset()
        assert len(runtime.steps) == 0
        assert runtime.status == "idle"


class TestMemoryProxy:
    @pytest.fixture
    def proxy(self, agent_label, pdp, crypto, mem_store, audit, var_store, session):
        write_pipe = WritePipeline(pdp, crypto, mem_store, audit, MagicMock())
        read_pipe = ReadPipeline(pdp, crypto, mem_store, audit, var_store)
        constrained = StubIsolatedLLM(var_store)
        return MemoryProxy(pdp, write_pipe, read_pipe, constrained,
                          var_store, agent_label, session, pdp.topo)

    def test_write_returns_result(self, proxy):
        result = proxy.write("test content", Clearance.L1_INTERNAL,
                            Layer.CONCLUSION, MemoryType.EPISODIC,
                            op=WriteOp.INFER, task_binding="TASK-1")
        assert result.allowed
        assert result.chunk_id

    def test_read_returns_result(self, proxy):
        w = proxy.write("hello", Clearance.L1_INTERNAL, Layer.CONCLUSION,
                       MemoryType.EPISODIC, op=WriteOp.INFER)
        r = proxy.read(w.chunk_id)
        assert r.decision.verdict in (Verdict.ALLOW, Verdict.DENY)

    def test_t_eff_property(self, proxy):
        assert proxy.t_eff
