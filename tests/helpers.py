"""Shared test helpers — importable functions, not fixtures."""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from core.labels import AgentLabel, Clearance, Trust, Role
from core.session import SessionStore
from core.pipeline import WritePipeline, ReadPipeline
from core.llm.stub import StubLLMBackend
from core.agent.builder import AgentBuilder
from core.agent.tools import ToolRegistry


def make_agent_label(agent_id: str, role, clearance, trust):
    """Create an AgentLabel for testing."""
    return AgentLabel(
        agent_id, role, clearance, trust,
        task_domain={"TASK-1"}, collab_group={"soc"},
        tool_scope=set(), epoch=1,
        ttl_start=datetime.now(timezone.utc),
        ttl_end=datetime.now(timezone.utc) + timedelta(days=1),
    )


AGENT_ROLES = {
    "planner":  (Role.PLANNER,  Clearance.L3_SECRET,    Trust.T3_HIGH),
    "intel":    (Role.EXTERNAL, Clearance.L0_PUBLIC,     Trust.T1_LOW),
    "log":      (Role.RETRIEVER, Clearance.L2_SENSITIVE, Trust.T3_HIGH),
    "analyst":  (Role.ANALYST,  Clearance.L2_SENSITIVE,  Trust.T2_MEDIUM),
    "executor": (Role.EXECUTOR, Clearance.L3_SECRET,    Trust.T3_HIGH),
    "auditor":  (Role.AUDITOR,  Clearance.L3_SECRET,    Trust.T3_HIGH),
}


def make_agent_labels():
    """Create the standard 6-agent label dict for SOC scenario tests."""
    return {
        agent_id: make_agent_label(agent_id, role, clearance, trust)
        for agent_id, (role, clearance, trust) in AGENT_ROLES.items()
    }


def build_test_runtimes(topo, pdp, crypto, mem_store, audit, var_store,
                        session_store=None, session_id="test-sess"):
    """Build agent runtimes for graph/e2e tests. Returns (runtimes, session_store)."""
    if session_store is None:
        session_store = SessionStore()
    llm = StubLLMBackend()
    builder = AgentBuilder(llm, pdp,
        WritePipeline(pdp, crypto, mem_store, audit, MagicMock()),
        ReadPipeline(pdp, crypto, mem_store, audit, var_store),
        var_store, topo, session_store)

    agents_labels = make_agent_labels()

    runtimes = {}
    for aid, alabel in agents_labels.items():
        rt = builder.build(alabel, f"You are {aid}.", ToolRegistry(),
                          session_id=session_id, task_id="TASK-1")
        runtimes[aid] = rt
    return runtimes, session_store
