"""AgentBuilder — DI factory wiring a full AgentRuntime from components."""
from __future__ import annotations

from core.labels import AgentLabel
from core.pdp import PDP
from core.pipeline import WritePipeline, ReadPipeline
from core.session import Session, SessionStore
from core.topology import Topology
from core.varstore import VarStore
from core.isolated_llm import StubIsolatedLLM
from core.llm.base import LLMBackend
from core.llm.constrained import ConstrainedQueryAdapter

from .tools import ToolRegistry
from .memory_proxy import MemoryProxy
from .runtime import AgentRuntime


class AgentBuilder:
    """Factory that wires all dependencies for a single AgentRuntime.

    Usage:
        builder = AgentBuilder(llm, pdp, write_pipeline, read_pipeline,
                               var_store, topo, session_store)
        agent_runtime = builder.build(agent_label, system_prompt, tool_registry)
    """

    def __init__(
        self,
        llm: LLMBackend,
        pdp: PDP,
        write_pipeline: WritePipeline,
        read_pipeline: ReadPipeline,
        var_store: VarStore,
        topo: Topology,
        session_store: SessionStore,
    ) -> None:
        self._llm = llm
        self._pdp = pdp
        self._write_pipe = write_pipeline
        self._read_pipe = read_pipeline
        self._var_store = var_store
        self._topo = topo
        self._session_store = session_store

    def build(
        self,
        agent: AgentLabel,
        system_prompt: str,
        tool_registry: ToolRegistry | None = None,
        session_id: str = "",
        task_id: str = "",
    ) -> AgentRuntime:
        tools = tool_registry or ToolRegistry()
        session = self._session_store.get_or_start(
            session_id or f"session-{agent.agent_id}",
            agent,
            task_id or "default",
        )

        constrained = ConstrainedQueryAdapter(
            self._llm, self._var_store,
        )
        memory = MemoryProxy(
            pdp=self._pdp,
            write_pipeline=self._write_pipe,
            read_pipeline=self._read_pipe,
            constrained_llm=constrained,
            var_store=self._var_store,
            agent=agent,
            session=session,
            topo=self._topo,
        )

        return AgentRuntime(
            agent_label=agent,
            llm=self._llm,
            tools=tools,
            memory=memory,
            system_prompt=system_prompt,
        )
