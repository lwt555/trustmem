"""MemoryProxy — PEP layer intercepting all memory read/write with PDP checks.

No memory access bypasses this proxy. Read/write operations are ONLY
executed if PDP returns ALLOW. HIDE verdicts create #var# handles.
DENY verdicts are returned as error results.
"""
from __future__ import annotations

from datetime import datetime

from core.labels import (AgentLabel, Clearance, Layer, MemoryType, WriteOp,
                         TaskScope, fmt)
from core.pdp import PDP, Decision
from core.pipeline import WritePipeline, ReadPipeline, WriteResult, ReadResult
from core.session import Session
from core.topology import Topology
from core.verdict import Verdict
from core.isolated_llm import IsolatedLLMProto, ConstrainedAnswer
from core.varstore import VarStore


class MemoryProxy:
    """PEP (Policy Enforcement Point) for agent memory operations.

    Every memory read/write flows through this proxy. PDP is called BEFORE
    any I/O. The proxy wraps WritePipeline and ReadPipeline, adding agent
    and session context automatically.
    """

    def __init__(
        self,
        pdp: PDP,
        write_pipeline: WritePipeline,
        read_pipeline: ReadPipeline,
        constrained_llm: IsolatedLLMProto,
        var_store: VarStore,
        agent: AgentLabel,
        session: Session,
        topo: Topology,
    ) -> None:
        self._pdp = pdp
        self._write_pipe = write_pipeline
        self._read_pipe = read_pipeline
        self._constrained = constrained_llm
        self._var_store = var_store
        self.agent = agent
        self.session = session
        self.topo = topo

    def write(
        self, content: str, sensitivity: Clearance, layer: Layer,
        memory_type: MemoryType = MemoryType.EPISODIC,
        input_chunk_ids: list[str] | None = None,
        op: WriteOp = WriteOp.INFER,
        task_binding: str | None = None,
        scope: TaskScope | None = None,
    ) -> WriteResult:
        input_ids = input_chunk_ids or []
        input_mems = [self._read_pipe.mem_store.get(cid) for cid in input_ids]
        input_mems = [m for m in input_mems if m is not None]

        return self._write_pipe.write(
            agent=self.agent,
            session=self.session,
            content=content,
            target_sensitivity=sensitivity,
            target_layer=layer,
            memory_type=memory_type,
            input_mems=input_mems,
            op=op,
            task_binding=task_binding,
            scope=scope,
        )

    def read(self, chunk_id: str,
             scope: TaskScope | None = None) -> ReadResult:
        return self._read_pipe.read(
            agent=self.agent,
            session=self.session,
            chunk_id=chunk_id,
            scope=scope,
        )

    def read_many(self, chunk_ids: list[str],
                  scope: TaskScope | None = None) -> list[ReadResult]:
        return self._read_pipe.read_many(
            agent=self.agent,
            session=self.session,
            chunk_ids=chunk_ids,
            scope=scope,
        )

    def query_var(self, var_id: str, question: str,
                  constraint_type: str = "bool",
                  **kwargs) -> ConstrainedAnswer:
        if constraint_type == "bool":
            return self._constrained.query_bool(var_id, question)
        elif constraint_type == "enum":
            return self._constrained.query_enum(
                var_id, question, kwargs.get("options", []))
        elif constraint_type == "number":
            return self._constrained.query_number(
                var_id, question,
                min_val=kwargs.get("min_val", 0),
                max_val=kwargs.get("max_val", 100))
        raise ValueError(f"Unknown constraint type: {constraint_type}")

    def can_invoke_tool(self, tool_name: str,
                        action_fingerprint: str = "",
                        provenance=None, arg_labels=None) -> Decision:
        """Check whether the agent is allowed to invoke a tool via PDP.

        provenance / arg_labels 一并传入，让 P-T-Provenance 与 Flow-Egress-Args
        两条检查生效（F-02/F-03）。
        """
        return self._pdp.can_invoke(
            self.agent, self.session, tool_name, action_fingerprint,
            provenance=provenance, arg_labels=arg_labels)

    @property
    def t_eff(self) -> str:
        return fmt(self.session.t_eff)
