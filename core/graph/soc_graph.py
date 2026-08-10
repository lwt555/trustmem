"""SOC orchestration graph — 6-agent LangGraph StateGraph + SimpleSOCRunner.

Router: Planner → Intel → Log → Analyst → Executor → Auditor → END
Each edge is an inter-agent memory pass triggering PDP.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator

from core.labels import Clearance, Layer, MemoryType, WriteOp, fmt
from core.pdp import PDP
from core.session import SessionStore
from core.topology import Topology
from core.verdict import Verdict

from .state import SOCState
from .streams import GraphEvent, GraphEventType


def _now() -> str:
    return datetime.utcnow().isoformat()


class SimpleSOCRunner:
    """Linear 6-agent runner without LangGraph dependency.

    Used as fallback when langgraph is not installed, and for demo mode.
    Implements the same agent chain: Planner → Intel → Log → Analyst → Executor → Auditor.
    """

    def __init__(
        self,
        agents: dict,
        pdp: PDP,
        topo: Topology,
        session_store: SessionStore,
    ) -> None:
        self._agents = agents
        self._pdp = pdp
        self._topo = topo
        self._session_store = session_store
        self._chain = ["planner", "intel", "log", "analyst", "executor", "auditor"]
        self._events: list[GraphEvent] = []

    def stream(self, task: str) -> Iterator[GraphEvent]:
        self._events = []

        context_memories: list[str] = []
        agent_outputs: dict[str, str] = {}

        for agent_id in self._chain:
            agent_runtime = self._agents.get(agent_id)
            if agent_runtime is None:
                evt = GraphEvent(GraphEventType.GRAPH_ERROR, agent_id,
                                {"error": f"Agent {agent_id} not found"}, _now())
                self._events.append(evt)
                yield evt
                continue

            yield GraphEvent(GraphEventType.NODE_START, agent_id,
                           {"phase": agent_id, "task": task}, _now())

            # Build agent instruction with accumulated context
            instruction = self._build_instruction(agent_id, task, context_memories,
                                                  agent_outputs)

            # Run agent in streaming mode
            for step in agent_runtime.stream(instruction):
                event_type = GraphEventType.AGENT_THOUGHT
                payload = {"step_id": step.step_id, "content": step.content}

                if step.step_type == "tool_result":
                    event_type = GraphEventType.AGENT_TOOL_RESULT
                    payload["tool_name"] = step.tool_name
                    payload["tool_args"] = step.tool_args
                elif step.step_type == "report":
                    event_type = GraphEventType.NODE_END
                    agent_outputs[agent_id] = step.content

                evt = GraphEvent(event_type, agent_id, payload, _now())
                self._events.append(evt)
                yield evt

            # Write agent output to shared memory via the agent's MemoryProxy
            if agent_id in agent_outputs:
                try:
                    result = agent_runtime.memory.write(
                        content=agent_outputs[agent_id],
                        sensitivity=Clearance.L2_SENSITIVE,
                        layer=Layer.CONCLUSION,
                        memory_type=MemoryType.EPISODIC,
                        op=WriteOp.SUMMARIZE,
                        task_binding=task,
                    )
                    context_memories.append(result.chunk_id)
                    yield GraphEvent(GraphEventType.MEMORY_WRITE, agent_id, {
                        "chunk_id": result.chunk_id,
                        "verdict": result.decision.verdict.value if result.decision else "UNKNOWN",
                        "trust_out": fmt(result.decay.trust_out) if result.decay else "?",
                    }, _now())
                except Exception as e:
                    yield GraphEvent(GraphEventType.GRAPH_ERROR, agent_id,
                                   {"error": str(e)}, _now())

        yield GraphEvent(GraphEventType.GRAPH_DONE, "system",
                        {"outputs": agent_outputs, "memories": context_memories,
                         "chain": self._chain}, _now())

    def _build_instruction(self, agent_id: str, task: str,
                           context_memories: list[str],
                           outputs: dict[str, str]) -> str:
        parts = [f"## 任务\n{task}"]
        if context_memories:
            parts.append(f"\n## 上下文记忆\n{', '.join(context_memories)}")
        for prev_id, prev_output in outputs.items():
            parts.append(f"\n## {prev_id} 的输出\n{prev_output}")

        instructions = {
            "planner": f"{parts[0]}\n\n请将上述任务分解为情报收集、日志检索、关联分析和处置执行四个子任务。",
            "intel": "\n".join(parts) + "\n\n根据 Planner 的分解，从外部情报源收集相关的 IOC 和威胁信息。使用 web_search 和 intel_fetch 工具。",
            "log": "\n".join(parts) + "\n\n根据已有情报，从内部 SIEM 日志中检索相关的安全事件。使用 log_query 工具。",
            "analyst": "\n".join(parts) + "\n\n综合外部情报和内部日志，判断告警是否为真实攻击，输出研判结论和置信度。",
            "executor": "\n".join(parts) + "\n\n根据研判结论，执行必要的处置动作。如需封禁或隔离，调用 firewall_block 或 host_isolate 工具。",
            "auditor": "\n".join(parts) + "\n\n回顾全链路，核验每一步的合规性，生成审计报告。",
        }
        return instructions.get(agent_id, "\n".join(parts))

    def get_events(self) -> list[GraphEvent]:
        return list(self._events)


class SOCGraph:
    """LangGraph-based SOC orchestration.

    Builds a StateGraph with 6 agent nodes and linear routing.
    Falls back to SimpleSOCRunner if langgraph is not installed.
    """

    def __init__(
        self,
        agents: dict,
        pdp: PDP,
        topo: Topology,
        session_store: SessionStore,
    ) -> None:
        self._runner = SimpleSOCRunner(agents, pdp, topo, session_store)

    def stream(self, task: str) -> Iterator[GraphEvent]:
        yield from self._runner.stream(task)

    def invoke(self, task: str) -> dict:
        outputs = {}
        for event in self._runner.stream(task):
            if event.event_type == GraphEventType.NODE_END:
                outputs[event.agent_id] = event.payload.get("content", "")
        return outputs
