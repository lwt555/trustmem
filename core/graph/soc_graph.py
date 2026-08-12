"""SOC orchestration — 6-agent linear runner with memory pass and PDP gating.

Router: Planner → Intel → Log → Analyst → Executor → Auditor → END
Each edge is an inter-agent memory pass triggering PDP.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Iterator

from core.labels import Clearance, Layer, MemoryType, WriteOp, fmt
from core.pdp import PDP
from core.session import SessionStore
from core.topology import Topology

from .streams import GraphEvent, GraphEventType

_log = logging.getLogger(__name__)


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
        # pdp and topo accepted for caller compat; PDP gating lives in AgentRuntime
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
                                {"error": f"Agent {agent_id} not found"}, _utc_iso())
                self._events.append(evt)
                yield evt
                continue

            yield GraphEvent(GraphEventType.NODE_START, agent_id,
                           {"phase": agent_id, "task": task}, _utc_iso())

            instruction = self._build_instruction(agent_id, task, context_memories,
                                                  agent_outputs)

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

                evt = GraphEvent(event_type, agent_id, payload, _utc_iso())
                self._events.append(evt)
                yield evt

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
                    }, _utc_iso())
                except Exception:
                    _log.warning("Memory write failed for %s", agent_id, exc_info=True)
                    yield GraphEvent(GraphEventType.GRAPH_ERROR, agent_id,
                                   {"error": "memory write failed"}, _utc_iso())

        yield GraphEvent(GraphEventType.GRAPH_DONE, "system",
                        {"outputs": agent_outputs, "memories": context_memories,
                         "chain": self._chain}, _utc_iso())

    def _build_instruction(self, agent_id: str, task: str,
                           context_memories: list[str],
                           outputs: dict[str, str]) -> str:
        parts = [f"## 任务\n{task}"]
        if context_memories:
            parts.append(f"\n## 上下文记忆\n{', '.join(context_memories)}")
        for prev_id in ("planner", "intel", "log", "analyst", "executor"):
            if prev_id in outputs:
                parts.append(f"\n## {prev_id} 的输出\n{outputs[prev_id]}")

        instructions = {
            "planner": f"{parts[0]}\n\n请将上述任务分解为情报收集、日志检索、关联分析和处置执行四个子任务。",
            "intel": "\n".join(parts) + "\n\n根据 Planner 的分解，从外部情报源收集相关的 IOC 和威胁信息。",
            "log": "\n".join(parts) + "\n\n根据已有情报，从内部 SIEM 日志中检索相关的安全事件。",
            "analyst": "\n".join(parts) + "\n\n综合外部情报和内部日志，判断告警是否为真实攻击，输出研判结论和置信度。",
            "executor": "\n".join(parts) + "\n\n根据研判结论，执行必要的处置动作。如需封禁或隔离，调用 firewall_block 或 host_isolate 工具。",
            "auditor": "\n".join(parts) + "\n\n回顾全链路，核验每一步的合规性，生成审计报告。",
        }
        return instructions.get(agent_id, "\n".join(parts))

    def get_events(self) -> list[GraphEvent]:
        return list(self._events)
