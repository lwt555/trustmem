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

        written: list[dict] = []
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

            # 真读：下游通过 PDP 读上游记忆，触发读门 + LOMAC + 溯源。
            read_chunk_ids, read_notes, read_events = self._read_upstream(
                agent_runtime, written)
            for evt in read_events:
                self._events.append(evt)
                yield evt

            instruction = self._build_instruction(agent_id, task, read_notes)

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
                        sensitivity=self._sensitivity_for(agent_runtime.agent),
                        layer=Layer.CONCLUSION,
                        memory_type=MemoryType.EPISODIC,
                        input_chunk_ids=read_chunk_ids,
                        op=self._op_for(agent_id),
                        schema_ok=self._schema_ok_for(agent_id),
                        task_binding=agent_runtime.memory.session.task_id,
                    )
                    written.append(self._record_write(agent_id, agent_outputs[agent_id], result))

                    decision = result.decision
                    decay = result.decay
                    checks = [{"rule": c.rule, "passed": c.passed, "detail": c.detail}
                              for c in (decision.checks if decision else [])]
                    decay_info = None
                    if decay is not None:
                        decay_info = {
                            "trust_out": fmt(decay.trust_out),
                            "op_claimed": decay.op_claimed.value,
                            "op_effective": decay.op_effective.value,
                            "t_inputs": fmt(decay.t_inputs),
                            "t_agent": fmt(decay.t_agent),
                            "delta": decay.delta,
                            "downgraded_reason": decay.downgraded_reason,
                            "formula": decay.explain(),
                        }
                    sess = agent_runtime.memory.session
                    yield GraphEvent(GraphEventType.MEMORY_WRITE, agent_id, {
                        "chunk_id": result.chunk_id,
                        "verdict": decision.verdict.value if decision else "UNKNOWN",
                        "denied_by": result.denied_by or (decision.denied_by if decision else None),
                        "trust_out": fmt(decay.trust_out) if decay else "?",
                        "input_chunk_ids": read_chunk_ids,
                        "checks": checks,
                        "decay": decay_info,
                        "side_effects": result.side_effects,
                        "session": {
                            "t_eff": fmt(sess.t_eff),
                            "t_eff_ctl": fmt(sess.t_eff_ctl),
                            "c_eff": fmt(sess.c_eff),
                        },
                    }, _utc_iso())
                except Exception:
                    _log.warning("Memory write failed for %s", agent_id, exc_info=True)
                    yield GraphEvent(GraphEventType.GRAPH_ERROR, agent_id,
                                   {"error": "memory write failed"}, _utc_iso())

        yield GraphEvent(GraphEventType.GRAPH_DONE, "system",
                        {"outputs": agent_outputs,
                         "memories": [w["chunk_id"] for w in written if w.get("chunk_id")],
                         "chain": self._chain}, _utc_iso())

    def _read_upstream(self, agent_runtime, written: list[dict]):
        """下游通过 PDP 读上游记忆，返回 (read_chunk_ids, notes, events)。

        ALLOW 读入的 chunk_id 进入 input_chunk_ids（写时驱动 min_i T_in 衰减）；
        读门拒绝或上游写被拒的原文不进入下游上下文。
        """
        read_chunk_ids: list[str] = []
        notes: list[dict] = []
        events: list[GraphEvent] = []

        for rec in written:
            cid = rec.get("chunk_id")
            if not cid:
                notes.append({
                    "agent_id": rec["agent_id"],
                    "verdict": rec.get("verdict", "DENY"),
                    "denied_by": rec.get("denied_by") or "写入被拒",
                    "content": None,
                    "write_denied": True,
                })
                continue

            result = agent_runtime.memory.read(cid)
            verdict = result.decision.verdict.value if result.decision else "DENY"
            denied_by = result.denied_by or (result.decision.denied_by if result.decision else None)

            if result.allowed:
                read_chunk_ids.append(cid)
                notes.append({
                    "agent_id": rec["agent_id"],
                    "verdict": verdict,
                    "denied_by": None,
                    "content": rec.get("content", ""),
                    "trust_out": rec.get("trust_out"),
                    "t_eff_dropped": result.t_eff_dropped,
                    "t_eff_after": fmt(result.t_eff_after) if result.t_eff_after is not None else None,
                    "write_denied": False,
                })
            else:
                notes.append({
                    "agent_id": rec["agent_id"],
                    "verdict": verdict,
                    "denied_by": denied_by or "读门拒绝",
                    "content": None,
                    "write_denied": False,
                })

            payload = {"chunk_id": cid, "verdict": verdict, "denied_by": denied_by}
            if result.allowed:
                payload["t_eff_dropped"] = result.t_eff_dropped
                if result.t_eff_before is not None:
                    payload["t_eff_before"] = fmt(result.t_eff_before)
                if result.t_eff_after is not None:
                    payload["t_eff_after"] = fmt(result.t_eff_after)
            events.append(GraphEvent(GraphEventType.MEMORY_READ,
                                     agent_runtime.agent.agent_id, payload, _utc_iso()))

        return read_chunk_ids, notes, events

    def _build_instruction(self, agent_id: str, task: str,
                           notes: list[dict]) -> str:
        parts = [f"## 任务\n{task}"]
        for note in notes:
            parts.append(f"\n{self._format_note(note)}")

        instructions = {
            "planner": (f"{parts[0]}\n\n请将上述任务分解为情报收集、日志检索、关联分析和处置执行四个子任务。"
                        "只输出任务分解与逐项委派指令；下游 Agent 尚未运行，禁止预测或编造它们的回传结果、"
                        "情报、日志证据与汇总结论。"),
            "intel": "\n".join(parts) + "\n\n根据 Planner 的分解，从外部情报源收集相关的 IOC 和威胁信息。",
            "log": "\n".join(parts) + "\n\n根据已有情报，从内部 SIEM 日志中检索相关的安全事件。",
            "analyst": "\n".join(parts) + "\n\n综合外部情报和内部日志，判断告警是否为真实攻击，输出研判结论和置信度。",
            "executor": "\n".join(parts) + "\n\n根据研判结论，执行必要的处置动作。如需封禁或隔离，调用 firewall_block 或 host_isolate 工具。",
            "auditor": "\n".join(parts) + "\n\n回顾全链路，核验每一步的合规性，生成审计报告。",
        }
        return instructions.get(agent_id, "\n".join(parts))

    @staticmethod
    def _format_note(note: dict) -> str:
        """把一条上游记忆的读结果格式化为下游上下文片段。

        读门 ALLOW → 原文进入下游；读门拒绝或上游写被拒 → 只保留一句判决说明，
        原文不进入下游（记忆门禁不被指令文本通道绕过）。
        """
        header = f"## {note['agent_id']} 的输出"
        verdict = note.get("verdict", "DENY")
        if note.get("content") is not None:
            header += f"（已通过读门，可信度 {note.get('trust_out', '?')}）"
            return f"{header}\n{note['content']}"
        denied = note.get("denied_by") or "可信度不足"
        if note.get("write_denied"):
            return (f"{header}（⚠️ 已被 PDP {verdict} 拒绝写入共享记忆："
                    f"{denied}；内容已截断，不参与后续研判。）")
        return (f"{header}（⚠️ 读门 {verdict} 拒绝：{denied}；内容不可见，不参与后续研判。）")

    @staticmethod
    def _sensitivity_for(agent) -> Clearance:
        """外部情报 intel 写公开层 L0；其余写内网敏感层 L2（共享记忆域）。"""
        return min(agent.clearance, Clearance.L2_SENSITIVE)

    @staticmethod
    def _op_for(agent_id: str) -> WriteOp:
        """intel 只做采集与格式化抽取（δ=0），其余为 LLM 摘要（δ=1）。"""
        return WriteOp.EXTRACT if agent_id == "intel" else WriteOp.SUMMARIZE

    @staticmethod
    def _schema_ok_for(agent_id: str) -> bool | None:
        """EXTRACT 需 schema 校验通过才 δ=0；intel 的结构化 IOC 抽取视为通过。"""
        return True if agent_id == "intel" else None

    @staticmethod
    def _record_write(agent_id: str, content: str, result) -> dict:
        if result.allowed:
            return {
                "agent_id": agent_id,
                "chunk_id": result.chunk_id,
                "content": content,
                "verdict": "ALLOW",
                "denied_by": None,
                "trust_out": fmt(result.decay.trust_out) if result.decay else "?",
            }
        decision = result.decision
        return {
            "agent_id": agent_id,
            "chunk_id": None,
            "content": content,
            "verdict": decision.verdict.value if decision else "DENY",
            "denied_by": result.denied_by or (decision.denied_by if decision else None),
            "trust_out": None,
        }

    def get_events(self) -> list[GraphEvent]:
        return list(self._events)
