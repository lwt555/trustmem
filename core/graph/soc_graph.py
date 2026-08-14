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
from core.human_gate import HumanRequest

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
        endorser=None,
        human_gate=None,
    ) -> None:
        self._agents = agents
        # pdp and topo accepted for caller compat; PDP gating lives in AgentRuntime
        self._session_store = session_store
        self._endorser = endorser
        self._human_gate = human_gate
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

            # HITL 门内容核验：executor 的高危动作依据 analyst 结论发起，
            # 把 analyst 结论的 chunk 引用注入 runtime，触发 HITL 时一并展示，
            # 让人工能解密查看该结论明文后再决定是否放行。
            if agent_id == "executor":
                analyst_rec = next(
                    (r for r in written
                     if r.get("agent_id") == "analyst" and r.get("chunk_id")),
                    None)
                if analyst_rec:
                    agent_runtime.hitl_context = {
                        "chunk_id": analyst_rec["chunk_id"],
                        "sensitivity": analyst_rec.get("sensitivity", ""),
                        "layer": analyst_rec.get("layer", ""),
                        "owner": analyst_rec.get("owner", ""),
                        "policy": analyst_rec.get("policy", ""),
                        "trust": analyst_rec.get("trust_out", ""),
                    }

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

                    # 背书门（F-19 / TR13）：analyst 的 T1 研判经「人工」背书直升 T3。
                    # 不再自动背书——submit 后阻塞等待人决定，批准才 endorse；
                    # 拒绝则维持 T1（executor 读不到 T3 结论，高危工具连 CONFIRM 门都到不了）。
                    if agent_id == "analyst" and result.allowed and self._human_gate is not None:
                        req = HumanRequest(
                            kind="endorse",
                            agent_id="analyst",
                            summary="是否背书 analyst 的研判结论（升 T3）",
                            chunk_id=result.chunk_id,
                            trust=fmt(decay.trust_out) if decay else "?",
                            checks=checks,
                            sensitivity=fmt(result.memory.sensitivity) if result.memory else "",
                            layer=result.memory.layer.value if result.memory else "",
                            owner=result.memory.owner_agent if result.memory else "",
                            policy=getattr(result.ciphertext, "policy", "") if result.ciphertext else "",
                        )
                        self._human_gate.submit(req)
                        human = self._human_gate.wait(req.request_id)
                        if human.get("decision") == "approve" and self._endorser is not None:
                            ct_bytes = (result.ciphertext.to_bytes()
                                        if hasattr(result.ciphertext, "to_bytes")
                                        else result.ciphertext)
                            upgrade = self._endorser.endorse(result.memory, ct_bytes)
                            if upgrade is not None:
                                written[-1]["chunk_id"] = upgrade.new_chunk.chunk_id
                                written[-1]["trust_out"] = fmt(upgrade.new_chunk.provenance_trust)
                                written[-1]["upgraded_from"] = result.chunk_id
                                yield GraphEvent(GraphEventType.TRUST_UPGRADE, agent_id, {
                                    "upgraded_from": result.chunk_id,
                                    "chunk_id": upgrade.new_chunk.chunk_id,
                                    "from": fmt(upgrade.trust_before),
                                    "to": fmt(upgrade.trust_after),
                                    "evidence": upgrade.reason,
                                    "anchor_payload": upgrade.anchor_payload,
                                }, _utc_iso())
                        else:
                            yield GraphEvent(GraphEventType.TRUST_UPGRADE, agent_id, {
                                "upgraded_from": result.chunk_id,
                                "chunk_id": None,
                                "from": fmt(decay.trust_out) if decay else "?",
                                "to": fmt(decay.trust_out) if decay else "?",
                                "evidence": f"人工拒绝背书：{human.get('reason', '未批准')}",
                                "anchor_payload": None,
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

            # 线索读（absorb=False）：外部情报对所有人是线索；executor 只把 analyst 的
            # 背书结论作为控制指令 FULL-absorb，planner/log 对其只是上下文，不降水位。
            absorb = self._absorb_for(agent_runtime.agent.agent_id, rec.get("agent_id"))
            result = agent_runtime.memory.read(cid, absorb=absorb)
            verdict = result.decision.verdict.value if result.decision else "DENY"
            denied_by = result.denied_by or (result.decision.denied_by if result.decision else None)

            if result.allowed:
                if absorb:
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

    @staticmethod
    def _absorb_for(downstream_id: str, upstream_id: str) -> bool:
        """下游 FULL-absorb 哪些上游记忆（吸收即降 t_eff / t_eff_ctl）。

        - 外部情报（intel）对所有人都是「线索」，只取内容、不采信、不降水位。
        - executor 只把 analyst 的（背书后）结论作为控制指令吸收；planner/log
          对其是上下文（已由 analyst 消化进结论），不降控制流水位，否则 LOMAC
          会把 executor 的 t_eff_ctl 拖到 T2，连 CONFIRM 门都走不到。
        """
        if upstream_id == "intel":
            return False
        if downstream_id == "executor" and upstream_id != "analyst":
            return False
        return True

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
        """intel 采集外部情报、log 检索内部日志：都是「抽取/检索」δ=0；
        其余（planner/analyst/executor/auditor）是 LLM 加工 δ=1。"""
        return WriteOp.EXTRACT if agent_id in ("intel", "log") else WriteOp.SUMMARIZE

    @staticmethod
    def _schema_ok_for(agent_id: str) -> bool | None:
        """EXTRACT 需 schema 校验通过才 δ=0；intel/log 的结构化抽取视为通过。"""
        return True if agent_id in ("intel", "log") else None

    @staticmethod
    def _record_write(agent_id: str, content: str, result) -> dict:
        if result.allowed:
            mem = result.memory
            return {
                "agent_id": agent_id,
                "chunk_id": result.chunk_id,
                "content": content,
                "verdict": "ALLOW",
                "denied_by": None,
                "trust_out": fmt(result.decay.trust_out) if result.decay else "?",
                "sensitivity": fmt(mem.sensitivity) if mem else "",
                "layer": mem.layer.value if mem else "",
                "owner": mem.owner_agent if mem else "",
                "policy": getattr(result.ciphertext, "policy", "") if result.ciphertext else "",
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
