"""AgentRuntime — full lifecycle management for a single AI agent.

Lifecycle: receive task → reason → call tools → read/write memory → report
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterator

from core.labels import AgentLabel, Trust, MemoryLabel, Layer, MemoryType, fmt
from core.pdp import PDP, Decision
from core.session import Session
from core.topology import Topology
from core.verdict import Verdict
from core.llm.base import LLMBackend, LLMResponse

from .tools import ToolRegistry, ToolResult
from .memory_proxy import MemoryProxy


@dataclass
class AgentStep:
    step_id: str
    step_type: str  # thought | tool_call | tool_result | memory_read | memory_write | report
    content: str
    tool_name: str | None = None
    tool_args: dict | None = None
    tool_result: ToolResult | None = None
    decision: Decision | None = None
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AgentRuntime:
    """Wraps a single agent's full reasoning lifecycle.

    Each agent holds its own LLM backend, tool registry, memory proxy (PEP),
    and session state. The task() method runs the full reasoning loop until
    the agent produces a final report.
    """

    def __init__(
        self,
        agent_label: AgentLabel,
        llm: LLMBackend,
        tools: ToolRegistry,
        memory: MemoryProxy,
        system_prompt: str,
    ) -> None:
        self.agent = agent_label
        self._llm = llm
        self._tools = tools
        self.memory = memory
        self._system = system_prompt
        self._conversation: list[dict] = []
        self.steps: list[AgentStep] = []
        self._done = False
        self._status: str = "idle"

    @property
    def status(self) -> str:
        return self._status

    @property
    def t_eff(self) -> str:
        return self.memory.t_eff

    def task(self, instruction: str, max_turns: int = 8) -> str:
        """Run the full reasoning loop. Returns the agent's final report."""
        self._done = False
        self._status = "thinking"
        self._conversation = [{"role": "user", "content": instruction}]
        tool_schemas = self._tools.to_anthropic_schema() or None

        for turn in range(max_turns):
            resp = self._llm.chat(
                messages=self._conversation,
                tools=tool_schemas,
                system=self._system,
            )

            if resp.tool_calls:
                self._status = "acting"
                self._conversation.append({
                    "role": "assistant",
                    "content": [{"type": "text", "text": resp.content}]
                })
                self._add_step("thought", resp.content)
                self._handle_tool_calls(resp, tool_schemas)
            else:
                self._status = "done"
                self._done = True
                self._add_step("report", resp.content)
                return resp.content

        self._status = "done"
        self._done = True
        return self.steps[-1].content if self.steps else "(no output)"

    def step(self, instruction: str) -> AgentStep | None:
        """Single turn of the reasoning loop."""
        if not self._conversation:
            self._conversation = [{"role": "user", "content": instruction}]

        self._status = "thinking"
        tool_schemas = self._tools.to_anthropic_schema() or None
        resp = self._llm.chat(
            messages=self._conversation,
            tools=tool_schemas,
            system=self._system,
        )

        if resp.tool_calls:
            self._status = "acting"
            self._conversation.append({
                "role": "assistant",
                "content": resp.content,
            })
            step = self._add_step("thought", resp.content)
            self._handle_tool_calls(resp, tool_schemas)
            return step
        else:
            self._status = "done"
            self._done = True
            return self._add_step("report", resp.content)

    def stream(self, instruction: str,
               max_turns: int = 8) -> Iterator[AgentStep]:
        """Generator yielding each step as it happens, for WebSocket push."""
        self._done = False
        self._conversation = [{"role": "user", "content": instruction}]
        tool_schemas = self._tools.to_anthropic_schema() or None

        for turn in range(max_turns):
            self._status = "thinking"
            resp = self._llm.chat(
                messages=self._conversation,
                tools=tool_schemas,
                system=self._system,
            )

            if resp.tool_calls:
                self._status = "acting"
                self._conversation.append({
                    "role": "assistant",
                    "content": resp.content,
                })
                step = self._add_step("thought", resp.content)
                yield step

                for tc in resp.tool_calls:
                    result = self._execute_tool(tc)
                    s = self._add_step("tool_result", result.output,
                                       tool_name=tc.name,
                                       tool_args=tc.arguments,
                                       tool_result=result)
                    yield s

                    self._conversation.append({
                        "role": "user",
                        "content": f"[Tool result for {tc.name}]: {self._tool_output(result)}",
                    })
            else:
                self._status = "done"
                self._done = True
                step = self._add_step("report", resp.content)
                yield step
                return

        self._status = "done"
        self._done = True

    @staticmethod
    def _tool_fingerprint(tc) -> str:
        raw = json.dumps({"tool": tc.name, "args": tc.arguments}, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _execute_tool(self, tc) -> ToolResult:
        """Execute a single tool call, gated through PDP can_invoke."""
        fp = self._tool_fingerprint(tc)
        # 传入本会话已读记忆的 provenance，让 P-T-Provenance 对高危工具真正生效，
        # 而非「无 provenance 参数」恒 PASS（自我申报）。
        decision = self.memory.can_invoke_tool(
            tc.name, action_fingerprint=fp, provenance=self._session_provenance())
        if decision.verdict != Verdict.ALLOW:
            deny_msg = f"PDP DENIED tool '{tc.name}': {decision.verdict.value}"
            return ToolResult(tool_name=tc.name, success=False, output=deny_msg)
        return self._tools.execute(tc.name, tc.arguments)

    def _session_provenance(self) -> list:
        """从本会话已读记忆（session.reads）构造 provenance 标签。

        can_invoke 的 P-T-Provenance 只取 MemoryLabel.provenance_trust 与
        derived_from_consult 两个字段，故此处用 ReadRecord 轻量重建即可。
        """
        sess = self.memory.session
        labels: list = []
        for rec in sess.reads:
            labels.append(MemoryLabel(
                chunk_id=rec.chunk_id,
                sensitivity=rec.sensitivity,
                provenance_trust=rec.trust,
                layer=Layer.CONCLUSION,
                memory_type=MemoryType.EPISODIC,
                owner_agent=self.agent.agent_id,
                task_binding=sess.task_id,
                derived_from_consult=rec.chunk_id in sess.consulted,
            ))
        return labels

    @staticmethod
    def _tool_output(result: ToolResult) -> str:
        """STUB 结果统一加醒目标记，防止下游把占位数据当真实证据采信。"""
        if result.is_stub:
            return ("[STUB 占位数据·非真实数据源·禁止作为研判或处置依据] "
                    + result.output)
        return result.output

    def _handle_tool_calls(self, resp: LLMResponse,
                           tool_schemas: list[dict] | None) -> None:
        """Execute tool calls after PDP can_invoke checks, append results."""
        tool_contents = []
        for tc in resp.tool_calls:
            result = self._execute_tool(tc)
            self._add_step("tool_result", result.output,
                          tool_name=tc.name, tool_args=tc.arguments,
                          tool_result=result)
            tool_contents.append({
                "type": "tool_result",
                "tool_use_id": tc.id,
                "content": self._tool_output(result),
            })

        if tool_contents:
            self._conversation.append({
                "role": "user",
                "content": tool_contents,
            })

    def _add_step(self, step_type: str, content: str,
                  tool_name: str | None = None,
                  tool_args: dict | None = None,
                  tool_result: ToolResult | None = None) -> AgentStep:
        step = AgentStep(
            step_id=f"step-{uuid.uuid4().hex[:8]}",
            step_type=step_type,
            content=content,
            tool_name=tool_name,
            tool_args=tool_args,
            tool_result=tool_result,
        )
        self.steps.append(step)
        return step

    def reset(self) -> None:
        self._conversation.clear()
        self.steps.clear()
        self._done = False
        self._status = "idle"

    @property
    def has_tools(self) -> bool:
        return self._tools.count > 0

    @property
    def tool_names(self) -> list[str]:
        return self._tools.tool_names
