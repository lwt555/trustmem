"""AgentRuntime — full lifecycle management for a single AI agent.

Lifecycle: receive task → reason → call tools → read/write memory → report
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator

from core.labels import AgentLabel, Trust, fmt
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
    at: datetime = field(default_factory=datetime.utcnow)


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
                    result = self._tools.execute(tc.name, tc.arguments)
                    s = self._add_step("tool_result", result.output,
                                       tool_name=tc.name,
                                       tool_args=tc.arguments,
                                       tool_result=result)
                    yield s

                    self._conversation.append({
                        "role": "user",
                        "content": f"[Tool result for {tc.name}]: {result.output}",
                    })
            else:
                self._status = "done"
                self._done = True
                step = self._add_step("report", resp.content)
                yield step
                return

        self._status = "done"
        self._done = True

    def _handle_tool_calls(self, resp: LLMResponse,
                           tool_schemas: list[dict] | None) -> None:
        """Execute tool calls and append results to conversation."""
        tool_contents = []
        for tc in resp.tool_calls:
            result = self._tools.execute(tc.name, tc.arguments)
            self._add_step("tool_result", result.output,
                          tool_name=tc.name, tool_args=tc.arguments,
                          tool_result=result)
            tool_contents.append({
                "type": "tool_result",
                "tool_use_id": tc.id,
                "content": result.output,
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
