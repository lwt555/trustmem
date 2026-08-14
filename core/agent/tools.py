"""Tool definition, registry, and stub execution for agent tool calling."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from core.labels import Trust, TOOL_REQUIRED_TRUST, TOOL_REQUIRE_HITL, fmt


@dataclass
class ToolDefinition:
    name: str
    description: str
    parameters: dict          # JSON Schema for tool input
    required_trust: Trust = Trust.T0_UNTRUSTED
    requires_hitl: bool = False
    func: Callable | None = None


@dataclass
class ToolResult:
    tool_name: str
    success: bool
    output: str
    error: str | None = None
    is_stub: bool = False   # STUB 占位数据：非真实数据源，禁止作为研判/处置依据


# Stub tool implementations that return realistic demo data
_STUB_TOOLS: dict[str, Callable] = {}


def _register_stub(name: str, output_template: str):
    def _stub(**kwargs) -> ToolResult:
        args_str = ", ".join(f"{k}={v}" for k, v in kwargs.items())
        return ToolResult(
            tool_name=name,
            success=True,
            output=output_template.format(**kwargs, args=args_str),
            is_stub=True,
        )
    _STUB_TOOLS[name] = _stub


# STUB 工具如实声明「未接入真实环境 / 未执行」，不编造演示数据、不谎称动作成功，
# 否则下游 Agent 会把占位结果当成真实证据或已执行动作（投毒 / 虚假闭环）。
_register_stub("web_search", "[STUB] 搜索 '{query}': 未接入真实情报源，无可用威胁情报。")
_register_stub("intel_fetch", "[STUB] 情报源未接入真实数据，无可用 IOC 返回。")
_register_stub("log_query", "[STUB] SIEM 日志源未接入真实数据，无日志事件返回。")
_register_stub("asset_query", "[STUB] 资产台账未接入真实数据，无可用资产清单。")
_register_stub("file_read", "[STUB] 文件读取未执行：无真实文件系统接入。")
_register_stub("file_write", "[STUB] 文件写入未执行：无真实落盘，未产生任何文件。")
_register_stub("exec_command", "[STUB] 命令未执行：无真实执行环境接入。")
_register_stub("firewall_block", "[STUB] 防火墙封禁未执行：无真实网络设备接入，未阻断任何 IP。")
_register_stub("host_isolate", "[STUB] 主机隔离未执行：无真实隔离能力，未隔离任何主机。")


class ToolRegistry:
    """Registry of tools available to an agent.

    Each tool has a required_trust threshold. When an agent tries to execute
    a tool with provenance below the threshold, PDP returns DENY.
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> None:
        self._tools[tool.name] = tool

    def register_builtin(self, name: str, description: str,
                         parameters: dict, required_trust: Trust | None = None,
                         requires_hitl: bool | None = None,
                         func: Callable | None = None) -> None:
        trust = required_trust if required_trust is not None else \
            TOOL_REQUIRED_TRUST.get(name, Trust.T0_UNTRUSTED)
        hitl = requires_hitl if requires_hitl is not None else \
            name in TOOL_REQUIRE_HITL
        impl = func if func is not None else _STUB_TOOLS.get(name)
        self.register(ToolDefinition(
            name=name, description=description, parameters=parameters,
            required_trust=trust, requires_hitl=hitl, func=impl,
        ))

    def get(self, name: str) -> ToolDefinition | None:
        return self._tools.get(name)

    def for_trust(self, t: Trust) -> list[ToolDefinition]:
        return [td for td in self._tools.values() if td.required_trust <= t]

    def execute(self, tool_name: str, args: dict) -> ToolResult:
        tool = self._tools.get(tool_name)
        if tool is None:
            return ToolResult(tool_name, False, "", f"Unknown tool: {tool_name}")
        if tool.func is None:
            return ToolResult(tool_name, False, "",
                            f"Tool {tool_name} has no implementation")
        try:
            return tool.func(**args)
        except Exception as e:
            return ToolResult(tool_name, False, "", str(e))

    def to_anthropic_schema(self) -> list[dict]:
        schemas = []
        for t in self._tools.values():
            schemas.append({
                "name": t.name,
                "description": t.description,
                "input_schema": t.parameters,
            })
        return schemas

    def to_openai_schema(self) -> list[dict]:
        schemas = []
        for t in self._tools.values():
            schemas.append({
                "type": "function",
                "function": {
                    "name": t.name,
                    "description": t.description,
                    "parameters": t.parameters,
                },
            })
        return schemas

    @property
    def tool_names(self) -> list[str]:
        return sorted(self._tools.keys())

    @property
    def count(self) -> int:
        return len(self._tools)
