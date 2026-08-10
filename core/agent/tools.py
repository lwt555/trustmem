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


# Stub tool implementations that return realistic demo data
_STUB_TOOLS: dict[str, Callable] = {}


def _register_stub(name: str, output_template: str):
    def _stub(**kwargs) -> ToolResult:
        args_str = ", ".join(f"{k}={v}" for k, v in kwargs.items())
        return ToolResult(
            tool_name=name,
            success=True,
            output=output_template.format(**kwargs, args=args_str),
        )
    _STUB_TOOLS[name] = _stub


_register_stub("web_search", "[STUB] 搜索 '{query}': 未发现相关威胁情报。")
_register_stub("intel_fetch", "[STUB] 从情报源获取 IOC: 192.0.2.1 → 恶意软件 C2 (可信度: T1)")
_register_stub("log_query", "[STUB] SIEM 日志: 最近24h内 {args} 条登录事件，无异常。")
_register_stub("asset_query", "[STUB] 资产清单: 192.168.1.0/24, 共 47 台主机。")
_register_stub("file_read", "[STUB] 读取文件内容 (模拟)")
_register_stub("file_write", "[STUB] 写入文件成功: {args}")
_register_stub("exec_command", "[STUB] 命令 '{args}' 执行完成 (模拟)")
_register_stub("firewall_block", "[STUB] 防火墙规则已添加: 阻断 IP {args} (模拟)")
_register_stub("host_isolate", "[STUB] 主机 {args} 已从网络隔离 (模拟)")
_register_stub("log_query", "[STUB] SIEM日志查询: {args}")


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
                         requires_hitl: bool | None = None) -> None:
        trust = required_trust if required_trust is not None else \
            TOOL_REQUIRED_TRUST.get(name, Trust.T0_UNTRUSTED)
        hitl = requires_hitl if requires_hitl is not None else \
            name in TOOL_REQUIRE_HITL
        stub = _STUB_TOOLS.get(name)
        self.register(ToolDefinition(
            name=name, description=description, parameters=parameters,
            required_trust=trust, requires_hitl=hitl, func=stub,
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
