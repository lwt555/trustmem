"""
能力分级（F-16）。

工具按能力后果分四级：
    READ      只读，低危，无需 HITL
    WRITE     写，中危，受 BLP/Biba 约束
    DANGEROUS 高危（封禁 / 隔离 / 命令执行），命中无 HITL → CONFIRM
    SYSTEM    系统级（密钥导出 / 锚定发布），需显式授权，默认 DENY
"""
from __future__ import annotations

from enum import Enum


class CapabilityLevel(str, Enum):
    READ = "read"
    WRITE = "write"
    DANGEROUS = "dangerous"
    SYSTEM = "system"


# 高危能力：命中即需人在环确认（CONFIRM），与 TOOL_REQUIRE_HITL 语义一致。
DANGEROUS_CAPABILITIES: frozenset[str] = frozenset({
    "firewall_block",
    "host_isolate",
    "exec_command",
})

# 系统级能力：需显式授权，未授权一律 DENY（fail-closed）。
SYSTEM_CAPABILITIES: frozenset[str] = frozenset({
    "key_export",
    "anchor_publish",
    "keyring_rotate",
})

# 写类能力（受 BLP/Biba 写约束，但无需 HITL）。
WRITE_CAPABILITIES: frozenset[str] = frozenset({
    "file_write",
    "memory.write",
})


def capability_level(tool: str) -> CapabilityLevel:
    """返回工具的能力等级。未登记工具默认 READ（fail-closed 由 can_invoke 的
    ToolScope 检查兜底，不在此处放大权限）。"""
    if tool in SYSTEM_CAPABILITIES:
        return CapabilityLevel.SYSTEM
    if tool in DANGEROUS_CAPABILITIES:
        return CapabilityLevel.DANGEROUS
    if tool in WRITE_CAPABILITIES:
        return CapabilityLevel.WRITE
    return CapabilityLevel.READ
