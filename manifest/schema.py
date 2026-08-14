"""
能力清单 DSL（F-25）。

对应设计文档 §3.4 第 1 步的「四来源 deny-by-default 合成」：

    workspace 基线 → agent/skill 清单 → 持久授权 → 会话授权(HITL)

安全边界是**交集运算**，不是抽取器，也不是任何单一来源：

    - 抽取器（PromptLens / LLM）的产出**只能收紧、不能放宽**——它抽出来的
      权限需求与人工维护的工具注册表取交集，交集之外一律拒。
    - 所以抽取器被注入的后果是「任务做不成（fail-closed）」，不是「权限被放大」。

论证（设计文档第十部分第 8 条）就落在这个模块里：安全边界是那个交集运算，
不是抽取器。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


# 能力命名空间（工具名 + 内容级推断能力名，统一在此登记）。
# 与 core/labels.py 的 TOOL_REQUIRED_TRUST / EGRESS_TOOLS 互补，不重复定义门槛。
CAPABILITY_NAMESPACE: tuple[str, ...] = (
    # 读类
    "file_read", "log_query", "asset_query", "memory.read",
    # 写类
    "file_write", "memory.write",
    # 有后果 / 高危
    "exec_command", "firewall_block", "host_isolate",
    # 数据出口
    "web_search", "intel_fetch", "external_api.call", "answer_to_user",
    # 内容级推断能力（capability_infer.py 产出）
    "net.post", "context.inject",
)


@dataclass(frozen=True)
class CapabilityGrant:
    """单个授权条目：某主体在某个任务上下文中被授予的一组能力。"""
    subject: str
    task_id: str
    capabilities: frozenset[str] = field(default_factory=frozenset)
    source: str = "registry"          # 授权来源：workspace / manifest / persistent / hitl
    session_id: str = ""


def compose_capabilities(inferred: Iterable[str],
                         registry: Iterable[str]) -> set[str]:
    """安全边界：抽取器（可被注入）声称需要的权限 ∩ 人工维护的注册表。

    交集之外一律拒。这是设计文档第十部分第 8 条的落点——抽取器被注入的后果
    是任务做不成（fail-closed），不是权限被放大。
    """
    return set(inferred) & set(registry)


def synthesize(*sources: Iterable[str]) -> set[str]:
    """四来源 deny-by-default 合成：逐层取交。

    顺序：workspace 基线 → agent/skill 清单 → 持久授权 → 会话授权(HITL)。
    任一来源为空集 → 最终为空集（deny-by-default）。
    """
    result: set[str] | None = None
    for src in sources:
        s = set(src)
        result = s if result is None else (result & s)
    return result or set()


def intersect_grants(grants: Iterable[CapabilityGrant]) -> set[str]:
    """把多个 CapabilityGrant 折叠成一份交集能力集。

    任何一层授权缺失即该能力被剔除——用于把「会话授权(HITL)」与「持久授权」
    合并成最终生效的能力集。
    """
    grants = list(grants)
    if not grants:
        return set()
    result: set[str] | None = None
    for g in grants:
        result = set(g.capabilities) if result is None else (result & set(g.capabilities))
    return result or set()
