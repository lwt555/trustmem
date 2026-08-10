"""Scenario registry — maps scenario IDs to their runner functions."""
from __future__ import annotations

from typing import Callable, Iterator

from core.graph.streams import GraphEvent

SCENARIOS: dict[str, dict] = {
    "threat-intel": {
        "name": "威胁情报处理",
        "description": "从外部威胁情报到处置决策的完整流程：Intel收集IOC → Log检索匹配日志 → Analyst研判 → Executor处置 → Auditor审计",
        "demonstrates": "T1外部情报经过PDP裁决后如何限制高危工具调用（完整性低水位传播）",
    },
    "incident-response": {
        "name": "安全事件响应",
        "description": "从内部异常日志检测到账户冻结的全链路：Log检测异常 → Analyst研判 → Intel收集关联情报 → Executor执行冻结 → Auditor审计全链路",
        "demonstrates": "T3高可信内源数据链路：Executor可以成功调用高危工具（可信度充足）",
    },
    "echoleak": {
        "name": "EchoLeak攻击演示 (A11)",
        "description": "恶意情报夹带外泄指令：Intel收集到含外泄指令的情报 → 经Analyst研判 → Executor尝试外泄被双平面联合防御截断",
        "demonstrates": "P-T(provenance-trust)拒高危工具 + P-F(scope)拒网络出口 = 双平面联合防御",
    },
}
