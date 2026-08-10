"""
场景实例化：SOC 多智能体安全事件响应
=====================================
六个 Agent 的编排。这个场景之所以好讲，因为四个轴同时有真实落点：

  可信度天然分层 : 外部情报 T1  vs  内网日志 T3
  上下级天然存在 : Planner → Executor，认知分层有意义
  高危动作真实   : Executor 能封 IP、隔离主机，Invoke 规则有意义
  敏感数据真实   : 内网资产清单、账号拓扑，密级轴有意义
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

from core.labels import AgentLabel, MemoryLabel, Clearance, Trust, Layer, Role, MemoryType
from core.topology import Topology

TASK = "INC-2026-0731"
GROUP_SOC = "soc-response"

SYSTEM_PROMPTS: dict[str, str] = {
    "planner": (
        "你是 SOC 事件响应的总编排 Agent。你负责接收安全告警，拆解成子任务并"
        "下发给情报采集、日志检索、关联研判三个下级 Agent，汇总它们的结论后"
        "制定处置方案，交由执行 Agent 落地。你不直接访问外部网络。"
        "所有高危处置动作必须先经人工确认。"
    ),
    "intel": (
        "你是外部威胁情报采集 Agent。你从公开威胁情报源、开源情报站点和第三方"
        "API 获取 IOC、攻击者画像和 TTP 信息。你只做采集和格式化抽取，不做推理。"
        "你没有任何内网访问权限。"
    ),
    "log": (
        "你是内网日志检索 Agent。你从内部 SIEM 和日志平台按条件检索连接日志、"
        "进程日志和认证日志。数据源均为内部已验签的日志平台。你只做检索和过滤。"
    ),
    "analyst": (
        "你是关联研判 Agent。你综合外部情报与内网日志，判断告警是真实攻击还是"
        "误报，输出研判结论和置信度。你不调用任何外部工具，也不执行任何处置动作。"
    ),
    "executor": (
        "你是处置执行 Agent。你根据总编排下发的处置方案，调用防火墙封禁、主机"
        "隔离和取证文件写入等接口执行操作。你拥有 firewall_block、host_isolate、"
        "file_write 三个高危工具权限。"
    ),
    "auditor": (
        "你是合规审计 Agent。你旁路读取全部记忆（包括各 Agent 的推理过程），"
        "核验处置动作是否合规、是否存在越权，并生成审计报告。你只读不写业务数据。"
    ),
}

# 工具注册表 ---- 权限的"背书"来源，Agent 的自我声明必须与此求交
TOOL_REGISTRY: dict[str, set[str]] = {
    "planner":  set(),
    "intel":    {"web_search", "intel_fetch"},
    "log":      {"log_query"},
    "analyst":  set(),
    "executor": {"firewall_block", "host_isolate", "file_write"},
    "auditor":  {"asset_query"},
}


def prompt_hash(pid: str) -> str:
    return hashlib.sha256(SYSTEM_PROMPTS[pid].encode()).hexdigest()


def build_topology() -> Topology:
    topo = Topology()
    topo.add_agent("planner")
    for child in ("intel", "log", "analyst", "executor"):
        topo.add_agent(child, parent="planner")
    topo.add_agent("auditor")     # 旁路，不在树中
    return topo


def build_agents() -> dict[str, AgentLabel]:
    now = datetime.utcnow()
    end = now + timedelta(hours=8)
    common = dict(task_domain={TASK}, collab_group={GROUP_SOC},
                  ttl_start=now, ttl_end=end, epoch=1)

    return {
        "planner": AgentLabel("planner", Role.PLANNER, Clearance.L3_SECRET,
                              Trust.T3_HIGH, tool_scope=TOOL_REGISTRY["planner"],
                              prompt_hash=prompt_hash("planner"), **common),
        "intel": AgentLabel("intel", Role.EXTERNAL, Clearance.L0_PUBLIC,
                            Trust.T1_LOW, tool_scope=TOOL_REGISTRY["intel"],
                            prompt_hash=prompt_hash("intel"), **common),
        "log": AgentLabel("log", Role.RETRIEVER, Clearance.L2_SENSITIVE,
                          Trust.T3_HIGH, tool_scope=TOOL_REGISTRY["log"],
                          prompt_hash=prompt_hash("log"), **common),
        "analyst": AgentLabel("analyst", Role.ANALYST, Clearance.L2_SENSITIVE,
                              Trust.T2_MEDIUM, tool_scope=TOOL_REGISTRY["analyst"],
                              prompt_hash=prompt_hash("analyst"), **common),
        "executor": AgentLabel("executor", Role.EXECUTOR, Clearance.L3_SECRET,
                               Trust.T3_HIGH, tool_scope=TOOL_REGISTRY["executor"],
                               prompt_hash=prompt_hash("executor"), **common),
        "auditor": AgentLabel("auditor", Role.AUDITOR, Clearance.L3_SECRET,
                              Trust.T3_HIGH, tool_scope=TOOL_REGISTRY["auditor"],
                              prompt_hash=prompt_hash("auditor"), **common),
    }


def mk_mem(chunk_id: str, sensitivity: Clearance, trust: Trust, layer: Layer,
           owner: str, mtype: MemoryType = MemoryType.EPISODIC,
           provenance: list[str] | None = None) -> MemoryLabel:
    return MemoryLabel(
        chunk_id=chunk_id, sensitivity=sensitivity, provenance_trust=trust,
        layer=layer, memory_type=mtype, owner_agent=owner, task_binding=TASK,
        collab_group={GROUP_SOC}, provenance_chain=provenance or [], epoch=1,
    )
