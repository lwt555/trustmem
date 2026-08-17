"""军事场景（joint）装配 —— 联合态势研判。

与 SOC 场景并列的第二套六智能体场景，后端启动时按环境变量二选一装配，
两套不同时加载。

六个智能体：planner / situation / cyber / ew / security / external。
标签一律由 PromptLens 从系统提示词 + 工具注册表真实推导，不手写字面量。
"""
from __future__ import annotations

import hashlib
import os

from core.labels import AgentLabel, Clearance, Trust, IngestMode, TaskScope, derive_taskscope
from core.topology import Topology
from promptlens.pipeline import PromptLens

JOINT_TASK = "JOINT-2026"
GROUP_JOINT = "joint-ops"

AGENT_DISPLAY_NAME = {
    "planner": "规划智能体", "situation": "态势智能体", "cyber": "网络智能体",
    "ew": "电磁智能体", "security": "安全智能体", "external": "外协智能体",
}

JOINT_TOOL_REGISTRY = {
    "planner":   {"risk_level_publish"},
    "situation": {"situation_query"},
    "cyber":     {"log_query"},
    "ew":        {"spectrum_query"},
    "security":  set(),
    "external":  {"xdomain_receive", "xdomain_forward"},
}

JOINT_TASK_MODES: dict[str, IngestMode] = {
    "JOINT-2026-RISKLEVEL": IngestMode.LEARN,
    "JOINT-2026-THREATRPT": IngestMode.LEARN,
}

# 每个任务的（数据出口，高危处置工具），供 derive_taskscope 推导区间。
JOINT_TASK_TOOLS: dict[str, tuple[set[str], set[str]]] = {
    "JOINT-2026-RISKLEVEL": ({"memory.write"}, {"risk_level_publish"}),
    "JOINT-2026-THREATRPT": ({"memory.write"}, set()),
}

_PROMPT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "prompts", "joint")


def _read_prompt(aid: str) -> str:
    path = os.path.join(_PROMPT_DIR, f"{aid}.txt")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def prompt_hash(aid: str) -> str:
    return hashlib.sha256(_read_prompt(aid).encode()).hexdigest()


class JointTask:
    """联合态势研判任务描述：持有由 derive_taskscope 推导出的 TaskScope。"""
    def __init__(self, task_id: str, scope: TaskScope) -> None:
        self.task_id = task_id
        self.scope = scope


def load_task(tid: str) -> JointTask:
    """加载一个任务，附带由 derive_taskscope 自动推导的 TaskScope（禁止手填）。"""
    exports, tools = JOINT_TASK_TOOLS.get(tid, (set(), set()))
    # 威胁分析报告任务：低于 T2 的记忆即使通过区间判定（t_ctx_min=T0），
    # 也按 CONSULT 语义处理（门③b）——可看、可摘、不可写回。
    consult_below = (Trust.T2_MEDIUM if tid == "JOINT-2026-THREATRPT"
                     else Trust.T0_UNTRUSTED)
    scope = derive_taskscope(tid, exports=exports, tools=tools,
                             default_ingest=JOINT_TASK_MODES.get(tid, IngestMode.LEARN),
                             consult_below=consult_below)
    return JointTask(tid, scope)


def build_topology() -> Topology:
    """planner 为根，其余五个均为其 child。不注册审计（链上承担），不进指挥控制台。"""
    topo = Topology()
    topo.add_agent("planner")
    for child in ("situation", "cyber", "ew", "security", "external"):
        topo.add_agent(child, parent="planner")
    return topo


def build_agents() -> dict[str, AgentLabel]:
    """对六个智能体逐个调用 PromptLens 真实标注，返回 result.label。

    使用内置规则抽取器（不传 llm_call），确定性、离线可复现。
    标签不是硬编码返回——EXPECTED_LABELS 仅用于测试断言。
    """
    topo = build_topology()
    pl = PromptLens()
    agents: dict[str, AgentLabel] = {}
    for aid in AGENT_DISPLAY_NAME:
        res = pl.label(
            agent_id=aid,
            system_prompt=_read_prompt(aid),
            tool_registry=JOINT_TOOL_REGISTRY[aid],
            task_max_clearance=Clearance.L3_SECRET,
            parent=topo.parent(aid),
            task_domain={JOINT_TASK},
            collab_group={GROUP_JOINT},
            chain_committed_prompt_hash=prompt_hash(aid),
            epoch=1,
        )
        agents[aid] = res.label
    return agents


# 仅用于测试断言；运行时一律取 build_agents() 的输出。
# 外协密级必须是 L1_INTERNAL 不是 L0：压到 L0 会使它读不到内部级综合态势摘要，
# 第三阶段"外泄动作重放"在读那一步就被门①拦死，门④（机密性门）永远没机会触发。
# 定为 L1 后门①拦"外协读机密级内部研判"，门④拦"内部级内容流向公开级信道"。
EXPECTED_LABELS: dict[str, tuple[Clearance, Trust, set[str]]] = {
    "planner":   (Clearance.L3_SECRET,    Trust.T2_MEDIUM, {"risk_level_publish"}),
    "situation": (Clearance.L2_SENSITIVE, Trust.T2_MEDIUM, {"situation_query"}),
    "cyber":     (Clearance.L2_SENSITIVE, Trust.T2_MEDIUM, {"log_query"}),
    "ew":        (Clearance.L2_SENSITIVE, Trust.T3_HIGH,   {"spectrum_query"}),
    "security":  (Clearance.L3_SECRET,    Trust.T3_HIGH,   set()),
    "external":  (Clearance.L1_INTERNAL,  Trust.T1_LOW,
                  {"xdomain_receive", "xdomain_forward"}),
}
