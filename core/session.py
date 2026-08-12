"""
会话态与低水位标记 (Low Water-Mark, LOMAC)
==========================================

原始 Biba 的 "no read down" 在本场景不可用 -- 分析 Agent 必须读外部情报，
否则系统根本不工作。采用 Biba 的成熟变体 LOMAC（Fraser, IEEE S&P 2000）：

    允许读低完整性客体，但读取后主体的**有效完整性等级下降到该客体的水平**。

        读操作后:  T_eff(A) <- min( T_eff(A), T(m) )
        写/执行时: 要求 T(target) <= T_eff(A)

这一条直接实现了会上说的"二手记忆更可能被操控"：
分析 Agent 读了 T1 情报，它这一轮产出的结论就是 T1，
无法进入 T3 记忆区，也无法触发要求 T3 的封禁动作。

完整性坍缩问题（必被问）：
    "跑几轮所有 Agent 都降到 T0，系统不就废了？"
解法三条：
    (a) 会话级隔离 -- T_eff 只在当前任务会话内下降，会话结束重置
    (b) 提升网关   -- 见 upgrader.py，交叉印证/结构校验/人在环可提升
    (c) 降级 != 禁用 -- T1 记忆仍可读、可分析、可展示，
                       受限的只是"进入高可信决策链"和"触发高危工具"

铁律 7：水位只在 `Session.absorb()` 与 `Session.reset()` 两处变化。
    无 read-down 的 Biba 变体里，可信度只有一条上升通道——背书门（TR11–TR14）。
    `elevate()` 已删除；`absorb_c` / `degrade_ctl` 并入单一入口 `absorb`。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import ClassVar

from .labels import AgentLabel, Trust, Clearance
from .trust_rules import trust_rule


class AbsorbMode(str, Enum):
    """受限展开与无界展开的两种语义（TR3 / TR4）。"""
    FULL = "full"        # 无界展开：t_eff 与 t_eff_ctl 一起下降
    BOUNDED = "bounded"  # 受限展开：t_eff 下降，t_eff_ctl 不变


@dataclass
class ReadRecord:
    chunk_id: str
    trust: Trust
    sensitivity: Clearance
    mode: AbsorbMode
    t_eff_before: Trust
    t_eff_after: Trust
    at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Session:
    """一次任务会话内某个 Agent 的动态状态。"""
    session_id: str
    agent_id: str
    task_id: str
    t_eff: Trust
    t_intrinsic: Trust
    reads: list[ReadRecord] = field(default_factory=list)
    hitl_confirmations: frozenset[str] = field(default_factory=frozenset)
    consulted: set[str] = field(default_factory=set)
    # BLP confidentiality high-watermark — rises on read (max), constrains write-down
    c_eff: Clearance = Clearance.L0_PUBLIC
    c_intrinsic: Clearance = Clearance.L0_PUBLIC
    # LLM isolation watermark — separate from Biba t_eff; drops only on unbounded absorb
    t_eff_ctl: Trust = Trust.T3_HIGH
    # 控制流预算（4 bit 封顶，全会话共享、不可中途重置）
    capacity_used_bits: float = 0.0

    CAPACITY_BUDGET_BITS: ClassVar[float] = 4.0

    @classmethod
    def start(cls, session_id: str, agent: AgentLabel, task_id: str) -> "Session":
        return cls(session_id=session_id, agent_id=agent.agent_id, task_id=task_id,
                   t_eff=agent.trust_intrinsic, t_intrinsic=agent.trust_intrinsic,
                   c_eff=Clearance.L0_PUBLIC, c_intrinsic=agent.clearance,
                   t_eff_ctl=agent.trust_intrinsic)

    @trust_rule("TR1", group="A",
                trigger="LEARN 模式读入一条低可信记忆",
                change="t_eff ← min(t_eff, T(m)) 只降不升；c_eff ← max(c_eff, L(m)) 只升不降",
                basis="LOMAC 低水位（Fraser, IEEE S&P 2000）")
    def absorb(self, chunk_id: str, sensitivity: Clearance, trust: Trust,
               mode: AbsorbMode = AbsorbMode.FULL) -> ReadRecord:
        """唯一水位变更入口。mode ∈ {FULL, BOUNDED}。

        - 两种模式都降 t_eff（数据流真相不变，前端照实显示）
        - 仅 FULL 降 t_eff_ctl（无界展开）
        - c_eff 始终取 max（机密性高水位只升）
        """
        before = self.t_eff
        self.t_eff = Trust(min(int(self.t_eff), int(trust)))
        if mode is AbsorbMode.FULL:
            self.t_eff_ctl = Trust(min(int(self.t_eff_ctl), int(trust)))
        self.c_eff = Clearance(max(int(self.c_eff), int(sensitivity)))
        rec = ReadRecord(chunk_id=chunk_id, trust=trust, sensitivity=sensitivity,
                         mode=mode, t_eff_before=before, t_eff_after=self.t_eff)
        self.reads.append(rec)
        return rec

    def consult(self, chunk_id: str) -> None:
        self.consulted.add(chunk_id)

    def _raise_trust_via_gate(self, new_trust: Trust) -> None:
        """唯一允许 t_eff 上升的私有入口（铁律 8 / I6）。

        只可被 `Upgrader.apply_to_session` 调用 —— 那是背书门（TR11–TR14）
        的显式提权点，要求证据 + HITL 签名 + 锚定回执三者齐全。
        """
        self.t_eff = Trust(max(int(self.t_eff), int(new_trust)))

    def consume_bits(self, bits: float) -> bool:
        """尝试消耗控制流预算。返回 False 表示预算耗尽。"""
        if self.capacity_used_bits + bits > self.CAPACITY_BUDGET_BITS:
            return False
        self.capacity_used_bits += bits
        return True

    @trust_rule("TR5", group="A",
                trigger="会话结束 reset()",
                change="t_eff / t_eff_ctl 复位到 t_intrinsic，c_eff 复位 L0，容量预算清零",
                basis="会话级隔离（会话结束语义）")
    def reset(self) -> None:
        self.t_eff = self.t_intrinsic
        self.c_eff = Clearance.L0_PUBLIC
        self.t_eff_ctl = self.t_intrinsic
        self.capacity_used_bits = 0.0
        self.reads.clear()
        self.hitl_confirmations = frozenset()
        self.consulted.clear()

    def add_hitl(self, action_fingerprint: str) -> None:
        # F-16：hitl_confirmations 是只读 frozenset，只能经此方法写入。
        self.hitl_confirmations = self.hitl_confirmations | {action_fingerprint}

    def has_hitl(self, action_fingerprint: str) -> bool:
        return action_fingerprint in self.hitl_confirmations


class SessionStore:
    def __init__(self) -> None:
        self._s: dict[tuple[str, str], Session] = {}

    def get_or_start(self, session_id: str, agent: AgentLabel, task_id: str) -> Session:
        key = (session_id, agent.agent_id)
        if key not in self._s:
            self._s[key] = Session.start(session_id, agent, task_id)
        return self._s[key]

    def end(self, session_id: str) -> None:
        for (sid, _), sess in list(self._s.items()):
            if sid == session_id:
                sess.reset()

    def all_of(self, session_id: str) -> list[Session]:
        return [s for (sid, _), s in self._s.items() if sid == session_id]

    @property
    def count(self) -> int:
        return len({sid for (sid, _) in self._s})

    def consume_ctl(self, session_id: str, cost: float = 1.0,
                    source_trust: Trust | None = None) -> bool:
        """Session-wide constrained-query budget. Returns False if exhausted.

        受限展开（source_trust 非空）→ BOUNDED：t_eff 降、t_eff_ctl 不变（TR3）。
        """
        sessions = self.all_of(session_id)
        if not sessions:
            return False
        sess = sessions[0]
        if not sess.consume_bits(cost):
            return False
        if source_trust is not None:
            for s in sessions:
                s.absorb(f"#var#{session_id}", Clearance.L0_PUBLIC, source_trust,
                         mode=AbsorbMode.BOUNDED)
        return True

    @trust_rule("TR15", group="D",
                trigger="委派创建子会话（跨主体边界）",
                change="t_eff_child ← min(t_eff_parent, t_intrinsic_child)；区间只能更紧",
                basis="委派继承只紧不松（§3.6）")
    def delegate(self, parent_session_id: str, agent: "AgentLabel",
                 child_task_id: str, child_session_id: str | None = None) -> "Session":
        """创建子会话，继承父会话的 consulted、容量预算和水位。

        父会话查找使用 all_of() 而非 _s.get((sid, aid))，确保不因 AgentLabel
        实例不同而静默跳过继承。
        """
        child_sid = child_session_id or f"{parent_session_id}/{child_task_id}"
        sess = self.get_or_start(child_sid, agent, child_task_id)

        parent = None
        for p in self.all_of(parent_session_id):
            if p.agent_id == agent.agent_id:
                parent = p
                break
        if parent is not None:
            sess.consulted = set(parent.consulted)
            sess.c_eff = parent.c_eff
            sess.t_eff = parent.t_eff
            sess.t_eff_ctl = parent.t_eff_ctl
            sess.capacity_used_bits = parent.capacity_used_bits

        return sess
