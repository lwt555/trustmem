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
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from .labels import AgentLabel, Trust, Clearance


@dataclass
class ReadRecord:
    chunk_id: str
    trust: Trust
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
    hitl_confirmations: set[str] = field(default_factory=set)
    consulted: set[str] = field(default_factory=set)
    # BLP confidentiality high-watermark — rises on read (max), constrains write-down
    c_eff: Clearance = Clearance.L0_PUBLIC
    c_intrinsic: Clearance = Clearance.L0_PUBLIC
    # LLM isolation watermark — separate from Biba t_eff; drops on constrained queries only
    t_eff_ctl: Trust = Trust.T3_HIGH

    @classmethod
    def start(cls, session_id: str, agent: AgentLabel, task_id: str) -> "Session":
        return cls(session_id=session_id, agent_id=agent.agent_id, task_id=task_id,
                   t_eff=agent.trust_intrinsic, t_intrinsic=agent.trust_intrinsic,
                   c_eff=Clearance.L0_PUBLIC, c_intrinsic=agent.clearance,
                   t_eff_ctl=agent.trust_intrinsic)

    def absorb(self, chunk_id: str, trust: Trust) -> ReadRecord:
        before = self.t_eff
        self.t_eff = Trust(min(int(self.t_eff), int(trust)))
        rec = ReadRecord(chunk_id, trust, before, self.t_eff)
        self.reads.append(rec)
        return rec

    def absorb_c(self, sensitivity: Clearance) -> None:
        """BLP high-watermark: rise to highest sensitivity read this session."""
        self.c_eff = Clearance(max(int(self.c_eff), int(sensitivity)))

    def consult(self, chunk_id: str) -> None:
        self.consulted.add(chunk_id)

    def reset(self) -> None:
        self.t_eff = self.t_intrinsic
        self.c_eff = Clearance.L0_PUBLIC
        self.t_eff_ctl = self.t_intrinsic
        self.reads.clear()
        self.hitl_confirmations.clear()
        self.consulted.clear()

    def add_hitl(self, action_fingerprint: str) -> None:
        self.hitl_confirmations.add(action_fingerprint)

    def has_hitl(self, action_fingerprint: str) -> bool:
        return action_fingerprint in self.hitl_confirmations

    def elevate(self, new_trust: Trust) -> None:
        self.t_eff = Trust(max(int(self.t_eff), int(new_trust)))

    def degrade_ctl(self, trust: Trust) -> None:
        """Degrade LLM isolation watermark after constrained query on low-trust content."""
        self.t_eff_ctl = Trust(min(int(self.t_eff_ctl), int(trust)))



class SessionStore:
    def __init__(self) -> None:
        self._s: dict[tuple[str, str], Session] = {}
        self._capacity_used: dict[str, float] = {}     # session_id → used
        self._capacity_budget: dict[str, float] = {}    # session_id → budget

    def get_or_start(self, session_id: str, agent: AgentLabel, task_id: str) -> Session:
        key = (session_id, agent.agent_id)
        if key not in self._s:
            self._s[key] = Session.start(session_id, agent, task_id)
        return self._s[key]

    def end(self, session_id: str) -> None:
        for (sid, _), sess in list(self._s.items()):
            if sid == session_id:
                sess.reset()
        self.reset_ctl(session_id)

    def all_of(self, session_id: str) -> list[Session]:
        return [s for (sid, _), s in self._s.items() if sid == session_id]

    @property
    def count(self) -> int:
        return len({sid for (sid, _) in self._s})

    def consume_ctl(self, session_id: str, cost: float = 1.0,
                    source_trust: Trust | None = None) -> bool:
        """Session-wide constrained-query budget. Returns False if exhausted."""
        budget = self._capacity_budget.setdefault(session_id, 16.0)
        used = self._capacity_used.setdefault(session_id, 0.0)
        if used + cost > budget:
            return False
        self._capacity_used[session_id] = used + cost
        if source_trust is not None:
            for sess in self.all_of(session_id):
                sess.degrade_ctl(source_trust)
        return True

    def reset_ctl(self, session_id: str) -> None:
        self._capacity_used.pop(session_id, None)
        self._capacity_budget.pop(session_id, None)

    def delegate(self, parent_session_id: str, agent: "AgentLabel",
                 child_task_id: str, child_session_id: str | None = None) -> "Session":
        """创建子会话，继承父会话的 consulted、容量预算和水位。

        §4 第 5 项抽查：子会话必须继承 consulted 集合，否则 I14 被绕开。
        §4 第 8 项抽查：capacity_used 不许因 delegate 而重置。

        父会话查找使用 all_of() 而非 _s.get((sid, aid))，确保不因 AgentLabel
        实例不同而静默跳过继承。
        """
        child_sid = child_session_id or f"{parent_session_id}/{child_task_id}"
        sess = self.get_or_start(child_sid, agent, child_task_id)

        # 继承父会话的 consulted 集合和水位（防止 I14 绕开）
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

        # 继承容量预算（不许因 delegate 而重置）
        p_used = self._capacity_used.get(parent_session_id, 0.0)
        p_budget = self._capacity_budget.get(parent_session_id, 16.0)
        if child_sid not in self._capacity_used:
            self._capacity_used[child_sid] = p_used
            self._capacity_budget[child_sid] = p_budget

        return sess
