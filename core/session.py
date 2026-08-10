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

from .labels import AgentLabel, Trust


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

    @classmethod
    def start(cls, session_id: str, agent: AgentLabel, task_id: str) -> "Session":
        return cls(session_id=session_id, agent_id=agent.agent_id, task_id=task_id,
                   t_eff=agent.trust_intrinsic, t_intrinsic=agent.trust_intrinsic)

    def absorb(self, chunk_id: str, trust: Trust) -> ReadRecord:
        before = self.t_eff
        self.t_eff = Trust(min(int(self.t_eff), int(trust)))
        rec = ReadRecord(chunk_id, trust, before, self.t_eff)
        self.reads.append(rec)
        return rec

    def consult(self, chunk_id: str) -> None:
        self.consulted.add(chunk_id)

    def reset(self) -> None:
        self.t_eff = self.t_intrinsic
        self.reads.clear()
        self.hitl_confirmations.clear()
        self.consulted.clear()

    def add_hitl(self, action_fingerprint: str) -> None:
        self.hitl_confirmations.add(action_fingerprint)

    def has_hitl(self, action_fingerprint: str) -> bool:
        return action_fingerprint in self.hitl_confirmations

    def _elevate(self, new_trust: Trust) -> None:
        self.t_eff = Trust(max(int(self.t_eff), int(new_trust)))


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
