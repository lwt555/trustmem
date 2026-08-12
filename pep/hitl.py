"""
人在环确认门（F-16）。

高危能力命中 → PDP 产出 CONFIRM 裁决 → HITLGate 阻塞等待人工确认。
AUTO_POLICY 环境变量控制自动化行为：
    once       : 评测/CI 用，人工确认一律放行（只有 deny 算拦截）
    session    : 本会话放行
    deny       : 一律拦截
    interactive: 真实人在环终端（仿真档不实现，抛错）
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum


class HITLDecision(str, Enum):
    ALLOW_ONCE = "allow_once"
    ALLOW_SESSION = "allow_session"
    DENY = "deny"


@dataclass
class HITLResult:
    decision: HITLDecision
    signature: str = ""
    reason: str = ""
    action_fingerprint: str = ""

    @property
    def approved(self) -> bool:
        return self.decision in (HITLDecision.ALLOW_ONCE, HITLDecision.ALLOW_SESSION)


def _auto_policy() -> str:
    return os.environ.get("AUTO_POLICY", "deny").lower()


@contextmanager
def hitl_policy(policy: str):
    """临时切换 AUTO_POLICY（测试用）。"""
    old = os.environ.get("AUTO_POLICY")
    os.environ["AUTO_POLICY"] = policy
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("AUTO_POLICY", None)
        else:
            os.environ["AUTO_POLICY"] = old


class HITLGate:
    """人工确认门。request() 阻塞等待人工确认（仿真档按 AUTO_POLICY 自动化）。"""

    def request(self, decision, timeout_s: float = 30.0) -> HITLResult:
        policy = _auto_policy()
        fp = getattr(decision, "object", "") or ""
        if policy == "once":
            return HITLResult(HITLDecision.ALLOW_ONCE,
                              reason="AUTO_POLICY=once 评测放行",
                              action_fingerprint=fp)
        if policy == "session":
            return HITLResult(HITLDecision.ALLOW_SESSION,
                              reason="AUTO_POLICY=session 会话放行",
                              action_fingerprint=fp)
        if policy == "deny":
            return HITLResult(HITLDecision.DENY,
                              reason="AUTO_POLICY=deny 拦截",
                              action_fingerprint=fp)
        if policy == "interactive":
            raise NotImplementedError("interactive HITL 需真实人在环终端（仿真档不实现）")
        return HITLResult(HITLDecision.DENY, reason=f"未知 AUTO_POLICY={policy}",
                          action_fingerprint=fp)
