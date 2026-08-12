"""
三档消融配置与攻击执行环境（F-13）
==================================
「防护 OFF」不再是一个硬编码的 ``success = True`` 常量，而是真实地跑一遍
同一份攻击脚本，仅把 PDP 换成三档消融配置中的一档：

    NO_PROTECTION : PDP 全部检查旁路（bypass_all=True），无标签传播、无衰减
    DENY_ONLY     : 全部检查生效，但 hide_enabled=False（HIDE 退化为 DENY）
    FULL          : 全部检查 + HIDE + 双平面

三档必须跑同一份攻击脚本、同一份任务脚本，差别只在 PDP 配置——这是「消融」的
定义（设计文档铁律 12「如实报数」）。

评测约定（设计文档 §3.4）
------------------------
跑攻击评测与 CI 时 ``AUTO_POLICY="once"``，人工确认一律按放行处理，只有
``deny`` 算拦截。本开关在此显式实现：``AUTO_POLICY="once"`` 时，评测环境
把 HITL 视为已放行，使 ``HumanInTheLoop`` 检查不构成拦截——「拦截」只来自
规则本身，而不是「缺人签」。此约定已在 ``bench/report.md`` 中写明。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Literal

from core.pdp import PDP, Decision
from core.session import SessionStore
from pep.pep import PEP
from scenarios.soc_setup import build_agents, build_topology, TASK

Tier = Literal["NO_PROTECTION", "DENY_ONLY", "FULL"]

# 评测约定：评测与 CI 一律 once；strict 仅作预留，不用于评测判分。
AUTO_POLICY = os.environ.get("AUTO_POLICY", "once")
assert AUTO_POLICY == "once", "评测与 CI 必须使用 AUTO_POLICY=once"


@dataclass(frozen=True)
class AblationConfig:
    tier: Tier
    bypass_all: bool
    hide_enabled: bool


NO_PROTECTION = AblationConfig("NO_PROTECTION", bypass_all=True, hide_enabled=False)
DENY_ONLY = AblationConfig("DENY_ONLY", bypass_all=False, hide_enabled=False)
FULL = AblationConfig("FULL", bypass_all=False, hide_enabled=True)

TIERS: tuple[AblationConfig, ...] = (NO_PROTECTION, DENY_ONLY, FULL)
BY_TIER: dict[str, AblationConfig] = {c.tier: c for c in TIERS}

ATTACK_IDS: list[str] = [f"A{i:02d}" for i in range(1, 14)]


@dataclass
class AttackResult:
    attack_id: str
    succeeded: bool
    blocked_by: list[str] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)
    step_signature: tuple[str, ...] = ()

    @property
    def asr(self) -> int:
        """攻击成功率：1 = 成功，0 = 被拦。"""
        return 1 if self.succeeded else 0


@dataclass
class AttackEnv:
    """攻击执行环境：三档共用，差别只在 cfg 对应的 PDP 配置。"""
    cfg: AblationConfig
    pdp: PDP
    agents: dict
    topo: object
    store: SessionStore
    decisions: list[Decision] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    pep: PEP = field(default_factory=PEP)

    @property
    def task(self) -> str:
        return TASK

    def trace(self, step: str) -> None:
        """记录一个攻击步骤名，供三档 step_signature 一致性断言（F-13）。"""
        self.steps.append(step)

    def decide(self, d: Decision) -> Decision:
        """登记一次裁决并返回之，供攻击函数链式使用。"""
        self.decisions.append(d)
        return d

    def read(self, agent, mem, sess) -> Decision:
        """读 + PEP 提交水位（反映真实读路径的 LOMAC 低水位）。"""
        self.trace(f"read:{mem.chunk_id}")
        d = self.pdp.can_read(agent, mem, sess)
        self.pep.commit(sess, d)
        return self.decide(d)

    def write(self, agent, sess, sensitivity, layer, input_mems, op,
              output_text="", declassify_approved=False):
        """写 + 返回 (decision, decay)。"""
        self.trace(f"write:{layer.value}/{sensitivity.name[:2]}")
        d, decay = self.pdp.can_write(
            agent, sess, sensitivity, layer, input_mems, op,
            output_text=output_text, declassify_approved=declassify_approved)
        self.decide(d)
        return d, decay

    def invoke(self, agent, sess, tool, action_fingerprint="", provenance=None,
               arg_labels=None) -> Decision:
        """调用高危工具。"""
        self.trace(f"invoke:{tool}")
        d = self.pdp.can_invoke(agent, sess, tool, action_fingerprint,
                                provenance=provenance, arg_labels=arg_labels)
        return self.decide(d)

    def session(self, sid: str, agent):
        return self.store.get_or_start(sid, agent, TASK)

    @property
    def step_signature(self) -> tuple[str, ...]:
        return tuple(self.steps)


def build_env(cfg: AblationConfig) -> AttackEnv:
    agents, topo = build_agents(), build_topology()
    pdp = PDP(topo, hide_enabled=cfg.hide_enabled, bypass_all=cfg.bypass_all)
    store = SessionStore()
    return AttackEnv(cfg=cfg, pdp=pdp, agents=agents, topo=topo, store=store)


def _rule_name(denied_by: str) -> str:
    """把写降密的类别标签 NoWriteDown(...) 归一为 NoWriteDown，
    其余规则名保留原值。"""
    if denied_by.startswith("NoWriteDown"):
        return "NoWriteDown"
    return denied_by


def blocked_rules(decisions: list[Decision]) -> list[str]:
    """从裁决序列提取「拦截规则名」。"""
    return [_rule_name(d.denied_by) for d in decisions
            if not d.allowed and d.denied_by is not None]


def run_attack(attack_id: str, cfg: AblationConfig) -> AttackResult:
    """按档位执行一条攻击。攻击脚本同一份，差别只在 cfg。"""
    from scenarios import attacks  # 延迟导入，避免模块级循环
    return attacks.ATTACK_FNS[attack_id](cfg)
