"""
策略执行点 (Policy Enforcement Point, PEP)
==========================================
判定与生效分离（F-04）：PDP 只算 verdict 与 checks，水位变更只在 PEP 提交。

铁律 7：水位只在 `Session.absorb()` 与 `Session.reset()` 两处变化。
`PEP.commit` 是 absorb 的**唯一调用方**（读路径），写路径在 WritePipeline
落库前由 can_write 返回的 decay 驱动。
"""
from __future__ import annotations

from core.session import Session, AbsorbMode
from core.pdp import Decision
from core.verdict import Verdict


class PEP:
    def commit(self, sess: Session, d: Decision, absorb: bool = True) -> None:
        """唯一的水位提交点。非 ALLOW 一律 no-op（I8 隐藏中立性）。

        absorb=False 用于「线索读」：外部情报（T1）作为检索方向进入下游，
        只取内容、不采信，故不降任何水位（t_eff / t_eff_ctl 都不动）。
        """
        if d.verdict is not Verdict.ALLOW or d.pending_absorb is None:
            return
        if not absorb:
            return
        c, t = d.pending_absorb
        sess.absorb(d.object, c, t, mode=AbsorbMode.FULL)
