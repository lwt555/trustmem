"""
13 个攻防 A/B 对照场景的 pytest 测试（F-13 消融档）
================================================
每个场景验证：NO_PROTECTION（防护 OFF）下攻击成功，FULL（防护 ON）下攻击被阻断。
"""
from __future__ import annotations

import pytest

from scenarios.ablation import (
    ATTACK_IDS, NO_PROTECTION, DENY_ONLY, FULL, run_attack,
)


@pytest.mark.parametrize("aid", ATTACK_IDS)
def test_attack_blocked_with_protection_on(aid):
    """防护 ON（FULL）：所有攻击必须被阻断。"""
    r = run_attack(aid, FULL)
    assert not r.succeeded, f"[{aid}] 防护 ON 时攻击应被阻断，但 succeeded=True"


@pytest.mark.parametrize("aid", ATTACK_IDS)
def test_attack_succeeds_with_protection_off(aid):
    """防护 OFF（NO_PROTECTION）：所有攻击应该成功（无防护时的对照基线）。"""
    r = run_attack(aid, NO_PROTECTION)
    assert r.succeeded, f"[{aid}] 防护 OFF 时攻击应成功，但 succeeded=False"


def test_summary_all_attacks_blocked():
    """全量汇总：所有攻击 防护ON=阻断, 防护OFF=成功。"""
    for aid in ATTACK_IDS:
        off = run_attack(aid, NO_PROTECTION)
        on = run_attack(aid, FULL)
        assert off.succeeded, f"[{aid}] 防护OFF应成功"
        assert not on.succeeded, f"[{aid}] 防护ON应阻断"


def test_a11_echoleak_dual_rule_denial():
    """A11 双平面拒止：机密性平面 NoWriteDown + 完整性平面 Flow-Egress 各拦一次。"""
    r = run_attack("A11", FULL)
    assert not r.succeeded, "A11 应被阻断"
    assert len({b for b in r.blocked_by}) >= 2, f"A11 应被两条不同规则拦截: {r.blocked_by}"
    assert "NoWriteDown" in r.blocked_by, f"机密性平面未拦，实际: {r.blocked_by}"
    assert "Flow-Egress" in r.blocked_by, f"完整性平面未拦，实际: {r.blocked_by}"
