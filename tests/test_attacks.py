"""
13 个攻防 A/B 对照场景的 pytest 测试
==================================
每个场景验证：防护 OFF 下攻击成功，防护 ON 下攻击被阻断。
"""
from __future__ import annotations

import pytest
from scenarios.attacks import (
    attack1_memory_poisoning,
    attack2_reasoning_leak,
    attack3_collusion,
    attack5_sybil_cross_source,
    attack6_indirect_injection,
    attack7_unauthorized_retrieval,
    attack8_reasoning_theft,
    attack9_cumulative_leak,
    attack10_membership_inference,
    attack11_echoleak,
    attack12_downgrade_wash,
    attack13_contamination_spread,
)

ATTACKS = [
    ("A01-记忆投毒->横向越权", attack1_memory_poisoning),
    ("A02-思考过程窃取->定向注入", attack2_reasoning_leak),
    ("A03-属性合谋提权", attack3_collusion),
    ("A05-Sybil伪造多源印证", attack5_sybil_cross_source),
    ("A06-间接注入跨Agent传播", attack6_indirect_injection),
    ("A07-越权检索L3机密", attack7_unauthorized_retrieval),
    ("A08-推理层窃取", attack8_reasoning_theft),
    ("A09-长链累积泄露", attack9_cumulative_leak),
    ("A10-成员推理探测", attack10_membership_inference),
    ("A11-EchoLeak投毒诱导外泄", attack11_echoleak),
    ("A12-降级洗白外泄", attack12_downgrade_wash),
    ("A13-记忆污染多跳扩散", attack13_contamination_spread),
]


@pytest.mark.parametrize("name,fn", ATTACKS)
def test_attack_blocked_with_protection_on(name, fn):
    """防护 ON：所有攻击必须被阻断。"""
    result = fn(protection=True)
    assert not result["attack_success"], (
        f"[{name}] 防护 ON 时攻击应被阻断，但 attack_success=True"
    )


@pytest.mark.parametrize("name,fn", ATTACKS)
def test_attack_succeeds_with_protection_off(name, fn):
    """防护 OFF：所有攻击应该成功（无防护时的对照基线）。"""
    result = fn(protection=False)
    assert result["attack_success"], (
        f"[{name}] 防护 OFF 时攻击应成功，但 attack_success=False"
    )


def test_a04_prompt_tampering_blocked():
    """A04 单独测，因依赖 promptlens。"""
    from scenarios.attacks import attack4_prompt_tampering
    result = attack4_prompt_tampering(protection=True)
    assert not result["attack_success"], "提示词篡改在防护 ON 时应被阻断"


def test_a04_prompt_tampering_succeeds_off():
    """A04 防护 OFF。"""
    from scenarios.attacks import attack4_prompt_tampering
    result = attack4_prompt_tampering(protection=False)
    assert result["attack_success"], "提示词篡改在防护 OFF 时应成功"


def test_summary_all_attacks_blocked():
    """全量汇总：所有攻击 防护ON=阻断, 防护OFF=成功。"""
    results = []
    for name, fn in ATTACKS:
        off = fn(False)
        on = fn(True)
        results.append((name, off["attack_success"], on["attack_success"]))

    # 防护 OFF 全部成功
    for name, off_ok, _ in results:
        assert off_ok, f"[{name}] 防护OFF应成功"

    # 防护 ON 全部阻断
    for name, _, on_ok in results:
        assert not on_ok, f"[{name}] 防护ON应阻断"

    # A04 单独测
    from scenarios.attacks import attack4_prompt_tampering
    a4_off = attack4_prompt_tampering(False)
    a4_on = attack4_prompt_tampering(True)
    assert a4_off["attack_success"]
    assert not a4_on["attack_success"]
