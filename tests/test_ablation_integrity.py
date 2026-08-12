"""F-13 验收：真实消融档 + 攻击改写（学术诚信）。

- 攻击函数体内不得出现 success/succeeded 常量赋值
- 三档跑同一份脚本（step_signature 一致）
- A11 被 NoWriteDown（机密性平面）+ Flow-Egress（完整性平面）各拦一次
- A13 产出真实 8 跳传播曲线到 bench/propagation.json
- 表 6 第一句：DENY_ONLY 与 FULL 攻击成功率完全一致（实测）
- 绘图脚本从实测产物读取，禁止硬编码数值
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from scenarios.ablation import (
    ATTACK_IDS, NO_PROTECTION, DENY_ONLY, FULL, run_attack,
)
from scenarios.attacks import write_bench_outputs


@pytest.fixture(scope="module")
def bench_data():
    """确保 bench/ 实测产物与当前代码一致。"""
    write_bench_outputs()
    return json.loads(Path("bench/propagation.json").read_text(encoding="utf-8"))


def test_F13_no_constant_success_in_attacks():
    """静态检查：攻击函数体内不得出现 success/succeeded 常量赋值。"""
    tree = ast.parse(Path("scenarios/attacks.py").read_text(encoding="utf-8"))
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        if not fn.name.startswith("attack"):
            continue
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and \
               any(getattr(t, "id", "") in ("success", "succeeded") for t in node.targets) and \
               isinstance(node.value, ast.Constant):
                raise AssertionError(f"{fn.name} 硬编码了攻击结果")


def test_F13_three_tiers_run_same_script():
    for aid in ATTACK_IDS:
        traces = {c.tier: run_attack(aid, c).step_signature
                  for c in (NO_PROTECTION, DENY_ONLY, FULL)}
        assert len(set(traces.values())) == 1, \
            f"{aid} 三档执行路径不一致，不构成消融: {traces}"


def test_F13_a11_blocked_by_two_distinct_rules():
    r = run_attack("A11", FULL)
    assert not r.succeeded
    assert len({b for b in r.blocked_by}) >= 2, f"A11 应被两条不同规则拦截: {r.blocked_by}"
    assert "NoWriteDown" in r.blocked_by and "Flow-Egress" in r.blocked_by


def test_F13_a13_propagation_curve_is_measured(bench_data):
    assert len(bench_data["hops"]) == 8
    assert bench_data["NO_PROTECTION"]["laundered_at"] == 1
    assert bench_data["FULL"]["laundered_at"] is None
    assert all(a >= b for a, b in zip(bench_data["FULL"]["trust_curve"],
                                      bench_data["FULL"]["trust_curve"][1:]))


def test_F13_table6_asr_equal_between_tier2_and_tier3():
    """表 6 四句话第一句：②③ 攻击成功率完全相同。这条必须是实测出来的。"""
    for aid in ATTACK_IDS:
        assert run_attack(aid, DENY_ONLY).succeeded == run_attack(aid, FULL).succeeded


def test_F13_no_hardcoded_data_in_figures():
    src = Path("scripts/generate_figures.py").read_text(encoding="utf-8")
    assert "[1.0] * 13" not in src and "[0.0] * 13" not in src
    assert "json.load" in src or "read_json" in src
