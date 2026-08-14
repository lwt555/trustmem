#!/usr/bin/env python
"""三条基线回归（F-25）。

进入下一阶段之前的门禁之一（设计文档 §4.2）。三条基线必须全绿：

    B1 可信规则对拍   —— docs/TRUST_RULES.md 与代码 @trust_rule 登记一致
    B2 设计一致性回归 —— tests/test_design_conformance.py 全绿（安全语义未反转）
    B3 攻击消融完整性 —— A11 双平面各拦一次、A13 8 跳传播、三档同脚本

用法：
    python tools/regress.py          # 跑三条基线，任一失败返回非零退出码
    python tools/regress.py --list   # 只列基线，不执行
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def _reconfigure_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


# ──────────────────────────────────────────────────────────────
# B1 · 可信规则对拍
# ──────────────────────────────────────────────────────────────

def baseline_1_trust_rules() -> bool:
    from tools.gen_trust_rules import check
    print("\n[B1] 可信规则对拍 (TRUST_RULES.md ↔ @trust_rule)")
    return check() == 0


# ──────────────────────────────────────────────────────────────
# B2 · 设计一致性回归
# ──────────────────────────────────────────────────────────────

def baseline_2_design_conformance() -> bool:
    print("\n[B2] 设计一致性回归 (tests/test_design_conformance.py)")
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/test_design_conformance.py", "-q"],
        cwd=str(ROOT),
    )
    return r.returncode == 0


# ──────────────────────────────────────────────────────────────
# B3 · 攻击消融完整性
# ──────────────────────────────────────────────────────────────

def baseline_3_attack_ablation() -> bool:
    print("\n[B3] 攻击消融完整性 (A11 双平面 + A13 传播 + 三档同脚本)")
    from scenarios.ablation import (run_attack, NO_PROTECTION, DENY_ONLY, FULL,
                                    TIERS)

    ok = True

    # A11：必须由机密性平面(NoWriteDown)与完整性平面(Flow-Egress)各拦一次。
    r = run_attack("A11", FULL)
    a11_two_rules = (not r.succeeded
                     and "NoWriteDown" in r.blocked_by
                     and "Flow-Egress" in r.blocked_by)
    print(f"    A11 blocked_by={sorted(set(r.blocked_by))} "
          f"双平面拦截={'OK' if a11_two_rules else 'FAIL'}")
    ok = ok and a11_two_rules

    # A13：8 跳传播，FULL 不被洗白，NO_PROTECTION 被洗白。
    from scenarios.attacks import _propagation
    full = _propagation(FULL)
    off = _propagation(NO_PROTECTION)
    a13_curve = (len(full["trust_curve"]) == 8
                 and full["laundered_at"] is None
                 and off["laundered_at"] is not None)
    print(f"    A13 hops={len(full['trust_curve'])} "
          f"FULL.laundered={full['laundered_at']} "
          f"OFF.laundered={off['laundered_at']} "
          f"{'OK' if a13_curve else 'FAIL'}")
    ok = ok and a13_curve

    # 三档同一份攻击脚本（step_signature 一致，才构成消融）。
    sigs = {c.tier: run_attack("A11", c).step_signature for c in TIERS}
    same_script = len(set(sigs.values())) == 1
    print(f"    三档 step_signature 一致={'OK' if same_script else 'FAIL'}")
    ok = ok and same_script

    return ok


BASELINES = (
    ("B1 可信规则对拍", baseline_1_trust_rules),
    ("B2 设计一致性回归", baseline_2_design_conformance),
    ("B3 攻击消融完整性", baseline_3_attack_ablation),
)


def main(argv: list[str] | None = None) -> int:
    _reconfigure_streams()
    if argv and "--list" in argv:
        for name, _ in BASELINES:
            print(f"- {name}")
        return 0

    failed: list[str] = []
    for name, fn in BASELINES:
        try:
            passed = fn()
        except Exception as exc:  # noqa: BLE001 — 基线失败也要报全
            passed = False
            print(f"    [EXCEPTION] {type(exc).__name__}: {exc}")
        print(f"  -> {name}: {'PASS' if passed else 'FAIL'}")
        if not passed:
            failed.append(name)

    print("\n" + "=" * 60)
    if failed:
        print(f"基线回归失败 {len(failed)}/3: {', '.join(failed)}")
        return 1
    print("三条基线回归全绿")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
