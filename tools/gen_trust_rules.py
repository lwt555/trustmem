#!/usr/bin/env python
"""从代码反向生成 docs/TRUST_RULES.md（F-15）。

每条可信流转规则在实现处用 ``@trust_rule`` 装饰器登记；本脚本扫描
登记项生成四组十六条的规则表，与手写文档对拍。

用法：
    python tools/gen_trust_rules.py            # 生成并覆盖 docs/TRUST_RULES.md
    python tools/gen_trust_rules.py --check    # 对拍校验，不一致则返回非零退出码
    python tools/gen_trust_rules.py --print    # 打印规则表到 stdout（不写文件）
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# 导入全部带 @trust_rule 装饰的模块，填充 REGISTRY。
import core.session        # noqa: E402,F401  (TR1 / TR5 / TR15)
import core.pdp            # noqa: E402,F401  (TR2 / TR10)
import core.decay          # noqa: E402,F401  (TR6 / TR7 / TR8 / TR9)
import core.upgrader       # noqa: E402,F401  (TR11 / TR12 / TR13 / TR14)
import core.varstore       # noqa: E402,F401  (TR3 / TR4)
import core.pipeline       # noqa: E402,F401  (TR16)

from core.trust_rules import all_rules, parse_trust_rules  # noqa: E402

DOC_PATH = ROOT / "docs" / "TRUST_RULES.md"

GROUP_TITLES = {
    "A": "A 组 · 读入（可信度进入上下文的时刻）",
    "B": "B 组 · 写出（可信度离开主体的时刻）",
    "C": "C 组 · 越格（唯一上升通道：背书门）",
    "D": "D 组 · 跨主体（传播边界）",
}

HEADER = """# TrustMem 可信流转规则 TR1–TR16

> **总纲**：可信度在本系统里**只有一条上升通道**——背书门（TR11–TR14）；
> 其余全部路径单调不增。这条性质使「洗白」与「污染扩散」在结构上失效，而不是靠检测。

本表由 `tools/gen_trust_rules.py` 从代码反向生成——每条规则的实现处用
`@trust_rule` 装饰器登记元数据，脚本扫描生成，与实现永远同步。
改动规则实现后运行 `python tools/gen_trust_rules.py --check` 对拍校验。

## 一、两条独立的格子

TrustMem 的可信流转建立在两条偏序格上：

| 格 | 方向 | 读入效应 | 写出效应 |
|---|---|---|---|
| 机密性格 L（Bell-LaPadula） | 只升不降 | c_eff ← max（高水位） | 无写下（no write down） |
| 完整性格 T（Biba） | 只降不升 | t_eff ← min（低水位） | 无写上（no write up） |

---

## 二、规则表（四组十六条）

每条五列：`ID | 触发事件 | 变化 | 依据 | 代码位置`。
"""


def render_tables() -> str:
    out: list[str] = []
    for g in ("A", "B", "C", "D"):
        out.append(f"### {GROUP_TITLES[g]}\n")
        out.append("| ID | 触发事件 | 变化 | 依据 | 代码位置 |")
        out.append("|---|---|---|---|---|")
        for r in all_rules():
            if r.group == g:
                out.append(
                    f"| {r.rule_id} | {r.trigger} | {r.change} | {r.basis} "
                    f"| `{r.code_location}` |")
        out.append("")
    return "\n".join(out)


ARGUMENT = """## 三、三段论证（设计文档第十部分第 5 条）

### 3.1 分组即分阶段

可信度只在三个时刻可能变化——**进入上下文、离开主体、显式越格**：

| 组 | 作用时刻 | 时序 |
|---|---|---|
| A 组（TR1–TR5） | 读入：可信度进入上下文 | 最先 |
| B 组（TR6–TR10） | 写出：可信度离开主体 | 其次 |
| C 组（TR11–TR14） | 越格：显式背书 | 唯一上升 |
| D 组（TR15–TR16） | 跨主体：传播边界 | A+B 的复合 |

四组在时序上互斥，因此**不存在组间冲突**。

### 3.2 组内优先级（代码可验证）

- **A 组**：`TR2 > TR1`（模式检查先于标签判定——CONSULT 读入不触发 LOMAC 吸收）
- **B 组**：`TR10 > TR7 > TR9 > TR8 > TR6`（硬拒 > 谎报降级 > 融合取脏 > 加工衰减 > 基线 meet）

实现位置：`PDP.can_write` 中 TR10（Provenance-NoConsult）最先判定，命中即 DENY，
不进入 `compute_trust` 的衰减计算；衰减计算内部按 TR7（谎报降级）→ TR9/TR8（取脏+衰减）
→ TR6（基线 meet）的顺序执行。

### 3.3 完备性论证

可信度只在三个时刻可能变化——进入上下文、离开主体、显式越格。
A/B/C 三组各覆盖一个，D 组是 A+B 在跨主体边界上的复合。
穷举测试（`test_invariants.py`：4×4×4×4 全组合 + 7000 条随机操作序列）是这条论证的实测支撑。

---

## 四、与经典 Biba 的差异

| 维度 | 经典 Biba | TrustMem |
|---|---|---|
| 处理数据是否改变完整性 | 不变（主体处理数据不改变完整性） | LLM 会幻觉，过程本身计入衰减 δ(op)（TR8） |
| δ=0 声明 | 无校验 | VERBATIM/EXTRACT 必须可验证，失败降 INFER（TR7） |
| 完整性提升 | 无 | 唯一上升通道：背书门（TR11–TR14），抗 Sybil、可上链 |
"""


def render_anchor_events() -> str:
    from core.merkle import DESIGN_EVENT_TYPES
    rows = "\n".join(f"| {t} |" for t in DESIGN_EVENT_TYPES)
    return (
        "## 五、13 类锚定事件（F-18 / 设计文档 §3.7）\n\n"
        "Merkle 审计树的事件类型必须与设计文档点名清单完全一致；"
        "未映射的裁决一律抛错，绝不静默回退成 CONSULT。\n\n"
        f"| EventType |\n|---|\n{rows}\n"
    )


def render_doc() -> str:
    return (HEADER + "\n" + render_tables().rstrip() + "\n\n---\n\n"
            + ARGUMENT.rstrip() + "\n\n---\n\n" + render_anchor_events())


def check() -> int:
    """对拍校验 docs/TRUST_RULES.md 与代码登记项。返回 0 表示一致。"""
    if not DOC_PATH.exists():
        print(f"[ERROR] {DOC_PATH} 不存在")
        return 1
    doc = {r.rule_id: r for r in parse_trust_rules(str(DOC_PATH))}
    reg = {r.rule_id: r for r in all_rules()}
    ok = True

    if set(doc) != set(reg):
        missing = sorted(set(reg) - set(doc))
        extra = sorted(set(doc) - set(reg))
        if missing:
            print(f"[MISMATCH] 文档缺少规则: {missing}")
        if extra:
            print(f"[MISMATCH] 文档多余规则: {extra}")
        ok = False

    for rid, r in reg.items():
        if rid not in doc:
            continue
        d = doc[rid]
        for field in ("trigger", "change", "basis", "code_location"):
            if getattr(d, field) != getattr(r, field):
                print(f"[MISMATCH] {rid}.{field}:")
                print(f"    doc  = {getattr(d, field)!r}")
                print(f"    code = {getattr(r, field)!r}")
                ok = False

    if ok:
        print(f"[OK] {len(reg)} 条规则全部与代码一致")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    # Windows 控制台默认 GBK，显式切 UTF-8 避免打印中文时崩溃。
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="对拍校验，不一致返回非零")
    ap.add_argument("--print", action="store_true", dest="to_stdout",
                    help="打印到 stdout，不写文件")
    args = ap.parse_args(argv)

    if args.check:
        return check()

    text = render_doc()
    if args.to_stdout:
        sys.stdout.write(text)
        return 0

    DOC_PATH.write_text(text, encoding="utf-8")
    print(f"[OK] 已生成 {DOC_PATH}（{len(all_rules())} 条规则）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
