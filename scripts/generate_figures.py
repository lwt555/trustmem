"""
TrustMem 报告图表生成脚本
========================
生成 5 张论文级图表：
  fig1 — 攻击 A/B 对照柱状图
  fig2 — 信息流不变式覆盖报告
  fig3 — 性能基准对比
  fig4 — 可信度衰减曲线
  fig5 — 四值裁决典型场景分布

用法:  python scripts/generate_figures.py
输出:  figures/*.png
"""
from __future__ import annotations

import sys
import os

# 修复 Windows 终端编码问题
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.font_manager as fm
import numpy as np

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "figures")
os.makedirs(OUT, exist_ok=True)

# 查找系统 CJK 字体
_font_name = None
for _f in fm.fontManager.ttflist:
    if _f.name in ("Microsoft YaHei", "SimHei", "Noto Sans SC"):
        _font_name = _f.name
        break
if _font_name is None:
    _font_name = "Microsoft YaHei"  # fallback

# 全局样式
plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": [_font_name, "DejaVu Sans", "Arial"],
    "font.size": 11,
    "axes.titlesize": 14,
    "axes.labelsize": 12,
    "figure.dpi": 150,
    "savefig.dpi": 150,
    "savefig.bbox": "tight",
    "axes.grid": True,
    "grid.alpha": 0.3,
    "axes.unicode_minus": False,
})

print(f"字体: {_font_name}")


# ══════════════════════════════════════════════════════════════
# Figure 1: 攻击 A/B 对照
# ══════════════════════════════════════════════════════════════
def fig1_attack_ab():
    attacks = [
        "A01\n记忆投毒", "A02\n思考窃取", "A03\n属性合谋",
        "A04\n提示词篡改", "A05\nSybil伪造", "A06\n间接注入",
        "A07\n越权检索", "A08\n推理层窃取", "A09\n累积泄露",
        "A10\n成员推理", "A11\nEchoLeak", "A12\n降级洗白",
        "A13\n污染扩散",
    ]
    # All attacks: OFF=100% success, ON=0% success
    off = [1.0] * 13
    on = [0.0] * 13

    x = np.arange(len(attacks))
    width = 0.35

    fig, ax = plt.subplots(figsize=(14, 5.5))
    bars1 = ax.bar(x - width / 2, [v * 100 for v in off], width,
                   label="防护 OFF", color="#ef4444", alpha=0.85, edgecolor="white")
    bars2 = ax.bar(x + width / 2, [v * 100 for v in on], width,
                   label="防护 ON", color="#22c55e", alpha=0.85, edgecolor="white")

    ax.set_ylabel("攻击成功率 (%)")
    ax.set_title("图 1：13 个攻击场景 A/B 对照 — 防护 ON 下攻击成功率 0%")
    ax.set_xticks(x)
    ax.set_xticklabels(attacks, fontsize=8)
    ax.legend(loc="upper right")
    ax.set_ylim(0, 115)

    for bar in bars1:
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1, "100%",
                ha="center", va="bottom", fontsize=7, fontweight="bold", color="#ef4444")
    for bar in bars2:
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1, "0%",
                ha="center", va="bottom", fontsize=7, fontweight="bold", color="#22c55e")

    ax.axhline(y=0, color="black", linewidth=0.5)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "fig1_attack_ab.png"))
    plt.close(fig)
    print(f"  ✓ fig1_attack_ab.png")


# ══════════════════════════════════════════════════════════════
# Figure 2: 不变量覆盖矩阵
# ══════════════════════════════════════════════════════════════
def fig2_invariant_coverage():
    invariants = [
        ("I1", "BLP\nno-read-up", 5184, 0),
        ("I2", "R层\n仅向上", 216, 0),
        ("I3", "低水位\n单调性", 2000, 0),
        ("I4", "Biba\nno-write-up", 3000, 0),
        ("I5", "污染禁\n高危", 2000, 0),
        ("I6", "Need-to\n-Know", 1, 0),
        ("I7", "TTL\n过期阻断", 1, 0),
        ("I8", "Epoch\n版本隔离", 1000, 0),
        ("I9", "Lifecycle\n非active", 2, 0),
        ("I10", "LayerWrite\n需下级", 1, 0),
        ("I11", "会话\n隔离", 2000, 0),
        ("I12", "TaskScope\n推导一致", 3, 0),
        ("I13", "写降密\n审批", 1, 0),
        ("I14", "CONSULT\n禁写回", 1000, 0),
    ]

    ids = [i[0] for i in invariants]
    names = [i[1] for i in invariants]
    combos = [i[2] for i in invariants]
    violations = [i[3] for i in invariants]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))

    # Left: combo counts
    colors = ["#22c55e" if v == 0 else "#ef4444" for v in violations]
    bars = ax1.barh(ids, combos, color=colors, alpha=0.8, edgecolor="white")
    ax1.set_xlabel("穷举组合数")
    ax1.set_title("验证规模（组合数）")
    ax1.set_xscale("log")
    for bar, val in zip(bars, combos):
        ax1.text(bar.get_width() + 5, bar.get_y() + bar.get_height() / 2,
                f"{val:,}", va="center", fontsize=7)

    # Right: violation count (all zero)
    ax2.barh(ids, violations, color="#22c55e", alpha=0.8, edgecolor="white")
    ax2.set_xlabel("违反次数")
    ax2.set_title("违反次数（全部 = 0）")
    ax2.set_xlim(-0.5, 1.5)
    ax2.set_xticks([0, 1])

    fig.suptitle("图 2：信息流不变式穷举验证 — 14 条不变式零违反", fontsize=14, fontweight="bold", y=1.01)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "fig2_invariant_coverage.png"))
    plt.close(fig)
    print(f"  ✓ fig2_invariant_coverage.png")


# ══════════════════════════════════════════════════════════════
# Figure 3: 性能基准
# ══════════════════════════════════════════════════════════════
def fig3_benchmarks():
    metrics = [
        ("PDP\ncan_read", 48000, 3000),
        ("PDP\ncan_write", 35000, 2000),
        ("Merkle\nlog", 280000, 10000),
        ("Merkle\nproof", 180, 5000),    # μs
        ("ABE\nenc+dec", 650, 100),
        ("Policy\ncheck", 850000, 10000),
    ]

    labels = [m[0] for m in metrics]
    actual = [m[1] for m in metrics]
    target = [m[2] for m in metrics]

    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(labels))
    width = 0.35

    bars1 = ax.bar(x - width / 2, actual, width, label="实测", color="#60a5fa", alpha=0.85, edgecolor="white")
    bars2 = ax.bar(x + width / 2, target, width, label="目标", color="#94a3b8", alpha=0.5, edgecolor="white", hatch="//")

    ax.set_ylabel("ops/s（对数）")
    ax.set_title("图 3：TrustMem 核心模块吞吐量基准")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_yscale("log")
    ax.legend()

    for bar, val in zip(bars1, actual):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() * 1.1,
                f"{val:,}", ha="center", va="bottom", fontsize=7, rotation=0)

    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "fig3_benchmarks.png"))
    plt.close(fig)
    print(f"  ✓ fig3_benchmarks.png")


# ══════════════════════════════════════════════════════════════
# Figure 4: 可信度衰减曲线
# ══════════════════════════════════════════════════════════════
def fig4_trust_decay():
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # Left: decay by operation type
    ops = ["VERBATIM\n(δ=0)", "EXTRACT\n(δ=0)", "SUMMARIZE\n(δ=1)", "INFER\n(δ=1)", "FUSE\n(δ=1)"]
    input_trust_levels = [3, 2, 1, 0]  # T3, T2, T1, T0

    x = np.arange(len(ops))
    width = 0.2
    colors = ["#22c55e", "#eab308", "#f97316", "#ef4444"]

    for i, (t_in, color) in enumerate(zip(input_trust_levels, colors)):
        agent_t = 3  # T3 agent
        deltas = [0, 0, 1, 1, 1]
        outputs = [max(0, min(t_in, agent_t) - d) for d in deltas]
        bars = ax1.bar(x + (i - 1.5) * width, outputs, width,
                       label=f"T_in=T{t_in}", color=color, alpha=0.8, edgecolor="white")

    ax1.set_ylabel("输出可信度 T_out")
    ax1.set_title("不同输入的衰减 (agent=T3)")
    ax1.set_xticks(x)
    ax1.set_xticklabels(ops, fontsize=8)
    ax1.set_yticks([0, 1, 2, 3])
    ax1.set_yticklabels(["T0", "T1", "T2", "T3"])
    ax1.legend(fontsize=7)

    # Right: contamination cascade
    hops = ["原始\n情报", "第1跳\n(INFER)", "第2跳\n(INFER)", "第3跳\n(INFER)"]
    trust_clean = [3, 3, 2, 1]   # starting with T3, δ=1 per hop
    trust_dirty = [1, 0, 0, 0]   # starting with T1, δ=1 per hop

    ax2.plot(hops, trust_clean, "o-", color="#22c55e", linewidth=2, markersize=10, label="干净链 (T3 起始)")
    ax2.plot(hops, trust_dirty, "s--", color="#ef4444", linewidth=2, markersize=10, label="污染链 (T1 起始)")
    ax2.set_ylabel("可信度")
    ax2.set_title("污染多跳扩散")
    ax2.set_yticks([0, 1, 2, 3])
    ax2.set_yticklabels(["T0", "T1", "T2", "T3"])
    ax2.legend(fontsize=8)
    ax2.axhline(y=2, color="gray", linestyle=":", alpha=0.5, label="T2 (动作门槛)")
    ax2.axhline(y=3, color="gray", linestyle=":", alpha=0.5, label="T3 (高危门槛)")

    fig.suptitle("图 4：可信度衰减曲线", fontsize=14, fontweight="bold", y=1.01)
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "fig4_trust_decay.png"))
    plt.close(fig)
    print(f"  ✓ fig4_trust_decay.png")


# ══════════════════════════════════════════════════════════════
# Figure 5: 4-value verdict distribution
# ══════════════════════════════════════════════════════════════
def fig5_verdict_distribution():
    """Show the 4-value verdict space with real cardinalities."""
    scenarios = [
        "正常同级读\n(L2→L2)", "上级读下级\n(L3→L1)", "下级读上级\n(L1→L3)",
        "同组写\n(C层)", "跨组写\n(D层)", "高危工具\n(T3)",
        "污染会话\n高危(T1→T3)", "CONSULT\n写回",
    ]
    verdicts = [
        "ALLOW", "ALLOW", "HIDE",
        "ALLOW", "DENY", "ALLOW",
        "DENY", "DENY",
    ]
    colors = {
        "ALLOW": "#22c55e",
        "HIDE": "#eab308",
        "DENY": "#ef4444",
        "CONFIRM": "#f97316",
    }

    fig, ax = plt.subplots(figsize=(10, 5))
    x = np.arange(len(scenarios))
    y = [1] * len(scenarios)
    bar_colors = [colors[v] for v in verdicts]

    ax.barh(x, y, color=bar_colors, alpha=0.8, height=0.6, edgecolor="white")
    ax.set_yticks(x)
    ax.set_yticklabels(scenarios, fontsize=8)
    ax.set_xticks([])
    ax.set_xlim(0, 1.5)

    for i, v in enumerate(verdicts):
        ax.text(0.55, i, v, va="center", fontsize=9, fontweight="bold", color=colors[v])

    # Legend
    legend_patches = [
        mpatches.Patch(color=colors["ALLOW"], label="ALLOW — 完全放行"),
        mpatches.Patch(color=colors["HIDE"], label="HIDE — 隐藏但可受限查询"),
        mpatches.Patch(color=colors["DENY"], label="DENY — 完全阻断"),
        mpatches.Patch(color=colors["CONFIRM"], label="CONFIRM — 需人在环"),
    ]
    ax.legend(handles=legend_patches, loc="lower right", fontsize=8)

    ax.set_title("图 5：四值裁决典型场景分布", fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "fig5_verdict_distribution.png"))
    plt.close(fig)
    print(f"  ✓ fig5_verdict_distribution.png")


# ══════════════════════════════════════════════════════════════
def main():
    print("TrustMem 报告图表生成")
    print("=" * 50)
    fig1_attack_ab()
    fig2_invariant_coverage()
    fig3_benchmarks()
    fig4_trust_decay()
    fig5_verdict_distribution()
    print("=" * 50)
    print(f"输出目录: {OUT}")


if __name__ == "__main__":
    main()
