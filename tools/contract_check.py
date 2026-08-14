#!/usr/bin/env python
"""契约对账（F-25 / F-31），``make contract`` 的实现。

设计文档 §6.4 点了六层目录（ifc / pep / manifest / chain / bench / tools）+
密钥目录 keys/ 里各自该有的模块。本脚本把这些「契约要求」与仓库实际文件对拍，
生成 ``docs/contract_report.md``（全程唯一签名依据），并在 ``docs/BUILD_LOG.md``
追加一条生成记录（时间 + commit）。

关键：过期的契约报告比没有更危险（F-31）。所以：

    python tools/contract_check.py            # 重新生成契约报告
    python tools/contract_check.py --check    # 对拍：报告 commit ≠ HEAD 或缺失 → 非零

报告头部记录生成时的 HEAD commit；``--check`` 只比较这个 commit，不做内容级 diff。
"""
from __future__ import annotations

import argparse
import datetime
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

REPORT_PATH = ROOT / "docs" / "contract_report.md"
BUILD_LOG_PATH = ROOT / "docs" / "BUILD_LOG.md"

# ──────────────────────────────────────────────────────────────
# 契约：设计文档 §6.4 点名的模块（目录 → 该有的文件）
# ──────────────────────────────────────────────────────────────

REQUIRED: dict[str, tuple[str, ...]] = {
    "ifc":      ("crypto_client.py", "varstore.py", "quarantined.py", "writer_sign.py"),
    "pep":      ("pep.py", "memory_proxy.py", "tool_proxy.py", "hitl.py"),
    "manifest": ("schema.py", "compose.py", "capability_infer.py", "agents"),
    "chain":    ("local_anchor.py", "replay.py", "anchor_log.jsonl"),
    "bench":    ("benchmark.py", "report.py"),
    "tools":    ("contract_check.py", "regress.py", "gen_trust_rules.py"),
    "keys":     ("keyring.json",),
}

# 已知移位：契约里点名的文件，实际落在别处（对拍时标注「移位」而非「缺失」）。
KNOWN_RELOCATIONS: dict[str, str] = {
    "ifc/varstore.py":        "core/varstore.py",
    "pep/memory_proxy.py":    "core/agent/memory_proxy.py",
    "manifest/compose.py":    "manifest/schema.py（compose_capabilities / synthesize）",
    "chain/anchor_log.jsonl": "core/merkle.py（MerkleAuditStore 内实现锚定）",
}


def git_head() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(ROOT),
            capture_output=True, text=True, check=True,
        )
        return out.stdout.strip()
    except Exception:
        return "unknown"


def git_short() -> str:
    h = git_head()
    return h[:7] if len(h) >= 7 else h


def _reconfigure_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _check_module(directory: str, name: str) -> tuple[str, str]:
    """返回 (状态, 备注)。状态 ∈ {OK, MISSING, RELOCATED}。"""
    path = ROOT / directory / name
    if path.exists():
        return "OK", ""
    relocated = KNOWN_RELOCATIONS.get(f"{directory}/{name}")
    if relocated:
        return "RELOCATED", relocated
    return "MISSING", ""


def _collect() -> list[tuple[str, str, str, str]]:
    """(目录, 文件, 状态, 备注)。"""
    rows: list[tuple[str, str, str, str]] = []
    for directory, names in REQUIRED.items():
        for name in names:
            status, note = _check_module(directory, name)
            rows.append((directory, name, status, note))
    return rows


def _markdown_icon(status: str) -> str:
    return {"OK": "✅", "MISSING": "❌", "RELOCATED": "⚠️ 移位"}[status]


def render_report() -> str:
    rows = _collect()
    total = len(rows)
    ok = sum(1 for r in rows if r[2] == "OK")
    relocated = sum(1 for r in rows if r[2] == "RELOCATED")
    missing = sum(1 for r in rows if r[2] == "MISSING")

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = []
    lines.append("# TrustMem 契约对账报告")
    lines.append("")
    lines.append(f"生成 commit：`{git_head()}`")
    lines.append(f"生成时间：{now}")
    lines.append("")
    lines.append("> 本报告由 `tools/contract_check.py` 生成，是全程唯一签名依据。")
    lines.append("> 每次施工前运行 `make contract` 重新生成；过期报告比没有更危险。")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"## 汇总：{ok} 项就位 / {relocated} 项移位 / {missing} 项缺失（共 {total} 项）")
    lines.append("")
    lines.append("| 目录 | 契约要求 | 状态 | 备注 |")
    lines.append("|---|---|---|---|")
    for directory, name, status, note in rows:
        lines.append(f"| `{directory}/` | `{name}` | {_markdown_icon(status)} | {note or '—'} |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## 安全边界定位（设计文档第十部分第 8 条）")
    lines.append("")
    lines.append("抽取器的产出只能收紧、不能放宽：`manifest/schema.py:compose_capabilities`")
    lines.append("把抽取器（可被注入）声称需要的权限与人工维护的注册表取**交集**，交集之外")
    lines.append("一律拒。抽取器被注入的后果是任务做不成（fail-closed），不是权限被放大。")
    lines.append("")
    return "\n".join(lines)


def write_report() -> str:
    text = render_report()
    REPORT_PATH.write_text(text, encoding="utf-8")
    return text


def write_build_log() -> None:
    entry = f"- {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  commit `{git_head()}`  `make contract` 重新生成契约报告"
    if BUILD_LOG_PATH.exists():
        BUILD_LOG_PATH.write_text(
            BUILD_LOG_PATH.read_text(encoding="utf-8").rstrip() + "\n" + entry + "\n",
            encoding="utf-8",
        )
    else:
        BUILD_LOG_PATH.write_text(
            "# 施工日志（BUILD_LOG）\n\n" + entry + "\n", encoding="utf-8"
        )


def check() -> int:
    """对拍：报告头部 commit 是否等于 HEAD。过期或缺失 → 返回非零。"""
    if not REPORT_PATH.exists():
        print(f"[STALE] {REPORT_PATH} 不存在，请运行 `make contract` 生成")
        return 1
    text = REPORT_PATH.read_text(encoding="utf-8")
    head = git_head()
    for line in text.splitlines():
        if line.startswith("生成 commit："):
            recorded = line.split("`")[1] if "`" in line else ""
            if recorded == head:
                print(f"[OK] 契约报告与 HEAD（{head[:7]}）一致")
                return 0
            print(f"[STALE] 契约报告 commit {recorded[:7]} ≠ HEAD {head[:7]}，"
                  f"请运行 `make contract` 重新生成")
            return 1
    print("[STALE] 契约报告缺少「生成 commit」头部，请运行 `make contract` 重新生成")
    return 1


def main(argv: list[str] | None = None) -> int:
    _reconfigure_streams()
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="对拍校验，过期返回非零")
    args = ap.parse_args(argv)

    if args.check:
        return check()

    write_report()
    write_build_log()
    rows = _collect()
    ok = sum(1 for r in rows if r[2] == "OK")
    missing = sum(1 for r in rows if r[2] == "MISSING")
    print(f"[OK] 已生成 {REPORT_PATH}（{ok} 项就位 / {missing} 项缺失）")
    print(f"[OK] 已记录 {BUILD_LOG_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
