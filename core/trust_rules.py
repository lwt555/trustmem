"""可信流转规则注册表（TR1–TR16）。

F-15：TR1–TR16 规则表从代码反向生成。每条规则的实现处用
`@trust_rule` 装饰器登记「触发事件 / 变化方向 / 依据」；
`tools/gen_trust_rules.py` 扫描登记项生成 `docs/TRUST_RULES.md`，
并与手写文档对拍校验，保证文档与实现永远同步。

装饰器是透明的——不改变被装饰函数的任何行为，只登记元数据。
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TypeVar

F = TypeVar("F", bound=Callable)


@dataclass(frozen=True)
class TrustRule:
    """一条可信流转规则。code_location 指向实现处的 ``file:line``。"""
    rule_id: str
    group: str          # A/B/C/D
    trigger: str        # 触发事件
    change: str         # 变化方向
    basis: str          # 依据
    code_location: str  # file:line（相对仓库根）
    func: str           # 实现函数名（诊断用）

    @property
    def id(self) -> str:
        return self.rule_id


REGISTRY: dict[str, TrustRule] = {}


def trust_rule(rule_id: str, group: str, trigger: str, change: str,
               basis: str) -> Callable[[F], F]:
    """登记一条可信流转规则，返回原函数（不改行为）。"""
    if group not in ("A", "B", "C", "D"):
        raise ValueError(f"未知规则组: {group}")

    def deco(func: F) -> F:
        if rule_id in REGISTRY:
            raise ValueError(f"规则 {rule_id} 重复登记")
        REGISTRY[rule_id] = TrustRule(
            rule_id=rule_id,
            group=group,
            trigger=trigger,
            change=change,
            basis=basis,
            code_location=_locate(func),
            func=getattr(func, "__qualname__", str(func)),
        )
        return func
    return deco


def _locate(func: Callable) -> str:
    """返回实现处的 ``file:line``，路径相对仓库根。"""
    try:
        fname = func.__code__.co_filename
        lineno = func.__code__.co_firstlineno
    except AttributeError:
        return "?:?"
    p = Path(fname)
    try:
        rel = p.relative_to(Path.cwd())
    except ValueError:
        rel = p
    return f"{rel.as_posix()}:{lineno}"


def all_rules() -> list[TrustRule]:
    """按规则号排序返回全部已登记规则。"""
    return sorted(REGISTRY.values(), key=lambda r: r.rule_id)


def group_of(rule_id: str) -> str:
    """按编号推导所属组（TR1-5=A / TR6-10=B / TR11-14=C / TR15-16=D）。"""
    n = int(rule_id[2:])
    if n <= 5:
        return "A"
    if n <= 10:
        return "B"
    if n <= 14:
        return "C"
    return "D"


def parse_trust_rules(path: str) -> list[TrustRule]:
    """解析 docs/TRUST_RULES.md 的规则表，返回 TrustRule 列表。

    表格式（每行五列）：``| ID | 触发事件 | 变化 | 依据 | 代码位置 |``。
    """
    rules: list[TrustRule] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped.startswith("| TR"):
            continue
        cells = [c.strip() for c in stripped.strip("|").split("|")]
        if len(cells) != 5:
            continue
        rid, trigger, change, basis, loc = cells
        rules.append(TrustRule(
            rule_id=rid,
            group=group_of(rid),
            trigger=trigger,
            change=change,
            basis=basis,
            code_location=loc.strip("`"),
            func="",
        ))
    return rules


def count_lines(path: str) -> int:
    """返回文本文件行数（用于校验代码位置不越界）。"""
    return len(Path(path).read_text(encoding="utf-8").splitlines())
