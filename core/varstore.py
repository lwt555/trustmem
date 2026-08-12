"""
VarStore — #var# 句柄注册表。

当 PDP 返回 HIDE 裁决时，隐藏内容被分配一个 #var# 句柄。
Agent 可通过隔离 LLM 对 #var# 发起类型约束查询 (bool/enum/number)，
但不能读取原文。

受限展开（TR3/TR4）：`expand` 按受限类型的容量（bit）决定
BOUNDED（t_eff 降、t_eff_ctl 不变）还是 FULL（两者同降）。
"""
from __future__ import annotations

import math
import uuid
from dataclasses import dataclass, field
from typing import Literal

from .labels import Trust, Clearance
from .session import AbsorbMode
from .trust_rules import trust_rule

ConstraintType = Literal["bool", "enum", "number"]


# 受限类型的容量表（bit 为单位）。None 表示运行时计算。
VTYPE_CAPACITY_BITS: dict[str, float | None] = {
    "bool": 1.0,
    "enum": None,           # 运行时算：log2(len(options)) 向上取整
    "number": None,         # 运行时算：log2((max-min)/step + 1) 向上取整
    "short_string": 32.0,
    "string": float("inf"),
}

# 受限展开阈值（I11）：容量 ≤ 4 bit 走受限展开，超过则无界展开
BOUNDED_THRESHOLD_BITS = 4.0


def capacity_of(vtype: str, **kw) -> float:
    """计算某个受限类型的容量（bit）。"""
    base = VTYPE_CAPACITY_BITS.get(vtype)
    if base is not None:
        return base
    if vtype == "enum":
        n = max(1, len(kw.get("options", [])))
        return math.ceil(math.log2(n)) if n > 1 else 1.0
    if vtype == "number":
        min_val = kw.get("min_val", 0.0)
        max_val = kw.get("max_val", 100.0)
        step = kw.get("step", 1.0)
        n = max(1, int((max_val - min_val) / step) + 1)
        return math.ceil(math.log2(n)) if n > 1 else 1.0
    raise ValueError(f"未知受限类型: {vtype}")


@dataclass
class ExpandResult:
    """受限展开的结果：展开后水位的记录。"""
    var_id: str
    vtype: str
    bits: float
    mode: AbsorbMode
    budget_remaining: float


@dataclass
class VarHandle:
    """A #var# handle representing hidden memory content."""
    var_id: str
    chunk_id: str
    reason: str                           # which rule caused HIDE
    constraint_types: list[ConstraintType] = field(default_factory=lambda: ["bool", "enum", "number"])
    source_trust: Trust = Trust.T0_UNTRUSTED  # trust level of the hidden content
    sensitivity: Clearance = Clearance.L0_PUBLIC
    metadata: dict = field(default_factory=dict)

    @property
    def placeholder(self) -> str:
        """The placeholder text to show in context instead of content."""
        return f"#{self.var_id}#"

    def describe(self) -> str:
        """Human-readable description of the handle."""
        lines = [
            f"[HIDE] #{self.var_id}# 引用记忆 {self.chunk_id}",
            f"  原因: {self.reason}",
            f"  允许查询类型: {', '.join(self.constraint_types)}",
        ]
        if self.metadata:
            meta_str = ", ".join(f"{k}={v}" for k, v in self.metadata.items())
            lines.append(f"  元数据: {meta_str}")
        return "\n".join(lines)


class VarStore:
    """#var# 句柄注册表。存储所有被隐藏的记忆引用。"""

    def __init__(self, budget: object | None = None) -> None:
        self._by_var: dict[str, VarHandle] = {}
        self._by_chunk: dict[str, VarHandle] = {}

    @trust_rule("TR4", group="A",
                trigger="无界展开（string，或预算耗尽退化）",
                change="t_eff 与 t_eff_ctl 一起下降",
                basis="无界展开（数据流与控制流同时被污染）")
    @trust_rule("TR3", group="A",
                trigger="受限展开（bool/enum/number，容量 ≤ 4 bit 且预算充足）",
                change="t_eff 下降，t_eff_ctl 不变",
                basis="受限展开（隔离 LLM 的控制流水位不受影响）")
    def expand(self, var_id: str, vtype: str, *, sess,
               source_trust: Trust | None = None,
               sensitivity: Clearance | None = None,
               **kw) -> ExpandResult:
        """受限展开（TR3/TR4）。

        容量 ≤ 4 bit 且 Session 预算充足 → BOUNDED（t_eff 降，t_eff_ctl 不变）。
        否则 → FULL（两者同降）。预算耗尽后受限展开退化为无界（I11 后半句）。

        F-24：控制流预算只有一套，挂在 Session.capacity_used_bits 上；
        VarStore 不再维护独立预算。
        """
        handle = self._by_var.get(var_id)
        if handle is None:
            raise KeyError(f"Unknown var_id: {var_id}")
        bits = capacity_of(vtype, **kw)
        src_trust = source_trust if source_trust is not None else handle.source_trust
        sens = sensitivity if sensitivity is not None else handle.sensitivity

        if bits <= BOUNDED_THRESHOLD_BITS and sess.consume_bits(bits):
            mode = AbsorbMode.BOUNDED
        else:
            mode = AbsorbMode.FULL
        sess.absorb(handle.chunk_id, sens, src_trust, mode=mode)
        remaining = sess.CAPACITY_BUDGET_BITS - sess.capacity_used_bits
        return ExpandResult(var_id=var_id, vtype=vtype, bits=bits, mode=mode,
                            budget_remaining=remaining)

    def store(self, handle: VarHandle) -> None:
        self._by_var[handle.var_id] = handle
        self._by_chunk[handle.chunk_id] = handle

    def get(self, var_id: str) -> VarHandle | None:
        return self._by_var.get(var_id)

    def resolve(self, chunk_id: str) -> VarHandle | None:
        """Find the var handle for a given chunk_id."""
        return self._by_chunk.get(chunk_id)

    def list_all(self) -> list[VarHandle]:
        return list(self._by_var.values())

    def list_by_reason(self, reason: str) -> list[VarHandle]:
        return [h for h in self._by_var.values() if h.reason == reason]

    def remove(self, var_id: str) -> None:
        handle = self._by_var.pop(var_id, None)
        if handle:
            self._by_chunk.pop(handle.chunk_id, None)

    def clear(self) -> None:
        self._by_var.clear()
        self._by_chunk.clear()

    @staticmethod
    def new_id() -> str:
        return f"var-{uuid.uuid4().hex[:8]}"

    @property
    def count(self) -> int:
        return len(self._by_var)

    def stats(self) -> dict:
        reasons: dict[str, int] = {}
        for h in self._by_var.values():
            reasons[h.reason] = reasons.get(h.reason, 0) + 1
        return {"total": self.count, "by_reason": reasons}
