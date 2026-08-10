"""
VarStore — #var# 句柄注册表。

当 PDP 返回 HIDE 裁决时，隐藏内容被分配一个 #var# 句柄。
Agent 可通过隔离 LLM 对 #var# 发起类型约束查询 (bool/enum/number)，
但不能读取原文。
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Literal

ConstraintType = Literal["bool", "enum", "number"]


@dataclass
class VarHandle:
    """A #var# handle representing hidden memory content."""
    var_id: str
    chunk_id: str
    reason: str                           # which rule caused HIDE
    constraint_types: list[ConstraintType] = field(default_factory=lambda: ["bool", "enum", "number"])
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

    def __init__(self) -> None:
        self._by_var: dict[str, VarHandle] = {}
        self._by_chunk: dict[str, VarHandle] = {}

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
