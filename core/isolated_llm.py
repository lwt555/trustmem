"""
隔离 LLM + 控制流预算。

对 #var# 句柄进行受限查询的接口：
- 无工具（不能写记忆、不能调 API、不能读文件）
- 约束解码（只输出 bool / enum / number）
- 每次查询消耗控制流预算（4 bit 封顶 = 最多 16 次查询）
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, Protocol

from .varstore import VarHandle, VarStore, ConstraintType


# ──────────────────────────────────────────────────────────────
# 控制流预算
# ──────────────────────────────────────────────────────────────


class ControlFlowBudget:
    """
    4-bit 控制流预算。

    攻击者对一次会话控制流的影响最多 4 bit（翻转 16 个二元决策）。
    每次受限查询消耗 1 bit（可配置为 0.5 bit 以区分 bool/enum/number）。
    """

    MAX_BITS = 4.0

    def __init__(self, max_bits: float = MAX_BITS) -> None:
        self.max_bits = max_bits
        self._remaining = max_bits
        self._query_count = 0
        self._exhausted = False

    @property
    def remaining(self) -> float:
        return self._remaining

    @property
    def query_count(self) -> int:
        return self._query_count

    @property
    def is_exhausted(self) -> bool:
        return self._exhausted

    def consume(self, cost: float = 1.0) -> bool:
        """尝试消耗预算。返回 True 如果还有足够预算。"""
        if self._exhausted:
            return False
        if self._remaining < cost:
            self._exhausted = True
            return False
        self._remaining -= cost
        self._query_count += 1
        if self._remaining <= 0:
            self._exhausted = True
        return True

    def reset(self) -> None:
        self._remaining = self.max_bits
        self._query_count = 0
        self._exhausted = False

    def stats(self) -> dict:
        return {
            "max_bits": self.max_bits,
            "remaining": self._remaining,
            "query_count": self._query_count,
            "exhausted": self._exhausted,
        }


# ──────────────────────────────────────────────────────────────
# 查询结果
# ──────────────────────────────────────────────────────────────


@dataclass
class ConstrainedAnswer:
    var_id: str
    question: str
    answer: str | bool | float | None
    answer_type: ConstraintType
    budget_consumed: float
    budget_remaining: float


# ──────────────────────────────────────────────────────────────
# 隔离 LLM 接口
# ──────────────────────────────────────────────────────────────


class IsolatedLLMProto(Protocol):
    """隔离 LLM 协议。生产实现替换为真正的 LLM + 约束解码。"""

    def query_bool(self, var_id: str, question: str) -> ConstrainedAnswer: ...
    def query_enum(self, var_id: str, question: str,
                   options: list[str]) -> ConstrainedAnswer: ...
    def query_number(self, var_id: str, question: str,
                     min_val: float = 0, max_val: float = 100) -> ConstrainedAnswer: ...


class StubIsolatedLLM:
    """
    Stub 隔离 LLM。用于测试 HIDE 路径和预算机制。

    存储实际内容（模拟 LLM 能访问原文），基于内容回答约束查询。
    在生产环境中替换为真实隔离 LLM 调用。
    """

    def __init__(self, var_store: VarStore | None = None,
                 budget: ControlFlowBudget | None = None) -> None:
        self.var_store = var_store or VarStore()
        self.budget = budget or ControlFlowBudget()
        self._content_store: dict[str, str] = {}          # var_id → content
        self._query_log: list[ConstrainedAnswer] = []

    def register_content(self, var_id: str, content: str) -> None:
        """注册 #var# 的实际内容（仅 stub 需要，生产环境由隔离 LLM 内部处理）。"""
        self._content_store[var_id] = content

    # ── 查询接口 ───────────────────────────────────────────────

    def query_bool(self, var_id: str, question: str) -> ConstrainedAnswer:
        result = self._query(var_id, question, "bool")
        if result.budget_consumed > 0:
            content = self._content_store.get(var_id, "")
            result.answer = self._answer_bool(question, content)
        self._query_log.append(result)
        return result

    def query_enum(self, var_id: str, question: str,
                   options: list[str]) -> ConstrainedAnswer:
        result = self._query(var_id, question, "enum")
        if result.budget_consumed > 0:
            content = self._content_store.get(var_id, "")
            result.answer = self._answer_enum(question, content, options)
        self._query_log.append(result)
        return result

    def query_number(self, var_id: str, question: str,
                     min_val: float = 0, max_val: float = 100) -> ConstrainedAnswer:
        result = self._query(var_id, question, "number")
        if result.budget_consumed > 0:
            content = self._content_store.get(var_id, "")
            result.answer = self._answer_number(question, content, min_val, max_val)
        self._query_log.append(result)
        return result

    # ── 内部方法 ────────────────────────────────────────────────

    def _query(self, var_id: str, question: str,
               answer_type: ConstraintType) -> ConstrainedAnswer:
        handle = self.var_store.get(var_id)
        if handle is None:
            raise KeyError(f"Unknown var_id: {var_id}")
        if answer_type not in handle.constraint_types:
            raise ValueError(
                f"Query type '{answer_type}' not allowed for #{var_id}. "
                f"Allowed: {handle.constraint_types}")

        ok = self.budget.consume(1.0)
        return ConstrainedAnswer(
            var_id=var_id,
            question=question,
            answer=None,
            answer_type=answer_type,
            budget_consumed=1.0 if ok else 0,
            budget_remaining=self.budget.remaining,
        )

    # Stub "LLM" 的简单关键词匹配（模拟约束解码）
    def _answer_bool(self, question: str, content: str) -> bool:
        q_lower = question.lower()
        c_lower = content.lower()
        # Common boolean patterns
        indicators_true = ["是", "yes", "true", "存在", "有", "包含", "contains",
                          "occur", "found", "detected", "elevated", "critical"]
        indicators_false = ["否", "no", "false", "不存在", "无", "不", "没有",
                           "none", "clear", "normal", "safe"]
        for w in indicators_true:
            if w in q_lower and w in c_lower:
                return True
        for w in indicators_false:
            if w in q_lower and w in c_lower:
                return False
        # Default: check if question keywords appear in content
        q_words = set(q_lower.split()) - {"is", "the", "are", "a", "an", "in", "of",
                                           "是否", "的", "了", "在", "有", "是"}
        return bool(q_words & set(c_lower.split()))

    def _answer_enum(self, question: str, content: str,
                     options: list[str]) -> str:
        """Pick the option that best matches the content."""
        c_lower = content.lower()
        best = options[0]
        best_score = -1
        for opt in options:
            score = c_lower.count(opt.lower())
            if score > best_score:
                best_score = score
                best = opt
        return best

    def _answer_number(self, question: str, content: str,
                       min_val: float, max_val: float) -> float:
        """Extract relevant number from content or return midpoint."""
        import re
        # Look for numbers in content
        numbers = re.findall(r'\d+\.?\d*', content)
        if numbers:
            vals = [float(n) for n in numbers]
            return max(min_val, min(max_val, vals[0]))
        return (min_val + max_val) / 2.0

    # ── 工具方法 ────────────────────────────────────────────────

    def reset_budget(self) -> None:
        self.budget.reset()

    def stats(self) -> dict:
        return {
            "budget": self.budget.stats(),
            "content_count": len(self._content_store),
            "query_log_size": len(self._query_log),
        }
