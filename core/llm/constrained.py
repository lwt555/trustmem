"""ConstrainedQueryAdapter — wraps LLMBackend to satisfy IsolatedLLMProto.

For the HIDE verdict path: when memory is hidden behind a #var# handle,
the agent can ask constrained boolean/enum/number queries. The adapter
uses the real LLM with strict output constraints instead of keyword matching.
"""
from __future__ import annotations

from core.isolated_llm import (
    ConstrainedAnswer, ControlFlowBudget, IsolatedLLMProto,
)
from core.varstore import VarStore, ConstraintType
from .base import LLMBackend


_CONSTRAINT_PROMPTS: dict[ConstraintType, str] = {
    "bool": "Reply with ONLY the single word 'true' or 'false'. No other text.",
    "enum": "Reply with EXACTLY ONE of the allowed options. No other text.",
    "number": "Reply with ONLY a number. No other text.",
}


class ConstrainedQueryAdapter:
    """Adapts an LLMBackend to the IsolatedLLMProto for HIDE-path queries.

    Unlike StubIsolatedLLM (keyword-matching), this sends constrained prompts
    to a real LLM and parses the single-token response.
    """

    def __init__(self, llm: LLMBackend, var_store: VarStore,
                 budget: ControlFlowBudget | None = None) -> None:
        self._llm = llm
        self.var_store = var_store
        self.budget = budget or ControlFlowBudget()
        self._query_log: list[ConstrainedAnswer] = []

    def query_bool(self, var_id: str, question: str) -> ConstrainedAnswer:
        return self._query(var_id, question, "bool")

    def query_enum(self, var_id: str, question: str,
                   options: list[str]) -> ConstrainedAnswer:
        return self._query(var_id, question, "enum", options=options)

    def query_number(self, var_id: str, question: str,
                     min_val: float = 0, max_val: float = 100) -> ConstrainedAnswer:
        return self._query(var_id, question, "number",
                          min_val=min_val, max_val=max_val)

    def _query(self, var_id: str, question: str,
               answer_type: ConstraintType, **kwargs) -> ConstrainedAnswer:
        handle = self.var_store.get(var_id)
        if handle is None:
            raise KeyError(f"Unknown var_id: {var_id}")
        if answer_type not in handle.constraint_types:
            raise ValueError(
                f"Query type '{answer_type}' not allowed for #{var_id}. "
                f"Allowed: {handle.constraint_types}")

        ok = self.budget.consume(1.0)

        answer = None
        if ok:
            constraint = _CONSTRAINT_PROMPTS[answer_type]
            if answer_type == "enum":
                options = kwargs.get("options", [])
                constraint += f"\nAllowed options: {', '.join(options)}"
            elif answer_type == "number":
                constraint += (f"\nThe number must be between "
                             f"{kwargs.get('min_val', 0)} and "
                             f"{kwargs.get('max_val', 100)}.")

            prompt = (f"Context: A hidden memory chunk referenced as "
                     f"{handle.placeholder}.\n"
                     f"Question: {question}\n"
                     f"Constraint: {constraint}")

            try:
                resp = self._llm.chat(
                    messages=[{"role": "user", "content": prompt}],
                    system="You are a constrained query engine. Follow constraints exactly.",
                )
                answer = self._parse_answer(resp.content, answer_type, **kwargs)
            except Exception:
                answer = None

        result = ConstrainedAnswer(
            var_id=var_id, question=question, answer=answer,
            answer_type=answer_type,
            budget_consumed=1.0 if ok else 0,
            budget_remaining=self.budget.remaining,
        )
        self._query_log.append(result)
        return result

    def _parse_answer(self, raw: str, answer_type: ConstraintType,
                      **kwargs) -> bool | str | float | None:
        text = raw.strip().lower()
        if answer_type == "bool":
            if text in ("true", "yes", "是"):
                return True
            if text in ("false", "no", "否"):
                return False
            return "true" in text and "false" not in text
        elif answer_type == "enum":
            options = kwargs.get("options", [])
            for opt in options:
                if opt.lower() in text:
                    return opt
            return options[0] if options else text
        elif answer_type == "number":
            import re
            nums = re.findall(r'-?\d+\.?\d*', text)
            if nums:
                val = float(nums[0])
                lo = kwargs.get("min_val", 0)
                hi = kwargs.get("max_val", 100)
                return max(lo, min(hi, val))
            return None
        return None

    def reset_budget(self) -> None:
        self.budget.reset()

    def stats(self) -> dict:
        return {
            "budget": self.budget.stats(),
            "query_log_size": len(self._query_log),
        }
