"""LangGraph state definition for SOC orchestration."""
from __future__ import annotations

from typing import TypedDict, Annotated, Sequence


class SOCState(TypedDict, total=False):
    task: str
    context: list[dict]
    decisions: list[dict]
    current_agent: str
    planner_output: str
    intel_output: str
    log_output: str
    analyst_output: str
    executor_output: str
    auditor_output: str
    messages: list
    phase: str
    error: str
    done: bool
