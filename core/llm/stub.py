"""Stub LLM backend — echoes input, for testing without API keys."""
from __future__ import annotations

from .base import LLMBackend, LLMResponse, LLMUsage


class StubLLMBackend:
    """Stub backend for dev/testing. Echoes the user message as output.

    Used when no API key is available. Produces deterministic responses
    so integration tests can run without external services.
    """

    def __init__(self) -> None:
        self._call_count = 0

    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        system: str | None = None,
    ) -> LLMResponse:
        self._call_count += 1
        last = messages[-1]["content"] if messages else ""
        return LLMResponse(
            content=f"[STUB] Echo: {last}",
            tool_calls=[],
            stop_reason="end_turn",
        )
