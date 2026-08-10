"""LLM Backend abstract protocol and shared data types."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class LLMToolCall:
    id: str
    name: str
    arguments: dict


@dataclass
class LLMUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


@dataclass
class LLMResponse:
    content: str
    tool_calls: list[LLMToolCall] = field(default_factory=list)
    stop_reason: str = "end_turn"
    usage: LLMUsage | None = None
    raw: object = None


class LLMBackend(Protocol):
    """Pluggable LLM backend protocol.

    Implementations: ClaudeBackend, OpenAIBackend, OllamaBackend.
    The chat() signature mirrors the Anthropic Messages API.
    """

    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        system: str | None = None,
    ) -> LLMResponse:
        ...
