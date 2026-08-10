"""Claude API backend via the Anthropic Python SDK."""
from __future__ import annotations

import os

from .base import LLMBackend, LLMResponse, LLMToolCall, LLMUsage


class ClaudeBackend:
    """LLM backend backed by Anthropic Claude API."""

    def __init__(self, model: str = "claude-sonnet-4-6") -> None:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable not set")
        import anthropic
        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model

    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        system: str | None = None,
    ) -> LLMResponse:
        import anthropic

        kwargs: dict = {"model": self._model, "max_tokens": 4096, "messages": messages}
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = tools

        resp = self._client.messages.create(**kwargs)

        tool_calls: list[LLMToolCall] = []
        content_text = ""

        for block in resp.content:
            if block.type == "text":
                content_text += block.text
            elif block.type == "tool_use":
                tool_calls.append(LLMToolCall(
                    id=block.id,
                    name=block.name,
                    arguments=block.input if isinstance(block.input, dict) else {},
                ))

        usage = LLMUsage(
            input_tokens=resp.usage.input_tokens if resp.usage else 0,
            output_tokens=resp.usage.output_tokens if resp.usage else 0,
            cache_read_tokens=getattr(resp.usage, 'cache_read_input_tokens', 0) or 0,
            cache_write_tokens=getattr(resp.usage, 'cache_creation_input_tokens', 0) or 0,
        )

        return LLMResponse(
            content=content_text,
            tool_calls=tool_calls,
            stop_reason=resp.stop_reason or "end_turn",
            usage=usage,
            raw=resp,
        )
