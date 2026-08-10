"""OpenAI API backend — translates tool schemas from Anthropic format."""
from __future__ import annotations

import json
import os

from .base import LLMBackend, LLMResponse, LLMToolCall, LLMUsage


def _to_openai_tools(tools: list[dict] | None) -> list[dict] | None:
    if tools is None:
        return None
    converted = []
    for t in tools:
        converted.append({
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("input_schema", {}),
            },
        })
    return converted


def _from_openai_tool_calls(raw_calls) -> list[LLMToolCall]:
    out = []
    for tc in raw_calls or []:
        args = {}
        try:
            args = json.loads(tc.function.arguments)
        except (json.JSONDecodeError, AttributeError):
            pass
        out.append(LLMToolCall(id=tc.id, name=tc.function.name, arguments=args))
    return out


class OpenAIBackend:
    """LLM backend backed by OpenAI API (GPT-4o, etc.)."""

    def __init__(self, model: str = "gpt-4o") -> None:
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable not set")
        import openai
        self._client = openai.OpenAI(api_key=api_key)
        self._model = model

    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        system: str | None = None,
    ) -> LLMResponse:
        api_messages: list[dict] = []
        if system:
            api_messages.append({"role": "system", "content": system})
        for m in messages:
            role = m.get("role", "user")
            content = m.get("content", "")
            api_messages.append({"role": role, "content": str(content)})

        kwargs: dict = {"model": self._model, "messages": api_messages}
        oai_tools = _to_openai_tools(tools)
        if oai_tools:
            kwargs["tools"] = oai_tools

        resp = self._client.chat.completions.create(**kwargs)
        choice = resp.choices[0] if resp.choices else None
        if choice is None:
            return LLMResponse(content="", stop_reason="error")

        finish = choice.finish_reason or "stop"
        stop_map = {"stop": "end_turn", "tool_calls": "tool_use", "length": "max_tokens"}
        stop_reason = stop_map.get(finish, finish)

        usage = None
        if resp.usage:
            usage = LLMUsage(
                input_tokens=resp.usage.prompt_tokens or 0,
                output_tokens=resp.usage.completion_tokens or 0,
            )

        return LLMResponse(
            content=choice.message.content or "",
            tool_calls=_from_openai_tool_calls(choice.message.tool_calls),
            stop_reason=stop_reason,
            usage=usage,
            raw=resp,
        )
