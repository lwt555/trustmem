"""Ollama backend — local LLM via HTTP API."""
from __future__ import annotations

import json
import os

import httpx

from .base import LLMBackend, LLMResponse, LLMToolCall, LLMUsage

OLLAMA_BASE = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")


class OllamaBackend:
    """LLM backend backed by a local Ollama service."""

    def __init__(self, model: str = "llama3.2") -> None:
        self._model = model

    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        system: str | None = None,
    ) -> LLMResponse:
        ollama_msgs: list[dict] = []
        if system:
            ollama_msgs.append({"role": "system", "content": system})
        for m in messages:
            ollama_msgs.append({"role": m.get("role", "user"),
                               "content": str(m.get("content", ""))})

        body = {"model": self._model, "messages": ollama_msgs, "stream": False}
        if tools:
            body["tools"] = tools

        try:
            resp = httpx.post(f"{OLLAMA_BASE}/api/chat", json=body,
                            timeout=httpx.Timeout(120.0))
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as e:
            return LLMResponse(content=f"[Ollama error: {e}]", stop_reason="error")

        msg = data.get("message", {})
        content = msg.get("content", "")

        tool_calls: list[LLMToolCall] = []
        for tc in msg.get("tool_calls", []):
            fn = tc.get("function", {})
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            tool_calls.append(LLMToolCall(
                id=tc.get("id", ""),
                name=fn.get("name", ""),
                arguments=args,
            ))

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            stop_reason=data.get("done_reason", "stop"),
            usage=LLMUsage(
                input_tokens=data.get("prompt_eval_count", 0),
                output_tokens=data.get("eval_count", 0),
            ),
            raw=data,
        )
