"""LLM backend factory — reads environment variables to pick the backend."""
from __future__ import annotations

import os

from .base import LLMBackend


def create_llm_backend() -> LLMBackend:
    """Create the LLM backend based on TRUSTMEM_LLM_BACKEND env var.

    TRUSTMEM_LLM_BACKEND:
        claude  (default) — Anthropic Claude API
        openai             — OpenAI API
        ollama             — Local Ollama

    TRUSTMEM_DEMO_MODE=1 wraps the backend in DemoCache.

    Stub mode: if no API key is found, falls back to a stub that echoes
    the user message, suitable for integration tests without API costs.
    """
    backend_name = os.environ.get("TRUSTMEM_LLM_BACKEND", "claude").lower()
    demo_mode = os.environ.get("TRUSTMEM_DEMO_MODE", "0") == "1"

    backend: LLMBackend

    try:
        if backend_name == "openai":
            from .openai import OpenAIBackend
            backend = OpenAIBackend()
        elif backend_name == "ollama":
            from .ollama import OllamaBackend
            backend = OllamaBackend()
        else:
            from .claude import ClaudeBackend
            backend = ClaudeBackend()
    except (ValueError, ImportError) as e:
        # No API key or SDK not installed — use stub for dev/testing
        from .stub import StubLLMBackend
        backend = StubLLMBackend()
        if "API_KEY" in str(e):
            import warnings
            warnings.warn(f"LLM backend unavailable ({e}), using StubLLMBackend")

    if demo_mode:
        from .cache import DemoCache
        backend = DemoCache(backend)  # type: ignore[arg-type]

    return backend
