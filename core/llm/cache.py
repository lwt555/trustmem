"""Demo-mode LLM response cache to reduce API costs during development."""
from __future__ import annotations

import hashlib
import json
import threading
import time

from .base import LLMBackend, LLMResponse


def _cache_key(messages: list[dict], tools: list[dict] | None,
               system: str | None) -> str:
    payload = json.dumps({"msgs": messages, "tools": tools, "sys": system},
                         sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode()).hexdigest()


class DemoCache:
    """TTL-based in-memory cache wrapping an LLMBackend.

    When TRUSTMEM_DEMO_MODE=1, this avoids repeated API calls for identical
    (messages, tools, system) tuples during demos.
    """

    def __init__(self, backend: LLMBackend, ttl: int = 3600) -> None:
        self._backend = backend
        self._ttl = ttl
        self._store: dict[str, tuple[float, LLMResponse]] = {}
        self._lock = threading.Lock()

    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        system: str | None = None,
    ) -> LLMResponse:
        key = _cache_key(messages, tools, system)
        now = time.monotonic()

        with self._lock:
            if key in self._store:
                expiry, resp = self._store[key]
                if now < expiry:
                    return resp
                del self._store[key]

        resp = self._backend.chat(messages, tools, system)

        with self._lock:
            self._store[key] = (now + self._ttl, resp)

        return resp

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._store)
