"""Tests for LLM adapter layer — backends, cache, constrained adapter."""
import pytest
from unittest.mock import patch, MagicMock

from core.llm.base import LLMResponse, LLMToolCall, LLMUsage
from core.llm.stub import StubLLMBackend
from core.llm.cache import DemoCache
from core.llm.constrained import ConstrainedQueryAdapter
from core.varstore import VarStore, VarHandle
from core.isolated_llm import ControlFlowBudget


class TestStubLLMBackend:
    def test_chat_echoes_message(self):
        backend = StubLLMBackend()
        resp = backend.chat([{"role": "user", "content": "Hello"}])
        assert "Hello" in resp.content
        assert resp.stop_reason == "end_turn"
        assert resp.tool_calls == []

    def test_chat_empty_messages(self):
        backend = StubLLMBackend()
        resp = backend.chat([])
        assert resp.content is not None


class TestDemoCache:
    def test_cache_hit(self):
        stub = StubLLMBackend()
        cache = DemoCache(stub, ttl=3600)
        msgs = [{"role": "user", "content": "Test"}]

        r1 = cache.chat(msgs)
        r2 = cache.chat(msgs)
        assert r1.content == r2.content

    def test_cache_size(self):
        stub = StubLLMBackend()
        cache = DemoCache(stub, ttl=3600)
        cache.chat([{"role": "user", "content": "A"}])
        cache.chat([{"role": "user", "content": "B"}])
        assert cache.size == 2

    def test_cache_clear(self):
        stub = StubLLMBackend()
        cache = DemoCache(stub, ttl=3600)
        cache.chat([{"role": "user", "content": "A"}])
        cache.clear()
        assert cache.size == 0


class TestConstrainedQueryAdapter:
    @pytest.fixture
    def adapter(self):
        llm = StubLLMBackend()
        store = VarStore()
        store.store(VarHandle(
            var_id="test-var",
            chunk_id="mem-1",
            reason="BLP-SimpleSecurity",
            constraint_types=["bool", "enum", "number"],
            metadata={"sensitivity": "L2"},
        ))
        adapter = ConstrainedQueryAdapter(llm, store, ControlFlowBudget())
        return adapter, store

    def test_query_bool_allowed(self, adapter):
        a, _ = adapter
        result = a.query_bool("test-var", "does the content exist?")
        assert result.var_id == "test-var"

    def test_query_enum_allowed(self, adapter):
        a, _ = adapter
        result = a.query_enum("test-var", "what type?", ["A", "B", "C"])
        assert result.var_id == "test-var"

    def test_query_number_allowed(self, adapter):
        a, _ = adapter
        result = a.query_number("test-var", "how many?", 0, 100)
        assert result.var_id == "test-var"

    def test_unknown_var_raises(self, adapter):
        a, _ = adapter
        with pytest.raises(KeyError):
            a.query_bool("unknown-var", "?")

    def test_budget_exhaustion(self, adapter):
        a, _ = adapter
        for _ in range(4):
            a.query_bool("test-var", "q")
        assert a.budget.is_exhausted
