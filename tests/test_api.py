"""Integration tests for TrustMem REST + WebSocket API."""
from __future__ import annotations

import json
import pytest
from fastapi.testclient import TestClient

from backend.api.main import create_app
from backend.api.deps import (
    get_agents, get_session_store, get_var_store,
    get_merkle_audit, get_write_pipeline, get_read_pipeline,
)


@pytest.fixture
def client():
    app = create_app()
    return TestClient(app)


def _flush():
    get_merkle_audit().flush()


# ══════════════════════════════════════════════════════════════
# Health / Stats / Agents
# ══════════════════════════════════════════════════════════════

class TestHealthAndStats:
    def test_health(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_stats(self, client):
        r = client.get("/api/stats")
        assert r.status_code == 200
        data = r.json()
        assert "memories" in data
        assert "merkle_blocks" in data
        assert "var_handles" in data

    def test_list_agents(self, client):
        r = client.get("/api/agents")
        assert r.status_code == 200
        agents = r.json()
        assert len(agents) == 6
        agent_ids = {a["agent_id"] for a in agents}
        assert agent_ids == {"planner", "intel", "log", "analyst", "executor", "auditor"}
        # Verify agent structure
        a = agents[0]
        assert "role" in a
        assert "clearance" in a
        assert "trust" in a
        assert "tools" in a


# ══════════════════════════════════════════════════════════════
# Write
# ══════════════════════════════════════════════════════════════

class TestWriteEndpoint:
    def test_write_allow(self, client):
        r = client.post("/api/write", json={
            "agent_id": "analyst", "session_id": "sess-w1",
            "content": "Suspicious login from IP 10.0.0.5 detected",
            "sensitivity": "L2", "layer": "C", "memory_type": "INTEL",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["allowed"] is True
        assert data["chunk_id"].startswith("mem-")
        assert data["decision_verdict"] == "ALLOW"
        _flush()

    def test_write_deny_bad_agent(self, client):
        r = client.post("/api/write", json={
            "agent_id": "nonexistent", "session_id": "sess",
            "content": "test", "sensitivity": "L1", "layer": "C",
        })
        assert r.status_code == 200
        assert r.json()["denied_by"] == "UnknownAgent"

    def test_write_with_input_mems(self, client):
        """Write with provenance chain from existing memories."""
        # First write a memory
        r1 = client.post("/api/write", json={
            "agent_id": "analyst", "session_id": "sess-w3",
            "content": "Intel report: IOC match found",
            "sensitivity": "L2", "layer": "C", "memory_type": "INTEL",
        })
        cid = r1.json()["chunk_id"]

        # Now write a derived memory
        r2 = client.post("/api/write", json={
            "agent_id": "analyst", "session_id": "sess-w3",
            "content": "Analysis: IOC confirmed, recommend action",
            "sensitivity": "L2", "layer": "C", "memory_type": "EPISODIC",
            "input_chunk_ids": [cid], "op": "infer",
        })
        assert r2.status_code == 200
        assert r2.json()["allowed"] is True
        _flush()

    def test_write_declassify(self, client):
        """Write down with declassify should be allowed (with HITL)."""
        store = get_session_store()
        agents = get_agents()
        planner = agents["planner"]
        sess = store.get_or_start("sess-w4", planner, "unknown")
        sess.add_hitl("declassify:planner:L0")
        r = client.post("/api/write", json={
            "agent_id": "planner", "session_id": "sess-w4",
            "content": "Declassified summary for public",
            "sensitivity": "L0", "layer": "D", "memory_type": "EPISODIC",
            "declassify_approved": True, "op": "verbatim",
        })
        assert r.status_code == 200
        assert r.json()["allowed"] is True
        _flush()

    def test_write_schema_ok(self, client):
        r = client.post("/api/write", json={
            "agent_id": "analyst", "session_id": "sess-w5",
            "content": "Structured intel: {ip, hash, confidence}",
            "sensitivity": "L2", "layer": "C", "memory_type": "INTEL",
            "schema_ok": True,
        })
        assert r.status_code == 200
        _flush()


# ══════════════════════════════════════════════════════════════
# Read
# ══════════════════════════════════════════════════════════════

class TestReadEndpoint:
    def _write_and_flush(self, client, agent="analyst", sid="sess-r0",
                         content="Test memory", sens="L2"):
        r = client.post("/api/write", json={
            "agent_id": agent, "session_id": sid, "task_id": "INC-2026-0731",
            "content": content, "sensitivity": sens, "layer": "C",
            "memory_type": "INTEL",
        })
        _flush()
        return r.json()["chunk_id"]

    def test_read_allow(self, client):
        cid = self._write_and_flush(client)
        r = client.post("/api/read", json={
            "agent_id": "analyst", "session_id": "sess-r1", "chunk_id": cid,
        })
        assert r.status_code == 200
        data = r.json()
        assert data["allowed"] is True
        assert data["hidden"] is False
        assert data["decision_verdict"] == "ALLOW"

    def test_read_hide(self, client):
        """analyst reading L2 memory under c_ctx_max=L0 → TaskScope-C HIDE."""
        cid = self._write_and_flush(client)
        r = client.post("/api/read", json={
            "agent_id": "analyst", "session_id": "sess-r2", "chunk_id": cid,
            "scope_c_max": "L0",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["allowed"] is False
        assert data["hidden"] is True
        assert data["decision_verdict"] == "HIDE"
        assert data["var_handle"] is not None
        assert data["var_handle"]["var_id"].startswith("var-")

    def test_read_not_found(self, client):
        r = client.post("/api/read", json={
            "agent_id": "analyst", "session_id": "sess-r3",
            "chunk_id": "nonexistent",
        })
        assert r.status_code == 200
        assert r.json()["denied_by"] == "NotFound"

    def test_read_bad_agent(self, client):
        cid = self._write_and_flush(client)
        r = client.post("/api/read", json={
            "agent_id": "nonexistent", "session_id": "sess-r4",
            "chunk_id": cid,
        })
        assert r.status_code == 200
        assert r.json()["denied_by"] == "UnknownAgent"


# ══════════════════════════════════════════════════════════════
# Read Many
# ══════════════════════════════════════════════════════════════

class TestReadManyEndpoint:
    def test_read_many(self, client):
        # Write two memories
        ids = []
        for i in range(2):
            r = client.post("/api/write", json={
                "agent_id": "analyst", "session_id": f"sess-rm-{i}",
                "task_id": "INC-2026-0731",
                "content": f"Memory {i}", "sensitivity": "L2", "layer": "C",
                "memory_type": "INTEL",
            })
            ids.append(r.json()["chunk_id"])
        _flush()

        r = client.post("/api/read-many", json={
            "agent_id": "analyst", "session_id": "sess-rm-read",
            "chunk_ids": ids,
        })
        assert r.status_code == 200
        results = r.json()
        assert len(results) == 2
        for res in results:
            assert res["allowed"] is True


# ══════════════════════════════════════════════════════════════
# Audit
# ══════════════════════════════════════════════════════════════

class TestAuditEndpoints:
    def test_chain_verify(self, client):
        r = client.get("/api/audit/chain/verify")
        assert r.status_code == 200
        data = r.json()
        assert "valid" in data
        assert "chain_length" in data

    def test_session_replay(self, client):
        # Write and read to generate audit events
        w = client.post("/api/write", json={
            "agent_id": "analyst", "session_id": "sess-audit",
            "content": "Audit test memory", "sensitivity": "L2", "layer": "C",
            "memory_type": "INTEL",
        })
        _flush()
        cid = w.json()["chunk_id"]
        client.post("/api/read", json={
            "agent_id": "analyst", "session_id": "sess-audit",
            "chunk_id": cid,
        })
        _flush()

        r = client.get("/api/audit/session/sess-audit")
        assert r.status_code == 200
        data = r.json()
        assert data["session_id"] == "sess-audit"
        assert data["total_events"] >= 2

    def test_list_audit_events(self, client):
        r = client.get("/api/audit/events", params={"limit": 10})
        assert r.status_code == 200
        assert "events" in r.json()

    def test_flush_session(self, client):
        client.post("/api/write", json={
            "agent_id": "analyst", "session_id": "sess-flush",
            "content": "Flush test", "sensitivity": "L2", "layer": "C",
            "memory_type": "INTEL",
        })
        r = client.post("/api/session/flush")
        assert r.status_code == 200
        assert r.json()["flushed"] is True


# ══════════════════════════════════════════════════════════════
# Memories
# ══════════════════════════════════════════════════════════════

class TestMemoriesEndpoint:
    def test_list_memories(self, client):
        r = client.get("/api/memories")
        assert r.status_code == 200
        assert "memories" in r.json()

    def test_get_memory(self, client):
        w = client.post("/api/write", json={
            "agent_id": "analyst", "session_id": "sess-mem",
            "content": "Memory for get test", "sensitivity": "L2", "layer": "C",
            "memory_type": "INTEL",
        })
        _flush()
        cid = w.json()["chunk_id"]

        r = client.get(f"/api/memories/{cid}")
        assert r.status_code == 200
        data = r.json()
        assert data["chunk_id"] == cid

    def test_get_memory_not_found(self, client):
        r = client.get("/api/memories/nonexistent")
        assert r.status_code == 404


# ══════════════════════════════════════════════════════════════
# WebSocket
# ══════════════════════════════════════════════════════════════

class TestWebSocket:
    def test_ws_write_step(self, client):
        with client.websocket_connect("/ws/step") as ws:
            ws.send_json({
                "step_type": "write",
                "payload": {
                    "agent_id": "analyst", "session_id": "ws-test-1",
                    "content": "WS write test", "sensitivity": "L2",
                    "layer": "C", "memory_type": "INTEL",
                },
            })
            data = ws.receive_json()
            assert data["step_type"] == "write"
            assert data["allowed"] is True
            assert data["decision_verdict"] == "ALLOW"
            assert data["merkle_root"] is not None

    def test_ws_read_allow_step(self, client):
        # First write via REST
        w = client.post("/api/write", json={
            "agent_id": "analyst", "session_id": "ws-test-2",
            "task_id": "INC-2026-0731",
            "content": "WS read test memory", "sensitivity": "L2",
            "layer": "C", "memory_type": "INTEL",
        })
        _flush()
        cid = w.json()["chunk_id"]

        with client.websocket_connect("/ws/step") as ws:
            ws.send_json({
                "step_type": "read",
                "payload": {
                    "agent_id": "analyst", "session_id": "ws-test-2",
                    "chunk_id": cid,
                },
            })
            data = ws.receive_json()
            assert data["step_type"] == "read"
            assert data["allowed"] is True

    def test_ws_read_hide_step(self, client):
        """analyst reads L2 memory under c_ctx_max=L0 → TaskScope-C HIDE via WebSocket."""
        w = client.post("/api/write", json={
            "agent_id": "analyst", "session_id": "ws-test-3",
            "task_id": "INC-2026-0731",
            "content": "Secret intel for WS hide test", "sensitivity": "L2",
            "layer": "C", "memory_type": "INTEL",
        })
        _flush()
        cid = w.json()["chunk_id"]

        with client.websocket_connect("/ws/step") as ws:
            ws.send_json({
                "step_type": "read",
                "payload": {
                    "agent_id": "analyst", "session_id": "ws-test-hide",
                    "chunk_id": cid,
                    "scope_c_max": "L0", "scope_t_min": "T0",
                },
            })
            data = ws.receive_json()
            assert data["step_type"] == "read"
            assert data["allowed"] is False
            assert data["hidden"] is True
            assert data["var_handle"] is not None
            assert data["var_handle"]["var_id"].startswith("var-")
