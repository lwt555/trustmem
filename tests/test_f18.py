"""F-18 验收：13 类锚定事件 + 未映射裁决抛错 + 异步锚定 + 回放 + 后端互换。"""
from __future__ import annotations

import time

import pytest

from core.merkle import (DESIGN_EVENT_TYPES, EventType, MerkleStore,
                         _decision_to_event_type)
from core.pdp import Decision
from core.verdict import Verdict
from chain.anchor import AnchorQueue, on_anchor, on_decision
from chain.local_anchor import LocalAnchor
from chain.fisco_anchor import FiscoAnchor
from chain.replay import replay


def test_F18_thirteen_event_types_match_design():
    assert {e.value for e in EventType} == set(DESIGN_EVENT_TYPES)
    for must in ("TRUST_UPGRADE", "SIGNKEY_BIND", "MANIFEST_COMMIT", "DECLASSIFY"):
        assert must in {e.value for e in EventType}


def test_F18_unmapped_decision_raises():
    with pytest.raises(ValueError):
        _decision_to_event_type(Decision(Verdict.DENY, "UNKNOWN_ACTION", "a", "o", []))


class _SlowAnchor:
    def send(self, root, meta):
        time.sleep(2.0)
        from chain.anchor import AnchorReceipt
        return AnchorReceipt(tx_id="slow", verified=True, root=root, meta=meta)


def test_F18_anchor_does_not_block_decision():
    q = AnchorQueue(_SlowAnchor())
    t0 = time.perf_counter()
    on_anchor(q, b"\x00" * 32, {"session": "s"})
    elapsed = time.perf_counter() - t0
    assert elapsed < 0.05, "锚定不得阻塞裁决路径"


def test_F18_replay_detects_tampering(monkeypatch):
    monkeypatch.setenv("TRUSTMEM_ALLOW_TAMPER", "1")
    store = MerkleStore()
    from core.merkle import AuditEvent
    for i in range(3):
        store.log(AuditEvent(
            event_id=f"ev-{i}", event_type=EventType.READ_ALLOW,
            subject="a", object=f"chunk-{i}", session_id="sess-11",
            payload={"verdict": "ALLOW"},
        ))
    store.flush()

    assert replay("sess-11", store=store).verified is True
    store.tamper_event("ev-0", {"verdict": "DENY"})
    assert replay("sess-11", store=store).verified is False


def test_F18_backends_are_interchangeable(tmp_path):
    for backend in (LocalAnchor(path=str(tmp_path / "anchor_log.jsonl")),
                    FiscoAnchor(mock=True)):
        r = backend.send(b"\x00" * 32, {})
        assert r.verified and hasattr(r, "tx_id")
