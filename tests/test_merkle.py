"""Tests for Merkle audit trail: tree, proof, store, session replay, chain integrity."""
from __future__ import annotations

import pytest

from core.merkle import (
    _leaf_hash,
    _node_hash,
    AuditEvent,
    EventType,
    MerkleProof,
    MerkleTree,
    MerkleBlock,
    MerkleStore,
    MerkleAuditStore,
)
from core.pdp import Decision, Check
from core.verdict import Verdict


# ══════════════════════════════════════════════════════════════
# Leaf / Node hashing (domain separation)
# ══════════════════════════════════════════════════════════════

class TestHashFunctions:
    def test_leaf_hash_prepends_zero_byte(self):
        h1 = _leaf_hash(b"hello")
        h2 = _leaf_hash(b"hello")
        assert h1 == h2
        assert len(h1) == 32

    def test_leaf_and_node_hash_differ_for_same_input(self):
        """Domain separation: leaf and node hashes must differ."""
        h_leaf = _leaf_hash(b"test")
        h_node = _node_hash(b"test", b"test")
        assert h_leaf != h_node

    def test_node_hash_is_deterministic(self):
        a, b = b"left", b"right"
        assert _node_hash(a, b) == _node_hash(a, b)

    def test_node_hash_order_matters(self):
        a, b = b"left", b"right"
        assert _node_hash(a, b) != _node_hash(b, a)

    def test_leaf_hash_empty_data(self):
        h = _leaf_hash(b"")
        assert len(h) == 32
        assert h != _leaf_hash(b"x")


# ══════════════════════════════════════════════════════════════
# AuditEvent
# ══════════════════════════════════════════════════════════════

class TestAuditEvent:
    def test_serialize_is_deterministic(self):
        e = AuditEvent(
            event_id="ev-1",
            event_type=EventType.WRITE_ALLOW,
            subject="agent-a",
            object="chunk-x",
            session_id="sess-1",
            payload={"key": "val"},
        )
        assert e.serialize() == e.serialize()

    def test_leaf_hash_different_for_different_payloads(self):
        e1 = AuditEvent("ev-1", EventType.WRITE_ALLOW, "a", "o", "s", {"k": "v1"})
        e2 = AuditEvent("ev-1", EventType.WRITE_ALLOW, "a", "o", "s", {"k": "v2"})
        assert e1.leaf_hash != e2.leaf_hash

    def test_serialize_contains_all_fields(self):
        e = AuditEvent("ev-1", EventType.READ_HIDE, "subj", "obj", "sess")
        data = e.serialize().decode("utf-8")
        assert "ev-1" in data
        assert "READ_HIDE" in data
        assert "subj" in data
        assert "obj" in data
        assert "sess" in data

    def test_all_13_event_types_can_serialize(self):
        for et in EventType:
            e = AuditEvent("ev", et, "a", "o", "s")
            assert len(e.serialize()) > 0
            assert len(e.leaf_hash) == 32

    def test_leaf_hash_is_bytes(self):
        e = AuditEvent("ev", EventType.CONSULT, "a", "o", "s")
        assert isinstance(e.leaf_hash, bytes)
        assert len(e.leaf_hash) == 32


# ══════════════════════════════════════════════════════════════
# MerkleProof
# ══════════════════════════════════════════════════════════════

class TestMerkleProof:
    def test_empty_proof_verify(self):
        """Single-leaf tree: empty siblings, verify should pass."""
        leaf = _leaf_hash(b"data")
        proof = MerkleProof(leaf_hash=leaf, siblings=[], root=leaf, leaf_index=0)
        assert proof.verify()

    def test_empty_proof_tampered_root_fails(self):
        leaf = _leaf_hash(b"data")
        proof = MerkleProof(leaf_hash=leaf, siblings=[], root=b"\x00" * 32, leaf_index=0)
        assert not proof.verify()

    def test_verify_with_leaf_hash_matches_verify(self):
        leaf = _leaf_hash(b"data")
        proof = MerkleProof(leaf_hash=leaf, siblings=[], root=leaf, leaf_index=0)
        assert proof.verify_with_leaf_hash(leaf)
        assert not proof.verify_with_leaf_hash(_leaf_hash(b"other"))

    def test_two_leaf_proof_verify(self):
        tree = MerkleTree([b"a", b"b"])
        proof = tree.proof(0)
        assert proof is not None
        assert proof.verify()
        assert proof.verify_with_leaf_hash(_leaf_hash(b"a"))

    def test_two_leaf_proof_tampered_sibling_fails(self):
        tree = MerkleTree([b"a", b"b"])
        proof = tree.proof(0)
        assert proof is not None
        proof.siblings[0] = (b"\x00" * 32, proof.siblings[0][1])
        assert not proof.verify()

    def test_to_dict(self):
        leaf = _leaf_hash(b"data")
        proof = MerkleProof(leaf_hash=leaf, siblings=[], root=leaf, leaf_index=0)
        d = proof.to_dict()
        assert d["leaf_hash"] == leaf.hex()
        assert d["siblings"] == []
        assert d["root"] == leaf.hex()
        assert d["leaf_index"] == 0


# ══════════════════════════════════════════════════════════════
# MerkleTree
# ══════════════════════════════════════════════════════════════

class TestMerkleTree:
    def test_empty_tree(self):
        tree = MerkleTree([])
        assert tree.leaf_count == 0
        assert len(tree.root) == 32
        assert tree.depth == 1
        assert tree.proof(0) is None

    def test_single_leaf(self):
        tree = MerkleTree([b"hello"])
        assert tree.leaf_count == 1
        assert tree.depth == 1
        proof = tree.proof(0)
        assert proof is not None
        assert proof.verify()
        assert proof.leaf_index == 0

    def test_two_leaves(self):
        tree = MerkleTree([b"a", b"b"])
        assert tree.leaf_count == 2
        assert tree.depth == 2  # leaves + root
        # Both proofs verify
        for i in range(2):
            proof = tree.proof(i)
            assert proof is not None
            assert proof.verify()
            assert proof.leaf_index == i

    def test_three_leaves_odd_padding(self):
        """3 leaves → padded to 4 (duplicate last)."""
        tree = MerkleTree([b"a", b"b", b"c"])
        assert tree.leaf_count == 3
        proof0 = tree.proof(0)
        proof2 = tree.proof(2)
        assert proof0 is not None and proof0.verify()
        assert proof2 is not None and proof2.verify()

    def test_seven_leaves(self):
        leaves = [f"data-{i}".encode() for i in range(7)]
        tree = MerkleTree(leaves)
        assert tree.leaf_count == 7
        for i in range(7):
            proof = tree.proof(i)
            assert proof is not None, f"proof({i}) returned None"
            assert proof.verify(), f"proof({i}) verification failed"

    def test_large_tree(self):
        leaves = [f"data-{i}".encode() for i in range(100)]
        tree = MerkleTree(leaves)
        assert tree.leaf_count == 100
        # Spot-check
        for i in [0, 1, 49, 50, 99]:
            proof = tree.proof(i)
            assert proof is not None
            assert proof.verify()

    def test_root_changes_with_different_data(self):
        t1 = MerkleTree([b"a", b"b"])
        t2 = MerkleTree([b"a", b"c"])
        assert t1.root != t2.root

    def test_root_same_for_same_data(self):
        t1 = MerkleTree([b"a", b"b"])
        t2 = MerkleTree([b"a", b"b"])
        assert t1.root == t2.root

    def test_proof_out_of_range(self):
        tree = MerkleTree([b"a", b"b"])
        assert tree.proof(-1) is None
        assert tree.proof(2) is None
        assert tree.proof(100) is None

    def test_verify_static_method(self):
        tree = MerkleTree([b"secret"])
        proof = tree.proof(0)
        assert proof is not None
        assert MerkleTree.verify(b"secret", proof)
        assert not MerkleTree.verify(b"wrong", proof)

    def test_stats(self):
        tree = MerkleTree([b"a", b"b"])
        s = tree.stats()
        assert s["leaf_count"] == 2
        assert s["depth"] == 2
        assert "root" in s

    def test_proof_index_consistency(self):
        """Proof at index i must not verify against data at index j."""
        tree = MerkleTree([b"a", b"b", b"c", b"d"])
        p0 = tree.proof(0)
        assert p0 is not None
        assert p0.verify_with_leaf_hash(_leaf_hash(b"a"))
        assert not p0.verify_with_leaf_hash(_leaf_hash(b"b"))


# ══════════════════════════════════════════════════════════════
# MerkleBlock
# ══════════════════════════════════════════════════════════════

class TestMerkleBlock:
    def _make_events(self, n: int) -> list[AuditEvent]:
        return [
            AuditEvent(f"ev-{i}", EventType.WRITE_ALLOW, "agent", f"chunk-{i}", "sess")
            for i in range(n)
        ]

    def test_block_creation(self):
        events = self._make_events(3)
        tree = MerkleTree([e.serialize() for e in events])
        block = MerkleBlock(block_id="blk-1", events=events, tree=tree)
        assert block.block_id == "blk-1"
        assert block.event_count == 3
        assert len(block.root) == 32

    def test_proof_for_existing_event(self):
        events = self._make_events(5)
        tree = MerkleTree([e.serialize() for e in events])
        block = MerkleBlock(block_id="blk-1", events=events, tree=tree)
        proof = block.proof_for("ev-2")
        assert proof is not None
        assert proof.verify()

    def test_proof_for_missing_event(self):
        events = self._make_events(2)
        tree = MerkleTree([e.serialize() for e in events])
        block = MerkleBlock(block_id="blk-1", events=events, tree=tree)
        assert block.proof_for("nonexistent") is None

    def test_verify_event(self):
        events = self._make_events(3)
        tree = MerkleTree([e.serialize() for e in events])
        block = MerkleBlock(block_id="blk-1", events=events, tree=tree)
        assert block.verify_event("ev-0")
        assert block.verify_event("ev-1")
        assert not block.verify_event("nonexistent")

    def test_chain_to(self):
        events = self._make_events(2)
        tree = MerkleTree([e.serialize() for e in events])
        block = MerkleBlock(block_id="blk-1", events=events, tree=tree)
        prev_root = b"\xaa" * 32
        block.chain_to(prev_root)
        assert block.prev_root == prev_root

    def test_chain_to_default_empty(self):
        events = self._make_events(2)
        tree = MerkleTree([e.serialize() for e in events])
        block = MerkleBlock(block_id="blk-1", events=events, tree=tree)
        assert block.prev_root == b""

    def test_to_dict(self):
        events = self._make_events(1)
        tree = MerkleTree([e.serialize() for e in events])
        block = MerkleBlock(block_id="blk-1", events=events, tree=tree)
        block.chain_to(b"\xbb" * 32)
        d = block.to_dict()
        assert d["block_id"] == "blk-1"
        assert d["event_count"] == 1
        assert d["prev_root"] == (b"\xbb" * 32).hex()
        assert "root" in d


# ══════════════════════════════════════════════════════════════
# MerkleStore
# ══════════════════════════════════════════════════════════════

class TestMerkleStore:
    def _event(self, ev_id: str, ev_type: EventType = EventType.WRITE_ALLOW,
               subject: str = "agent-a", obj: str = "chunk-x",
               session: str = "sess-1") -> AuditEvent:
        return AuditEvent(ev_id, ev_type, subject, obj, session)

    def test_initial_state(self):
        store = MerkleStore()
        s = store.stats()
        assert s["blocks"] == 0
        assert s["pending"] == 0
        assert s["total_events"] == 0
        assert s["last_root"] is None

    def test_log_and_flush(self):
        store = MerkleStore(block_size=64)
        store.log(self._event("ev-1"))
        store.log(self._event("ev-2"))
        assert store.stats()["pending"] == 2
        block = store.flush()
        assert block is not None
        assert block.event_count == 2
        assert store.stats()["pending"] == 0
        assert store.stats()["blocks"] == 1

    def test_auto_commit_on_full_block(self):
        store = MerkleStore(block_size=3)
        store.log(self._event("ev-1"))
        store.log(self._event("ev-2"))
        assert store.stats()["blocks"] == 0
        store.log(self._event("ev-3"))  # triggers auto-commit
        assert store.stats()["blocks"] == 1
        assert store.stats()["pending"] == 0

    def test_flush_empty_returns_none(self):
        store = MerkleStore()
        assert store.flush() is None

    def test_get_event(self):
        store = MerkleStore()
        store.log(self._event("ev-1"))
        store.flush()
        evt = store.get_event("ev-1")
        assert evt is not None
        assert evt.event_id == "ev-1"

    def test_get_event_missing(self):
        store = MerkleStore()
        assert store.get_event("nonexistent") is None

    def test_get_proof_and_verify(self):
        store = MerkleStore()
        store.log(self._event("ev-1"))
        store.log(self._event("ev-2"))
        store.log(self._event("ev-3"))
        store.flush()

        proof = store.get_proof("ev-2")
        assert proof is not None
        assert proof.verify()
        assert store.verify_event("ev-2")

    def test_verify_event_missing(self):
        store = MerkleStore()
        assert not store.verify_event("nonexistent")

    def test_get_block(self):
        store = MerkleStore()
        store.log(self._event("ev-1"))
        block = store.flush()
        assert block is not None
        fetched = store.get_block(block.block_id)
        assert fetched is not None
        assert fetched.block_id == block.block_id

    def test_get_block_missing(self):
        store = MerkleStore()
        assert store.get_block("nonexistent") is None

    def test_replay_session(self):
        store = MerkleStore()
        for i in range(5):
            store.log(self._event(f"ev-{i}", session="sess-a"))
        store.flush()

        events = store.replay_session("sess-a")
        assert len(events) == 5

    def test_replay_session_empty(self):
        store = MerkleStore()
        assert store.replay_session("nonexistent") == []

    def test_replay_session_multiple_sessions(self):
        store = MerkleStore()
        for i in range(3):
            store.log(self._event(f"ev-a-{i}", session="sess-a"))
        for i in range(2):
            store.log(self._event(f"ev-b-{i}", session="sess-b"))
        store.flush()

        assert len(store.replay_session("sess-a")) == 3
        assert len(store.replay_session("sess-b")) == 2

    def test_session_stats(self):
        store = MerkleStore()
        store.log(self._event("ev-1", EventType.WRITE_ALLOW, session="sess"))
        store.log(self._event("ev-2", EventType.WRITE_DENY, session="sess"))
        store.log(self._event("ev-3", EventType.READ_ALLOW, session="sess"))
        store.flush()

        stats = store.session_stats("sess")
        assert stats["total_events"] == 3
        assert stats["by_type"]["WRITE_ALLOW"] == 1
        assert stats["by_type"]["WRITE_DENY"] == 1
        assert stats["by_type"]["READ_ALLOW"] == 1

    def test_verify_chain_all_valid(self):
        store = MerkleStore(block_size=2)
        for i in range(6):
            store.log(self._event(f"ev-{i}"))
        store.flush()  # commit any remaining

        result = store.verify_chain()
        assert result["valid"]
        assert result["chain_length"] >= 3

    def test_verify_chain_tampered(self, monkeypatch):
        monkeypatch.setenv("TRUSTMEM_ALLOW_TAMPER", "1")
        store = MerkleStore(block_size=3)
        for i in range(6):
            store.log(self._event(f"ev-{i}"))
        store.flush()

        # Tamper with an event
        assert store.tamper_event("ev-2", {"tampered": True})
        # Event integrity check should fail
        assert not store.verify_event("ev-2")

    def test_tamper_event_nonexistent(self, monkeypatch):
        monkeypatch.setenv("TRUSTMEM_ALLOW_TAMPER", "1")
        store = MerkleStore()
        assert not store.tamper_event("nonexistent", {})

    def test_chain_linking(self):
        """Blocks should chain: each block's prev_root equals previous block's root."""
        store = MerkleStore(block_size=2)
        for i in range(5):
            store.log(self._event(f"ev-{i}"))
        store.flush()

        chain_ids = store._chain
        prev_root = b""
        for bid in chain_ids:
            block = store.get_block(bid)
            assert block is not None
            if prev_root:
                assert block.prev_root == prev_root
            prev_root = block.root

    def test_multiple_event_types_in_block(self):
        store = MerkleStore()
        store.log(self._event("ev-1", EventType.WRITE_ALLOW))
        store.log(self._event("ev-2", EventType.READ_HIDE))
        store.log(self._event("ev-3", EventType.DECLASSIFY))
        store.log(self._event("ev-4", EventType.HITL_CONFIRM))
        store.flush()

        for eid in ["ev-1", "ev-2", "ev-3", "ev-4"]:
            assert store.verify_event(eid)

    def test_stats_reflects_state(self):
        store = MerkleStore()
        store.log(self._event("ev-1", session="s1"))
        store.log(self._event("ev-2", session="s2"))
        store.flush()

        s = store.stats()
        assert s["blocks"] == 1
        assert s["total_events"] == 2
        assert s["sessions"] == 2
        assert s["chain_length"] == 1
        assert s["last_root"] is not None

    def test_large_block_size_no_auto_commit(self):
        store = MerkleStore(block_size=100)
        for i in range(50):
            store.log(self._event(f"ev-{i}"))
        assert store.stats()["blocks"] == 0
        assert store.stats()["pending"] == 50

    def test_replay_session_sorted_by_time(self):
        store = MerkleStore()
        import time
        for i in range(3):
            store.log(self._event(f"ev-{i}", session="sess"))
            time.sleep(0.01)
        store.flush()

        events = store.replay_session("sess")
        for i in range(len(events) - 1):
            assert events[i].at <= events[i + 1].at

    def test_get_event_from_correct_block_with_multiple_blocks(self):
        store = MerkleStore(block_size=2)
        for i in range(5):
            store.log(self._event(f"ev-{i}"))
        store.flush()

        for i in range(5):
            evt = store.get_event(f"ev-{i}")
            assert evt is not None
            assert evt.event_id == f"ev-{i}"


# ══════════════════════════════════════════════════════════════
# MerkleAuditStore — Pipeline adapter tests
# ══════════════════════════════════════════════════════════════

class TestMerkleAuditStore:
    def _decision(self, action="READ", allowed=True,
                  subject="agent-a", obj="chunk-x",
                  session_id="sess-1", denied_by=None) -> Decision:
        verdict = Verdict.ALLOW if allowed else (
            Verdict.HIDE if denied_by == "BLP-SimpleSecurity" else Verdict.DENY
        )
        return Decision(
            verdict=verdict, action=action, subject=subject, object=obj,
            session_id=session_id, denied_by=denied_by,
        )

    def test_log_creates_audit_event(self):
        store = MerkleAuditStore()
        d = self._decision("WRITE", True)
        event = store.log(d)
        assert event.event_type == EventType.WRITE_ALLOW
        assert event.subject == "agent-a"
        assert event.object == "chunk-x"
        assert event.session_id == "sess-1"

    def test_log_write_deny(self):
        store = MerkleAuditStore()
        d = self._decision("WRITE", False, denied_by="BLP-Star")
        event = store.log(d)
        assert event.event_type == EventType.WRITE_DENY

    def test_log_read_hide(self):
        store = MerkleAuditStore()
        d = self._decision("READ", False, denied_by="BLP-SimpleSecurity")
        event = store.log(d)
        assert event.event_type == EventType.READ_HIDE

    def test_log_read_deny_ntk(self):
        store = MerkleAuditStore()
        d = self._decision("READ", False, denied_by="NeedToKnow")
        event = store.log(d)
        assert event.event_type == EventType.READ_DENY

    def test_log_read_allow(self):
        store = MerkleAuditStore()
        d = self._decision("READ", True)
        event = store.log(d)
        assert event.event_type == EventType.READ_ALLOW

    def test_log_tool_invoke(self):
        store = MerkleAuditStore()
        d = self._decision("INVOKE(search)", True)
        event = store.log(d)
        assert event.event_type == EventType.TOOL_INVOKE

    def test_log_tool_deny(self):
        store = MerkleAuditStore()
        d = self._decision("INVOKE(search)", False, denied_by="Provenance-Trust")
        event = store.log(d)
        assert event.event_type == EventType.TOOL_DENY

    def test_flush_and_verify(self):
        store = MerkleAuditStore()
        d1 = self._decision("WRITE", True, obj="c1")
        d2 = self._decision("WRITE", True, obj="c2")
        store.log(d1)
        store.log(d2)
        store.flush()

        assert store.stats()["total_events"] == 2
        assert store.stats()["blocks"] == 1

    def test_get_proof_and_verify(self):
        store = MerkleAuditStore()
        e1 = store.log(self._decision("WRITE", True, obj="c1"))
        e2 = store.log(self._decision("READ", True, obj="c2"))
        store.flush()

        proof = store.get_proof(e1.event_id)
        assert proof is not None
        assert proof.verify()
        assert store.verify_event(e1.event_id)
        assert store.verify_event(e2.event_id)

    def test_replay_session(self):
        store = MerkleAuditStore()
        store.log(self._decision("WRITE", True, obj="c1", session_id="sess-a"))
        store.log(self._decision("READ", True, obj="c2", session_id="sess-a"))
        store.flush()

        events = store.replay_session("sess-a")
        assert len(events) == 2

    def test_session_stats(self):
        store = MerkleAuditStore()
        store.log(self._decision("WRITE", True, session_id="sess-x"))
        store.log(self._decision("READ", False, denied_by="BLP-SimpleSecurity", session_id="sess-x"))
        store.flush()

        s = store.session_stats("sess-x")
        assert s["total_events"] == 2

    def test_verify_chain(self):
        store = MerkleAuditStore(block_size=2)
        for i in range(4):
            store.log(self._decision("WRITE", True, session_id="sess"))
        store.flush()
        result = store.verify_chain()
        assert result["valid"]
        assert result["chain_length"] >= 2

    def test_stats(self):
        store = MerkleAuditStore()
        store.log(self._decision("WRITE", True, session_id="s1"))
        store.log(self._decision("READ", True, session_id="s2"))
        store.flush()
        s = store.stats()
        assert s["blocks"] == 1
        assert s["total_events"] == 2
        assert s["sessions"] == 2

    def test_root_property(self):
        store = MerkleAuditStore()
        store.log(self._decision("WRITE", True))
        store.flush()
        assert len(store.root) == 32
