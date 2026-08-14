"""
Merkle 审计树 — SHA-256 二叉 Merkle 树 + 13 类事件存证 + 会话回放。

Leaf:   hash(0x00 || event_bytes)
Node:   hash(0x01 || left || right)

Proof: sibling hashes from leaf to root, plus direction (L/R).
Verify: recompute root from leaf + proof, compare to stored root.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .pdp import Decision


def _leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


# ──────────────────────────────────────────────────────────────
# 事件类型（13 类）
# ──────────────────────────────────────────────────────────────


# 设计文档 §3.7 点名的 13 类事件（权威清单）。EventType 必须与此完全一致。
DESIGN_EVENT_TYPES: tuple[str, ...] = (
    "READ_ALLOW",
    "READ_HIDE",
    "READ_DENY",
    "WRITE_ALLOW",
    "WRITE_DENY",
    "TOOL_INVOKE",
    "TOOL_DENY",
    "TRUST_UPGRADE",
    "DECLASSIFY",
    "HITL_CONFIRM",
    "SIGNKEY_BIND",
    "MANIFEST_COMMIT",
    "CONSULT",
)


class EventType(str, Enum):
    WRITE_ALLOW = "WRITE_ALLOW"
    WRITE_DENY = "WRITE_DENY"
    READ_ALLOW = "READ_ALLOW"
    READ_HIDE = "READ_HIDE"
    READ_DENY = "READ_DENY"
    TOOL_INVOKE = "TOOL_INVOKE"
    TOOL_DENY = "TOOL_DENY"
    HITL_CONFIRM = "HITL_CONFIRM"
    DECLASSIFY = "DECLASSIFY"
    CONSULT = "CONSULT"
    TRUST_UPGRADE = "TRUST_UPGRADE"
    MANIFEST_COMMIT = "MANIFEST_COMMIT"
    SIGNKEY_BIND = "SIGNKEY_BIND"


# ──────────────────────────────────────────────────────────────
# 审计事件
# ──────────────────────────────────────────────────────────────


@dataclass
class AuditEvent:
    event_id: str
    event_type: EventType
    subject: str          # agent_id
    object: str           # chunk_id or tool name
    session_id: str
    payload: dict = field(default_factory=dict)
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def serialize(self) -> bytes:
        obj = {
            "id": self.event_id,
            "type": self.event_type.value,
            "subject": self.subject,
            "object": self.object,
            "session": self.session_id,
            "payload": self.payload,
            "at": self.at.isoformat(),
        }
        return json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")

    @property
    def leaf_hash(self) -> bytes:
        return _leaf_hash(self.serialize())


# ──────────────────────────────────────────────────────────────
# Merkle Proof
# ──────────────────────────────────────────────────────────────


@dataclass
class MerkleProof:
    leaf_hash: bytes
    siblings: list[tuple[bytes, bool]]   # (hash, is_left)
    root: bytes
    leaf_index: int

    def verify(self) -> bool:
        """Recompute root from leaf and siblings."""
        current = self.leaf_hash
        for sibling_hash, sibling_is_left in self.siblings:
            if sibling_is_left:
                current = _node_hash(sibling_hash, current)  # hash(sibling || current)
            else:
                current = _node_hash(current, sibling_hash)  # hash(current || sibling)
        return current == self.root

    def to_dict(self) -> dict:
        return {
            "leaf_hash": self.leaf_hash.hex(),
            "siblings": [(h.hex(), side) for h, side in self.siblings],
            "root": self.root.hex(),
            "leaf_index": self.leaf_index,
        }


# ──────────────────────────────────────────────────────────────
# Merkle Tree
# ──────────────────────────────────────────────────────────────


class MerkleTree:
    """SHA-256 二叉 Merkle 树。"""

    def __init__(self, leaves: list[bytes]) -> None:
        self._leaf_hashes = [_leaf_hash(l) for l in leaves]
        self._nodes: list[list[bytes]] = []   # levels[0]=leaves, levels[-1]=[root]
        self._build()

    def _build(self) -> None:
        if not self._leaf_hashes:
            self.root = hashlib.sha256(b"empty").digest()
            self._nodes = [[self.root]]
            return

        level = list(self._leaf_hashes)
        self._nodes.append(level)

        while len(level) > 1:
            next_level = []
            # Pad with last element if odd
            if len(level) % 2 == 1:
                level = level + [level[-1]]
            for i in range(0, len(level), 2):
                next_level.append(_node_hash(level[i], level[i + 1]))
            self._nodes.append(next_level)
            level = next_level

        self.root = self._nodes[-1][0]

    @property
    def leaf_count(self) -> int:
        return len(self._leaf_hashes)

    @property
    def depth(self) -> int:
        return len(self._nodes)

    def proof(self, leaf_index: int) -> MerkleProof | None:
        """Generate Merkle proof for a leaf."""
        if leaf_index < 0 or leaf_index >= self.leaf_count:
            return None
        if self.leaf_count == 1:
            return MerkleProof(
                leaf_hash=self._leaf_hashes[leaf_index],
                siblings=[],
                root=self.root,
                leaf_index=leaf_index,
            )

        siblings: list[tuple[bytes, bool]] = []
        idx = leaf_index
        for level in self._nodes[:-1]:  # all levels except root
            if idx % 2 == 0:
                # Current is left child, sibling is right child → parent = hash(current || sibling)
                sibling_idx = idx + 1
                sibling_hash = level[sibling_idx] if sibling_idx < len(level) else level[idx]
                siblings.append((sibling_hash, False))  # sibling is right of parent
            else:
                # Current is right child, sibling is left child → parent = hash(sibling || current)
                siblings.append((level[idx - 1], True))  # sibling is left of parent
            idx //= 2

        return MerkleProof(
            leaf_hash=self._leaf_hashes[leaf_index],
            siblings=siblings,
            root=self.root,
            leaf_index=leaf_index,
        )

    @staticmethod
    def verify(leaf_data: bytes, proof: MerkleProof) -> bool:
        """Verify a leaf against a proof and root."""
        computed = _leaf_hash(leaf_data)
        return proof.verify_with_leaf_hash(computed)

    def stats(self) -> dict:
        return {
            "leaf_count": self.leaf_count,
            "depth": self.depth,
            "root": self.root.hex(),
        }


# Patch verify_with_leaf_hash onto MerkleProof
def _verify_with_leaf_hash(self: MerkleProof, leaf_hash: bytes) -> bool:
    current = leaf_hash
    for sibling_hash, sibling_is_left in self.siblings:
        if sibling_is_left:
            current = _node_hash(sibling_hash, current)  # hash(sibling || current)
        else:
            current = _node_hash(current, sibling_hash)  # hash(current || sibling)
    return current == self.root


MerkleProof.verify_with_leaf_hash = _verify_with_leaf_hash


# ──────────────────────────────────────────────────────────────
# Merkle Block (一组事件构成的树)
# ──────────────────────────────────────────────────────────────


@dataclass
class MerkleBlock:
    block_id: str
    events: list[AuditEvent]
    tree: MerkleTree
    prev_root: bytes = b""
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def root(self) -> bytes:
        return self.tree.root

    @property
    def event_count(self) -> int:
        return len(self.events)

    def proof_for(self, event_id: str) -> MerkleProof | None:
        for i, e in enumerate(self.events):
            if e.event_id == event_id:
                return self.tree.proof(i)
        return None

    def verify_event(self, event_id: str) -> bool:
        for i, e in enumerate(self.events):
            if e.event_id == event_id:
                proof = self.tree.proof(i)
                if proof is None:
                    return False
                return proof.verify_with_leaf_hash(e.leaf_hash)
        return False

    def chain_to(self, prev_root: bytes) -> None:
        """Link this block to the previous block's root."""
        self.prev_root = prev_root

    def to_dict(self) -> dict:
        return {
            "block_id": self.block_id,
            "root": self.root.hex(),
            "prev_root": self.prev_root.hex() if self.prev_root else None,
            "event_count": self.event_count,
            "at": self.at.isoformat(),
        }


# ──────────────────────────────────────────────────────────────
# MerkleStore（持久化审计存储）
# ──────────────────────────────────────────────────────────────


class MerkleStore:
    """
    Merkle 审计存储。

    每条裁决自动 commit 事件到 Merkle 树。块大小默认为 64 条事件。
    支持：commit、proof、verify、session replay、chain integrity check。
    """

    def __init__(self, block_size: int = 64) -> None:
        self.block_size = block_size
        self._blocks: dict[str, MerkleBlock] = {}
        self._event_index: dict[str, str] = {}       # event_id -> block_id
        self._pending: list[AuditEvent] = []
        self._session_index: dict[str, list[str]] = {}  # session_id -> [event_id, ...]
        self._chain: list[str] = []                   # block_ids in order
        self._last_root: bytes = b""

    # ── Commit ─────────────────────────────────────────────────

    def log(self, event: AuditEvent) -> None:
        """Log a single event. Auto-commits when block is full."""
        self._pending.append(event)
        if len(self._pending) >= self.block_size:
            self._commit_block()

    def flush(self) -> MerkleBlock | None:
        """Force commit current pending events."""
        if self._pending:
            return self._commit_block()
        return None

    def _commit_block(self) -> MerkleBlock:
        events = list(self._pending)
        self._pending.clear()

        leaves = [e.serialize() for e in events]
        tree = MerkleTree(leaves)

        block_id = f"blk-{uuid.uuid4().hex[:12]}"
        block = MerkleBlock(block_id=block_id, events=events, tree=tree)

        if self._last_root:
            block.chain_to(self._last_root)

        self._last_root = block.root
        self._chain.append(block_id)
        self._blocks[block_id] = block

        for e in events:
            self._event_index[e.event_id] = block_id
            self._session_index.setdefault(e.session_id, []).append(e.event_id)

        return block

    # ── Query ───────────────────────────────────────────────────

    def get_event(self, event_id: str) -> AuditEvent | None:
        block_id = self._event_index.get(event_id)
        if not block_id:
            return None
        block = self._blocks.get(block_id)
        if not block:
            return None
        for e in block.events:
            if e.event_id == event_id:
                return e
        return None

    def get_block(self, block_id: str) -> MerkleBlock | None:
        return self._blocks.get(block_id)

    def get_proof(self, event_id: str) -> MerkleProof | None:
        """Get Merkle proof for an event."""
        block_id = self._event_index.get(event_id)
        if not block_id:
            return None
        block = self._blocks.get(block_id)
        if not block:
            return None
        return block.proof_for(event_id)

    def verify_event(self, event_id: str) -> bool:
        """Verify an event against its block's Merkle root."""
        block_id = self._event_index.get(event_id)
        if not block_id:
            return False
        block = self._blocks.get(block_id)
        if not block:
            return False
        return block.verify_event(event_id)

    def events_by_type(self, event_type: EventType) -> list[AuditEvent]:
        """返回某类型的所有事件（含已提交块与待提交 pending）。"""
        out: list[AuditEvent] = []
        for block in self._blocks.values():
            for e in block.events:
                if e.event_type == event_type:
                    out.append(e)
        for e in self._pending:
            if e.event_type == event_type:
                out.append(e)
        return out

    # ── Session replay ──────────────────────────────────────────

    def replay_session(self, session_id: str, start: datetime | None = None,
                       end: datetime | None = None) -> list[AuditEvent]:
        """Reconstruct all events for a session, optionally filtered by time."""
        event_ids = self._session_index.get(session_id, [])
        events = []
        for eid in event_ids:
            evt = self.get_event(eid)
            if evt is None:
                continue
            if start and evt.at < start:
                continue
            if end and evt.at > end:
                continue
            events.append(evt)
        events.sort(key=lambda e: e.at)
        return events

    def session_stats(self, session_id: str) -> dict:
        """Summary statistics for a session."""
        events = self.replay_session(session_id)
        counts: dict[str, int] = {}
        for e in events:
            counts[e.event_type.value] = counts.get(e.event_type.value, 0) + 1
        return {
            "session_id": session_id,
            "total_events": len(events),
            "by_type": counts,
        }

    # ── Chain integrity ─────────────────────────────────────────

    def verify_chain(self) -> dict:
        """Verify the integrity of the entire block chain."""
        results = []
        prev = b""
        for bid in self._chain:
            block = self._blocks[bid]
            ok = True
            if prev and block.prev_root != prev:
                ok = False
            prev = block.root
            results.append({"block_id": bid, "root": block.root.hex(), "valid": ok})
        return {
            "valid": all(r["valid"] for r in results),
            "blocks": results,
            "chain_length": len(results),
        }

    # ── Tamper attempt (for testing) ────────────────────────────

    _TAMPER_GATE_ENV = "TRUSTMEM_ALLOW_TAMPER"

    def tamper_event(self, event_id: str, new_payload: dict) -> bool:
        """Modify an event's payload (simulates tampering). 仅测试用途（F-28）。

        生产接口上绝不允许改写已落链的事件——那是演示「改一行后 verify 失败」
        所需的越权入口。默认关闭：未设 ``TRUSTMEM_ALLOW_TAMPER=1`` 即抛错，
        每次调用强制打 WARNING 日志；API 层绝不暴露本方法。
        """
        if os.environ.get(self._TAMPER_GATE_ENV) != "1":
            logging.getLogger("trustmem.merkle").warning(
                "tamper_event(%s) 被调用但未开启 %s=1，拒绝执行（F-28 生产门禁）",
                event_id, self._TAMPER_GATE_ENV)
            raise RuntimeError(
                f"tamper_event 仅测试用途，需设 {self._TAMPER_GATE_ENV}=1（F-28）")

        block_id = self._event_index.get(event_id)
        if not block_id:
            return False
        block = self._blocks.get(block_id)
        if not block:
            return False
        for e in block.events:
            if e.event_id == event_id:
                e.payload = new_payload
                logging.getLogger("trustmem.merkle").warning(
                    "tamper_event(%s): 已篡改事件 payload（仅供演示链完整性被破坏）", event_id)
                return True
        return False

    # ── Stats ───────────────────────────────────────────────────

    def stats(self) -> dict:
        return {
            "blocks": len(self._blocks),
            "pending": len(self._pending),
            "total_events": len(self._event_index),
            "sessions": len(self._session_index),
            "chain_length": len(self._chain),
            "last_root": self._last_root.hex() if self._last_root else None,
        }


# ──────────────────────────────────────────────────────────────
# MerkleAuditStore — Pipeline adapter
# ──────────────────────────────────────────────────────────────

# Event type mapping: (action, is_allowed, denied_by) → EventType
# INVOKE actions are handled first in _decision_to_event_type, so tool-related
# denied_by values ("ProvenanceTrust", "ToolScope", "HumanInTheLoop") are
# not needed here.
_EVENT_MAP: dict[tuple[str, bool, str | None], EventType] = {
    # ── WRITE ──
    ("WRITE", True, None): EventType.WRITE_ALLOW,
    ("WRITE", False, "BLP-Star"): EventType.WRITE_DENY,
    ("WRITE", False, "Biba-Star"): EventType.WRITE_DENY,
    ("WRITE", False, "LayerWrite"): EventType.WRITE_DENY,
    ("WRITE", False, "Provenance-NoConsult"): EventType.WRITE_DENY,
    ("WRITE", False, "P-T-ControlFlow"): EventType.WRITE_DENY,
    ("WRITE", False, "NoWriteDown(BLP-Star)"): EventType.WRITE_DENY,
    ("WRITE", False, "NoWriteDown(C-Eff-WriteDown)"): EventType.WRITE_DENY,
    ("WRITE", False, "NoWriteDown(BLP-Star + C-Eff-WriteDown)"): EventType.WRITE_DENY,
    ("WRITE", False, "TaskScope-C"): EventType.WRITE_DENY,
    ("WRITE", False, "TaskScope-T"): EventType.WRITE_DENY,
    # ── READ ──
    ("READ", True, None): EventType.READ_ALLOW,
    ("READ", False, "BLP-SimpleSecurity"): EventType.READ_HIDE,
    ("READ", False, "TaskScope-C"): EventType.READ_HIDE,
    ("READ", False, "NeedToKnow"): EventType.READ_DENY,
    ("READ", False, "CognitiveLayer"): EventType.READ_DENY,
    ("READ", False, "TTL"): EventType.READ_DENY,
    ("READ", False, "Epoch"): EventType.READ_DENY,
    ("READ", False, "Lifecycle"): EventType.READ_DENY,
    ("READ", False, "TaskScope-T"): EventType.READ_DENY,
    ("READ", False, "NotFound"): EventType.READ_DENY,
}


def _decision_to_event_type(decision: Decision) -> EventType:
    """Map a PDP Decision to the most specific Merkle EventType.

    未映射的裁决直接抛错（F-18）：绝不允许静默回退成 CONSULT，
    否则审计链会把未知裁决记成"查阅"，证据链不可信。
    """
    from .verdict import Verdict
    if decision.action.startswith("INVOKE"):
        return EventType.TOOL_INVOKE if decision.allowed else EventType.TOOL_DENY
    key = (decision.action, decision.allowed, decision.denied_by)
    ev = _EVENT_MAP.get(key)
    if ev is None:
        raise ValueError(f"未映射的裁决类型: {key}，请补充 _EVENT_MAP")
    return ev


class MerkleAuditStore:
    """
    Pipeline-compatible audit store backed by a Merkle tree.

    Implements the AuditStoreProto interface (log) while committing
    every PDP decision into an immutable Merkle audit trail.
    """

    def __init__(self, block_size: int = 64) -> None:
        self._merkle = MerkleStore(block_size=block_size)

    def log(self, decision: Decision) -> AuditEvent:
        """Convert a PDP Decision to an AuditEvent and commit it."""
        event = AuditEvent(
            event_id=f"audit-{uuid.uuid4().hex[:12]}",
            event_type=_decision_to_event_type(decision),
            subject=decision.subject,
            object=decision.object,
            session_id=decision.session_id or "unknown",
            payload={
                "action": decision.action,
                "verdict": decision.verdict.value,
                "denied_by": decision.denied_by,
                "side_effect": decision.side_effect,
                "checks": [{"rule": c.rule, "passed": c.passed, "detail": c.detail}
                           for c in decision.checks],
            },
        )
        self._merkle.log(event)
        return event

    def flush(self) -> MerkleBlock | None:
        return self._merkle.flush()

    def get_event(self, event_id: str) -> AuditEvent | None:
        return self._merkle.get_event(event_id)

    def get_proof(self, event_id: str) -> MerkleProof | None:
        return self._merkle.get_proof(event_id)

    def verify_event(self, event_id: str) -> bool:
        return self._merkle.verify_event(event_id)

    def replay_session(self, session_id: str,
                       start: datetime | None = None,
                       end: datetime | None = None) -> list[AuditEvent]:
        return self._merkle.replay_session(session_id, start, end)

    def session_stats(self, session_id: str) -> dict:
        return self._merkle.session_stats(session_id)

    def verify_chain(self) -> dict:
        return self._merkle.verify_chain()

    def stats(self) -> dict:
        return self._merkle.stats()

    @property
    def root(self) -> bytes:
        return self._merkle._last_root
