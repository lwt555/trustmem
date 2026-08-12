"""
DB-backed persistence for TrustMem runtime state.

The in-memory SessionStore (core/session.py) is kept for hot-path speed --
PDP checks must be sub-ms. This module persists completed state so that
memories, sessions, audit events, and provenance links survive restarts.
"""
from __future__ import annotations

from datetime import datetime
from typing import Sequence

from sqlalchemy.orm import Session as SASession

from .database import get_db
from .models import MemoryChunk as MemoryChunkORM
from .models import SessionRecord as SessionRecordORM
from .models import ReadRecord as ReadRecordORM
from .models import AuditEvent as AuditEventORM
from .models import ProvenanceLink as ProvenanceLinkORM

from core.labels import (
    AgentLabel, MemoryLabel, Clearance, Trust, Layer, MemoryType,
    Role, WriteOp,
)
from core.session import Session, ReadRecord, SessionStore
from core.pdp import Decision, Check
from core.decay import DecayResult


# ──────────────────────────────────────────────────────────────
# Converters: dataclass <-> ORM
# ──────────────────────────────────────────────────────────────

def _memlabel_from_orm(row: MemoryChunkORM) -> MemoryLabel:
    return MemoryLabel(
        chunk_id=row.chunk_id,
        sensitivity=Clearance(row.sensitivity),
        provenance_trust=Trust(row.provenance_trust),
        layer=Layer(row.layer),
        memory_type=MemoryType(row.memory_type),
        owner_agent=row.owner_agent,
        task_binding=row.task_binding,
        collab_group=set(row.collab_group or []),
        provenance_chain=list(row.provenance_chain or []),
        lifecycle=row.lifecycle or "active",
        epoch=row.epoch or 1,
        declassified=bool(row.declassified),
        ttl_end=row.ttl_end,
    )


def _memlabel_to_orm(m: MemoryLabel) -> MemoryChunkORM:
    return MemoryChunkORM(
        chunk_id=m.chunk_id,
        sensitivity=int(m.sensitivity),
        provenance_trust=int(m.provenance_trust),
        layer=m.layer.value,
        memory_type=m.memory_type.value,
        owner_agent=m.owner_agent,
        task_binding=m.task_binding,
        collab_group=list(m.collab_group),
        provenance_chain=list(m.provenance_chain),
        lifecycle=m.lifecycle,
        epoch=m.epoch,
        declassified=m.declassified,
        ttl_end=m.ttl_end,
    )


def _session_to_orm(sess: Session) -> SessionRecordORM:
    return SessionRecordORM(
        session_id=sess.session_id,
        agent_id=sess.agent_id,
        task_id=sess.task_id,
        t_eff=int(sess.t_eff),
        t_intrinsic=int(sess.t_intrinsic),
        is_active=True,
        consulted=list(sess.consulted),
        hitl_confirmations=list(sess.hitl_confirmations),
    )


def _check_to_dict(c: Check) -> dict:
    return {"rule": c.rule, "passed": c.passed, "detail": c.detail}


# ──────────────────────────────────────────────────────────────
# Memory Store
# ──────────────────────────────────────────────────────────────

class MemoryStore:
    """Persistent storage for MemoryLabel records."""

    def __init__(self, db: SASession | None = None) -> None:
        self._db = db or get_db()

    def put(self, mem: MemoryLabel, ciphertext: bytes | None = None) -> MemoryChunkORM:
        row = self._db.query(MemoryChunkORM).filter_by(chunk_id=mem.chunk_id).first()
        if row:
            for attr in ("sensitivity", "provenance_trust", "layer", "memory_type",
                         "owner_agent", "task_binding", "collab_group",
                         "provenance_chain", "lifecycle", "epoch", "declassified",
                         "ttl_end"):
                setattr(row, attr, getattr(_memlabel_to_orm(mem), attr))
            if ciphertext is not None:
                row.content_encrypted = ciphertext.decode("utf-8")
        else:
            row = _memlabel_to_orm(mem)
            if ciphertext is not None:
                row.content_encrypted = ciphertext.decode("utf-8")
            self._db.add(row)
        self._db.commit()
        return row

    def get(self, chunk_id: str) -> MemoryLabel | None:
        row = self._db.query(MemoryChunkORM).filter_by(chunk_id=chunk_id).first()
        return _memlabel_from_orm(row) if row else None

    def get_ciphertext(self, chunk_id: str) -> bytes | None:
        row = self._db.query(MemoryChunkORM).filter_by(chunk_id=chunk_id).first()
        if row is None or not row.content_encrypted:
            return None
        return row.content_encrypted.encode("utf-8")

    def list_by_owner(self, agent_id: str) -> list[MemoryLabel]:
        rows = self._db.query(MemoryChunkORM).filter_by(owner_agent=agent_id).all()
        return [_memlabel_from_orm(r) for r in rows]

    def list_by_task(self, task_id: str) -> list[MemoryLabel]:
        rows = self._db.query(MemoryChunkORM).filter_by(task_binding=task_id).all()
        return [_memlabel_from_orm(r) for r in rows]

    def list_active(self) -> list[MemoryLabel]:
        rows = self._db.query(MemoryChunkORM).filter_by(lifecycle="active").all()
        return [_memlabel_from_orm(r) for r in rows]

    def set_lifecycle(self, chunk_id: str, state: str) -> bool:
        row = self._db.query(MemoryChunkORM).filter_by(chunk_id=chunk_id).first()
        if not row:
            return False
        row.lifecycle = state
        self._db.commit()
        return True

    def delete(self, chunk_id: str) -> bool:
        row = self._db.query(MemoryChunkORM).filter_by(chunk_id=chunk_id).first()
        if not row:
            return False
        self._db.delete(row)
        self._db.commit()
        return True

    def count(self) -> int:
        return self._db.query(MemoryChunkORM).count()


# ──────────────────────────────────────────────────────────────
# Session Persistence
# ──────────────────────────────────────────────────────────────

class SessionPersistence:
    """Persist completed session state to DB for audit/history."""

    def __init__(self, db: SASession | None = None) -> None:
        self._db = db or get_db()

    def save(self, sess: Session) -> SessionRecordORM:
        row = self._db.query(SessionRecordORM).filter_by(
            session_id=sess.session_id, agent_id=sess.agent_id).first()
        if row:
            row.t_eff = int(sess.t_eff)
            row.t_intrinsic = int(sess.t_intrinsic)
            row.consulted = list(sess.consulted)
            row.hitl_confirmations = list(sess.hitl_confirmations)
        else:
            row = _session_to_orm(sess)
            self._db.add(row)
        self._db.commit()
        return row

    def end_session(self, session_id: str) -> None:
        rows = self._db.query(SessionRecordORM).filter_by(session_id=session_id).all()
        for r in rows:
            r.is_active = False
        self._db.commit()

    def get_active(self, session_id: str) -> list[SessionRecordORM]:
        return self._db.query(SessionRecordORM).filter_by(
            session_id=session_id, is_active=True).all()


# ──────────────────────────────────────────────────────────────
# Read Record Store
# ──────────────────────────────────────────────────────────────

class ReadRecordStore:
    """Persist per-read LOMAC records."""

    def __init__(self, db: SASession | None = None) -> None:
        self._db = db or get_db()

    def record(self, session_id: str, agent_id: str, rec: ReadRecord) -> ReadRecordORM:
        row = ReadRecordORM(
            session_id=session_id,
            agent_id=agent_id,
            chunk_id=rec.chunk_id,
            trust=int(rec.trust),
            t_eff_before=int(rec.t_eff_before),
            t_eff_after=int(rec.t_eff_after),
            read_at=rec.at,
        )
        self._db.add(row)
        self._db.commit()
        return row

    def for_session(self, session_id: str) -> list[ReadRecordORM]:
        return self._db.query(ReadRecordORM).filter_by(session_id=session_id).all()

    def for_chunk(self, chunk_id: str, limit: int = 100) -> list[ReadRecordORM]:
        return self._db.query(ReadRecordORM).filter_by(
            chunk_id=chunk_id).order_by(ReadRecordORM.read_at.desc()).limit(limit).all()


# ──────────────────────────────────────────────────────────────
# Audit Store
# ──────────────────────────────────────────────────────────────

class AuditStore:
    """Persist PDP decisions as audit events for Merkle anchoring."""

    def __init__(self, db: SASession | None = None) -> None:
        self._db = db or get_db()

    def log(self, decision: Decision) -> AuditEventORM:
        row = AuditEventORM(
            event_type=decision.action,
            agent_id=decision.subject,
            chunk_id=decision.object if decision.action == "READ" else None,
            decision=("ALLOW" if decision.allowed
                      else decision.denied_by.upper() if decision.denied_by
                      else "DENY"),
            denied_by=decision.denied_by,
            side_effect=decision.side_effect,
            checks_detail=[_check_to_dict(c) for c in decision.checks],
            created_at=decision.at,
        )
        self._db.add(row)
        self._db.commit()
        return row

    def recent(self, limit: int = 100) -> list[AuditEventORM]:
        return self._db.query(AuditEventORM).order_by(
            AuditEventORM.created_at.desc()).limit(limit).all()

    def for_agent(self, agent_id: str, limit: int = 200) -> list[AuditEventORM]:
        return self._db.query(AuditEventORM).filter_by(agent_id=agent_id).order_by(
            AuditEventORM.created_at.desc()).limit(limit).all()

    def for_chunk(self, chunk_id: str) -> list[AuditEventORM]:
        return self._db.query(AuditEventORM).filter_by(chunk_id=chunk_id).order_by(
            AuditEventORM.created_at.desc()).all()


# ──────────────────────────────────────────────────────────────
# Provenance Store
# ──────────────────────────────────────────────────────────────

class ProvenanceStore:
    """Persist provenance edges: which memory cited which other memories."""

    def __init__(self, db: SASession | None = None) -> None:
        self._db = db or get_db()

    def link(self, source_chunk_id: str, target_chunk_id: str,
             decay: DecayResult) -> ProvenanceLinkORM:
        row = ProvenanceLinkORM(
            source_chunk_id=source_chunk_id,
            target_chunk_id=target_chunk_id,
            op=decay.op_claimed.value,
            op_effective=decay.op_effective.value,
            t_inputs=int(decay.t_inputs),
            t_agent=int(decay.t_agent),
            delta=decay.delta,
            trust_out=int(decay.trust_out),
        )
        self._db.add(row)
        self._db.commit()
        return row

    def chain_of(self, chunk_id: str) -> list[ProvenanceLinkORM]:
        """Return the provenance chain upstream of chunk_id."""
        return self._db.query(ProvenanceLinkORM).filter_by(
            source_chunk_id=chunk_id).all()

    def backtrace(self, chunk_id: str) -> list[str]:
        """BFS backtrace -- all chunks that this chunk's provenance transitively depends on."""
        visited: set[str] = set()
        frontier = [chunk_id]
        while frontier:
            cur = frontier.pop()
            if cur in visited:
                continue
            visited.add(cur)
            links = self._db.query(ProvenanceLinkORM).filter_by(
                source_chunk_id=cur).all()
            for link in links:
                if link.target_chunk_id not in visited:
                    frontier.append(link.target_chunk_id)
        visited.discard(chunk_id)
        return list(visited)


# ──────────────────────────────────────────────────────────────
# Unified persistence facade
# ──────────────────────────────────────────────────────────────

class TrustMemStore:
    """Single entry point for all persistence operations."""

    def __init__(self, db: SASession | None = None) -> None:
        self.db = db or get_db()
        self.memories = MemoryStore(self.db)
        self.sessions = SessionPersistence(self.db)
        self.reads = ReadRecordStore(self.db)
        self.audit = AuditStore(self.db)
        self.provenance = ProvenanceStore(self.db)

    def close(self) -> None:
        self.db.close()
