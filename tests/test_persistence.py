"""Tests for backend/db persistence layer."""
from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, StaticPool
from sqlalchemy.orm import sessionmaker

from backend.db.models import (
    MemoryChunk as MemoryChunkORM,
    SessionRecord as SessionRecordORM,
    ReadRecord as ReadRecordORM,
    AuditEvent as AuditEventORM,
    ProvenanceLink as ProvenanceLinkORM,
    Base,
)
from backend.db.store import (
    MemoryStore, SessionPersistence, ReadRecordStore,
    AuditStore, ProvenanceStore, TrustMemStore,
    _memlabel_from_orm, _memlabel_to_orm,
)

from core.labels import (
    MemoryLabel, AgentLabel, Clearance, Trust, Layer, MemoryType,
    Role, WriteOp,
)
from core.session import Session, ReadRecord, AbsorbMode
from core.pdp import Decision, Check
from core.decay import compute_trust, DecayResult


@pytest.fixture
def db():
    """Each test gets a fresh in-memory SQLite database."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture
def mem_store(db):
    return MemoryStore(db)


@pytest.fixture
def sess_persist(db):
    return SessionPersistence(db)


@pytest.fixture
def read_store(db):
    return ReadRecordStore(db)


@pytest.fixture
def audit_store(db):
    return AuditStore(db)


@pytest.fixture
def prov_store(db):
    return ProvenanceStore(db)


# ──────────────────────────────────────────────────────────
# Converter roundtrip
# ──────────────────────────────────────────────────────────

def test_roundtrip_memorylabel_to_orm_and_back():
    ml = MemoryLabel(
        chunk_id="ch-001", sensitivity=Clearance.L2_SENSITIVE,
        provenance_trust=Trust.T1_LOW, layer=Layer.CONCLUSION,
        memory_type=MemoryType.INTEL, owner_agent="analyst-1",
        task_binding="task-42",
        collab_group={"group-a", "group-b"},
        provenance_chain=["ch-000", "ch-000a"],
        lifecycle="active", epoch=3, declassified=False,
        ttl_end=datetime.now(timezone.utc) + timedelta(days=7),
    )
    orm_row = _memlabel_to_orm(ml)
    ml2 = _memlabel_from_orm(orm_row)
    assert ml2.chunk_id == ml.chunk_id
    assert ml2.sensitivity == ml.sensitivity
    assert ml2.provenance_trust == ml.provenance_trust
    assert ml2.layer == ml.layer
    assert ml2.memory_type == ml.memory_type
    assert ml2.collab_group == ml.collab_group
    assert ml2.provenance_chain == ml.provenance_chain
    assert ml2.epoch == 3


# ──────────────────────────────────────────────────────────
# MemoryStore
# ──────────────────────────────────────────────────────────

def test_memory_put_and_get(mem_store):
    m = MemoryLabel(chunk_id="m1", sensitivity=Clearance.L1_INTERNAL,
                    provenance_trust=Trust.T2_MEDIUM, layer=Layer.DIRECTIVE,
                    memory_type=MemoryType.PROCEDURAL, owner_agent="a1",
                    task_binding="t1")
    mem_store.put(m)
    got = mem_store.get("m1")
    assert got is not None
    assert got.chunk_id == "m1"
    assert got.sensitivity == Clearance.L1_INTERNAL
    assert got.provenance_trust == Trust.T2_MEDIUM


def test_memory_put_update(mem_store):
    m = MemoryLabel(chunk_id="m1", sensitivity=Clearance.L1_INTERNAL,
                    provenance_trust=Trust.T2_MEDIUM, layer=Layer.DIRECTIVE,
                    memory_type=MemoryType.PROCEDURAL, owner_agent="a1",
                    task_binding="t1")
    mem_store.put(m)

    m.provenance_trust = Trust.T0_UNTRUSTED
    mem_store.put(m)

    got = mem_store.get("m1")
    assert got.provenance_trust == Trust.T0_UNTRUSTED


def test_memory_list_by_owner(mem_store):
    for i in range(3):
        m = MemoryLabel(chunk_id=f"m-{i}", sensitivity=Clearance.L0_PUBLIC,
                        provenance_trust=Trust.T3_HIGH, layer=Layer.REASONING,
                        memory_type=MemoryType.TRAJECTORY, owner_agent="alice",
                        task_binding="t1")
        mem_store.put(m)

    m2 = MemoryLabel(chunk_id="m-bob", sensitivity=Clearance.L0_PUBLIC,
                     provenance_trust=Trust.T3_HIGH, layer=Layer.REASONING,
                     memory_type=MemoryType.TRAJECTORY, owner_agent="bob",
                     task_binding="t1")
    mem_store.put(m2)

    assert len(mem_store.list_by_owner("alice")) == 3
    assert len(mem_store.list_by_owner("bob")) == 1
    assert len(mem_store.list_by_owner("nobody")) == 0


def test_memory_list_by_task(mem_store):
    for i in range(2):
        m = MemoryLabel(chunk_id=f"ma-{i}", sensitivity=Clearance.L0_PUBLIC,
                        provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                        memory_type=MemoryType.SEMANTIC, owner_agent="a1",
                        task_binding="task-A")
        mem_store.put(m)
    m = MemoryLabel(chunk_id="mb-0", sensitivity=Clearance.L0_PUBLIC,
                    provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                    memory_type=MemoryType.SEMANTIC, owner_agent="a1",
                    task_binding="task-B")
    mem_store.put(m)

    assert len(mem_store.list_by_task("task-A")) == 2
    assert len(mem_store.list_by_task("task-B")) == 1


def test_memory_list_active(mem_store):
    m1 = MemoryLabel(chunk_id="active-1", sensitivity=Clearance.L0_PUBLIC,
                     provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                     memory_type=MemoryType.SEMANTIC, owner_agent="a1",
                     task_binding="t1", lifecycle="active")
    m2 = MemoryLabel(chunk_id="archived-1", sensitivity=Clearance.L0_PUBLIC,
                     provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                     memory_type=MemoryType.SEMANTIC, owner_agent="a1",
                     task_binding="t1", lifecycle="archived")
    mem_store.put(m1)
    mem_store.put(m2)

    active = mem_store.list_active()
    assert len(active) == 1
    assert active[0].chunk_id == "active-1"


def test_memory_set_lifecycle(mem_store):
    m = MemoryLabel(chunk_id="m1", sensitivity=Clearance.L1_INTERNAL,
                    provenance_trust=Trust.T2_MEDIUM, layer=Layer.DIRECTIVE,
                    memory_type=MemoryType.PROCEDURAL, owner_agent="a1",
                    task_binding="t1")
    mem_store.put(m)
    assert mem_store.set_lifecycle("m1", "revoked")
    assert mem_store.get("m1").lifecycle == "revoked"
    assert not mem_store.set_lifecycle("nonexistent", "archived")


def test_memory_delete(mem_store):
    m = MemoryLabel(chunk_id="m1", sensitivity=Clearance.L0_PUBLIC,
                    provenance_trust=Trust.T2_MEDIUM, layer=Layer.DIRECTIVE,
                    memory_type=MemoryType.PROCEDURAL, owner_agent="a1",
                    task_binding="t1")
    mem_store.put(m)
    assert mem_store.count() == 1
    assert mem_store.delete("m1")
    assert mem_store.count() == 0
    assert mem_store.delete("m1") is False


def test_memory_count(mem_store):
    assert mem_store.count() == 0
    for i in range(5):
        m = MemoryLabel(chunk_id=f"mc-{i}", sensitivity=Clearance.L0_PUBLIC,
                        provenance_trust=Trust.T2_MEDIUM, layer=Layer.CONCLUSION,
                        memory_type=MemoryType.SEMANTIC, owner_agent="a1",
                        task_binding="t1")
        mem_store.put(m)
    assert mem_store.count() == 5


# ──────────────────────────────────────────────────────────
# SessionPersistence
# ──────────────────────────────────────────────────────────

def test_session_save_and_retrieve(sess_persist):
    sess = Session(session_id="s1", agent_id="a1", task_id="t1",
                   t_eff=Trust.T2_MEDIUM, t_intrinsic=Trust.T3_HIGH,
                   consulted={"ch-1", "ch-2"},
                   hitl_confirmations={"cmd-1"})

    sess_persist.save(sess)
    active = sess_persist.get_active("s1")
    assert len(active) == 1
    assert active[0].agent_id == "a1"
    assert active[0].t_eff == 2
    assert active[0].t_intrinsic == 3
    assert "ch-1" in active[0].consulted

    # Update same session
    sess.t_eff = Trust.T1_LOW
    sess_persist.save(sess)
    active = sess_persist.get_active("s1")
    assert len(active) == 1  # still 1, updated in place
    assert active[0].t_eff == 1


def test_session_end(sess_persist):
    sess = Session(session_id="s1", agent_id="a1", task_id="t1",
                   t_eff=Trust.T2_MEDIUM, t_intrinsic=Trust.T3_HIGH)
    sess_persist.save(sess)
    sess_persist.end_session("s1")
    assert len(sess_persist.get_active("s1")) == 0


# ──────────────────────────────────────────────────────────
# ReadRecordStore
# ──────────────────────────────────────────────────────────

def test_read_record_persist(read_store):
    rec = ReadRecord(chunk_id="ch-1", trust=Trust.T1_LOW,
                     sensitivity=Clearance.L0_PUBLIC, mode=AbsorbMode.FULL,
                     t_eff_before=Trust.T3_HIGH, t_eff_after=Trust.T1_LOW)
    read_store.record("s1", "a1", rec)

    records = read_store.for_session("s1")
    assert len(records) == 1
    assert records[0].chunk_id == "ch-1"
    assert records[0].t_eff_before == 3
    assert records[0].t_eff_after == 1


def test_read_record_for_chunk(read_store):
    for i in range(5):
        rec = ReadRecord(chunk_id="ch-X", trust=Trust.T2_MEDIUM,
                         sensitivity=Clearance.L0_PUBLIC, mode=AbsorbMode.FULL,
                         t_eff_before=Trust.T3_HIGH, t_eff_after=Trust.T2_MEDIUM)
        read_store.record(f"s{i}", "a1", rec)

    rec = ReadRecord(chunk_id="ch-Y", trust=Trust.T1_LOW,
                     sensitivity=Clearance.L0_PUBLIC, mode=AbsorbMode.FULL,
                     t_eff_before=Trust.T2_MEDIUM, t_eff_after=Trust.T1_LOW)
    read_store.record("s-other", "a1", rec)

    chunk_x = read_store.for_chunk("ch-X", limit=10)
    assert len(chunk_x) == 5
    chunk_y = read_store.for_chunk("ch-Y", limit=10)
    assert len(chunk_y) == 1


# ──────────────────────────────────────────────────────────
# AuditStore
# ──────────────────────────────────────────────────────────

def test_audit_log_and_query(audit_store):
    ck = [Check("BLP-SimpleSecurity", True, "ok"), Check("NeedToKnow", False, "domain mismatch")]
    d = Decision(False, "READ", "agent-a", "ch-1", ck,
                 denied_by="NeedToKnow", side_effect="blocked")

    audit_store.log(d)
    recent = audit_store.recent(10)
    assert len(recent) == 1
    assert recent[0].event_type == "READ"
    assert recent[0].agent_id == "agent-a"
    assert recent[0].decision == "NEEDTOKNOW"
    assert recent[0].denied_by == "NeedToKnow"
    assert len(recent[0].checks_detail) == 2


def test_audit_for_agent(audit_store):
    for i in range(3):
        ck = [Check("test", True, "ok")]
        d = Decision(True, "READ", "alice", "ch-1", ck)
        audit_store.log(d)
    ck = [Check("test", True, "ok")]
    d = Decision(True, "WRITE", "bob", "ch-2", ck)
    audit_store.log(d)

    assert len(audit_store.for_agent("alice")) == 3
    assert len(audit_store.for_agent("bob")) == 1


def test_audit_for_chunk(audit_store):
    ck = [Check("test", True, "ok")]
    audit_store.log(Decision(True, "READ", "a1", "ch-A", ck))
    audit_store.log(Decision(True, "READ", "a2", "ch-A", ck))
    audit_store.log(Decision(True, "READ", "a1", "ch-B", ck))

    assert len(audit_store.for_chunk("ch-A")) == 2
    assert len(audit_store.for_chunk("ch-B")) == 1
    assert len(audit_store.for_chunk("ch-None")) == 0


# ──────────────────────────────────────────────────────────
# ProvenanceStore
# ──────────────────────────────────────────────────────────

def test_provenance_link_and_chain(prov_store):
    input_mems = [
        MemoryLabel(chunk_id="src1", sensitivity=Clearance.L0_PUBLIC,
                    provenance_trust=Trust.T2_MEDIUM, layer=Layer.CONCLUSION,
                    memory_type=MemoryType.INTEL, owner_agent="a1",
                    task_binding="t1"),
        MemoryLabel(chunk_id="src2", sensitivity=Clearance.L0_PUBLIC,
                    provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                    memory_type=MemoryType.INTEL, owner_agent="a1",
                    task_binding="t1"),
    ]
    decay = compute_trust(input_mems, Trust.T3_HIGH, WriteOp.SUMMARIZE)
    prov_store.link("out-1", "src1", decay)
    prov_store.link("out-1", "src2", decay)

    chain = prov_store.chain_of("out-1")
    assert len(chain) == 2
    assert {l.target_chunk_id for l in chain} == {"src1", "src2"}


def test_provenance_backtrace(prov_store):
    # Build a small DAG: out <- mid1 <- src1
    #                       out <- mid2 <- src2
    input_mems = [MemoryLabel(chunk_id="any", sensitivity=Clearance.L0_PUBLIC,
                               provenance_trust=Trust.T2_MEDIUM, layer=Layer.CONCLUSION,
                               memory_type=MemoryType.INTEL, owner_agent="a1",
                               task_binding="t1")]
    decay = compute_trust(input_mems, Trust.T3_HIGH, WriteOp.VERBATIM)
    prov_store.link("mid1", "src1", decay)
    prov_store.link("mid2", "src2", decay)
    prov_store.link("out", "mid1", decay)
    prov_store.link("out", "mid2", decay)

    bt = prov_store.backtrace("out")
    assert set(bt) == {"mid1", "mid2", "src1", "src2"}


def test_provenance_link_metadata(prov_store):
    input_mems = [
        MemoryLabel(chunk_id="in1", sensitivity=Clearance.L0_PUBLIC,
                    provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                    memory_type=MemoryType.INTEL, owner_agent="a1",
                    task_binding="t1"),
        MemoryLabel(chunk_id="in2", sensitivity=Clearance.L0_PUBLIC,
                    provenance_trust=Trust.T1_LOW, layer=Layer.CONCLUSION,
                    memory_type=MemoryType.INTEL, owner_agent="a1",
                    task_binding="t1"),
    ]
    decay = compute_trust(input_mems, Trust.T3_HIGH, WriteOp.FUSE)
    row = prov_store.link("out", "in1", decay)
    assert row.t_inputs == 1  # min(T3, T1) = T1
    assert row.t_agent == 3
    assert row.delta == 1
    assert row.trust_out == 0  # min(1,3) - 1 = 0
    assert row.op == "fuse"


# ──────────────────────────────────────────────────────────
# Session + Audit integration
# ──────────────────────────────────────────────────────────

def test_session_and_audit_integration(sess_persist, audit_store, read_store):
    """End-to-end: start session -> read (LOMAC drop) -> audit log -> persist."""
    sess = Session(session_id="int-s1", agent_id="analyst-1", task_id="t1",
                   t_eff=Trust.T3_HIGH, t_intrinsic=Trust.T3_HIGH)
    sess_persist.save(sess)

    # Simulate LOMAC absorption
    rec = sess.absorb("ch-low", Clearance.L0_PUBLIC, Trust.T1_LOW)
    read_store.record("int-s1", "analyst-1", rec)

    assert rec.t_eff_before == Trust.T3_HIGH
    assert rec.t_eff_after == Trust.T1_LOW

    # Session reflects the drop
    assert sess.t_eff == Trust.T1_LOW
    sess_persist.save(sess)

    active = sess_persist.get_active("int-s1")
    assert active[0].t_eff == 1

    # Audit log
    ck = [Check("BLP-SimpleSecurity", True, "ok")]
    d = Decision(True, "READ", "analyst-1", "ch-low", ck,
                 side_effect=f"T_eff drop 3->1")
    audit_store.log(d)

    assert len(audit_store.for_agent("analyst-1")) == 1
    assert len(read_store.for_session("int-s1")) == 1


# ──────────────────────────────────────────────────────────
# TrustMemStore facade
# ──────────────────────────────────────────────────────────

def test_unified_store_facade(db):
    store = TrustMemStore(db)
    m = MemoryLabel(chunk_id="facade-1", sensitivity=Clearance.L2_SENSITIVE,
                    provenance_trust=Trust.T3_HIGH, layer=Layer.DIRECTIVE,
                    memory_type=MemoryType.SEMANTIC, owner_agent="a1",
                    task_binding="t1")
    store.memories.put(m)
    assert store.memories.count() == 1

    sess = Session(session_id="f1", agent_id="a1", task_id="t1",
                   t_eff=Trust.T3_HIGH, t_intrinsic=Trust.T3_HIGH)
    store.sessions.save(sess)
    assert len(store.sessions.get_active("f1")) == 1

    store.close()
