"""F-20 验收：委派规则六条——区间只能更紧 + CONSULT→LEARN 反向不可 + 水位取 min。"""
from __future__ import annotations

import pytest

from core.labels import (AgentLabel, MemoryLabel, Clearance, Trust, Layer,
                         MemoryType, Role, WriteOp, IngestMode, TaskScope)
from core.session import Session, SessionStore
from core.pdp import PDP
from core.topology import Topology
from core.verdict import Verdict


def _agent(trust=Trust.T3_HIGH) -> AgentLabel:
    return AgentLabel("a", Role.ANALYST, Clearance.L3_SECRET, trust,
                      task_domain={"t"}, collab_group={"g"}, epoch=1)


def _scope(c=Clearance.L3_SECRET, t=Trust.T0_UNTRUSTED,
           ingest=IngestMode.LEARN) -> TaskScope:
    return TaskScope(task_id="t", c_ctx_max=c, t_ctx_min=t, ingest=ingest)


def test_F20_child_scope_must_be_tighter():
    store = SessionStore()
    store._s[("p", "a")] = Session.start("p", _agent(), "t")
    with pytest.raises(PermissionError):
        store.delegate("p", _agent(), "t",
                       parent_scope=_scope(c=Clearance.L1_INTERNAL,
                                           t=Trust.T2_MEDIUM),
                       child_scope=_scope(c=Clearance.L3_SECRET,
                                          t=Trust.T0_UNTRUSTED))


def test_F20_consult_to_learn_forbidden():
    store = SessionStore()
    store._s[("p", "a")] = Session.start("p", _agent(), "t")
    with pytest.raises(PermissionError):
        store.delegate("p", _agent(), "t",
                       parent_scope=_scope(ingest=IngestMode.CONSULT),
                       child_scope=_scope(ingest=IngestMode.LEARN))


def test_F20_learn_to_consult_allowed():
    store = SessionStore()
    store._s[("p", "a")] = Session.start("p", _agent(), "t")
    s = store.delegate("p", _agent(), "t",
                       parent_scope=_scope(ingest=IngestMode.LEARN),
                       child_scope=_scope(ingest=IngestMode.CONSULT))
    assert s.session_id == "p/t"


def test_F20_trust_takes_min_with_child_intrinsic():
    store = SessionStore()
    parent = Session.start("p", _agent(Trust.T3_HIGH), "t")
    store._s[("p", "a")] = parent
    child_agent = _agent(Trust.T1_LOW)
    s = store.delegate("p", child_agent, "t",
                       parent_scope=_scope(), child_scope=_scope())
    assert s.t_eff == Trust.T1_LOW
    assert s.t_eff_ctl == Trust.T1_LOW


def test_F20_delegation_cannot_launder():
    topo = Topology()
    topo.add_agent("auditor")
    pdp = PDP(topo)
    auditor = AgentLabel("auditor", Role.AUDITOR, Clearance.L3_SECRET,
                         Trust.T3_HIGH, task_domain={"t"}, collab_group={"g"},
                         epoch=1)
    store = SessionStore()
    parent_sess = Session.start("s", auditor, "t")
    store._s[("s", "auditor")] = parent_sess

    scope_consult = _scope(ingest=IngestMode.CONSULT)
    dirty = MemoryLabel(chunk_id="dirty_intel", sensitivity=Clearance.L0_PUBLIC,
                        provenance_trust=Trust.T1_LOW, layer=Layer.CONCLUSION,
                        memory_type=MemoryType.INTEL, owner_agent="intel",
                        task_binding="t", collab_group={"g"})
    pdp.can_read_scoped(auditor, dirty, parent_sess, scope_consult)
    assert dirty.chunk_id in parent_sess.consulted

    child_sess = store.delegate("s", auditor, "t_sub", "child_sess",
                                parent_scope=_scope(), child_scope=_scope())
    assert dirty.chunk_id in child_sess.consulted

    d, _ = pdp.can_write(auditor, child_sess, Clearance.L0_PUBLIC,
                         Layer.CONCLUSION, [dirty], WriteOp.INFER)
    assert d.verdict is Verdict.DENY
    assert d.denied_by == "Provenance-NoConsult"
