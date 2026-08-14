"""F-04 验收：隐藏中立性 I8 —— HIDE / DENY 不改变任何水位与预算。

判定（PDP）与生效（PEP）分离：can_read / can_read_scoped 是纯函数，
水位只在 ReadPipeline 的 pep.commit（ALLOW 路径）提交。
"""
from __future__ import annotations

from pathlib import Path

import pytest

from core.labels import (AgentLabel, MemoryLabel, Clearance, Trust, Layer,
                         MemoryType, Role, WriteOp, TaskScope, IngestMode)
from core.session import Session, AbsorbMode
from core.topology import Topology
from core.pdp import PDP
from core.verdict import Verdict
from core.pipeline import ReadPipeline
from core.varstore import VarStore


def _agent(**kw) -> AgentLabel:
    defaults = dict(agent_id="analyst", role=Role.ANALYST,
                    clearance=Clearance.L2_SENSITIVE, trust_intrinsic=Trust.T2_MEDIUM,
                    task_domain={"task-x"}, collab_group={"grp"})
    return AgentLabel(**(defaults | kw))


def _mem(**kw) -> MemoryLabel:
    defaults = dict(chunk_id="m", sensitivity=Clearance.L2_SENSITIVE,
                    provenance_trust=Trust.T3_HIGH, layer=Layer.CONCLUSION,
                    memory_type=MemoryType.INTEL, owner_agent="owner",
                    task_binding="task-x", collab_group={"grp"})
    return MemoryLabel(**(defaults | kw))


def _snapshot(sess: Session):
    return (sess.c_eff, sess.t_eff, sess.t_eff_ctl, sess.capacity_used_bits)


class _MemStore:
    def __init__(self, mems: dict[str, MemoryLabel]):
        self._m = mems

    def get(self, cid):
        return self._m.get(cid)


class _Audit:
    def log(self, d):
        pass


def _pipe(pdp, mems):
    return ReadPipeline(pdp, None, _MemStore(mems), _Audit(), VarStore())


def test_F04_consult_changes_nothing():
    pdp = PDP(Topology())
    auditor = _agent(agent_id="auditor", role=Role.AUDITOR,
                     clearance=Clearance.L3_SECRET, trust_intrinsic=Trust.T3_HIGH)
    dirty = _mem(chunk_id="dirty", sensitivity=Clearance.L2_SENSITIVE,
                 provenance_trust=Trust.T1_LOW)
    pipe = _pipe(pdp, {dirty.chunk_id: dirty})
    sess = Session.start("s", auditor, "task-x")
    before = _snapshot(sess)

    r = pipe.read(agent=auditor, session=sess, chunk_id=dirty.chunk_id,
                  scope=TaskScope("t", Clearance.L3_SECRET, Trust.T0_UNTRUSTED,
                                  IngestMode.CONSULT))
    assert r.decision.verdict is Verdict.HIDE
    assert _snapshot(sess) == before, "CONSULT 隐藏不得改变水位"


def test_F04_scope_hide_changes_nothing():
    pdp = PDP(Topology())
    agent = _agent()
    l3 = _mem(chunk_id="l3", sensitivity=Clearance.L2_SENSITIVE)
    pipe = _pipe(pdp, {l3.chunk_id: l3})
    sess = Session.start("s", agent, "task-x")
    before = _snapshot(sess)

    r = pipe.read(agent=agent, session=sess, chunk_id=l3.chunk_id,
                  scope=TaskScope("t", Clearance.L1_INTERNAL, Trust.T0_UNTRUSTED))
    assert r.decision.verdict is Verdict.HIDE
    assert _snapshot(sess) == before, "区间超密级 HIDE 不得改变水位"


def test_F04_deny_changes_nothing():
    pdp = PDP(Topology())
    low = _agent(agent_id="low", clearance=Clearance.L0_PUBLIC)
    secret = _mem(chunk_id="secret", sensitivity=Clearance.L3_SECRET)
    pipe = _pipe(pdp, {secret.chunk_id: secret})
    sess = Session.start("s", low, "task-x")
    before = _snapshot(sess)

    r = pipe.read(agent=low, session=sess, chunk_id=secret.chunk_id,
                  scope=TaskScope("t", Clearance.L3_SECRET, Trust.T0_UNTRUSTED))
    assert r.decision.verdict is Verdict.DENY
    assert _snapshot(sess) == before, "硬拒绝不得改变水位"


def test_F04_no_elevate_absorb_c_degrade_ctl():
    """铁律 7：水位单一入口。elevate / absorb_c / degrade_ctl 必须已删除。"""
    src = Path("core/session.py").read_text(encoding="utf-8")
    for banned in ("def elevate", "def absorb_c", "def degrade_ctl"):
        assert banned not in src, f"{banned} 必须已删除（水位单一入口）"


def test_F04_auditor_can_write_own_conclusion_after_consult():
    """设计文档 §3.8 第 ⑨ 步：CONSULT 之后审计员写自己的独立结论必须放行。"""
    pdp = PDP(Topology())
    auditor = _agent(agent_id="auditor", role=Role.AUDITOR,
                     clearance=Clearance.L3_SECRET, trust_intrinsic=Trust.T3_HIGH)
    dirty = _mem(chunk_id="dirty", sensitivity=Clearance.L2_SENSITIVE,
                 provenance_trust=Trust.T1_LOW)
    pipe = _pipe(pdp, {dirty.chunk_id: dirty})
    sess = Session.start("s", auditor, "task-x")

    pipe.read(agent=auditor, session=sess, chunk_id=dirty.chunk_id,
              scope=TaskScope("audit", Clearance.L3_SECRET, Trust.T0_UNTRUSTED,
                              IngestMode.CONSULT))
    d, decay = pdp.can_write(auditor, sess, Clearance.L2_SENSITIVE,
                             Layer.CONCLUSION, input_mems=[], op=WriteOp.INFER)
    assert d.verdict is Verdict.ALLOW, f"审计员独立结论应放行，denied_by={d.denied_by}"
    assert decay.trust_out >= Trust.T2_MEDIUM, \
        f"查阅脏情报不得压低审计员结论。trust_out={decay.trust_out}"
