"""F-21 验收：需知检查必须同时校验 task_domain 与 collab_group（I2）。"""
from __future__ import annotations

from core.labels import (AgentLabel, MemoryLabel, Clearance, Trust, Layer,
                         MemoryType, Role)
from core.session import Session
from core.topology import Topology
from core.pdp import PDP
from core.verdict import Verdict


def _agent(collab_group: set[str]) -> AgentLabel:
    return AgentLabel("a", Role.ANALYST, Clearance.L3_SECRET, Trust.T3_HIGH,
                      task_domain={"t"}, collab_group=collab_group, epoch=1)


def _mem(collab_group: set[str], task_binding: str = "t") -> MemoryLabel:
    return MemoryLabel(chunk_id="m", sensitivity=Clearance.L1_INTERNAL,
                       provenance_trust=Trust.T2_MEDIUM, layer=Layer.CONCLUSION,
                       memory_type=MemoryType.INTEL, owner_agent="a",
                       task_binding=task_binding, collab_group=collab_group)


def _pdp() -> PDP:
    topo = Topology()
    topo.add_agent("a")
    topo.add_agent("other")
    return PDP(topo)


def test_F21_collab_group_disjoint_denies():
    a = _agent({"grp_a"})
    m = _mem({"grp_b"})
    sess = Session.start("s", a, "t")
    d = _pdp().can_read(a, m, sess)
    assert d.verdict is Verdict.DENY
    assert d.denied_by == "NeedToKnow"


def test_F21_collab_group_intersect_allows():
    a = _agent({"grp_a", "grp_x"})
    m = _mem({"grp_b", "grp_x"})
    sess = Session.start("s", a, "t")
    d = _pdp().can_read(a, m, sess)
    assert d.verdict is Verdict.ALLOW


def test_F21_empty_memory_group_is_world_readable_within_task():
    a = _agent({"grp_a"})
    m = _mem(set())
    sess = Session.start("s", a, "t")
    d = _pdp().can_read(a, m, sess)
    assert d.verdict is Verdict.ALLOW


def test_F21_task_mismatch_still_denies_even_with_group_intersect():
    a = _agent({"grp_x"})
    m = _mem({"grp_x"}, task_binding="other-task")
    sess = Session.start("s", a, "t")
    d = _pdp().can_read(a, m, sess)
    assert d.verdict is Verdict.DENY
    assert d.denied_by == "NeedToKnow"
