"""F-16 验收：CONFIRM 裁决落地 + HITL 门（高危能力需人在环，会话不可自证）。"""
from __future__ import annotations

import pytest

from core.labels import (AgentLabel, MemoryLabel, Clearance, Trust, Layer,
                         MemoryType, Role, WriteOp)
from core.session import Session
from core.topology import Topology
from core.pdp import PDP, Decision
from core.verdict import Verdict
from pep.hitl import HITLGate, HITLDecision, hitl_policy


def _executor() -> AgentLabel:
    return AgentLabel("executor", Role.EXECUTOR, Clearance.L3_SECRET, Trust.T3_HIGH,
                      task_domain={"t"}, collab_group={"g"},
                      tool_scope={"firewall_block", "host_isolate", "file_write"},
                      epoch=1)


def test_F16_dangerous_tool_yields_confirm():
    topo = Topology()
    topo.add_agent("executor")
    pdp = PDP(topo)
    executor = _executor()
    sess = Session.start("s", executor, "t")
    d = pdp.can_invoke(executor, sess, "firewall_block", "fp")
    assert d.verdict is Verdict.CONFIRM


def test_F16_dangerous_tool_allows_after_hitl():
    topo = Topology()
    topo.add_agent("executor")
    pdp = PDP(topo)
    executor = _executor()
    sess = Session.start("s", executor, "t")
    sess.add_hitl("fp")
    d = pdp.can_invoke(executor, sess, "firewall_block", "fp")
    assert d.verdict is Verdict.ALLOW


def test_F16_system_capability_denies():
    topo = Topology()
    topo.add_agent("executor")
    pdp = PDP(topo)
    executor = _executor()
    sess = Session.start("s", executor, "t")
    d = pdp.can_invoke(executor, sess, "key_export", "k")
    assert d.verdict is Verdict.DENY
    assert d.denied_by == "SystemCapability"


def test_F16_confirm_blocks_pipeline_until_approved():
    from core.pipeline import ReadPipeline

    class _PDP:
        def can_read(self, agent, mem, session, now=None, epoch_current=None):
            return Decision(Verdict.CONFIRM, "READ", agent.agent_id, mem.chunk_id,
                            [], denied_by="HumanInTheLoop",
                            session_id=session.session_id)

    class _Store:
        def get(self, chunk_id):
            return MemoryLabel(chunk_id=chunk_id, sensitivity=Clearance.L1_INTERNAL,
                               provenance_trust=Trust.T2_MEDIUM, layer=Layer.CONCLUSION,
                               memory_type=MemoryType.INTEL, owner_agent="a",
                               task_binding="t", collab_group={"g"})
        def get_ciphertext(self, chunk_id):
            return b"\x00" * 16
        def put(self, mem, ciphertext=None):
            pass
        def list_by_task(self, task_id):
            return []

    class _Audit:
        def __init__(self):
            self.events = []
        def log(self, d):
            self.events.append(d)

    agent = AgentLabel("a", Role.ANALYST, Clearance.L3_SECRET, Trust.T3_HIGH,
                       task_domain={"t"}, collab_group={"g"}, epoch=1)
    sess = Session.start("s", agent, "t")

    with hitl_policy("deny"):
        pipe = ReadPipeline(_PDP(), None, _Store(), _Audit())
        r = pipe.read(agent=agent, session=sess, chunk_id="confirm-chunk")
        assert r.allowed is False
        assert r.plaintext is None


def test_F16_session_cannot_self_confirm():
    sess = Session.start("s", _executor(), "t")
    with pytest.raises((AttributeError, TypeError)):
        sess.hitl_confirmations.add("forged")  # frozenset 无 add


def test_F16_declassify_requires_signed_hitl():
    topo = Topology()
    topo.add_agent("planner")
    topo.add_agent("analyst", parent="planner")
    pdp = PDP(topo)
    planner = AgentLabel("planner", Role.PLANNER, Clearance.L3_SECRET, Trust.T3_HIGH,
                         task_domain={"t"}, collab_group={"g"}, epoch=1)
    sess = Session.start("s", planner, "t")
    d, _ = pdp.can_write(planner, sess, Clearance.L0_PUBLIC, Layer.DIRECTIVE, [],
                         WriteOp.VERBATIM, declassify_approved=True)
    assert d.verdict is Verdict.DENY, "裸 bool 不得作为降级凭证"


def test_F16_eval_policy_once_only_counts_deny_as_block():
    from scenarios.ablation import run_attack, FULL, blocked_rules
    with hitl_policy("once"):
        r = run_attack("A11", FULL)
        assert "HumanInTheLoop" not in r.blocked_by, \
            "A11 必须是规则硬拦，不靠缺人签"


def test_F16_hitl_gate_auto_policy():
    with hitl_policy("once"):
        gate = HITLGate()
        assert gate.request(None).decision is HITLDecision.ALLOW_ONCE
    with hitl_policy("deny"):
        gate = HITLGate()
        assert gate.request(None).decision is HITLDecision.DENY
