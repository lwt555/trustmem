"""Tests for CP-ABE backend interface and simulation."""
import pytest
from datetime import datetime, timedelta, timezone

from core.crypto.abe_backend import ABEBackend, create_abe_backend
from core.crypto.abe_simulation import ABESimulationBackend
from core.crypto.abe import policy_satisfied, check_policy
from core.labels import (
    AgentLabel, MemoryLabel, Clearance, Trust, Layer, Role, MemoryType,
)
from core.topology import Topology
from core.policy import policy_from_label, agent_attributes


@pytest.fixture
def abe():
    return ABESimulationBackend()


@pytest.fixture
def topo():
    t = Topology()
    t.add_agent("planner")
    t.add_agent("intel", parent="planner")
    t.add_agent("analyst", parent="planner")
    t.add_agent("auditor")
    return t


class TestABESimulationBackend:
    def test_setup(self, abe):
        abe.setup()
        assert abe._mk is not None
        assert abe._pk is not None

    def test_issue_key(self, abe):
        key = abe.issue_key("agent1", ["role_Analyst", "clearance_2"], epoch=1)
        assert key.agent_id == "agent1"
        assert "role_Analyst" in key.attributes

    def test_encrypt_decrypt_roundtrip(self, abe):
        key = abe.issue_key("agent1", ["attr_A", "attr_B"], epoch=1)
        ct = abe.encrypt("secret data", "attr_A and attr_B")
        plain = abe.decrypt(key, ct)
        assert plain == b"secret data"

    def test_decrypt_fails_wrong_attributes(self, abe):
        key = abe.issue_key("agent1", ["attr_A"], epoch=1)
        ct = abe.encrypt("secret data", "attr_A and attr_B")
        plain = abe.decrypt(key, ct)
        assert plain is None

    def test_policy_satisfied_simple(self, abe):
        assert abe.policy_satisfied("attr_A", ["attr_A"])
        assert not abe.policy_satisfied("attr_A", ["attr_B"])

    def test_policy_satisfied_and(self, abe):
        assert abe.policy_satisfied("attr_A and attr_B", ["attr_A", "attr_B"])
        assert not abe.policy_satisfied("attr_A and attr_B", ["attr_A"])

    def test_policy_satisfied_or(self, abe):
        assert abe.policy_satisfied("attr_A or attr_B", ["attr_A"])
        assert abe.policy_satisfied("attr_A or attr_B", ["attr_B"])
        assert not abe.policy_satisfied("attr_A or attr_B", ["attr_C"])

    def test_policy_satisfied_nested(self, abe):
        assert abe.policy_satisfied("(attr_A or attr_B) and attr_C",
                                   ["attr_A", "attr_C"])
        assert not abe.policy_satisfied("(attr_A or attr_B) and attr_C",
                                       ["attr_A"])

    def test_create_abe_backend_returns_simulation(self):
        backend = create_abe_backend()
        assert isinstance(backend, ABEBackend)


class TestPolicyGeneration:
    def test_agent_attributes_generates(self, topo):
        agent = AgentLabel(
            "analyst", Role.ANALYST, Clearance.L2_SENSITIVE, Trust.T2_MEDIUM,
            task_domain={"TASK-1"}, collab_group={"soc"},
            epoch=1,
            ttl_start=datetime.now(timezone.utc),
            ttl_end=datetime.now(timezone.utc) + timedelta(days=1),
        )
        attrs = agent_attributes(agent, topo)
        assert "agent_analyst" in attrs
        assert "role_Analyst" in attrs
        assert "clearance_2" in attrs
        assert "task_TASK-1" in attrs

    def test_policy_from_label_generates(self, topo):
        mem = MemoryLabel(
            "mem-1", Clearance.L2_SENSITIVE, Trust.T2_MEDIUM,
            Layer.CONCLUSION, MemoryType.INTEL,
            "analyst", "TASK-1", collab_group={"soc"}, epoch=1,
        )
        policy = policy_from_label(mem, topo)
        assert "clearance_2" in policy
        assert "task_TASK-1" in policy
        assert "and" in policy.lower()
