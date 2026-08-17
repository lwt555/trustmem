"""Pytest shared fixtures — reused across all test files."""
import os
os.environ.setdefault("TRUSTMEM_SCENARIO", "soc")

import pytest
from datetime import datetime, timezone, timedelta

from core.labels import AgentLabel, Clearance, Trust, Role
from core.topology import Topology
from core.pdp import PDP
from core.crypto.engine import CryptoEngine
from core.varstore import VarStore
from core.merkle import MerkleAuditStore


@pytest.fixture
def mem_store():
    """In-memory store shared across agent/graph/e2e tests."""
    class MemStore:
        def __init__(self):
            self._m = {}
        def put(self, mem):
            self._m[mem.chunk_id] = mem
        def get(self, cid):
            return self._m.get(cid)
        def list_active(self):
            return list(self._m.values())
        def list_by_task(self, tid):
            return [m for m in self._m.values() if m.task_binding == tid]
    return MemStore()


@pytest.fixture
def topo():
    """6-agent SOC topology."""
    t = Topology()
    t.add_agent("planner")
    for child in ("intel", "log", "analyst", "executor"):
        t.add_agent(child, parent="planner")
    t.add_agent("auditor")
    return t


@pytest.fixture
def pdp(topo):
    return PDP(topo)


@pytest.fixture
def crypto(topo):
    return CryptoEngine(topo)


@pytest.fixture
def audit():
    return MerkleAuditStore(block_size=64)


@pytest.fixture
def var_store():
    return VarStore()
