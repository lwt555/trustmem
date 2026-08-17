"""Dependency injection for TrustMem API.

Provides singleton-like access to PDP, stores, and topology.
In production these would be scoped to request; for the demo they are module-level.
"""
from __future__ import annotations

import logging
import os

from backend.db.database import get_db
from backend.db.store import TrustMemStore
from core.pdp import PDP
from core.pipeline import WritePipeline, ReadPipeline
from core.varstore import VarStore
from core.merkle import MerkleAuditStore
from core.session import SessionStore
from core.topology import Topology
from core.crypto.engine import CryptoEngine
from core.llm.factory import create_llm_backend
from core.llm.base import LLMBackend
from core.llm.stub import StubLLMBackend
from core.agent.builder import AgentBuilder
from core.endorser import HumanEndorser
from core.human_gate import HumanGate

# 场景按环境变量切换，默认 joint（演示机不依赖"记得设环境变量"）。
_scenario = os.environ.get("TRUSTMEM_SCENARIO", "joint")
if _scenario == "soc":
    from scenarios.soc_setup import build_agents, build_topology, TASK, GROUP_SOC
    AGENT_DISPLAY_NAME: dict[str, str] = {}
else:
    from scenarios.joint.setup import (
        build_agents, build_topology,
        JOINT_TASK as TASK, GROUP_JOINT as GROUP_SOC, AGENT_DISPLAY_NAME,
    )

_log = logging.getLogger(__name__)


# ── Bootstrap (runs once on import) ─────────────────────────

_topology = build_topology()
_agents = build_agents()
_pdp = PDP(_topology)
_crypto = CryptoEngine(_topology)
_crypto.register_human_reviewer(TASK, {GROUP_SOC}, epoch=1)
_session_store = SessionStore()
_var_store = VarStore()
_db_store = TrustMemStore(get_db())
_merkle_audit = MerkleAuditStore(block_size=64)

_write_pipe = WritePipeline(
    pdp=_pdp,
    crypto=_crypto,
    mem_store=_db_store.memories,
    audit_store=_merkle_audit,
    prov_store=_db_store.provenance,
)

_read_pipe = ReadPipeline(
    pdp=_pdp,
    crypto=_crypto,
    mem_store=_db_store.memories,
    audit_store=_merkle_audit,
    var_store=_var_store,
)

# ── LLM / Agent infrastructure ────────────────────────────────

_llm: LLMBackend | None = None
_agent_builder: AgentBuilder | None = None
_endorser: HumanEndorser | None = None
_human_gate: HumanGate | None = None


def _create_llm_on_demand() -> LLMBackend:
    global _llm
    if _llm is None:
        try:
            _llm = create_llm_backend()
        except Exception:
            _log.warning("Failed to create LLM backend, falling back to stub", exc_info=True)
            _llm = StubLLMBackend()
    return _llm


def _create_builder_on_demand() -> AgentBuilder:
    global _agent_builder
    if _agent_builder is None:
        _agent_builder = AgentBuilder(
            llm=_create_llm_on_demand(),
            pdp=_pdp,
            write_pipeline=_write_pipe,
            read_pipeline=_read_pipe,
            var_store=_var_store,
            topo=_topology,
            session_store=_session_store,
        )
    return _agent_builder


# ── Accessors ───────────────────────────────────────────────

def get_topology() -> Topology:
    return _topology


def get_agents() -> dict:
    return _agents


def get_display_name(agent_id: str) -> str:
    """当前场景的显示名，无映射时回落为 agent_id。"""
    return AGENT_DISPLAY_NAME.get(agent_id, agent_id)


def get_pdp() -> PDP:
    return _pdp


def get_crypto() -> CryptoEngine:
    return _crypto


def get_session_store() -> SessionStore:
    return _session_store


def get_var_store() -> VarStore:
    return _var_store


def get_merkle_audit() -> MerkleAuditStore:
    return _merkle_audit


def get_write_pipeline() -> WritePipeline:
    return _write_pipe


def get_read_pipeline() -> ReadPipeline:
    return _read_pipe


def get_db_store() -> TrustMemStore:
    return _db_store


def get_llm() -> LLMBackend:
    return _create_llm_on_demand()


def get_agent_builder() -> AgentBuilder:
    return _create_builder_on_demand()


def get_human_endorser() -> HumanEndorser:
    global _endorser
    if _endorser is None:
        _endorser = HumanEndorser(_db_store.memories)
    return _endorser


def get_human_gate() -> HumanGate:
    global _human_gate
    if _human_gate is None:
        _human_gate = HumanGate()
    return _human_gate
