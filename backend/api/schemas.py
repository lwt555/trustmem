"""Pydantic schemas for TrustMem REST API."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


# ── Agent ──────────────────────────────────────────────────

class AgentInfo(BaseModel):
    agent_id: str
    role: str
    clearance: str
    trust: str
    tools: list[str]
    task_domain: list[str]


# ── Write ──────────────────────────────────────────────────

class WriteRequest(BaseModel):
    agent_id: str
    session_id: str
    content: str
    sensitivity: str = "L1"
    layer: str = "C"
    memory_type: str = "EPISODIC"
    input_chunk_ids: list[str] = Field(default_factory=list)
    op: str = "INFER"
    task_id: str | None = None
    declassify_approved: bool = False
    input_texts: list[str] | None = None
    schema_ok: bool | None = None
    ttl_end: str | None = None   # ISO datetime
    scope_c_max: str | None = None
    scope_t_min: str | None = None
    scope_ingest: str | None = None


class WriteResponse(BaseModel):
    allowed: bool
    chunk_id: str
    decision_verdict: str
    denied_by: str | None = None
    trust_out: str | None = None
    checks: list[dict[str, Any]] = Field(default_factory=list)
    side_effects: list[str] = Field(default_factory=list)
    explanation: str = ""


# ── Read ───────────────────────────────────────────────────

class ReadRequest(BaseModel):
    agent_id: str
    session_id: str
    chunk_id: str
    task_id: str | None = None
    scope_c_max: str | None = None
    scope_t_min: str | None = None
    scope_ingest: str | None = None


class VarHandleInfo(BaseModel):
    var_id: str
    placeholder: str
    reason: str
    constraint_types: list[str]
    metadata: dict[str, str]


class ReadResponse(BaseModel):
    allowed: bool
    hidden: bool = False
    decision_verdict: str
    denied_by: str | None = None
    chunk_id: str = ""
    var_handle: VarHandleInfo | None = None
    checks: list[dict[str, Any]] = Field(default_factory=list)
    side_effects: list[str] = Field(default_factory=list)
    t_eff: str | None = None
    t_eff_dropped: bool = False
    explanation: str = ""


class ReadManyRequest(BaseModel):
    agent_id: str
    session_id: str
    chunk_ids: list[str]
    task_id: str | None = None
    scope_c_max: str | None = None
    scope_t_min: str | None = None
    scope_ingest: str | None = None


# ── Audit ──────────────────────────────────────────────────

class AuditEventInfo(BaseModel):
    event_id: str
    event_type: str
    subject: str
    object: str
    session_id: str
    payload: dict[str, Any]
    at: str


class MerkleProofInfo(BaseModel):
    leaf_hash: str
    root: str
    leaf_index: int
    siblings: list[tuple[str, bool]]
    valid: bool


class SessionReplayResponse(BaseModel):
    session_id: str
    total_events: int
    events: list[AuditEventInfo]


class ChainVerificationResponse(BaseModel):
    valid: bool
    chain_length: int
    blocks: list[dict[str, Any]]


# ── Stats ──────────────────────────────────────────────────

class SystemStats(BaseModel):
    memories: int
    sessions: int
    merkle_blocks: int
    merkle_events: int
    merkle_root: str | None = None
    var_handles: int


# ── WebSocket ──────────────────────────────────────────────

class StepMessage(BaseModel):
    """WebSocket: single-step demo request."""
    step_type: str  # "write" | "read" | "attack"
    payload: dict[str, Any]


class Watermarks(BaseModel):
    """Session watermarks exposed to the frontend (F-30: dual-gauge visualization)."""
    c_eff: str            # 机密性高水位（只升）
    t_eff: str            # 完整性低水位（只降）
    t_eff_ctl: str        # LLM 控制流隔离水位
    capacity_used_bits: float
    capacity_budget_bits: float


class StepResult(BaseModel):
    """WebSocket: single-step result pushed to client."""
    step_type: str
    decision_verdict: str
    allowed: bool
    hidden: bool = False
    explanation: str
    checks: list[dict[str, Any]] = Field(default_factory=list)
    side_effects: list[str] = Field(default_factory=list)
    merkle_root: str | None = None
    var_handle: VarHandleInfo | None = None
    watermarks: Watermarks | None = None


# ── Scenario / Graph ─────────────────────────────────────────

class ScenarioRunRequest(BaseModel):
    scenario_id: str = "threat-intel"
    task: str | None = None
    protection: bool = True
    demo_mode: bool = True


class ScenarioStatusResponse(BaseModel):
    scenario_id: str
    name: str = ""
    status: str = "idle"
    phase: str = ""
    current_agent: str = ""
    run_id: str = ""
    decisions: list[dict[str, Any]] = Field(default_factory=list)
    events: list[dict[str, Any]] = Field(default_factory=list)


class AgentStatusResponse(BaseModel):
    agent_id: str
    role: str
    status: str = "idle"
    t_eff: str = "?"
    t_intrinsic: str = "?"
    tool_names: list[str] = Field(default_factory=list)
    steps: list[dict[str, Any]] = Field(default_factory=list)
    recent_reads: list[str] = Field(default_factory=list)
    recent_writes: list[str] = Field(default_factory=list)


class GraphCommand(BaseModel):
    """WebSocket: graph command from client."""
    command: str = "run"
    task: str = ""
    scenario_id: str = "threat-intel"
    protection: bool = True


class HumanResolveRequest(BaseModel):
    """REST: 人工确认门的决定回执（背书 / HITL）。"""
    request_id: str
    decision: str = "deny"   # "approve" | "deny"
    reason: str = ""


class HumanDecryptRequest(BaseModel):
    """REST: 人工以某密级审查员密钥解密查看记忆明文。"""
    chunk_id: str
    clearance: str = "L3"    # "L0".."L3" 或 "0".."3"


class GraphEventMessage(BaseModel):
    """WebSocket: graph event pushed to client."""
    event_type: str
    agent_id: str
    payload: dict[str, Any]
    at: str
