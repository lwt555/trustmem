"""
TrustMem REST + WebSocket API.

Endpoints:
  GET  /api/health
  GET  /api/stats
  GET  /api/agents
  POST /api/write
  POST /api/read
  POST /api/read-many
  GET  /api/audit/events/{event_id}
  GET  /api/audit/proof/{event_id}
  GET  /api/audit/session/{session_id}
  GET  /api/audit/chain/verify
  GET  /api/audit/events
  POST /api/session/flush
  GET  /api/memories
  GET  /api/memories/{chunk_id}
  WS   /ws/step
"""
from __future__ import annotations

import json
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from .schemas import (
    WriteRequest, WriteResponse,
    ReadRequest, ReadResponse, ReadManyRequest,
    AuditEventInfo, MerkleProofInfo,
    SessionReplayResponse, ChainVerificationResponse,
    SystemStats, StepMessage, StepResult, VarHandleInfo, AgentInfo,
    ScenarioRunRequest, ScenarioStatusResponse, AgentStatusResponse,
)
from .deps import (
    get_agents, get_session_store, get_var_store,
    get_merkle_audit, get_write_pipeline, get_read_pipeline, get_db_store,
    get_llm, get_agent_builder, get_topology,
)
from core.labels import (
    Clearance, Trust, Layer, MemoryType, WriteOp, TaskScope, IngestMode,
    fmt, meet_trust,
)
from core.verdict import Verdict
from core.agent.tools import ToolRegistry
from scenarios.soc_setup import TOOL_REGISTRY
from scenarios.scenario_registry import SCENARIOS
from .ws_graph import handle_graph_ws

app = FastAPI(title="TrustMem API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Helpers ─────────────────────────────────────────────────

def _parse_clearance(s: str | None) -> Clearance:
    if s is None:
        return Clearance.L1_INTERNAL
    # Handle "L0".."L3" short format
    short_map = {"L0": Clearance.L0_PUBLIC, "L1": Clearance.L1_INTERNAL,
                 "L2": Clearance.L2_SENSITIVE, "L3": Clearance.L3_SECRET}
    if s in short_map:
        return short_map[s]
    # Handle name format "L0_PUBLIC", int, or enum value
    if hasattr(Clearance, s):
        return getattr(Clearance, s)
    return Clearance(int(s))


def _parse_trust(s: str | None) -> Trust:
    if s is None:
        return Trust.T1_LOW
    short_map = {"T0": Trust.T0_UNTRUSTED, "T1": Trust.T1_LOW,
                 "T2": Trust.T2_MEDIUM, "T3": Trust.T3_HIGH}
    if s in short_map:
        return short_map[s]
    if hasattr(Trust, s):
        return getattr(Trust, s)
    return Trust(int(s))


def _parse_memory_type(s: str) -> MemoryType:
    """Parse MemoryType from name or value, case-insensitive."""
    try:
        return MemoryType(s)
    except ValueError:
        return MemoryType[s.upper()]


def _parse_write_op(s: str) -> WriteOp:
    """Parse WriteOp from name or value, case-insensitive."""
    try:
        return WriteOp(s)
    except ValueError:
        return WriteOp[s.upper()]


def _format_checks(checks) -> list[dict]:
    return [{"rule": c.rule, "passed": c.passed, "detail": c.detail} for c in checks]


def _audit_event_to_info(event) -> AuditEventInfo:
    return AuditEventInfo(
        event_id=event.event_id,
        event_type=event.event_type.value,
        subject=event.subject,
        object=event.object,
        session_id=event.session_id,
        payload=event.payload,
        at=event.at.isoformat(),
    )


# ── Health / Stats ──────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/stats", response_model=SystemStats)
def stats():
    merkle = get_merkle_audit()
    ms = merkle.stats()
    return SystemStats(
        memories=get_db_store().memories.count(),
        sessions=get_session_store().count,
        merkle_blocks=ms["blocks"],
        merkle_events=ms["total_events"],
        merkle_root=ms["last_root"],
        var_handles=get_var_store().count,
    )


@app.get("/api/agents", response_model=list[AgentInfo])
def list_agents():
    agents = get_agents()
    return [
        AgentInfo(
            agent_id=a.agent_id,
            role=a.role.value,
            clearance=fmt(a.clearance),
            trust=fmt(a.trust_intrinsic),
            tools=list(a.tool_scope),
            task_domain=list(a.task_domain),
        )
        for a in agents.values()
    ]


# ── Write ───────────────────────────────────────────────────

@app.post("/api/write", response_model=WriteResponse)
def write(req: WriteRequest):
    agents = get_agents()
    store = get_session_store()
    pipe = get_write_pipeline()

    agent = agents.get(req.agent_id)
    if agent is None:
        return WriteResponse(allowed=False, chunk_id="",
                             decision_verdict="DENY",
                             denied_by="UnknownAgent")

    session = store.get_or_start(req.session_id, agent, req.task_id or "unknown")
    input_mems = [pipe.mem_store.get(cid) for cid in req.input_chunk_ids]
    input_mems = [m for m in input_mems if m is not None]

    scope = None
    if req.scope_c_max or req.scope_t_min:
        scope = TaskScope(
            task_id=req.task_id or "",
            c_ctx_max=_parse_clearance(req.scope_c_max),
            t_ctx_min=_parse_trust(req.scope_t_min),
            ingest=IngestMode.LEARN,
        )

    result = pipe.write(
        agent=agent, session=session, content=req.content,
        target_sensitivity=_parse_clearance(req.sensitivity),
        target_layer=Layer(req.layer),
        memory_type=_parse_memory_type(req.memory_type),
        input_mems=input_mems,
        op=_parse_write_op(req.op),
        task_binding=req.task_id,
        declassify_approved=req.declassify_approved,
        input_texts=req.input_texts,
        schema_ok=req.schema_ok,
        scope=scope,
    )

    return WriteResponse(
        allowed=result.allowed,
        chunk_id=result.chunk_id,
        decision_verdict=result.decision.verdict.value,
        denied_by=result.denied_by,
        trust_out=fmt(result.decay.trust_out) if result.decay else None,
        checks=_format_checks(result.checks),
        side_effects=result.side_effects,
        explanation=result.explain(),
    )


# ── Read ────────────────────────────────────────────────────

@app.post("/api/read", response_model=ReadResponse)
def read(req: ReadRequest):
    agents = get_agents()
    store = get_session_store()
    pipe = get_read_pipeline()

    agent = agents.get(req.agent_id)
    if agent is None:
        return ReadResponse(allowed=False, hidden=False,
                            decision_verdict="DENY",
                            denied_by="UnknownAgent")

    session = store.get_or_start(req.session_id, agent, req.task_id or "unknown")

    scope = None
    if req.scope_c_max or req.scope_t_min:
        scope = TaskScope(
            task_id=req.task_id or "",
            c_ctx_max=_parse_clearance(req.scope_c_max),
            t_ctx_min=_parse_trust(req.scope_t_min),
            ingest=IngestMode.LEARN,
        )

    result = pipe.read(agent=agent, session=session, chunk_id=req.chunk_id, scope=scope)

    var_info = None
    if result.var_handle:
        vh = result.var_handle
        var_info = VarHandleInfo(
            var_id=vh.var_id,
            placeholder=vh.placeholder,
            reason=vh.reason,
            constraint_types=list(vh.constraint_types),
            metadata=vh.metadata,
        )

    return ReadResponse(
        allowed=result.allowed,
        hidden=result.hidden,
        decision_verdict=result.decision.verdict.value,
        denied_by=result.denied_by,
        chunk_id=req.chunk_id,
        var_handle=var_info,
        checks=_format_checks(result.checks),
        side_effects=result.side_effects,
        t_eff=fmt(session.t_eff) if result.allowed else None,
        t_eff_dropped=result.t_eff_dropped,
        explanation=result.explain(),
    )


@app.post("/api/read-many", response_model=list[ReadResponse])
def read_many(req: ReadManyRequest):
    agents = get_agents()
    store = get_session_store()
    pipe = get_read_pipeline()

    agent = agents.get(req.agent_id)
    if agent is None:
        return []

    session = store.get_or_start(req.session_id, agent, req.task_id or "unknown")

    scope = None
    if req.scope_c_max or req.scope_t_min:
        scope = TaskScope(
            task_id=req.task_id or "",
            c_ctx_max=_parse_clearance(req.scope_c_max),
            t_ctx_min=_parse_trust(req.scope_t_min),
            ingest=IngestMode.LEARN,
        )

    results = pipe.read_many(agent=agent, session=session,
                             chunk_ids=req.chunk_ids, scope=scope)
    responses = []
    for r in results:
        var_info = None
        if r.var_handle:
            vh = r.var_handle
            var_info = VarHandleInfo(
                var_id=vh.var_id,
                placeholder=vh.placeholder,
                reason=vh.reason,
                constraint_types=list(vh.constraint_types),
                metadata=vh.metadata,
            )
        responses.append(ReadResponse(
            allowed=r.allowed, hidden=r.hidden,
            decision_verdict=r.decision.verdict.value,
            denied_by=r.denied_by, chunk_id=r.memory.chunk_id if r.memory else "",
            var_handle=var_info, checks=_format_checks(r.checks),
            side_effects=r.side_effects,
            t_eff=fmt(session.t_eff),
            t_eff_dropped=r.t_eff_dropped,
            explanation=r.explain(),
        ))
    return responses


# ── Audit ───────────────────────────────────────────────────

@app.get("/api/audit/events/{event_id}", response_model=AuditEventInfo)
def get_audit_event(event_id: str):
    ma = get_merkle_audit()
    evt = ma.get_event(event_id)
    if evt is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Event not found")
    return _audit_event_to_info(evt)


@app.get("/api/audit/proof/{event_id}", response_model=MerkleProofInfo)
def get_audit_proof(event_id: str):
    ma = get_merkle_audit()
    proof = ma.get_proof(event_id)
    if proof is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Event not found")
    return MerkleProofInfo(
        leaf_hash=proof.leaf_hash.hex(),
        root=proof.root.hex(),
        leaf_index=proof.leaf_index,
        siblings=[(h.hex(), side) for h, side in proof.siblings],
        valid=proof.verify(),
    )


@app.get("/api/audit/session/{session_id}", response_model=SessionReplayResponse)
def replay_session(session_id: str):
    ma = get_merkle_audit()
    events = ma.replay_session(session_id)
    return SessionReplayResponse(
        session_id=session_id,
        total_events=len(events),
        events=[_audit_event_to_info(e) for e in events],
    )


@app.get("/api/audit/chain/verify", response_model=ChainVerificationResponse)
def verify_chain():
    ma = get_merkle_audit()
    result = ma.verify_chain()
    return ChainVerificationResponse(
        valid=result["valid"],
        chain_length=result["chain_length"],
        blocks=result["blocks"],
    )


@app.get("/api/audit/events")
def list_audit_events(session_id: str | None = None, limit: int = 50):
    ma = get_merkle_audit()
    if session_id:
        events = ma.replay_session(session_id)
    else:
        events = []
    events = events[-limit:]
    return {"events": [_audit_event_to_info(e) for e in events]}


@app.post("/api/session/flush")
def flush_session():
    ma = get_merkle_audit()
    block = ma.flush()
    return {"flushed": block is not None,
            "block_id": block.block_id if block else None,
            "event_count": block.event_count if block else 0}


# ── Memories ────────────────────────────────────────────────

@app.get("/api/memories")
def list_memories():
    mems = get_db_store().memories.list_active()
    return {"memories": [{ "chunk_id": m.chunk_id, "sensitivity": fmt(m.sensitivity),
                           "trust": fmt(m.provenance_trust), "layer": m.layer.value,
                           "type": m.memory_type.value, "owner": m.owner_agent,
                           "task": m.task_binding, "lifecycle": m.lifecycle }
                         for m in mems]}


@app.get("/api/memories/{chunk_id}")
def get_memory(chunk_id: str):
    m = get_db_store().memories.get(chunk_id)
    if m is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Memory not found")
    return {"chunk_id": m.chunk_id, "sensitivity": fmt(m.sensitivity),
            "trust": fmt(m.provenance_trust), "layer": m.layer.value,
            "type": m.memory_type.value, "owner": m.owner_agent,
            "task": m.task_binding, "lifecycle": m.lifecycle,
            "provenance_chain": m.provenance_chain}


# ── WebSocket ───────────────────────────────────────────────

@app.websocket("/ws/step")
async def ws_step(websocket: WebSocket):
    """Single-step demo WebSocket: client sends steps, server pushes results."""
    await websocket.accept()

    agents = get_agents()
    store = get_session_store()
    write_pipe = get_write_pipeline()
    read_pipe = get_read_pipeline()

    try:
        while True:
            data = await websocket.receive_text()
            msg = StepMessage.model_validate_json(data)

            if msg.step_type == "write":
                p = msg.payload
                agent = agents[p["agent_id"]]
                sid = p.get("session_id", "ws-session")
                session = store.get_or_start(sid, agent, p.get("task_id", "ws-task"))
                result = write_pipe.write(
                    agent=agent, session=session,
                    content=p["content"],
                    target_sensitivity=_parse_clearance(p.get("sensitivity")),
                    target_layer=Layer(p.get("layer", "C")),
                    memory_type=_parse_memory_type(p.get("memory_type", "EPISODIC")),
                    input_mems=[],
                    op=_parse_write_op(p.get("op", "INFER")),
                    task_binding=p.get("task_id"),
                )
                step = StepResult(
                    step_type="write", allowed=result.allowed, hidden=False,
                    decision_verdict=result.decision.verdict.value,
                    explanation=result.explain(),
                    checks=_format_checks(result.checks),
                    side_effects=result.side_effects,
                    merkle_root=get_merkle_audit().root.hex(),
                )

            elif msg.step_type == "read":
                p = msg.payload
                agent = agents[p["agent_id"]]
                sid = p.get("session_id", "ws-session")
                session = store.get_or_start(sid, agent, p.get("task_id", "ws-task"))
                result = read_pipe.read(agent=agent, session=session, chunk_id=p["chunk_id"])

                var_info = None
                if result.var_handle:
                    vh = result.var_handle
                    var_info = VarHandleInfo(
                        var_id=vh.var_id, placeholder=vh.placeholder,
                        reason=vh.reason, constraint_types=list(vh.constraint_types),
                        metadata=vh.metadata,
                    )
                step = StepResult(
                    step_type="read", allowed=result.allowed,
                    hidden=result.hidden,
                    decision_verdict=result.decision.verdict.value,
                    explanation=result.explain(),
                    checks=_format_checks(result.checks),
                    side_effects=result.side_effects,
                    merkle_root=get_merkle_audit().root.hex(),
                    var_handle=var_info,
                )

            else:
                step = StepResult(
                    step_type=msg.step_type, allowed=False, hidden=False,
                    decision_verdict="ERROR",
                    explanation=f"Unknown step_type: {msg.step_type}",
                )

            await websocket.send_text(step.model_dump_json())

    except WebSocketDisconnect:
        pass


# ── Graph WebSocket ──────────────────────────────────────────

@app.websocket("/ws/graph")
async def ws_graph(websocket: WebSocket):
    """Graph streaming WebSocket: client sends run/abort commands, server streams events."""
    await handle_graph_ws(websocket)


# ── Scenario endpoints ───────────────────────────────────────

@app.get("/api/scenarios")
def list_scenarios():
    """List available SOC scenarios."""
    return {"scenarios": [
        {"scenario_id": sid, "name": info["name"], "description": info["description"]}
        for sid, info in SCENARIOS.items()
    ]}


@app.post("/api/scenario/run", response_model=ScenarioStatusResponse)
def run_scenario(req: ScenarioRunRequest):
    """Start a scenario run (returns initial status; use /ws/graph for live events)."""
    info = SCENARIOS.get(req.scenario_id, {"name": req.scenario_id})
    return ScenarioStatusResponse(
        scenario_id=req.scenario_id,
        name=info.get("name", req.scenario_id),
        status="ready",
        phase="planner",
        current_agent="",
    )


@app.get("/api/agent/{agent_id}/status", response_model=AgentStatusResponse)
def get_agent_status(agent_id: str):
    """Get the current status of an agent (from its last run)."""
    agents = get_agents()
    agent = agents.get(agent_id)
    if agent is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Agent not found")
    return AgentStatusResponse(
        agent_id=agent.agent_id,
        role=agent.role.value,
        status="idle",
        t_eff=fmt(agent.trust_intrinsic),
        t_intrinsic=fmt(agent.trust_intrinsic),
        tool_names=list(agent.tool_scope),
    )


# ── Startup ─────────────────────────────────────────────────

def create_app() -> FastAPI:
    from backend.db.database import init_db
    init_db()
    return app
