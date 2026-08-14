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

import uuid
from datetime import datetime, timezone

from pathlib import Path

from dotenv import load_dotenv

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from .schemas import (
    WriteRequest, WriteResponse,
    ReadRequest, ReadResponse, ReadManyRequest,
    SystemStats, StepMessage, StepResult, VarHandleInfo, AgentInfo, Watermarks,
    ScenarioRunRequest, ScenarioStatusResponse, AgentStatusResponse,
    HumanResolveRequest, HumanDecryptRequest,
)
from .deps import (
    get_agents, get_session_store, get_var_store,
    get_merkle_audit, get_write_pipeline, get_read_pipeline, get_db_store,
    get_topology, get_human_gate, get_crypto,
)
from core.labels import (
    Clearance, Trust, Layer, MemoryType, WriteOp, TaskScope, IngestMode,
    fmt,
)
from scenarios.scenario_registry import SCENARIOS
from .ws_graph import handle_graph_ws
from .audit import router as audit_router

load_dotenv(Path(__file__).resolve().parents[2] / ".env")

app = FastAPI(title="TrustMem API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(audit_router)


# ── Console (new frontend) ──────────────────────────────────

_CONSOLE_PATH = Path(__file__).resolve().parents[2] / "console.html"


@app.get("/", include_in_schema=False)
def serve_console():
    return FileResponse(_CONSOLE_PATH, media_type="text/html")


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


def _default_scope(task_id: str = "") -> TaskScope:
    """无 scope 字段时退回宽松区间（F-22：scope 必填，不再允许 None）。"""
    return TaskScope(
        task_id=task_id,
        c_ctx_max=Clearance.L3_SECRET,
        t_ctx_min=Trust.T0_UNTRUSTED,
        ingest=IngestMode.LEARN,
    )


def _build_task_scope(req) -> TaskScope:
    """Extract TaskScope from a request if scope fields are present."""
    task_id = getattr(req, "task_id", None) or ""
    if not req.scope_c_max and not req.scope_t_min:
        return _default_scope(task_id)
    ingest_str = getattr(req, "scope_ingest", None)
    if ingest_str and ingest_str.upper() == "CONSULT":
        ingest = IngestMode.CONSULT
    else:
        ingest = IngestMode.LEARN
    return TaskScope(
        task_id=task_id,
        c_ctx_max=_parse_clearance(req.scope_c_max),
        t_ctx_min=_parse_trust(req.scope_t_min),
        ingest=ingest,
    )


def _format_checks(checks) -> list[dict]:
    return [{"rule": c.rule, "passed": c.passed, "detail": c.detail} for c in checks]


def _build_var_info(result) -> VarHandleInfo | None:
    if not result.var_handle:
        return None
    vh = result.var_handle
    return VarHandleInfo(
        var_id=vh.var_id,
        placeholder=vh.placeholder,
        reason=vh.reason,
        constraint_types=list(vh.constraint_types),
        metadata=vh.metadata,
    )


def _build_watermarks(session) -> Watermarks:
    """Expose session watermarks to the frontend (F-30)."""
    return Watermarks(
        c_eff=fmt(session.c_eff),
        t_eff=fmt(session.t_eff),
        t_eff_ctl=fmt(session.t_eff_ctl),
        capacity_used_bits=session.capacity_used_bits,
        capacity_budget_bits=session.CAPACITY_BUDGET_BITS,
    )


# ── Health / Stats ──────────────────────────────────────────

@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/graph")
def graph_http():
    """HTTP fallback for graph topology.

    Returns six topology nodes with visual encoding:
    - fill depth = confidentiality (lighter=lower, darker=higher)
    - border color = trust/integrity
    """
    from core.topology import Topology
    topo = get_topology()
    agents = get_agents()
    nodes = []
    for agent_id, agent in agents.items():
        node_info = {
            "agent_id": agent_id,
            "role": agent.role.value,
            "clearance": fmt(agent.clearance),
            "trust": fmt(agent.trust_intrinsic),
            "tools": list(agent.tool_scope),
            "task_domain": list(agent.task_domain),
        }
        # 拓扑关系
        ancestors = topo.ancestors(agent_id) if hasattr(topo, "ancestors") else []
        descendants = topo.descendants(agent_id) if hasattr(topo, "descendants") else []
        node_info["ancestors"] = ancestors
        node_info["descendants"] = descendants
        nodes.append(node_info)
    # Topology edges
    edges = []
    if hasattr(topo, "edges"):
        edges = topo.edges
    return {"nodes": nodes, "edges": edges, "node_count": len(nodes)}


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
        scope=_build_task_scope(req),
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

    result = pipe.read(agent=agent, session=session, chunk_id=req.chunk_id,
                       scope=_build_task_scope(req))

    return ReadResponse(
        allowed=result.allowed,
        hidden=result.hidden,
        decision_verdict=result.decision.verdict.value,
        denied_by=result.denied_by,
        chunk_id=req.chunk_id,
        var_handle=_build_var_info(result),
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

    results = pipe.read_many(agent=agent, session=session,
                             chunk_ids=req.chunk_ids, scope=_build_task_scope(req))
    responses = []
    for r in results:
        responses.append(ReadResponse(
            allowed=r.allowed, hidden=r.hidden,
            decision_verdict=r.decision.verdict.value,
            denied_by=r.denied_by, chunk_id=r.memory.chunk_id if r.memory else "",
            var_handle=_build_var_info(r), checks=_format_checks(r.checks),
            side_effects=r.side_effects,
            t_eff=fmt(session.t_eff),
            t_eff_dropped=r.t_eff_dropped,
            explanation=r.explain(),
        ))
    return responses


# ── Session ──────────────────────────────────────────────────

@app.post("/api/session/flush")
def flush_session():
    ma = get_merkle_audit()
    block = ma.flush()
    return {"flushed": block is not None,
            "block_id": block.block_id if block else None,
            "event_count": block.event_count if block else 0}


# ── Human-in-the-loop (背书门 / HITL 门人工确认) ─────────────

@app.post("/api/human/resolve")
def human_resolve(req: HumanResolveRequest):
    """人工确认门的决定回执：approve 放行 / deny 拒绝，唤醒阻塞中的 wait()。"""
    gate = get_human_gate()
    ok = gate.resolve(req.request_id, req.decision, req.reason)
    if not ok:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="请求不存在或已过期")
    return {"resolved": True, "request_id": req.request_id, "decision": req.decision}


@app.get("/api/human/pending")
def human_pending():
    """只读快照：当前待人工确认的请求（调试/兜底，不清空）。"""
    gate = get_human_gate()
    return {"pending": [r.to_dict() for r in gate.list_new()],
            "count": gate.pending_count}


@app.post("/api/human/decrypt")
def human_decrypt(req: HumanDecryptRequest):
    """人工以某密级审查员密钥解密查看记忆明文（背书门/HITL 门内容核验）。

    密级不足或属性不满足 CP-ABE 策略 → allowed=False（密码学层面解不开）。
    """
    from fastapi import HTTPException
    ct = get_db_store().memories.get_ciphertext(req.chunk_id)
    if ct is None:
        raise HTTPException(status_code=404, detail="密文不存在或 chunk_id 无效")
    lvl = int(_parse_clearance(req.clearance))
    plain, reason = get_crypto().decrypt_as_human(lvl, ct)
    if plain is None:
        return {"allowed": False, "chunk_id": req.chunk_id,
                "clearance": fmt(Clearance(lvl)), "reason": reason}
    return {"allowed": True, "chunk_id": req.chunk_id,
            "clearance": fmt(Clearance(lvl)),
            "plaintext": plain.decode("utf-8", "replace"), "reason": reason}


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
                    scope=_default_scope(p.get("task_id", "") or ""),
                )
                step = StepResult(
                    step_type="write", allowed=result.allowed, hidden=False,
                    decision_verdict=result.decision.verdict.value,
                    explanation=result.explain(),
                    checks=_format_checks(result.checks),
                    side_effects=result.side_effects,
                    merkle_root=get_merkle_audit().root.hex(),
                    watermarks=_build_watermarks(session),
                )

            elif msg.step_type == "read":
                p = msg.payload
                agent = agents[p["agent_id"]]
                sid = p.get("session_id", "ws-session")
                session = store.get_or_start(sid, agent, p.get("task_id", "ws-task"))
                if p.get("scope_c_max") or p.get("scope_t_min"):
                    scope = TaskScope(
                        task_id=p.get("task_id", "") or "",
                        c_ctx_max=_parse_clearance(p.get("scope_c_max")),
                        t_ctx_min=_parse_trust(p.get("scope_t_min")),
                        ingest=(IngestMode.CONSULT
                                if str(p.get("scope_ingest", "")).upper() == "CONSULT"
                                else IngestMode.LEARN),
                    )
                else:
                    scope = _default_scope(p.get("task_id", "") or "")
                result = read_pipe.read(agent=agent, session=session, chunk_id=p["chunk_id"], scope=scope)

                step = StepResult(
                    step_type="read", allowed=result.allowed,
                    hidden=result.hidden,
                    decision_verdict=result.decision.verdict.value,
                    explanation=result.explain(),
                    checks=_format_checks(result.checks),
                    side_effects=result.side_effects,
                    merkle_root=get_merkle_audit().root.hex(),
                    var_handle=_build_var_info(result),
                    watermarks=_build_watermarks(session),
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

_scenario_runs: dict[str, dict] = {}


@app.get("/api/scenarios")
def list_scenarios():
    """List available SOC scenarios."""
    return {"scenarios": [
        {"scenario_id": sid, "name": info["name"], "description": info["description"]}
        for sid, info in SCENARIOS.items()
    ]}


@app.post("/api/scenario/run", response_model=ScenarioStatusResponse)
def run_scenario(req: ScenarioRunRequest):
    """Start a scenario run. Returns a run_id for status polling and /ws/graph streaming."""
    from fastapi import HTTPException
    if req.scenario_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail=f"Unknown scenario: {req.scenario_id}")

    run_id = uuid.uuid4().hex[:12]
    info = SCENARIOS[req.scenario_id]
    status = {
        "scenario_id": req.scenario_id,
        "name": info["name"],
        "status": "ready",
        "phase": "planner",
        "current_agent": "",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "protection": req.protection,
    }
    _scenario_runs[run_id] = status

    return ScenarioStatusResponse(
        scenario_id=req.scenario_id,
        name=info["name"],
        status="ready",
        phase="planner",
        current_agent="",
        run_id=run_id,
    )


@app.get("/api/scenario/status/{run_id}", response_model=ScenarioStatusResponse)
def get_scenario_status(run_id: str):
    """Get the current status of a scenario run."""
    from fastapi import HTTPException
    status = _scenario_runs.get(run_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return ScenarioStatusResponse(
        scenario_id=status["scenario_id"],
        name=status["name"],
        status=status["status"],
        phase=status["phase"],
        current_agent=status.get("current_agent", ""),
        run_id=run_id,
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
    from backend.db.seed_ops import seed_ops
    init_db()
    seed_ops(get_db_store().db, reset=True)   # 灌入作战场景内部数据（54资产+攻击链日志+情报）
    return app
