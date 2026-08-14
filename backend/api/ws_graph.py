"""WebSocket handler for graph streaming — pushes LangGraph stream events."""
from __future__ import annotations

import asyncio
import json
import threading
import traceback

from fastapi import WebSocket, WebSocketDisconnect

from .schemas import GraphCommand, GraphEventMessage
from .deps import (
    get_agents, get_pdp, get_topology, get_session_store,
    get_llm, get_agent_builder,
)
from core.graph.soc_graph import SimpleSOCRunner
from core.agent.tools import ToolRegistry
from scenarios.soc_setup import TOOL_REGISTRY
from scenarios import soc_scenario1, soc_scenario2, soc_scenario3
from backend.tools import REAL_TOOLS, TOOL_SCHEMAS


_SCENARIO_TASKS = {
    "threat-intel": soc_scenario1.TASK_INSTRUCTION,
    "incident-response": soc_scenario2.TASK_INSTRUCTION,
    "echoleak": soc_scenario3.TASK_INSTRUCTION,
}


async def handle_graph_ws(websocket: WebSocket) -> None:
    await websocket.accept()

    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = GraphCommand.model_validate_json(data)
            except Exception:
                await websocket.send_text(json.dumps({
                    "event_type": "graph_error",
                    "agent_id": "system",
                    "payload": {"error": "Invalid command format"},
                    "at": "",
                }))
                continue

            if msg.command == "run":
                await _run_scenario(websocket, msg)
            elif msg.command == "abort":
                await websocket.send_text(json.dumps({
                    "event_type": "graph_done",
                    "agent_id": "system",
                    "payload": {"aborted": True},
                    "at": "",
                }))
            else:
                await websocket.send_text(json.dumps({
                    "event_type": "graph_error",
                    "agent_id": "system",
                    "payload": {"error": f"Unknown command: {msg.command}"},
                    "at": "",
                }))

    except WebSocketDisconnect:
        pass


async def _run_scenario(websocket: WebSocket, msg: GraphCommand) -> None:
    task = msg.task or _SCENARIO_TASKS.get(msg.scenario_id,
                                            "默认SOC安全事件响应任务")
    agent_labels = get_agents()
    builder = get_agent_builder()
    session_store = get_session_store()
    pdp = get_pdp()
    topo = get_topology()

    # Build agent runtimes with session-scoped sessions
    agent_runtimes = {}
    for agent_id, agent_label in agent_labels.items():
        tool_names = TOOL_REGISTRY.get(agent_id, set())
        tool_registry = ToolRegistry()
        for tname in tool_names:
            func = REAL_TOOLS.get(tname)          # 查询类工具接真实 SQLite 数据源
            desc = f"Real {tname} tool" if func else f"Stub {tname} tool"
            tool_registry.register_builtin(
                tname, desc,
                TOOL_SCHEMAS.get(tname, {"type": "object", "properties": {}}),
                func=func,
            )

        prompt_file_map = {
            "planner": "prompts/planner.txt",
            "intel": "prompts/intel.txt",
            "log": "prompts/log.txt",
            "analyst": "prompts/analyst.txt",
            "executor": "prompts/executor.txt",
            "auditor": "prompts/auditor.txt",
        }
        prompt_path = prompt_file_map.get(agent_id, "prompts/planner.txt")
        try:
            with open(prompt_path, encoding="utf-8") as f:
                system_prompt = f.read()
        except FileNotFoundError:
            system_prompt = f"You are {agent_id}, an AI agent in the SOC team."

        runtime = builder.build(
            agent=agent_label,
            system_prompt=system_prompt,
            tool_registry=tool_registry,
            session_id=f"graph-{msg.scenario_id}",
            task_id=msg.scenario_id,
        )
        agent_runtimes[agent_id] = runtime

    runner = SimpleSOCRunner(agent_runtimes, pdp, topo, session_store)

    # runner.stream() 同步调用 LLM，会阻塞事件循环导致 WebSocket 心跳超时；
    # 放到后台线程执行，事件经队列送回主循环再推送。
    queue: asyncio.Queue = asyncio.Queue()

    def _produce() -> None:
        try:
            for event in runner.stream(task):
                queue.put_nowait(event)
        except Exception as e:
            queue.put_nowait(("error", str(e), traceback.format_exc()))
        finally:
            queue.put_nowait(None)

    threading.Thread(target=_produce, daemon=True).start()

    while True:
        item = await queue.get()
        if item is None:
            break
        if isinstance(item, tuple) and item[0] == "error":
            await websocket.send_text(json.dumps({
                "event_type": "graph_error",
                "agent_id": "system",
                "payload": {"error": item[1], "traceback": item[2]},
                "at": "",
            }, ensure_ascii=False))
            break
        d = item.to_dict()
        await websocket.send_text(json.dumps(d, ensure_ascii=False))
