"""军事场景（joint）工具的真实实现 —— 查询本地 SQLite 业务数据表。

situation_query / spectrum_query / xdomain_receive 读真实结构的数据
（sensor_reports / relay_intel 表），返回 is_stub=False，下游 Agent 会当真实数据
采信，再进入 PDP 可信度衰减链。log_query 复用 backend/tools.py 既有实现（查
siem_logs），不重写。动作类工具 xdomain_forward / risk_level_publish 保持 STUB，
沿用既有诚实措辞（如实声明未接入真实环境、未执行任何动作），禁止编造成功回执。
"""
from __future__ import annotations

import json
import re

from core.agent.tools import ToolResult

from backend.db.database import get_db
from backend.db.models import SensorReport, RelayIntel
from backend.tools import log_query  # 复用 SOC 场景既有实现（查 siem_logs）


def _rows_to_str(rows: list[dict]) -> str:
    """把查询结果序列化为 LLM 可读的紧凑 JSON。"""
    if not rows:
        return "（无匹配数据）"
    return json.dumps(rows, ensure_ascii=False, default=str, indent=1)


def _tokens(q: str | None) -> list[str]:
    """把查询拆成有意义的 token（去标点、去停用词、长度>=2）。"""
    if not q:
        return []
    raw = re.split(r"[\s,;:：、/\\|()\[\]\"']+", q.lower())
    stop = {"the", "a", "an", "of", "and", "or", "for", "in", "on", "to",
            "is", "are", "请", "查询", "搜索", "检索", "相关", "关于", "的"}
    return [t for t in raw if len(t) >= 2 and t not in stop]


def _any_token_in(tokens: list[str], *fields: str) -> bool:
    """任意 token 命中任意字段即匹配（子串，大小写不敏感）。"""
    for tok in tokens:
        for f in fields:
            if tok in (f or "").lower():
                return True
    return False


def _sensor_rows(db, sensor_type: str, q: str | None) -> list[dict]:
    tokens = _tokens(q)
    rows = db.query(SensorReport).filter(
        SensorReport.sensor_type == sensor_type).all()
    if tokens:
        rows = [s for s in rows if _any_token_in(
            tokens, s.sector, s.report_id,
            json.dumps(s.payload or {}, ensure_ascii=False))]
    return [{
        "report_id": s.report_id, "ts": str(s.ts),
        "sensor_type": s.sensor_type, "sector": s.sector,
        "payload": s.payload, "verified": s.verified,
        "trust": s.trust, "sensitivity": s.sensitivity,
    } for s in rows]


def situation_query(query: str | None = None, **kwargs) -> ToolResult:
    """态势查询：雷达直报（sensor_reports where sensor_type='radar'）。"""
    db = get_db()
    try:
        data = _sensor_rows(db, "radar", query)
        return ToolResult("situation_query", True, _rows_to_str(data), is_stub=False)
    finally:
        db.close()


def spectrum_query(query: str | None = None, **kwargs) -> ToolResult:
    """频谱分析：频谱直报（sensor_reports where sensor_type='spectrum'）。"""
    db = get_db()
    try:
        data = _sensor_rows(db, "spectrum", query)
        return ToolResult("spectrum_query", True, _rows_to_str(data), is_stub=False)
    finally:
        db.close()


def xdomain_receive(query: str | None = None, **kwargs) -> ToolResult:
    """跨域接收：读取跨域协同信道转报（relay_intel）。"""
    db = get_db()
    try:
        tokens = _tokens(query)
        rows = db.query(RelayIntel).all()
        if tokens:
            rows = [r for r in rows if _any_token_in(
                tokens, r.relay_id, r.channel, r.origin, r.payload)]
        data = [{
            "relay_id": r.relay_id, "received_at": str(r.received_at),
            "channel": r.channel, "origin": r.origin, "payload": r.payload,
            "trust": r.trust,
        } for r in rows]
        return ToolResult("xdomain_receive", True, _rows_to_str(data), is_stub=False)
    finally:
        db.close()


# 动作类工具：沿用既有 STUB 诚实措辞——如实声明未接入真实环境、未执行任何动作。
def xdomain_forward(**kwargs) -> ToolResult:
    return ToolResult(
        "xdomain_forward", True,
        "[STUB] 跨域转发未执行：无真实外部信道接入，未向任何信道发送内容。",
        is_stub=True)


def risk_level_publish(**kwargs) -> ToolResult:
    return ToolResult(
        "risk_level_publish", True,
        "[STUB] 风险定级发布未执行：无真实发布通道接入，未发布任何风险等级。",
        is_stub=True)


# 工具名 → 实现。log_query 复用 backend/tools.py 既有实现。
REAL_TOOLS = {
    "situation_query": situation_query,
    "spectrum_query": spectrum_query,
    "xdomain_receive": xdomain_receive,
    "xdomain_forward": xdomain_forward,
    "risk_level_publish": risk_level_publish,
    "log_query": log_query,
}

# 工具名 → JSON Schema。让 LLM 按正确参数调用。
TOOL_SCHEMAS = {
    "situation_query": {"type": "object", "properties": {"query": {"type": "string"}}},
    "spectrum_query": {"type": "object", "properties": {"query": {"type": "string"}}},
    "xdomain_receive": {"type": "object", "properties": {"query": {"type": "string"}}},
    "xdomain_forward": {"type": "object", "properties": {}},
    "risk_level_publish": {"type": "object", "properties": {}},
    "log_query": {"type": "object", "properties": {"query": {"type": "string"}}},
}
