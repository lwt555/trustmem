"""SOC 工具的真实实现 —— 查询本地 SQLite 业务数据表。

替换 core/agent/tools.py 里的 STUB 占位实现。这些工具读的是真实结构的数据
（assets / siem_logs / threat_intel 三张表），返回 is_stub=False，下游 Agent
会把它当真实数据采信，再进入 PDP 可信度衰减链。
"""
from __future__ import annotations

import json
import re

from core.agent.tools import ToolResult

from backend.db.database import get_db
from backend.db.models import Asset, SiemLog, ThreatIntel


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


def _any_token_in(tokens: list[str], *fields: str | None) -> bool:
    """任意 token 命中任意字段即匹配（子串，大小写不敏感）。"""
    for tok in tokens:
        for f in fields:
            if tok in (f or "").lower():
                return True
    return False


def asset_query(query: str | None = None, **kwargs) -> ToolResult:
    """查询资产台账。可按 hostname / ip / env / owner / tags 过滤。"""
    db = get_db()
    try:
        tokens = _tokens(query)
        rows = db.query(Asset).all()
        if tokens:
            rows = [a for a in rows if _any_token_in(
                tokens, a.ip, a.hostname, a.env, a.owner, a.os,
                " ".join(a.tags or []))]
        data = [{
            "asset_id": a.asset_id, "hostname": a.hostname, "ip": a.ip,
            "os": a.os, "owner": a.owner, "env": a.env,
            "sensitivity": a.sensitivity, "trust": a.trust, "tags": a.tags,
        } for a in rows]
        return ToolResult("asset_query", True, _rows_to_str(data), is_stub=False)
    finally:
        db.close()


def log_query(query: str | None = None, **kwargs) -> ToolResult:
    """查询 SIEM 日志。可按 IP / hostname / event_type / user / 原文过滤。"""
    db = get_db()
    try:
        tokens = _tokens(query)
        rows = db.query(SiemLog).order_by(SiemLog.ts.desc()).all()
        if tokens:
            rows = [l for l in rows if _any_token_in(
                tokens, l.source_ip, l.dest_ip, l.hostname, l.event_type,
                l.user, l.raw)]
        data = [{
            "ts": str(l.ts), "source_ip": l.source_ip, "dest_ip": l.dest_ip,
            "hostname": l.hostname, "event_type": l.event_type,
            "user": l.user, "outcome": l.outcome, "raw": l.raw,
            "trust": l.trust,
        } for l in rows]
        return ToolResult("log_query", True, _rows_to_str(data), is_stub=False)
    finally:
        db.close()


def _intel_rows(db, q: str | None):
    tokens = _tokens(q)
    rows = db.query(ThreatIntel).all()
    if tokens:
        rows = [t for t in rows if _any_token_in(
            tokens, t.ioc_value, t.ioc_type, t.ttp, t.source, t.description)]
    return [{
        "ioc_type": t.ioc_type, "ioc_value": t.ioc_value, "source": t.source,
        "confidence": t.confidence, "ttp": t.ttp, "description": t.description,
    } for t in rows]


def intel_fetch(url: str | None = None, **kwargs) -> ToolResult:
    """抓取威胁情报。按 IOC 值 / 来源 / TTP 关键字过滤，返回结构化 IOC。"""
    db = get_db()
    try:
        data = _intel_rows(db, url)
        return ToolResult("intel_fetch", True, _rows_to_str(data), is_stub=False)
    finally:
        db.close()


def web_search(query: str | None = None, **kwargs) -> ToolResult:
    """搜索公开威胁情报源。当前落到本地 threat_intel 表，按关键字匹配。"""
    db = get_db()
    try:
        data = _intel_rows(db, query)
        return ToolResult("web_search", True, _rows_to_str(data), is_stub=False)
    finally:
        db.close()


# 工具名 → 真实实现。供 API 层注册时替换 STUB。
REAL_TOOLS = {
    "asset_query": asset_query,
    "log_query": log_query,
    "intel_fetch": intel_fetch,
    "web_search": web_search,
}

# 工具名 → JSON Schema。让 LLM 按正确参数调用（替换原来的空 schema）。
TOOL_SCHEMAS = {
    "web_search": {"type": "object", "properties": {"query": {"type": "string"}},
                   "required": ["query"]},
    "intel_fetch": {"type": "object", "properties": {"url": {"type": "string"}}},
    "log_query": {"type": "object", "properties": {"query": {"type": "string"}}},
    "asset_query": {"type": "object", "properties": {"query": {"type": "string"}}},
    "file_read": {"type": "object", "properties": {"path": {"type": "string"}}},
    "file_write": {"type": "object", "properties": {
        "path": {"type": "string"}, "content": {"type": "string"}}},
    "exec_command": {"type": "object", "properties": {"command": {"type": "string"}}},
    "firewall_block": {"type": "object", "properties": {"ip": {"type": "string"}}},
    "host_isolate": {"type": "object", "properties": {"host": {"type": "string"}}},
}
