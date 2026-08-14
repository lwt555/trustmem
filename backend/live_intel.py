"""真实威胁情报源接入 —— 拉取 + 写入管线入库 + 可信度标注。

设计原则(对齐 labels.py 与 TR 表):
  - Intel 抓公开互联网源 → provenance_trust = T1_LOW(可能被投毒,符合 T1 定义)
  - Log / Auditor 读内部源 → T3_HIGH(本地可控),沿用 SQLite 种子表
  - 取数只是第一步;可信度标注发生在 WritePipeline.write() 那一刻,
    不是工具自己填的。只查不写 = 无标注。

真实源(默认 ThreatFox,免费无需 key):
  - ThreatFox   POST https://threatfox-api.abuse.ch/api/v1/   (get_iocs)
  - URLhaus     POST https://urlhaus-api.abuse.ch/v1/urls/recent/
  - CISA KEV    GET  https://www.cisa.gov/.../known_exploited_vulnerabilities.json
  - OTX         需 OTX_API_KEY

失败策略:fail-closed。拉不到就返回明确的空结果 + is_stub=True 语义标记,
绝不编造 IOC(否则等于系统自投毒)。
"""
from __future__ import annotations

import json
import os
import re

import requests

from core.agent.tools import ToolResult
from core.labels import (AgentLabel, Clearance, Trust, Layer, MemoryType,
                         WriteOp, TaskScope, IngestMode)

# 每个源的超时与拉取上限(演示够用,别把答辩现场卡死)
_TIMEOUT = 12
_MAX_IOCS = 25


# ══════════════════════════════════════════════════════════════
# 1. 真实源拉取(纯取数,不入库)
# ══════════════════════════════════════════════════════════════
def fetch_threatfox(days: int = 1) -> list[dict]:
    """ThreatFox 近 N 天的恶意 IOC。免费无需 key。"""
    r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                      json={"query": "get_iocs", "days": days}, timeout=_TIMEOUT)
    r.raise_for_status()
    data = r.json().get("data", []) or []
    out = []
    for it in data[:_MAX_IOCS]:
        out.append({
            "ioc_type": it.get("ioc_type", ""),
            "ioc_value": it.get("ioc", ""),
            "source": f"ThreatFox/{it.get('threat_type', '')}",
            "malware": it.get("malware_printable", ""),
            "confidence_pct": it.get("confidence_level", 0),
            "first_seen": it.get("first_seen", ""),
        })
    return out


def fetch_urlhaus() -> list[dict]:
    """URLhaus 最近提交的恶意 URL。免费无需 key。"""
    r = requests.post("https://urlhaus-api.abuse.ch/v1/urls/recent/",
                      data={}, timeout=_TIMEOUT)
    r.raise_for_status()
    data = r.json().get("urls", []) or []
    out = []
    for it in data[:_MAX_IOCS]:
        out.append({
            "ioc_type": "url",
            "ioc_value": it.get("url", ""),
            "source": f"URLhaus/{it.get('threat', '')}",
            "malware": ",".join(it.get("tags", []) or []),
            "first_seen": it.get("date_added", ""),
        })
    return out


def fetch_cisa_kev(limit: int = _MAX_IOCS) -> list[dict]:
    """CISA 已知被利用漏洞目录(政府源)。"""
    r = requests.get(
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json", timeout=_TIMEOUT)
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities", []) or []
    out = []
    for v in vulns[:limit]:
        out.append({
            "ioc_type": "cve",
            "ioc_value": v.get("cveID", ""),
            "source": "CISA-KEV",
            "malware": v.get("vendorProject", ""),
            "description": v.get("vulnerabilityName", ""),
        })
    return out


_SOURCES = {
    "threatfox": fetch_threatfox,
    "urlhaus": fetch_urlhaus,
    "cisa_kev": fetch_cisa_kev,
}


def _active_source() -> str:
    # 默认 CISA KEV：abuse.ch(ThreatFox/URLhaus)会拒绝云代理出口 IP(401)，
    # 需换真实出口或配 auth-key 才可用；CISA 政府源对云 IP 无限制。
    return os.environ.get("TRUSTMEM_INTEL_SOURCE", "cisa_kev").lower()


# ══════════════════════════════════════════════════════════════
# 2. 工具封装(供 Intel 智能体调用;取数,标 is_stub=False)
# ══════════════════════════════════════════════════════════════
def intel_fetch_live(url: str | None = None, **kwargs) -> ToolResult:
    """Intel 的真实情报抓取工具。fail-closed:拉不到不编造。"""
    src = _active_source()
    fetcher = _SOURCES.get(src, fetch_threatfox)
    try:
        iocs = fetcher()
    except Exception as e:  # noqa: BLE001 — 演示健壮性优先
        return ToolResult(
            "intel_fetch", success=False,
            output=f"[真实源 {src} 拉取失败,未编造任何 IOC] {type(e).__name__}: {e}",
            error=str(e), is_stub=True)
    if not iocs:
        return ToolResult("intel_fetch", True,
                          f"[真实源 {src} 返回空,无近期 IOC]", is_stub=False)
    return ToolResult("intel_fetch", True,
                      json.dumps({"source": src, "count": len(iocs),
                                  "iocs": iocs}, ensure_ascii=False, indent=1),
                      is_stub=False)


def web_search_live(query: str | None = None, **kwargs) -> ToolResult:
    """web_search 落到真实情报源(与 intel_fetch 同源),按 CVE 号或关键词过滤。

    LLM 生成的 query 是自然语言短语,不能用「整串子串匹配」——那几乎必然 miss。
    拆两条路:
      1. query 含 CVE 编号 → 用 CVE 号精确匹配 ioc_value(最可靠)
      2. 否则拆成非停用词 token,任一 token 命中 IOC 字段即返回(容忍多余措辞)
    """
    res = intel_fetch_live()
    if not res.success or res.is_stub or query is None:
        return res
    try:
        payload = json.loads(res.output)
        q = query.lower()
        m = re.search(r"cve-\d{4}-\d+", q)
        if m:
            cve = m.group(0)
            hit = [i for i in payload["iocs"]
                   if i.get("ioc_value", "").lower() == cve]
            if not hit:
                # 前 25 条没命中 → 全量拉 KEV 精确找,演示别翻车
                hit = [i for i in fetch_cisa_kev(limit=5000)
                       if i.get("ioc_value", "").lower() == cve]
        else:
            stop = {"the", "a", "an", "of", "in", "on", "for", "to", "and",
                    "or", "is", "are", "was", "were", "with", "by", "from",
                    "at", "as", "vs", "known", "exploited", "exploit",
                    "vulnerability", "vulnerabilities", "wild", "cve",
                    "jetbrains"}
            tokens = [w for w in re.split(r"[^a-z0-9\-\.]+", q)
                      if len(w) > 2 and w not in stop]
            hit = []
            for i in payload["iocs"]:
                blob = json.dumps(i, ensure_ascii=False).lower()
                if any(t in blob for t in tokens):
                    hit.append(i)
        payload["iocs"], payload["count"] = hit, len(hit)
        return ToolResult("web_search", True,
                          json.dumps(payload, ensure_ascii=False, indent=1),
                          is_stub=False)
    except Exception:  # noqa: BLE001
        return res


# 供 API 层注册时替换 STUB / 覆盖 SQLite 版本
LIVE_TOOLS = {
    "intel_fetch": intel_fetch_live,
    "web_search": web_search_live,
}


# ══════════════════════════════════════════════════════════════
# 3. 入库(关键步:走 WritePipeline,可信度标注在这里发生)
# ══════════════════════════════════════════════════════════════
def ingest_live_intel(
    *, write_pipeline, intel_agent: AgentLabel, session, anchor=None,
    source: str | None = None, task_binding: str = "soc",
) -> dict:
    """把真实源的 IOC 逐条写入共享记忆库。

    每条 IOC:
      - op = VERBATIM(原样引入,溯源指针 = 源名),写时演算按 δ=0 处理
      - 但 provenance_trust 最终由 compute_trust 钉死:因 Intel 固有 T1_LOW,
        meet(输入∅=T3, 主体 T1) = T1 → 公开情报标为 T1_LOW,正是设计意图
      - target_sensitivity = L0_PUBLIC(公开情报本就是公开的)
    返回 {'written': n, 'trust': 'T1_LOW', 'chunk_ids': [...], 'source': ...}。
    """
    src = source or _active_source()
    res = intel_fetch_live()
    if not res.success or res.is_stub:
        return {"written": 0, "reason": res.output, "source": src}
    payload = json.loads(res.output)

    # 公开情报的任务区间:低完整性可进(t_ctx_min=T0),密级公开(c_ctx_max=L0)
    scope = TaskScope(task_id=task_binding, c_ctx_max=Clearance.L0_PUBLIC,
                      t_ctx_min=Trust.T0_UNTRUSTED, ingest=IngestMode.LEARN)
    if anchor is not None:
        from core.task_scope import commit_scope
        commit_scope(scope, anchor)

    written, chunk_ids = 0, []
    for ioc in payload["iocs"]:
        content = (f"[{ioc['ioc_type']}] {ioc['ioc_value']} "
                   f"| 来源={ioc['source']} | {ioc.get('malware', '')} "
                   f"{ioc.get('description', '')}").strip()
        r = write_pipeline.write(
            agent=intel_agent, session=session, content=content,
            target_sensitivity=Clearance.L0_PUBLIC,
            target_layer=Layer.CONCLUSION,
            memory_type=MemoryType.INTEL,
            op=WriteOp.VERBATIM,
            input_texts=[content],
            task_binding=task_binding,
            scope=scope, anchor=anchor,
        )
        if r.allowed:
            written += 1
            chunk_ids.append(r.chunk_id)
    trust_name = "—"
    if chunk_ids:
        m = write_pipeline.mem_store.get(chunk_ids[0])
        trust_name = m.provenance_trust.name if m else "—"
    return {"written": written, "trust": trust_name,
            "chunk_ids": chunk_ids, "source": src}
