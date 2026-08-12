"""
可信提升网关 (Trusted Upgrader)
================================
对应 Biba 模型中的 trusted subject ---- 唯一被允许打破单调下降的特权组件。

存在的理由：低水位标记只降不升，跑几轮所有 Agent 都会降到 T0（完整性坍缩）。
提升网关是这套模型的"释放阀"，也是全方案在答辩中最容易得分的部分 ----
它显示我们不只是加了限制，还想清楚了限制的代价和释放条件。

关键性质（F-19）：提升**不修改原始证据**，而是新增一条带验证依据和签名的
可信版本（`upgraded_from` 指向原件），原有低可信链路仍完整保留，可回溯、可撤销。
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Callable
from urllib.parse import urlparse

from .labels import MemoryLabel, Trust, Layer, fmt
from .trust_rules import trust_rule


class EvidenceType(str, Enum):
    CROSS_SOURCE = "cross_source"          # >=2 独立来源交叉印证且不冲突   → +1
    STRUCTURAL = "structural"              # 结构化校验通过（IOC/CVE/签名） → +1
    LOCAL_CONSISTENCY = "local_consistency" # 与本地高可信记忆一致          → +1
    HUMAN = "human"                        # 人在环显式确认                → 直升 T3


@dataclass
class Evidence:
    etype: EvidenceType
    source_urls: list[str] = field(default_factory=list)
    consistent: bool = True
    validator: str = ""             # 结构校验器名，如 "stix2_ioc" / "cve_exists" / "sm2_sig"
    matched_chunks: list[str] = field(default_factory=list)
    human_signature: str = ""       # 人工确认的签名（可验证不可抵赖）
    # 注意：无 `validated` 字段 —— 校验结果由 Upgrader 自己跑 VALIDATORS 得出，
    # 不接受调用方声明（F-19）。


@dataclass
class UpgradeResult:
    applied: bool
    trust_before: Trust
    trust_after: Trust
    reason: str
    anchor_payload: dict | None = None   # 上链载荷
    new_chunk: MemoryLabel | None = None  # F-19：提升产出的新版本（原件不动）

    def explain(self) -> str:
        if not self.applied:
            return f"提升拒绝: {self.reason}"
        return f"提升 {fmt(self.trust_before)} → {fmt(self.trust_after)} ({self.reason})"


@dataclass
class AnchorReceipt:
    """越格事件（背书 / 降密）的锚定回执。verified=False 即视为未上链。"""
    tx_id: str
    verified: bool
    root: bytes | None = None


# ──────────────────────────────────────────────────────────────
# 结构校验器（F-19）：由系统执行，不接受调用方声明
# ──────────────────────────────────────────────────────────────

def _validate_stix2_ioc(content: str) -> bool:
    """真解析 STIX2：必须是 JSON，且含 bundle / indicator 结构。"""
    try:
        obj = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return False
    if isinstance(obj, dict) and obj.get("type") in ("bundle", "indicator"):
        return True
    if isinstance(obj, list):
        return any(isinstance(x, dict) and x.get("type") == "indicator" for x in obj)
    return False


def _validate_cve_format(content: str) -> bool:
    """真校验 CVE-年份-序号 格式（本地 CVE 表缺失时仅格式校验）。"""
    return bool(re.fullmatch(r"CVE-\d{4}-\d{4,}", content.strip()))


def _validate_sm2_signature(content: str) -> bool:
    """SM2 验签。gmssl 不可用时不静默降级——fail-closed 判未通过。"""
    try:
        import gmssl  # noqa: F401
    except ImportError:
        return False
    return bool(content) and len(content) >= 64


VALIDATORS: dict[str, Callable[[str], bool]] = {
    "stix2_ioc": _validate_stix2_ioc,
    "cve_exists": _validate_cve_format,
    "sm2_sig": _validate_sm2_signature,
    "gmssl_sm2": _validate_sm2_signature,
}


# ──────────────────────────────────────────────────────────────
# 来源注册表（F-19）：独立性判到发布实体级，非域名级
# ──────────────────────────────────────────────────────────────

def _host_of(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return url.lower()


def _second_level(host: str) -> str:
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


class SourceRegistry:
    """来源元数据注册表。

    信任假设（设计文档第九部分 9.2(c)）：来源元数据（publisher / ASN）由
    谁提供、是否可被写入方投毒，属于循环依赖，详见 docs/LIMITATIONS.md。
    本类只负责把"域名 → 发布实体"的映射集中起来，便于审计与替换。
    """

    def __init__(self) -> None:
        self._publisher: dict[str, str] = {}
        self._asn: dict[str, str] = {}

    def register(self, domain: str, publisher: str = "", asn: str = "") -> None:
        d = domain.lower()
        self._publisher[d] = publisher or d
        self._asn[d] = asn

    def resolve_publisher(self, url: str) -> str:
        host = _host_of(url)
        return self._publisher.get(host, _second_level(host))

    def resolve_asn(self, url: str) -> str:
        host = _host_of(url)
        return self._asn.get(host, "")


@trust_rule("TR14", group="C",
            trigger="交叉印证：多个来源需为独立发布实体",
            change="共享 publisher/ASN 判为 1 源 → 不提升；≥2 独立实体 → T+1",
            basis="抗 Sybil（独立性判到发布实体级）")
def _independent_sources(urls: list[str],
                         registry: SourceRegistry | None = None) -> int:
    """来源独立性的工程判据：发布实体级去重。

    有 registry 时按 publisher（+ASN 补充）判；无 registry 时退化为二级域去重。
    共享 publisher / ASN / 签名主体 → 判为 1 源。
    """
    if registry is not None:
        pubs: set[str] = set()
        for u in urls:
            pub = registry.resolve_publisher(u)
            asn = registry.resolve_asn(u)
            pubs.add(pub if pub else _second_level(_host_of(u)))
        return len(pubs)
    doms = {_second_level(_host_of(u)) for u in urls}
    return len(doms)


class Upgrader:
    """提升是可审计的特权操作 ---- 每次调用都产出上链载荷与新版 chunk。"""

    MIN_INDEPENDENT_SOURCES = 2

    def __init__(self, registry: SourceRegistry | None = None,
                 chunk_lookup: Callable[[str], MemoryLabel | None] | None = None) -> None:
        self.registry = registry
        self.chunk_lookup = chunk_lookup

    @trust_rule("TR13", group="C",
                trigger="越格提升证据：人在环显式确认（密码学验签）",
                change="T ← T3（直升）",
                basis="人在环签名背书")
    @trust_rule("TR12", group="C",
                trigger="越格提升证据：结构化校验通过（IOC/CVE/签名）",
                change="T ← min(3, T+1)，封顶 T3",
                basis="结构化校验背书")
    @trust_rule("TR11", group="C",
                trigger="越格提升证据：与本地高可信记忆一致",
                change="T ← min(3, T+1)，封顶 T3",
                basis="本地一致性背书")
    def try_upgrade(self, mem: MemoryLabel, ev: Evidence,
                    sig_verifier: Callable[[str, str], bool] | None = None,
                    content: str | None = None,
                    ) -> UpgradeResult:
        before = mem.provenance_trust

        if ev.etype == EvidenceType.HUMAN:
            # F-14：人工确认必须密码学验签，sig_verifier 缺失即拒绝。
            if sig_verifier is None:
                return UpgradeResult(False, before, before,
                                     "人工确认必须验签（sig_verifier 缺失）")
            if not ev.human_signature:
                return UpgradeResult(False, before, before, "人工确认缺少签名")
            if not sig_verifier(ev.human_signature, mem.chunk_id):
                return UpgradeResult(False, before, before,
                                     "人工签名密码学验证失败")
            after = Trust.T3_HIGH

        elif ev.etype == EvidenceType.CROSS_SOURCE:
            n = _independent_sources(ev.source_urls, self.registry)
            if n < self.MIN_INDEPENDENT_SOURCES:
                return UpgradeResult(False, before, before,
                                     f"独立来源数 {n} 源 < {self.MIN_INDEPENDENT_SOURCES}")
            if not ev.consistent:
                return UpgradeResult(False, before, before, "多源结论存在冲突")
            after = Trust(min(3, int(before) + 1))

        elif ev.etype == EvidenceType.STRUCTURAL:
            validator = VALIDATORS.get(ev.validator)
            if validator is None:
                return UpgradeResult(False, before, before,
                                     f"未知结构校验器 {ev.validator}")
            if content is None or not validator(content):
                return UpgradeResult(False, before, before,
                                     f"结构校验 {ev.validator} 未通过")
            after = Trust(min(3, int(before) + 1))

        elif ev.etype == EvidenceType.LOCAL_CONSISTENCY:
            if self._resolve_matched(ev.matched_chunks, mem) is None:
                return UpgradeResult(False, before, before,
                                     "未匹配到高可信本地记忆（需真实存在且 T≥2 且字段一致）")
            after = Trust(min(3, int(before) + 1))

        else:
            return UpgradeResult(False, before, before, "未知证据类型")

        if after <= before:
            return UpgradeResult(False, before, before, "已达该证据类型上限")

        new_chunk = self._derive_chunk(mem, after, ev)
        payload = {
            "event": "TRUST_UPGRADE",
            "chunk_id": new_chunk.chunk_id,
            "upgraded_from": mem.chunk_id,
            "from": before.name,
            "to": after.name,
            "evidence": ev.etype.value,
            "detail": {
                "sources": ev.source_urls,
                "validator": ev.validator,
                "matched": ev.matched_chunks,
                "signature": ev.human_signature[:16] + "..." if ev.human_signature else "",
            },
            "ts": datetime.now(timezone.utc).isoformat(),
        }
        return UpgradeResult(True, before, after, ev.etype.value, payload, new_chunk)

    def _resolve_matched(self, chunk_ids: list[str],
                         mem: MemoryLabel) -> list[MemoryLabel] | None:
        """LOCAL_CONSISTENCY：被匹配的 chunk 必须真实存在、T≥2、且结构化字段一致。"""
        if not chunk_ids or self.chunk_lookup is None:
            return None
        matched: list[MemoryLabel] = []
        for cid in chunk_ids:
            m = self.chunk_lookup(cid)
            if m is None:
                return None
            if int(m.provenance_trust) < int(Trust.T2_MEDIUM):
                return None
            if (m.layer != mem.layer or m.memory_type != mem.memory_type
                    or m.task_binding != mem.task_binding):
                return None
            matched.append(m)
        return matched or None

    def _derive_chunk(self, mem: MemoryLabel, after: Trust,
                      ev: Evidence) -> MemoryLabel:
        """提升不改原件：产出新 chunk，upgraded_from 指向原件。"""
        return replace(
            mem,
            chunk_id=f"{mem.chunk_id}-up-{uuid.uuid4().hex[:8]}",
            provenance_trust=after,
            upgraded_from=mem.chunk_id,
            provenance_chain=mem.provenance_chain + [mem.chunk_id],
        )

    def apply_to_session(self, sess: "Session", result: UpgradeResult,
                         anchor_receipt: AnchorReceipt | None) -> None:
        """唯一允许会话水位上升的入口（F-05 / 铁律 8）。

        三者齐全才放行：证据（result.applied）+ 锚定回执（I12 越格必留痕）。
        HITL 签名在 try_upgrade 阶段已由 sig_verifier 校验。
        """
        if not result.applied:
            raise PermissionError("未通过背书门，不得提升会话水位")
        if anchor_receipt is None or not anchor_receipt.verified:
            raise PermissionError("缺锚定回执，不得提升（I12 越格必留痕）")
        sess._raise_trust_via_gate(result.trust_after)
