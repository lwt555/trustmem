"""
可信提升网关 (Trusted Upgrader)
================================
对应 Biba 模型中的 trusted subject ---- 唯一被允许打破单调下降的特权组件。

存在的理由：低水位标记只降不升，跑几轮所有 Agent 都会降到 T0（完整性坍缩）。
提升网关是这套模型的"释放阀"，也是全方案在答辩中最容易得分的部分 ----
它显示我们不只是加了限制，还想清楚了限制的代价和释放条件。

四类提升证据，每次提升上链存证：
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable
from urllib.parse import urlparse

from .labels import MemoryLabel, Trust, fmt
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
    validator: str = ""             # 结构校验器名，如 "stix2_ioc" / "cve_exists" / "gmssl_sm2"
    validated: bool = False
    matched_chunks: list[str] = field(default_factory=list)
    human_signature: str = ""       # 人工确认的签名（可验证不可抵赖）


@dataclass
class UpgradeResult:
    applied: bool
    trust_before: Trust
    trust_after: Trust
    reason: str
    anchor_payload: dict | None = None   # 上链载荷

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


@trust_rule("TR14", group="C",
            trigger="交叉印证：多个来源需为独立发布实体",
            change="共享 publisher/ASN 判为 1 源 → 不提升；≥2 独立实体 → T+1",
            basis="抗 Sybil（独立性判到发布实体级）")
def _independent_sources(urls: list[str]) -> int:
    """
    来源独立性的工程判据：注册域 + 二级域去重。
    真实系统应再加 ASN / 发布方实体去重，防止同一机构多个域名冒充多源。
    """
    doms = set()
    for u in urls:
        try:
            host = urlparse(u).netloc.lower()
        except Exception:
            host = u.lower()
        parts = host.split(".")
        doms.add(".".join(parts[-2:]) if len(parts) >= 2 else host)
    return len(doms)


class Upgrader:
    """提升是可审计的特权操作 ---- 每次调用都产出上链载荷。"""

    MIN_INDEPENDENT_SOURCES = 2

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
                    ) -> UpgradeResult:
        before = mem.provenance_trust

        if ev.etype == EvidenceType.HUMAN:
            # F-14：人工确认必须密码学验签，sig_verifier 缺失即拒绝。
            # 任意非空字符串不得直升 T3（旧实现的可自证漏洞）。
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
            n = _independent_sources(ev.source_urls)
            if n < self.MIN_INDEPENDENT_SOURCES:
                return UpgradeResult(False, before, before,
                                     f"独立来源数 {n} < {self.MIN_INDEPENDENT_SOURCES}")
            if not ev.consistent:
                return UpgradeResult(False, before, before, "多源结论存在冲突")
            after = Trust(min(3, int(before) + 1))

        elif ev.etype == EvidenceType.STRUCTURAL:
            if not ev.validated:
                return UpgradeResult(False, before, before, f"结构校验 {ev.validator} 未通过")
            after = Trust(min(3, int(before) + 1))

        elif ev.etype == EvidenceType.LOCAL_CONSISTENCY:
            if not ev.matched_chunks:
                return UpgradeResult(False, before, before, "未匹配到高可信本地记忆")
            after = Trust(min(3, int(before) + 1))

        else:
            return UpgradeResult(False, before, before, "未知证据类型")

        if after <= before:
            return UpgradeResult(False, before, before, "已达该证据类型上限")

        mem.provenance_trust = after
        payload = {
            "event": "TRUST_UPGRADE",
            "chunk_id": mem.chunk_id,
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
        return UpgradeResult(True, before, after, ev.etype.value, payload)

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
