"""
对抗性设计一致性回归（由根目录 probe_design_conformance.py 迁移而来）。

本文件是「防止后续改动再次偏离设计文档」的永久回归：每一条都对应
《TrustMem 系统完整梳理》里的一条不变式或铁律，判定方向与实现直接对拍。

修补完成后本文件应 0 失败；任何一项变红都意味着某条安全语义被再次反转或架空。
"""
from __future__ import annotations

import ast
import inspect
from datetime import datetime, timedelta, timezone

import pytest

from core.labels import (
    AgentLabel, MemoryLabel, Clearance, Trust, Layer, Role, MemoryType,
    TaskScope, IngestMode,
)
from core.session import Session, SessionStore, AbsorbMode
from core.pdp import PDP
from core.topology import Topology
from core.verdict import Verdict
from core.upgrader import Upgrader, Evidence, EvidenceType, SourceRegistry, AnchorReceipt
from core.crypto.abe import abe_setup, abe_issue_key, abe_encrypt, abe_decrypt
from core.isolated_llm import ControlFlowBudget
from core.varstore import VarStore


# ──────────────────────────────────────────────────────────────
# 夹具与构造器
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def topo() -> Topology:
    t = Topology()
    t.add_agent("planner")
    t.add_agent("analyst", parent="planner")
    t.add_agent("intel", parent="planner")
    return t


def mk_agent(aid: str, role: Role, cl: Clearance, tr: Trust) -> AgentLabel:
    now = datetime.now(timezone.utc)
    return AgentLabel(
        agent_id=aid, role=role, clearance=cl, trust_intrinsic=tr,
        task_domain={"soc"}, collab_group={"a"},
        tool_scope={"web_search", "file_write", "firewall_block", "log_query"},
        ttl_start=now, ttl_end=now + timedelta(days=1), epoch=0,
    )


def mk_mem(cid: str, sens: Clearance, tr: Trust,
           layer: Layer = Layer.CONCLUSION, owner: str = "intel") -> MemoryLabel:
    return MemoryLabel(
        chunk_id=cid, sensitivity=sens, provenance_trust=tr, layer=layer,
        memory_type=MemoryType.INTEL, owner_agent=owner,
        task_binding="soc", collab_group={"a"}, epoch=0,
    )


# ──────────────────────────────────────────────────────────────
# 1. I8 隐藏中立性：HIDE 不改变任何水位与预算
# ──────────────────────────────────────────────────────────────

def _snapshot(s: Session):
    return (s.c_eff, s.t_eff, s.t_eff_ctl)


def test_I8_consult_changes_nothing(topo):
    analyst = mk_agent("analyst", Role.ANALYST, Clearance.L3_SECRET, Trust.T3_HIGH)
    s = Session.start("s1", analyst, "soc")
    scope = TaskScope("soc", Clearance.L3_SECRET, Trust.T0_UNTRUSTED, IngestMode.CONSULT)
    m = mk_mem("m1", Clearance.L2_SENSITIVE, Trust.T1_LOW)
    pdp = PDP(topo)
    before = _snapshot(s)
    d = pdp.can_read_scoped(analyst, m, s, scope)
    assert d.verdict is Verdict.HIDE
    assert _snapshot(s) == before, "CONSULT 裁决 HIDE 后三水位必须纹丝不动"


def test_I8_scope_hide_changes_nothing(topo):
    analyst = mk_agent("analyst", Role.ANALYST, Clearance.L3_SECRET, Trust.T3_HIGH)
    s = Session.start("s2", analyst, "soc")
    scope = TaskScope("s2", Clearance.L1_INTERNAL, Trust.T0_UNTRUSTED, IngestMode.LEARN)
    m = mk_mem("m2", Clearance.L3_SECRET, Trust.T1_LOW)
    pdp = PDP(topo)
    before = _snapshot(s)
    d = pdp.can_read_scoped(analyst, m, s, scope)
    assert d.verdict is Verdict.HIDE
    assert _snapshot(s) == before, "超密级区间 HIDE 后水位不动"


def test_I8_deny_changes_nothing(topo):
    low = mk_agent("low", Role.RETRIEVER, Clearance.L0_PUBLIC, Trust.T2_MEDIUM)
    s = Session.start("s3", low, "soc")
    m = mk_mem("m3", Clearance.L3_SECRET, Trust.T3_HIGH)
    pdp = PDP(topo)
    before = _snapshot(s)
    pdp.can_read(low, m, s)
    assert _snapshot(s) == before, "DENY 也不得改变水位"


# ──────────────────────────────────────────────────────────────
# 2. 铁律 5：跌破 t_ctx_min 应 HIDE，不是 DENY
# ──────────────────────────────────────────────────────────────

def test_F07_trust_below_floor_is_hide(topo):
    analyst = mk_agent("analyst", Role.ANALYST, Clearance.L3_SECRET, Trust.T3_HIGH)
    s = Session.start("s4", analyst, "soc")
    scope = TaskScope("s4", Clearance.L3_SECRET, Trust.T3_HIGH, IngestMode.LEARN)
    m = mk_mem("m4", Clearance.L0_PUBLIC, Trust.T1_LOW)
    d = PDP(topo).can_read_scoped(analyst, m, s, scope)
    assert d.verdict is Verdict.HIDE
    assert d.denied_by == "TaskScope-T"


def test_F07_uses_joined_watermark_not_raw_label(topo):
    analyst = mk_agent("analyst", Role.ANALYST, Clearance.L3_SECRET, Trust.T3_HIGH)
    s = Session.start("s5", analyst, "soc")
    s.absorb("dirty", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED)  # t_eff_ctl → T0
    scope = TaskScope("s5", Clearance.L3_SECRET, Trust.T2_MEDIUM, IngestMode.LEARN)
    m = mk_mem("m5", Clearance.L0_PUBLIC, Trust.T3_HIGH)
    d = PDP(topo).can_read_scoped(analyst, m, s, scope)
    # would_t = min(t_eff_ctl=T0, mem.trust=T3) = T0 < T2，必须 HIDE
    assert d.verdict is Verdict.HIDE


# ──────────────────────────────────────────────────────────────
# 3. I1 无读上：越权读是硬拒绝，不可 HIDE
# ──────────────────────────────────────────────────────────────

def test_I1_no_read_up_is_hard_deny(topo):
    low = mk_agent("low", Role.RETRIEVER, Clearance.L0_PUBLIC, Trust.T2_MEDIUM)
    s = Session.start("s6", low, "soc")
    m = mk_mem("m6", Clearance.L3_SECRET, Trust.T3_HIGH)
    d = PDP(topo).can_read(low, m, s)
    assert d.verdict is Verdict.DENY
    assert d.hideable is False
    assert d.denied_by == "BLP-SimpleSecurity"


# ──────────────────────────────────────────────────────────────
# 4. P-F 出口约束方向：c_eff ⊑ readers
# ──────────────────────────────────────────────────────────────

def test_F02_high_watermark_blocks_public_egress(topo):
    analyst = mk_agent("analyst", Role.ANALYST, Clearance.L3_SECRET, Trust.T3_HIGH)
    s = Session.start("s7", analyst, "soc")
    s.absorb("x", Clearance.L3_SECRET, Trust.T3_HIGH)   # c_eff → L3
    d = PDP(topo).can_invoke(analyst, s, "web_search", "egress:public")
    assert d.verdict is Verdict.DENY
    assert d.denied_by == "Flow-Egress"


def test_F02_param_label_checked_independently(topo):
    analyst = mk_agent("analyst", Role.ANALYST, Clearance.L3_SECRET, Trust.T3_HIGH)
    s = Session.start("s7b", analyst, "soc")
    # 上下文干净（c_eff=L0），但参数标签带 L3 机密 → 参数级出口约束必须独立拦截
    d = PDP(topo).can_invoke(analyst, s, "web_search", "e",
                             arg_labels=[mk_mem("secret", Clearance.L3_SECRET, Trust.T3_HIGH)])
    assert d.verdict is Verdict.DENY
    assert d.denied_by == "Flow-Egress-Args"


# ──────────────────────────────────────────────────────────────
# 5. P-T 门查的是 t_eff_ctl，不是 t_eff
# ──────────────────────────────────────────────────────────────

def test_F03_pt_uses_ctl_watermark(topo):
    analyst = mk_agent("analyst", Role.ANALYST, Clearance.L3_SECRET, Trust.T3_HIGH)
    s = Session.start("s8", analyst, "soc")
    s.t_eff = Trust.T3_HIGH
    s.t_eff_ctl = Trust.T0_UNTRUSTED     # 控制流已污染
    d = PDP(topo).can_invoke(analyst, s, "firewall_block", "fp")
    assert d.verdict is Verdict.DENY
    assert d.denied_by == "P-T-ControlFlow"


def test_F03_provenance_and_ctl_both_checked(topo):
    analyst = mk_agent("analyst", Role.ANALYST, Clearance.L3_SECRET, Trust.T3_HIGH)
    s = Session.start("s8b", analyst, "soc")
    s.t_eff_ctl = Trust.T0_UNTRUSTED
    clean = mk_mem("clean", Clearance.L0_PUBLIC, Trust.T3_HIGH)
    d = PDP(topo).can_invoke(analyst, s, "file_write", "fp", provenance=[clean])
    assert d.verdict is Verdict.DENY, "干净 provenance 不得掩盖脏控制流"


# ──────────────────────────────────────────────────────────────
# 6. I6 单调性：t_eff 无门上升的入口已删除
# ──────────────────────────────────────────────────────────────

def test_F05_no_elevate_method():
    assert not hasattr(Session, "elevate"), "I6 唯一上升通道是背书门"


def test_F05_trust_only_rises_via_gate(topo):
    analyst = mk_agent("analyst", Role.ANALYST, Clearance.L3_SECRET, Trust.T3_HIGH)
    s = Session.start("s9", analyst, "soc")
    s.absorb("x", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED)
    assert s.t_eff == Trust.T0_UNTRUSTED
    # 唯一上升入口是私有 _raise_trust_via_gate（铁律 8），由 Upgrader.apply_to_session 独占调用
    assert hasattr(Session, "_raise_trust_via_gate")
    assert not hasattr(Session, "elevate")


# ──────────────────────────────────────────────────────────────
# 7. I13 区间单调收紧：widen 抛异常，narrow 只收紧
# ──────────────────────────────────────────────────────────────

def test_F09_widen_always_raises():
    sc = TaskScope("soc", Clearance.L1_INTERNAL, Trust.T2_MEDIUM)
    with pytest.raises(PermissionError):
        sc.widen(Clearance.L3_SECRET, Trust.T0_UNTRUSTED, sc.scope_hash)


def test_F09_narrow_only_tightens():
    sc = TaskScope("soc", Clearance.L1_INTERNAL, Trust.T2_MEDIUM)
    tighter = sc.narrow(Clearance.L0_PUBLIC, Trust.T3_HIGH)
    assert tighter.c_ctx_max <= sc.c_ctx_max
    assert tighter.t_ctx_min >= sc.t_ctx_min
    with pytest.raises(PermissionError):
        sc.narrow(Clearance.L3_SECRET, Trust.T0_UNTRUSTED)


# ──────────────────────────────────────────────────────────────
# 8. TR14 抗 Sybil：同发布实体的多域名判 1 源
# ──────────────────────────────────────────────────────────────

def test_TR14_same_publisher_counts_as_one():
    registry = SourceRegistry()
    registry.register("a-threat.com", publisher="EvilCorp", asn="AS12345")
    registry.register("b-threat.net", publisher="EvilCorp", asn="AS12345")
    up = Upgrader(registry=registry)
    mm = mk_mem("m10", Clearance.L0_PUBLIC, Trust.T1_LOW)
    ev = Evidence(etype=EvidenceType.CROSS_SOURCE,
                  source_urls=["https://a-threat.com/x", "https://b-threat.net/y"])
    r = up.try_upgrade(mm, ev)
    assert not r.applied, "同 publisher 不同域名必须判为 1 源"


def test_TR14_distinct_publishers_count_two():
    registry = SourceRegistry()
    registry.register("a-threat.com", publisher="A-Corp", asn="AS111")
    registry.register("b-threat.net", publisher="B-Corp", asn="AS222")
    up = Upgrader(registry=registry)
    mm = mk_mem("m10b", Clearance.L0_PUBLIC, Trust.T1_LOW)
    ev = Evidence(etype=EvidenceType.CROSS_SOURCE,
                  source_urls=["https://a-threat.com/x", "https://b-threat.net/y"])
    r = up.try_upgrade(mm, ev)
    assert r.applied


# ──────────────────────────────────────────────────────────────
# 9. TR13 人工背书：无验签器不得直升 T3
# ──────────────────────────────────────────────────────────────

def test_TR13_human_endorsement_requires_signature():
    up = Upgrader()
    mm = mk_mem("m11", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED)
    r = up.try_upgrade(mm, Evidence(etype=EvidenceType.HUMAN,
                                    human_signature="随便一个字符串"))
    assert not r.applied, "无密码学验签器不得提升（sig_verifier 缺失即拒绝）"


# ──────────────────────────────────────────────────────────────
# 10. TR12 结构校验由系统执行，不接受调用方声明
# ──────────────────────────────────────────────────────────────

def test_TR12_structural_cannot_be_self_declared():
    assert not hasattr(Evidence, "validated"), "校验结果不得由调用方声明"
    up = Upgrader()
    mm = mk_mem("m12", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED)
    r = up.try_upgrade(mm, Evidence(etype=EvidenceType.STRUCTURAL, validator="stix2_ioc"),
                       content="这不是合法的 STIX2")
    assert not r.applied


# ──────────────────────────────────────────────────────────────
# 11. CP-ABE：低属性主体在密码学层面解不开，密钥材料各不相同
# ──────────────────────────────────────────────────────────────

def test_F10_agent_keys_are_distinct_and_low_cannot_decrypt():
    mk_, pk_ = abe_setup()
    k_high = abe_issue_key(mk_, "planner", ["clearance_3", "task_soc"])
    k_low = abe_issue_key(mk_, "intel", ["clearance_0", "task_soc"])
    ct = abe_encrypt(pk_, "内网资产清单：10.0.0.1", "(clearance_3) and task_soc")

    # 高属性主体能解，低属性主体解不开（KEM 密钥隔离，无软件 if）
    assert abe_decrypt(k_low, ct) is None
    assert abe_decrypt(k_high, ct) == "内网资产清单：10.0.0.1".encode()

    # 不同主体密钥材料不同，且低属性密钥不含高属性派生密钥
    assert k_high.keys != k_low.keys
    assert "clearance_3" not in k_low.keys


# ──────────────────────────────────────────────────────────────
# 12. 读管线：ALLOW 路径传真实密文，CONFIRM 被拦截
# ──────────────────────────────────────────────────────────────

def test_pipeline_decrypts_real_ciphertext():
    from core.pipeline import ReadPipeline
    src = inspect.getsource(ReadPipeline.read)
    assert "decrypt_memory(agent, None)" not in src, "ALLOW 路径不得传 None 占位密文"
    assert "Verdict.CONFIRM" in src, "CONFIRM 必须被拦截，不得直落解密路径"


# ──────────────────────────────────────────────────────────────
# 13. 4bit 容量预算一致性（单一预算）
# ──────────────────────────────────────────────────────────────

def test_F24_single_budget_of_four_bits(topo):
    assert Session.CAPACITY_BUDGET_BITS == 4.0
    assert ControlFlowBudget.MAX_BITS == 4.0
    assert not hasattr(SessionStore, "_capacity_budget"), "双预算已合并到 Session"


# ──────────────────────────────────────────────────────────────
# 14. TR3/TR4 展开语义方向：受限展开 t_eff↓ 而 t_eff_ctl 不变
# ──────────────────────────────────────────────────────────────

def test_F06_bounded_expand_lowers_t_eff_only(topo):
    analyst = mk_agent("analyst", Role.ANALYST, Clearance.L3_SECRET, Trust.T3_HIGH)
    s = Session.start("s13", analyst, "soc")
    before_t, before_ctl = s.t_eff, s.t_eff_ctl
    s.absorb("x", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED, mode=AbsorbMode.BOUNDED)
    assert s.t_eff < before_t, "TR3: t_eff 必须照实下降"
    assert s.t_eff_ctl == before_ctl, "TR3: t_eff_ctl 必须不变"


def test_F06_unbounded_expand_lowers_both(topo):
    analyst = mk_agent("analyst", Role.ANALYST, Clearance.L3_SECRET, Trust.T3_HIGH)
    s = Session.start("s14", analyst, "soc")
    before_ctl = s.t_eff_ctl
    s.absorb("x", Clearance.L0_PUBLIC, Trust.T0_UNTRUSTED, mode=AbsorbMode.FULL)
    assert s.t_eff_ctl < before_ctl, "TR4: 无界展开两个水位都降"


# ──────────────────────────────────────────────────────────────
# 15. VarStore 受限展开 expand() 存在
# ──────────────────────────────────────────────────────────────

def test_varstore_expand_exists():
    assert hasattr(VarStore, "expand"), "受限展开路径完全缺失"
