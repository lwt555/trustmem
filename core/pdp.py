"""
策略裁决点 (Policy Decision Point, PDP)
=======================================
所有裁决都是格上的偏序比较 -- 确定性的、可穷举的、可证明的。

这是与"训个分类器判断这个调用像不像攻击"的经验主义方案的本质区别：
    经验主义 : 判定是概率的，无法证明覆盖率，可被对抗样本绕过
    格上判定 : 判定是确定性的，可以对 |Agent| × |L| × |T| × |Layer|
               的全部组合做穷举测试，报"信息流不变式覆盖率"

每次裁决返回完整的 check trace，前端逐条展示 -- 这既是可解释性，
也是演示效果的来源（评委能看见每一条规则是怎么起作用的）。

判定序（设计文档 §3.2，写死）：
    ① 硬拒绝（任何模式下都拦，不可 HIDE）
    ② 读取模式检查（CONSULT → HIDE）
    ③ 区间判定（仅 LEARN，join 假想水位）
    ④ hideable == False（纯拒绝基线消融档）→ DENY

铁律：判定与生效分离。can_read / can_read_scoped 是纯函数，只计算
verdict 与 checks，不调用任何水位变更。水位变更只在 pep 层提交。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .labels import (
    AgentLabel, MemoryLabel, Clearance, Trust, Layer, Role, WriteOp, IngestMode,
    TaskScope, TOOL_REQUIRED_TRUST, TOOL_REQUIRE_HITL, EGRESS_TOOLS, EGRESS_READERS,
    EXPORT_TOOL_REQUIRED_TRUST, fmt, meet_trust,
)
from .session import Session
from .topology import Topology
from .trust_rules import trust_rule
from .decay import compute_trust, DecayResult
from .verdict import Verdict
from manifest.capability import capability_level, CapabilityLevel


# 硬拒绝规则集：命中即无条件 DENY，不可 HIDE（I1/I2/I10 + 时间/版本/生命周期）
HARD_DENY_RULES: frozenset[str] = frozenset({
    "BLP-SimpleSecurity",   # I1 无读上
    "NeedToKnow",           # I2 需知
    "CognitiveLayer",       # I10 R 层仅向上
    "TTL",
    "Epoch",
    "Lifecycle",
})


@dataclass
class Check:
    rule: str
    passed: bool
    detail: str

    def __str__(self) -> str:
        return f"{'[PASS]' if self.passed else '[FAIL]'} {self.rule}: {self.detail}"


@dataclass
class Decision:
    verdict: Verdict
    action: str
    subject: str
    object: str
    checks: list[Check] = field(default_factory=list)
    side_effect: str | None = None
    denied_by: str | None = None
    at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    session_id: str = ""
    decision_id: str = ""
    hideable: bool = True
    pending_absorb: tuple[Clearance, Trust] | None = None

    @property
    def allowed(self) -> bool:
        """Backward-compat: True only for ALLOW verdict."""
        return self.verdict == Verdict.ALLOW

    @allowed.setter
    def allowed(self, value: bool) -> None:
        self.verdict = Verdict.ALLOW if value else Verdict.DENY

    @property
    def is_allowed(self) -> bool:
        return self.allowed

    def explain(self) -> str:
        head = f"[{self.at:%H:%M:%S}] {self.subject} -> {self.action} {self.object}"
        body = "\n".join(f"    {c}" for c in self.checks)
        label = self.verdict.value
        if self.denied_by:
            label += f" by {self.denied_by}"
        tail = f"\n  -> [{label}]"
        if self.side_effect:
            tail += f"\n  [!] {self.side_effect}"
        return f"{head}\n{body}{tail}"


class PDP:
    def __init__(self, topo: Topology, hide_enabled: bool = True,
                 bypass_all: bool = False) -> None:
        self.topo = topo
        self.hide_enabled = hide_enabled
        # 消融档 NO_PROTECTION：全部检查旁路，无标签传播、无衰减（F-13）。
        self.bypass_all = bypass_all

    def _bypass(self, action: str, subject: str, object_: str,
                sess: Session) -> Decision:
        """消融档 NO_PROTECTION 的统一旁路裁决：ALLOW，无 pending_absorb。"""
        return Decision(Verdict.ALLOW, action, subject, object_,
                        [Check("Bypass", True, "bypass_all：无防护消融档（F-13）")],
                        hideable=True, session_id=sess.session_id)

    # ══════════════════════════════════════════════════════════
    # 认知分层可读性
    # ══════════════════════════════════════════════════════════
    def _layer_readable(self, agent: AgentLabel, mem: MemoryLabel) -> tuple[bool, str]:
        owner = mem.owner_agent
        me = agent.agent_id

        if me == owner:
            return True, "自有记忆"
        if agent.role == Role.AUDITOR:
            return True, "Auditor 旁路，可读全部含 R 层"

        if mem.layer == Layer.DIRECTIVE:
            ok = self.topo.is_descendant_of(me, owner)
            return ok, f"D层需 {me} in descendants({owner}) = {ok}"

        if mem.layer == Layer.CONCLUSION:
            same_group = bool(agent.collab_group & mem.collab_group)
            is_anc = self.topo.is_ancestor_of(me, owner)
            ok = same_group or is_anc
            return ok, f"C层需 同协作组({same_group}) 或 上级({is_anc})"

        # R 层：只向上
        is_anc = self.topo.is_ancestor_of(me, owner)
        return is_anc, f"R层仅向上：{me} in ancestors({owner}) = {is_anc}"

    # ══════════════════════════════════════════════════════════
    # 硬拒绝检查集（任何模式下都拦，不可 HIDE）
    # ══════════════════════════════════════════════════════════
    def _hard_checks(self, agent: AgentLabel, mem: MemoryLabel, sess: Session,
                     now: datetime | None = None,
                     epoch_current: int | None = None) -> list[Check]:
        now = now or datetime.now(timezone.utc)
        ck: list[Check] = []

        ok_blp = agent.clearance >= mem.sensitivity
        ck.append(Check("BLP-SimpleSecurity", ok_blp,
                        f"clearance({fmt(agent.clearance)}) >= sensitivity({fmt(mem.sensitivity)})"))

        ok_task = mem.task_binding in agent.task_domain
        ok_group = (not mem.collab_group) or bool(agent.collab_group & mem.collab_group)
        ok_ntk = ok_task and ok_group
        ck.append(Check("NeedToKnow", ok_ntk,
                        f"task={ok_task}, group交集={sorted(agent.collab_group & mem.collab_group)}"))

        ok_layer, why = self._layer_readable(agent, mem)
        ck.append(Check("CognitiveLayer", ok_layer, why))

        ok_ttl = agent.in_ttl(now) and mem.in_ttl(now)
        ck.append(Check("TTL", ok_ttl, "主客体均在有效时间窗内" if ok_ttl else "超出时间窗"))

        cur = epoch_current if epoch_current is not None else mem.epoch
        ok_epoch = agent.epoch >= cur
        ck.append(Check("Epoch", ok_epoch, f"agent.epoch={agent.epoch} vs required={cur}"))

        ok_life = mem.lifecycle == "active"
        ck.append(Check("Lifecycle", ok_life, f"lifecycle={mem.lifecycle}"))

        return ck

    # ══════════════════════════════════════════════════════════
    # 读判定（纯函数：不改变任何水位）
    # ══════════════════════════════════════════════════════════
    def can_read(
        self, agent: AgentLabel, mem: MemoryLabel, sess: Session,
        now: datetime | None = None, epoch_current: int | None = None,
    ) -> Decision:
        if self.bypass_all:
            return self._bypass("READ", agent.agent_id, mem.chunk_id, sess)
        ck = self._hard_checks(agent, mem, sess, now, epoch_current)
        allowed = all(c.passed for c in ck)
        if allowed:
            return Decision(Verdict.ALLOW, "READ", agent.agent_id, mem.chunk_id, ck,
                            hideable=True,
                            pending_absorb=(mem.sensitivity, mem.provenance_trust),
                            session_id=sess.session_id)
        return Decision(Verdict.DENY, "READ", agent.agent_id, mem.chunk_id, ck,
                        denied_by=next(c.rule for c in ck if not c.passed),
                        hideable=False, session_id=sess.session_id)

    # ══════════════════════════════════════════════════════════
    # 带 TaskScope 的读判定（四段式判定序）
    # ══════════════════════════════════════════════════════════
    @trust_rule("TR2", group="A",
                trigger="CONSULT 模式读入，或 LEARN 读入超出任务区间",
                change="裁决 HIDE，c_eff / t_eff / t_eff_ctl 完全不变",
                basis="隐藏中立性 I8")
    def can_read_scoped(
        self, agent: AgentLabel, mem: MemoryLabel, sess: Session,
        scope: TaskScope,
        now: datetime | None = None, epoch_current: int | None = None,
    ) -> Decision:
        ck: list[Check] = []

        if self.bypass_all:
            return self._bypass("READ", agent.agent_id, mem.chunk_id, sess)

        # ① 硬拒绝（任何模式下都拦，不可 HIDE）
        hard = self._hard_checks(agent, mem, sess, now, epoch_current)
        ck.extend(hard)
        if any(not c.passed for c in hard):
            return Decision(Verdict.DENY, "READ", agent.agent_id, mem.chunk_id, ck,
                            denied_by=next(c.rule for c in hard if not c.passed),
                            hideable=False, session_id=sess.session_id)

        # ② 读取模式检查（硬拒绝之后、区间判定之前）
        if scope.ingest is IngestMode.CONSULT:
            sess.consult(mem.chunk_id)   # 记账：I14 的唯一数据来源
            ck.append(Check("Ingest-Mode", True, "CONSULT → 一律 HIDE（TR2）"))
            return Decision(Verdict.HIDE, "READ", agent.agent_id, mem.chunk_id, ck,
                            denied_by="Ingest-Mode-CONSULT", hideable=True,
                            session_id=sess.session_id)
        ck.append(Check("Ingest-Mode", True, "LEARN → 进入区间判定"))

        # ③ 区间判定（仅 LEARN 模式，join 假想水位，F-07）
        would_c = Clearance(max(int(sess.c_eff), int(mem.sensitivity)))
        would_t = Trust(min(int(sess.t_eff_ctl), int(mem.provenance_trust)))
        ok_c = would_c <= scope.c_ctx_max
        ok_t = would_t >= scope.t_ctx_min
        ck.append(Check("TaskScope-C", ok_c,
                        f"would_c({fmt(would_c)}) ≤ c_ctx_max({fmt(scope.c_ctx_max)})"))
        ck.append(Check("TaskScope-T", ok_t,
                        f"would_t({fmt(would_t)}) ≥ t_ctx_min({fmt(scope.t_ctx_min)})"))
        if not (ok_c and ok_t):
            denied_by = "TaskScope-C" if not ok_c else "TaskScope-T"
            # ④ hideable == False（消融档）→ DENY
            verdict = Verdict.HIDE if self.hide_enabled else Verdict.DENY
            return Decision(verdict, "READ", agent.agent_id, mem.chunk_id, ck,
                            denied_by=denied_by, hideable=True,
                            session_id=sess.session_id)

        return Decision(Verdict.ALLOW, "READ", agent.agent_id, mem.chunk_id, ck,
                        hideable=True,
                        pending_absorb=(mem.sensitivity, mem.provenance_trust),
                        session_id=sess.session_id)

    # ══════════════════════════════════════════════════════════
    # 写判定
    # ══════════════════════════════════════════════════════════
    @trust_rule("TR10", group="B",
                trigger="CONSULT 读入的 chunk 出现在 input_mems",
                change="直接 DENY，不进入衰减计算",
                basis="CONSULT 禁写回 I14")
    def can_write(
        self, agent: AgentLabel, sess: Session,
        target_sensitivity: Clearance, target_layer: Layer,
        input_mems: list[MemoryLabel], op: WriteOp,
        input_texts: list[str] | None = None, output_text: str = "",
        schema_ok: bool | None = None,
        declassify_approved: bool = False,
    ) -> tuple[Decision, DecayResult]:
        ck: list[Check] = []

        if self.bypass_all:
            t_in = meet_trust(m.provenance_trust for m in input_mems)
            decay = DecayResult(trust_out=Trust.T3_HIGH, op_claimed=op,
                                op_effective=op, t_inputs=t_in,
                                t_agent=Trust.T3_HIGH, delta=0)
            d = self._bypass("WRITE", agent.agent_id,
                             f"<new {target_layer.value}/{fmt(target_sensitivity)}>", sess)
            return d, decay

        # P-T：写记忆挂完整性门（F-03）
        req_write = EXPORT_TOOL_REQUIRED_TRUST.get("memory.write", Trust.T2_MEDIUM)
        ok_pt_write = sess.t_eff_ctl >= req_write
        ck.append(Check("P-T-ControlFlow", ok_pt_write,
                        f"t_eff_ctl({fmt(sess.t_eff_ctl)}) ⊒ required(memory.write)={fmt(req_write)}"))

        # Provenance-NoConsult (I14): CONSULT 读入的内容禁止出现在 provenance_chain 中
        consulted_inputs = [m for m in input_mems if m.chunk_id in sess.consulted]
        ok_no_consult = not consulted_inputs
        ck.append(Check("Provenance-NoConsult", ok_no_consult,
            "通过" if ok_no_consult
            else f"违反I14: {[m.chunk_id for m in consulted_inputs]} 来自CONSULT模式，禁止写回"))

        if not ok_no_consult:
            decay = compute_trust(input_mems, sess.t_eff, op,
                                  input_texts, output_text, schema_ok)
            d = Decision(Verdict.DENY, "WRITE", agent.agent_id,
                         f"<new {target_layer.value}/{fmt(target_sensitivity)}>", ck,
                         session_id=sess.session_id)
            d.denied_by = "Provenance-NoConsult"
            return d, decay

        # 先算出这条记忆应有的可信度
        decay = compute_trust(input_mems, sess.t_eff, op,
                              input_texts, output_text, schema_ok)

        # Biba *-特性：no write up
        ok_biba = decay.trust_out <= sess.t_eff
        ck.append(Check("Biba-Star", ok_biba,
                        f"T(new)={fmt(decay.trust_out)} <= T_eff={fmt(sess.t_eff)}  |  {decay.explain()}"))

        # BLP *-特性：no write down（大跨级降密需审批）
        if target_sensitivity >= agent.clearance:
            ok_blp, why = True, f"sensitivity({fmt(target_sensitivity)}) >= clearance({fmt(agent.clearance)})"
        elif target_layer == Layer.DIRECTIVE and declassify_approved:
            declassify_fp = f"declassify:{agent.agent_id}:{fmt(target_sensitivity)}"
            if sess.has_hitl(declassify_fp):
                ok_blp, why = True, "D层受控降密网关ALLOW（HITL已确认）"
            else:
                ok_blp, why = False, "D层降密需HITL确认（declassify_approved但无人在环记录）"
        else:
            gap = int(agent.clearance) - int(target_sensitivity)
            if gap > 2:
                ok_blp, why = False, (f"写降密: sensitivity({fmt(target_sensitivity)}) "
                                      f"< clearance({fmt(agent.clearance)})，跨{gap}级需降密审批")
            else:
                ok_blp, why = True, f"controlled write-down (gap={gap})"
        ck.append(Check("BLP-Star", ok_blp, why))

        # C-Eff 写降密检查：读过的高密级内容禁止写入低密级容器
        ok_c_eff = int(target_sensitivity) >= int(sess.c_eff)
        ck.append(Check("C-Eff-WriteDown", ok_c_eff,
            f"target sensitivity({fmt(target_sensitivity)}) >= c_eff({fmt(sess.c_eff)})"
            if ok_c_eff else
            f"c_eff 写降密拒绝: 已读取 {fmt(sess.c_eff)} 级内容，禁止写入 {fmt(target_sensitivity)} 级容器"))

        # 层级写入权
        ok_layer = not (target_layer == Layer.DIRECTIVE and not self.topo.children(agent.agent_id))
        ck.append(Check("LayerWrite", ok_layer,
                        "D层需有下级" if not ok_layer else f"可写 {target_layer.value} 层"))

        allowed = all(c.passed for c in ck)
        verdict = Verdict.ALLOW if allowed else Verdict.DENY
        d = Decision(verdict, "WRITE", agent.agent_id,
                     f"<new {target_layer.value}/{fmt(target_sensitivity)}>", ck,
                     session_id=sess.session_id)
        if not allowed:
            d.denied_by = next(c.rule for c in ck if not c.passed)
            if not ok_blp or not ok_c_eff:
                failed_writedown = [c.rule for c in ck
                                    if not c.passed and c.rule in ("BLP-Star", "C-Eff-WriteDown")]
                d.denied_by = f"NoWriteDown({' + '.join(failed_writedown)})"
        else:
            d.side_effect = f"新记忆标签: T={fmt(decay.trust_out)}, L={fmt(target_sensitivity)}, layer={target_layer.value}"
        return d, decay

    # ══════════════════════════════════════════════════════════
    # 执行判定
    # ══════════════════════════════════════════════════════════
    def can_invoke(
        self, agent: AgentLabel, sess: Session, tool: str,
        action_fingerprint: str = "",
        provenance: list[MemoryLabel] | None = None,
        arg_labels: list[MemoryLabel] | None = None,
    ) -> Decision:
        ck: list[Check] = []

        if self.bypass_all:
            return self._bypass(f"INVOKE({tool})", agent.agent_id,
                                action_fingerprint or tool, sess)

        ok_scope = tool in agent.tool_scope
        ck.append(Check("ToolScope", ok_scope,
                        f"'{tool}' in tool_scope{sorted(agent.tool_scope)}"))

        req = TOOL_REQUIRED_TRUST.get(tool, Trust.T3_HIGH)

        # P-T：控制流水位（t_eff_ctl，F-03）
        ok_ctl = sess.t_eff_ctl >= req
        ck.append(Check("P-T-ControlFlow", ok_ctl,
                        f"t_eff_ctl({fmt(sess.t_eff_ctl)}) ⊒ required({fmt(req)})"))

        # P-T：参数溯源链（并列的第二条，不是二选一，F-03）
        if provenance:
            t_prov = meet_trust(m.provenance_trust for m in provenance)
            ok_prov = t_prov >= req
            ck.append(Check("P-T-Provenance", ok_prov,
                            f"provenance min={fmt(t_prov)} ⊒ required({fmt(req)})"))

            # F-29：CONSULT 派生记忆不得作为高危动作的 provenance（内容级泄漏兜底）
            consult_derived = [m for m in provenance if m.derived_from_consult]
            ck.append(Check("P-T-ConsultDerived", not consult_derived,
                            "无 CONSULT 派生记忆" if not consult_derived else
                            f"provenance 含 {[m.chunk_id for m in consult_derived]} CONSULT 派生，禁止驱动高危动作"))
        else:
            ck.append(Check("P-T-Provenance", True, "无 provenance 参数"))

        # P-F：出口约束（方向修正 F-02：c_eff ⊑ readers）
        if tool in EGRESS_TOOLS:
            readers = EGRESS_READERS.get(tool)
            if readers is None:
                readers = Clearance.L0_PUBLIC   # fail-closed：未登记按 L0
            ok_egress = sess.c_eff <= readers
            ck.append(Check("Flow-Egress", ok_egress,
                            f"c_eff({fmt(sess.c_eff)}) ⊑ readers({fmt(readers)})"))
            if arg_labels:
                max_sens = Clearance(max(int(m.sensitivity) for m in arg_labels))
                ok_arg = max_sens <= readers
                ck.append(Check("Flow-Egress-Args", ok_arg,
                                f"max(arg sensitivity)({fmt(max_sens)}) ⊑ readers({fmt(readers)})"))
        else:
            ck.append(Check("Flow-Egress", True, "非出口工具，仅传播标签"))

        # 系统级能力：需显式授权，未授权一律 DENY（fail-closed，F-16）。
        level = capability_level(tool)
        if level is CapabilityLevel.SYSTEM:
            ck.append(Check("SystemCapability", False, "系统级能力需显式授权"))
            return Decision(Verdict.DENY, f"INVOKE({tool})", agent.agent_id,
                            action_fingerprint or tool, ck,
                            denied_by="SystemCapability", session_id=sess.session_id)

        # 高危能力：硬门全过但缺 HITL → CONFIRM（四值裁决落地，F-16）。
        need_hitl = level is CapabilityLevel.DANGEROUS
        ok_hitl = (not need_hitl) or sess.has_hitl(action_fingerprint)
        ck.append(Check("HumanInTheLoop", ok_hitl,
                        "无需人在环" if not need_hitl
                        else ("已获人工确认" if ok_hitl else "高危动作缺人工确认")))

        hard_ok = all(c.passed for c in ck if c.rule != "HumanInTheLoop")
        if need_hitl and hard_ok and not ok_hitl:
            return Decision(Verdict.CONFIRM, f"INVOKE({tool})", agent.agent_id,
                            action_fingerprint or tool, ck,
                            denied_by="HumanInTheLoop", hideable=False,
                            session_id=sess.session_id)

        allowed = all(c.passed for c in ck)
        verdict = Verdict.ALLOW if allowed else Verdict.DENY
        d = Decision(verdict, f"INVOKE({tool})", agent.agent_id, action_fingerprint or tool, ck,
                     session_id=sess.session_id)
        if not allowed:
            d.denied_by = next(c.rule for c in ck if not c.passed)
        return d
