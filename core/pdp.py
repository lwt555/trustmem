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
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .labels import (
    AgentLabel, MemoryLabel, Clearance, Trust, Layer, Role, WriteOp, IngestMode,
    TaskScope, TOOL_REQUIRED_TRUST, TOOL_REQUIRE_HITL, EGRESS_TOOLS, EGRESS_READERS, fmt,
)
from .session import Session
from .topology import Topology
from .decay import compute_trust, DecayResult
from .verdict import Verdict


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
    def __init__(self, topo: Topology) -> None:
        self.topo = topo

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
    # 读判定
    # ══════════════════════════════════════════════════════════
    def can_read(
        self, agent: AgentLabel, mem: MemoryLabel, sess: Session,
        now: datetime | None = None, epoch_current: int | None = None,
    ) -> Decision:
        now = now or datetime.now(timezone.utc)
        ck: list[Check] = []

        # BLP 简单安全特性：no read up
        ok_blp = agent.clearance >= mem.sensitivity
        ck.append(Check("BLP-SimpleSecurity",
                        ok_blp,
                        f"clearance({fmt(agent.clearance)}) >= sensitivity({fmt(mem.sensitivity)})"))

        # need-to-know：范畴集包含
        ok_ntk = mem.task_binding in agent.task_domain
        ck.append(Check("NeedToKnow", ok_ntk,
                        f"task '{mem.task_binding}' in task_domain{sorted(agent.task_domain)}"))

        # 认知分层
        ok_layer, why = self._layer_readable(agent, mem)
        ck.append(Check("CognitiveLayer", ok_layer, why))

        # 时间窗
        ok_ttl = agent.in_ttl(now) and mem.in_ttl(now)
        ck.append(Check("TTL", ok_ttl, "主客体均在有效时间窗内" if ok_ttl else "超出时间窗"))

        # 属性版本
        cur = epoch_current if epoch_current is not None else mem.epoch
        ok_epoch = agent.epoch >= cur
        ck.append(Check("Epoch", ok_epoch, f"agent.epoch={agent.epoch} vs required={cur}"))

        # 生命周期
        ok_life = mem.lifecycle == "active"
        ck.append(Check("Lifecycle", ok_life, f"lifecycle={mem.lifecycle}"))

        allowed = all(c.passed for c in ck)
        # 四值裁决：BLP 失败 → HIDE（可受限查询），否则 DENY
        if allowed:
            verdict = Verdict.ALLOW
        elif not ok_blp:
            verdict = Verdict.HIDE
        else:
            verdict = Verdict.DENY
        d = Decision(verdict, "READ", agent.agent_id, mem.chunk_id, ck,
                     session_id=sess.session_id)
        if verdict == Verdict.ALLOW:
            rec = sess.absorb(mem.chunk_id, mem.provenance_trust)
            sess.absorb_c(mem.sensitivity)
            side_lines = []
            if rec.t_eff_after < rec.t_eff_before:
                side_lines.append(f"低水位触发: T_eff({agent.agent_id}) "
                                 f"{fmt(rec.t_eff_before)} -> {fmt(rec.t_eff_after)}")
            else:
                side_lines.append(f"T_eff({agent.agent_id}) 保持 {fmt(sess.t_eff)}")
            side_lines.append(f"c_eff({agent.agent_id}) = {fmt(sess.c_eff)}")
            d.side_effect = " | ".join(side_lines)
        else:
            d.denied_by = next(c.rule for c in ck if not c.passed)
        return d

    # ══════════════════════════════════════════════════════════
    # 带 TaskScope 的读判定（P5 修补）
    # ══════════════════════════════════════════════════════════
    def can_read_scoped(
        self, agent: AgentLabel, mem: MemoryLabel, sess: Session,
        scope: TaskScope,
        now: datetime | None = None, epoch_current: int | None = None,
    ) -> Decision:
        d = self.can_read(agent, mem, sess, now, epoch_current)
        if not d.allowed:
            return d

        # TaskScope 密级区间检查
        ok_c = scope.contains_c(mem.sensitivity)
        d.checks.append(Check("TaskScope-C",
            ok_c,
            f"sensitivity({fmt(mem.sensitivity)}) <= c_ctx_max({fmt(scope.c_ctx_max)})"))

        # TaskScope 完整性区间检查
        ok_t = scope.contains_t(mem.provenance_trust)
        d.checks.append(Check("TaskScope-T",
            ok_t,
            f"provenance_trust({fmt(mem.provenance_trust)}) >= t_ctx_min({fmt(scope.t_ctx_min)})"))

        # Ingest-Mode 检查
        if scope.ingest == IngestMode.CONSULT:
            # CONSULT: 所有读取一律走 VarStore（哪怕在区间内），不进低水位
            sess.consult(mem.chunk_id)
            d.checks.append(Check("Ingest-Mode",
                True,
                f"CONSULT模式: {mem.chunk_id} 走VarStore句柄（不进长期溯源链）"))
            d.side_effect = (d.side_effect or "") + f" [CONSULT: {mem.chunk_id}]"
            # CONSULT 永不暴露原始内容 — 通过 VarStore 隔离查询
            if d.verdict == Verdict.ALLOW:
                d.verdict = Verdict.HIDE
        else:
            d.checks.append(Check("Ingest-Mode",
                True,
                "LEARN模式: 可吸收可写回"))

        # CONSULT 不是提权通道 —— 被 scope 拒绝的内容仍然不能读
        if not (ok_c and ok_t):
            d.verdict = Verdict.HIDE if not ok_c else Verdict.DENY
            d.denied_by = "TaskScope-C" if not ok_c else "TaskScope-T"

        return d

    # ══════════════════════════════════════════════════════════
    # 写判定
    # ══════════════════════════════════════════════════════════
    def can_write(
        self, agent: AgentLabel, sess: Session,
        target_sensitivity: Clearance, target_layer: Layer,
        input_mems: list[MemoryLabel], op: WriteOp,
        input_texts: list[str] | None = None, output_text: str = "",
        schema_ok: bool | None = None,
        declassify_approved: bool = False,
    ) -> tuple[Decision, DecayResult]:
        ck: list[Check] = []

        # Provenance-NoConsult (I14): CONSULT 读入的内容禁止出现在 provenance_chain 中
        consulted_inputs = [m for m in input_mems if m.chunk_id in sess.consulted]
        ok_no_consult = not consulted_inputs
        ck.append(Check("Provenance-NoConsult", ok_no_consult,
            "通过" if ok_no_consult
            else f"违反I14: {[m.chunk_id for m in consulted_inputs]} 来自CONSULT模式，禁止写回"))

        if not ok_no_consult:
            # 即使后续检查通过，CONSULT 违规直接 DENY
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
            # BLP 写降密或 C-Eff 写降密失败 → 统一加 NoWriteDown 标签
            # 便于 A11 双规则日志识别：NoWriteDown + Egress/ProvenanceTrust
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
    ) -> Decision:
        ck: list[Check] = []

        ok_scope = tool in agent.tool_scope
        ck.append(Check("ToolScope", ok_scope,
                        f"'{tool}' in tool_scope{sorted(agent.tool_scope)}"))

        req = TOOL_REQUIRED_TRUST.get(tool, Trust.T3_HIGH)
        if provenance:
            from .labels import meet_trust
            t_src = meet_trust(m.provenance_trust for m in provenance)
            src_desc = f"参数溯源链 min={fmt(t_src)} (细粒度)"
        else:
            t_src = sess.t_eff
            src_desc = f"会话有效可信 T_eff={fmt(t_src)} (会话级污点)"
        ok_trust = t_src >= req
        ck.append(Check("ProvenanceTrust", ok_trust,
                        f"{src_desc} >= RequiredTrust({tool})={fmt(req)}"))

        need_hitl = tool in TOOL_REQUIRE_HITL
        ok_hitl = (not need_hitl) or sess.has_hitl(action_fingerprint)
        ck.append(Check("HumanInTheLoop", ok_hitl,
                        "无需人在环" if not need_hitl
                        else ("已获人工确认" if ok_hitl else "高危动作缺人工确认")))

        if tool in EGRESS_TOOLS:
            if tool in EGRESS_READERS:
                req_cl = EGRESS_READERS[tool]
                ok_egress = agent.clearance >= req_cl
                ck.append(Check("EgressReader", ok_egress,
                    f"出口 '{tool}' 要求 clearance >= {fmt(req_cl)}，"
                    f"agent clearance={fmt(agent.clearance)}"))
            else:
                ck.append(Check("EgressReader", False,
                    f"未登记出口工具 '{tool}' —— fail-closed 拒绝"))

        allowed = all(c.passed for c in ck)
        verdict = Verdict.ALLOW if allowed else Verdict.DENY
        d = Decision(verdict, f"INVOKE({tool})", agent.agent_id, action_fingerprint or tool, ck,
                     session_id=sess.session_id)
        if not allowed:
            d.denied_by = next(c.rule for c in ck if not c.passed)
        return d
