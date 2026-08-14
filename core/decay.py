"""
可信度衰减代数
===============
    T(m_out) = min( min_i T(m_in^i) , T_intrinsic(A) )  -  δ(op)

两个 min 各自的含义（必须分清，答辩会问）：
    min_i T(m_in^i)     ---- 一条链的可信度不高于其最弱的一环（输入侧）
    T_intrinsic(A)      ---- 一个 Agent 不能产出比自己更可信的东西（主体侧）
    - δ(op)             ---- LLM 的处理过程**本身**引入不确定性（过程侧）

第三项是本方案区别于经典 Biba 的地方。经典模型里主体处理数据不改变完整性，
但 LLM 会产生幻觉：同样是 T3 的输入，逐字引用出来还是 T3，让它"总结一下"
就可能悄悄丢掉限定条件、编造不存在的因果。所以过程本身要计入衰减。

δ=0 的声明必须可验证 ---- 否则 Agent 只要都声称自己是 verbatim 就绕过了衰减。
    VERBATIM : 输出必须与输入有足够高的字面重叠
    EXTRACT  : 输出必须通过 schema 校验
校验失败自动降级为 INFER（δ=1）。
"""
from __future__ import annotations

import difflib
from dataclasses import dataclass

from .labels import Trust, WriteOp, MemoryLabel, meet_trust
from .trust_rules import trust_rule

# 操作类型 → 衰减量
DELTA: dict[WriteOp, int] = {
    WriteOp.VERBATIM: 0,
    WriteOp.EXTRACT: 0,
    WriteOp.SUMMARIZE: 1,
    WriteOp.INFER: 1,
    WriteOp.FUSE: 1,
}

VERBATIM_OVERLAP_THRESHOLD = 0.85   # 逐字引用的最低字面重叠率
MAX_VERBATIM_LEN = 10_000           # 重叠率校验的长度上限（字符）。超长走 O(1) 保守降级，避开 O(n²)


@dataclass
class DecayResult:
    trust_out: Trust
    op_claimed: WriteOp
    op_effective: WriteOp        # 校验失败后的实际操作类型
    t_inputs: Trust
    t_agent: Trust
    delta: int
    downgraded_reason: str | None = None

    def explain(self) -> str:
        base = (f"T_in={self.t_inputs.name[:2]} AND T_agent={self.t_agent.name[:2]} "
                f"- δ({self.op_effective.value})={self.delta} → {self.trust_out.name[:2]}")
        if self.downgraded_reason:
            base += f"  [声明 {self.op_claimed.value} 校验失败: {self.downgraded_reason}]"
        return base


def _overlap_ratio(src: str, out: str) -> float:
    if not out:
        return 0.0
    return difflib.SequenceMatcher(None, src, out, autojunk=True).ratio()


@trust_rule("TR7", group="B",
            trigger="声明 δ=0 的操作（VERBATIM / EXTRACT）但校验失败",
            change="op 强制降为 INFER（δ=1），可信度再降一级",
            basis="谎报降级（δ=0 声明必须可验证）")
def verify_op(
    op_claimed: WriteOp,
    input_texts: list[str],
    output_text: str,
    schema_ok: bool | None = None,
) -> tuple[WriteOp, str | None]:
    """
    校验 δ=0 的声明。校验不通过则降级为 INFER。
    这是防止 Agent 通过谎报操作类型规避衰减的闸门。
    """
    if op_claimed == WriteOp.VERBATIM:
        if (len(output_text) > MAX_VERBATIM_LEN
                or any(len(s) > MAX_VERBATIM_LEN for s in input_texts)):
            return WriteOp.INFER, f"超长文本（>{MAX_VERBATIM_LEN} 字符）跳过重叠率校验，保守降级"
        best = max((_overlap_ratio(s, output_text) for s in input_texts), default=0.0)
        if best < VERBATIM_OVERLAP_THRESHOLD:
            return WriteOp.INFER, f"字面重叠率 {best:.2f} < {VERBATIM_OVERLAP_THRESHOLD}"
        return WriteOp.VERBATIM, None

    if op_claimed == WriteOp.EXTRACT:
        if schema_ok is False:
            return WriteOp.INFER, "schema 校验未通过"
        if schema_ok is None:
            return WriteOp.INFER, "未提供 schema 校验结果"
        return WriteOp.EXTRACT, None

    return op_claimed, None


@trust_rule("TR9", group="B",
            trigger="跨源融合（FUSE）多条输入",
            change="trust_out ≤ meet(全部输入)，取最脏一环",
            basis="融合取脏（一颗老鼠屎坏一锅汤）")
@trust_rule("TR8", group="B",
            trigger="LLM 加工一条输入（SUMMARIZE / INFER / FUSE）",
            change="trust_out 额外减去 δ(op)",
            basis="加工衰减（LLM 过程本身引入不确定性）")
@trust_rule("TR6", group="B",
            trigger="写出一条新记忆",
            change="trust_out ≤ meet(输入集合, 主体 t_eff)，取最弱一环，不是 max / 均值",
            basis="Biba 无写上（no write up）")
def compute_trust(
    input_mems: list[MemoryLabel],
    agent_trust_effective: Trust,
    op_claimed: WriteOp,
    input_texts: list[str] | None = None,
    output_text: str = "",
    schema_ok: bool | None = None,
) -> DecayResult:
    """
    计算写入记忆的可信度。

    注意 agent_trust_effective 传的是**会话内的有效可信度 T_eff**，
    不是 T_intrinsic ---- 因为低水位标记已经把"读过什么"折进去了。
    """
    op_eff, reason = verify_op(op_claimed, input_texts or [], output_text, schema_ok)
    t_in = meet_trust(m.provenance_trust for m in input_mems)
    delta = DELTA[op_eff]
    raw = min(int(t_in), int(agent_trust_effective)) - delta
    return DecayResult(
        trust_out=Trust(max(0, raw)),
        op_claimed=op_claimed,
        op_effective=op_eff,
        t_inputs=t_in,
        t_agent=agent_trust_effective,
        delta=delta,
        downgraded_reason=reason,
    )
