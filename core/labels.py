"""
TrustMem v2 · 标签本体与格结构
================================
两条独立的格（lattice）+ 一个范畴集 + 一个认知层维度。

  保密性格 L (Bell-LaPadula, 1973)  : L0 <= L1 <= L2 <= L3     管"能不能看"
  完整性格 T (Biba, 1977)           : T0 <= T1 <= T2 <= T3     管"能不能信"
  范畴集   C (Compartments)         : 幂集，偏序为 <=         管"是不是你该管的"
  认知层   layer (本文新增)          : D / C / R             管"哪一层的心智内容"

为什么保密性和完整性必须是两条独立的格：
  一条从公开互联网抓来的 IOC，密级极低（本来就是公开的），
  但可信度也极低（可能被投毒）。
  单轴模型下"高权限主体读低密级客体"完全合法 ---- 投毒直达执行端。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import IntEnum, Enum
from typing import Iterable


# ──────────────────────────────────────────────────────────────
# 保密性格 L
# ──────────────────────────────────────────────────────────────
class Clearance(IntEnum):
    """保密性等级。IntEnum 使得 <= 直接是 <=。"""
    L0_PUBLIC = 0      # 公开
    L1_INTERNAL = 1    # 内部
    L2_SENSITIVE = 2   # 敏感
    L3_SECRET = 3      # 机密


# ──────────────────────────────────────────────────────────────
# 完整性格 T
# ──────────────────────────────────────────────────────────────
class Trust(IntEnum):
    """完整性 / 可信等级。"""
    T0_UNTRUSTED = 0   # 不可信：已知被污染、校验失败
    T1_LOW = 1         # 低：公开互联网、用户上传、未验签情报
    T2_MEDIUM = 2      # 中：内部但未校验、经 LLM 推理产生
    T3_HIGH = 3        # 高：内部权威源、已验签、人在环确认


# ──────────────────────────────────────────────────────────────
# 认知层
# ──────────────────────────────────────────────────────────────
class Layer(str, Enum):
    """
    记忆的认知层级 ---- 本方案针对多智能体场景新增的第四个维度。

      D  Directive  命令层：任务指派、约束、参数        → 向下可见
      C  Conclusion 结论层：最终判断、结构化产出        → 同级 + 向上可见
      R  Reasoning  思考层：推理链、中间假设、被否方案  → 只向上可见

    R 层只向上的核心理由（答辩重点）：
      推理链是最优的注入载体。攻击者控制一个下级后，若能读到上级的思考过程，
      就把黑盒攻击变成了白盒攻击 ---- 可以精确构造绕过上级判断逻辑的输入。
      这是多智能体特有的横向移动路径，单智能体系统里不存在。
    """
    DIRECTIVE = "D"
    CONCLUSION = "C"
    REASONING = "R"


class Role(str, Enum):
    PLANNER = "Planner"      # 规划编排，root
    RETRIEVER = "Retriever"  # 内部检索
    ANALYST = "Analyst"      # 关联研判
    EXECUTOR = "Executor"    # 处置执行，持有高危工具
    AUDITOR = "Auditor"      # 旁路审计，可读全部含 R 层
    EXTERNAL = "External"    # 外部数据接入，天然低可信


class MemoryType(str, Enum):
    SEMANTIC = "semantic"        # 语义记忆：领域知识
    EPISODIC = "episodic"        # 情景记忆：事件经过
    TRAJECTORY = "trajectory"    # 任务轨迹
    PROCEDURAL = "procedural"    # 程序经验
    INTEL = "intel"              # 威胁情报


class WriteOp(str, Enum):
    """
    写入操作类型，决定可信度衰减量 δ。
    δ=0 的声明必须可验证，否则自动降级为 INFER（见 decay.py）。
    """
    VERBATIM = "verbatim"      # δ=0  逐字引用 + 保留溯源指针（可验证：重叠率）
    EXTRACT = "extract"        # δ=0  schema 约束抽取（可验证：schema 校验）
    SUMMARIZE = "summarize"    # δ=1  LLM 摘要，可能丢失/扭曲限定条件
    INFER = "infer"            # δ=1  LLM 推理生成新结论，幻觉主要来源
    FUSE = "fuse"              # δ=1  无印证的跨源融合


# ──────────────────────────────────────────────────────────────
# 主体标签
# ──────────────────────────────────────────────────────────────
@dataclass
class AgentLabel:
    agent_id: str
    role: Role
    clearance: Clearance
    trust_intrinsic: Trust          # 固有可信度，由数据来源决定（PromptLens 查表）
    task_domain: set[str] = field(default_factory=set)
    collab_group: set[str] = field(default_factory=set)
    tool_scope: set[str] = field(default_factory=set)   # 来自工具注册表，非自我声明
    ttl_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ttl_end: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(days=1))
    prompt_hash: str = ""           # 系统提示词承诺，上链锚定
    epoch: int = 0                  # 属性版本号，权限变更即 +1，旧密钥失效

    def in_ttl(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        return self.ttl_start <= now <= self.ttl_end


# ──────────────────────────────────────────────────────────────
# 客体标签
# ──────────────────────────────────────────────────────────────
@dataclass
class MemoryLabel:
    chunk_id: str
    sensitivity: Clearance
    provenance_trust: Trust
    layer: Layer
    memory_type: MemoryType
    owner_agent: str
    task_binding: str
    collab_group: set[str] = field(default_factory=set)
    provenance_chain: list[str] = field(default_factory=list)  # 上游 chunk_id，用于污染反向追溯
    lifecycle: str = "active"       # active / archived / revoked
    epoch: int = 0
    declassified: bool = False      # 是否经受控降密网关放行
    ttl_end: datetime | None = None

    def in_ttl(self, now: datetime | None = None) -> bool:
        if self.ttl_end is None:
            return True
        return (now or datetime.now(timezone.utc)) <= self.ttl_end


# ──────────────────────────────────────────────────────────────
# 高危工具的可信度门槛
# ──────────────────────────────────────────────────────────────
TOOL_REQUIRED_TRUST: dict[str, Trust] = {
    "web_search":    Trust.T0_UNTRUSTED,
    "intel_fetch":   Trust.T0_UNTRUSTED,
    "log_query":     Trust.T1_LOW,
    "asset_query":   Trust.T2_MEDIUM,
    "file_read":     Trust.T2_MEDIUM,
    "file_write":    Trust.T3_HIGH,
    "exec_command":  Trust.T3_HIGH,
    "firewall_block": Trust.T3_HIGH,
    "host_isolate":  Trust.T3_HIGH,
}

# 需要人在环二次确认的工具
TOOL_REQUIRE_HITL: set[str] = {"firewall_block", "host_isolate", "exec_command"}


def fmt(v: Clearance | Trust) -> str:
    return v.name.split("_")[0]


def meet_trust(values: Iterable[Trust]) -> Trust:
    """完整性格的 meet（取下确界）。空集返回 T3（幺元）。"""
    vals = list(values)
    return Trust(min(vals)) if vals else Trust.T3_HIGH


# ──────────────────────────────────────────────────────────────
# IngestMode · 读取模式（P5 修补）
# ──────────────────────────────────────────────────────────────
class IngestMode(str, Enum):
    """
    对应老师「装脑子里 vs 当书翻」的区分：

        LEARN   — 装脑子里：可 join、可吸收、可写回的长期记忆
        CONSULT — 当书翻着看：只影响本轮，reset() 即清，
                  且这些 chunk_id 禁止出现在本会话任何 memory.write 的 provenance_chain 里

    这是 TaskScope 的第三个维度。
    """
    LEARN = "learn"
    CONSULT = "consult"


@dataclass
class TaskScope:
    """
    任务级可行区间。三维约束：

        c_ctx_max  — 本任务可接触的最高密级（取任务声明出口与工具的下界）
        t_ctx_min  — 本任务可接受的最低完整性（从声明的决策出口推导）
        ingest     — LEARN 还是 CONSULT

    区间从任务声明的出口和工具自动推导，不手填。
    """
    task_id: str
    c_ctx_max: Clearance
    t_ctx_min: Trust
    ingest: IngestMode = IngestMode.LEARN
    scope_hash: str = ""

    def __post_init__(self) -> None:
        if not self.scope_hash:
            self.scope_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        import hashlib, json
        payload = json.dumps({
            "task_id": self.task_id,
            "c_ctx_max": int(self.c_ctx_max),
            "t_ctx_min": int(self.t_ctx_min),
            "ingest": self.ingest.value,
        }, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def widen(self, new_c_max: Clearance, new_t_min: Trust,
              claimed_hash: str) -> "TaskScope":
        """扩展任务区间。claim_hash 必须匹配当前 scope_hash，否则拒绝扩展。

        §4 第 6 项抽查：区间防篡改 — 攻击者注入"本任务也允许写外部"无法生效，
        因为 hash 不匹配会直接抛异常。
        """
        if claimed_hash != self.scope_hash:
            raise ValueError(
                f"Scope hash mismatch: claimed={claimed_hash[:8]}..., "
                f"actual={self.scope_hash}. 区间防篡改: 拒绝扩展。")
        if new_c_max < self.c_ctx_max:
            raise ValueError(
                f"widen c_ctx_max must expand, not shrink: "
                f"{fmt(new_c_max)} < {fmt(self.c_ctx_max)}")
        if new_t_min > self.t_ctx_min:
            raise ValueError(
                f"widen t_ctx_min must expand, not shrink: "
                f"{fmt(new_t_min)} > {fmt(self.t_ctx_min)}")
        return TaskScope(
            task_id=self.task_id,
            c_ctx_max=new_c_max,
            t_ctx_min=new_t_min,
            ingest=self.ingest,
        )

    def contains_c(self, sensitivity: Clearance) -> bool:
        return sensitivity <= self.c_ctx_max

    def contains_t(self, trust: Trust) -> bool:
        return trust >= self.t_ctx_min

    def contains(self, sensitivity: Clearance, trust: Trust) -> bool:
        return self.contains_c(sensitivity) and self.contains_t(trust)


# 出口工具 → 需要的最低完整性阈值
EXPORT_TOOL_REQUIRED_TRUST: dict[str, Trust] = {
    "memory.write": Trust.T2_MEDIUM,     # 写回记忆至少 T2
    "file.write": Trust.T3_HIGH,
    "exec_command": Trust.T3_HIGH,
    "firewall_block": Trust.T3_HIGH,
    "host_isolate": Trust.T3_HIGH,
    "api.respond": Trust.T1_LOW,          # 仅响应，几乎不受限
}


# 网络出口工具 —— 一旦声明就会拉低 c_ctx_max
EGRESS_TOOLS: set[str] = {"web_search", "intel_fetch", "api.external"}

# 出口读者要求 —— 每个出口工具对 agent 密级的下限要求
# Fail-closed: 在 EGRESS_TOOLS 中但不在 EGRESS_READERS 中的工具一律拒绝
EGRESS_READERS: dict[str, Clearance] = {
    "web_search": Clearance.L0_PUBLIC,
    "intel_fetch": Clearance.L0_PUBLIC,
    "api.external": Clearance.L1_INTERNAL,
}


def derive_taskscope(
    task_id: str,
    declared_exports: set[str],
    declared_tools: set[str],
    task_max_clearance: Clearance = Clearance.L3_SECRET,
    default_ingest: IngestMode = IngestMode.LEARN,
) -> TaskScope:
    """
    从任务声明的出口与工具自动推导 TaskScope。

    推导规则：
        c_ctx_max = min(任务密级上限, 出口密级上界)
            出口含有网络出口工具 → 密级上限锁定 L0（防止外泄）
        t_ctx_min = max(各出口所需的最低完整性)
            出口需要写回 → T2；出口需要执行高危工具 → T3
    """
    # c_ctx_max: 取所有约束的下界
    cap = task_max_clearance
    if declared_tools & EGRESS_TOOLS:
        cap = Clearance(min(int(cap), int(Clearance.L0_PUBLIC)))
    c_ctx_max = cap

    # t_ctx_min: 取所有出口要求的最高门槛
    thresholds = [Trust.T0_UNTRUSTED]
    for export in declared_exports:
        req = EXPORT_TOOL_REQUIRED_TRUST.get(export, Trust.T0_UNTRUSTED)
        thresholds.append(req)
    for tool in declared_tools:
        req = TOOL_REQUIRED_TRUST.get(tool, Trust.T0_UNTRUSTED)
        thresholds.append(req)
    t_ctx_min = Trust(max(int(t) for t in thresholds))

    return TaskScope(task_id=task_id, c_ctx_max=c_ctx_max,
                     t_ctx_min=t_ctx_min, ingest=default_ingest)
