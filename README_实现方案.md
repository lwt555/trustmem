# TrustMem v2 · 实现方案

代码已跑通。本文说明架构、集成点、技术栈、6 天排期与验收标准。

```
python tests/test_invariants.py     # 不变式穷举验证
python -m scenarios.attacks         # 四个攻防 A/B
python -m promptlens.bench          # 标注准确率消融
```

---

## 一、架构：为什么必须做成中间件

### 1.1 PDP / PEP 分离（XACML 术语）

```
        Agent 业务代码（不改）
                 │
    ┌────────────┴────────────┐
    │   PEP  策略执行点        │   ← memory_proxy / tool_proxy
    │   拦截 read/write/invoke │      A/B 开关就是这里一个 bool
    └────────────┬────────────┘
                 │ 请求裁决
    ┌────────────▼────────────┐
    │   PDP  策略裁决点        │   ← core/pdp.py，纯函数、无副作用、可穷举
    │   BLP × Biba × Layer     │
    └────────────┬────────────┘
                 │
    ┌────────────▼────────────┐
    │  PIP 策略信息点          │   ← 标签库(labels) + 会话态(session) + 拓扑(topology)
    └─────────────────────────┘
```

**三个必须做成中间件的理由：**

1. **演示开关。** `PEP.enabled = False` 一行就能切成"无防护"，左右分屏对照。如果权限逻辑写在 Agent 代码里，你没法做 A/B。
2. **可穷举。** PDP 是纯函数：`(AgentLabel, MemoryLabel, Session) → Decision`。正因为没有副作用（除低水位外显式返回），才能对全部标签组合穷举验证。
3. **可复用。** 换个多智能体框架（LangGraph/AutoGen/CrewAI）只需重写 PEP，PDP 一行不动。答辩问"怎么接现有框架"，这就是答案。

### 1.2 代码结构

| 路径 | 职责 | 状态 |
|---|---|---|
| `core/labels.py` | 标签本体、两条格、工具可信门槛 | ✅ 完成 |
| `core/topology.py` | 编排 DAG，ancestors/descendants | ✅ 完成 |
| `core/decay.py` | 可信度衰减代数 + δ=0 声明的可验证性 | ✅ 完成 |
| `core/session.py` | 会话态、低水位标记 | ✅ 完成 |
| `core/pdp.py` | 裁决引擎 can_read/can_write/can_invoke | ✅ 完成 |
| `core/upgrader.py` | 可信提升网关 | ✅ 完成 |
| `core/policy.py` | 标签 → CP-ABE 策略串 | ✅ 完成 |
| `promptlens/pipeline.py` | 三阶段自动标注 | ✅ 完成 |
| `promptlens/bench.py` | 标注评测 + 消融 | ✅ 完成 |
| `scenarios/soc_setup.py` | 六 Agent SOC 编排 | ✅ 完成 |
| `scenarios/attacks.py` | 四个攻防 A/B | ✅ 完成 |
| `tests/test_invariants.py` | 五条不变式穷举 | ✅ 完成 |
| `pep/memory_proxy.py` | 记忆读写拦截 | ⬜ 待写（~80 行） |
| `pep/tool_proxy.py` | 工具调用拦截 | ⬜ 待写（~60 行） |
| `chain/anchor.py` | 上链事件封装 | ⬜ 接现有 FISCO SDK |
| `api/main.py` | FastAPI + WebSocket 推裁决日志 | ⬜ 待写 |
| `web/` | React 四屏前端 | ⬜ 待写 |

**核心逻辑已全部完成，剩下的是接线和界面。**

---

## 二、与现有 v1 系统的集成

### 2.1 三个接入点，不动现有 CP-ABE / CKKS / 链

| 现有模块 | 改动 | 工作量 |
|---|---|---|
| CP-ABE 加解密 | 只换策略串生成函数，调 `core/policy.py::policy_from_label` | 半天 |
| 属性私钥签发 | 属性集合改用 `agent_attributes()`；签发载荷加 `prompt_hash` | 半天 |
| CKKS 密态检索 | **完全不动**。检索前多一次 `can_read` 裁决 | 0 |
| Main-Delta 索引 | **完全不动** | 0 |
| 链上存证 | 新增 5 类事件（见 2.3） | 半天 |
| 前端 | 重做，见第五节 | 2 天 |

### 2.2 CP-ABE 集成的两个关键点

**(1) 序关系必须展开为析取。** CP-ABE 不支持数值比较：

```python
# clearance ≥ L2  →  (clearance_2 or clearance_3)
lv = [f"clearance_{i}" for i in range(int(mem.sensitivity), 4)]
```

**(2) 关系型属性在签发期展开。** `layer=R` 的策略需要"owner 的上级"，
拓扑固定后把 `ancestorof_{X}` 作为静态属性发给每个 X 的上级：

```python
for d in topo.descendants(agent_id):
    attrs.append(f"ancestorof_{d}")
```

### 2.3 新增的上链事件

| 事件 | 触发时机 | 为什么非上链不可 |
|---|---|---|
| `AGENT_LABEL_ISSUE` | 标注完成、私钥签发 | `prompt_hash` 承诺，各方都不能单独改 |
| `TRUST_UPGRADE` | 提升网关放行 | 提升是特权操作，必须不可抵赖 |
| `DECLASSIFY` | D 层受控降密 | 唯一的向下信息流出口，必须留痕 |
| `ACCESS_DENIED` | 越权拦截 | 争议时的证据 |
| `HITL_CONFIRM` | 人工确认高危动作 | 责任认定 |

> 答辩「区块链是不是硬凑的」的诚实答法：单一运营方场景下 Merkle 追加日志 +
> TSA 时间戳就够。联盟链的不可替代性在**跨组织多智能体协作** —— 不同厂商的
> Agent 协同时，`prompt_hash` 承诺需要一个各方都无法单独修改的锚点。

---

## 三、技术栈

| 层 | 选型 | 备注 |
|---|---|---|
| 编排 | **LangGraph** | 唯一能稳定拿到 intermediate steps 的主流框架，R 层记忆靠它 |
| PEP | 自研 Python 中间件 | 见 1.1 |
| 向量 | 沿用现有 FAISS/Milvus 层次聚类 | 不动 |
| CP-ABE | `charm-crypto` (bswabe) | 已在用。装不上可退 `rabe` Rust 绑定 |
| 同态 | `TenSEAL` (CKKS) | 已在用 |
| 链 | FISCO BCOS + Python SDK | 已在用 |
| 标签库 | SQLite / PostgreSQL | 标签是结构化小数据 |
| 会话态 | Redis（或进程内 dict） | `T_eff` 高频读写 |
| API | FastAPI + WebSocket | 裁决日志实时推前端 |
| 前端 | React + ReactFlow + framer-motion | 拓扑图 + 粒子动画 |

**LangGraph 的接入点（关键）：**

```python
# 1. 记忆读写 —— 替换 checkpointer
graph = StateGraph(...).compile(checkpointer=TrustMemCheckpointer(pep))

# 2. 工具调用 —— 包一层 wrapper
@pep.guard_tool
def firewall_block(ip: str) -> str: ...

# 3. 推理链落 R 层 —— 从 stream 里捞
for chunk in graph.stream(state, stream_mode="updates"):
    if "intermediate_steps" in chunk:
        pep.write(agent, chunk, layer=Layer.REASONING)
```

拿不到 reasoning 的场景（闭源模型无 scratchpad）退化为 D/C 两层，主体机制不受影响 —— 答辩问到直接这么说。

---

## 四、`can_invoke` 的两种溯源粒度

这是全系统最容易被问"误拦怎么办"的地方，两套都实现，前端可切：

| 粒度 | 依据 | 特点 |
|---|---|---|
| **会话级污点**（默认） | `session.t_eff` | 保守、无需 Agent 配合、绝不漏。代价：本会话读过一条 T1 就全线降级 |
| **参数级溯源** | `provenance=[chunk_ids]` | 精确、误拦低。代价：要求 Agent 在工具调用里声明依据，缺失则按 T0 处理 |

口径：「我们默认用会话级污点，因为它**不依赖 Agent 的配合**——被劫持的 Agent 不会诚实声明依据。参数级溯源作为可选优化，用于降低误拦，但对未声明依据的调用一律按最低可信处理。」

---

## 五、前端四屏

现在的界面是 RAG 问答界面 —— 看不到多智能体，看不到权限。会上说"太假""多智能体影子看都看不到"，问题就在这。

| 区域 | 内容 | 演示价值 |
|---|---|---|
| **主视图 60%** | Agent 拓扑图。节点颜色 = 当前 `T_eff`（绿T3/黄T2/橙T1/红T0）；记忆作为粒子在节点间流动，颜色=trust，形状=layer（方块D/圆C/菱形R）；拦截时粒子变红 ✕ 停在边上 | **可信度衰减实时变色是全场最直观的效果**，评委一眼就懂 |
| **右栏** | 裁决日志逐条滚动，直接渲染 `Decision.explain()` 的输出（代码里已经是这个格式） | 让"自动化"和"合理性"可见 |
| **底部** | 标注面板：左贴 system prompt 原文，右显示抽取属性表，中间连线标出哪句推出哪个属性，冲突项标红显示"已保守降级" | 专门回答"你怎么自动打标签" |
| **顶部** | 防护 ON/OFF 大开关 + 攻击场景选择器 + **单步执行**按钮 | 会上要求的"一步一动" |

后端已经把裁决日志做成了可直接渲染的结构（`Decision.checks` 是 `[规则, 通过?, 详情]` 三元组），前端不需要再解析。

---

## 六、6 天排期（今天 8/6，8/12 交稿）

| 日 | 任务 | 人 | 产出 |
|---|---|---|---|
| **D1** 8/6-7 | ①吃透 BLP/Biba/LOMAC ②把本仓库跑通 ③定稿标签本体 | 全员 | 每人能口述双轴模型 |
| **D2** 8/7-8 | 写 `pep/` 两个 proxy；LangGraph 接六个 Agent | 工程A | SOC 链路能真跑 |
| **D2** 8/7-8 | 扩标注评测集到 50–80 条 + 三人独立标注 | 全员分工 | κ 值 + 准确率表 |
| **D3** 8/8-9 | 接 LLM 抽取器，重跑 bench；接 CP-ABE 策略串 | 工程B | 消融表最终版 |
| **D3-D4** | 前端主视图 + 裁决日志 | 工程C | 可演示 |
| **D4** 8/9-10 | 四个攻击接进真实链路，采 A/B 数据 | 工程A | 攻击成功率表 |
| **D5** 8/10-11 | 前端底部标注面板 + 单步执行；上链事件接入 | 工程B/C | 完整演示 |
| **D5-D6** | 改文档：2.3.0 新章节、2.3.4 PromptLens、第四章创新性重写、摘要重写 | 主笔 | 定稿 |
| **D6** 8/11-12 | 全员过 18 问互相拷问；录演示视频备份 | 全员 | 交稿 |

**时间不够时从后往前砍：**
1. 攻击 3（合谋）—— CP-ABE 原生特性，只讲不演
2. 底部标注面板 —— 用静态截图
3. 参数级溯源 —— 只留会话级污点
4. 链上事件 —— 先用本地 Merkle 日志，接口留好

**绝对不能砍：** 攻击 1、攻击 2 的 A/B 演示；主视图的可信度衰减动画；标注准确率数据；不变式覆盖率表。

---

## 七、验收标准（跑出这四张表就够了）

**表 1 · 攻击成功率 A/B**（已跑通）

| 攻击场景 | 防护 OFF | 防护 ON |
|---|---|---|
| 记忆投毒→横向越权 | 100% | 0% |
| 思考过程窃取→定向注入 | 100% | 0% |
| 属性合谋提权 | 100% | 0% |
| 提示词篡改提权 | 100% | 0% |

**表 2 · 信息流不变式覆盖率**（已跑通）

| 不变式 | 验证方式 | 违反 |
|---|---|---|
| I1 BLP no-read-up | 1,728 组合穷举 | 0 |
| I2 R 层仅向上 | 36 组合穷举 | 0 |
| I3 低水位单调性 | 2,000 随机序列 | 0 |
| I4 Biba no-write-up | 3,000 随机写 | 0 |
| I5 污染会话禁高危 | 1,508 污染会话 | 0 |

**表 3 · 标注准确率消融**（已跑通框架，待接 LLM + 扩样本）

| 指标 | A: 纯抽取 | B: +工具背书取交 |
|---|---|---|
| **过授权率** | 40.0% | **0.0%** |
| 欠授权率 | 30.0% | 30.0% |
| 对抗样本检出率 | 100% | 100% |

**表 4 · 开销拆分**（待补，务必分开报）

| 环节 | P50 | P95 |
|---|---|---|
| 权限裁决（纯逻辑） | ? ms | ? ms |
| CP-ABE 解密 DEK | ? ms | ? ms |
| CKKS 密态检索 | ? s | ? s |
| 端到端 vs 无防护基线 | +?% | |

> ⚠ 现有文档报的检索耗时 3.1–4.01s 必须拆开。不拆的话评委会误以为是权限模型很重，
> 实际上裁决只有毫秒级，绝大部分开销在同态计算上。

---

## 八、代码里埋的三个答辩加分点

**① CP-ABE 只管读，不管写（`core/policy.py` 模块注释）**

CP-ABE 只约束解密，不约束加密——任何人都能用任意策略加密。所以保密性可以用密码学强制，完整性只能靠运行时 PDP。更根本的原因：完整性约束是**状态相关**的（`T_eff` 随会话变化），而密码学策略在加密那一刻就固定了，静态策略天然表达不了动态状态。

这是回答"为什么不把所有事都用密码学做"的标准答案，也解释了信任假设里为什么必须保留可信 PEP。

**② δ=0 的声明必须可验证（`core/decay.py::verify_op`）**

如果 Agent 只要声称自己是"逐字引用"就能规避衰减，整套代数就废了。所以 `VERBATIM` 要校验字面重叠率 ≥0.85，`EXTRACT` 要校验 schema 通过，不过就自动降级为 `INFER`（δ=1）。

**③ 网络出口 × 高密级 = 外泄通道（`promptlens/pipeline.py::EGRESS_EXFIL_PATH`）**

这条是写评测时发现的真实缺口：一个 Agent 同时具备"读高密级记忆"和"访问外网"两种能力，本身就是数据外泄路径，跟它有没有被攻击无关。标注阶段直接把这类 Agent 的密级钉死在 L0。这是 confused-deputy 的经典形态，加上这条之后过授权率才从 10% 降到 0。

答辩时可以主动讲这个发现过程——它证明你们不是把模型抄下来，是真跑通了。
