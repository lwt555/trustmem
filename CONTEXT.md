# TrustMem · 领域词汇表

## 核心概念

### 双平面标签 (Dual-Plane Labels)

每条记忆、每个智能体、每次会话都携带两个独立维度的标签：

- **安全级别 (Clearance / Sensitivity)** — BLP 机密性平面。取值 L0（公开）→ L3（最高机密）。决定「谁能看」。
- **完整性级别 (Integrity / Trust)** — Biba 完整性平面。取值 T0（不可信）→ T3（完全可信）。决定「能不能信」。

两个平面独立传播、独立裁决。BLP 管读取方向（不向上读），Biba 管写入方向（不向下写）。

### 认知层 (Cognitive Layers)

三个信息可见域，按层级组织：

| 层 | 缩写 | 规则 |
|---|---|---|
| 指令层 (Directive) | D | 向下可见：上级可看下级的 D 层记忆，反之不可 |
| 结论层 (Conclusion) | C | 同级+向上可见：同协作组内互通，上级可看 |
| 推理层 (Reasoning) | R | 仅向上可见：只有上级可看推理过程 |

### 四值裁决 (4-Value Verdict)

PDP 对每次记忆访问返回四种判决之一：

| 裁决 | 含义 | 效果 |
|---|---|---|
| **ALLOW** | 允许 | 内容直接进入上下文，可被吸收为长期记忆 |
| **HIDE**（隐藏） | 允许但遮蔽 | 内容变为 `#var#` 句柄，隔离 LLM 取受限答案；不进上下文，不参与标签传播 |
| **CONFIRM** | 需人工确认 | 暂停，等待人工在回路确认后放行 |
| **DENY** | 拒绝 | 操作被阻断，记录审计日志 |

### LOMAC 低水位

读操作后完整性水位的单调递减规则：

```text
T_eff := min(T_eff, T(m))
```

每次读取后，智能体的有效完整性取当前值和读取内容的较小值。这意味着「读了一条不可信的记忆，你的判断也变得不可信了」。

### 可信度衰减 (Trust Decay)

写入新记忆时，输出完整性由四个因素决定：

```text
T(m_out) = min(min_i T(m_in^i), T_intrinsic(A)) - δ(op)
```

其中 δ(op)：VERBATIM/EXTRACT = 0，SUMMARIZE/INFER/FUSE = 1。

隐含规则：**可信度只有一条上升通道（Upgrader 背书门），其余全部单调不增。**

### 任务区间 (TaskScope)

每个任务实例自动推导的可行区间，三个维度：

- `c_ctx_max`：上下文最高密级
- `t_ctx_min`：上下文最低完整性
- `ingest`：摄取模式，LEARN（可吸收写回）或 CONSULT（仅本轮查阅）

区间从任务声明的出口和工具自动推导，不手填。

### 溯源链 (Provenance Chain)

每条记忆记录其完整来源链：`chunk_id` 列表，追溯到最初情报源。

不变式 I14：CONSULT 模式读入的记忆，其 chunk_id 禁止出现在任何写回记忆的溯源链中。

### 智能体 (Agent)

系统中的六个参与者，各自拥有独立的：
- **安全级别** (L0–L3)：决定能读什么
- **完整性级别** (T0–T3)：决定被信多少
- **角色属性** (Role)：展开为属性集合，用于 CP-ABE 策略
- **工具注册表** (Tool Scope)：可调用的工具列表，每个工具有完整性门槛
- **任务域** (Task Domain)：绑定的任务范围
- **协作组** (Collab Group)：C 层互通的组

| Agent | 角色 | 职责 |
|---|---|---|
| Planner | 计划者 | 分解任务、统筹调度、分配子任务给下游 |
| Intel | 情报员 | 收集外部情报、验证信息源、上报原始数据 |
| Log | 日志员 | 汇聚情报、持久化记忆、维护索引 |
| Analyst | 分析师 | 分析情报、生成结论、写分析报告 |
| Executor | 执行者 | 执行具体操作（封禁/隔离/告警） |
| Auditor | 审计员 | 回溯全链路、验证合规性、发现异常 |

### 隔离 LLM (Isolated LLM)

处理 HIDE 裁决中 `#var#` 句柄的专用 LLM 实例：
- **无工具**：不能调用任何外部功能
- **受限输出**：只能返回 bool/enum/number
- **4 bit 控制流预算**：一���会话最多影响 16 次二元决策

安全假设：隔离 LLM 可能被注入，但无工具 + 受限输出 + 容量封顶保证了影响上界。

### Merkle 审计树

SHA-256 域分离（0x00 叶子，0x01 节点）的二叉 Merkle 树。13 类事件记录，可回放任一会话的完整决策链。

## 缩写对照

| 缩写 | 全称 | 中文 |
|---|---|---|
| BLP | Bell-LaPadula | 贝尔-拉帕杜拉模型 |
| Biba | Biba Integrity Model | 比巴完整性模型 |
| LOMAC | Low Water-Mark Access Control | 低水位标记 |
| PDP | Policy Decision Point | 策略裁决点 |
| PEP | Policy Enforcement Point | 策略执行点 |
| PIP | Policy Information Point | 策略信息点 |
| CP-ABE | Ciphertext-Policy Attribute-Based Encryption | 密文策略属性基加密 |
| CKKS | Cheon-Kim-Kim-Song | 全同态加密方案 |
| HITL | Human-In-The-Loop | 人工在回路 |
| FAISS | Facebook AI Similarity Search | 向量相似度搜索库 |

## 命名约定

| 上下文 | 用词 |
|---|---|
| 文档/论文 | 安全级别 (Clearance)、完整性级别 (Trust/Integrity) |
| 代码 | `clearance`、`trust`、`sensitivity` |
| 前端 | 机密级 (L0-L3)、完整度 (T0-T3) |
| PPT | 谁能看（机密级）、能不能信（完整度） |
