# TrustMem 信任规则体系 v2

## 一、两条独立的格子

TrustMem 的权限判定基于两条独立的偏序格（lattice），而非传统的单轴权限模型。

### 1.1 保密性格 L（Bell-LaPadula, 1973）

管控"能不能看"——主体密级不低于客体密级才可读。

| 等级 | 名称 | 说明 |
|---|---|---|
| L0 | PUBLIC | 公开信息，无限制 |
| L1 | INTERNAL | 内部信息，仅内部人员可访问 |
| L2 | SENSITIVE | 敏感信息，需授权 |
| L3 | SECRET | 机密信息，最高管控 |

### 1.2 完整性格 T（Biba, 1977）

管控"能不能信"——低完整性数据不能污染高完整性决策。

| 等级 | 名称 | 说明 |
|---|---|---|
| T0 | UNTRUSTED | 已知被污染、校验失败、不可用于任何可信决策 |
| T1 | LOW | 公开互联网、用户上传、未验签的外部情报 |
| T2 | MEDIUM | 内部但未校验、LLM 推理产生 |
| T3 | HIGH | 内部权威源、已验签、人在环确认 |

**为什么必须是两条独立格子：** 从公开互联网抓取的 IOC 密级极低但可信度也极低。单轴模型下高权限主体读低密级客体完全合法——投毒直达执行端。

---

## 二、认知层维度（Layer）

多智能体特有的第四维度，管控记忆在认知层级间的可见性。

| 层 | 编号 | 可见规则 |
|---|---|---|
| D (Directive) | 命令层 | 向下可见——上级写的命令下级可见 |
| C (Conclusion) | 结论层 | 同级 + 向上可见——共享协作组或上级可读 |
| R (Reasoning) | 思考层 | **仅向上可见**——owner / 上级 / Auditor 可读 |

**R 层仅向上的核心安全意义：** 推理链是最优注入载体。攻击者控制一个下级后，若能读到上级的思考过程，就实现了黑盒攻击→白盒攻击的跨越——可以精确构造绕过上级判断逻辑的恶意输入。

---

## 三、四值裁决（4-Value Verdict）

PDP 返回四种裁决，而非简单的 allow/deny 二元判定。

| 裁决 | 含义 | 行为 |
|---|---|---|
| **ALLOW** | 完全放行 | 解密内容，正常访问，触发低水位标记 |
| **HIDE** | 隐藏但不完全阻断 | 内容替换为 #var# 占位符，允许受限的结构化查询 |
| **CONFIRM** | 需人在环确认 | 挂起等待人类审批 |
| **DENY** | 完全阻断 | 拒绝所有形式的访问 |

**HIDE 的判据：** 当 BLP 简单安全特性失败（主体密级 < 客体密级）时返回 HIDE，而非 DENY——允许受限的结构化查询（如"这个 chunk 是什么时间写的"），但不返回实际内容。

---

## 四、读操作规则（5 条检查）

每次 `can_read` 执行 6 条检查，全部通过才返回 ALLOW。

### R1. BLP 简单安全特性（no read up）

```
主体密级 >= 客体密级
```

失败 → HIDE（而非 DENY），允许受限查询。

### R2. Need-to-Know

```
客体的 task_binding ∈ 主体的 task_domain
```

Agent 只能读绑定到其任务域的记录，实现最小权限原则。

### R3. 认知分层（Cognitive Layer）

| 客体层 | 谁能读 |
|---|---|
| D 层 | owner 的下级 |
| C 层 | 同协作组 或 上级 |
| R 层 | owner / 上级 / Auditor |

### R4. 时间窗（TTL）

```
主体标签和客体标签均在有效期内
```

过期的 Agent 标签不能读任何记录，过期的 Memory 不能被任何 Agent 读取。

### R5. 属性版本（Epoch）

```
agent.epoch >= memory.epoch
```

Agent 标签的 epoch 低于记忆要求的 epoch → 拒绝。权限变更通过升级 epoch 实现旧密钥失效。

### R6. 生命周期（Lifecycle）

```
memory.lifecycle == "active"
```

非 active 状态（archived / revoked）的记忆不可读。

---

## 五、低水位标记（LOMAC）

### 核心机制

```
读操作:  T_eff(A) ← min(T_eff(A), T(m))
写/执行: 要求 T(output) <= T_eff(A)
```

允许读低完整性数据，但读取后主体的有效完整性等级立即降到该数据水平。被污染的主体无法产生高完整性输出或触发高风险动作。

### 三条防坍缩机制

| 机制 | 说明 |
|---|---|
| 会话级隔离 | T_eff 只在当前任务会话内下降，会话结束重置到 T_intrinsic |
| 提升网关 | 交叉印证 / 结构校验 / 人在环可提升 T_eff（见 upgrader.py） |
| 降级≠禁用 | T1 记忆仍可读、可分析、可展示，受限的只是入高可信决策链和触发高危工具 |

---

## 六、写操作规则（3 条检查）

### W1. CONSULT 禁写回（I14）

```
CONSULT 模式读入的 chunk_id 禁止出现在任何写操作的 provenance_chain 中
```

"当书翻着看"的内容不能作为决策依据写回长期记忆。违规直接 DENY，不进入后续检查。

### W2. 可信度衰减（Decay）

新记忆的可信度由衰减公式计算：

```
T(m_out) = min(min_i T(m_in^i), T_intrinsic(A)) - δ(op)
```

其中 δ(op) 为操作衰减量：

| 操作 | δ | 条件 |
|---|---|---|
| VERBATIM（逐字引用） | 0 | 输出与输入字面重叠率 ≥ 85% |
| EXTRACT（结构化抽取） | 0 | 输出通过 schema 校验 |
| SUMMARIZE（摘要） | 1 | LLM 可能丢失/扭曲条件 |
| INFER（推理） | 1 | LLM 可能产生幻觉 |
| FUSE（跨源融合） | 1 | 无印证的跨源融合 |

δ=0 的声明必须可验证：校验失败自动降级为 INFER（δ=1）。

### W3. Biba *-特性（no write up）

```
T(new_memory) <= T_eff(writer)
```

被污染的主体无法产生高完整性输出。注意比较的是衰减后的 T(m_out)，即写了受污染的输入后输出的可信度必定降低。

### W4. BLP *-特性（no write down / 受控降密）

```
target_sensitivity >= agent.clearance  → ALLOW（写同级或上级，正常）
target_sensitivity < agent.clearance   → gated:
  gap <= 2 级 → 允许受控降密
  gap > 2 级  → 需要降密审批（declassify_approved=True）
  D 层       → 需受控降密网关 ALLOW + 上链存证
```

### W5. 层级写入权

```
target_layer == DIRECTIVE → 主体必须有下级
```

只有有下级编排权的 Agent 才能写 D 层命令。

---

## 七、工具执行规则（3 条检查）

### I1. 工具背书

```
tool ∈ agent.tool_scope
```

Agent 的工具集来自工具注册表（TOOL_REGISTRY），非自我声明。即使 PromptLens 标注被完全操纵，未注册的工具也拿不到。

### I2. 溯源可信度门槛

```
min(provenance_trust(params)) >= RequiredTrust(tool)
```

各工具的最低可信度要求：

| 工具 | 最低 T_eff |
|---|---|
| web_search, intel_fetch | T0 — 几乎无门槛 |
| log_query | T1 |
| asset_query, file_read | T2 |
| file_write, exec_command, firewall_block, host_isolate | T3 — 最高门槛 |

当提供 provenance 参数时，以参数所属记忆的可信度为准（细粒度溯源）。无 provenance 时以会话 T_eff 为准（会话级污点）。

### I3. 人在环（Human-in-the-Loop）

```
tool ∈ {firewall_block, host_isolate, exec_command} → 需人工确认
```

高危动作必须经过人工确认。`sess.add_hitl(action_fingerprint)` 完成确认。

---

## 八、TaskScope 自动推导

任务级三维约束区间，从声明的出口和工具**自动推导**，不手填。

| 维度 | 规则 |
|---|---|
| c_ctx_max | min(任务密级上限, 出口密级上界)；出口含网络工具 → 锁定 L0 |
| t_ctx_min | max(各出口所需的最小完整性)；写回需 T2，高危工具需 T3 |
| ingest | LEARN（可吸收可写回）或 CONSULT（禁写回，本会话 reset() 即清） |

---

## 九、提示词安全（4 条防线）

1. **输出空间约束** — 非法值丢弃并降级为最低权限
2. **指令隔离** — system_prompt 作为数据分析传入，定界符包裹
3. **工具背书兜底** — 无注册工具则无对应权限
4. **提示词承诺绑定** — prompt_hash 上链锚定，运行时校验不符则私钥失效

---

## 十、规则索引

| 编号 | 规则 | 类型 | 失败裁决 |
|---|---|---|---|
| R1 | BLP no read up | 读 | HIDE |
| R2 | Need-to-Know | 读 | DENY |
| R3 | Cognitive Layer | 读 | DENY |
| R4 | TTL | 读 | DENY |
| R5 | Epoch | 读 | DENY |
| R6 | Lifecycle | 读 | DENY |
| W1 | Provenance-NoConsult (I14) | 写 | DENY |
| W2 | Trust Decay | 写 | DENY |
| W3 | Biba no write up | 写 | DENY |
| W4 | BLP-Star no write down | 写 | DENY |
| W5 | LayerWrite | 写 | DENY |
| I1 | ToolScope | 执行 | DENY |
| I2 | ProvenanceTrust | 执行 | DENY |
| I3 | HumanInTheLoop | 执行 | DENY |
| — | LOMAC 低水位 | 副作用 | —（降级而非阻断） |

---

## 十一、信息流不变式（14 条）

这些不变式对全标签空间穷举验证，无一违反（覆盖率 100%）。

| 编号 | 不变式 |
|---|---|
| I1 | BLP 保密性：放行的读，主体密级必不低于客体 |
| I2 | 认知分层：R 层只对 owner / 上级 / Auditor 可读 |
| I3 | 低水位单调性：T_eff = min(初始, 所有已读记忆) |
| I4 | Biba 完整性：放行的写，新记忆可信度必不高于 T_eff |
| I5 | 污染会话禁高危：T1 以下污染的会话无法触发 T3 高危动作 |
| I6 | Need-to-Know：任务域不匹配的读必被拒 |
| I7 | TTL：过期主体标签阻断所有操作 |
| I8 | Epoch 版本隔离：agent.epoch < memory.epoch 时读被拒 |
| I9 | Lifecycle：非 active 记忆不可读 |
| I10 | LayerWrite：无下级的 Agent 不可写 D 层 |
| I11 | 会话隔离：跨 Session 的 T_eff 互不影响 |
| I12 | TaskScope 推导一致性：出口不可超范围 |
| I13 | 写降密：跨 3+ 级降密未经审批时写被拒 |
| I14 | CONSULT 禁写回：CONSULT 模式读入的内容禁止写回 |

验证规模：6 Agent × 4 密级 × 4 可信 × 3 认知层 × 3 动作 = 全组合穷举。
