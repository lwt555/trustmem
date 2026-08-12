# TrustMem 可信流转规则 TR1–TR16

> **总纲**：可信度在本系统里**只有一条上升通道**——背书门（TR11–TR14）；
> 其余全部路径单调不增。这条性质使「洗白」与「污染扩散」在结构上失效，而不是靠检测。

本表由 `tools/gen_trust_rules.py` 从代码反向生成——每条规则的实现处用
`@trust_rule` 装饰器登记元数据，脚本扫描生成，与实现永远同步。
改动规则实现后运行 `python tools/gen_trust_rules.py --check` 对拍校验。

## 一、两条独立的格子

TrustMem 的可信流转建立在两条偏序格上：

| 格 | 方向 | 读入效应 | 写出效应 |
|---|---|---|---|
| 机密性格 L（Bell-LaPadula） | 只升不降 | c_eff ← max（高水位） | 无写下（no write down） |
| 完整性格 T（Biba） | 只降不升 | t_eff ← min（低水位） | 无写上（no write up） |

---

## 二、规则表（四组十六条）

每条五列：`ID | 触发事件 | 变化 | 依据 | 代码位置`。

### A 组 · 读入（可信度进入上下文的时刻）

| ID | 触发事件 | 变化 | 依据 | 代码位置 |
|---|---|---|---|---|
| TR1 | LEARN 模式读入一条低可信记忆 | t_eff ← min(t_eff, T(m)) 只降不升；c_eff ← max(c_eff, L(m)) 只升不降 | LOMAC 低水位（Fraser, IEEE S&P 2000） | `core/session.py:85` |
| TR2 | CONSULT 模式读入，或 LEARN 读入超出任务区间 | 裁决 HIDE，c_eff / t_eff / t_eff_ctl 完全不变 | 隐藏中立性 I8 | `core/pdp.py:200` |
| TR3 | 受限展开（bool/enum/number，容量 ≤ 4 bit 且预算充足） | t_eff 下降，t_eff_ctl 不变 | 受限展开（隔离 LLM 的控制流水位不受影响） | `core/varstore.py:101` |
| TR4 | 无界展开（string，或预算耗尽退化） | t_eff 与 t_eff_ctl 一起下降 | 无界展开（数据流与控制流同时被污染） | `core/varstore.py:101` |
| TR5 | 会话结束 reset() | t_eff / t_eff_ctl 复位到 t_intrinsic，c_eff 复位 L0，容量预算清零 | 会话级隔离（会话结束语义） | `core/session.py:125` |

### B 组 · 写出（可信度离开主体的时刻）

| ID | 触发事件 | 变化 | 依据 | 代码位置 |
|---|---|---|---|---|
| TR10 | CONSULT 读入的 chunk 出现在 input_mems | 直接 DENY，不进入衰减计算 | CONSULT 禁写回 I14 | `core/pdp.py:256` |
| TR6 | 写出一条新记忆 | trust_out ≤ meet(输入集合, 主体 t_eff)，取最弱一环，不是 max / 均值 | Biba 无写上（no write up） | `core/decay.py:94` |
| TR7 | 声明 δ=0 的操作（VERBATIM / EXTRACT）但校验失败 | op 强制降为 INFER（δ=1），可信度再降一级 | 谎报降级（δ=0 声明必须可验证） | `core/decay.py:64` |
| TR8 | LLM 加工一条输入（SUMMARIZE / INFER / FUSE） | trust_out 额外减去 δ(op) | 加工衰减（LLM 过程本身引入不确定性） | `core/decay.py:94` |
| TR9 | 跨源融合（FUSE）多条输入 | trust_out ≤ meet(全部输入)，取最脏一环 | 融合取脏（一颗老鼠屎坏一锅汤） | `core/decay.py:94` |

### C 组 · 越格（唯一上升通道：背书门）

| ID | 触发事件 | 变化 | 依据 | 代码位置 |
|---|---|---|---|---|
| TR11 | 越格提升证据：与本地高可信记忆一致 | T ← min(3, T+1)，封顶 T3 | 本地一致性背书 | `core/upgrader.py:89` |
| TR12 | 越格提升证据：结构化校验通过（IOC/CVE/签名） | T ← min(3, T+1)，封顶 T3 | 结构化校验背书 | `core/upgrader.py:89` |
| TR13 | 越格提升证据：人在环显式确认（密码学验签） | T ← T3（直升） | 人在环签名背书 | `core/upgrader.py:89` |
| TR14 | 交叉印证：多个来源需为独立发布实体 | 共享 publisher/ASN 判为 1 源 → 不提升；≥2 独立实体 → T+1 | 抗 Sybil（独立性判到发布实体级） | `core/upgrader.py:64` |

### D 组 · 跨主体（传播边界）

| ID | 触发事件 | 变化 | 依据 | 代码位置 |
|---|---|---|---|---|
| TR15 | 委派创建子会话（跨主体边界） | t_eff_child ← min(t_eff_parent, t_intrinsic_child)；区间只能更紧 | 委派继承只紧不松（§3.6） | `core/session.py:186` |
| TR16 | 记忆跨主体传播（写入即定标） | provenance_trust 钉死在写时衰减值，不随写者固有可信度重置 | 跨主体边界复合（A 组读入 + B 组写出在边界上复合） | `core/pipeline.py:169` |

---

## 三、三段论证（设计文档第十部分第 5 条）

### 3.1 分组即分阶段

可信度只在三个时刻可能变化——**进入上下文、离开主体、显式越格**：

| 组 | 作用时刻 | 时序 |
|---|---|---|
| A 组（TR1–TR5） | 读入：可信度进入上下文 | 最先 |
| B 组（TR6–TR10） | 写出：可信度离开主体 | 其次 |
| C 组（TR11–TR14） | 越格：显式背书 | 唯一上升 |
| D 组（TR15–TR16） | 跨主体：传播边界 | A+B 的复合 |

四组在时序上互斥，因此**不存在组间冲突**。

### 3.2 组内优先级（代码可验证）

- **A 组**：`TR2 > TR1`（模式检查先于标签判定——CONSULT 读入不触发 LOMAC 吸收）
- **B 组**：`TR10 > TR7 > TR9 > TR8 > TR6`（硬拒 > 谎报降级 > 融合取脏 > 加工衰减 > 基线 meet）

实现位置：`PDP.can_write` 中 TR10（Provenance-NoConsult）最先判定，命中即 DENY，
不进入 `compute_trust` 的衰减计算；衰减计算内部按 TR7（谎报降级）→ TR9/TR8（取脏+衰减）
→ TR6（基线 meet）的顺序执行。

### 3.3 完备性论证

可信度只在三个时刻可能变化——进入上下文、离开主体、显式越格。
A/B/C 三组各覆盖一个，D 组是 A+B 在跨主体边界上的复合。
穷举测试（`test_invariants.py`：4×4×4×4 全组合 + 7000 条随机操作序列）是这条论证的实测支撑。

---

## 四、与经典 Biba 的差异

| 维度 | 经典 Biba | TrustMem |
|---|---|---|
| 处理数据是否改变完整性 | 不变（主体处理数据不改变完整性） | LLM 会幻觉，过程本身计入衰减 δ(op)（TR8） |
| δ=0 声明 | 无校验 | VERBATIM/EXTRACT 必须可验证，失败降 INFER（TR7） |
| 完整性提升 | 无 | 唯一上升通道：背书门（TR11–TR14），抗 Sybil、可上链 |
