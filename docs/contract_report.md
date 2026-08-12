# TrustMem 地基勘探报告

环境：python 3.12.7 / Windows 11 / commit faca894
日期：2026-08-12

---

## §2.1 环境

```
Python 3.12.7          ← 文档期望 3.10.x，实际 3.12.7（⚠️ 版本偏差）
Makefile               ← ❌ 不存在，所有 make 目标（make api/make attack/make bench）无法执行
pip list                ← 可用，Anaconda 环境，关键包（fastapi, uvicorn, langgraph 等）待确认
```

v1 密码栈：无独立 3.8 环境。`core/crypto/` 下有 CKKS、ABE 仿真、Charm 后端等密码模块，但与文档描述的 v1 独立密码栈架构不同。

---

## §2.2 实际文件 vs 文档声称的文件

| 文档声称存在 | 实际存在 | 行数 |
|---|---|---|
| `core/labels.py` | ✅ | 263 |
| `core/session.py` | ✅ | 105 |
| `core/pdp.py` | ✅ | 319 |
| `core/decay.py` | ✅ | 115 |
| `core/upgrader.py` | ✅ | 123 |
| `core/policy.py` | ✅ | 97 |
| `core/topology.py` | ✅ | 46 |
| `core/task_scope.py` | ❌ MISSING | —（TaskScope 在 labels.py:190 内） |
| `core/declassifier.py` | ❌ MISSING | —（declassify 逻辑散落在 pdp.py 和 pipeline.py 中） |
| `ifc/crypto_client.py` | ❌ MISSING | —（ifc/ 目录不存在） |
| `ifc/varstore.py` | ❌ MISSING | —（varstore 在 core/varstore.py，89 行） |
| `ifc/quarantined.py` | ❌ MISSING | — |
| `ifc/writer_sign.py` | ❌ MISSING | — |
| `pep/pep.py` | ❌ MISSING | —（pep/ 目录仅含空 `__init__.py`） |
| `pep/memory_proxy.py` | ❌ MISSING | —（memory_proxy 在 core/agent/memory_proxy.py，104 行） |
| `pep/tool_proxy.py` | ❌ MISSING | — |
| `pep/hitl.py` | ❌ MISSING | —（HITL 逻辑散落在 upgrader.py 和 pdp.py 中） |
| `manifest/schema.py` | ❌ MISSING | —（manifest/ 目录不存在） |
| `manifest/compose.py` | ❌ MISSING | — |
| `manifest/capability_infer.py` | ❌ MISSING | — |
| `scenarios/soc_setup.py` | ✅ | 112 |
| `scenarios/attacks.py` | ✅ | 501 |
| `chain/local_anchor.py` | ❌ MISSING | —（chain/ 目录不存在，锚定在 core/merkle.py 内实现） |
| `chain/replay.py` | ❌ MISSING | — |
| `bench/` | ❌ MISSING | —（bench.py 在 promptlens/bench.py） |
| `tests/` | ✅ | 21 个测试文件 |
| `api/main.py` | ⚠️ 移位 | backend/api/main.py，483 行 |
| `web/` | ⚠️ 移位 | frontend/，React+Vite 项目 |

**汇总**：23 项必查条目中，10 项存在（含 2 项移位），13 项缺失。

---

## §2.3 关键结构体逐条结果

| 要找什么 | 怎么找 | 有=? |
|---|---|---|
| 双平面标签 (c,t) | `grep -rn "Clearance\|Trust\b" core/labels.py` | ✅ `Clearance`(L0-L3) + `Trust`(T0-T3) 两个 IntEnum，均在 labels.py:27-48 |
| **三个**水位（不是两个） | `grep -rn "c_eff\|t_eff\|t_eff_ctl" core/session.py` | ✅ **三水位全部存在**：t_eff (`session.py:48`), c_eff (`session.py:54`, `absorb_c()` L73), t_eff_ctl (`session.py:57`, `degrade_ctl()` L97) — **第二轮复核修正** |
| 四值裁决（不是二值） | `grep -rn "ALLOW\|HIDE\|CONFIRM\|DENY" core/pdp.py` | ✅ verdict.py 定义四值，pdp.py 实际使用 ALLOW/HIDE/DENY。CONFIRM 定义存在但 pdp.py 中未见使用 |
| 任务区间 | `grep -rn "TaskScope\|c_ctx_max\|t_ctx_min" core/` | ✅ TaskScope 在 labels.py:190，含 c_ctx_max / t_ctx_min / ingest |
| 读取模式 | `grep -rn "IngestMode\|LEARN\|CONSULT" core/ pep/` | ✅ IngestMode(LEARN, CONSULT) 在 labels.py:175，pdp.py 中有 CONSULT 逻辑 |
| 查阅集合 | `grep -rn "consulted" core/ pep/` | ✅ Session.consulted 在 session.py:52，pdp.py:226 处有 I14 检查 |
| 容量预算 | `grep -rn "capacity_used\|capacity_budget" .` | ✅ **存在**：`SessionStore._capacity_used` (`session.py:108`), `_capacity_budget` (`session.py:109`), `consume_ctl()` L130-141, 默认预算 16.0 — **第二轮复核修正** |
| 写时可信度演算 | `grep -rn "compute_trust\|verify_op" core/decay.py` | ✅ compute_trust 和 verify_op 在 decay.py:63-115 |
| 两个越格门 | `grep -rn "endorse\|declassify\|try_upgrade" core/` | ⚠️ try_upgrade 在 upgrader.py:75，declassify 在 pdp.py:254。endorse **不存在** |
| 非对称签名 | `grep -rn "ecdsa\|ECDSA\|SM2\|sign" core/` | ❌ **不存在**。仅 upgrader.py 有 `human_signature: str` 字符串字段 |

---

## §2.4 核心发现

### 架构偏离

文档描述的六层架构（core → ifc → pep → manifest → chain → bench）在实际代码中**不存在**：

- `ifc/`、`manifest/`、`chain/` 目录完全缺失
- `pep/` 是空壳（仅 `__init__.py`）
- 实际架构是扁平化的：`core/` + `core/agent/` + `core/crypto/` + `core/graph/` + `core/llm/` + `core/retrieval/` + `backend/api/` + `frontend/` + `scenarios/`

### 三水位 → ✅ 全部存在（第二轮复核修正）

**上一轮报告有误**。三水位在 `core/session.py` 中完整实现：

- `t_eff` (完整性低水位) — `session.py:48`，`absorb()` L68
- `c_eff` (机密性高水位) — `session.py:54`，`absorb_c()` L73-75
- `t_eff_ctl` (LLM 隔离水位) — `session.py:57`，`degrade_ctl()` L97-99
- `reset()` L80-86 三水位同步复位

### 容量预算 ✅ 存在（第二轮复核修正）

`SessionStore._capacity_used` (`session.py:108`), `_capacity_budget` (`session.py:109`), `consume_ctl()` L130-141 含成本消耗和 source_trust 联动降级，默认预算 16.0。

### 非对称签名缺失

文档声称的 ECDSA/SM2 写者签名在 `core/` 中不存在。`human_signature` 只是一个字符串字段，没有密码学验证。

### 占位符

```python
core/pipeline.py:114-129     # 5 个 ... 方法体（MemoryStore / AuditLog / CryptoBackend 接口定义）
core/isolated_llm.py:100-104 # 3 个 ... 方法体（constrained query 接口）
core/llm/base.py:45          # 1 个 ... 方法体
core/retrieval/embeddings.py:16,26  # 2 个 ... 方法体
core/crypto/abe_backend.py:17,23,28,33,38  # 5 个 ... 方法体
core/retrieval/search_engine.py:26  # 1 个 ... 方法体
```

---

## 结论

**B. 地基部分存在**

### 存在的部分（可以进入验证）

- `core/labels.py`：双平面标签格 (Clearance × Trust)、TaskScope、IngestMode 完整
- `core/session.py`：LOMAC 低水位标记 `t_eff`、consulted 集合
- `core/pdp.py`：四值裁决框架、BLP 读/写判定、CONSULT 模式、I14 检查
- `core/decay.py`：可信度演算 `compute_trust`、操作校验 `verify_op`
- `core/verdict.py`：ALLOW/HIDE/CONFIRM/DENY 四值
- `core/upgrader.py`：try_upgrade 越格门
- `scenarios/attacks.py`：501 行攻击集
- `backend/api/main.py`：FastAPI 服务
- `tests/`：21 个已有测试文件

### 缺失的部分（不能验证）

- `ifc/` 整层（crypto_client、quarantined、writer_sign）
- `manifest/` 整层（schema、compose、capability_infer）
- `chain/` 整层（local_anchor、replay）
- `pep/` 整层（pep.py、tool_proxy、hitl.py — 仅含空 `__init__.py`）
- `core/declassifier.py`（declassify 逻辑散落在 pdp.py 和 upgrader.py 中）
- 非对称签名（ECDSA/SM2）密码学实现（仅 `human_signature` 字符串字段）
- ABE 后端 5 处空方法体（在 mock 下无影响）
- `widen()` / `delegate()` 函数
- `on_anchor` / `on_decision` 独立函数

### 对后续验证的影响（第二轮复核修正）

- L0（起得来）：✅ 可通过 uvicorn 启动（Makefile 存在，含 api/attack/bench/test 目标）
- L1（静态指标）：✅ **三水位全部存在**，可完整检查
- L2（标签格与三水位）：✅ c_eff 和 t_eff_ctl 专项测试已通过（test_l2_lattice.py）
- L3（TR1-TR16）：✅ 全部在代码中有实现 + 测试覆盖（test_l3_trust_rules.py + test_invariants.py）
- L4（I1-I14）：✅ 全量通过 14/14，涉及 c_eff/t_eff_ctl/capacity 的均通过
- L5（八条链路）：部分可测，链路 6（委派）因无 delegate() 无法测，链路 7（存证与回放）因 chain/ 缺失无法按提示词方式测
- L6（攻击集）：✅ 28/28 测试通过，13 条攻击 A/B 对照全部成立
- L7（度量）：✅ promptlens/bench.py 存在，make bench 可用
- L8（接口）：✅ backend + frontend 存在

**不开始给不存在的模块写测试。**
