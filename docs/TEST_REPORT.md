# TrustMem 功能验证报告（F-33 重写版）

环境：Python 3.12.7 / commit `a8940ef` / 日期：2026-08-13 / 全量测试 **541 passed**

---

## 一、总结论（三句）

1. **内核安全语义已全部对齐设计文档**：双平面标签格 (L0–L3 / T0–T3)、三水位 `c_eff`/`t_eff`/`t_eff_ctl`、
   四值裁决 ALLOW/HIDE/CONFIRM/DENY、PDP/PEP 判定生效分离、CP-ABE 密钥隔离（KEM 路线 B）、
   ECDSA P-256 写入签名、13 类锚定事件 + 回放、HITL 门与能力分级均已落地并有验收测试。

2. **设计文档不变式 I1–I14 已全部有测试覆盖**（此前「编号撞车」已修正，见第二节对照表）。
   旧报告「I1–I14 穷举 0 违反」测的是 `test_invariants.py` 自己的一套编号，**不是**设计文档那 14 条；
   修补后 `tests/test_design_conformance.py` 补齐了设计文档编号的永久回归。

3. **攻击消融是真实三档实验，不是硬编码常量**：13 条攻击在同一份脚本下跑
   `NO_PROTECTION` / `DENY_ONLY` / `FULL` 三档，`succeeded` 由攻击目标是否实际达成判定。
   旧报告「13 条攻击 A/B 对照全通过」里的 OFF 档曾是 `success = True` 常量（F-13 修复前），现已移除。

---

## 二、设计文档不变式编号 ↔ 测试函数名（F-33 核心交付物）

> 背景：`tests/test_invariants.py` 的 `I1–I14` 与设计文档的 `I1–I14` 是两套编号，只是撞车。
> 下表左列是**设计文档**的定义，右列是**实际覆盖它的测试函数**。

| 设计文档不变式 | 定义 | 覆盖测试函数 |
|---|---|---|
| I1 | 无读上（硬拒绝，不可 HIDE） | `test_design_conformance.py::test_I1_no_read_up_is_hard_deny` |
| I2 | 需知（task_domain / collab_group 交集） | `test_invariants.py::test_I6_need_to_know` |
| I3 | 无写下（先判决后解密，密文落库） | `test_design_conformance.py::test_pipeline_decrypts_real_ciphertext`；`test_invariants.py::test_I13_no_write_down_without_declassify` |
| I4 | 出口约束 `c_eff ⊑ EGRESS_READERS` | `test_design_conformance.py::test_F02_high_watermark_blocks_public_egress` / `test_F02_param_label_checked_independently` |
| I5 | 无写上（Biba-Star） | `test_invariants.py::test_I4_no_write_up` |
| I6 | 低水位单调不增（唯一上升通道=背书门） | `test_invariants.py::test_I3_low_water_mark`；`test_design_conformance.py::test_F05_no_elevate_method` / `test_F05_trust_only_rises_via_gate` |
| I7 | 高水位单调不减 | `test_l2_lattice.py::test_c_eff_present` |
| I8 | 隐藏中立性（HIDE 不改任何水位与预算） | `test_design_conformance.py::test_I8_consult_changes_nothing` / `test_I8_scope_hide_changes_nothing` / `test_I8_deny_changes_nothing` |
| I9 | 高危工具门（P-T 查 `t_eff_ctl` + provenance） | `test_design_conformance.py::test_F03_pt_uses_ctl_watermark` / `test_F03_provenance_and_ctl_both_checked` |
| I10 | R 层仅向上 | `test_invariants.py::test_I2_reasoning_only_upward` |
| I11 | 容量预算 ≤ 4 bit | `test_design_conformance.py::test_F24_single_budget_of_four_bits` |
| I12 | 越格必留痕（背书需验签 + 结构校验系统执行） | `test_design_conformance.py::test_TR13_human_endorsement_requires_signature` / `test_TR12_structural_cannot_be_self_declared` |
| I13 | 区间单调收紧（`widen` 抛异常） | `test_design_conformance.py::test_F09_widen_always_raises` / `test_F09_narrow_only_tightens` |
| I14 | 查阅不留痕（CONSULT 禁写回） | `test_invariants.py::test_I14_consult_no_provenance`；`test_l3_trust_rules.py::test_TR10_consult_write_deny` |

14/14 全覆盖，无一「只在文档里」。

---

## 三、攻击消融（F-13 三档真实实验）

13 条攻击（`scenarios/attacks.py` A1–A13）全部改写为统一形状，同一份脚本跑三档 PDP 配置：

| 档位 | 配置 | 含义 |
|---|---|---|
| `NO_PROTECTION` | `bypass_all=True` | 无防护消融档 |
| `DENY_ONLY` | 全检查生效，`hide_enabled=False` | 纯拒绝消融档 |
| `FULL` | 全检查 + HIDE + 双平面 | 完整防护 |

关键断言（`tests/test_ablation_integrity.py` + `tools/regress.py` B3）：

- **三档同脚本**：每条攻击三档的 `step_signature` 一致（否则不构成消融）。
- **A11 双平面各拦一次**：`blocked_by` 同时含 `NoWriteDown`（机密性平面）与 `Flow-Egress`（完整性平面）。
- **A13 八跳传播**：`FULL.laundered_at is None`（不被洗白）、`NO_PROTECTION.laundered_at is not None`、
  `trust_curve` 单调不增，跑满 8 跳。
- **表 6 ②③ 同 ASR**：`DENY_ONLY` 与 `FULL` 攻击成功率一致（HIDE 不影响拦截）。

绘图脚本 `scripts/generate_figures.py` 已改为从 `bench/*.json` 实测产物读取，无硬编码数值。

---

## 四、结论

- 全量回归：`python -m pytest tests/ -q` → **541 passed**。
- 三条基线回归：`python tools/regress.py` → B1（可信规则对拍）/ B2（设计一致性）/ B3（攻击消融）全绿。
- 契约对账：`python tools/contract_check.py --check` → 与 HEAD 一致。

### 仍未完成（如实交代）

| 项 | 说明 |
|---|---|
| F-11 CKKS 密钥拆分 | `core/crypto/ckks.py` 仍先解密；路线 B（Public/SecretContext 拆分）未做 |
| F-17 38 条基准任务 + 八张表 | `bench/benchmark.py` 仅覆盖核心模块微基准 |
| F-23 隔离 LLM 约束解码 | 仍是关键词匹配，无真约束解码 |
| F-26 Role 枚举对齐 | Intel/Log 尚未替换 Retriever/External |
| F-30 前端双水位标尺 + 粒子三态 | 核心已做：节点填充深浅=机密性、右侧双水位标尺（c_eff↑/t_eff↓ + t_eff_ctl + 4bit 容量）、粒子三态；「第 3/4 屏」（graph 场景逐事件水位）仍缺（提示词 §4.3 可推迟） |

这些项已逐条列入 `docs/LIMITATIONS.md`，不掩盖、不虚报。
