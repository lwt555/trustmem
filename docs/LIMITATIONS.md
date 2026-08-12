# TrustMem 已知局限与推迟项（如实交代）

> 本文按《TrustMem 修补工程提示词》§4.3 编写，逐条交代「当前实现」与「设计文档宣称」之间的
> 差距。原则（设计文档 8.6 引老师原话）：**编出来的完美 100% 比报出来的缺口更容易被翻穿。**

## 1. 已完成的最小可交付集

以下 F 项已实现、已有验收测试、全量测试通过（456 passed）：

| F 编号 | 内容 | 验收测试 |
|---|---|---|
| F-01 | 无读上是硬拒绝（DENY 非 HIDE） | `tests/test_hard_deny.py` |
| F-02 | Flow-Egress 出口方向修正 | `tests/test_egress.py` |
| F-03 | P-T 门改查 `t_eff_ctl` | `tests/test_pt_gate.py` |
| F-04 | 判定/生效分离，水位单一入口 | `tests/test_i8_neutrality.py` |
| F-05 | 删除 `elevate()` 无门直升 | `tests/test_invariants.py` |
| F-06 | TR3/TR4 受限展开语义方向 | `tests/test_expand.py` |
| F-07 | 区间外可信度 HIDE 非 DENY | `tests/test_hide_path.py` |
| F-08 | 判定序：硬拒 → 模式 → 区间 | `tests/test_s4_gaps.py` |
| F-12 | 先判决后解密 + 解密账本 | `tests/test_decrypt_ledger.py` |
| F-13 | 真实三档消融（无硬编码 OFF） | `tests/test_ablation_integrity.py` |
| F-15 | TR1–TR16 规则表 + 反向生成 | `tests/test_trust_rules_doc.py` |

## 2. 密码栈（保底路线 B，仿真档如实标注）

按修补提示词 §F-10/F-11 的「路线 B」执行：**不上真配对/真 CKKS，但做到密钥隔离与类型级盲化**。

| F 编号 | 状态 | 说明 |
|---|---|---|
| F-10 | **未完成** | 当前 `core/crypto/abe.py` 所有主体仍共享 `enc_key`，属性绑定是软件 `if`。路线 B：KEM 派生 per-属性集包装密钥，`issue_key` 不给主密钥，靠密钥材料隔离（`tests/test_abe_isolation.py` 待写）。 |
| F-11 | **未完成** | `core/crypto/ckks.py` 算子仍先解密；服务端持 `secret_key`。路线 B：拆 `PublicContext`/`SecretContext`，自制流密码换 AES-GCM 加认证（`tests/test_ckks_blindness.py` 待写）。 |
| F-14 | **未完成** | `Upgrader.try_upgrade` 已有 `sig_verifier` 钩子但无 ECDSA/SM2 真实现。需补写入签名（`cryptography` ECDSA 或 `gmssl` SM2）。 |

## 3. 功能完整性推迟项

| F 编号 | 状态 | 说明 |
|---|---|---|
| F-09 | **未完成** | `widen()` 仍可用，`narrow()` 不存在，`scope_hash` 未与链上承诺对拍。 |
| F-16 | **未完成** | CONFIRM 裁决未落地，HITL 仍是 `set`；`pipeline.py` 中 CONFIRM 路径是占位。 |
| F-18 | **未完成** | 13 类事件中 `TRUST_UPGRADE` / `MANIFEST_COMMIT` 等关键事件未入 `EventType` 枚举。 |
| F-19 | **未完成** | 背书门证据四类仍可由调用方自证，缺密码学不可伪造性。 |
| F-20 | **未完成** | 委派继承规则六条只实现三条。 |
| F-21 | **未完成** | 需知检查漏 `collab_group`。 |
| F-22 | **未完成** | TaskScope 在攻击与编排路径未全量必填。 |
| F-23 | **未完成** | 隔离 LLM 仍是关键词匹配，无约束解码；容量计费未按类型容量表。 |
| F-24 | **未完成** | 容量预算两套数字矛盾（4 bit vs 16）。 |
| F-25 | **部分** | `ifc/`、`pep/`、`bench/`、`tools/` 已建；`manifest/`、`chain/` 目录仍缺。 |

## 4. 报告与基准

| F 编号 | 状态 | 说明 |
|---|---|---|
| F-17 | **部分** | `bench/benchmark.py` + `bench/report.md` 已建，但**38 条基准任务集 + 八张表**未全量完成，当前仅覆盖核心模块微基准（表 6/7/8 部分）。 |
| F-26~F-33 | **未完成** | Role 枚举对齐、`verify_op` 长文本、`tamper_event` 生产接口、CONSULT 内容级泄漏局限、前端双水位标尺、`contract_report.md`/`TEST_REPORT.md` 重写、`make` 目标对齐等完善项。 |

## 5. 来源元数据的信任假设（F-19 / 设计文档 9.2(c)）

背书门的 `CROSS_SOURCE` 独立性判定（TR14）在 `SourceRegistry` 存在时判到**发布实体级**
（publisher / ASN），而非域名级。但 `SourceRegistry` 的元数据本身由谁提供、是否可被写入方
投毒，是一个**循环依赖**：如果注册表能被攻击者写入，那么把两个域名都登记成"独立实体"就能
绕过抗 Sybil 判定。

当前实现把「域名 → publisher / ASN」的映射集中到 `SourceRegistry`，便于审计与替换，但
**不解决元数据来源可信问题**。如实交代：这条在真实系统里需要由独立于被防护主体的
外部权威（如 BGP 路由注册表、证书透明度日志、权威情报源目录）提供，本项目仿真档不实现，
仅把局限写明。无 `SourceRegistry` 时退化为二级域去重，抗 Sybil 更弱。

## 6. 如何复现当前结论

```bash
python -m pytest tests/ -q          # 456 passed
python -m scenarios.attacks --bench # 重跑消融真值 → bench/attack_results.json + propagation.json
python -m bench.benchmark           # 重跑微基准 → bench/benchmarks.json
python scripts/generate_figures.py  # 从 bench/*.json 重新出图（禁止硬编码）
```

## 7. 门禁现状

§4.2 门禁中 `grep -rn "\.\.\.\|# TODO\|placeholder"` 要求为 0，当前非 0——剩余命中全部来自上文推迟项
（F-16 CONFIRM 占位、F-11/F-23 的 Protocol 抽象方法 `...`、F-11 的流密码占位等），在对应 F 项完成前属预期。
