# TrustMem 契约对账报告

生成 commit：`a8940efe9b02ec941fa84e038a49b4962af11b32`
生成时间：2026-08-13 04:40:45 UTC

> 本报告由 `tools/contract_check.py` 生成，是全程唯一签名依据。
> 每次施工前运行 `make contract` 重新生成；过期报告比没有更危险。

---

## 汇总：13 项就位 / 4 项移位 / 4 项缺失（共 21 项）

| 目录 | 契约要求 | 状态 | 备注 |
|---|---|---|---|
| `ifc/` | `crypto_client.py` | ✅ | — |
| `ifc/` | `varstore.py` | ⚠️ 移位 | core/varstore.py |
| `ifc/` | `quarantined.py` | ❌ | — |
| `ifc/` | `writer_sign.py` | ✅ | — |
| `pep/` | `pep.py` | ✅ | — |
| `pep/` | `memory_proxy.py` | ⚠️ 移位 | core/agent/memory_proxy.py |
| `pep/` | `tool_proxy.py` | ❌ | — |
| `pep/` | `hitl.py` | ✅ | — |
| `manifest/` | `schema.py` | ✅ | — |
| `manifest/` | `compose.py` | ⚠️ 移位 | manifest/schema.py（compose_capabilities / synthesize） |
| `manifest/` | `capability_infer.py` | ✅ | — |
| `manifest/` | `agents` | ❌ | — |
| `chain/` | `local_anchor.py` | ✅ | — |
| `chain/` | `replay.py` | ✅ | — |
| `chain/` | `anchor_log.jsonl` | ⚠️ 移位 | core/merkle.py（MerkleAuditStore 内实现锚定） |
| `bench/` | `benchmark.py` | ✅ | — |
| `bench/` | `report.py` | ❌ | — |
| `tools/` | `contract_check.py` | ✅ | — |
| `tools/` | `regress.py` | ✅ | — |
| `tools/` | `gen_trust_rules.py` | ✅ | — |
| `keys/` | `keyring.json` | ✅ | — |

---

## 安全边界定位（设计文档第十部分第 8 条）

抽取器的产出只能收紧、不能放宽：`manifest/schema.py:compose_capabilities`
把抽取器（可被注入）声称需要的权限与人工维护的注册表取**交集**，交集之外
一律拒。抽取器被注入的后果是任务做不成（fail-closed），不是权限被放大。
