# ADR-003: 向量检索方案

## 状态

已接受 (2026-08-09)

## 背景

智能体需要语义检索相关记忆。常规方案是 CKKS 密态检索（全同态加密），但 CKKS 是性能开销最大的环节（秒级），且 v1 已有实现。

## 决策

**当前阶段使用明文 FAISS + Claude Embeddings API**。CKKS 接口预留，作为独立模块后续接入。

## 方案对比

| 方案 | 性能 | 隐私 | 实现复杂度 |
|---|---|---|---|
| FAISS + Embeddings API | 毫秒级 | 服务端可见查询向量 | 低 |
| CKKS (TenSEAL) | 秒级 | 服务端不可见 | 高 |

## 实现要点

- `EmbeddingBackend` 抽象基类：`embed(text) -> list[float]`、`search(query_vec, top_k) -> list[str]`
- 使用 Anthropic Embeddings API 或 OpenAI Embeddings API
- FAISS 索引存储在 `core/retrieval/faiss_index/`
- 检索流程：embed(query) → FAISS top-k → PDP 裁决 → 返回 ALLOW 的 chunk
- PDP 裁决在检索之后、返回之前，确保密文不可读的内容不会被返回

## 后果

- 服务端能看到明文查询向量（隐私降级，演示可接受）
- 检索性能远优于 CKKS（毫秒 vs 秒级）
- CKKS 接口保留（`CKKSEncryptedVector`、`encrypt_embedding` 等），后续可切换
- 答辩口径：「CKKS 是 v1 已验证的能力，当前演示聚焦治理层而非密码层」
