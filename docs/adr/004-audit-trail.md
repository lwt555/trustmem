# ADR-004: 审计链方案

## 状态

已接受 (2026-08-09)

## 背景

所有 PDP 裁决需要不可篡改的审计轨迹。施工提示词提到两种方案：本地 Merkle 树和 FISCO BCOS 联盟链。

## 决策

**当前阶段使用本地 SHA-256 Merkle 树**。接口与 FISCO BCOS 保持一致，一行切换。

## 实现要点

- 使用现有 `core/merkle.py` 的 `MerkleStore` 和 `MerkleAuditStore`
- 域分离：`0x00` 叶子哈希，`0x01` 内部节点哈希
- 批量写入：`flush()` 将缓冲区事件打包为一个 Merkle 块
- 13 类事件：READ_ALLOW、READ_HIDE、READ_DENY、WRITE_ALLOW、WRITE_DENY、TOOL_INVOKE、TOOL_DENY、TRUST_UPGRADE、DECLASSIFY、HITL_CONFIRM、AGENT_LABEL_ISSUE、SESSION_START、SESSION_END
- `MerkleAuditStore` 适配器将 `Decision` 对象转为 `AuditEvent`

## 后果

- 单一运营方场景下，Merkle 追加日志 + TSA 时间戳足以满足审计需求
- FISCO BCOS 的不可替代性在跨组织协同时才体现（`prompt_hash` 需要各方无法单独修改的锚点）
- 答辩口径：「演示期用本地 Merkle，跨组织协作场景下接口一致，可一行切换到 FISCO BCOS」
