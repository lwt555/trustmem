# ADR-007: CONFIRM 人工在回路

## 状态

已接受 (2026-08-09)

## 背景

四值裁决中的 CONFIRM 表示「操作需要人工确认才能放行」。施工提示词中 `can_invoke` 对高危工具（`firewall_block`、`host_isolate`、`exec_command`）设置了 `requires: HITL` 要求。

## 决策

**实现真实的 CONFIRM 流程**：高危工具调用暂停 → 推送审批请求到前端 → 人工点击确认/拒绝 → 结果写回会话。

## 实现要点

- `Session.add_hitl(action_fingerprint)` 和 `Session.has_hitl(action_fingerprint)` 管理确认状态
- PEP 层拦截高危工具调用，检查 `has_hitl()`，未确认则返回 `CONFIRM` 裁决
- WebSocket 推送 HITL 请求到前端（包含操作指纹、说明、风险等级）
- 前端弹出确认对话框，人工点击「确认」或「拒绝」
- 确认后的操作带上 `HITL_CONFIRM` 审计事件写入 Merkle 树
- 操作指纹 = SHA-256(tool_name + args + timestamp)，确保不可抵赖

## 后果

- 演示时可展示完整的 CONFIRM 流程（ALLOW/HIDE/DENY/CONFIRM 四种裁决全部可见）
- HITL 确认记录进入 Merkle 审计树，满足不可抵赖要求
- 高危操作的定义在 `core/labels.py` 的工具注册表中配置
- 演示口语：「AI 要封禁 IP 之前，必须有人点头——这就是 CONFIRM」
