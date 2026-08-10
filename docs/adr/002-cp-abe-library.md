# ADR-002: CP-ABE 加密库选型

## 状态

已接受 (2026-08-09)

## 背景

每条记忆写入前需要用 CP-ABE 加密，密文策略基于记忆的 `MemoryLabel` 属性集合。解密时检查 Agent 属性私钥是否满足策略。

## 决策

使用 **charm-crypto + bswabe** 方案。

## 方案对比

| 方案 | 成熟度 | Python 集成 | 安装难度 | 性能 |
|---|---|---|---|---|
| charm-crypto + bswabe | 学术标准实现 | 原生 Python | 需系统安装 PBC 库 | 十毫秒级 |
| rabe (Rust 绑定) | 较新 | pip install 即可 | 低 | 更快 |
| 文件级 AES 模拟 | N/A | 原生 | 零依赖 | 最快 |

## 实现要点

- 策略串由 `core/policy.py::policy_from_label()` 生成
- 属性私钥由 `agent_attributes()` 生成，签发时绑定 `prompt_hash`
- 序关系展开为析取：`clearance >= L2 → (clearance_2 or clearance_3)`
- 关系型属性（`ancestorof_X`）在签发期静态展开
- 解密失败返回 `None`，上游 PDP 标记为 DENY

## 后果

- 部署前需安装 PBC 库：`apt install libpbc-dev` (Linux) 或 `brew install pbc` (macOS)
- Windows 环境可能需要额外编译步骤或使用 WSL
- charm-crypto 上游维护不活跃，但 bswabe 方案是 CP-ABE 学术标准实现
