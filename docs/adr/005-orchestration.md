# ADR-005: 多智能体编排框架

## 状态

已接受 (2026-08-09)

## 背景

六个智能体需要编排协作：Planner 分解任务 → Intel 收集情报 → Log 持久化 → Analyst 分析 → Executor 执行 → Auditor 审计。每次 Agent 间记忆传递需触发 PDP 裁决。

## 决策

使用 **LangGraph StateGraph** 作为编排框架。

## 选择理由

- 唯一能稳定拿到 intermediate steps 的主流框架（R 层记忆依赖推理中间步骤）
- `stream()` 模式原生支持逐步骤推送到前端 WebSocket
- `checkpointer` 机制可直接替换为 TrustMem 的记忆后端
- 状态图语义与 SOC 工作流（有向无环图 + 条件路由）天然匹配

## 实现要点

- `SOCStateGraph` 继承 LangGraph `StateGraph`
- 状态：`task`、`context: list[MemoryLabel]`、`decisions: list[Decision]`、`current_agent`
- 每条边触发 `MemoryProxy.write()` / `MemoryProxy.read()`，自动走 PDP
- 工具调用通过 `@pep.guard_tool` 装饰器拦截
- 推理链中间步骤写入 R 层记忆
- `stream_mode="updates"` 推送实时事件到前端

## 后果

- 新增依赖：`langgraph`、`langgraph-checkpoint`
- 不拿到推理链的场景（闭源模型无 scratchpad）退化为 D/C 两层
- 答辩口径：「LangGraph 是目前唯一能稳定暴露推理中间步骤的框架，这是 R 层记忆实现的必要条件」
