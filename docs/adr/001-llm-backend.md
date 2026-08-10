# ADR-001: LLM 后端选型

## 状态

已接受 (2026-08-09)

## 背景

TrustMem 的六个智能体需要真实 LLM 推理能力。当前 `StubIsolatedLLM` 使用关键词匹配冒充 LLM。需要替换为真实 API 驱动的后端。

## 决策

使用 **Claude API (Anthropic)** 作为默认 LLM 后端，通过 `core/llm/` 下的可插拔适配层支持切换。

## 方案对比

| 方案 | 推理质量 | 部署成本 | 中文能力 | 多模态 |
|---|---|---|---|---|
| Claude API | 最高 | 零（云端） | 优秀 | 支持 |
| OpenAI API | 高 | 零（云端） | 好 | 支持 |
| Ollama 本地 | 取决于模型 | 需 GPU 服务器 | 取决于模型 | 有限 |

## 实现要点

- `LLMBackend` 抽象基类：`chat(messages, tools=None) -> LLMResponse`
- `ClaudeBackend`：使用 `anthropic` Python SDK
- 预留 `OpenAIBackend` 和 `OllamaBackend` 实现位置
- 环境变量 `TRUSTMEM_LLM_BACKEND=claude` 切换
- API key 通过 `ANTHROPIC_API_KEY` 环境变量传入
- `IsolatedLLMProto` 协议由 `LLMBackend` 的子集实现（无工具模式）

## 后果

- 需要有效的 Claude API key 才能运行系统
- 演示时可通过 `TRUSTMEM_DEMO_MODE=1` 缓存 LLM 响应降低调用频率
- 隔离 LLM 的 4 bit 控制流预算在 Claude API 上通过受限 tool_choice 实现
