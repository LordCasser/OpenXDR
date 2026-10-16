# Pi 运行时

使用锁定为 **0.84.4** 的 `@earendil-works/pi-agent-core` 与 `pi-ai`。
这是 SDK runner，**不是 Pi CLI 的 RPC 模式，也不是 CLI extension**。
推理循环、工具参数校验与消息格式由 Pi 原生 SDK 提供；JSONL 是本项目与 Go 的桥接协议。
当前支持 OpenAI-compatible Chat Completions 文本模型，不启用 thinking。

## 安装与验证

需要 Node >=22.19.0：

```sh
cd server/pi-runtime
npm ci
npm test
```

Go 侧位于 `server/internal/piruntime`，执行 `go test ./internal/piruntime`。
Node 测试使用真实 SDK、本地 mock SSE 模型和真实 runner 子进程；不会访问外部模型或主机。

## Go 接入契约

```go
runtime := piruntime.Runtime{
    Runner: "/app/pi-runtime/runner.mjs", // 必填；相对路径基于 server 工作目录
    Timeout: 10 * time.Minute,          // 非正值默认十分钟，包含工具与审批等待
}
result, err := runtime.Run(ctx, piruntime.Request{
    APIBase: endpoint,
    APIKey: apiKey,
    Model: model,
    SystemPrompt: systemPrompt,
    Prompt: userPrompt,
    Messages: history, // []json.RawMessage，Pi 原生消息，按原顺序回放
    Tools: tools,     // []piruntime.Tool{Name, Description, Parameters}
}, handleTool, recordEvent)
```

- 每次 `Run` 创建一个子进程，返回前回收；并发调用互不共享会话状态。
- `handleTool(ctx, name, args) (string, error)` 必须由接入层绑定身份、资产组、权限和审批，
  并响应 ctx 取消。业务错误作为失败工具结果回传模型；未知工具或重复调用 ID 终止进程。
- `recordEvent(ctx, event) error` 必填，同步调用，必须先保存再返回。
  回调失败立即终止，不再执行后续工具。
- `event.Type == "event"` 时 `event.Event` 为 Pi 原生事件 JSON；
  `message_end.message` 是完整消息（user / assistant / toolResult），可保存到 SessionMessage，
  后续用 `Request.Messages` 原样回放。`message_update` 用于 SSE，不能当完整历史再次追加。
  本次 Prompt 由 SDK 追加，调用方不要提前把同一条消息重复放入 Messages。
- `tool_request` 在调用处理器之前交给记录器；`tool_execution_end`、
  `message_end` 包含 Pi 的工具结果与错误状态。命令执行自身的审计和结果持久化仍由平台负责。
- 只有进程正常退出且收到唯一 `result`，`Run` 才返回成功。
  `StopReason` 是 `stop`、`length` 或 `max_turns` 等 Pi 停止原因；调用方必须区分
  正常完成、输出截断和轮数耗尽，不能把所有 nil error 都标记为完整任务成功。
- 默认最多 32 轮、每次模型输出最多 8192 token；可设 `MaxTurns`（1–256）和
  `MaxTokens`（1–65536）。这不是费用或总 token 预算。
- API key 只走 stdin，不写进命令行；不得记录 Request。stderr 丢弃，错误通过协议返回；已配置 API key 会从事件、嵌套消息和最终错误中脱敏后再记录/推送。
  事件可能包含敏感调查内容，接入层应沿用会话访问控制与保留策略。

## JSONL 协议

stdin/stdout 每行一条 JSON，stdout 仅用于协议。每个进程只接受一个 run。

输入：

```json
{"type":"run","api_base":"http://model/v1","api_key":"...","model":"model-id","system_prompt":"...","prompt":"巡检","messages":[],"tools":[{"name":"query","description":"查询","parameters":{"type":"object","properties":{"sql":{"type":"string"}},"required":["sql"]}}],"max_turns":32,"max_tokens":8192}
{"type":"tool_result","call_id":"call_1","success":true,"output":"查询结果"}
```

输出：

```json
{"type":"event","event":{"type":"agent_start"}}
{"type":"tool_request","call_id":"call_1","name":"query","args":{"sql":"select 1"}}
{"type":"result","response":"巡检完成","stop_reason":"stop","turns":2}
```

失败时输出 `{"type":"error","error":"原因"}` 并非零退出。
父进程关闭 stdin 或取消运行后，当前推理和工具等待会中止。
Go 默认单行上限 4 MiB；工具结果应在平台工具层截断，避免超过协议上限。

## 本模块边界

只提供子进程托管、事件回调、工具回调与历史回放，不自行访问数据库或主机。
`exec` / `query` / `report`、会话表、REST/SSE 和审批已接入
`server/internal/agentchat`、`server/internal/commandgate` 与 `server/internal/api`。
运行配置和接口见 `docs/pi-backend.md`。
没有注册 Pi 内置 bash/read/write/edit；注册工具完全来自平台传入的 Tools。
