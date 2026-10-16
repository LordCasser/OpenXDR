// Package piruntime 托管独立 Pi 子进程。权限、审批和持久化由调用方负责。
package piruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"openxdr/server/internal/worklimit"
	"os/exec"
	"strings"
	"time"
)

type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

// Request.Messages 使用 Pi 原生消息格式，必须来自平台保存的可信会话记录。
// APIKey 只通过 stdin 发送，不应将 Request 写入日志或会话表。
type Request struct {
	Type         string            `json:"type"`
	APIBase      string            `json:"api_base"`
	APIKey       string            `json:"api_key"`
	Model        string            `json:"model"`
	SystemPrompt string            `json:"system_prompt"`
	Prompt       string            `json:"prompt"`
	Messages     []json.RawMessage `json:"messages,omitempty"`
	Tools        []Tool            `json:"tools,omitempty"`
	MaxTurns     int               `json:"max_turns,omitempty"`
	MaxTokens    int               `json:"max_tokens,omitempty"`
}

type Event struct {
	Type       string          `json:"type"`
	Event      json.RawMessage `json:"event,omitempty"`
	CallID     string          `json:"call_id,omitempty"`
	Name       string          `json:"name,omitempty"`
	Args       json.RawMessage `json:"args,omitempty"`
	Response   string          `json:"response,omitempty"`
	StopReason string          `json:"stop_reason,omitempty"`
	Turns      int             `json:"turns,omitempty"`
	Error      string          `json:"error,omitempty"`
}

type Result struct {
	Response   string
	StopReason string
	Turns      int
}

// Handler 必须检查当前会话身份与权限，并响应 ctx 取消。
// 工具业务错误会回传模型；Observer 错误则立即终止会话，避免丢失审计后继续操作。
type Handler func(ctx context.Context, name string, args json.RawMessage) (string, error)
type Observer func(ctx context.Context, event Event) error

var runtimeSlots = worklimit.New(4, 32)

type Runtime struct {
	Node    string
	Runner  string
	Timeout time.Duration
}

func (r Runtime) Run(ctx context.Context, request Request, handle Handler, observe Observer) (*Result, error) {
	if r.Runner == "" || observe == nil {
		return nil, errors.New("Pi 必须配置 runner 与事件记录器")
	}
	allowed := make(map[string]bool, len(request.Tools))
	for _, tool := range request.Tools {
		if tool.Name == "" || allowed[tool.Name] {
			return nil, errors.New("Pi 工具名称为空或重复")
		}
		allowed[tool.Name] = true
	}
	if len(allowed) > 0 && handle == nil {
		return nil, errors.New("Pi 工具处理器未配置")
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	release, err := runtimeSlots.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	node := r.Node
	if node == "" {
		node = "node"
	}
	cmd := exec.CommandContext(ctx, node, r.Runner)
	cmd.WaitDelay = time.Second
	// stderr 不混入 JSONL，也不保留可能含供应商凭据的异常正文。
	cmd.Stderr = io.Discard
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	defer stdin.Close()
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	defer stdout.Close()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动 Pi 失败: %w", err)
	}
	defer func() {
		cancel()
		if cmd.ProcessState == nil {
			_ = cmd.Wait()
		}
	}()
	encoder := json.NewEncoder(stdin)
	request.Type = "run"
	if err := encoder.Encode(request); err != nil {
		return nil, fmt.Errorf("发送 Pi 请求失败: %w", err)
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var result *Result
	seen := make(map[string]bool)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, errors.New("Pi 返回无效 JSONL")
		}
		if result != nil {
			return nil, errors.New("Pi 在最终结果后继续输出")
		}
		switch event.Type {
		case "event", "tool_request", "result", "error":
		default:
			return nil, fmt.Errorf("Pi 返回未知事件类型 %q", event.Type)
		}
		observed := event
		if request.APIKey != "" {
			observed.Error = strings.ReplaceAll(observed.Error, request.APIKey, "[已隐藏]")
			observed.Response = strings.ReplaceAll(observed.Response, request.APIKey, "[已隐藏]")
			// 供应商错误也可能出现在 message_end.message.errorMessage 中。
			observed.Event = redactJSON(observed.Event, request.APIKey)
			observed.Args = redactJSON(observed.Args, request.APIKey)
		}
		if err := observe(ctx, observed); err != nil {
			return nil, fmt.Errorf("记录 Pi 事件失败: %w", err)
		}
		switch event.Type {
		case "tool_request":
			if event.CallID == "" || seen[event.CallID] {
				return nil, errors.New("Pi 工具调用 ID 为空或重复")
			}
			seen[event.CallID] = true
			if !allowed[event.Name] {
				return nil, errors.New("Pi 请求了未注册工具")
			}
			output, toolErr := handle(ctx, event.Name, event.Args)
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if toolErr != nil {
				output = toolErr.Error()
			}
			reply := struct {
				Type    string `json:"type"`
				CallID  string `json:"call_id"`
				Success bool   `json:"success"`
				Output  string `json:"output"`
			}{"tool_result", event.CallID, toolErr == nil, output}
			if err := encoder.Encode(reply); err != nil {
				return nil, fmt.Errorf("发送 Pi 工具结果失败: %w", err)
			}
		case "result":
			if event.StopReason == "" {
				return nil, errors.New("Pi 结果缺少停止原因")
			}
			result = &Result{observed.Response, event.StopReason, event.Turns}
		case "error":
			return nil, fmt.Errorf("Pi 执行失败: %s", observed.Error)
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取 Pi 事件失败: %w", err)
	}
	_ = stdin.Close()
	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("Pi 子进程失败: %w", err)
	}
	if result == nil {
		return nil, errors.New("Pi 退出但未返回结果")
	}
	return result, nil
}

// 只在完成 JSON 解码后替换字符串，避免密钥中的引号/反斜杠破坏协议。
func redactJSON(raw json.RawMessage, secret string) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return raw
	}
	var redact func(any) any
	redact = func(v any) any {
		switch v := v.(type) {
		case string:
			return strings.ReplaceAll(v, secret, "[已隐藏]")
		case []any:
			for i := range v {
				v[i] = redact(v[i])
			}
		case map[string]any:
			for key, item := range v {
				v[key] = redact(item)
			}
		}
		return v
	}
	result, err := json.Marshal(redact(value))
	if err != nil {
		return raw
	}
	return result
}
