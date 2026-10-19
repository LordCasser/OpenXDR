package agentchat

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// 会话历史折叠：长会话每轮都把全部历史原样喂回模型，越往后越贵、越容易跑偏。
// 生产里工具结果占历史体积的七成（SQL 结果、命令输出），思考过程只占几个百分点。
//
// 规则是确定性的，不调模型做摘要（多花钱、还可能丢证据）：历史超过 foldAbove 时，最近约一半
// 预算的消息原样保留，更早的工具结果超过 foldToolBytes 的只留开头和「已折叠」说明。
// 思考过程不动：GLM 有意跨轮保留推理（deploy/pi-sandbox/bridge.mjs 的 preserve_thinking）。
// 只改内容不删消息，工具调用与结果的配对不受影响；库里存的完整记录不动，界面照常显示原文。
const (
	foldToolBytes  = 1024
	foldKeepPrefix = 400
)

// fold 返回发给模型的历史。foldAbove 为 0 或历史没超过它时原样返回
func fold(messages []json.RawMessage, foldAbove int) []json.RawMessage {
	total := 0
	for _, m := range messages {
		total += len(m)
	}
	if foldAbove <= 0 || total <= foldAbove {
		return messages
	}
	// 从最新往前数，保留约一半预算的尾部原样不动；最新一条无论多大都不折叠，那是模型最要看清的
	boundary, tail := len(messages), 0
	for boundary > 0 && (boundary == len(messages) || tail+len(messages[boundary-1]) <= foldAbove/2) {
		boundary--
		tail += len(messages[boundary])
	}
	out := make([]json.RawMessage, len(messages))
	copy(out, messages)
	for i := 0; i < boundary; i++ {
		out[i] = foldOne(messages[i])
	}
	return out
}

// foldOne 折叠一条消息；解析不了的原样保留
func foldOne(raw json.RawMessage) json.RawMessage {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // 时间戳、用量按原样回写，不经 float64
	var msg map[string]any
	if dec.Decode(&msg) != nil {
		return raw
	}
	content, _ := msg["content"].([]any)
	switch msg["role"] {
	case "toolResult":
		var text strings.Builder
		other := 0
		for _, c := range content {
			block, _ := c.(map[string]any)
			if s, ok := block["text"].(string); ok && block["type"] == "text" {
				text.WriteString(s)
			} else {
				other++
			}
		}
		if text.Len() <= foldToolBytes && other == 0 {
			return raw
		}
		head := []rune(text.String())
		if len(head) > foldKeepPrefix {
			head = head[:foldKeepPrefix]
		}
		note := fmt.Sprintf("[较早的工具结果已折叠：原文 %d 字节", text.Len())
		if other > 0 {
			note += fmt.Sprintf("，另有 %d 个非文本块", other)
		}
		msg["content"] = []any{map[string]any{"type": "text", "text": note + "；需要细节请重新查询。开头如下]\n" + string(head)}}
	default:
		return raw
	}
	out, err := json.Marshal(msg)
	if err != nil {
		return raw
	}
	return out
}
