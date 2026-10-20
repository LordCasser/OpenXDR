package agentchat

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func msg(v map[string]any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func toolResult(id string, text string) json.RawMessage {
	return msg(map[string]any{"role": "toolResult", "toolCallId": id, "toolName": "query", "isError": false, "timestamp": 1792300056123,
		"content": []any{map[string]any{"type": "text", "text": text}}})
}

func assistant(thinking, text string) json.RawMessage {
	return msg(map[string]any{"role": "assistant", "content": []any{
		map[string]any{"type": "thinking", "thinking": thinking},
		map[string]any{"type": "text", "text": text},
		map[string]any{"type": "toolCall", "id": "c1", "name": "query", "arguments": map[string]any{"sql": "select 1"}},
	}})
}

func TestFold(t *testing.T) {
	big := strings.Repeat("行", 3000) // 9000 字节
	history := []json.RawMessage{
		msg(map[string]any{"role": "user", "content": "查一下"}),
		assistant("先想想", "我去查"),
		toolResult("c1", big),
		toolResult("c2", "小结果"),
		json.RawMessage(`not json`),
		assistant("再想想", "结论"),
		toolResult("c3", big),
	}
	// 没超阈值：原样
	if got := fold(history, 1<<20); fmt.Sprint(got) != fmt.Sprint(history) {
		t.Fatal("没超阈值不应改动")
	}
	if got := fold(history, 0); fmt.Sprint(got) != fmt.Sprint(history) {
		t.Fatal("阈值 0 表示不折叠")
	}
	got := fold(history, 16000) // 共约 18.8 KB 超过阈值；尾部预算 8000，最后一条大结果超了预算也照样保留
	if string(got[6]) != string(history[6]) || string(got[3]) != string(history[3]) || string(got[4]) != "not json" {
		t.Fatal("尾部、小结果与解析不了的消息应原样")
	}
	var folded struct {
		ToolCallID string                  `json:"toolCallId"`
		Timestamp  json.Number             `json:"timestamp"`
		Content    []struct{ Text string } `json:"content"`
	}
	if err := json.Unmarshal(got[2], &folded); err != nil {
		t.Fatal(err)
	}
	if folded.ToolCallID != "c1" || folded.Timestamp != "1792300056123" || !strings.Contains(folded.Content[0].Text, "原文 9000 字节") || len([]rune(folded.Content[0].Text)) > 500 {
		t.Fatalf("早先的大结果应折叠并保留配对与时间戳: %s", got[2])
	}
	if string(got[1]) != string(history[1]) {
		t.Fatalf("助手消息（含思考过程）不折叠: %s", got[1])
	}
	if string(got[5]) != string(history[5]) {
		t.Fatal("助手消息原样")
	}
	// 尾部预算够大时，边界之后的消息一字不改
	all := 0
	for _, m := range history {
		all += len(m)
	}
	budget := 2 * (len(history[5]) + len(history[6]))
	if budget >= all {
		t.Fatalf("测试数据要让最后两条装得下、总量仍超阈值：%d / %d", budget, all)
	}
	roomy := fold(history, budget)
	if string(roomy[5]) != string(history[5]) || string(roomy[6]) != string(history[6]) {
		t.Fatal("尾部预算内的消息应原样")
	}
	total := 0
	for _, m := range got {
		total += len(m)
	}
	if total >= 12000 {
		t.Fatalf("折叠后应明显变小，得到 %d", total)
	}
}
