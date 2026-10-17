package grpcsvc

import (
	"encoding/json"
	"strings"

	"openxdr/server/internal/redact"
)

// 清洗原始事件 JSON 里的每个字符串：
//   - 剥掉 NUL：jsonb 不接受 \u0000（SQLSTATE 22P05），一条带 NUL 的脏事件会让整个批量插入失败，
//     agent 重连后重放同一批又失败，事件管道被无限毒化。采集端已尽量在源头剥除，这里是最后一道。
//   - 抹掉凭据：入库、检测与送模型用的都是这一份，见 redact。
func sanitizeRawJSON(raw json.RawMessage) json.RawMessage {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return json.RawMessage("{}")
	}
	v = clean(v)
	out, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("{}")
	}
	return out
}

// 递归遍历解码后的 JSON 值，逐个清洗字符串。
func clean(v any) any {
	switch t := v.(type) {
	case string:
		return redact.String(strings.ReplaceAll(t, "\x00", ""))
	case map[string]any:
		for k, val := range t {
			t[k] = clean(val)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = clean(val)
		}
		return t
	default:
		return v
	}
}
