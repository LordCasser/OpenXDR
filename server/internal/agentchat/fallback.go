package agentchat

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/approval"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/sessionmessage"
	reportfmt "openxdr/server/internal/report"
)

// PartialNote 定时任务会话的终态说明：模型没在时限内交报告，平台整理了保底报告。
// 会话 status 记 succeeded（有报告、照常推送），error 写这句话与正常完成区分；任务运行记录据此标「部分完成」。
const PartialNote = "模型未在时限内完成，已由平台根据已执行的命令与查询结果生成保底报告"

// 保底报告的截断：单条参数与结果各取开头一段，正文总量留足 report 上限的余地
const (
	fallbackArgLimit    = 1500
	fallbackResultLimit = 1500
	fallbackBodyLimit   = 200 << 10
)

// fallbackReport 模型没交报告时由平台整理一份部分报告：只列本轮已执行的工具调用与结果摘要、
// 等待批准没执行的命令和任务要求的检查项。不读模型的文字与思考，不做任何判断。
func (s *Service) fallbackReport(ctx context.Context, session *ent.AgentSession, prompt string) error {
	calls, err := s.toolCalls(ctx, session.ID)
	if err != nil {
		return err
	}
	waiting, err := s.unapproved(ctx, session.ID)
	if err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("> 模型未在时限内完成，以下为平台根据已执行命令与查询结果整理，不含模型结论，平台未做任何判断。\n\n")
	b.WriteString("## 结论\n本轮模型没有在运行时限内提交报告，没有结论。下面只是已执行的命令、查询与结果摘要，需要人查看会话记录或重跑任务后再下结论。\n\n")
	b.WriteString("## 需要人处理\n- 本轮巡检不完整：打开会话查看完整记录，或在「定时任务」页重跑。\n")
	if len(waiting) > 0 {
		fmt.Fprintf(&b, "- %d 条命令等待组管理员批准，到期未执行：\n", len(waiting))
		for _, w := range waiting {
			fmt.Fprintf(&b, "  - %s：`` %s ``\n", w.host, oneLine(w.cmd, 200))
		}
	}
	fmt.Fprintf(&b, "\n## 证据\n本轮共 %d 次工具调用，按调用顺序列出；参数与结果均截断，完整内容见会话记录。\n", len(calls))
	for i, c := range calls {
		if b.Len() > fallbackBodyLimit {
			fmt.Fprintf(&b, "\n其余 %d 次调用超出篇幅，见会话记录。\n", len(calls)-i)
			break
		}
		fmt.Fprintf(&b, "\n### %d. %s\n%s\n", i+1, c.name, fenced(clip(c.args, fallbackArgLimit)))
		switch {
		case !c.answered:
			b.WriteString("结果：未取得\n")
		case c.failed:
			fmt.Fprintf(&b, "结果（出错）：\n%s\n", fenced(clip(c.result, fallbackResultLimit)))
		default:
			fmt.Fprintf(&b, "结果：\n%s\n", fenced(clip(c.result, fallbackResultLimit)))
		}
	}
	b.WriteString("\n## 未验证\n模型没有完成研判，任务要求的以下检查项是否覆盖、结果如何均未验证：\n")
	for _, item := range checkItems(prompt) {
		fmt.Fprintf(&b, "- %s\n", item)
	}
	title := "定时任务"
	if session.Title != nil && *session.Title != "" {
		title = *session.Title
	}
	title, summary, markdown, err := reportfmt.Normalize(title, fmt.Sprintf("模型未在时限内完成，平台整理了已执行的 %d 次调用与结果，未下结论", len(calls)), b.String())
	if err != nil {
		return err
	}
	return s.DB.Report.Create().SetSessionID(session.ID).SetGroupID(session.GroupID).
		SetTitle(title).SetSummary(summary).SetMarkdown(markdown).SetLevel("attention").Exec(ctx)
}

type toolCall struct {
	name, args, result string
	answered, failed   bool
}

// toolCalls 会话里的工具调用按顺序配上结果。只取调用参数与工具结果，模型的文字与思考不进报告；
// 沙箱里的 read 只是读 skill 等沙箱文件，不是主机证据，略去
func (s *Service) toolCalls(ctx context.Context, id uuid.UUID) ([]*toolCall, error) {
	rows, err := s.DB.SessionMessage.Query().Where(sessionmessage.SessionIDEQ(id), sessionmessage.RoleIn("assistant", "toolResult")).
		Order(ent.Asc(sessionmessage.FieldSeq)).All(ctx)
	if err != nil {
		return nil, err
	}
	var calls []*toolCall
	byID := map[string]*toolCall{}
	for _, m := range rows {
		var msg struct {
			Role       string `json:"role"`
			ToolCallID string `json:"toolCallId"`
			IsError    bool   `json:"isError"`
			Content    []struct {
				Type      string          `json:"type"`
				ID        string          `json:"id"`
				Name      string          `json:"name"`
				Text      string          `json:"text"`
				Arguments json.RawMessage `json:"arguments"`
			} `json:"content"`
		}
		if json.Unmarshal(m.Content, &msg) != nil {
			continue
		}
		if msg.Role == "toolResult" {
			c := byID[msg.ToolCallID]
			if c == nil {
				continue
			}
			var text []string
			for _, part := range msg.Content {
				if part.Type == "text" {
					text = append(text, part.Text)
				}
			}
			c.result, c.answered, c.failed = strings.Join(text, "\n"), true, msg.IsError
			continue
		}
		for _, part := range msg.Content {
			if part.Type != "toolCall" || part.Name == "read" {
				continue
			}
			c := &toolCall{name: part.Name, args: argsText(part.Arguments)}
			calls = append(calls, c)
			byID[part.ID] = c
		}
	}
	return calls, nil
}

// argsText 调用参数里最有用的那一项：命令、SQL；其余原样给 JSON
func argsText(raw json.RawMessage) string {
	var args map[string]any
	if json.Unmarshal(raw, &args) == nil {
		for _, key := range []string{"command", "cmd", "sql"} {
			if v, ok := args[key].(string); ok {
				if host, ok := args["host"].(string); ok {
					return "主机 " + host + "\n" + v
				}
				return v
			}
		}
	}
	return string(raw)
}

type waitingCommand struct{ host, cmd string }

// unapproved 本会话等批准到期或被取消、没有执行的命令
func (s *Service) unapproved(ctx context.Context, id uuid.UUID) ([]waitingCommand, error) {
	rows, err := s.DB.Approval.Query().Where(approval.SessionIDEQ(id), approval.StatusIn(approval.StatusPending, approval.StatusExpired, approval.StatusCancelled)).
		Order(ent.Asc(approval.FieldCreatedAt)).All(ctx)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.AssetID
	}
	assets, err := s.DB.Asset.Query().Where(asset.IDIn(ids...)).All(ctx)
	if err != nil {
		return nil, err
	}
	names := map[uuid.UUID]string{}
	for _, a := range assets {
		names[a.ID] = a.Hostname
	}
	out := make([]waitingCommand, len(rows))
	for i, r := range rows {
		host := names[r.AssetID]
		if host == "" {
			host = r.AssetID.String()
		}
		out[i] = waitingCommand{host, r.Cmd}
	}
	return out, nil
}

var checkItem = regexp.MustCompile(`^\s*\d+[.、]\s*(\S.*)$`)

// checkItems 任务说明里编号的检查项；没有编号时整体算一项
func checkItems(prompt string) []string {
	var items []string
	for _, line := range strings.Split(prompt, "\n") {
		if m := checkItem.FindStringSubmatch(line); m != nil {
			items = append(items, oneLine(m[1], 200))
		}
	}
	if len(items) == 0 {
		return []string{"任务说明要求的全部检查项"}
	}
	return items
}

// clip 按字节截断，不切断 UTF-8 字符
func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	end := n
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end] + "\n…（已截断）"
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

// fenced 代码块的围栏比内容里最长的反引号串多一个，内容里的 ``` 不会提前结束代码块
func fenced(s string) string {
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", max(3, longest+1))
	return fence + "\n" + s + "\n" + fence
}
