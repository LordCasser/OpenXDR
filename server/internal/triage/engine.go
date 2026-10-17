// Package triage AI 研判引擎：对关联引擎产出的 incident 做 LLM 定性，
// 结论写回 incidents.ai_verdict，状态推进到 triaged。
package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/predicate"
	"openxdr/server/internal/review"
)

const systemPrompt = `你是资深安全分析师，负责研判 XDR 平台聚合出的安全事件。
输入包含事件的实体关系图（主机/进程/告警）和按时间排序的告警明细。
你可以调用工具主动调查：检索原始事件、追进程血缘、查主机告警前科。
证据不足时先调查再下结论，证据已经充分时直接给结论，不要为了调查而调查。
最终结论只输出一个 JSON 对象，不要输出任何其他文字，结构如下：
{
  "verdict": "malicious | suspicious | benign",
  "confidence": 0 到 100 的整数,
  "summary": "一段话说清这个事件是什么、为什么这样判定",
  "kill_chain": ["按时间顺序还原的攻击链步骤，非攻击事件则为空数组"],
  "actions": ["建议的处置动作，按优先级排序"]
}
三档结论的边界：
- malicious：有明确攻击链证据，如持久化加回连、凭据读取加外传。
- suspicious：中危及以上的攻击手法（反弹 shell、持久化落盘、读凭据、清痕迹等），
  但拿不到合法来源的正面证据。需要人去核实的，都归这一档。
- benign：有正面证据表明合法，如已知运维任务、与分析师判过的误报同一模式、进程血缘与来源都正常；
  或者只有单条低危告警（端口探测、侦察命令之类），也没有任何后续动作。
中危及以上的告警，"像测试或演练"本身不是 benign 的理由，查不到对应记录就按 suspicious；
summary 里写了"需确认来源"的，verdict 也不能是 benign。
告警里的 severity：1 信息、2 低、3 中、4 高、5 严重。`

type Engine struct {
	DB       *ent.Client
	LLM      *LLM
	Interval time.Duration
	// Rules 用于把上下文里的规则 UUID 翻译成标题，模型看得懂才判得准
	Rules interface{ TitleOf(id string) string }
	// OnVerdict 结论落库后的钩子（自动响应挂在这里），nil 表示无人关心
	OnVerdict func(ctx context.Context, incidentID uuid.UUID, verdict json.RawMessage)
}

func (e *Engine) Run(ctx context.Context) {
	if !e.LLM.Enabled() {
		slog.Warn("AI 研判未启用：未配置 AI_MODEL")
		return
	}
	ticker := time.NewTicker(e.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.batch(ctx); err != nil {
				slog.Error("研判批次失败", "err", err)
			}
		}
	}
}

func (e *Engine) batch(ctx context.Context) error {
	// 只看 status：重开的 incident（带新证据）会被重新研判，旧 verdict 被覆盖
	incidents, err := e.DB.Incident.Query().
		Where(incident.StatusEQ("open")).
		Order(ent.Asc(incident.FieldCreatedAt)).
		Limit(5).
		All(ctx)
	if err != nil {
		return err
	}

	for _, inc := range incidents {
		context_, err := e.buildContext(ctx, inc)
		if err != nil {
			return err
		}
		answer, err := e.investigate(ctx, context_)
		if err != nil {
			return err
		}
		verdict := parseVerdict(inc.ID.String(), answer)
		// LLM 调用慢，逐个落库，中途挂了不丢已完成的研判
		if err := e.DB.Incident.UpdateOneID(inc.ID).
			SetAiVerdict(verdict).
			SetStatus("triaged").
			Exec(ctx); err != nil {
			return err
		}
		slog.Info("incident 研判完成", "id", inc.ID)
		if e.OnVerdict != nil {
			e.OnVerdict(ctx, inc.ID, verdict)
		}
	}
	return nil
}

// 工具调用轮数上限：防模型在调查里打转。用尽后强制收结论。
const maxToolTurns = 6

// toolLoop 带工具的研判循环。模型不调用工具时第一轮
// 就返回答案，不支持工具的模型也走同一条路径，天然退化为单轮问答。
func (e *Engine) toolLoop(ctx context.Context, msgs []Message, nudge string) (string, error) {
	for turn := 0; turn < maxToolTurns; turn++ {
		msg, err := e.LLM.Chat(ctx, msgs, investigationTools)
		if err != nil {
			return "", err
		}
		if len(msg.ToolCalls) == 0 {
			return msg.Content, nil
		}
		msgs = append(msgs, msg)
		for _, tc := range msg.ToolCalls {
			result := e.execTool(ctx, tc.Function.Name, tc.Function.Arguments)
			slog.Info("调查", "tool", tc.Function.Name, "args", tc.Function.Arguments)
			msgs = append(msgs, Message{Role: "tool", ToolCallID: tc.ID, Content: result})
		}
	}
	// 轮数用尽：收走工具，强制收口
	msgs = append(msgs, Message{Role: "user", Content: nudge})
	msg, err := e.LLM.Chat(ctx, msgs, nil)
	if err != nil {
		return "", err
	}
	return msg.Content, nil
}

func (e *Engine) investigate(ctx context.Context, incidentContext string) (string, error) {
	answer, err := e.toolLoop(ctx, []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: incidentContext},
	}, "调查轮数已用尽，基于以上全部信息立即输出最终 JSON 结论。")
	return answer, err
}

func parseVerdict(incidentID, answer string) json.RawMessage {
	if start, end := strings.Index(answer, "{"), strings.LastIndex(answer, "}"); start >= 0 && end > start {
		candidate := answer[start : end+1]
		if json.Valid([]byte(candidate)) {
			return json.RawMessage(candidate)
		}
	}
	slog.Warn("研判输出不是合法 JSON，原样存档", "incident", incidentID)
	if len(answer) > 2000 {
		answer = answer[:2000]
	}
	fallback, _ := json.Marshal(map[string]string{"error": "unparseable", "raw": answer})
	return fallback
}

func (e *Engine) buildContext(ctx context.Context, inc *ent.Incident) (string, error) {
	alerts, err := e.DB.Alert.Query().
		Where(alert.IncidentIDEQ(inc.ID)).
		Order(ent.Asc(alert.FieldTs)).
		Limit(50).
		WithEvent().
		All(ctx)
	if err != nil {
		return "", err
	}

	var sb strings.Builder
	title := ""
	if inc.Title != nil {
		title = *inc.Title
	}
	fmt.Fprintf(&sb, "# 事件: %s\n创建时间: %s\n", title, inc.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(&sb, "## 实体关系图\n%s\n", inc.Graph)
	fmt.Fprintf(&sb, "## 告警明细（%d 条，按时间排序）\n", len(alerts))
	for _, a := range alerts {
		raw := "{}"
		if a.Edges.Event != nil {
			raw = string(a.Edges.Event.Raw)
			if len(raw) > 500 {
				raw = raw[:500] + "…"
			}
		}
		rule := a.RuleID
		if e.Rules != nil {
			if title := e.Rules.TitleOf(a.RuleID); title != "" {
				rule = title
			}
		}
		fmt.Fprintf(&sb, "- [%s] severity=%d count=%d rule=%s event=%s\n",
			a.Ts.Format("15:04:05"), a.Severity, a.Count, rule, raw)
	}
	e.appendCaseHistory(ctx, &sb, inc, alerts)
	return sb.String(), nil
}

// appendCaseHistory 把分析师的结案喂回模型：同规则或同主机、近 90 天人工结过案的事件，
// 连同当时 AI 的判断与结案备注。人的结论是最贵的信号；AI 与人不一致的案例最有用。
func (e *Engine) appendCaseHistory(ctx context.Context, sb *strings.Builder, inc *ent.Incident, alerts []*ent.Alert) {
	var related []predicate.Alert
	ruleIDs, assetIDs := []string{}, []uuid.UUID{}
	for _, a := range alerts {
		ruleIDs = append(ruleIDs, a.RuleID)
		if a.AssetID != nil {
			assetIDs = append(assetIDs, *a.AssetID)
		}
	}
	related = append(related, alert.RuleIDIn(ruleIDs...))
	if len(assetIDs) > 0 {
		related = append(related, alert.AssetIDIn(assetIDs...))
	}
	cases, err := e.DB.Incident.Query().
		Where(
			incident.IDNEQ(inc.ID),
			incident.StatusIn("closed", "false_positive"),
			// 系统自动结案只是复述 AI 自己的结论，不能当人工案例喂回来自我强化
			incident.Or(incident.ResolvedByIsNil(), incident.ResolvedByNEQ(review.ClosedBy)),
			incident.HasAlertsWith(alert.Or(related...), alert.TsGTE(time.Now().AddDate(0, 0, -90))),
		).
		Order(ent.Desc(incident.FieldCreatedAt)).
		Limit(8).
		All(ctx)
	if err != nil || len(cases) == 0 {
		return
	}
	sb.WriteString("## 历史结案参考（同规则或同主机，分析师的人工结论；仅供权衡，本次证据不同则不适用）\n")
	for _, c := range cases {
		title, note := "", "无备注"
		if c.Title != nil {
			title = *c.Title
		}
		if c.Resolution != nil {
			note = excerpt(*c.Resolution, 200)
		}
		var v struct {
			Verdict string `json:"verdict"`
		}
		_ = json.Unmarshal(c.AiVerdict, &v)
		if v.Verdict == "" {
			v.Verdict = "未研判"
		}
		outcome := "误报或良性"
		if c.Status == "closed" {
			outcome = "属实已处置"
		}
		fmt.Fprintf(sb, "- %s「%s」：AI 判 %s，人工结案为%s。备注：%s\n",
			c.CreatedAt.Format("2006-01-02"), title, v.Verdict, outcome, note)
	}
}

// excerpt 按字符截断，案例备注只取要点
func excerpt(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n]) + "…"
}
