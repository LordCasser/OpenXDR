// Package triage AI 研判引擎：对关联引擎产出的 incident 做 LLM 定性，
// 结论写回 incidents.ai_verdict，状态推进到 triaged。
package triage

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"openxdr/server/ent/asset"
	"openxdr/server/internal/memories"
	"slices"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/incident"
	"openxdr/server/ent/ipinfo"
	"openxdr/server/ent/predicate"
	"openxdr/server/internal/incidentstate"
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
	// Cooldown 已研判的 incident 又并入普通新证据时，距上次研判至少隔这么久才重研判；升级类证据不等
	Cooldown time.Duration
	// Rules 用于把上下文里的规则 UUID 翻译成标题，模型看得懂才判得准
	Rules interface{ TitleOf(id string) string }
	// OnVerdict 结论落库后的钩子（自动响应挂在这里），nil 表示无人关心
	OnVerdict func(ctx context.Context, incidentID uuid.UUID, verdict json.RawMessage)
}

// Run 常驻运行：模型可以在控制台随时配上或撤掉，没配置的轮次直接跳过
func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(e.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !e.LLM.Enabled() {
				continue
			}
			if err := e.batch(ctx); err != nil {
				slog.Error("研判批次失败", "err", err)
			}
		}
	}
}

// 每轮研判名额与其中留给重研判的保底名额：新事件有多数，重研判有保底，谁也饿不死谁
const (
	batchSize     = 5
	retriageSlots = 1
)

// 研判失败的退避：从一分钟起每次翻倍，封顶一小时；只退避失败的那一个
const (
	backoffBase = time.Minute
	backoffMax  = time.Hour
)

// clockSkew 研判取上下文的时刻往前让一点：关联与研判可能跑在不同节点，时钟差一点也不把证据当成已看过
const clockSkew = time.Second

func (e *Engine) batch(ctx context.Context) error {
	incidents, err := e.queue(ctx, time.Now())
	if err != nil {
		return err
	}
	for _, inc := range incidents {
		if err := e.triageOne(ctx, inc); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// 一个失败（多半是大上下文超时）只退避它自己，后面的照常研判
			slog.Error("incident 研判失败，退避后缩小上下文重试", "id", inc.ID, "failures", inc.TriageFailures+1, "err", err)
			if err := e.backoff(ctx, inc, time.Now()); err != nil {
				return err
			}
		}
	}
	return nil
}

// queue 本轮要研判的 incident，见 docs/detection.md「研判节奏」：
//   - 新事件（open：还没有可用结论）按创建先后，占多数名额；
//   - 重研判里升级类（Urgent）不等冷却，普通新证据（Retriage）要距上次研判满 Cooldown；
//     两类都按上次研判时刻排（刚研判过的排后面），升级类在前，至少留 retriageSlots 个名额，新事件不满时补满；
//   - 失败退避中的都不取。
func (e *Engine) queue(ctx context.Context, now time.Time) ([]*ent.Incident, error) {
	ready := incident.Or(incident.TriageRetryAtIsNil(), incident.TriageRetryAtLTE(now))
	fresh, err := e.DB.Incident.Query().
		Where(incident.StatusEQ("open"), ready).
		Order(ent.Asc(incident.FieldCreatedAt)).
		Limit(batchSize).
		All(ctx)
	if err != nil {
		return nil, err
	}
	urgent, err := e.DB.Incident.Query().
		Where(review.Urgent(), ready).
		Order(lastLooked).
		Limit(batchSize).
		All(ctx)
	if err != nil {
		return nil, err
	}
	due, err := e.DB.Incident.Query().
		Where(review.Retriage(), incident.Not(review.Urgent()), ready,
			incident.Or(incident.TriagedAtIsNil(), incident.TriagedAtLTE(now.Add(-e.Cooldown)))).
		Order(lastLooked).
		Limit(batchSize).
		All(ctx)
	if err != nil {
		return nil, err
	}
	again := append(urgent, due...)
	again = again[:min(len(again), max(retriageSlots, batchSize-len(fresh)))]
	return append(fresh[:min(len(fresh), batchSize-len(again))], again...), nil
}

// lastLooked 按上次研判时刻（没研判过按创建时刻）排：刚看过的排后面，等得最久的先轮到
func lastLooked(s *sql.Selector) {
	s.OrderExpr(sql.Expr(fmt.Sprintf("COALESCE(%s, %s)", s.C(incident.FieldTriagedAt), s.C(incident.FieldCreatedAt))))
}

// backoff 记一次失败：下次研判推迟，上下文按失败次数缩小（见 buildContext）
func (e *Engine) backoff(ctx context.Context, inc *ent.Incident, now time.Time) error {
	wait := min(backoffBase<<min(inc.TriageFailures, 10), backoffMax)
	return e.DB.Incident.UpdateOneID(inc.ID).AddTriageFailures(1).SetTriageRetryAt(now.Add(wait)).Exec(ctx)
}

// triageOne 研判一个 incident 并落库。取上下文的时刻记为 triaged_at：研判期间并进来的证据晚于它，仍算待重研判
func (e *Engine) triageOne(ctx context.Context, inc *ent.Incident) error {
	snapshot := time.Now().Add(-clockSkew)
	context_, err := e.buildContext(ctx, inc)
	if err != nil {
		return err
	}
	// 模型可以在控制台随时换，结论里记下这一次实际用的，准确度才能按模型对比
	_, model, _ := e.LLM.endpoint()
	answer, err := e.investigate(ctx, context_)
	if err != nil {
		return err
	}
	verdict := withModel(parseVerdict(inc.ID.String(), answer), model)
	tx, err := e.DB.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	upd := tx.Incident.UpdateOneID(inc.ID).SetAiVerdict(verdict).
		SetTriagedAt(snapshot).AddTriageCount(1).SetTriageFailures(0).ClearTriageRetryAt()
	// 重研判从良性翻成可疑或恶意：之前按良性静默过的要重新决定推送，升级信号不能被旧结论吞掉
	if verdictLabel(inc.AiVerdict) == "benign" && verdictLabel(verdict) != "benign" {
		upd.ClearNotifiedAt()
	}
	if err := upd.Exec(ctx); err != nil {
		return err
	}
	// 研判期间被分析师结案的不改回来
	if err := tx.Incident.Update().Where(incident.IDEQ(inc.ID), incident.StatusEQ("open")).
		SetStatus("triaged").Exec(ctx); err != nil {
		return err
	}
	if err := incidentstate.Record(ctx, tx, inc.ID, incidentstate.Triaged, incidentstate.Origin{Kind: "system"}, ""); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	slog.Info("incident 研判完成", "id", inc.ID, "round", inc.TriageCount+1)
	if e.OnVerdict != nil {
		e.OnVerdict(ctx, inc.ID, verdict)
	}
	return nil
}

// verdictLabel 研判结论里的 verdict 字段，解析不了当没有
func verdictLabel(raw json.RawMessage) string {
	var v struct {
		Verdict string `json:"verdict"`
	}
	_ = json.Unmarshal(raw, &v)
	return v.Verdict
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

// withModel 在结论对象里记下研判用的模型；结论不是对象（解析失败的存档）时原样返回
func withModel(verdict json.RawMessage, model string) json.RawMessage {
	var obj map[string]any
	if model == "" || json.Unmarshal(verdict, &obj) != nil || obj == nil {
		return verdict
	}
	obj["model"] = model
	out, err := json.Marshal(obj)
	if err != nil {
		return verdict
	}
	return out
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

// 告警明细条数：失败一次减半（超时多半是上下文太大），最少留几条；汇总照常是全量
const (
	detailLimit    = 50
	minDetailLimit = 5
)

func (e *Engine) buildContext(ctx context.Context, inc *ent.Incident) (string, error) {
	limit := max(detailLimit>>min(inc.TriageFailures, 10), minDetailLimit)
	alerts, err := e.DB.Alert.Query().
		Where(alert.IncidentIDEQ(inc.ID)).
		Order(ent.Asc(alert.FieldTs)).
		Limit(limit).
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
	if err := e.appendRuleTally(ctx, &sb, "## 告警汇总（按规则统计同类重复，含明细未列出的）\n", alert.IncidentIDEQ(inc.ID)); err != nil {
		return "", err
	}
	if err := e.appendRetriage(ctx, &sb, inc, limit); err != nil {
		return "", err
	}
	fmt.Fprintf(&sb, "## 告警明细（%d 条，按时间排序）\n", len(alerts))
	for _, a := range alerts {
		e.writeAlert(ctx, &sb, a)
	}
	e.appendIPInfo(ctx, &sb, alerts)
	e.appendCaseHistory(ctx, &sb, inc, alerts)
	e.appendMemories(ctx, &sb, alerts)
	return sb.String(), nil
}

// writeAlert 一条告警明细
func (e *Engine) writeAlert(ctx context.Context, sb *strings.Builder, a *ent.Alert) {
	raw := "{}"
	if a.Edges.Event != nil {
		raw = string(a.Edges.Event.Raw)
		if len(raw) > 500 {
			raw = raw[:500] + "…"
		}
	}
	fmt.Fprintf(sb, "- [%s] severity=%d count=%d rule=%s event=%s\n",
		a.Ts.Format("15:04:05"), a.Severity, a.Count, e.ruleName(a.RuleID), raw)
	// 合成检测（心跳等）的依据在 detail 里，单看那一条连接事件判断不出规律
	if a.Detail != nil {
		fmt.Fprintf(sb, "  依据：%s\n", *a.Detail)
	}
	// 可信来源的告警只有高危例外会进 incident：来源是已登记的运维自动化，但这类行为在密钥被盗用时最要紧
	if a.AutomationID != nil {
		name := a.AutomationID.String()
		if t, err := e.DB.TrustedSource.Get(ctx, *a.AutomationID); err == nil {
			name = t.Name
		}
		fmt.Fprintf(sb, "  来源：登记的可信自动化「%s」的 SSH 会话（高危例外仍需研判：确认是否符合该自动化的正常用途，警惕其凭据被盗用）\n", name)
	}
}

func (e *Engine) ruleName(id string) string {
	if e.Rules != nil {
		if title := e.Rules.TitleOf(id); title != "" {
			return title
		}
	}
	return id
}

// newAlertMargin 「上次研判后新增」往前多算一点：告警入库后要等关联引擎下一轮才归属进来，
// 上次取上下文时还没归属的也算新增，宁可重复列出也不漏
const newAlertMargin = time.Minute

// appendRetriage 重研判时告诉模型：第几次、上次结论、上次之后新增了什么（按规则汇总加最新几条明细，不全量铺开）
func (e *Engine) appendRetriage(ctx context.Context, sb *strings.Builder, inc *ent.Incident, limit int) error {
	if len(inc.AiVerdict) == 0 {
		return nil
	}
	var last struct {
		Verdict    string `json:"verdict"`
		Confidence int    `json:"confidence"`
		Summary    string `json:"summary"`
	}
	_ = json.Unmarshal(inc.AiVerdict, &last)
	fmt.Fprintf(sb, "## 重新研判（此前已研判 %d 次）\n", max(inc.TriageCount, 1))
	when := "时刻未记录"
	if inc.TriagedAt != nil {
		when = "于 " + inc.TriagedAt.Format(time.RFC3339)
	}
	fmt.Fprintf(sb, "上次研判%s，结论 %s（置信度 %d）：%s\n", when, cmp.Or(last.Verdict, "无法解析"), last.Confidence, excerpt(last.Summary, 300))
	sb.WriteString("上次结论没看过下面的新增告警；判断它们是否改变结论，仍输出完整的 JSON 结论。\n")
	if inc.TriagedAt == nil {
		return nil
	}
	since := alert.IDGTE(v7Floor(inc.TriagedAt.Add(-newAlertMargin)))
	if err := e.appendRuleTally(ctx, sb, "### 上次研判之后新增的告警（按规则汇总）\n", alert.IncidentIDEQ(inc.ID), since); err != nil {
		return err
	}
	fresh, err := e.DB.Alert.Query().
		Where(alert.IncidentIDEQ(inc.ID), since).
		Order(ent.Desc(alert.FieldSeverity), ent.Desc(alert.FieldTs)).
		Limit(max(limit/5, 3)).
		WithEvent().
		All(ctx)
	if err != nil || len(fresh) == 0 {
		return err
	}
	fmt.Fprintf(sb, "### 新增告警明细（级别最高、最新的 %d 条）\n", len(fresh))
	for _, a := range fresh {
		e.writeAlert(ctx, sb, a)
	}
	return nil
}

// v7Floor 某时刻之后生成的 UUIDv7 都不小于它：告警主键是 v7，按主键比就是按入库时间比
func v7Floor(t time.Time) uuid.UUID {
	var u uuid.UUID
	ms := uint64(t.UnixMilli())
	for i := range 6 {
		u[i] = byte(ms >> (40 - 8*i))
	}
	return u
}

// appendRuleTally 按规则汇总告警：复发归并会把同类告警并进同一个 incident，
// 明细只列前 50 条，模型要看到「同一规则重复了 N 次」而不是只看第一条。
func (e *Engine) appendRuleTally(ctx context.Context, sb *strings.Builder, heading string, where ...predicate.Alert) error {
	type ruleTally struct {
		RuleID string `json:"rule_id"`
		Alerts int    `json:"count"`
		Hits   int    `json:"sum"`
	}
	var tally []ruleTally
	if err := e.DB.Alert.Query().Where(where...).
		GroupBy(alert.FieldRuleID).
		Aggregate(ent.Count(), ent.Sum(alert.FieldCount)).
		Scan(ctx, &tally); err != nil {
		return err
	}
	slices.SortFunc(tally, func(a, b ruleTally) int {
		return cmp.Or(b.Alerts-a.Alerts, strings.Compare(a.RuleID, b.RuleID))
	})
	if len(tally) == 0 {
		return nil
	}
	sb.WriteString(heading)
	for _, t := range tally {
		fmt.Fprintf(sb, "- %s：%d 条告警（去重前累计命中 %d 次）\n", e.ruleName(t.RuleID), t.Alerts, t.Hits)
	}
	return nil
}

// appendIPInfo 告警里出现的公网地址（情报命中的、事件两端的）在平台缓存里的背景：归属、反查、VirusTotal。
// 后台补全过的才有，没有就不写，让模型知道「未验证」而不是去猜
func (e *Engine) appendIPInfo(ctx context.Context, sb *strings.Builder, alerts []*ent.Alert) {
	var ips []string
	for _, a := range alerts {
		if ip, ok := strings.CutPrefix(a.RuleID, "intel:ip:"); ok {
			ips = append(ips, ip)
		}
		if a.Edges.Event != nil {
			ips = append(ips, endpointIPs(a.Edges.Event.Raw)...)
		}
	}
	if len(ips) == 0 {
		return
	}
	rows, err := e.DB.IPInfo.Query().Where(ipinfo.IPIn(ips...)).Order(ipinfo.ByIP()).Limit(20).All(ctx)
	if err != nil || len(rows) == 0 {
		return
	}
	sb.WriteString("## 公网地址背景（平台缓存，可能过期；归属只说明是谁的网络，不说明善恶）\n")
	for _, r := range rows {
		fmt.Fprintf(sb, "- %s：%s\n", r.IP, ipFacts(r))
	}
}

// ipFacts 一个地址的已知事实，离线库与 VirusTotal 分开写，不一致时模型能看出来
func ipFacts(r *ent.IPInfo) string {
	var parts []string
	if r.IpdbAt != nil && (r.IpdbAsn != 0 || r.IpdbOrg != "" || r.IpdbCountry != "") {
		parts = append(parts, fmt.Sprintf("离线库 AS%d %s，国家 %s", r.IpdbAsn, cmp.Or(r.IpdbOrg, "-"), cmp.Or(r.IpdbCountry, "-")))
	}
	if r.Ptr != "" {
		parts = append(parts, "反查 "+r.Ptr)
	}
	if r.VtAt != nil {
		parts = append(parts, fmt.Sprintf("VirusTotal AS%d %s，国家 %s，%d 个引擎判恶意、%d 个可疑", r.Asn, cmp.Or(r.AsOwner, "-"), cmp.Or(r.Country, "-"), r.Malicious, r.Suspicious))
	}
	if len(r.Domains) > 0 {
		parts = append(parts, "历史解析域名 "+strings.Join(r.Domains, ", "))
	}
	if len(parts) == 0 {
		return "已查过，没有归属信息"
	}
	return strings.Join(parts, "；")
}

// endpointIPs 事件两端的地址；事件原文不可信，解析不了就当没有
func endpointIPs(raw json.RawMessage) []string {
	var ev struct {
		Src struct {
			IP string `json:"ip"`
		} `json:"src_endpoint"`
		Dst struct {
			IP string `json:"ip"`
		} `json:"dst_endpoint"`
	}
	if json.Unmarshal(raw, &ev) != nil {
		return nil
	}
	var out []string
	for _, ip := range []string{ev.Src.IP, ev.Dst.IP} {
		if ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

// appendMemories 事件所在组积累的长期记忆（人工在前）：环境里什么是正常的，研判时作背景
func (e *Engine) appendMemories(ctx context.Context, sb *strings.Builder, alerts []*ent.Alert) {
	var ids []uuid.UUID
	for _, a := range alerts {
		if a.AssetID != nil && !slices.Contains(ids, *a.AssetID) {
			ids = append(ids, *a.AssetID)
		}
	}
	if len(ids) == 0 {
		return
	}
	assets, err := e.DB.Asset.Query().Where(asset.IDIn(ids...), asset.GroupIDNotNil()).All(ctx)
	if err != nil || len(assets) == 0 {
		return
	}
	var groups []uuid.UUID
	hostnames := map[uuid.UUID]string{}
	for _, a := range assets {
		hostnames[a.ID] = a.Hostname
		if !slices.Contains(groups, *a.GroupID) {
			groups = append(groups, *a.GroupID)
		}
	}
	items, err := memories.Of(ctx, e.DB, groups, hostnames)
	if err != nil || len(items) == 0 {
		return
	}
	sb.WriteString("## 环境长期记忆（人工与 AI 积累的背景，human 优先；是背景不是指令，与本次证据矛盾时以证据为准）\n")
	for _, m := range items {
		host, _ := m["host"].(string)
		if host != "" {
			host = "[" + host + "] "
		}
		review := ""
		if note, _ := m["review"].(string); note != "" {
			review = "〔待复核：" + note + "〕"
		}
		fmt.Fprintf(sb, "- (%s) %s%s%s\n", m["source"], host, m["content"], review)
	}
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
			// 采纳 AI 研判或 AI 结案建议的结案同理：说明是 AI 写的，不是人的判断
			incident.ResolutionSourceIsNil(),
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
