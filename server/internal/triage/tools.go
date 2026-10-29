package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"openxdr/server/ent"
	entalert "openxdr/server/ent/alert"
	entevent "openxdr/server/ent/event"
	"openxdr/server/internal/eventsearch"
)

// 调查工具集：模型像分析师一样主动查证，而不是只看摘要。
// 三个就够——检索、血缘、前科，对应人工研判的三个基本动作。
var investigationTools = []Tool{
	makeTool("query_events",
		"按关键词检索原始事件（对事件里的字段值做子串匹配）。可用于追查某个 IP、域名、命令行、文件路径出现在哪些事件里。",
		`{"type":"object","properties":{
			"keyword":{"type":"string","description":"要搜索的子串，如 IP、域名、命令片段"},
			"hours":{"type":"integer","description":"回溯小时数，默认 24，最大 168"},
            "mode":{"type":"string","enum":["indexed","raw"],"description":"默认 indexed：搜索字段值，不含纯 UUID/32 位以上十六进制哈希值；raw：完整原文，查 UUID/哈希时使用，最多等待 15 秒"}
		},"required":["keyword"]}`),
	makeTool("process_lineage",
		"查询进程的血缘：祖先链与直接子进程。用于还原攻击链的来龙去脉。",
		`{"type":"object","properties":{
			"process_guid":{"type":"string","description":"事件里的进程 GUID（process.uid）"}
		},"required":["process_guid"]}`),
	makeTool("host_alerts",
		"查询某主机最近的告警历史（含已关闭事件）。用于判断该主机是初犯还是惯犯、当前事件是否是更大活动的一部分。",
		`{"type":"object","properties":{
			"asset_id":{"type":"string","description":"主机的 asset ID（事件里的 asset_id，或图里 asset 节点的 id 后缀）"},
			"days":{"type":"integer","description":"回溯天数，默认 7"}
		},"required":["asset_id"]}`),
}

// execTool 执行一次工具调用。错误以文本返回给模型而不是中断研判——
// 模型能理解"查询失败"并继续，半途而废的研判什么都留不下。
func (e *Engine) execTool(ctx context.Context, name, args string) string {
	started := time.Now()
	var failed bool
	var out any
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	defer func() {
		if run := timingFrom(ctx); run != nil {
			run.toolCalls++
			elapsed := time.Since(started).Milliseconds()
			run.toolMS += elapsed
			tool := name
			if tool != "query_events" && tool != "host_alerts" && tool != "process_lineage" {
				tool = "unknown"
			}
			detail := map[string]any{"tool": tool, "duration_ms": elapsed, "failed": failed}
			if m, ok := out.(map[string]any); ok {
				if n, ok := m["returned"].(int); ok {
					detail["returned"] = n
				}
				if v, ok := m["truncated"].(bool); ok {
					detail["truncated"] = v
				}
			}
			run.tools = append(run.tools, detail)
			if failed {
				run.toolErrors++
			}
		}
	}()
	var err error
	out, err = func() (any, error) {
		switch name {
		case "query_events":
			return e.toolQueryEvents(ctx, args)
		case "process_lineage":
			return e.toolProcessLineage(ctx, args)
		case "host_alerts":
			return e.toolHostAlerts(ctx, args)
		default:
			return nil, fmt.Errorf("未知工具 %s", name)
		}
	}()
	if err != nil {
		failed = true
		return fmt.Sprintf(`{"status":"error","coverage":"unknown","error": %q}`, err.Error())
	}
	b, _ := json.Marshal(out)
	return string(b)
}

type eventBrief struct {
	Ts           string                     `json:"ts"`
	Class        int                        `json:"class"`
	Source       string                     `json:"source"`
	AssetID      string                     `json:"asset_id,omitempty"`
	Host         string                     `json:"host,omitempty"`
	Raw          string                     `json:"raw"`
	RawTruncated bool                       `json:"raw_truncated"`
	DNS          map[string]json.RawMessage `json:"dns,omitempty"`
	DNSOmitted   []string                   `json:"dns_omitted,omitempty"`
}

func (e *Engine) toolQueryEvents(ctx context.Context, args string) (any, error) {
	var in struct {
		Keyword string `json:"keyword"`
		Hours   int    `json:"hours"`
		Mode    string `json:"mode"`
	}
	if json.Unmarshal([]byte(args), &in) != nil || in.Keyword == "" {
		return nil, fmt.Errorf("keyword 必填")
	}
	if in.Hours <= 0 || in.Hours > 168 {
		in.Hours = 24
	}
	if in.Mode == "" {
		in.Mode = "indexed"
	}
	if in.Mode != "indexed" && in.Mode != "raw" {
		return nil, fmt.Errorf("mode 必须为 indexed 或 raw")
	}
	predicate := eventsearch.ValuesKeyword(in.Keyword)
	if in.Mode == "raw" {
		predicate = eventsearch.RawKeyword(in.Keyword)
	}
	until := time.Now().UTC()
	since := until.Add(-time.Duration(in.Hours) * time.Hour)
	rows, err := e.DB.Event.Query().
		Where(
			entevent.TsGTE(since), entevent.TsLTE(until),
			predicate,
		).
		Order(ent.Desc(entevent.FieldTs)).
		WithAsset().
		Limit(16).
		All(ctx)
	if err != nil {
		return nil, err
	}
	truncated := len(rows) > 15
	rows = rows[:min(len(rows), 15)]
	out := make([]eventBrief, len(rows))
	for i, ev := range rows {
		out[i] = brief(ev)
	}
	return map[string]any{"status": "ok", "mode": in.Mode, "items": out, "limit": 15, "returned": len(out), "truncated": truncated, "from": since, "to": until, "coverage": "仅覆盖已采集且仍保留的数据；indexed 不保证纯 UUID/32 位以上十六进制哈希值的覆盖，查这些值需用 raw。未发现不代表没有发生，截断时不能声称全量检索"}, nil
}

func (e *Engine) toolProcessLineage(ctx context.Context, args string) (any, error) {
	var in struct {
		ProcessGUID string `json:"process_guid"`
	}
	if json.Unmarshal([]byte(args), &in) != nil {
		return nil, fmt.Errorf("process_guid 必填")
	}
	guid, err := uuid.Parse(in.ProcessGUID)
	if err != nil {
		return nil, fmt.Errorf("process_guid 不是合法 UUID")
	}

	ancestors := []eventBrief{}
	ancestorTruncated, missingAncestor := false, false
	cur := guid
	for depth := 0; depth < 10; depth++ {
		ev, err := e.DB.Event.Query().
			Where(entevent.ProcessGUIDEQ(cur)).
			WithAsset().
			First(ctx)
		if err != nil {
			if !ent.IsNotFound(err) {
				return nil, err
			}
			missingAncestor = true
			break
		}
		ancestors = append(ancestors, brief(ev))
		if ev.ParentProcessGUID == nil {
			break
		}
		cur = *ev.ParentProcessGUID
		ancestorTruncated = depth == 9
	}

	children, err := e.DB.Event.Query().
		Where(entevent.ParentProcessGUIDEQ(guid)).
		WithAsset().
		Limit(11).
		All(ctx)
	if err != nil {
		return nil, err
	}
	childTruncated := len(children) > 10
	children = children[:min(len(children), 10)]
	childOut := make([]eventBrief, len(children))
	for i, ev := range children {
		childOut[i] = brief(ev)
	}
	return map[string]any{"self_and_ancestors": ancestors, "children": childOut, "status": "ok", "returned": len(ancestors) + len(childOut), "truncated": ancestorTruncated || childTruncated, "ancestors_truncated": ancestorTruncated, "children_truncated": childTruncated, "missing_ancestor": missingAncestor, "coverage": "仅限已采集并保留的进程记录；血缘缺失不是正常或无父进程的证据"}, nil
}

func (e *Engine) toolHostAlerts(ctx context.Context, args string) (any, error) {
	var in struct {
		AssetID string `json:"asset_id"`
		Days    int    `json:"days"`
	}
	if json.Unmarshal([]byte(args), &in) != nil {
		return nil, fmt.Errorf("asset_id 必填")
	}
	assetID, err := uuid.Parse(in.AssetID)
	if err != nil {
		return nil, fmt.Errorf("asset_id 不是合法 UUID")
	}
	if in.Days <= 0 || in.Days > 90 {
		in.Days = 7
	}
	until := time.Now().UTC()
	since := until.AddDate(0, 0, -in.Days)
	rows, err := e.DB.Alert.Query().
		Where(
			entalert.AssetIDEQ(assetID),
			entalert.TsGTE(since), entalert.TsLTE(until),
		).
		Order(ent.Desc(entalert.FieldTs)).
		Limit(21).
		All(ctx)
	if err != nil {
		return nil, err
	}
	truncated := len(rows) > 20
	rows = rows[:min(len(rows), 20)]
	type alertBrief struct {
		Ts       string `json:"ts"`
		Rule     string `json:"rule"`
		Severity int16  `json:"severity"`
		Count    int    `json:"count"`
	}
	out := make([]alertBrief, len(rows))
	for i, a := range rows {
		rule := a.RuleID
		if e.Rules != nil {
			if title := e.Rules.TitleOf(a.RuleID); title != "" {
				rule = title
			}
		}
		out[i] = alertBrief{Ts: a.Ts.Format(time.RFC3339), Rule: rule, Severity: a.Severity, Count: a.Count}
	}
	host := ""
	if as, err := e.DB.Asset.Get(ctx, assetID); err == nil {
		host = as.Hostname
	}
	return map[string]any{"host": host, "alerts": out, "status": "ok", "limit": 20, "returned": len(out), "truncated": truncated, "from": since, "to": until, "coverage": "按告警首次出现时间筛选；无告警不代表没有事件或没有攻击"}, nil
}

func brief(ev *ent.Event) eventBrief { return briefLimit(ev, 300) }

func briefLimit(ev *ent.Event, limit int) eventBrief {
	raw := string(ev.Raw)
	truncated := len(raw) > limit
	if truncated {
		end := limit
		for end > 0 && !utf8.ValidString(raw[:end]) {
			end--
		}
		raw = raw[:end] + "…"
	}
	b := eventBrief{
		Ts:           ev.Ts.Format(time.RFC3339),
		Class:        ev.ClassUID,
		Source:       ev.Source,
		Raw:          raw,
		RawTruncated: truncated,
	}
	// 只给 asset ID 模型没法在结论里说出是哪台机器
	if ev.AssetID != nil {
		b.AssetID = ev.AssetID.String()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(ev.Raw, &fields) == nil && fields["query"] != nil {
		b.DNS = make(map[string]json.RawMessage)
		for _, key := range []string{"query", "answers", "requester", "src_endpoint", "dst_endpoint", "process", "container"} {
			if value := fields[key]; len(value) > 2048 {
				b.DNSOmitted = append(b.DNSOmitted, key)
			} else if len(value) > 0 {
				b.DNS[key] = value
			}
		}
	}
	if ev.Edges.Asset != nil {
		b.Host = ev.Edges.Asset.Hostname
	}
	return b
}
