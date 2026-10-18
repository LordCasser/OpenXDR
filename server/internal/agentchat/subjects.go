package agentchat

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/finding"
	"openxdr/server/ent/incident"
)

// subjectsPrompt 会话绑定了事件或待办时追加的说明；结案留给人，因为结案备注会作为人工案例喂回研判。
const subjectsPrompt = "subjects 是用户从界面交给你处理的事件或待办，平台每轮按库里的当前状态提供：围绕它们调查、核实并处置，需要执行的命令照常直接下发，高风险操作照常等组管理员批准。" +
	"事件由人在界面上结案，你在结尾按事件逐个给出结案建议（属实已处置 / 误报或良性，附理由）；待办处理好并复查确认后，用 track 标 resolved（host 与 key 取 subject 里的值）。"

// roster 交来的对象逐条列进系统提示：只放在数据里时，模型会数错个数、做完一部分就收工
func roster(subjects []map[string]any) string {
	var b strings.Builder
	b.WriteString("本会话交给你 " + strconv.Itoa(len(subjects)) + " 个对象，必须逐个处理，全部处理完才算结束，结尾逐个说明结果：")
	for i, sub := range subjects {
		b.WriteString(strconv.Itoa(i+1) + ". ")
		if sub["kind"] == "finding" {
			b.WriteString(fmt.Sprintf("待办 %v / %v：%v；", sub["hostname"], sub["key"], sub["title"]))
		} else {
			title, _ := sub["title"].(*string)
			b.WriteString(fmt.Sprintf("事件 %v：%s；", sub["id"], deref(title)))
		}
	}
	return b.String()
}

func deref(s *string) string {
	if s == nil {
		return "（无标题）"
	}
	return *s
}

type subjectAlert struct {
	Rule     string `json:"rule"`
	Severity int16  `json:"severity"`
	Host     string `json:"host,omitempty"`
	Count    int    `json:"count"`
	First    string `json:"first"`
	Evidence string `json:"evidence,omitempty"`
}

// subjectsFor 会话绑定对象的当前状态。对象已删除就跳过，不让整轮请求失败。
func (s *Service) subjectsFor(ctx context.Context, session *ent.AgentSession, hostnames map[uuid.UUID]string) ([]map[string]any, error) {
	out := []map[string]any{}
	for _, subject := range session.Subjects {
		kind, raw, _ := strings.Cut(subject, ":")
		id, err := uuid.Parse(raw)
		if err != nil {
			continue
		}
		var item map[string]any
		switch kind {
		case "incident":
			item, err = s.incidentSubject(ctx, id, hostnames)
		case "finding":
			item, err = s.findingSubject(ctx, id, hostnames)
		}
		if ent.IsNotFound(err) || item == nil {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, nil
}

func (s *Service) incidentSubject(ctx context.Context, id uuid.UUID, hostnames map[uuid.UUID]string) (map[string]any, error) {
	inc, err := s.DB.Incident.Query().Where(incident.IDEQ(id)).Only(ctx)
	if err != nil {
		return nil, err
	}
	// 最要紧的 10 条：级别高的在前，同级按时间
	alerts, err := s.DB.Alert.Query().Where(alert.IncidentIDEQ(id)).
		Order(ent.Desc(alert.FieldSeverity), ent.Asc(alert.FieldTs)).Limit(10).WithEvent().All(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]subjectAlert, len(alerts))
	for i, a := range alerts {
		rule := a.RuleID
		if s.Rules != nil {
			if title := s.Rules.TitleOf(a.RuleID); title != "" {
				rule = title
			}
		}
		row := subjectAlert{Rule: rule, Severity: a.Severity, Count: a.Count, First: a.Ts.Format("2006-01-02 15:04:05")}
		if a.AssetID != nil {
			row.Host = hostnames[*a.AssetID]
		}
		if a.Edges.Event != nil {
			row.Evidence = evidence(a.Edges.Event.Raw)
		}
		rows[i] = row
	}
	return map[string]any{
		"kind": "incident", "id": inc.ID, "title": inc.Title, "status": inc.Status,
		"created_at": inc.CreatedAt, "ai_verdict": inc.AiVerdict, "alerts": rows,
	}, nil
}

func (s *Service) findingSubject(ctx context.Context, id uuid.UUID, hostnames map[uuid.UUID]string) (map[string]any, error) {
	f, err := s.DB.Finding.Query().Where(finding.IDEQ(id)).Only(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"kind": "finding", "id": f.ID, "host": f.AssetID, "hostname": hostnames[f.AssetID], "key": f.Key,
		"title": f.Title, "detail": f.Detail, "severity": f.Severity, "status": f.Status, "note": f.Note,
	}, nil
}

// evidence 告警事件里最能说明发生了什么的那一项：命令行 / 文件路径 / 连接目标，截到 200 字
func evidence(raw json.RawMessage) string {
	var r struct {
		Process struct {
			CmdLine string `json:"cmd_line"`
		} `json:"process"`
		File struct {
			Path string `json:"path"`
		} `json:"file"`
		Dst struct {
			IP   string `json:"ip"`
			Port int    `json:"port"`
		} `json:"dst_endpoint"`
	}
	if json.Unmarshal(raw, &r) != nil {
		return ""
	}
	text := r.Process.CmdLine
	if text == "" {
		text = r.File.Path
	}
	if text == "" && r.Dst.IP != "" {
		text = "→ " + r.Dst.IP
		if r.Dst.Port > 0 {
			text += ":" + strconv.Itoa(r.Dst.Port)
		}
	}
	if utf8.RuneCountInString(text) > 200 {
		text = string([]rune(text)[:200]) + "…"
	}
	return text
}
