package agentchat

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/finding"
	"openxdr/server/internal/commandgate"
)

const trackDescription = "登记或复查一条运维待办（巡检发现的问题）。同一主机同一问题每轮用同一个 key（小写字母、数字、. _ -），" +
	"如 backup-service-failed。status=open 登记新问题或确认遗留问题仍在；status=resolved 表示复查确认已修复。" +
	"人工忽略的待办会返回 ignored，不要再登记，也不要列进报告的待处理事项。"

var trackParameters = json.RawMessage(`{"type":"object","properties":{` +
	`"host":{"type":"string"},` +
	`"key":{"type":"string","pattern":"^[a-z0-9][a-z0-9._-]{0,63}$"},` +
	`"title":{"type":"string","minLength":1,"maxLength":200},` +
	`"detail":{"type":"string","maxLength":4000},` +
	`"severity":{"type":"string","enum":["info","low","medium","high"]},` +
	`"status":{"type":"string","enum":["open","resolved"]}},` +
	`"required":["host","key","title","severity","status"],"additionalProperties":false}`)

var findingKey = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// track 按（组、主机、key）登记或复查待办。人工忽略的不动，原样告诉模型。
func (s *Service) track(ctx context.Context, session *ent.AgentSession, args json.RawMessage) (string, error) {
	var body struct {
		Host     uuid.UUID `json:"host"`
		Key      string    `json:"key"`
		Title    string    `json:"title"`
		Detail   string    `json:"detail"`
		Severity string    `json:"severity"`
		Status   string    `json:"status"`
	}
	if err := json.Unmarshal(args, &body); err != nil {
		return "", err
	}
	switch {
	case !findingKey.MatchString(body.Key):
		return "", errors.New("key 只能是小写字母、数字与 . _ -，不超过 64 位")
	case body.Title == "" || len(body.Title) > 200 || len(body.Detail) > 4000:
		return "", errors.New("title 或 detail 长度无效")
	case !slices.Contains([]string{"info", "low", "medium", "high"}, body.Severity):
		return "", errors.New("severity 必须是 info / low / medium / high")
	case body.Status != "open" && body.Status != "resolved":
		return "", errors.New("status 必须是 open / resolved")
	}
	inGroup, err := s.DB.Asset.Query().Where(asset.IDEQ(body.Host), asset.GroupIDEQ(session.GroupID)).Exist(ctx)
	if err != nil {
		return "", err
	}
	if !inGroup {
		return "", errors.New("主机不在本组")
	}
	f, err := s.DB.Finding.Query().
		Where(finding.GroupIDEQ(session.GroupID), finding.AssetIDEQ(body.Host), finding.KeyEQ(body.Key)).
		Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return "", err
	}
	now := time.Now()
	switch {
	case f != nil && f.Status == "ignored":
		return marshal(map[string]any{"id": f.ID, "status": "ignored", "note": f.Note})
	case f == nil && body.Status == "resolved":
		return "", errors.New("没有这条待办；已修复的问题不用登记")
	case f == nil:
		f, err = s.DB.Finding.Create().SetGroupID(session.GroupID).SetAssetID(body.Host).SetKey(body.Key).
			SetTitle(body.Title).SetDetail(body.Detail).SetSeverity(body.Severity).SetSessionID(session.ID).Save(ctx)
		if err != nil {
			return "", err
		}
		return marshal(map[string]any{"id": f.ID, "status": "open", "new": true})
	case body.Status == "resolved":
		if f.Status == "open" {
			err = f.Update().SetStatus("resolved").SetResolvedAt(now).SetResolvedBy(commandgate.SystemActor).
				SetLastSeen(now).SetSessionID(session.ID).Exec(ctx)
		}
		if err != nil {
			return "", err
		}
		return marshal(map[string]any{"id": f.ID, "status": "resolved"})
	default:
		// 仍存在；之前被标成已修复的重新打开
		reopened := f.Status == "resolved"
		err = f.Update().SetStatus("open").SetTitle(body.Title).SetDetail(body.Detail).SetSeverity(body.Severity).
			SetLastSeen(now).SetSessionID(session.ID).ClearResolvedAt().ClearResolvedBy().Exec(ctx)
		if err != nil {
			return "", err
		}
		return marshal(map[string]any{"id": f.ID, "status": "open", "reopened": reopened})
	}
}

// findingBrief 给模型看的待办摘要。
type findingBrief struct {
	Host      uuid.UUID `json:"host"`
	Hostname  string    `json:"hostname"`
	Key       string    `json:"key"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity,omitempty"`
	FirstSeen string    `json:"first_seen,omitempty"`
	Note      *string   `json:"note,omitempty"`
}

// findingsFor 本组遗留待办与人工忽略的待办，各最多 100 条。
func (s *Service) findingsFor(ctx context.Context, group uuid.UUID, hostnames map[uuid.UUID]string) (open, ignored []findingBrief, err error) {
	open, ignored = []findingBrief{}, []findingBrief{}
	for _, status := range []string{"open", "ignored"} {
		rows, err := s.DB.Finding.Query().Where(finding.GroupIDEQ(group), finding.StatusEQ(status)).
			Order(ent.Desc(finding.FieldLastSeen)).Limit(100).All(ctx)
		if err != nil {
			return nil, nil, err
		}
		for _, f := range rows {
			b := findingBrief{Host: f.AssetID, Hostname: hostnames[f.AssetID], Key: f.Key, Title: f.Title}
			if status == "open" {
				b.Severity, b.FirstSeen = f.Severity, f.FirstSeen.Format(time.DateOnly)
				open = append(open, b)
			} else {
				b.Note = f.Note
				ignored = append(ignored, b)
			}
		}
	}
	return open, ignored, nil
}
