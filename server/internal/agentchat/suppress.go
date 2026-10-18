package agentchat

import (
	"context"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/suppression"
)

const suppressDescription = "提议在组内某台主机上抑制一条反复误报的检测规则，组管理员批准后才生效。" +
	"只用于查证过的良性、且会反复出现的命中（比如例行巡检脚本触发的侦察规则）；一次性的误报在结论里说明即可，不要提。" +
	"host 为主机 UUID（只能针对单台主机，不能全局）；rule_id 必须是这台主机上近 30 天确实命中过的规则；" +
	"reason 写清为什么是良性：哪个进程、什么命令、多久一次、属于什么正常业务；days 为有效期（1–90，默认 30），到期自动失效。"

var suppressParameters = json.RawMessage(`{"type":"object","properties":{` +
	`"host":{"type":"string"},` +
	`"rule_id":{"type":"string","minLength":1,"maxLength":200},` +
	`"reason":{"type":"string","minLength":10,"maxLength":500},` +
	`"days":{"type":"integer","minimum":1,"maximum":90}},` +
	`"required":["host","rule_id","reason"],"additionalProperties":false}`)

// rejectedCooldown 被拒绝的提议多久之内不再接受同一条（主机、规则）
const rejectedCooldown = 30 * 24 * time.Hour

// suppress 写一条待批准的抑制。不进抑制索引，组管理员在抑制页批准后才生效
func (s *Service) suppress(ctx context.Context, session *ent.AgentSession, args json.RawMessage) (string, error) {
	var body struct {
		Host   uuid.UUID `json:"host"`
		RuleID string    `json:"rule_id"`
		Reason string    `json:"reason"`
		Days   int       `json:"days"`
	}
	if err := json.Unmarshal(args, &body); err != nil {
		return "", err
	}
	if n := utf8.RuneCountInString(body.Reason); n < 10 || n > 500 {
		return "", errors.New("reason 须为 10–500 字，写清为什么是良性")
	}
	if body.Days == 0 {
		body.Days = 30
	}
	if body.Days < 1 || body.Days > 90 {
		return "", errors.New("days 须为 1–90")
	}
	inGroup, err := s.DB.Asset.Query().Where(asset.IDEQ(body.Host), asset.GroupIDEQ(session.GroupID)).Exist(ctx)
	if err != nil {
		return "", err
	}
	if !inGroup {
		return "", errors.New("主机不在本组")
	}
	// 只能抑制这台主机上真实命中过的规则；平台指令触发的不算，那些本来就不进事件
	hit, err := s.DB.Alert.Query().Where(alert.AssetIDEQ(body.Host), alert.RuleIDEQ(body.RuleID), alert.CommandIDIsNil(),
		alert.Or(alert.TsGT(time.Now().Add(-30*24*time.Hour)), alert.LastTsGT(time.Now().Add(-30*24*time.Hour)))).Exist(ctx)
	if err != nil {
		return "", err
	}
	if !hit {
		return "", errors.New("这台主机近 30 天没有命中过这条规则")
	}
	existing, err := s.DB.Suppression.Query().
		Where(suppression.RuleIDEQ(body.RuleID), suppression.Or(suppression.AssetIDEQ(body.Host), suppression.AssetIDIsNil())).
		Order(ent.Desc(suppression.FieldCreatedAt)).All(ctx)
	if err != nil {
		return "", err
	}
	for _, e := range existing {
		live := e.ExpiresAt == nil || e.ExpiresAt.After(time.Now())
		switch {
		case e.Status == "active" && live:
			return marshal(map[string]any{"status": "exists", "note": "已有生效的抑制"})
		case e.Status == "proposed":
			return marshal(map[string]any{"status": "pending", "note": "已有待批准的提议"})
		case e.Status == "rejected" && e.ReviewedAt != nil && time.Since(*e.ReviewedAt) < rejectedCooldown:
			return marshal(map[string]any{"status": "rejected", "note": "组管理员 30 天内拒绝过同样的提议，不要再提，在结论里说明即可"})
		}
	}
	p, err := s.DB.Suppression.Create().SetRuleID(body.RuleID).SetAssetID(body.Host).SetReason(body.Reason).
		SetCreatedBy("ai:" + session.ID.String()).SetSessionID(session.ID).SetStatus("proposed").
		SetExpiresAt(time.Now().AddDate(0, 0, body.Days)).Save(ctx)
	if err != nil {
		return "", err
	}
	return marshal(map[string]any{"status": "proposed", "id": p.ID, "note": "已提交，组管理员批准后生效"})
}
