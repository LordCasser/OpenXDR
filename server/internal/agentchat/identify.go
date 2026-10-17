package agentchat

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/internal/assetmap"
)

const identifyDescription = "记录对组内资产上某个监听服务的调查结论，攻击面据此显示服务名与风险。" +
	"port 写 协议/端口，如 udp/5405；name 为服务名；note 写清依据（进程、软件包、配置、访问来源）以及是否需要对当前范围开放；" +
	"risk 取 high / medium / low，指该服务按现在的暴露范围有多大风险。只记录查证过的结论，查不清就写进报告，不要记录。" +
	"人工已确认的服务会返回 locked，不要覆盖。"

var identifyParameters = json.RawMessage(`{"type":"object","properties":{` +
	`"host":{"type":"string"},` +
	`"port":{"type":"string","pattern":"^(tcp|udp)/[0-9]{1,5}$"},` +
	`"name":{"type":"string","minLength":1,"maxLength":32},` +
	`"note":{"type":"string","minLength":1,"maxLength":300},` +
	`"risk":{"type":"string","enum":["high","medium","low"]}},` +
	`"required":["host","port","name","note","risk"],"additionalProperties":false}`)

// identify 写入调查结论。来源固定为 investigation：不覆盖人工结论，会覆盖 AI 标注时的猜测
func (s *Service) identify(ctx context.Context, session *ent.AgentSession, args json.RawMessage) (string, error) {
	var body struct {
		Host uuid.UUID `json:"host"`
		Port string    `json:"port"`
		Name string    `json:"name"`
		Note string    `json:"note"`
		Risk string    `json:"risk"`
	}
	if err := json.Unmarshal(args, &body); err != nil {
		return "", err
	}
	inGroup, err := s.DB.Asset.Query().Where(asset.IDEQ(body.Host), asset.GroupIDEQ(session.GroupID)).Exist(ctx)
	if err != nil {
		return "", err
	}
	if !inGroup {
		return "", errors.New("主机不在本组")
	}
	n, err := assetmap.CleanNote(body.Name, body.Note, body.Risk)
	if err != nil {
		return "", err
	}
	if n.Name == "" || n.Note == "" {
		return "", errors.New("name 与 note 不能为空")
	}
	n.Source, n.By = "investigation", session.ID.String()
	if err := assetmap.SetServiceNote(ctx, s.DB, body.Host, body.Port, n); err != nil {
		if assetmap.IsLowerSource(err) {
			return marshal(map[string]any{"status": "locked", "note": "该服务已由人工确认，未覆盖"})
		}
		return "", err
	}
	return marshal(map[string]any{"status": "recorded", "port": body.Port, "name": n.Name})
}
