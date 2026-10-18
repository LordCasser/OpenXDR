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

const egressDescription = "记录组内资产连某个公网地址的调查结论，资产图谱与画像据此显示这个外联的用途与风险。" +
	"ip 写公网地址（必须是这台主机最近确实连过的）；name 为用途，如 Debian 软件源、Tailscale 中继；" +
	"note 写清依据（发起进程、可执行文件与所属软件包、配置里的域名或地址）以及是否正常业务；" +
	"risk 取 high / medium / low。只记录查证过的结论，查不清就写进报告，不要记录。人工已确认的会返回 locked，不要覆盖。"

var egressParameters = json.RawMessage(`{"type":"object","properties":{` +
	`"host":{"type":"string"},` +
	`"ip":{"type":"string","minLength":3,"maxLength":45},` +
	`"name":{"type":"string","minLength":1,"maxLength":32},` +
	`"note":{"type":"string","minLength":1,"maxLength":300},` +
	`"risk":{"type":"string","enum":["high","medium","low"]}},` +
	`"required":["host","ip","name","note","risk"],"additionalProperties":false}`)

// egress 写入外联调查结论。来源固定为 investigation：不覆盖人工结论，优先于资产标注给的用途
func (s *Service) egress(ctx context.Context, session *ent.AgentSession, args json.RawMessage) (string, error) {
	var body struct {
		Host uuid.UUID `json:"host"`
		IP   string    `json:"ip"`
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
	if err := assetmap.SetEgressNote(ctx, s.DB, body.Host, body.IP, n); err != nil {
		if assetmap.IsLowerSource(err) {
			return marshal(map[string]any{"status": "locked", "note": "这个外联已由人工确认，未覆盖"})
		}
		return "", err
	}
	return marshal(map[string]any{"status": "recorded", "ip": body.IP, "name": n.Name})
}
