// 自动响应：高置信度 malicious 的研判结论自动隔离涉事主机。
//
// 保险一道不少：
//   - 显式配置 AUTO_RESPONSE_ENABLED 才挂钩子，且仍受 RESPONSE_ENABLED 总开关约束；隔离一律真执行
//   - 只有 malicious 且置信度达到门槛才动
//   - 白名单主机绝不自动隔离——误杀一台生产机的代价高于慢五分钟
//   - 每次决策（含跳过）都进审计，事后能还原"为什么动了/没动"
package response

import (
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"time"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	entcommand "openxdr/server/ent/command"
	"openxdr/server/internal/audit"
)

type Auto struct {
	Hub *Hub
	// 置信度门槛：verdict 为 malicious 且 confidence 达标才动
	MinConfidence int
	// 绝不自动隔离的主机名
	Exempt map[string]bool
	// 隔离时放行的地址，必须含 server 自身
	AllowEndpoints []string
}

// React 研判结论落库后的钩子：满足条件则对 incident 涉事资产下发隔离。
// 任何失败只记日志——自动响应是锦上添花，绝不能反过来拖垮研判管道。
func (a *Auto) React(ctx context.Context, incidentID uuid.UUID, verdict json.RawMessage) {
	var v struct {
		Verdict    string `json:"verdict"`
		Confidence int    `json:"confidence"`
	}
	if json.Unmarshal(verdict, &v) != nil || v.Verdict != "malicious" || v.Confidence < a.MinConfidence {
		return
	}

	alerts, err := a.Hub.DB.Alert.Query().
		Where(alert.IncidentIDEQ(incidentID), alert.AssetIDNotNil()).
		WithAsset().
		Limit(500).
		All(ctx)
	if err != nil {
		slog.Error("自动响应查询告警失败", "incident", incidentID, "err", err)
		return
	}
	seen := map[uuid.UUID]bool{}
	for _, al := range alerts {
		assetID := *al.AssetID
		if seen[assetID] || al.Edges.Asset == nil {
			continue
		}
		seen[assetID] = true
		a.isolate(ctx, incidentID, al.Edges.Asset, v.Confidence)
	}
}

func (a *Auto) isolate(ctx context.Context, incidentID uuid.UUID, asset *ent.Asset, confidence int) {
	db := a.Hub.DB
	if a.Exempt[asset.Hostname] {
		audit.System(ctx, db, "auto_response_skipped", incidentID.String(),
			asset.Hostname+" 在自动响应白名单内")
		return
	}
	// 兼容旧版随机 ID 的自动指令；新指令另由固定 ID 主键防止并发重复创建。
	done, err := db.Command.Query().
		Where(
			entcommand.IncidentIDEQ(incidentID),
			entcommand.AssetIDEQ(asset.ID),
			entcommand.KindEQ("isolate_host"),
			entcommand.IssuedByEQ("auto"),
		).
		Exist(ctx)
	if err != nil || done {
		return
	}

	started := time.Now()
	cmd, err := a.Hub.Issue(ctx, Request{
		automatic:      true,
		AssetID:        asset.ID,
		Kind:           "isolate_host",
		IncidentID:     &incidentID,
		IssuedBy:       "auto",
		AllowEndpoints: a.AllowEndpoints,
	})
	if err != nil {
		audit.System(ctx, db, "auto_response_failed", incidentID.String(),
			asset.Hostname+": "+err.Error())
		return
	}
	// 并发研判撞上同一事件的同一条隔离：Issue 返回之前那条，已经审计过，不再重复记
	if cmd.CreatedAt.Before(started) {
		slog.Info("自动隔离已下发过，跳过重复审计", "incident", incidentID, "command", cmd.ID)
		return
	}
	audit.System(ctx, db, "auto_response", cmd.ID.String(),
		"isolate_host "+asset.Hostname+" (confidence "+strconv.Itoa(confidence)+", status "+cmd.Status+")")
	slog.Info("自动响应指令状态", "incident", incidentID,
		"host", asset.Hostname, "confidence", confidence, "command", cmd.ID, "status", cmd.Status)
}
