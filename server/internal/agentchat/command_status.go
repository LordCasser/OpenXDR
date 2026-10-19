package agentchat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/command"
	"openxdr/server/internal/piruntime"
)

var commandStatusTool = piruntime.Tool{
	Name:        "command_status",
	Description: "只读查询当前组已有指令的最新回执。exec 超时或结果未知时先查 command UUID；不会重新执行。succeeded 仅是动作回执，不证明处置有效；pending/sent/unknown 不代表未执行，禁止据此自动重试。",
	Parameters:  json.RawMessage(`{"type":"object","properties":{"command":{"type":"string","format":"uuid"}},"required":["command"],"additionalProperties":false}`),
}

func (s *Service) commandStatus(ctx context.Context, session *ent.AgentSession, args json.RawMessage) (string, error) {
	var body struct {
		Command uuid.UUID `json:"command"`
	}
	decoder := json.NewDecoder(bytes.NewReader(args))
	decoder.DisallowUnknownFields()
	if len(args) > 1024 || decoder.Decode(&body) != nil || body.Command == uuid.Nil || session.GroupID == uuid.Nil {
		return "", errors.New("command 必须为有效指令 UUID")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return "", errors.New("指令查询参数包含多余内容")
	}
	cmd, err := s.DB.Command.Query().Where(command.IDEQ(body.Command), command.HasAssetWith(asset.GroupIDEQ(session.GroupID))).Only(ctx)
	if ent.IsNotFound(err) {
		return "", errors.New("指令不存在或不在当前组")
	}
	if err != nil {
		return "", err
	}
	truncated := cmd.Truncated
	stdout := modelOutput(cmd.Stdout, &truncated)
	stderr := modelOutput(cmd.Stderr, &truncated)
	return marshal(map[string]any{
		"commandId": cmd.ID, "assetId": cmd.AssetID, "kind": cmd.Kind, "status": cmd.Status,
		"createdAt": cmd.CreatedAt, "completedAt": cmd.CompletedAt, "exitCode": cmd.ExitCode,
		"stdout": stdout, "stderr": stderr, "truncated": truncated,
		"effect": "not_assessed_by_this_tool", "retry": "not_authorized_by_this_tool",
	})
}
