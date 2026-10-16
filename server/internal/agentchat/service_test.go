package agentchat

import (
	"context"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"strings"
	"testing"
)

func TestUnknownCommandIsNotSuccessfulToolResult(t *testing.T) {
	id := uuid.New()
	output, err := (&Service{}).waitCommand(context.Background(), &ent.Command{ID: id, Status: "unknown"}, 1)
	if err == nil || output != "" || !strings.Contains(err.Error(), id.String()) || !strings.Contains(err.Error(), "禁止自动重试") {
		t.Fatalf("未知结果被当作成功: %q %v", output, err)
	}
}
