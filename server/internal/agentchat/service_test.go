package agentchat

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/google/uuid"
	"openxdr/server/ent"
)

func TestUnknownCommandIsNotSuccessfulToolResult(t *testing.T) {
	id := uuid.New()
	output, err := (&Service{}).waitCommand(context.Background(), &ent.Command{ID: id, Status: "unknown"}, 1)
	if err == nil || output != "" || !strings.Contains(err.Error(), id.String()) || !strings.Contains(err.Error(), "禁止自动重试") {
		t.Fatalf("未知结果被当作成功: %q %v", output, err)
	}
}

func TestCommandOutputBoundedWithoutChangingReceipt(t *testing.T) {
	stdout, stderr := strings.Repeat("中", 30000), strings.Repeat("e", 9000)
	original := &ent.Command{ID: uuid.New(), Status: "succeeded", Stdout: &stdout, Stderr: &stderr}
	output, err := (&Service{}).waitCommand(context.Background(), original, 1)
	if err != nil {
		t.Fatal(err)
	}
	var got ent.Command
	if err := json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Truncated || len(*got.Stdout) > 4096 || len(*got.Stderr) > 4096 || !utf8.ValidString(*got.Stdout) {
		t.Fatalf("模型回执未正确裁剪: %+v", got)
	}
	if original.Truncated || len(*original.Stdout) != 90000 || len(*original.Stderr) != 9000 {
		t.Fatal("完整命令回执被修改")
	}
	short := "完整输出"
	original.Stdout, original.Stderr = &short, nil
	output, err = (&Service{}).waitCommand(context.Background(), original, 1)
	if err != nil {
		t.Fatal(err)
	}
	got = ent.Command{}
	if err = json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatal(err)
	}
	if got.Truncated || *got.Stdout != short || got.Stderr != nil {
		t.Fatal("短输出不应截断或填充")
	}
}
