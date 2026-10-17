//go:build integration

package agentchat

import (
	"context"
	"strings"
	"testing"

	"openxdr/server/ent/finding"
	"openxdr/server/internal/commandgate"
	"openxdr/server/internal/testdb"
)

// 待办生命周期：登记 → 仍在 → 复查修复 → 复发重开 → 人工忽略后 AI 不再改动。
func TestTrackFindings(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("g").SaveX(ctx)
	other := db.Group.Create().SetName("o").SaveX(ctx)
	host := db.Asset.Create().SetHostname("pve2").SetGroupID(group.ID).SaveX(ctx)
	stranger := db.Asset.Create().SetHostname("x").SetGroupID(other.ID).SaveX(ctx)
	session := db.AgentSession.Create().SetKind("task").SetGroupID(group.ID).SetInitiator(commandgate.SystemActor).
		SetModel("m").SetStatus("running").SetTitle("巡检").SaveX(ctx)
	s := &Service{DB: db}
	track := func(host, status string) (string, error) {
		return s.tool(ctx, session, commandgate.Request{System: true}, "track", []byte(
			`{"host":"`+host+`","key":"backup-failed","title":"备份服务失败","detail":"termix-backup-pull failed","severity":"medium","status":"`+status+`"}`))
	}
	get := func() string { return db.Finding.Query().OnlyX(ctx).Status }

	if out, err := track(host.ID.String(), "resolved"); err == nil {
		t.Fatalf("没有待办时标修复应报错：%s", out)
	}
	if out, err := track(host.ID.String(), "open"); err != nil || !strings.Contains(out, `"new":true`) {
		t.Fatalf("应新登记：%s %v", out, err)
	}
	if out, err := track(host.ID.String(), "open"); err != nil || !strings.Contains(out, `"reopened":false`) || db.Finding.Query().CountX(ctx) != 1 {
		t.Fatalf("同一问题应去重更新：%s %v", out, err)
	}
	if _, err := track(host.ID.String(), "resolved"); err != nil || get() != "resolved" {
		t.Fatalf("复查修复应关闭：%v %s", err, get())
	}
	if f := db.Finding.Query().OnlyX(ctx); f.ResolvedBy == nil || *f.ResolvedBy != commandgate.SystemActor {
		t.Errorf("AI 关闭应记 system：%+v", f)
	}
	if out, err := track(host.ID.String(), "open"); err != nil || !strings.Contains(out, `"reopened":true`) || get() != "open" {
		t.Fatalf("复发应重开：%s %v", out, err)
	}

	db.Finding.Update().SetStatus("ignored").SetNote("计划下线，不处理").ExecX(ctx)
	if out, err := track(host.ID.String(), "open"); err != nil || !strings.Contains(out, `"ignored"`) || !strings.Contains(out, "计划下线") {
		t.Fatalf("忽略的待办应原样告知：%s %v", out, err)
	}
	if _, err := track(host.ID.String(), "resolved"); err != nil || get() != "ignored" {
		t.Fatalf("AI 不能改动人工忽略的待办：%s", get())
	}
	if _, err := track(stranger.ID.String(), "open"); err == nil {
		t.Fatal("别组主机不能登记")
	}

	// 遗留与忽略的待办随系统提示交给模型
	db.Finding.Create().SetGroupID(group.ID).SetAssetID(host.ID).SetKey("disk-full").SetTitle("磁盘将满").SaveX(ctx)
	r, err := s.request(context.Background(), session, "巡检", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.SystemPrompt, `"open_findings":[{"host":"`+host.ID.String()+`","hostname":"pve2","key":"disk-full"`) ||
		!strings.Contains(r.SystemPrompt, `"ignored_findings":[{`) || !strings.Contains(r.SystemPrompt, "计划下线") {
		t.Errorf("待办数据缺失：%s", r.SystemPrompt)
	}
	if n := db.Finding.Query().Where(finding.StatusEQ("open")).CountX(ctx); n != 1 {
		t.Errorf("应只有一条遗留：%d", n)
	}
}
