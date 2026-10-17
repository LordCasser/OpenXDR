//go:build integration

package hostimport

import (
	"encoding/base64"
	"strings"
	"testing"

	"openxdr/server/internal/testdb"
)

func TestImportTransactionAndCredentialScope(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("import-test").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	vault, _ := NewVault(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	svc := &Service{DB: db, Vault: vault}
	hosts, err := Parse("hosts:\n - hostname: app-01\n   address: 192.0.2.1\n   username: root\n   password: test-secret\n")
	if err != nil {
		t.Fatal(err)
	}
	ids, err := svc.Import(ctx, group.ID, hosts)
	if err != nil {
		t.Fatal(err)
	}
	a := db.Asset.GetX(ctx, ids[0])
	if a.AgentID != nil || a.LastSeen.Unix() != 0 {
		t.Fatal("导入被误记为在线 Agent")
	}
	c := db.HostCredential.Query().OnlyX(ctx)
	if strings.Contains(string(c.Sealed), "test-secret") {
		t.Fatal("数据库保存了明文")
	}
	if _, secret, err := svc.Credential(ctx, c.ID, group.ID); err != nil || secret.Password != "test-secret" {
		t.Fatal("合法组无法取用凭据")
	}
	if _, _, err := svc.Credential(ctx, c.ID, other.ID); err == nil {
		t.Fatal("跨组读取了凭据")
	}
	// 整批中的第二条冲突时，第一条也不能留下。
	duplicate := hosts[0]
	duplicate.Hostname = "new-before-conflict"
	if _, err := svc.Import(ctx, group.ID, []Host{duplicate, hosts[0]}); err == nil {
		t.Fatal("重复导入未拒绝")
	}
	if db.Asset.Query().CountX(ctx) != 1 || db.HostCredential.Query().CountX(ctx) != 1 {
		t.Fatal("失败批次留下部分数据")
	}
	// 删除凭据后，同组原资产可重新关联凭据，资产 ID 和字段保持不变。
	db.HostCredential.DeleteOne(c).ExecX(ctx)
	reimported, err := svc.Import(ctx, group.ID, hosts)
	if err != nil || reimported[0] != a.ID || db.Asset.Query().CountX(ctx) != 1 {
		t.Fatal("同组资产无法补录凭据")
	}
	c = db.HostCredential.Query().OnlyX(ctx)
	db.Asset.UpdateOne(a).SetGroupID(other.ID).ExecX(ctx)
	if _, _, err := svc.Credential(ctx, c.ID, group.ID); err == nil {
		t.Fatal("移组后原组仍可使用凭据")
	}
}
