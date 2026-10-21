//go:build integration

package integration

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"openxdr/server/internal/suricata"
	"openxdr/server/internal/testdb"
)

// Suricata 写入走集成 Token：需要 suricata:write 且恰好一个授权组，来源组与探针身份只取自集成本身。
func TestSuricataEventsEndpoint(t *testing.T) {
	ctx, db := testdb.New(t)
	owner := db.User.Create().SetUsername("owner").SetPasswordHash("x").SetRole("admin").SaveX(ctx)
	g := db.Group.Create().SetName("A").SaveX(ctx)
	i := db.Integration.Create().SetName("edge-a").SetPurpose("test").SetOwnerID(owner.ID).SetEnabled(true).SetScopes([]string{"suricata:write", "assets:read"}).SaveX(ctx)
	db.IntegrationGroup.Create().SetIntegrationID(i.ID).SetGroupID(g.ID).SaveX(ctx)
	token := func(name string, scopes ...string) string {
		plain := "oxi_" + name + strings.Repeat("x", 40)
		db.IntegrationToken.Create().SetIntegrationID(i.ID).SetPrefix("oxi_" + name).SetTokenHash(TokenHash(plain)).SetScopes(scopes).SetExpiresAt(time.Now().Add(time.Hour)).SaveX(ctx)
		return plain
	}
	writer, reader := token("w", "suricata:write"), token("r", "assets:read")
	var got []suricata.Origin
	h := (&Service{DB: db, Enabled: true, CursorKey: []byte(strings.Repeat("s", 32)), Suricata: func(_ context.Context, origin suricata.Origin, _ suricata.Event) error {
		got = append(got, origin)
		return nil
	}}).Handler()
	alert := `{"timestamp":"2026-10-21T10:20:30+0800","event_type":"alert","src_ip":"198.51.100.2","src_port":1,"dest_ip":"10.0.0.2","dest_port":80,"proto":"TCP","alert":{"gid":1,"signature_id":7,"rev":1,"signature":"受控测试","severity":2},"metadata":{"group_id":"` + uuid.NewString() + `"}}`
	post := func(plain string) int {
		r := httptest.NewRequest("POST", "/api/integration/v1/suricata/events", strings.NewReader(alert))
		r.Header.Set("Authorization", "Bearer "+plain)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := post(reader); code != 403 {
		t.Fatalf("缺 suricata:write 的令牌不能写入: %d", code)
	}
	// 持续告警流不受人工调用的限流约束
	for n := range 50 {
		if code := post(writer); code != 202 {
			t.Fatalf("第 %d 条写入失败: %d", n, code)
		}
	}
	if len(got) != 50 || got[0].GroupID != g.ID || got[0].Observer != i.ID.String() {
		t.Fatalf("来源不是集成本身: %+v", got[0])
	}
	db.IntegrationGroup.Create().SetIntegrationID(i.ID).SetGroupID(db.Group.Create().SetName("B").SaveX(ctx).ID).SaveX(ctx)
	if code := post(writer); code != 403 {
		t.Fatalf("多组授权时无从判断归属，应拒绝: %d", code)
	}
}
