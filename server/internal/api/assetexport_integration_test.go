//go:build integration

package api

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"openxdr/server/internal/testdb"
)

func TestAssetExportScopeAndFilters(t *testing.T) {
	ctx, db := testdb.New(t)
	ga := db.Group.Create().SetName("A").SaveX(ctx)
	gb := db.Group.Create().SetName("B").SaveX(ctx)
	own := db.Asset.Create().SetHostname("WEB-中文").SetIPAddrs([]string{"10.12.13.14"}).SetGroupID(ga.ID).SaveX(ctx)
	other := db.Asset.Create().SetHostname("private").SetGroupID(gb.ID).SaveX(ctx)
	db.Asset.Create().SetHostname("loose").SaveX(ctx)
	viewer := db.User.Create().SetUsername("export-viewer").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	db.GroupMember.Create().SetGroupID(ga.ID).SetUserID(viewer.ID).SetRole("viewer").SaveX(ctx)
	h := as(viewer, exportAssets(db))
	for _, tc := range []struct {
		selection   assetSelection
		code, count int
	}{
		{assetSelection{Mode: "filter"}, 200, 1},
		{assetSelection{Mode: "filter", Q: "web"}, 200, 1},
		{assetSelection{Mode: "filter", Q: "12.13"}, 200, 1},
		{assetSelection{Mode: "filter", Q: "absent"}, 200, 0},
		{assetSelection{Mode: "filter", GroupID: "ungrouped"}, 200, 0},
		{assetSelection{Mode: "ids", IDs: []uuid.UUID{own.ID, other.ID}}, 404, 0},
	} {
		body, _ := json.Marshal(map[string]any{"format": "json", "selection": tc.selection})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/api/assets/export", bytes.NewReader(body)))
		if w.Code != tc.code {
			t.Fatalf("%+v: %d %s", tc.selection, w.Code, w.Body.String())
		}
		if tc.code != 200 {
			if w.Header().Get("Content-Disposition") != "" {
				t.Fatal("错误附带附件头")
			}
			continue
		}
		var data struct {
			Items []assetExportRow `json:"items"`
			Count int              `json:"count"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
			t.Fatal(err)
		}
		if data.Count != tc.count || len(data.Items) != tc.count {
			t.Fatalf("unexpected count: %+v", data)
		}
		if bytes.Contains(w.Body.Bytes(), []byte("collectorHealth")) {
			t.Fatal("泄漏白名单以外字段")
		}
	}
	if n := db.AuditLog.Query().CountX(ctx); n != 5 {
		t.Fatalf("审计数量 %d", n)
	}
}
