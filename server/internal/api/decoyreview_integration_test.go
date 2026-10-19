//go:build integration

package api

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"openxdr/server/ent"
	"openxdr/server/ent/auditlog"
	entincident "openxdr/server/ent/incident"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/review"
	"openxdr/server/internal/testdb"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDecoyReviewPermissionsAtomicityAndIdempotency(t *testing.T) {
	ctx, db := testdb.New(t)
	g := db.Group.Create().SetName("review").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	host := db.Asset.Create().SetHostname("host").SetGroupID(g.ID).SaveX(ctx)
	user := db.User.Create().SetUsername("analyst").SetRole("analyst").SetPasswordHash("x").SaveX(ctx)
	viewer := db.User.Create().SetUsername("viewer").SetRole("viewer").SetPasswordHash("x").SaveX(ctx)
	db.GroupMember.Create().SetUserID(user.ID).SetGroupID(g.ID).SetRole("analyst").ExecX(ctx)
	db.GroupMember.Create().SetUserID(viewer.ID).SetGroupID(g.ID).SetRole("viewer").ExecX(ctx)
	deployment := db.DecoyDeployment.Create().SetAssetID(host.ID).SetPort(8088).SetProfile("decoy").SetTemplate("http-decoy-v1").SetCreatedBy("admin").SaveX(ctx)
	observation := db.DecoyObservation.Create().SetID(uuid.New()).SetDeploymentID(deployment.ID).SetKind("marker_used").SaveX(ctx)
	lifecycle := db.DecoyObservation.Create().SetID(uuid.New()).SetDeploymentID(deployment.ID).SetKind("file_installed").SaveX(ctx)
	mux := http.NewServeMux()
	mapSSHDecoys(mux, db)
	request := func(u *ent.User, id uuid.UUID) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/api/decoys/"+deployment.ID.String()+"/observations/"+id.String()+"/review", nil)
		r = r.WithContext(auth.WithUser(r.Context(), u))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := request(viewer, observation.ID); w.Code != 403 {
		t.Fatalf("viewer: %d", w.Code)
	}
	if w := request(user, lifecycle.ID); w.Code != 400 {
		t.Fatalf("生命周期事件: %d", w.Code)
	}
	var failAudit atomic.Bool
	failAudit.Store(true)
	db.AuditLog.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			if failAudit.Load() {
				return nil, errors.New("测试审计失败")
			}
			return next.Mutate(ctx, m)
		})
	})
	if w := request(user, observation.ID); w.Code != 500 {
		t.Fatalf("审计失败: %d", w.Code)
	}
	if db.Event.Query().CountX(ctx) != 0 || db.Incident.Query().CountX(ctx) != 0 || db.Alert.Query().CountX(ctx) != 0 || db.DecoyObservation.GetX(ctx, observation.ID).IncidentID != nil {
		t.Fatal("事务未回滚")
	}
	failAudit.Store(false)
	var wg sync.WaitGroup
	responses := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		wg.Go(func() { responses <- request(user, observation.ID) })
	}
	wg.Wait()
	close(responses)
	var incidentID string
	codes := map[int]int{}
	for w := range responses {
		codes[w.Code]++
		var result struct {
			IncidentID string `json:"incidentId"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(w.Code, w.Body)
		}
		if incidentID != "" && result.IncidentID != incidentID {
			t.Fatal("重复创建")
		}
		incidentID = result.IncidentID
	}
	if codes[201] != 1 || codes[200] != 1 {
		t.Fatal(codes)
	}
	if db.Incident.Query().CountX(ctx) != 1 || db.Event.Query().CountX(ctx) != 1 || db.Alert.Query().CountX(ctx) != 1 {
		t.Fatal("复核实体重复")
	}
	incident := db.Incident.Query().OnlyX(ctx)
	if incident.NotifiedAt != nil || len(incident.AiVerdict) != 0 || incident.Status != "open" {
		t.Fatal("通知或研判状态错误")
	}
	// 只有诱饵观察不推送；AI 判良性仍要人看，也不会被自动结案。
	db.Incident.UpdateOneID(incident.ID).SetAiVerdict(json.RawMessage(`{"verdict":"benign"}`)).ExecX(ctx)
	if !db.Incident.Query().Where(entincident.IDEQ(incident.ID), review.DecoyOnly(), review.Needed()).ExistX(ctx) || db.Incident.Query().Where(review.StaleBenign(time.Now().Add(time.Hour))).ExistX(ctx) {
		t.Fatal("诱饵复核口径错误")
	}
	evidence := db.Event.Query().OnlyX(ctx)
	if evidence.Source != "decoy" || !strings.Contains(string(evidence.Raw), "unconfirmed") {
		t.Fatal("归因证据错误")
	}
	if db.AuditLog.Query().Where(auditlog.ActionEQ("decoy_observation_review_requested")).CountX(ctx) != 1 {
		t.Fatal("审计重复")
	}
	db.Asset.UpdateOneID(host.ID).SetGroupID(other.ID).ExecX(ctx)
	if w := request(user, observation.ID); w.Code != 403 {
		t.Fatal("迁组后仍可提交", w.Code)
	}
}
