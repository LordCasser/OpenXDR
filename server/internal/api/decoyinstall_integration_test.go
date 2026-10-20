//go:build integration

package api

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/decoydeployment"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/hostimport"
	"openxdr/server/internal/testdb"
)

func TestDecoyInstallAccessAndLifecycle(t *testing.T) {
	ctx, db := testdb.New(t)
	group := db.Group.Create().SetName("install").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	vault, _ := hostimport.NewVault(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	svc := &hostimport.Service{DB: db, Vault: vault}
	hosts, err := hostimport.Parse("hosts:\n - hostname: install-host\n   os: linux\n   address: 192.0.2.1\n   username: root\n   password: install-test-secret\n")
	if err != nil {
		t.Fatal(err)
	}
	ids, err := svc.Import(ctx, group.ID, hosts)
	if err != nil {
		t.Fatal(err)
	}
	db.Asset.UpdateOneID(ids[0]).SetOs("linux").ExecX(ctx)
	create := func(port int) *ent.DecoyDeployment {
		return db.DecoyDeployment.Create().SetAssetID(ids[0]).SetKind(decoydeployment.KindHTTP).SetProfile("decoy").SetTemplate("http-decoy-v1").SetPort(port).SetCreatedBy("test").SaveX(ctx)
	}
	row := create(8088)
	dir := t.TempDir()
	data := make([]byte, 64)
	copy(data, []byte{127, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(data[16:], 2)
	binary.LittleEndian.PutUint16(data[18:], 62)
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint16(data[52:], 64)
	if err := os.WriteFile(filepath.Join(dir, "decoyhost-linux-amd64"), data, 0600); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	fail, preflight := false, false
	var token string
	cfg := DecoyInstallConfig{Enabled: true, PublicURL: "https://aidr.internal", DistDir: dir, install: func(_ context.Context, c *ent.HostCredential, secret hostimport.Secret, hostname, osName, url, plain, script, fp string) error {
		calls.Add(1)
		token = plain
		if secret.Password != "install-test-secret" || c.AssetID != ids[0] || hostname != "install-host" || osName != "linux" || !strings.Contains(script, "sha256sum -c") {
			t.Fatal("invalid dispatch")
		}
		if preflight {
			return fmt.Errorf("simulated refused connection: %w", hostimport.ErrNotStarted)
		}
		if fail {
			return errors.New("simulated interruption")
		}
		return nil
	}}
	h := DecoyInstalls(svc, cfg)
	admin := db.User.Create().SetUsername("admin").SetPasswordHash("unused").SetRole("admin").SaveX(ctx)
	analyst := db.User.Create().SetUsername("analyst").SetPasswordHash("unused").SetRole("analyst").SaveX(ctx)
	db.GroupMember.Create().SetGroupID(other.ID).SetUserID(analyst.ID).SetRole("admin").ExecX(ctx)
	body := map[string]string{"fingerprint": "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)), "arch": "amd64", "listenHost": "127.0.0.1"}
	request := func(handler http.Handler, user *ent.User, id string) *httptest.ResponseRecorder {
		t.Helper()
		b, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "/api/decoy-install/"+id, strings.NewReader(string(b)))
		if user != nil {
			r = r.WithContext(auth.WithUser(r.Context(), user))
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	for _, u := range []*ent.User{nil, analyst} {
		if w := request(h, u, row.ID.String()); w.Code != 401 && w.Code != 403 {
			t.Fatalf("unauthorized: %d", w.Code)
		}
	}
	disabled := cfg
	disabled.Enabled = false
	if w := request(DecoyInstalls(svc, disabled), admin, row.ID.String()); w.Code != 503 {
		t.Fatalf("disabled: %d", w.Code)
	}
	if calls.Load() != 0 {
		t.Fatal("unauthorized dispatch")
	}

	var failAudit atomic.Bool
	failAudit.Store(true)
	db.AuditLog.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			if failAudit.Load() {
				return nil, errors.New("audit unavailable")
			}
			return next.Mutate(ctx, m)
		})
	})
	if w := request(h, admin, row.ID.String()); w.Code != 500 || calls.Load() != 0 {
		t.Fatal("audit failure dispatched")
	}
	if got := db.DecoyDeployment.GetX(ctx, row.ID); got.InstallState != decoydeployment.InstallStateIdle || got.TokenHash != "" {
		t.Fatal("start transaction did not roll back")
	}
	failAudit.Store(false)
	if w := request(h, admin, row.ID.String()); w.Code != 200 {
		t.Fatalf("install: %d %s", w.Code, w.Body)
	}
	current := db.DecoyDeployment.GetX(ctx, row.ID)
	if current.InstallState != decoydeployment.InstallStateInstalled || current.TokenHash != decoyTokenHash(token) || current.RuntimeInstanceID != nil {
		t.Fatal("installation confused with online state")
	}
	if w := request(h, admin, row.ID.String()); w.Code != 409 || calls.Load() != 1 {
		t.Fatal("repeat dispatched")
	}
	for _, a := range db.AuditLog.Query().AllX(ctx) {
		if a.Detail != nil && (strings.Contains(*a.Detail, token) || strings.Contains(*a.Detail, "install-test-secret")) {
			t.Fatal("audit leaked secret")
		}
	}
	row = create(8089)
	fail = true
	if w := request(h, admin, row.ID.String()); w.Code != 502 {
		t.Fatalf("failure: %d", w.Code)
	}
	if db.DecoyDeployment.GetX(ctx, row.ID).InstallState != decoydeployment.InstallStateUnconfirmed {
		t.Fatal("failure lost")
	}
	if w := request(h, admin, row.ID.String()); w.Code != 409 || calls.Load() != 2 {
		t.Fatal("uncertain retry dispatched")
	}
	row = create(8090)
	credential := db.HostCredential.Query().OnlyX(ctx)
	db.HostCredential.UpdateOneID(credential.ID).SetLeaseUntil(time.Now().Add(time.Minute)).ExecX(ctx)
	if w := request(h, admin, row.ID.String()); w.Code != 409 || calls.Load() != 2 {
		t.Fatal("credential lease bypassed")
	}
	db.HostCredential.UpdateOneID(credential.ID).SetLeaseUntil(time.Unix(0, 0)).ExecX(ctx)

	fail = false
	var wg sync.WaitGroup
	results := make(chan int, 2)
	for range 2 {
		wg.Go(func() { results <- request(h, admin, row.ID.String()).Code })
	}
	wg.Wait()
	close(results)
	successes := 0
	for code := range results {
		if code == 200 {
			successes++
		} else if code != 409 {
			t.Fatalf("concurrent install: %d", code)
		}
	}
	if successes != 1 || calls.Load() != 3 {
		t.Fatal("duplicate concurrent dispatch")
	}
	// 脚本开始前失败没有远端副作用：退回全新登记，令牌作废，修正后可重试。
	row = create(8092)
	preflight = true
	if w := request(h, admin, row.ID.String()); w.Code != 409 || calls.Load() != 4 {
		t.Fatalf("preflight failure: %d", w.Code)
	}
	if got := db.DecoyDeployment.GetX(ctx, row.ID); got.InstallState != decoydeployment.InstallStateIdle || got.TokenHash != "" || got.Marker != "" || got.TokenExpiresAt != nil {
		t.Fatal("preflight failure left install state")
	}
	preflight = false
	if w := request(h, admin, row.ID.String()); w.Code != 200 || calls.Load() != 5 {
		t.Fatalf("retry after preflight failure: %d", w.Code)
	}
	row = create(8091)
	db.Asset.UpdateOneID(ids[0]).SetGroupID(other.ID).ExecX(ctx)
	if w := request(h, admin, row.ID.String()); w.Code != 409 || calls.Load() != 5 {
		t.Fatal("moved asset used old credential")
	}
}
