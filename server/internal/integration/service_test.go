package integration

import (
	"github.com/google/uuid"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCursorBindingAndTampering(t *testing.T) {
	s := &Service{CursorKey: []byte(strings.Repeat("a", 32))}
	id := uuid.New()
	value := s.signCursor(cursor{id, "authorized", time.Now().Add(time.Hour).Unix()})
	if got, err := s.parseCursor(value, "authorized"); err != nil || got != id {
		t.Fatal("有效游标被拒绝", err)
	}
	for _, c := range []struct{ v, b string }{{value, "other"}, {"x" + value, "authorized"}, {s.signCursor(cursor{id, "authorized", 1}), "authorized"}} {
		if _, err := s.parseCursor(c.v, c.b); err == nil {
			t.Fatal("无效游标被接受")
		}
	}
}
func TestIntegrationScopeAndRateLimits(t *testing.T) {
	if ValidScopes(nil) || ValidScopes([]string{"admin"}) || ValidScopes([]string{"assets:read", "assets:read"}) {
		t.Fatal("无效 scope")
	}
	s := &Service{}
	id := uuid.New()
	for range 20 {
		if !s.allow(id) {
			t.Fatal("突发额度错误")
		}
	}
	if s.allow(id) {
		t.Fatal("未限流")
	}
	if !s.allow(uuid.New()) {
		t.Fatal("不同身份共享额度")
	}
}

func TestHandlerWithoutMasterKey(t *testing.T) {
	w := httptest.NewRecorder()
	(&Service{}).Handler().ServeHTTP(w, httptest.NewRequest("GET", "/api/integration/v1/assets", nil))
	if w.Code != 503 || !strings.Contains(w.Body.String(), "HOST_CREDENTIAL_KEY") {
		t.Fatal("没配主密钥应明确 503", w.Code, w.Body.String())
	}
}
