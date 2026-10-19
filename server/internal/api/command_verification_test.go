package api

import (
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"openxdr/server/ent"
	"openxdr/server/internal/auth"
	"strings"
	"testing"
)

func TestVerificationRequestValidation(t *testing.T) {
	h := CommandVerifications(nil)
	path := "/api/commands/" + uuid.NewString() + "/verifications"
	for _, tc := range []struct {
		method, path, body string
		login              bool
		want               int
	}{
		{"GET", path, "", false, 401},
		{"GET", path + "/" + uuid.NewString(), "", false, 401},
		{"GET", path + "/bad", "", true, 400},
		{"GET", path + "/" + uuid.Nil.String(), "", true, 400},
		{"DELETE", path, "", true, 405},
		{"GET", "/api/commands/bad/verifications", "", true, 400},
		{"POST", path, `{"reviewer":"spoof"}`, true, 400},
		{"POST", path, `{} {}`, true, 400},
		{"POST", path, strings.Repeat("x", 17000), true, 400},
		{"POST", path, `{"outcome":"effective","expected":"check","observed":"yes"}`, true, 400},
	} {
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		if tc.login {
			r = r.WithContext(auth.WithUser(r.Context(), &ent.User{ID: uuid.New(), Role: "analyst"}))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s %s: %d want %d", tc.method, tc.path, w.Code, tc.want)
		}
		if tc.want == http.StatusMethodNotAllowed && w.Header().Get("Allow") == "" {
			t.Fatal("缺少 Allow")
		}
	}
}
