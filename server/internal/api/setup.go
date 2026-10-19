package api

import (
	"encoding/json"
	"net/http"
	"time"

	"openxdr/server/ent"
	"openxdr/server/ent/setting"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
)

// AgreementVersion 用户协议版本。协议文本改了就换版本号，管理员需要重新同意
const AgreementVersion = "2026-10-19"

const setupKey = "setup"

// setupState 安装初始化进度：管理员同意用户协议、走完（或跳过）首次引导
type setupState struct {
	AgreementVersion string     `json:"agreementVersion,omitempty"`
	AcceptedBy       string     `json:"acceptedBy,omitempty"`
	AcceptedAt       *time.Time `json:"acceptedAt,omitempty"`
	OnboardedAt      *time.Time `json:"onboardedAt,omitempty"`
}

// Setup 首次安装的用户协议与引导。读取对所有登录用户开放（非管理员据此显示等待提示），
// 同意协议与结束引导只有 admin 能做（门槛见 auth.minRole），都落审计。
func Setup(db *ent.Client) http.Handler {
	mux := http.NewServeMux()
	load := func(r *http.Request) (setupState, error) {
		var s setupState
		row, err := db.Setting.Get(r.Context(), setupKey)
		if ent.IsNotFound(err) {
			return s, nil
		}
		if err != nil {
			return s, err
		}
		return s, json.Unmarshal(row.Value, &s)
	}
	save := func(r *http.Request, s setupState) error {
		value, err := json.Marshal(s)
		if err != nil {
			return err
		}
		n, err := db.Setting.Update().Where(setting.IDEQ(setupKey)).SetValue(value).Save(r.Context())
		if err != nil || n > 0 {
			return err
		}
		return db.Setting.Create().SetID(setupKey).SetValue(value).Exec(r.Context())
	}

	mux.HandleFunc("GET /api/setup", func(w http.ResponseWriter, r *http.Request) {
		s, err := load(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// 已经有组或主机的实例（升级上来的）不再走首次引导，只补同意协议
		configured, err := db.Group.Query().Exist(r.Context())
		if err == nil && !configured {
			configured, err = db.Asset.Query().Exist(r.Context())
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{
			"agreementVersion": AgreementVersion,
			"accepted":         s.AgreementVersion == AgreementVersion,
			"acceptedBy":       s.AcceptedBy,
			"acceptedAt":       s.AcceptedAt,
			"onboarded":        s.OnboardedAt != nil || configured,
		})
	})

	mux.HandleFunc("POST /api/setup/agreement", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Version string `json:"version"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || body.Version != AgreementVersion {
			http.Error(w, "协议版本不符，请刷新后重新阅读", http.StatusConflict)
			return
		}
		s, err := load(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		now := time.Now()
		s.AgreementVersion, s.AcceptedBy, s.AcceptedAt = AgreementVersion, auth.From(r.Context()).Username, &now
		if err := save(r, s); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		audit.Log(r.Context(), db, r, "agreement_accepted", "setup", AgreementVersion)
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("POST /api/setup/onboarded", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Skipped []string `json:"skipped"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			http.Error(w, "请求体不是合法 JSON", http.StatusBadRequest)
			return
		}
		s, err := load(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if s.AgreementVersion != AgreementVersion {
			http.Error(w, "请先同意用户协议", http.StatusConflict)
			return
		}
		now := time.Now()
		s.OnboardedAt = &now
		if err := save(r, s); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		detail, _ := json.Marshal(map[string]any{"skipped": body.Skipped})
		audit.Log(r.Context(), db, r, "onboarding_finished", "setup", string(detail))
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}
