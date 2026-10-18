package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/hostcredential"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/enroll"
	"openxdr/server/internal/hostimport"
)

type credentialRow struct {
	ID       uuid.UUID `json:"id"`
	AssetID  uuid.UUID `json:"assetId"`
	Hostname string    `json:"hostname"`
	Address  string    `json:"address"`
	OS       string    `json:"os"`
	Port     int       `json:"port"`
	Username string    `json:"username"`
	Kind     string    `json:"kind"`
	HostKey  string    `json:"hostKey"`
}

// HostImports 的所有端点只对组 admin 开放。普通资产 API 与模型视图不接触凭据。
func HostImports(s *hostimport.Service, enroller *enroll.Service, publicURL string, sshEnabled bool) http.Handler {
	mux := http.NewServeMux()
	hostImportAI(mux, s)
	_, urlErr := hostimport.EnrollmentURL(publicURL)
	ready := sshEnabled && s.Vault != nil && urlErr == nil && enroller.CA != nil && strings.HasPrefix(enroller.GRPCURL, "https://") && enroller.Disabled() == ""
	mux.HandleFunc("GET /api/host-import/status", func(w http.ResponseWriter, r *http.Request) {
		// 这里只返回能力状态，任何登录用户可读，不含配置值或凭据。
		writeJSON(w, map[string]bool{"credentialStorage": s.Vault != nil, "sshEnrollment": ready, "aiParsing": (s.LLM != nil && s.LLM.Enabled()) || (s.VisionLLM != nil && s.VisionLLM.Enabled())})
	})
	for _, action := range []string{"preview", "commit"} {
		mux.HandleFunc("POST /api/host-import/"+action, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			var body struct {
				GroupID  uuid.UUID `json:"groupId"`
				Document string    `json:"document"`
				Digest   string    `json:"digest"`
			}
			if json.NewDecoder(http.MaxBytesReader(w, r.Body, 2*hostimport.MaxDocument)).Decode(&body) != nil {
				http.Error(w, "导入请求无效或过大", 400)
				return
			}
			if !requireGroup(w, r, s.DB, body.GroupID, "admin") {
				return
			}
			hosts, err := hostimport.Parse(body.Document)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			for _, h := range hosts {
				if h.Kind != "none" && s.Vault == nil {
					http.Error(w, "未配置 HOST_CREDENTIAL_KEY，不能导入含凭据的文档", 503)
					return
				}
			}
			digest := hostimport.Digest(body.Document)
			if action == "preview" {
				writeJSON(w, map[string]any{"digest": digest, "hosts": hosts})
				return
			}
			if body.Digest != digest {
				http.Error(w, "文档已变化，请重新预览后确认", 409)
				return
			}
			ids, err := s.Import(r.Context(), body.GroupID, hosts)
			if err != nil {
				http.Error(w, "导入未提交：凭据已存在、主机不属于所选组、组已删除或数据库操作失败；请核对后重新预览", 409)
				return
			}
			audit.Log(r.Context(), s.DB, r, "hosts_imported", body.GroupID.String(), fmt.Sprintf("导入 %d 台主机；原文与凭据不记录", len(ids)))
			w.WriteHeader(http.StatusCreated)
			writeJSON(w, map[string]any{"assetIds": ids})
		})
	}
	mux.HandleFunc("GET /api/host-import/credentials", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		groupID, err := uuid.Parse(r.URL.Query().Get("groupId"))
		if err != nil {
			http.Error(w, "groupId 必填", 400)
			return
		}
		if !requireGroup(w, r, s.DB, groupID, "admin") {
			return
		}
		rows, err := s.DB.HostCredential.Query().Where(hostcredential.GroupIDEQ(groupID)).Limit(1000).All(r.Context())
		if err != nil {
			http.Error(w, "读取凭据列表失败", 500)
			return
		}
		out := make([]credentialRow, 0, len(rows))
		for _, c := range rows {
			a, err := s.DB.Asset.Query().Where(asset.IDEQ(c.AssetID), asset.GroupIDEQ(groupID)).Only(r.Context())
			if ent.IsNotFound(err) {
				continue
			}
			if err != nil {
				http.Error(w, "读取资产失败", 500)
				return
			}
			osName := ""
			if a.Os != nil {
				osName = *a.Os
			}
			out = append(out, credentialRow{c.ID, c.AssetID, a.Hostname, c.Address, osName, c.Port, c.Username, c.Kind, c.HostKey})
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("DELETE /api/host-import/credentials/{id}", func(w http.ResponseWriter, r *http.Request) {
		c, ok := importCredential(w, r, s.DB)
		if !ok {
			return
		}
		n, err := s.DB.HostCredential.Delete().Where(hostcredential.IDEQ(c.ID), hostcredential.LeaseUntilLTE(time.Now())).Exec(r.Context())
		if err != nil {
			http.Error(w, "删除凭据失败", 500)
			return
		}
		if n != 1 {
			http.Error(w, "纳管操作进行中或凭据已删除", 409)
			return
		}
		audit.Log(r.Context(), s.DB, r, "host_credential_deleted", c.AssetID.String(), "")
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /api/host-import/credentials/{id}/enroll", func(w http.ResponseWriter, r *http.Request) {
		c, ok := importCredential(w, r, s.DB)
		if !ok {
			return
		}
		if !ready {
			http.Error(w, "SSH 纳管未启用；需要配置加密密钥、ENROLL_SSH_ENABLED、ENROLL_PUBLIC_URL 及 mTLS 在线接入", 503)
			return
		}
		var body struct {
			Fingerprint string `json:"fingerprint"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil || !hostimport.ValidFingerprint(body.Fingerprint) {
			http.Error(w, "须提供独立核对过的 SSH SHA256 主机指纹", 400)
			return
		}
		credentialID := c.ID
		lease := time.Now().Add(3 * time.Minute)
		n, err := s.DB.HostCredential.Update().Where(hostcredential.IDEQ(c.ID), hostcredential.LeaseUntilLT(time.Now())).SetLeaseUntil(lease).Save(r.Context())
		if err != nil || n != 1 {
			http.Error(w, "该主机已有纳管操作进行中", 409)
			return
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.DB.HostCredential.Update().Where(hostcredential.IDEQ(credentialID), hostcredential.LeaseUntilEQ(lease)).SetLeaseUntil(time.Unix(0, 0)).Exec(ctx)
		}()
		c, secret, err := s.Credential(r.Context(), c.ID, c.GroupID)
		if err != nil {
			http.Error(w, "凭据不可用或资产已移组", 409)
			return
		}
		a, err := s.DB.Asset.Get(r.Context(), c.AssetID)
		if err != nil {
			http.Error(w, "资产不存在", 409)
			return
		}
		osName := "linux"
		if a.Os != nil {
			osName = *a.Os
		}
		plain, tok, err := enroller.Issue(r.Context(), c.GroupID, auth.From(r.Context()).Username, 5*time.Minute)
		if err != nil {
			http.Error(w, "签发接入令牌失败", 500)
			return
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.DB.EnrollToken.UpdateOneID(tok.ID).SetRevoked(true).Exec(ctx)
		}()
		audit.Log(r.Context(), s.DB, r, "host_enrollment_started", a.ID.String(), "使用已保存凭据进行 SSH 纳管")
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		err = hostimport.Install(ctx, c, secret, a.Hostname, osName, publicURL, plain, enroll.InstallScript(osName), body.Fingerprint)
		auditCtx, auditCancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
		defer auditCancel()
		if err != nil {
			audit.Log(auditCtx, s.DB, r, "host_enrollment_unconfirmed", a.ID.String(), err.Error())
			http.Error(w, err.Error(), 502)
			return
		}
		audit.Log(auditCtx, s.DB, r, "host_enrollment_installed", a.ID.String(), "安装脚本完成，待 Agent 心跳确认")
		writeJSON(w, map[string]string{"status": "installed", "message": "安装脚本完成，待 Agent 注册与心跳确认"})
	})
	return mux
}

func importCredential(w http.ResponseWriter, r *http.Request, db *ent.Client) (*ent.HostCredential, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return nil, false
	}
	c, err := db.HostCredential.Get(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return nil, false
	}
	if !requireGroup(w, r, db, c.GroupID, "admin") {
		return nil, false
	}
	return c, true
}
