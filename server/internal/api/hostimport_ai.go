package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"openxdr/server/internal/aijob"
	"openxdr/server/internal/audit"
	"openxdr/server/internal/auth"
	"openxdr/server/internal/hostimport"
)

func hostImportAI(mux *http.ServeMux, s *hostimport.Service) {
	// 文件转换与模型调用有界并发，避免大文档占满服务进程。
	slots := make(chan struct{}, 2)
	run := func(w http.ResponseWriter, r *http.Request, fn func(context.Context)) {
		w.Header().Set("Cache-Control", "no-store")
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "文档解析繁忙，请稍后重试", 429)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
		defer cancel()
		fn(ctx)
	}
	mux.HandleFunc("POST /api/host-import/extract", func(w http.ResponseWriter, r *http.Request) {
		run(w, r, func(ctx context.Context) {
			r.Body = http.MaxBytesReader(w, r.Body, hostimport.MaxUpload+(1<<20))
			if err := r.ParseMultipartForm(hostimport.MaxUpload); err != nil {
				http.Error(w, "文件上传无效或超过 20 MiB", 400)
				return
			}
			if r.MultipartForm != nil {
				defer r.MultipartForm.RemoveAll()
			}
			groupID, err := uuid.Parse(r.FormValue("groupId"))
			if err != nil {
				http.Error(w, "groupId 必填", 400)
				return
			}
			if !requireGroup(w, r, s.DB, groupID, "admin") {
				return
			}
			file, header, err := r.FormFile("file")
			if err != nil {
				http.Error(w, "请选择文档", 400)
				return
			}
			defer file.Close()
			data, err := io.ReadAll(io.LimitReader(file, hostimport.MaxUpload+1))
			if err != nil {
				http.Error(w, "文件读取失败", 400)
				return
			}
			defer clear(data)
			text, err := hostimport.PrepareDocument(ctx, header.Filename, data)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			writeJSON(w, text)
		})
	})
	// AI 提取在后台跑：POST 发起后立即返回，GET 读这个组里自己最近一次；关掉弹窗、换页、刷新都能接着看结果。
	// 文档原文只在内存里交给模型，库里只存提取结果（凭据是封存令牌，只有发起人在本组能用），一小时后清掉
	analyzeKey := func(r *http.Request, group string) aijob.Key {
		return aijob.Key{Kind: "host_import", Subject: group, Owner: auth.From(r.Context()).ID.String()}
	}
	mux.HandleFunc("GET /api/host-import/analyze", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		groupID, err := uuid.Parse(r.URL.Query().Get("groupId"))
		if err != nil {
			http.Error(w, "groupId 必填", 400)
			return
		}
		if !requireGroup(w, r, s.DB, groupID, "admin") {
			return
		}
		j, err := aijob.Latest(r.Context(), s.DB, analyzeKey(r, groupID.String()))
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, aijob.ViewOf(j))
	})
	mux.HandleFunc("DELETE /api/host-import/analyze", func(w http.ResponseWriter, r *http.Request) {
		groupID, err := uuid.Parse(r.URL.Query().Get("groupId"))
		if err != nil {
			http.Error(w, "groupId 必填", 400)
			return
		}
		if !requireGroup(w, r, s.DB, groupID, "admin") {
			return
		}
		if err := aijob.Discard(r.Context(), s.DB, analyzeKey(r, groupID.String())); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/host-import/analyze", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		var body struct {
			GroupID  uuid.UUID                  `json:"groupId"`
			Document string                     `json:"document"`
			Images   []hostimport.DocumentImage `json:"images"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 40*hostimport.MaxDocument)).Decode(&body) != nil {
			http.Error(w, "导入请求无效或过大", 400)
			return
		}
		if !requireGroup(w, r, s.DB, body.GroupID, "admin") {
			return
		}
		if (s.LLM == nil || !s.LLM.Enabled()) && (s.VisionLLM == nil || !s.VisionLLM.Enabled()) {
			http.Error(w, "AI 文档解析未配置，请设置 AI_MODEL 或 PI_MODEL", 503)
			return
		}
		doc := hostimport.Document{Text: body.Document, Images: body.Images}
		if err := doc.Validate(); err != nil {
			http.Error(w, err.Error(), 422)
			return
		}
		k := analyzeKey(r, body.GroupID.String())
		if prev, err := aijob.Latest(r.Context(), s.DB, k); err == nil && aijob.Running(prev) {
			http.Error(w, "这个组已有一份文档在解析，等它完成后再提交", 409)
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			http.Error(w, "文档解析繁忙，请稍后重试", 429)
			return
		}
		actor, group := k.Owner, k.Subject
		j, err := aijob.Start(r.Context(), s.DB, k, func(ctx context.Context) (any, error) {
			return s.AnalyzeDocument(ctx, doc, actor, group)
		}, func() { <-slots })
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, aijob.ViewOf(j))
	})
	mux.HandleFunc("POST /api/host-import/confirm", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		var body struct {
			GroupID   uuid.UUID               `json:"groupId"`
			Hosts     []hostimport.ReviewHost `json:"hosts"`
			Confirmed bool                    `json:"confirmed"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 6*hostimport.MaxDocument)).Decode(&body) != nil {
			http.Error(w, "确认请求无效或过大", 400)
			return
		}
		if !requireGroup(w, r, s.DB, body.GroupID, "admin") {
			return
		}
		if !body.Confirmed {
			http.Error(w, "请先核对主机字段与凭据关联", 400)
			return
		}
		hosts, err := s.ConfirmHosts(body.Hosts, auth.From(r.Context()).ID.String(), body.GroupID.String())
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		ids, err := s.Import(r.Context(), body.GroupID, hosts)
		if err != nil {
			http.Error(w, "导入未提交：主机或凭据冲突，请核对组归属及已有资产后重试", 409)
			return
		}
		// 导入完成，提取结果里的凭据令牌不再需要
		if err := aijob.Discard(r.Context(), s.DB, analyzeKey(r, body.GroupID.String())); err != nil {
			slog.Warn("清理导入提取结果失败", "err", err)
		}
		audit.Log(r.Context(), s.DB, r, "hosts_imported", body.GroupID.String(), fmt.Sprintf("人工确认 AI 提取结果，导入 %d 台主机；原文与凭据不记录", len(ids)))
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"assetIds": ids})
	})
}
