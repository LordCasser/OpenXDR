package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
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
	mux.HandleFunc("POST /api/host-import/analyze", func(w http.ResponseWriter, r *http.Request) {
		run(w, r, func(ctx context.Context) {
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
			analysis, err := s.AnalyzeDocument(ctx, hostimport.Document{Text: body.Document, Images: body.Images}, auth.From(r.Context()).ID.String(), body.GroupID.String())
			if err != nil {
				http.Error(w, err.Error(), 422)
				return
			}
			writeJSON(w, analysis)
		})
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
		audit.Log(r.Context(), s.DB, r, "hosts_imported", body.GroupID.String(), fmt.Sprintf("人工确认 AI 提取结果，导入 %d 台主机；原文与凭据不记录", len(ids)))
		w.WriteHeader(http.StatusCreated)
		writeJSON(w, map[string]any{"assetIds": ids})
	})
}
