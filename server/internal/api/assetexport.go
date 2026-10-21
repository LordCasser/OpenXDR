package api

import (
	"bytes"
	"context"
	stdsql "database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/asset"
	"openxdr/server/ent/group"
	"openxdr/server/internal/audit"
)

const assetExportMax = 10000
const assetExportBytes = 32 << 20

var errExportSelectionLimit = errors.New("导出超过 10000 条，请缩小选择范围")

type assetSelection struct {
	Mode    string      `json:"mode"`
	Q       string      `json:"q,omitempty"`
	GroupID string      `json:"groupId,omitempty"`
	IDs     []uuid.UUID `json:"ids,omitempty"`
}

type assetExportRow struct {
	ID            uuid.UUID  `json:"id"`
	Hostname      string     `json:"hostname"`
	OS            *string    `json:"os"`
	OSDisplay     *string    `json:"osDisplay"`
	IPAddrs       []string   `json:"ipAddrs"`
	GroupID       *uuid.UUID `json:"groupId"`
	GroupName     *string    `json:"groupName"`
	AgentID       *uuid.UUID `json:"agentId"`
	AgentVersion  *string    `json:"agentVersion"`
	SensorVersion *string    `json:"sensorVersion"`
	FirstSeen     time.Time  `json:"firstSeen"`
	LastSeen      time.Time  `json:"lastSeen"`
	SensorSeen    *time.Time `json:"sensorSeen"`
	HostState     string     `json:"hostState"`
}

func exportedHostState(a *ent.Asset, now time.Time) string {
	if a.AgentID == nil && a.SensorSeen == nil && a.LastSeen.Equal(time.Unix(0, 0)) {
		return "imported"
	}
	if a.SilentSince != nil {
		return "silent"
	}
	seen := a.LastSeen
	if a.AgentID == nil && a.SensorSeen != nil {
		seen = *a.SensorSeen
	}
	if now.Sub(seen) < 5*time.Minute {
		return "online"
	}
	return "stale"
}

func (s *assetSelection) validate() error {
	switch s.Mode {
	case "filter":
		if len(s.IDs) != 0 {
			return errors.New("筛选模式不能指定资产 ID")
		}
		if s.GroupID != "" && s.GroupID != "ungrouped" {
			if _, err := uuid.Parse(s.GroupID); err != nil {
				return errors.New("无效的组 ID")
			}
		}
	case "ids":
		slices.SortFunc(s.IDs, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
		s.IDs = slices.Compact(s.IDs)
		if len(s.IDs) > assetExportMax {
			return errExportSelectionLimit
		}
		if len(s.IDs) == 0 || s.Q != "" || s.GroupID != "" {
			return errors.New("勾选模式须指定 1–10000 个资产，不能混用筛选条件")
		}
	default:
		return errors.New("选择模式必须是 filter 或 ids")
	}
	return nil
}

func exportAssets(db *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		requestID := uuid.NewString()
		w.Header().Set("X-Request-ID", requestID)
		var body struct {
			Format    string         `json:"format"`
			Selection assetSelection `json:"selection"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&body); err != nil {
			http.Error(w, "导出请求无效或过大", 400)
			return
		}
		if dec.Decode(new(any)) != io.EOF {
			http.Error(w, "请求只能包含一个 JSON 对象", 400)
			return
		}
		if body.Format != "csv" && body.Format != "json" {
			http.Error(w, "格式必须是 csv 或 json", 400)
			return
		}
		if err := body.Selection.validate(); err != nil {
			code := 400
			if errors.Is(err, errExportSelectionLimit) {
				code = 422
			}
			http.Error(w, err.Error(), code)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		tx, err := db.BeginTx(ctx, &stdsql.TxOptions{Isolation: stdsql.LevelRepeatableRead})
		if err != nil {
			http.Error(w, "无法开始导出", 500)
			return
		}
		defer tx.Rollback()
		s, err := scopeOf(ctx, tx.Client(), "viewer")
		if err != nil {
			http.Error(w, "无法检查导出权限", 500)
			return
		}
		q := tx.Asset.Query().Where(s.asset()...).Order(ent.Asc(asset.FieldID)).Limit(assetExportMax + 1)
		sel := body.Selection
		if sel.Mode == "ids" {
			q.Where(asset.IDIn(sel.IDs...))
		}
		if sel.Q != "" {
			q.Where(asset.Or(asset.HostnameContainsFold(sel.Q), func(s *sql.Selector) {
				s.Where(sql.P().Append(func(b *sql.Builder) {
					b.WriteString("EXISTS (SELECT 1 FROM jsonb_array_elements_text(").Ident(s.C(asset.FieldIPAddrs)).WriteString(") AS ip(value) WHERE strpos(ip.value, ").Arg(sel.Q).WriteString(") > 0)")
				}))
			}))
		}
		if sel.GroupID == "ungrouped" {
			q.Where(asset.GroupIDIsNil())
		} else if sel.GroupID != "" {
			id, _ := uuid.Parse(sel.GroupID)
			q.Where(asset.GroupIDEQ(id))
		}
		rows, err := q.All(ctx)
		if err != nil {
			http.Error(w, "读取资产失败", 500)
			return
		}
		if sel.Mode == "ids" && len(rows) != len(sel.IDs) {
			http.Error(w, "部分资产不存在或无权访问，请刷新后重选", 404)
			return
		}
		if len(rows) > assetExportMax {
			http.Error(w, "导出超过 10000 条，请缩小筛选范围", 422)
			return
		}
		groupIDs := []uuid.UUID{}
		for _, a := range rows {
			if a.GroupID != nil {
				groupIDs = append(groupIDs, *a.GroupID)
			}
		}
		groups, err := tx.Group.Query().Where(group.IDIn(groupIDs...)).All(ctx)
		if err != nil {
			http.Error(w, "读取资产归属失败", 500)
			return
		}
		names := map[uuid.UUID]string{}
		for _, g := range groups {
			names[g.ID] = g.Name
		}
		now := time.Now().UTC()
		out := make([]assetExportRow, 0, len(rows))
		for _, a := range rows {
			var name *string
			if a.GroupID != nil {
				n := names[*a.GroupID]
				name = &n
			}
			var sensorSeen *time.Time
			if a.SensorSeen != nil {
				t := a.SensorSeen.UTC()
				sensorSeen = &t
			}
			out = append(out, assetExportRow{a.ID, a.Hostname, a.Os, a.OsDisplay, a.IPAddrs, a.GroupID, name, a.AgentID, a.AgentVersion, a.SensorVersion, a.FirstSeen.UTC(), a.LastSeen.UTC(), sensorSeen, exportedHostState(a, now)})
		}
		data, err := encodeAssetExport(body.Format, sel, out, now)
		if err != nil {
			http.Error(w, "导出超过大小限制，请缩小筛选范围", 422)
			return
		}
		detail, _ := json.Marshal(struct {
			Format    string         `json:"format"`
			Selection assetSelection `json:"selection"`
			Count     int            `json:"count"`
			RequestID string         `json:"requestId"`
		}{body.Format, sel, len(out), requestID})
		if err = audit.Checked(ctx, tx.AuditLog.Create(), audit.Actor(ctx), audit.RemoteAddr(r), "assets_exported", "", string(detail)); err != nil {
			http.Error(w, "导出审计写入失败", 500)
			return
		}
		if err = tx.Commit(); err != nil {
			http.Error(w, "导出事务提交失败", 500)
			return
		}
		mime := "text/csv; charset=utf-8"
		if body.Format == "json" {
			mime = "application/json"
		}
		w.Header().Set("Content-Type", mime)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="openxdr-assets-%s.%s"`, now.Format("20060102T150405Z"), body.Format))
		w.Header().Set("X-Exported-At", now.Format(time.RFC3339Nano))
		w.Header().Set("X-Export-Count", strconv.Itoa(len(out)))
		if _, err = w.Write(data); err != nil {
			slog.Warn("资产导出传输失败", "requestId", requestID, "err", err)
		}
	}
}

type exportBuffer struct{ bytes.Buffer }

func (b *exportBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > assetExportBytes {
		return 0, errors.New("导出大小超限")
	}
	return b.Buffer.Write(p)
}

func csvSafe(s string) string {
	trimmed := strings.TrimLeftFunc(s, func(r rune) bool { return unicode.IsSpace(r) || r == '\ufeff' })
	if strings.HasPrefix(s, "\t") || strings.HasPrefix(s, "\r") || strings.HasPrefix(s, "\n") || (len(trimmed) > 0 && strings.ContainsRune("=+-@", rune(trimmed[0]))) {
		return "'" + s
	}
	return s
}
func exportString[T fmt.Stringer](p *T) string {
	if p == nil {
		return ""
	}
	return (*p).String()
}
func stringValue(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func encodeAssetExport(format string, selection assetSelection, rows []assetExportRow, now time.Time) ([]byte, error) {
	b := &exportBuffer{}
	if format == "json" {
		err := json.NewEncoder(b).Encode(struct {
			SchemaVersion string           `json:"schemaVersion"`
			ExportedAt    time.Time        `json:"exportedAt"`
			Filters       assetSelection   `json:"filters"`
			Count         int              `json:"count"`
			Items         []assetExportRow `json:"items"`
		}{"1", now, selection, len(rows), rows})
		return b.Bytes(), err
	}
	if _, err := b.Write([]byte{0xef, 0xbb, 0xbf}); err != nil {
		return nil, err
	}
	cw := csv.NewWriter(b)
	cw.UseCRLF = true
	if err := cw.Write([]string{"id", "hostname", "os", "osDisplay", "ipAddrs", "groupId", "groupName", "agentId", "agentVersion", "sensorVersion", "firstSeen", "lastSeen", "sensorSeen", "hostState"}); err != nil {
		return nil, err
	}
	for _, a := range rows {
		seen := ""
		if a.SensorSeen != nil {
			seen = a.SensorSeen.Format(time.RFC3339Nano)
		}
		values := []string{a.ID.String(), a.Hostname, stringValue(a.OS), stringValue(a.OSDisplay), strings.Join(a.IPAddrs, ";"), exportString(a.GroupID), stringValue(a.GroupName), exportString(a.AgentID), stringValue(a.AgentVersion), stringValue(a.SensorVersion), a.FirstSeen.Format(time.RFC3339Nano), a.LastSeen.Format(time.RFC3339Nano), seen, a.HostState}
		for i := range values {
			values[i] = csvSafe(values[i])
		}
		if err := cw.Write(values); err != nil {
			return nil, err
		}
	}
	cw.Flush()
	return b.Bytes(), cw.Error()
}
