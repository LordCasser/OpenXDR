package api

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/report"
	"openxdr/server/ent/reportread"
	"openxdr/server/internal/auth"
)

// 报告已读按人记：打开预览、HTML 或 PDF 都算看过；一个人看过不影响别人的未读。

// markRead 记一次已读，重复记无害（唯一索引挡住并发重复）
func markRead(ctx context.Context, db *ent.Client, reportID, userID uuid.UUID) error {
	exists, err := db.ReportRead.Query().Where(reportread.ReportIDEQ(reportID), reportread.UserIDEQ(userID)).Exist(ctx)
	if err != nil || exists {
		return err
	}
	if err := db.ReportRead.Create().SetReportID(reportID).SetUserID(userID).Exec(ctx); err != nil && !ent.IsConstraintError(err) {
		return err
	}
	return nil
}

// readOf 这个人看过列表里的哪些报告
func readOf(ctx context.Context, db *ent.Client, userID uuid.UUID, rows []*ent.Report) (map[uuid.UUID]bool, error) {
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	reads, err := db.ReportRead.Query().Where(reportread.UserIDEQ(userID), reportread.ReportIDIn(ids...)).All(ctx)
	if err != nil {
		return nil, err
	}
	read := make(map[uuid.UUID]bool, len(reads))
	for _, r := range reads {
		read[r.ReportID] = true
	}
	return read, nil
}

// reportRow 列表里的一份报告带上当前用户是否看过
type reportRow struct {
	*ent.Report
	Read bool `json:"read"`
}

func mapReportReads(mux *http.ServeMux, db *ent.Client) {
	mux.HandleFunc("POST /api/agent-reports/{id}/read", func(w http.ResponseWriter, r *http.Request) {
		row, ok := getByPath(w, r, "id", "report", db.Report.Get)
		if !ok || !requireGroup(w, r, db, row.GroupID, "viewer") {
			return
		}
		if err := markRead(r.Context(), db, row.ID, auth.From(r.Context()).ID); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	// 全部标为已读：只动列表里看得到的最近 100 份，与列表口径一致
	mux.HandleFunc("POST /api/agent-reports/read", func(w http.ResponseWriter, r *http.Request) {
		group, err := uuid.Parse(r.URL.Query().Get("groupId"))
		if err != nil {
			http.Error(w, "groupId 必填", 400)
			return
		}
		if !requireGroup(w, r, db, group, "viewer") {
			return
		}
		user := auth.From(r.Context()).ID
		rows, err := db.Report.Query().Where(report.GroupIDEQ(group)).Order(ent.Desc(report.FieldCreatedAt)).Limit(100).All(r.Context())
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		read, err := readOf(r.Context(), db, user, rows)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		for _, row := range rows {
			if read[row.ID] {
				continue
			}
			if err := markRead(r.Context(), db, row.ID, user); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
