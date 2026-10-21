package api

import (
	"github.com/google/uuid"
	"net/http"
	"openxdr/server/ent"
	"openxdr/server/ent/externalticket"
	integrationapi "openxdr/server/internal/integration"
)

func incidentTickets(db *ent.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if !incidentVisible(w, r, db, id, "viewer") {
			return
		}
		if _, err = db.Incident.Get(r.Context(), id); err != nil {
			if ent.IsNotFound(err) {
				http.NotFound(w, r)
			} else {
				http.Error(w, "读取事件失败", 500)
			}
			return
		}
		rows, err := db.ExternalTicket.Query().Where(externalticket.IncidentIDEQ(id)).Order(ent.Desc(externalticket.FieldUpdatedAt)).All(r.Context())
		if err != nil {
			http.Error(w, "读取关联工单失败", 500)
			return
		}
		out := make([]any, 0, len(rows))
		for _, t := range rows {
			out = append(out, integrationapi.TicketDTO(t))
		}
		writeJSON(w, out)
	}
}
