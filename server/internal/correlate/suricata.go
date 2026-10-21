package correlate

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqljson"
	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/alert"
	"openxdr/server/ent/event"
	"openxdr/server/ent/incident"
)

// 无法归属的外部告警按可信来源和连接隔离，不进入全局 unknown 桶。
func externalScope(al *ent.Alert) string {
	if al.AssetID != nil || al.Edges.Event == nil || al.Edges.Event.Source != "suricata" {
		return ""
	}
	var raw struct {
		Metadata struct {
			Scope string `json:"suricata_scope"`
		} `json:"metadata"`
	}
	_ = json.Unmarshal(al.Edges.Event.Raw, &raw)
	if raw.Metadata.Scope == "" {
		return al.ID.String()
	}
	return raw.Metadata.Scope
}

func correlationBucket(al *ent.Alert) string {
	if al.AssetID != nil {
		return al.AssetID.String()
	}
	if scope := externalScope(al); scope != "" {
		return "suricata|" + scope
	}
	return uuid.Nil.String()
}

func (e *Engine) findForAlert(ctx context.Context, al *ent.Alert, since time.Time) (*ent.Incident, error) {
	scope := externalScope(al)
	if scope == "" {
		return e.findOpen(ctx, al.AssetID, since)
	}
	found, err := e.DB.Alert.Query().Where(
		alert.AssetIDIsNil(), alert.TsGTE(since), alert.TsLTE(al.Ts), alert.IncidentIDNotNil(),
		alert.HasIncidentWith(incident.StatusIn("open", "triaged")),
		alert.HasEventWith(event.SourceEQ("suricata"), func(s *sql.Selector) {
			s.Where(sqljson.ValueEQ(event.FieldRaw, scope, sqljson.Path("metadata", "suricata_scope")))
		}),
	).Order(ent.Desc(alert.FieldTs)).WithIncident().First(ctx)
	if err != nil {
		return nil, err
	}
	return found.Edges.Incident, nil
}

func (e *Engine) alertTitle(al *ent.Alert) string {
	if strings.HasPrefix(al.RuleID, "suricata:") && al.Detail != nil {
		return *al.Detail
	}
	return e.ruleTitle(al.RuleID)
}
