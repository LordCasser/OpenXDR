// Package incidentstate 记录与 incident 修改同事务的对外事件。
package incidentstate

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"openxdr/server/ent"
	"openxdr/server/ent/alert"
)

const (
	Created         = "incident.created"
	Triaged         = "incident.triaged"
	EvidenceUpdated = "incident.evidence_updated"
	StatusChanged   = "incident.status_changed"
)

type Origin struct {
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"`
}
type Event struct {
	SchemaVersion string            `json:"schemaVersion"`
	EventID       uuid.UUID         `json:"eventId"`
	Type          string            `json:"type"`
	OccurredAt    time.Time         `json:"occurredAt"`
	IncidentID    uuid.UUID         `json:"incidentId"`
	Revision      int64             `json:"revision"`
	Origin        Origin            `json:"origin"`
	Data          map[string]string `json:"data"`
}

// Record 必须接收调用方事务，不能在状态提交后调用。无归属证据以空 UUID 标记，不可外发。
func Record(ctx context.Context, tx *ent.Tx, id uuid.UUID, kind string, origin Origin, previous string) error {
	if !slices.Contains([]string{Created, Triaged, EvidenceUpdated, StatusChanged}, kind) {
		return errors.New("不支持的联动事件类型")
	}
	row, err := tx.Incident.UpdateOneID(id).AddIntegrationRevision(1).Save(ctx)
	if err != nil {
		return err
	}
	alerts, err := tx.Alert.Query().Where(alert.IncidentIDEQ(id)).WithAsset().All(ctx)
	if err != nil {
		return err
	}
	groups := []string{}
	for _, a := range alerts {
		groupID := uuid.Nil.String()
		if a.Edges.Asset != nil && a.Edges.Asset.GroupID != nil {
			groupID = a.Edges.Asset.GroupID.String()
		}
		groups = append(groups, groupID)
	}
	slices.Sort(groups)
	groups = slices.Compact(groups)
	event := Event{SchemaVersion: "1", EventID: uuid.New(), Type: kind, OccurredAt: time.Now().UTC(), IncidentID: id, Revision: row.IntegrationRevision, Origin: origin, Data: map[string]string{"status": row.Status}}
	if kind == StatusChanged {
		event.Data["previousStatus"] = previous
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	return tx.IntegrationEvent.Create().SetID(event.EventID).SetIncidentID(id).SetRevision(event.Revision).SetKind(kind).SetOccurredAt(event.OccurredAt).SetGroupIds(groups).SetPayload(payload).Exec(ctx)
}
