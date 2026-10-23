package api

import (
	"encoding/json"
	"openxdr/server/ent"
	"testing"
	"time"
)

func TestSummaryTriageRunning(t *testing.T) {
	now := time.Now()
	stale := now.Add(-2 * time.Minute)
	for _, tc := range []struct {
		name, status string
		heartbeat    *time.Time
		want         bool
	}{
		{"执行中", "open", &now, true}, {"重研判", "triaged", &now, true},
		{"崩溃残留", "open", &stale, false}, {"缺心跳", "open", nil, false}, {"已结案", "closed", &now, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := summarize(&ent.Incident{Status: tc.status, TriageStartedAt: &now, TriageHeartbeatAt: tc.heartbeat}, 0, 0)
			raw, err := json.Marshal(row)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err = json.Unmarshal(raw, &fields); err != nil {
				t.Fatal(err)
			}
			_, got := fields["triageStartedAt"]
			if got != tc.want {
				t.Fatalf("running=%v want=%v", got, tc.want)
			}
		})
	}
}
