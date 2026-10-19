//go:build integration

package janitor

import (
	"github.com/google/uuid"
	"openxdr/server/internal/testdb"
	"testing"
	"time"
)

func TestDecoyRetentionPreservesReviewAndTokenWindow(t *testing.T) {
	ctx, db := testdb.New(t)
	deployment := uuid.New()
	old := db.DecoyObservation.Create().SetID(uuid.New()).SetDeploymentID(deployment).SetKind("http_page").SetReceivedAt(time.Now().Add(-96 * time.Hour)).SaveX(ctx)
	recent := db.DecoyObservation.Create().SetID(uuid.New()).SetDeploymentID(deployment).SetKind("marker_used").SetReceivedAt(time.Now().Add(-25 * time.Hour)).SaveX(ctx)
	evidence := db.DecoyObservation.Create().SetID(uuid.New()).SetDeploymentID(deployment).SetKind("file_opened").SetReceivedAt(time.Now().Add(-96 * time.Hour)).SetIncidentID(uuid.New()).SaveX(ctx)
	j := &Janitor{DB: db, Retention: time.Hour}
	n, err := j.sweepDecoys(ctx)
	if err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if _, err := db.DecoyObservation.Get(ctx, old.ID); err == nil {
		t.Fatal("未清过期观察")
	}
	db.DecoyObservation.GetX(ctx, recent.ID)
	db.DecoyObservation.GetX(ctx, evidence.ID)
	j.Retention = 0
	if n, err = j.sweepDecoys(ctx); err != nil || n != 0 {
		t.Fatal(n, err)
	}
}
