//go:build integration

package agentchat

import (
	"encoding/json"
	"openxdr/server/ent/decoydeployment"
	"openxdr/server/internal/testdb"
	"strings"
	"testing"
)

func TestDecoyExclusionsDoNotLeakSecretsOrOtherGroups(t *testing.T) {
	ctx, db := testdb.New(t)
	own := db.Group.Create().SetName("own").SaveX(ctx)
	other := db.Group.Create().SetName("other").SaveX(ctx)
	a := db.Asset.Create().SetHostname("a").SetGroupID(own.ID).SaveX(ctx)
	b := db.Asset.Create().SetHostname("b").SetGroupID(other.ID).SaveX(ctx)
	row := db.DecoyDeployment.Create().SetAssetID(a.ID).SetKind(decoydeployment.KindFile).SetPort(0).SetResource("README.md").SetProfile("pause").SetTemplate("file-pause-v1").SetCreatedBy("admin").SetMarker("secret-marker").SetTokenHash("secret-token-hash").SetStatus(decoydeployment.StatusRevoked).SaveX(ctx)
	foreign := db.DecoyDeployment.Create().SetAssetID(b.ID).SetPort(2222).SetProfile("decoy").SetTemplate("identify-v1").SetCreatedBy("admin").SaveX(ctx)
	service := &Service{DB: db}
	exclusions, truncated, err := service.decoyExclusions(ctx, own.ID)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(exclusions)
	text := string(data)
	if truncated || !strings.Contains(text, row.ID.String()) || strings.Contains(text, foreign.ID.String()) || strings.Contains(text, "secret-") || strings.Contains(text, "file-pause-v1") {
		t.Fatal(text)
	}
}
