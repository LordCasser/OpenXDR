//go:build integration

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"openxdr/server/internal/intel"
	"openxdr/server/internal/response"
	"openxdr/server/internal/suppress"
	"openxdr/server/internal/testdb"
)

func TestAPITasks(t *testing.T) {
	ctx, client := testdb.New(t)
	client.Task.Create().SetID("daily").SetName("巡检").SetSchedule("0 2 * * *").SetPrompt("x").SaveX(ctx)
	gA := client.Group.Create().SetName("A").SaveX(ctx)
	gB := client.Group.Create().SetName("B").SaveX(ctx)
	client.TaskRun.Create().SetTaskID("daily").SetGroupID(gA.ID).SaveX(ctx)
	client.TaskRun.Create().SetTaskID("daily").SetGroupID(gB.ID).SaveX(ctx)
	alice := client.User.Create().SetUsername("alice").SetPasswordHash("x").SetRole("viewer").SaveX(ctx)
	client.GroupMember.Create().SetGroupID(gA.ID).SetUserID(alice.ID).SetRole("viewer").SaveX(ctx)

	h := Handler(client, loadRules(t), t.TempDir(), response.NewHub(client, false), suppress.New(client, time.Hour), intel.New(client, time.Hour), nil, nil)
	admin := httptest.NewServer(asAdmin(h))
	t.Cleanup(admin.Close)
	viewer := httptest.NewServer(as(alice, h))
	t.Cleanup(viewer.Close)

	patch := func(body string) int {
		req, _ := http.NewRequest("PATCH", admin.URL+"/api/tasks/daily", strings.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := patch(`{"customSchedule":"every day"}`); code != 400 {
		t.Errorf("坏 cron 应 400，得到 %d", code)
	}
	if code := patch(`{"enabled":false,"customSchedule":"*/30 * * * *"}`); code != 200 {
		t.Fatalf("改任务应 200，得到 %d", code)
	}
	if task := client.Task.GetX(ctx, "daily"); task.Enabled || task.CustomSchedule == nil {
		t.Errorf("启停与周期未生效：%+v", task)
	}
	if code := patch(`{"customSchedule":""}`); code != 200 || client.Task.GetX(ctx, "daily").CustomSchedule != nil {
		t.Errorf("空串应恢复 YAML 周期")
	}

	_, body := get(t, viewer, "/api/tasks/daily/runs")
	var runs []taskRunRow
	if err := json.Unmarshal(body, &runs); err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].GroupID != gA.ID {
		t.Errorf("运行记录应只见 A 组：%+v", runs)
	}
}
