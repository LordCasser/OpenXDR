package schedule

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseSpec(t *testing.T) {
	s, err := parseSpec([]byte("id: t1\nschedule: '*/5 * * * *'\nprompt: 看看\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "t1" || s.Targets.Group != "*" || s.approvalTimeout != 10*time.Minute {
		t.Errorf("缺省值不符：%+v", s)
	}

	// 按名字指定时区：北京时间 2 点即 UTC 18 点，不依赖运行环境装没装 tzdata
	if sched, err := ParseSchedule("CRON_TZ=Asia/Shanghai 0 2 * * *"); err != nil {
		t.Fatalf("CRON_TZ 应可解析：%v", err)
	} else if next := sched.Next(time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)); next.UTC().Hour() != 18 {
		t.Errorf("北京时间 2 点应为 UTC 18 点，得到 %v", next.UTC())
	}

	bad := map[string]string{
		"缺 id":     "schedule: '@daily'\nprompt: x\n",
		"缺 prompt": "id: t\nschedule: '@daily'\n",
		"坏 cron":   "id: t\nschedule: '61 * * * *'\nprompt: x\n",
		"坏超时":      "id: t\nschedule: '@daily'\nprompt: x\napproval_timeout: soon\n",
		"拼错字段":     "id: t\nschedule: '@daily'\nprompt: x\nshedule: '@hourly'\n",
		"坏分类":      "id: t\nschedule: '@daily'\nprompt: x\ncategory: misc\n",
	}
	for name, y := range bad {
		if _, err := parseSpec([]byte(y)); err == nil {
			t.Errorf("%s 应被拒绝", name)
		}
	}
}

// 仓库自带任务必须全部可加载
func TestBundledTasks(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "tasks")
	files, _ := filepath.Glob(filepath.Join(dir, "*.yml"))
	if len(files) == 0 {
		t.Fatal("tasks/ 下没有任务")
	}
	specs := LoadDir(dir)
	if len(specs) != len(files) {
		t.Errorf("加载 %d 个，文件 %d 个", len(specs), len(files))
	}
	// 任务页靠这些字段展示；除每日巡检外，预设任务默认关闭，由管理员按组开启
	for _, s := range specs {
		if s.NameEN == "" || s.Description == "" || s.DescriptionEN == "" || s.Category == "" {
			t.Errorf("%s 缺少 name_en / description / description_en / category", s.ID)
		}
		if s.ID != "daily-host-inspection" && (s.Enabled == nil || *s.Enabled) {
			t.Errorf("%s 应写 enabled: false", s.ID)
		}
	}
}

func TestLoadDirSkipsBadAndDuplicate(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.yml", "id: a\nschedule: '@daily'\nprompt: x\n")
	write("b.yml", "id: a\nschedule: '@hourly'\nprompt: y\n")
	write("c.yaml", "id: c\nschedule: nope\nprompt: z\n")
	specs := LoadDir(dir)
	if len(specs) != 1 || specs[0].ID != "a" || !strings.Contains(specs[0].Schedule, "daily") {
		t.Errorf("应只留下 a.yml：%+v", specs)
	}
}
