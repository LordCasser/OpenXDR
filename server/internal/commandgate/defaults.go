package commandgate

import (
	"context"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/commandpolicy"
)

// DefaultAIAllow 新建组自带的 AI 免审批命令：只读、不吐密钥，够跑每日巡检。
// 按整条命令字面匹配，参数变一个字就回到审批。Linux 经 sh -c、Windows 经 PowerShell 执行，
// 两套命令互不冲突，混合组也能直接用。
var DefaultAIAllow = []string{
	// Linux
	"hostname",
	"uname -a",
	"uptime",
	"free -m",
	"df -hT",
	"df -i",
	"ip -br addr",
	"ip route",
	"systemctl --failed --no-pager",
	"systemctl list-timers --all --no-pager",
	"timedatectl status",
	"ss -lntup",
	"ss -Hntp state established",
	"ps -eo pid,ppid,user,lstart,comm,%cpu,%mem --sort=-%cpu",
	"getent passwd",
	"getent group sudo wheel",
	"who -a",
	"last -n 30 -a",
	"lastb -n 30 -a",
	"crontab -l",
	"ls -la /etc/cron.d",
	`journalctl -u ssh -u sshd --since "24 hours ago" --no-pager -n 200`,
	// Windows（PowerShell）
	"Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,LastBootUpTime,FreePhysicalMemory,TotalVisibleMemorySize",
	"Get-PSDrive -PSProvider FileSystem",
	"Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess",
	"Get-NetTCPConnection -State Established | Select-Object RemoteAddress,RemotePort,OwningProcess",
	"Get-LocalUser | Select-Object Name,Enabled,LastLogon",
	"Get-LocalGroupMember Administrators",
	"Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -ne 'Running'}",
	"Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object TaskPath,TaskName,State",
	"Get-Process | Sort-Object CPU -Descending | Select-Object -First 30 Id,ProcessName,CPU,WorkingSet",
	"w32tm /query /status",
	"Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddDays(-1)} -MaxEvents 50",
}

// SeedDefaults 给组写入默认 AI 免审批名单。
func SeedDefaults(ctx context.Context, db *ent.Client, groupID uuid.UUID) error {
	creates := make([]*ent.CommandPolicyCreate, len(DefaultAIAllow))
	for i, cmd := range DefaultAIAllow {
		creates[i] = db.CommandPolicy.Create().SetGroupID(groupID).SetOrigin("ai").SetMode("allow").
			SetPattern(regexp.QuoteMeta(cmd))
	}
	return db.CommandPolicy.CreateBulk(creates...).Exec(ctx)
}

// AllowedCommands 组内 AI 免审批名单，给模型看：字面命令原样列出，真正的正则标注出来。
func AllowedCommands(ctx context.Context, db *ent.Client, groupID uuid.UUID) ([]string, error) {
	policies, err := db.CommandPolicy.Query().
		Where(commandpolicy.GroupIDEQ(groupID), commandpolicy.OriginEQ("ai")).
		Order(ent.Asc(commandpolicy.FieldCreatedAt)).All(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(policies))
	for i, p := range policies {
		out[i] = display(p.Pattern)
	}
	return out, nil
}

// display 匹配时整条锚定，^…$ 写不写都一样；去掉后若是纯字面量就还原成命令本身。
func display(pattern string) string {
	body := strings.TrimSuffix(strings.TrimPrefix(pattern, "^"), "$")
	if re, err := regexp.Compile(body); err == nil {
		if literal, complete := re.LiteralPrefix(); complete {
			return literal
		}
	}
	return "正则：" + pattern
}
