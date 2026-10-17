package commandgate

import (
	"context"
	"log/slog"

	"github.com/google/uuid"

	"openxdr/server/ent"
	"openxdr/server/ent/commandpolicy"
	"openxdr/server/ent/predicate"
)

// cmdPos 命令位置：开头、shell 分隔符或引号之后，或 sudo/nohup/xargs 等包装之后，允许绝对路径。
// 只给与只读命令参数撞名的程序用（last reboot、getent passwd 不该挂起），其余用 \b 宽匹配。
const cmdPos = `(?:^|[;&|(\x60'"\n]|\b(?:sudo|doas|nohup|exec|xargs)\s)\s*(?:-\S+\s+)*(?:[^\s;&|'"]*/)?`

// DefaultAIDeny 新建组自带的 AI 高风险命令名单：在整条命令里非锚定搜索，任一段命中即挂起等组管理员批准，
// 其余命令直接执行。只覆盖破坏性、改配置、停服务与读密钥的操作，只读巡检不受影响。
// Linux 经 sh -c、Windows 经 PowerShell 执行，Windows 的条目不区分大小写。
var DefaultAIDeny = []string{
	// Linux：删除、格式化与写盘
	`\brm\s+(?:[^\s;&|]+\s+)*(?:-[a-zA-Z]*[rRf]|--recursive|--force)`,
	`\b(?:mkfs(?:\.\w+)?|mke2fs|wipefs|fdisk|sfdisk|parted|sgdisk)\b`,
	`\bdd\s(?:[^;&|]*\s)?of=`,
	// 关机重启与停服务
	cmdPos + `(?:shutdown|reboot|poweroff|halt)\b`,
	cmdPos + `(?:tel)?init\s+[06]\b`,
	`\bsystemctl\s+(?:-\S+\s+)*(?:stop|disable|mask|kill|isolate|reboot|poweroff|halt|kexec)\b`,
	`\bservice\s+\S+\s+stop\b`,
	`\b(?:kill|pkill|killall)\b`,
	// 防火墙
	`\bip6?tables(?:-legacy|-nft)?\s+(?:[^;&|]*\s)?(?:-[ADIRFPXNEZ]\b|--(?:append|delete|insert|replace|flush|policy|new-chain|delete-chain|rename-chain|zero)\b)`,
	`\bip6?tables(?:-legacy|-nft)?-restore\b`,
	`\bnft\s+(?:-[a-zA-Z]+\s+)*(?:add|delete|destroy|flush|insert|replace|create|reset|-f)\b`,
	`\bufw\s+(?:--\S+\s+)*(?:enable|disable|reset|reload|allow|deny|reject|limit|delete|insert|prepend|route|default)\b`,
	`\bfirewall-cmd\s+(?:[^;&|]*\s)?--(?:add|remove|set|change|new|delete|reload|complete-reload|panic-on|runtime-to-permanent|reset)`,
	// 账户
	cmdPos + `(?:useradd|userdel|usermod|adduser|deluser|groupadd|groupdel|groupmod|gpasswd|passwd|chpasswd|visudo)\b`,
	// 卸载软件包
	`\b(?:apt|apt-get|aptitude|yum|dnf|zypper)\s+(?:-\S+\s+)*(?:remove|purge|autoremove|erase|rm)\b`,
	`\bpacman\s+(?:-\S+\s+)*(?:-R[a-zA-Z]*|--remove)\b`,
	`\bdpkg\s+(?:-\S+\s+)*(?:-[rP]|--remove|--purge)\b`,
	`\brpm\s+(?:-\S+\s+)*(?:-e[a-zA-Z]*|--erase)\b`,
	// 存储与虚拟化
	`\bz(?:fs|pool)\s+(?:-\S+\s+)*(?:destroy|rollback)\b`,
	`\b(?:qm|pct)\s+(?:stop|destroy|shutdown|reboot|reset|rollback)\b`,
	`\bpvecm\s+(?:add|delnode|expected|create|updatecerts)\b`,
	// 计划任务、远程脚本、写系统目录
	`\bcrontab\s+(?:[^;&|]*\s)?-[a-zA-Z]*r[a-zA-Z]*\b`,
	`\b(?:curl|wget)\b[^;&]*\|\s*(?:sudo\s+)?(?:[^\s;&|]*/)?(?:ba|da|z|k)?sh\b`,
	`\b(?:ba|da|z|k)?sh\s+(?:-\S+\s+)*(?:-c\s+["']?)?(?:\$\(|<\()\s*(?:curl|wget)\b`,
	`>\s*["']?/(?:etc|boot|usr|bin|sbin|lib(?:32|64)?)(?:[/\s"']|$)`,
	`\btee\s+(?:-\S+\s+)*["']?/(?:etc|boot|usr|bin|sbin|lib(?:32|64)?)(?:[/\s"']|$)`,
	// 读密钥：shadow 与 SSH 私钥（.pub 公钥不算）
	`/etc/g?shadow\b`,
	`\bid_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?(?:$|[^\w.]|\.(?:$|[^p]|p(?:$|[^u]|u(?:$|[^b]))))`,
	// Windows（PowerShell）
	`(?i)\b(?:Stop|Restart)-Computer\b`,
	`(?i)\b(?:Remove-Item|ri|rmdir|rd|del|erase)\s+(?:[^;|\n]*\s)?(?:-r\w*|/s)\b`,
	`(?i)\b(?:Format-Volume|Clear-Disk|Remove-Partition)\b`,
	`(?i)\bStop-Service\b`,
	`(?i)\bSet-Service\b[^;|\n]*-StartupType\s+["']?Disabled\b`,
	`(?i)\bDisable-NetAdapter\b`,
	`(?i)\b(?:New|Remove|Disable|Set|Rename)-LocalUser\b`,
	`(?i)\b(?:Add|Remove)-LocalGroupMember\b`,
	`(?i)\b(?:Set|Add)-MpPreference\b`,
	`(?i)\b(?:Stop-Process|taskkill)\b`,
	`(?i)\bnetsh(?:\.exe)?\s+advfirewall\s+(?:firewall\s+)?(?:set|add|delete|reset|import)\b`,
	`(?i)\b(?:New|Set|Remove|Disable|Enable)-NetFirewall\w+`,
}

// SeedDefaults 给组写入默认 AI 高风险命令名单。
func SeedDefaults(ctx context.Context, db *ent.Client, groupID uuid.UUID) error {
	creates := make([]*ent.CommandPolicyCreate, len(DefaultAIDeny))
	for i, pattern := range DefaultAIDeny {
		creates[i] = db.CommandPolicy.Create().SetGroupID(groupID).SetOrigin(commandpolicy.OriginAi).
			SetMode(commandpolicy.ModeDeny).SetPattern(pattern)
	}
	return db.CommandPolicy.CreateBulk(creates...).Exec(ctx)
}

// MigrateAllowToDeny 把旧版 AI 免审批名单换成默认高风险名单：删掉全部 ai/allow 行，
// 只给本次确实删到行的组补默认名单。幂等：再跑一次没有 allow 行可删，
// 管理员主动清空的黑名单也不会被反复补回来。
func MigrateAllowToDeny(ctx context.Context, db *ent.Client) error {
	tx, err := db.Tx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	aiAllow := []predicate.CommandPolicy{commandpolicy.OriginEQ(commandpolicy.OriginAi), commandpolicy.ModeEQ(commandpolicy.ModeAllow)}
	rows, err := tx.CommandPolicy.Query().Where(aiAllow...).All(ctx)
	if err != nil || len(rows) == 0 {
		return err
	}
	groups := map[uuid.UUID]bool{}
	for _, row := range rows {
		groups[row.GroupID] = true
	}
	if _, err := tx.CommandPolicy.Delete().Where(aiAllow...).Exec(ctx); err != nil {
		return err
	}
	for id := range groups {
		if err := SeedDefaults(ctx, tx.Client(), id); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	slog.Info("AI 免审批名单已迁移为高风险名单：删除旧条目并给这些组补默认名单", "removed", len(rows), "groups", len(groups), "per_group", len(DefaultAIDeny))
	return nil
}
