package commandgate

import "testing"

// 生产上定时任务被名单误伤、半夜等审批到过期的只读巡检命令，以及常见只读写法：都应放行
func TestReadOnlyAccepts(t *testing.T) {
	for _, cmd := range []string{
		`for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers /var/log/auth.log; do [ -e "$f" ] && stat -c '%n|mtime=%y' "$f"; done; echo '---'; ls -la /etc/sudoers.d/ 2>/dev/null`,
		`echo '=== FAILED UNITS ==='; systemctl list-units --state=failed --no-legend; journalctl --since '-1 day' --no-pager 2>/dev/null | grep -iE 'oom|killed|segfault' | tail -20`,
		`echo '=== LAST -X REBOOT/SHUTDOWN ==='; last -x reboot shutdown 2>/dev/null | head -12; journalctl --no-pager -q -b -1 | grep -i 'shutdown' | tail -5`,
		`awk -F: '$3==0 || $3>=1000 {print $1, $3, $7}' /etc/passwd`,
		`getent passwd | awk -F: "\$3==0 || \$3>=1000 {print}"; ls -l /etc/shadow /etc/passwd`,
		`/usr/bin/df -hT && /usr/bin/df -i && /usr/bin/free -m && /usr/bin/uptime && /usr/bin/timedatectl status`,
		`ss -tlnp; ss -Hnt state established | grep 8081 || echo none`,
		`ps -eo pid,ppid,user,comm,%cpu --sort=-%cpu | head -n 6`,
		`crontab -l -u root 2>/dev/null; ls /etc/cron.d/`,
		`while read -r user; do chage -l "$user"; done < /etc/passwd`,
		`systemctl --failed --no-pager; systemctl is-active frr; systemctl status ssh --no-pager >/dev/null 2>&1 && echo up`,
		`dpkg -l | grep -c ^ii; dpkg -S /usr/sbin/sshd`,
		`qm list; pct list; pvecm status; zpool status -x`,
		`find /etc -maxdepth 2 -newermt '-1 day' -type f 2>/dev/null | head`,
		`LC_ALL=C sort -k2 -t: /etc/group | uniq -c`,
		`top -bn1 | head -15; ip -br addr; ip route show`,
		`docker ps --format '{{.Names}} {{.Status}}'`,
		`stat -c %y /etc/shadow; cat /etc/hostname`,
		`sshd -T 2>/dev/null | grep -E 'permitrootlogin|passwordauthentication'`,
		`echo '=== ATQ ==='; atq 2>/dev/null; loginctl list-sessions --no-legend`,
	} {
		if !ReadOnly(cmd) {
			t.Errorf("应判为只读：%s", cmd)
		}
	}
}

// 能改东西、能执行任意命令或读密钥内容的写法：一律不放行，交给人审批
func TestReadOnlyRejects(t *testing.T) {
	for _, cmd := range []string{
		// 拼接与绕道执行
		`cat /etc/passwd; rm -rf /tmp/x`,
		`ls $(rm -rf /)`,
		"ls `rm -rf /`",
		`echo "$(reboot)"`,
		`cat x | sh`,
		`bash -c 'cat /etc/passwd'`,
		`sh -c "ls"`,
		`eval ls`,
		`env rm -rf /`,
		`xargs rm < list`,
		`timeout 5 rm -rf /`,
		`sudo cat /etc/passwd`,
		`nohup ls &`,
		`ls &`,
		`(rm -rf /)`,
		`{ rm -rf /; }`,
		`cat <(rm -rf /)`,
		`cat <<EOF`,
		`$'\x72m' -rf /`,
		`./cat /etc/passwd`,
		`/tmp/cat /etc/passwd`,
		`$CMD`,
		`'rm' -rf /`,
		`cat 'unterminated`,
		// 写文件
		`echo x > /etc/passwd`,
		`echo x >> /root/.bashrc`,
		`ls >(rm -rf /)`,
		`ls 2> /tmp/err`,
		`cat /etc/hosts | tee /etc/hosts.bak`,
		`sort -o /etc/passwd /etc/passwd`,
		`sort -no out in`,
		`uniq in out`,
		`find / -name x -delete`,
		`find / -exec rm {} \;`,
		`find / -fprint /tmp/list`,
		`sed -i s/a/b/ /etc/hosts`,
		`awk 'BEGIN{system("rm -rf /")}'`,
		`awk '{print > "/etc/x"}' /etc/passwd`,
		`awk '{print | "sh"}' cmds`,
		`awk '{ "id" | getline x }'`,
		`awk -f evil.awk`,
		`awk -i inplace '{print}' /etc/hosts`,
		// 有副作用的子命令与选项
		`systemctl stop frr`,
		`systemctl restart ssh`,
		`ip link set eth0 down`,
		`ip netns exec x sh`,
		`crontab -r`,
		`crontab -l -root`,
		`date -s '2020-01-01'`,
		`hostname evil`,
		`sysctl -w net.ipv4.ip_forward=1`,
		`sysctl net.ipv4.ip_forward=1`,
		`journalctl --vacuum-time=1s`,
		`dmesg -c`,
		`docker rm -f x`,
		`docker exec x sh`,
		`qm guest exec 108 -- id`,
		`qm stop 108`,
		`zfs destroy pool/x`,
		`top`,
		`chage -d 0 root`,
		`sshd`,
		`loginctl terminate-session 3`,
		`sshd -D -p 2222`,
		`sshd -T -o PermitRootLogin=yes`,
		`rpm -e pkg`,
		`dpkg --purge pkg`,
		// 读密钥内容：提到密钥路径时只许看元数据
		`cat /etc/shadow`,
		`awk -F: '{print $1,$2}' /etc/shadow`,
		`for f in /etc/shadow; do cat "$f"; done`,
		`grep root /etc/gshadow`,
		`head ~/.ssh/id_ed25519`,
		`while read l; do echo "$l"; done < /etc/shadow; cat /etc/hostname`,
		`f=/etc/shadow; cat $f`,
		`cat < /etc/shadow`,
		`ls -l /etc/shadow && head -1 /etc/shadow`,
		`for f in /etc/passwd /etc/shadow; do stat "$f"; done; cat "$f"`,
		``,
		`   `,
	} {
		if ReadOnly(cmd) {
			t.Errorf("不应判为只读：%s", cmd)
		}
	}
}
