//! 进程所在的容器：按 /proc/<pid>/cgroup 识别 docker / podman / containerd / cri-o 容器、
//! Proxmox 的 LXC 容器与 QEMU 虚拟机、systemd-nspawn。
//!
//! 宿主机上的 agent 看得到容器里的全部进程（同一内核），但不知道它们属于谁：
//! 不标出来，容器里的外联与命令都算在宿主机头上。名字读不到就只给 ID，不编造。

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::Container;

/// cgroup 路径缓存上限：同一容器里的进程共用路径，正常远到不了这个数
const MAX_CACHED: usize = 4096;

/// pid 所在的容器；宿主机自己的进程、进程已退场或读不到 cgroup 都返回 None
pub fn of(pid: u32) -> Option<Arc<Container>> {
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let path = cgroup_path(&cgroup)?;
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Arc<Container>>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(hit) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(path) {
        return hit.clone();
    }
    let found = identify(path).map(|(runtime, uid)| {
        let name = name_of(runtime, &uid);
        Arc::new(Container { runtime, uid, name })
    });
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if cache.len() >= MAX_CACHED {
        cache.clear();
    }
    cache.insert(path.to_string(), found.clone());
    found
}

/// Proxmox LXC 容器（按 VMID）。DNS 采集从 veth 接口名认出容器时用
pub fn lxc(vmid: &str) -> Arc<Container> {
    Arc::new(Container {
        runtime: "lxc",
        uid: vmid.to_string(),
        name: name_of("lxc", vmid),
    })
}

/// cgroup v2 只有一行 0::<路径>；v1 有多行，取第一条带容器特征的
fn cgroup_path(cgroup: &str) -> Option<&str> {
    let paths = cgroup.lines().filter_map(|l| l.splitn(3, ':').nth(2));
    let mut first = None;
    for path in paths {
        if identify(path).is_some() {
            return Some(path);
        }
        first.get_or_insert(path);
    }
    first
}

/// 从 cgroup 路径认出容器运行时与 ID
fn identify(path: &str) -> Option<(&'static str, String)> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    for (i, seg) in segments.iter().enumerate() {
        let next = segments.get(i + 1).copied();
        let scoped = |prefix: &str| {
            seg.strip_prefix(prefix)
                .and_then(|r| r.strip_suffix(".scope"))
                .filter(|id| is_hex_id(id))
        };
        for (prefix, runtime) in [
            ("docker-", "docker"),
            ("libpod-", "podman"),
            ("cri-containerd-", "containerd"),
            ("crio-", "cri-o"),
        ] {
            if let Some(id) = scoped(prefix) {
                return Some((runtime, short(id)));
            }
        }
        match (*seg, next) {
            // cgroupfs 驱动：/docker/<id>
            ("docker", Some(id)) if is_hex_id(id) => return Some(("docker", short(id))),
            // Proxmox / LXC 4+：/lxc.payload.<id>/…；老版本：/lxc/<id>/…。lxc.monitor.* 是宿主机侧的监控进程
            ("lxc", Some(id)) if is_vmid(id) => return Some(("lxc", id.to_string())),
            ("qemu.slice", Some(scope)) => {
                if let Some(id) = scope.strip_suffix(".scope").filter(|id| is_vmid(id)) {
                    return Some(("qemu", id.to_string()));
                }
            }
            _ => {}
        }
        if let Some(id) = seg.strip_prefix("lxc.payload.") {
            return Some(("lxc", id.to_string()));
        }
        if let Some(name) = seg
            .strip_prefix("systemd-nspawn@")
            .and_then(|r| r.strip_suffix(".service"))
        {
            return Some(("nspawn", name.to_string()));
        }
    }
    None
}

fn is_hex_id(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_vmid(s: &str) -> bool {
    !s.is_empty() && s.len() <= 9 && s.bytes().all(|b| b.is_ascii_digit())
}

fn short(id: &str) -> String {
    id[..12].to_string()
}

/// 容器名：docker 读容器配置，Proxmox 读 /etc/pve 下的 LXC / VM 配置
fn name_of(runtime: &str, uid: &str) -> Option<String> {
    match runtime {
        "docker" => docker_name(uid),
        "lxc" => pve_conf_value(&format!("/etc/pve/lxc/{uid}.conf"), "hostname"),
        "qemu" => pve_conf_value(&format!("/etc/pve/qemu-server/{uid}.conf"), "name"),
        _ => None,
    }
}

fn docker_name(short_id: &str) -> Option<String> {
    let dir = std::fs::read_dir("/var/lib/docker/containers").ok()?;
    let full = dir
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| n.starts_with(short_id))?;
    let text = std::fs::read_to_string(format!("/var/lib/docker/containers/{full}/config.v2.json"))
        .ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    let name = v["Name"].as_str()?.trim_start_matches('/');
    (!name.is_empty()).then(|| name.to_string())
}

/// Proxmox 配置是 `键: 值` 行；快照段（[snapshot]）之后的同名键属于快照，不算
fn pve_conf_value(path: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    conf_value(&text, key)
}

fn conf_value(text: &str, key: &str) -> Option<String> {
    text.lines()
        .take_while(|l| !l.starts_with('['))
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            (k.trim() == key).then(|| v.trim().to_string())
        })
        .filter(|v| !v.is_empty())
}

/// 进程启动时间：/proc/<pid>/stat 第 22 列（开机后的时钟滴答）加开机时间。
/// 快照里早于 agent 启动的进程靠它算运行时长
pub fn started(pid: u32) -> Option<SystemTime> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // 进程名在括号里，可能含空格：从最后一个右括号之后开始数列
    let rest = &stat[stat.rfind(')')? + 2..];
    let ticks: u64 = rest.split_whitespace().nth(19)?.parse().ok()?;
    let boot = boot_time()?;
    // SAFETY: sysconf 只读系统配置
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let hz = if hz > 0 { hz as u64 } else { 100 };
    Some(boot + Duration::from_millis(ticks * 1000 / hz))
}

fn boot_time() -> Option<SystemTime> {
    static BOOT: OnceLock<Option<SystemTime>> = OnceLock::new();
    *BOOT.get_or_init(|| {
        let stat = std::fs::read_to_string("/proc/stat").ok()?;
        let secs: u64 = stat
            .lines()
            .find_map(|l| l.strip_prefix("btime "))?
            .trim()
            .parse()
            .ok()?;
        Some(UNIX_EPOCH + Duration::from_secs(secs))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "4f1c2a3b5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7a8";

    #[test]
    fn identifies_runtimes() {
        let cases = [
            (
                format!("/system.slice/docker-{ID}.scope"),
                Some(("docker", "4f1c2a3b5d6e")),
            ),
            (format!("/docker/{ID}"), Some(("docker", "4f1c2a3b5d6e"))),
            (
                format!("/machine.slice/libpod-{ID}.scope/container"),
                Some(("podman", "4f1c2a3b5d6e")),
            ),
            (
                format!("/kubepods.slice/kubepods-burstable.slice/cri-containerd-{ID}.scope"),
                Some(("containerd", "4f1c2a3b5d6e")),
            ),
            (
                "/lxc/203/ns/system.slice/nginx.service".to_string(),
                Some(("lxc", "203")),
            ),
            (
                "/lxc.payload.201/init.scope".to_string(),
                Some(("lxc", "201")),
            ),
            ("/qemu.slice/108.scope".to_string(), Some(("qemu", "108"))),
            (
                "/machine.slice/systemd-nspawn@web.service/payload".to_string(),
                Some(("nspawn", "web")),
            ),
            // 宿主机自己的进程、LXC 监控进程都不是容器
            ("/system.slice/sshd.service".to_string(), None),
            ("/lxc.monitor.203".to_string(), None),
            ("/user.slice/user-0.slice/session-3.scope".to_string(), None),
            ("/system.slice/docker-short.scope".to_string(), None),
        ];
        for (path, want) in cases {
            let got = identify(&path);
            assert_eq!(
                got.as_ref().map(|(r, id)| (*r, id.as_str())),
                want,
                "{path}"
            );
        }
    }

    #[test]
    fn v1_picks_container_line() {
        let v1 = format!("12:pids:/user.slice\n11:memory:/docker/{ID}\n0::/\n");
        assert_eq!(cgroup_path(&v1), Some(format!("/docker/{ID}").as_str()));
        assert_eq!(cgroup_path("0::/init.scope\n"), Some("/init.scope"));
    }

    #[test]
    fn pve_conf() {
        let conf = "arch: amd64\nhostname: termix\nnet0: name=eth0,bridge=vmbr0\n\n[pre-upgrade]\nhostname: old\n";
        assert_eq!(conf_value(conf, "hostname").as_deref(), Some("termix"));
        assert_eq!(
            conf_value("name: win11\n", "name").as_deref(),
            Some("win11")
        );
        assert_eq!(conf_value("[snap]\nhostname: x\n", "hostname"), None);
        assert_eq!(conf_value("hostname:\n", "hostname"), None);
    }
}
