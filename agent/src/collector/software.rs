//! 软件清单（Linux dpkg）：已装的包、版本，以及它们来自哪个源码包——发行版的漏洞公告按源码包发布，
//! server 拿源码包与版本对漏洞库。产出 OCSF Software Inventory Info（class_uid=5020）。
//!
//! 30 分钟查一次，清单变了才报，最长 24 小时补报一次。没有 dpkg 的主机（RPM、Alpine）暂不采集，
//! 健康快照里标为不可用，不编数据。

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;

use crate::pb::AgentEvent;

use super::EventSink;

/// OCSF Software Inventory Info
const CLASS_SOFTWARE_INVENTORY: u32 = 5020;
const POLL: Duration = Duration::from_secs(30 * 60);
const HEARTBEAT: Duration = Duration::from_secs(24 * 3600);
const MAX_PACKAGES: usize = 20_000;

/// 一个已装的二进制包：名称、版本、源码包名、源码版本
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub source: String,
    pub source_version: String,
}

pub fn spawn(agent_id: String, sink: EventSink) {
    std::thread::spawn(move || {
        let mut last: Option<(u64, Instant)> = None;
        while !sink.is_closed() {
            match snapshot() {
                Ok((os, packages)) => {
                    sink.capability("software", "dpkg", "active");
                    let fp = fingerprint(&os, &packages);
                    if last.is_none_or(|(prev, at)| prev != fp || at.elapsed() >= HEARTBEAT) {
                        if !sink.send(event(&agent_id, &os, &packages)) {
                            return;
                        }
                        last = Some((fp, Instant::now()));
                    }
                }
                Err(e) => {
                    sink.capability("software", "dpkg", "unavailable");
                    eprintln!("软件清单不可用（{e}）");
                }
            }
            // 分段睡，断线重连后旧线程能及时退出
            let until = Instant::now() + POLL;
            while Instant::now() < until && !sink.is_closed() {
                std::thread::sleep(Duration::from_secs(30));
            }
        }
    });
}

/// 发行版 ID 与版本（/etc/os-release），漏洞库按发行版版本分生态
pub type Os = (String, String);

fn snapshot() -> Result<(Os, Vec<Package>), String> {
    let release = std::fs::read_to_string("/etc/os-release")
        .map_err(|e| format!("读不到 /etc/os-release：{e}"))?;
    let out = Command::new("dpkg-query")
        .args(["-W", "-f=${Package}\\t${Version}\\t${source:Package}\\t${source:Version}\\t${db:Status-Abbrev}\\n"])
        .output()
        .map_err(|e| format!("没有 dpkg：{e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let packages = parse(&String::from_utf8_lossy(&out.stdout));
    if packages.is_empty() || packages.len() > MAX_PACKAGES {
        return Err(format!("dpkg 返回 {} 个包，不像正常清单", packages.len()));
    }
    Ok((os_release(&release), packages))
}

pub fn os_release(text: &str) -> Os {
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .map(|v| v.trim().trim_matches('"').to_string())
            .unwrap_or_default()
    };
    (field("ID"), field("VERSION_ID"))
}

/// 只要真正装好的包（状态 ii）；源码包名缺省就是包名本身
pub fn parse(text: &str) -> Vec<Package> {
    let mut out: Vec<Package> = text
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            if f.len() != 5 || !f[4].starts_with("ii") || f[0].is_empty() || f[1].is_empty() {
                return None;
            }
            let source = if f[2].is_empty() { f[0] } else { f[2] };
            let source_version = if f[3].is_empty() { f[1] } else { f[3] };
            Some(Package {
                name: f[0].into(),
                version: f[1].into(),
                source: source.into(),
                source_version: source_version.into(),
            })
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// 可执行文件属于哪个包（dpkg -S），监听服务据此对上漏洞。每个路径只查一次，查不到记空
pub fn package_of(path: &str) -> Option<String> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    if let Some(hit) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(path) {
        return hit.clone();
    }
    let found = Command::new("dpkg-query")
        .args(["-S", "--", path])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| owner_package(&String::from_utf8_lossy(&o.stdout)));
    cache
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(path.to_string(), found.clone());
    found
}

/// 「openssh-server: /usr/sbin/sshd」→ openssh-server；多个包共有（diversion）时取第一个，去掉架构后缀
fn owner_package(out: &str) -> Option<String> {
    let first = out.lines().next()?.split_once(": ")?.0;
    let name = first.split(", ").next()?.split(':').next()?.trim();
    (!name.is_empty() && !name.contains(' ')).then(|| name.to_string())
}

fn fingerprint(os: &Os, packages: &[Package]) -> u64 {
    let mut h = DefaultHasher::new();
    os.hash(&mut h);
    packages.hash(&mut h);
    h.finish()
}

fn event(agent_id: &str, os: &Os, packages: &[Package]) -> AgentEvent {
    // 包列表用数组的数组，上千个包时比对象数组小一半
    let rows: Vec<_> = packages
        .iter()
        .map(|p| json!([p.name, p.version, p.source, p.source_version]))
        .collect();
    let raw = json!({
        "activity_id": 2,
        "os": { "id": os.0, "version_id": os.1 },
        "manager": "dpkg",
        "packages": rows,
    });
    AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        class_uid: CLASS_SOFTWARE_INVENTORY,
        raw_json: raw.to_string(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_installed_packages_with_source() {
        let text = "acl\t2.3.2-2+b1\tacl\t2.3.2-2\tii \n\
                    libssl3t64\t3.5.1-1\topenssl\t\tii \n\
                    removed\t1.0\t\t\trc \n\
                    bash\t5.2.37-2\t\t\tii \n";
        let p = parse(text);
        assert_eq!(p.len(), 3, "rc（已删只剩配置）的不算");
        let ssl = p.iter().find(|p| p.name == "libssl3t64").unwrap();
        assert_eq!(
            (ssl.source.as_str(), ssl.source_version.as_str()),
            ("openssl", "3.5.1-1"),
            "源码版本缺省取包版本"
        );
        let bash = p.iter().find(|p| p.name == "bash").unwrap();
        assert_eq!(bash.source, "bash");
        let acl = p.iter().find(|p| p.name == "acl").unwrap();
        assert_eq!(
            acl.source_version, "2.3.2-2",
            "binNMU 的源码版本与包版本不同"
        );
    }

    #[test]
    fn owner_package_from_dpkg_search() {
        assert_eq!(
            owner_package("openssh-server: /usr/sbin/sshd\n").as_deref(),
            Some("openssh-server")
        );
        assert_eq!(
            owner_package("libc6:amd64: /usr/lib/x86_64-linux-gnu/libc.so.6\n").as_deref(),
            Some("libc6")
        );
        assert_eq!(owner_package("diversion by dash from: /bin/sh\n"), None);
        assert_eq!(owner_package(""), None);
    }

    #[test]
    fn reads_os_release() {
        let text = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nVERSION_ID=\"13\"\nID=debian\n";
        assert_eq!(os_release(text), ("debian".into(), "13".into()));
    }
}
