//! 事件采集层。平台差异封死在本模块内部，对外只有一个 channel。
//!
//! Linux 进程采集逐级降级：eBPF (tracepoint sched_process_exec) →
//! netlink proc connector → 跨平台轮询；Windows 优先 ETW (Kernel-Process)，
//! 不可用时（无权限、内核不支持）回落轮询。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;

use crate::pb::AgentEvent;

mod config;
mod hash;
mod poll;
mod registry;

#[cfg(target_os = "linux")]
mod authwatch;

#[cfg(target_os = "linux")]
mod container;

#[cfg(target_os = "linux")]
mod dnswatch;

// 资产清单（监听端口 + 云环境）：共用部分与云探测跨平台，监听表按平台取
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod cloud;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod inventory;
#[cfg(target_os = "linux")]
mod inventory_linux;
#[cfg(target_os = "windows")]
mod inventory_win;

#[cfg(target_os = "linux")]
mod fswatch;

#[cfg(target_os = "linux")]
mod kmodwatch;

#[cfg(target_os = "linux")]
mod netlink;

pub use config::Config;
pub use registry::{Container, ProcessRegistry};

// eBPF 采集是可选特性；关掉它 Linux 走 netlink，构建不需要 nightly。
// 网络采集（TCP 出站）：Linux 只在 eBPF 模式下提供，Windows 走 ETW Kernel-Network；
// netwatch 是两路共用的用户态组装（采样去重 + 归一化），不含平台代码
#[cfg(all(target_os = "linux", feature = "ebpf"))]
mod linux;

#[cfg(any(all(target_os = "linux", feature = "ebpf"), target_os = "windows"))]
mod netwatch;

#[cfg(target_os = "windows")]
mod netwatch_win;

#[cfg(target_os = "windows")]
mod authwatch_win;

#[cfg(target_os = "windows")]
mod fswatch_win;

#[cfg(target_os = "windows")]
mod persistwatch;

#[cfg(target_os = "windows")]
mod windows;

/// 平台指令 ID 的环境变量：respond/exec 拉起指令时设置，进程采集据此给指令进程树打标
pub const COMMAND_ENV: &str = "OPENXDR_COMMAND_ID";

/// 上报缓冲。server 每条事件要等三副本确认，单流约千条每秒；定时任务齐发时
/// 宿主机两秒内能冒出两千多条进程事件，缓冲得兜住这种尖峰慢慢排空，而不是丢
const SINK_CAPACITY: usize = 16 * 1024;

pub fn spawn(agent_id: String, cfg: Config) -> mpsc::Receiver<AgentEvent> {
    let (tx, rx) = mpsc::channel(SINK_CAPACITY);
    let sink = EventSink {
        tx,
        dropped: Arc::new(AtomicU64::new(0)),
    };

    // 进程采集的各分支会拿走 agent_id/sink 所有权，文件监控的副本先留出来
    #[cfg(target_os = "linux")]
    let (agent_id_fs, sink_fs) = (agent_id.clone(), sink.clone());
    #[cfg(target_os = "linux")]
    let (agent_id_auth, sink_auth) = (agent_id.clone(), sink.clone());
    // 内核模块加载监控（/proc/modules diff，rootkit 可见性）
    #[cfg(target_os = "linux")]
    kmodwatch::spawn(agent_id.clone(), sink.clone());

    // 资产清单：监听端口与属主进程、云环境，60s 轮询，变化或满 6 小时才报
    #[cfg(target_os = "linux")]
    if cfg.collect_inventory {
        inventory_linux::spawn(agent_id.clone(), sink.clone());
    }
    #[cfg(target_os = "windows")]
    if cfg.collect_inventory {
        inventory_win::spawn(agent_id.clone(), sink.clone());
    }

    #[cfg(all(target_os = "linux", feature = "ebpf"))]
    tokio::spawn(linux::run(agent_id, sink, cfg.collect_network));

    // 持久化点监控与进程采集并行
    #[cfg(target_os = "windows")]
    if cfg.collect_persist {
        persistwatch::spawn(agent_id.clone(), sink.clone());
    }

    // Windows 进程采集与网络采集共享同一张 GUID 注册表：
    // 网络事件按 pid 查到的 GUID 必须与进程事件登记的是同一个
    #[cfg(target_os = "windows")]
    let registry = std::sync::Arc::new(std::sync::Mutex::new(windows::seeded_registry()));

    // 登录事件：Security 日志 4624/4625，认证可见性与 Linux 侧对称
    #[cfg(target_os = "windows")]
    if cfg.collect_auth {
        authwatch_win::spawn(agent_id.clone(), sink.clone());
    }

    // 敏感文件监控：ReadDirectoryChangesW 盯关键配置目录，与 Linux 侧对称
    #[cfg(target_os = "windows")]
    if cfg.collect_files {
        match fswatch_win::spawn(agent_id.clone(), sink.clone(), &cfg.file_watch_dirs) {
            Ok(n) => eprintln!("文件监控: ReadDirectoryChangesW 盯 {n} 个敏感目录"),
            Err(e) => eprintln!("文件监控不可用（{e}）"),
        }
    }

    // 网络采集（TCP 出站）：ETW Kernel-Network TcpConnect，与进程采集共享
    // GUID 注册表，网络事件的 process_guid 才能与进程血缘对上；独立 trace，
    // 失败只降级警告，不影响进程采集主路
    #[cfg(target_os = "windows")]
    if cfg.collect_network {
        netwatch_win::spawn(agent_id.clone(), sink.clone(), registry.clone());
    }

    #[cfg(target_os = "windows")]
    tokio::spawn(windows::run(agent_id, sink, registry));

    // DNS 采集只靠 AF_PACKET，默认构建也有；eBPF 构建由 linux.rs 拉起，好按 UDP 事件归属进程
    #[cfg(all(target_os = "linux", not(feature = "ebpf")))]
    if cfg.collect_network {
        dnswatch::spawn(agent_id.clone(), sink.clone(), None);
    }

    // Linux 默认走三环的 netlink proc connector：内核主动推送 exec 事件，
    // 不漏短命进程，也不需要 eBPF 工具链。权限不足时才退到轮询。
    #[cfg(all(target_os = "linux", not(feature = "ebpf")))]
    match netlink::spawn(agent_id.clone(), sink.clone()) {
        Ok(()) => eprintln!("采集方式: netlink proc connector（用户态，捕获全部 exec）"),
        Err(e) => {
            eprintln!("netlink 采集不可用（{e}），回落到轮询采集（会漏短命进程）");
            tokio::spawn(poll::run(agent_id, sink));
        }
    }

    // 敏感文件监控与进程采集并行，各自独立降级
    #[cfg(target_os = "linux")]
    if cfg.collect_files {
        match fswatch::spawn(agent_id_fs, sink_fs, &cfg.file_watch_dirs) {
            // 具体走 fanotify 还是 inotify 由 fswatch 内部日志说明
            Ok(_) => {}
            Err(e) => eprintln!("文件监控不可用（{e}）"),
        }
    }

    // 登录事件：wtmp/btmp 增量读 + journald sshd，认证可见性不依赖 syslog 配置
    #[cfg(target_os = "linux")]
    if cfg.collect_auth {
        authwatch::spawn(agent_id_auth, sink_auth);
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    tokio::spawn(poll::run(agent_id, sink));

    rx
}

/// 事件出口。上报侧堵住时丢弃并计数，绝不反压采集——
/// 阻塞采集线程只会让内核缓冲区溢出，丢得更多且无从知晓。
#[derive(Clone)]
pub struct EventSink {
    tx: mpsc::Sender<AgentEvent>,
    dropped: Arc<AtomicU64>,
}

impl EventSink {
    /// 返回 false 表示上报侧已关闭，采集任务应当退出。
    pub fn send(&self, mut event: AgentEvent) -> bool {
        event.dropped_events = self.dropped.load(Ordering::Relaxed);
        match self.tx.try_send(event) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// 上报侧已关闭（断线重连后旧的一轮采集）。没有事件可发的采集循环靠它及时退出
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

/// OCSF 1007 活动类型：进程启动
pub const ACTIVITY_LAUNCH: u32 = 1;
/// OCSF 1007 活动类型：进程退出
pub const ACTIVITY_TERMINATE: u32 = 2;

/// 一个进程的采集结果。用具名字段而非位置参数：
/// exe 与 cmd_line 同为 Option<&str> 且相邻，位置传参很容易传反。
#[derive(Default)]
pub struct ProcessInfo<'a> {
    pub pid: u32,
    pub name: &'a str,
    pub exe: Option<&'a str>,
    pub cmd_line: Option<&'a str>,
    pub ppid: Option<u32>,
    pub username: String,
    /// 退出码，仅退出事件（Terminate）可能拿到
    pub exit_code: Option<u32>,
}

/// 用 /proc 快照预登记现有进程，之后派生的子进程才能找到父。
/// 启动时间与容器也一并记下：长驻服务退出时才说得清跑了多久、是哪个容器里的
#[cfg(target_os = "linux")]
fn seeded_registry() -> ProcessRegistry {
    let mut registry = ProcessRegistry::default();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for pid in entries
            .flatten()
            .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
        {
            let name = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
                .ok()
                .map(|p| p.to_string_lossy().into_owned());
            registry.seed(
                pid,
                full_name(name.trim_end(), exe.as_deref()),
                exe.as_deref(),
            );
            // 早于 agent 启动的进程不可能是本次运行下发的指令
            registry.annotate(pid, container::started(pid), container::of(pid), None);
        }
    }
    registry
}

/// 内核的进程名（comm）最多 15 个字节，长名字会被截断（ip6tables-restore → ip6tables-resto）。
/// 截断的名字是可执行文件名的前缀时，换回完整文件名
fn full_name<'a>(name: &'a str, exe: Option<&'a str>) -> &'a str {
    const COMM_MAX: usize = 15;
    let base = exe.and_then(|e| e.rsplit(['/', '\\']).next());
    match base {
        Some(base) if name.len() == COMM_MAX && base.len() > COMM_MAX && base.starts_with(name) => {
            base
        }
        _ => name,
    }
}

/// 新进程所属的平台指令：agent 自己直接拉起的进程看环境变量（只信 agent 的直接子进程，
/// 别的进程自己设这个变量没用），其余沿父进程继承
fn command_of(registry: &ProcessRegistry, pid: u32, ppid: Option<u32>) -> Option<Arc<str>> {
    let ppid = ppid?;
    if ppid == std::process::id() {
        return command_env(pid);
    }
    registry.command_of(ppid)
}

#[cfg(target_os = "linux")]
fn command_env(pid: u32) -> Option<Arc<str>> {
    let environ = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    let prefix = format!("{COMMAND_ENV}=");
    environ
        .split(|b| *b == 0)
        .find_map(|kv| kv.strip_prefix(prefix.as_bytes()))
        .and_then(|v| std::str::from_utf8(v).ok())
        .filter(|v| !v.is_empty() && v.len() <= 64)
        .map(Arc::from)
}

/// Windows 读不到别的进程的环境变量，指令打标只在 Linux 上做
#[cfg(not(target_os = "linux"))]
fn command_env(_pid: u32) -> Option<Arc<str>> {
    None
}

#[cfg(target_os = "linux")]
fn container_of(pid: u32) -> Option<Arc<Container>> {
    container::of(pid)
}

#[cfg(not(target_os = "linux"))]
fn container_of(_pid: u32) -> Option<Arc<Container>> {
    None
}

/// Linux 进程采集路径共用：按 pid 解析进程属主。
/// 先读 /proc/<pid>/status 的 real uid，再查 /etc/passwd 映射成用户名；
/// passwd 里没有退化为 uid 数字串（与轮询路径一致），进程已退场则给空串。
/// uid→用户名几乎不变，解析结果带缓存，不在事件路径上反复读 passwd。
#[cfg(target_os = "linux")]
fn username_of(pid: u32) -> String {
    use std::sync::{Mutex, OnceLock};

    fn uid_of(pid: u32) -> Option<u32> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        status.lines().find_map(|l| {
            l.strip_prefix("Uid:")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
    }

    fn name_of(uid: u32) -> Option<String> {
        static CACHE: OnceLock<Mutex<std::collections::HashMap<u32, Option<String>>>> =
            OnceLock::new();
        let cache = CACHE.get_or_init(Default::default);
        if let Some(hit) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(&uid) {
            return hit.clone();
        }
        let name = std::fs::read_to_string("/etc/passwd")
            .ok()
            .and_then(|passwd| {
                passwd.lines().find_map(|line| {
                    let mut fields = line.split(':');
                    let name = fields.next()?;
                    fields.next()?; // 口令占位
                    (fields.next()?.parse::<u32>().ok()? == uid).then(|| name.to_string())
                })
            });
        cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(uid, name.clone());
        name
    }

    match uid_of(pid) {
        Some(uid) => name_of(uid).unwrap_or_else(|| uid.to_string()),
        None => String::new(),
    }
}

/// 采集器共用：组装一条进程活动事件（OCSF 1007），并在注册表里建立血缘。
/// activity 取 ACTIVITY_LAUNCH / ACTIVITY_TERMINATE。退出事件的 GUID 优先
/// 复用启动时登记的映射——血缘分析靠退出事件与启动事件共享 process_guid；
/// 查不到（进程早于 agent 启动）再正常登记。
fn process_event(
    agent_id: &str,
    registry: &mut ProcessRegistry,
    activity: u32,
    info: ProcessInfo<'_>,
) -> Option<AgentEvent> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let ProcessInfo {
        pid,
        name,
        exe,
        cmd_line,
        ppid,
        username,
        exit_code,
    } = info;

    // 退出事件只认见过的进程，名字与路径从启动时的登记补上；没见过的退出
    // 配不上启动事件、也说不出是谁，只是噪声
    let known;
    let now = SystemTime::now();
    let (guid, parent_guid, name, exe, started, container, command) =
        if activity == ACTIVITY_TERMINATE {
            known = registry.known(pid)?;
            registry.forget(pid);
            (
                known.guid,
                ppid.and_then(|p| registry.guid_of(p)),
                if name.is_empty() {
                    known.name.as_str()
                } else {
                    name
                },
                exe.or(known.exe.as_deref()),
                known.started,
                known.container.clone(),
                known.command.clone(),
            )
        } else {
            let name = full_name(name, exe);
            let command = command_of(registry, pid, ppid);
            let (guid, parent) = registry.register(pid, ppid);
            let container = container_of(pid);
            registry.describe(pid, name, exe);
            registry.annotate(pid, Some(now), container.clone(), command.clone());
            (guid, parent, name, exe, None, container, command)
        };
    let mut raw = serde_json::json!({
        "activity_id": activity,
        "process": {
            "pid": pid,
            "uid": guid.to_string(),
            "name": name,
            "file": { "path": exe, "sha256": exe.and_then(hash::exe_sha256) },
            "cmd_line": cmd_line,
            "exit_code": exit_code,
            "parent_process": {
                "pid": ppid,
                "uid": parent_guid.map(|g| g.to_string()),
            },
        },
    });
    if let Some(c) = &container {
        raw["container"] = c.to_json();
    }
    if let Some(id) = &command {
        raw["platform_command"] = serde_json::json!({ "uid": id.as_ref() });
    }
    // 退出事件带上启动时间与运行时长；启动时间不知道（快照里读不到）就都不写
    if let Some(started) = started {
        let ms =
            |t: SystemTime| t.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
        raw["process"]["created_time"] = ms(started).into();
        raw["duration_ms"] =
            (now.duration_since(started).unwrap_or_default().as_millis() as u64).into();
    }

    Some(AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: now
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        class_uid: 1007,
        process_guid: guid.to_string(),
        parent_process_guid: parent_guid.map(|g| g.to_string()).unwrap_or_default(),
        username,
        conn_tuple: String::new(),
        raw_json: raw.to_string(),
        dropped_events: 0, // 由 EventSink 在发送时填当前累计值
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn process_event_links_lineage() {
        let mut reg = ProcessRegistry::default();
        let parent = process_event(
            "agent-1",
            &mut reg,
            ACTIVITY_LAUNCH,
            ProcessInfo {
                pid: 100,
                name: "parent.exe",
                exe: Some("/x/parent.exe"),
                cmd_line: Some("parent cmd"),
                ppid: None,
                username: "u".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
        let child = process_event(
            "agent-1",
            &mut reg,
            ACTIVITY_LAUNCH,
            ProcessInfo {
                pid: 200,
                name: "child.exe",
                exe: None,
                cmd_line: Some("child cmd"),
                ppid: Some(100),
                username: "u".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            parent.process_guid, child.parent_process_guid,
            "子进程应连到父进程 GUID"
        );
        assert_eq!(child.class_uid, 1007);
        assert!(!parent.process_guid.is_empty());
        assert!(!child.process_guid.is_empty());
    }

    #[test]
    fn process_event_parent_unknown() {
        let mut reg = ProcessRegistry::default();
        let evt = process_event(
            "agent-1",
            &mut reg,
            ACTIVITY_LAUNCH,
            ProcessInfo {
                pid: 1,
                name: "x",
                exe: None,
                cmd_line: Some("c"),
                ppid: Some(999),
                username: "u".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            evt.parent_process_guid.is_empty(),
            "父未登记时 parent GUID 应为空"
        );
        let v: Value = serde_json::from_str(&evt.raw_json).unwrap();
        assert_eq!(v["process"]["pid"], 1);
        assert_eq!(v["process"]["name"], "x");
        assert_eq!(v["process"]["cmd_line"], "c");
        assert!(
            v["process"]["parent_process"]["uid"].is_null(),
            "父未知时 uid 应为 null"
        );
    }

    #[test]
    fn process_event_raw_fields() {
        let mut reg = ProcessRegistry::default();
        let evt = process_event(
            "agent-x",
            &mut reg,
            ACTIVITY_LAUNCH,
            ProcessInfo {
                pid: 42,
                name: "bash",
                exe: Some("/bin/bash"),
                cmd_line: Some("-c whoami"),
                ppid: None,
                username: "root".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
        let v: Value = serde_json::from_str(&evt.raw_json).unwrap();
        assert_eq!(v["activity_id"], 1);
        assert_eq!(v["process"]["uid"], evt.process_guid);
        assert_eq!(v["process"]["file"]["path"], "/bin/bash");
        assert_eq!(v["process"]["pid"], 42);
        assert_eq!(evt.agent_id, "agent-x");
        assert_eq!(evt.username, "root");
        assert!(evt.ts_unix_ns > 0);
    }

    /// 退出事件：activity_id=2、带退出码，且 process_guid 复用启动时登记的
    /// 映射——血缘分析靠首尾事件共享同一个 GUID。
    #[test]
    fn process_event_terminate_reuses_guid() {
        let mut reg = ProcessRegistry::default();
        let launch = process_event(
            "agent-1",
            &mut reg,
            ACTIVITY_LAUNCH,
            ProcessInfo {
                pid: 300,
                name: "worker",
                exe: Some("/bin/worker"),
                cmd_line: Some("worker -d"),
                ppid: None,
                username: "u".to_string(),
                ..Default::default()
            },
        )
        .unwrap();
        let exit = process_event(
            "agent-1",
            &mut reg,
            ACTIVITY_TERMINATE,
            ProcessInfo {
                pid: 300,
                name: "worker",
                exit_code: Some(137),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(exit.process_guid, launch.process_guid);
        let v: Value = serde_json::from_str(&exit.raw_json).unwrap();
        assert_eq!(v["activity_id"], 2);
        assert_eq!(v["process"]["pid"], 300);
        assert_eq!(v["process"]["exit_code"], 137);
        assert_eq!(v["process"]["uid"], launch.process_guid);
    }

    /// 指令打标：agent 直接拉起的进程看环境变量，后代沿血缘继承；别的进程设了同名变量也不算
    #[cfg(target_os = "linux")]
    #[test]
    fn platform_command_tagging() {
        let launch = |reg: &mut ProcessRegistry, pid: u32, ppid: u32| {
            let evt = process_event(
                "a",
                reg,
                ACTIVITY_LAUNCH,
                ProcessInfo {
                    pid,
                    name: "sh",
                    ppid: Some(ppid),
                    ..Default::default()
                },
            )
            .unwrap();
            let v: Value = serde_json::from_str(&evt.raw_json).unwrap();
            v["platform_command"]["uid"].as_str().map(str::to_string)
        };
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .env(COMMAND_ENV, "cmd-1")
            .spawn()
            .unwrap();
        let mut reg = ProcessRegistry::default();
        let root = child.id();
        assert_eq!(
            launch(&mut reg, root, std::process::id()).as_deref(),
            Some("cmd-1")
        );
        assert_eq!(
            launch(&mut reg, 900_001, root).as_deref(),
            Some("cmd-1"),
            "子进程继承"
        );
        assert_eq!(
            launch(&mut reg, 900_002, 900_001).as_deref(),
            Some("cmd-1"),
            "孙进程继承"
        );
        // 不是 agent 直接拉起的：环境变量不作数
        let mut other = ProcessRegistry::default();
        assert_eq!(launch(&mut other, root, 1), None);
        let _ = child.kill();
        let _ = child.wait();
    }

    /// 被内核截成 15 字节的进程名换回完整文件名；本来就短、或与文件名对不上的保持原样
    #[test]
    fn full_name_restores_truncated_comm() {
        assert_eq!(
            full_name("ip6tables-resto", Some("/usr/sbin/ip6tables-restore")),
            "ip6tables-restore"
        );
        assert_eq!(full_name("bash", Some("/usr/bin/bash")), "bash");
        assert_eq!(
            full_name("python3.11-scri", Some("/usr/bin/python3.11")),
            "python3.11-scri"
        );
        assert_eq!(full_name("abcdefghijklmno", None), "abcdefghijklmno");
    }

    /// 退出事件带运行时长与启动时间，并从注册表删掉登记
    #[test]
    fn terminate_reports_duration_and_forgets() {
        let mut reg = ProcessRegistry::default();
        process_event(
            "a",
            &mut reg,
            ACTIVITY_LAUNCH,
            ProcessInfo {
                pid: 400,
                name: "job",
                ..Default::default()
            },
        )
        .unwrap();
        let exit = process_event(
            "a",
            &mut reg,
            ACTIVITY_TERMINATE,
            ProcessInfo {
                pid: 400,
                exit_code: Some(3),
                ..Default::default()
            },
        )
        .unwrap();
        let v: Value = serde_json::from_str(&exit.raw_json).unwrap();
        assert_eq!(v["process"]["exit_code"], 3);
        assert!(v["duration_ms"].is_u64() && v["process"]["created_time"].is_u64());
        assert!(reg.known(400).is_none(), "退出后应删掉登记");
    }

    /// 早于 agent 启动的进程由快照登记，退出时照样报出名字；
    /// 快照里也没有的 pid（线程、或启动事件丢了）退出不上报。
    #[test]
    fn process_event_terminate_seeded_and_unknown() {
        let mut reg = ProcessRegistry::default();
        reg.seed(555, "cron", Some("/usr/sbin/cron"));
        let exit = process_event(
            "agent-1",
            &mut reg,
            ACTIVITY_TERMINATE,
            ProcessInfo {
                pid: 555,
                ..Default::default()
            },
        )
        .unwrap();
        let v: Value = serde_json::from_str(&exit.raw_json).unwrap();
        assert_eq!(v["activity_id"], 2);
        assert_eq!(v["process"]["name"], "cron");
        assert!(
            v["process"]["exit_code"].is_null(),
            "拿不到退出码时应为 null"
        );

        let unknown = ProcessInfo {
            pid: 556,
            ..Default::default()
        };
        assert!(process_event("agent-1", &mut reg, ACTIVITY_TERMINATE, unknown).is_none());
    }
}
