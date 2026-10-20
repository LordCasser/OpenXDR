//! 采集活性检测：通道开着不等于有数据。
//!
//! 实机回放见过 ETW 会话还在、却一条事件都收不到，健康状态照报 active——检测整片失明却没人知道。
//! 这里给「正常主机上必然持续有事件」的通道（进程、文件、网络）记最近一次收到原始事件的时刻
//! （周期折叠、采样去重、回环过滤之前就记，不受上报口径影响）；静默久了先自检，
//! 自检也看不到就把能力降为 degraded 并带原因，事件一恢复就撤掉，回到采集路径自报的状态。
//!
//! 自检只制造本机自己认得出的动静，认出来就在 agent 内丢掉，不进上报、不碰规则和 AI：
//! - 进程：拉起一个立即退出的系统自带程序，持注册表锁拉起并登记 pid，采集回调按 pid 认出它与后代；
//! - 网络：本机回环上自连一次 TCP，连接事件本来就因回环被丢弃；
//! - 文件：在 agent 状态目录下的自检目录里改写一个文件，该目录随监控目标一起挂上，事件按路径认出。
//!
//! 只在静默时才自检：忙碌的主机永远不会多出一个自检进程或一次自连。

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub enum Channel {
    Process = 0,
    Files = 1,
    // 默认构建（Linux 无 eBPF）没有网络采集
    #[cfg_attr(all(target_os = "linux", not(feature = "ebpf")), allow(dead_code))]
    Network = 2,
}

static LAST: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// 进程内单调时钟的毫秒数，从 1 起算：0 留给「还没收到过」
fn now_ms() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64 + 1
}

/// 采集通道收到一条原始事件
pub fn pulse(channel: Channel) {
    LAST[channel as usize].store(now_ms(), Ordering::Relaxed);
}

/// 一个通道的活性判定参数
pub struct Watch {
    /// 健康快照里的能力名
    pub name: &'static str,
    channel: Channel,
    /// 静默这么久就自检，之后每隔这么久再检一次
    probe_after: Duration,
    /// 静默这么久判为降级：此前至少已有两次自检落空
    degrade_after: Duration,
    reason: &'static str,
}

/// 进程：正常主机几分钟内总会有进程起落，自检进程毫秒级就该被看到。
/// 静默 2 分钟自检，5 分钟（两次自检都落空）降级
pub const PROCESS: Watch = Watch {
    name: "process",
    channel: Channel::Process,
    probe_after: Duration::from_secs(120),
    degrade_after: Duration::from_secs(300),
    reason: "持续 5 分钟收不到进程事件，自检进程也没被看到",
};

/// 网络：空闲主机可能很久没有新连接，靠回环自连兜底；静默 2 分钟自检，10 分钟降级
#[cfg_attr(all(target_os = "linux", not(feature = "ebpf")), allow(dead_code))]
pub const NETWORK: Watch = Watch {
    name: "network",
    channel: Channel::Network,
    probe_after: Duration::from_secs(120),
    degrade_after: Duration::from_secs(600),
    reason: "持续 10 分钟收不到连接事件，回环自检连接也没被看到",
};

/// 文件：敏感目录在空闲主机上可以几天不变，只能靠自检文件；每次自检都要落盘，
/// 间隔放长：静默 10 分钟自检，30 分钟降级
pub const FILES: Watch = Watch {
    name: "files",
    channel: Channel::Files,
    probe_after: Duration::from_secs(600),
    degrade_after: Duration::from_secs(1800),
    reason: "持续 30 分钟收不到文件事件，自检文件改动也没被看到",
};

/// 巡检间隔
const TICK: Duration = Duration::from_secs(30);

/// 按静默时长与距上次自检的时长判断：是否该自检、是否已静默到降级
fn assess(watch: &Watch, quiet: Duration, since_probe: Option<Duration>) -> (bool, bool) {
    let probe = quiet >= watch.probe_after && since_probe.is_none_or(|d| d >= watch.probe_after);
    (probe, quiet >= watch.degrade_after)
}

/// 静默时长：从最近一次事件算，开始盯之前的事件不算（刚启动的通道从启动时刻算）
fn quiet_since(channel: Channel, started: u64, now: u64) -> Duration {
    let last = LAST[channel as usize].load(Ordering::Relaxed).max(started);
    Duration::from_millis(now.saturating_sub(last))
}

/// 开始盯一个通道，直到这一轮采集结束（上报侧关闭）。probe 在巡检线程上同步执行
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn spawn(sink: super::EventSink, watch: &'static Watch, probe: impl Fn() + Send + 'static) {
    std::thread::spawn(move || {
        let started = now_ms();
        let mut probed: Option<Instant> = None;
        let mut silent = false;
        loop {
            std::thread::sleep(TICK);
            if sink.is_closed() {
                return;
            }
            let quiet = quiet_since(watch.channel, started, now_ms());
            let (probe_now, degraded) = assess(watch, quiet, probed.map(|t| t.elapsed()));
            if probe_now {
                probe();
                probed = Some(Instant::now());
            }
            if degraded != silent {
                silent = degraded;
                if degraded {
                    eprintln!("采集活性: {}（{}）", watch.reason, watch.name);
                } else {
                    eprintln!("采集活性: {} 恢复收到事件", watch.name);
                }
            }
            sink.silence(watch.name, degraded.then_some(watch.reason));
        }
    });
}

/// 进程自检：持注册表锁拉起自检进程并登记 pid。采集回调处理任何进程事件都要先拿这把锁，
/// 拿到时登记已经在了，自检进程的启动事件不会抢在登记前被当成普通进程上报
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn probe_process(registry: &std::sync::Mutex<super::ProcessRegistry>) {
    let Some(mut command) = canary_command() else {
        return;
    };
    let mut reg = registry.lock().unwrap_or_else(|e| e.into_inner());
    match command.spawn() {
        Ok(mut child) => {
            reg.add_canary(child.id());
            drop(reg);
            let _ = child.wait();
        }
        Err(e) => eprintln!("采集活性: 自检进程拉不起来（{e}）"),
    }
}

/// 自检进程：系统自带、立即退出、不碰任何东西
#[cfg(target_os = "linux")]
fn canary_command() -> Option<std::process::Command> {
    let exe = ["/bin/true", "/usr/bin/true"]
        .into_iter()
        .find(|p| std::path::Path::new(p).is_file())?;
    let mut command = std::process::Command::new(exe);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    Some(command)
}

/// cmd /d /c exit 0：DETACHED_PROCESS 不建控制台，也就不会多拉起一个 conhost
#[cfg(target_os = "windows")]
fn canary_command() -> Option<std::process::Command> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let exe = std::path::Path::new(&root).join("System32").join("cmd.exe");
    let mut command = std::process::Command::new(exe);
    command
        .args(["/d", "/c", "exit", "0"])
        .creation_flags(DETACHED_PROCESS)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    Some(command)
}

/// 网络自检：回环上自连一次 TCP。连上才 accept，连不上不会卡住巡检线程
#[cfg(any(target_os = "linux", target_os = "windows"))]
#[cfg_attr(all(target_os = "linux", not(feature = "ebpf")), allow(dead_code))]
pub fn probe_network() {
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)) else {
        return;
    };
    let Ok(addr) = listener.local_addr() else {
        return;
    };
    if TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_ok() {
        let _ = listener.accept();
    }
}

/// 文件自检目录（agent 状态目录下的 selfcheck），建不起来返回 None——那就不盯文件通道
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn canary_dir() -> Option<&'static str> {
    static DIR: OnceLock<Option<String>> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = crate::delivery::state_root().join("selfcheck");
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!("采集活性: 文件自检目录建不起来（{e}），文件通道不做活性检测");
            return None;
        }
        // fanotify 按句柄还原的是真实路径，状态目录挂在符号链接下也要对得上
        #[cfg(target_os = "linux")]
        let dir = std::fs::canonicalize(&dir).ok()?;
        Some(dir.to_string_lossy().into_owned())
    })
    .as_deref()
}

/// 文件自检：改写自检目录里的文件
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn probe_files(dir: &str) {
    let stamp = now_ms().to_string();
    if let Err(e) = std::fs::write(std::path::Path::new(dir).join("probe"), stamp) {
        eprintln!("采集活性: 自检文件写不进去（{e}）");
    }
}

/// 文件监控收到一条事件：记一次活性，返回它是不是自检文件的（是就不上报）
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn files_pulse(path: &str) -> bool {
    pulse(Channel::Files);
    canary_dir().is_some_and(|dir| is_under(path, dir))
}

fn is_under(path: &str, dir: &str) -> bool {
    path.strip_prefix(dir)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(['/', '\\']))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);

    /// 静默不到自检阈值什么都不做；到了先自检，同一间隔内不重复；到降级阈值才降级
    #[test]
    fn silence_probes_then_degrades() {
        let w = &PROCESS;
        assert_eq!(assess(w, MIN, None), (false, false));
        assert_eq!(assess(w, 2 * MIN, None), (true, false), "静默 2 分钟先自检");
        assert_eq!(
            assess(w, 3 * MIN, Some(MIN)),
            (false, false),
            "间隔内不重复自检"
        );
        assert_eq!(assess(w, 4 * MIN, Some(2 * MIN)), (true, false));
        assert_eq!(
            assess(w, 5 * MIN, Some(MIN)),
            (false, true),
            "5 分钟零事件降级"
        );
    }

    /// 事件一到，静默时长归零，降级撤掉；开始盯之前的旧事件不算数
    #[test]
    fn pulse_recovers() {
        // 用网络通道：其他单测会经 emit_process 给进程通道记活性
        let started = now_ms();
        std::thread::sleep(Duration::from_millis(5));
        let later = now_ms() + 11 * 60 * 1000;
        let quiet = quiet_since(Channel::Network, started, later);
        assert!(assess(&NETWORK, quiet, Some(MIN)).1, "11 分钟零事件应降级");
        pulse(Channel::Network);
        let quiet = quiet_since(Channel::Network, started, now_ms());
        assert_eq!(
            assess(&NETWORK, quiet, None),
            (false, false),
            "收到事件即恢复"
        );
    }

    #[test]
    fn files_wait_longer() {
        assert_eq!(assess(&FILES, 5 * MIN, None), (false, false));
        assert_eq!(assess(&FILES, 10 * MIN, None), (true, false));
        assert_eq!(assess(&FILES, 29 * MIN, Some(9 * MIN)), (false, false));
        assert!(assess(&FILES, 30 * MIN, Some(MIN)).1);
    }

    #[test]
    fn canary_paths() {
        assert!(is_under(
            "/var/lib/openxdr/agent/selfcheck/probe",
            "/var/lib/openxdr/agent/selfcheck"
        ));
        assert!(is_under(
            r"C:\ProgramData\OpenXDR\state\selfcheck\probe",
            r"C:\ProgramData\OpenXDR\state\selfcheck"
        ));
        assert!(!is_under(
            "/var/lib/openxdr/agent/selfcheck2/x",
            "/var/lib/openxdr/agent/selfcheck"
        ));
        assert!(!is_under("/etc/passwd", "/var/lib/openxdr/agent/selfcheck"));
    }
}
