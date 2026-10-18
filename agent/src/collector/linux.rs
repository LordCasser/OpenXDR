//! Linux eBPF 采集：tracepoint sched_process_exec 抓进程启动，
//! sched_process_exit 抓进程退出（sys_enter_exit_group 补退出码），
//! tracepoint sock:inet_sock_set_state 抓 TCP 出站与入站，kprobe udp_sendmsg 抓 UDP 出站。
//! 捕获所有 execve（含短命进程），需要 root/CAP_BPF；
//! 失败按 netlink proc connector → 轮询逐级回落，不跳档。网络与退出码各自独立降级。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::dnswatch::{self, Origin};
use super::inventory::{Owner, Proto};
use super::inventory_linux::Scanner;
use super::netwatch::{self, ConnInfo, ConnSampler};
use super::{
    ACTIVITY_LAUNCH, ACTIVITY_TERMINATE, EventSink, ProcessInfo, ProcessRegistry, container,
    netlink, poll, process_event, seeded_registry, username_of,
};
use crate::pb::AgentEvent;

// 与 ebpf/src/main.rs 中的定义保持一致
#[repr(C)]
#[derive(Clone, Copy)]
struct ExecEvent {
    pid: u32,
    comm: [u8; 16],
    filename: [u8; 256],
}

// 与 ebpf/src/main.rs 中的定义保持一致
#[repr(C)]
#[derive(Clone, Copy)]
struct ExitEvent {
    pid: u32,
    code: i32,
    has_code: u32,
}

// 与 ebpf/src/main.rs 中的定义保持一致
#[repr(C)]
#[derive(Clone, Copy)]
struct ConnEvent {
    pid: u32,
    family: u16,
    sport: u16,
    dport: u16,
    kind: u16,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

const AF_INET: u16 = 2;
const CONN_TCP_OUT: u16 = 0;
const CONN_TCP_IN: u16 = 1;
const CONN_UDP_OUT: u16 = 2;
const DNS_PORT: u16 = 53;

type Shared<T> = Arc<Mutex<T>>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub async fn run(agent_id: String, tx: EventSink, collect_network: bool) {
    if let Err(e) = run_ebpf(agent_id.clone(), tx.clone(), collect_network).await {
        eprintln!("eBPF 采集不可用（{e}），尝试 netlink proc connector");
        if collect_network {
            dnswatch::spawn(agent_id.clone(), tx.clone(), None);
        }
        // 与默认构建同一降级链：netlink 拿不到再退轮询，不直接从最强掉到最弱
        match netlink::spawn(agent_id.clone(), tx.clone()) {
            Ok(()) => eprintln!("采集方式: netlink proc connector（用户态，捕获全部 exec）"),
            Err(e) => {
                eprintln!("netlink 采集不可用（{e}），回落到轮询采集（会漏短命进程）");
                poll::run(agent_id, tx).await;
            }
        }
    }
}

async fn run_ebpf(
    agent_id: String,
    tx: EventSink,
    collect_network: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use aya::maps::perf::AsyncPerfEventArray;
    use aya::programs::TracePoint;
    use aya::util::online_cpus;

    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/openxdr-ebpf"
    )))?;

    let program: &mut TracePoint = bpf
        .program_mut("sched_process_exec")
        .ok_or("eBPF 程序缺失")?
        .try_into()?;
    program.load()?;
    program.attach("sched", "sched_process_exec")?;

    let exit_program: &mut TracePoint = bpf
        .program_mut("sched_process_exit")
        .ok_or("eBPF 程序缺失")?
        .try_into()?;
    exit_program.load()?;
    exit_program.attach("sched", "sched_process_exit")?;

    let mut events: AsyncPerfEventArray<_> = bpf
        .take_map("EVENTS")
        .ok_or("EVENTS map 缺失")?
        .try_into()?;

    let mut exits: AsyncPerfEventArray<_> =
        bpf.take_map("EXITS").ok_or("EXITS map 缺失")?.try_into()?;

    // 退出码独立降级：没有 syscalls tracepoint（内核没开 FTRACE_SYSCALLS）时退出事件照报，只是不带退出码
    if let Err(e) = attach_tracepoint(&mut bpf, "sys_enter_exit_group", "syscalls") {
        eprintln!("退出码采集不可用（{e}）");
    }

    // exec 事件按 CPU 分发到多个任务，进程血缘是全局的，注册表要共享。
    // exec 频率远低于包速率，这把锁的争用可以忽略。
    let registry = std::sync::Arc::new(std::sync::Mutex::new(seeded_registry()));

    for cpu in online_cpus().map_err(|(_, e)| e)? {
        let mut buf = events.open(cpu, None)?;
        let tx = tx.clone();
        let agent_id = agent_id.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            let mut bufs = (0..8)
                .map(|_| bytes::BytesMut::with_capacity(2048))
                .collect::<Vec<_>>();
            loop {
                let Ok(batch) = buf.read_events(&mut bufs).await else {
                    return;
                };
                for b in bufs.iter().take(batch.read) {
                    if b.len() < size_of::<ExecEvent>() {
                        continue;
                    }
                    let ev = unsafe { std::ptr::read_unaligned(b.as_ptr() as *const ExecEvent) };
                    let event = {
                        let mut reg = registry.lock().unwrap_or_else(|e| e.into_inner());
                        to_agent_event(&agent_id, &mut reg, &ev)
                    };
                    if let Some(event) = event
                        && !tx.send(event)
                    {
                        return;
                    }
                }
            }
        });
    }

    for cpu in online_cpus().map_err(|(_, e)| e)? {
        let mut buf = exits.open(cpu, None)?;
        let tx = tx.clone();
        let agent_id = agent_id.clone();
        let registry = registry.clone();
        tokio::spawn(async move {
            let mut bufs = (0..8)
                .map(|_| bytes::BytesMut::with_capacity(256))
                .collect::<Vec<_>>();
            loop {
                let Ok(batch) = buf.read_events(&mut bufs).await else {
                    return;
                };
                for b in bufs.iter().take(batch.read) {
                    if b.len() < size_of::<ExitEvent>() {
                        continue;
                    }
                    let ev = unsafe { std::ptr::read_unaligned(b.as_ptr() as *const ExitEvent) };
                    let event = {
                        let mut reg = registry.lock().unwrap_or_else(|e| e.into_inner());
                        to_exit_event(&agent_id, &mut reg, &ev)
                    };
                    if let Some(event) = event
                        && !tx.send(event)
                    {
                        return;
                    }
                }
            }
        });
    }

    // 网络采集独立降级：老内核没有 inet_sock_set_state 时进程采集照常
    if collect_network {
        let owners: Shared<HashMap<u16, (u32, Instant)>> = Default::default();
        match spawn_conn_readers(&mut bpf, &agent_id, &tx, &registry, &owners).await {
            Ok(udp) => {
                let udp = if udp { "、UDP 出站" } else { "" };
                eprintln!("网络采集: eBPF（TCP 出站与入站{udp}，60s 采样）");
                dnswatch::spawn(
                    agent_id.clone(),
                    tx.clone(),
                    Some(dns_resolver(registry.clone(), owners)),
                );
            }
            Err(e) => {
                eprintln!("网络采集不可用（{e}）");
                dnswatch::spawn(agent_id.clone(), tx.clone(), None);
            }
        }
    }

    // 常驻：bpf 句柄在本栈上保活，程序保持挂载
    std::future::pending::<()>().await;
    Ok(())
}

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn attach_tracepoint(bpf: &mut aya::Ebpf, name: &str, category: &str) -> Result<(), BoxError> {
    let program: &mut aya::programs::TracePoint =
        bpf.program_mut(name).ok_or("eBPF 程序缺失")?.try_into()?;
    program.load()?;
    program.attach(category, name)?;
    Ok(())
}

fn attach_kprobe(bpf: &mut aya::Ebpf, name: &str, function: &str) -> Result<(), BoxError> {
    let program: &mut aya::programs::KProbe =
        bpf.program_mut(name).ok_or("eBPF 程序缺失")?.try_into()?;
    program.load()?;
    program.attach(function, 0)?;
    Ok(())
}

/// 连接事件的用户态共享状态：各 CPU 的读取任务共用，同一目标不因内核把事件派到不同 CPU 而重复上报
struct ConnState {
    registry: Shared<ProcessRegistry>,
    tcp_out: Mutex<ConnSampler>,
    tcp_in: Mutex<ConnSampler>,
    udp_out: Mutex<ConnSampler>,
    listeners: Mutex<Listeners>,
    /// DNS 查询的源端口 → 发起进程，dnswatch 归属进程用
    dns_owners: Shared<HashMap<u16, (u32, Instant)>>,
}

/// 挂载连接探针并按 CPU 派发读取任务。UDP 探针挂不上只降级，返回是否挂上了
async fn spawn_conn_readers(
    bpf: &mut aya::Ebpf,
    agent_id: &str,
    tx: &EventSink,
    registry: &Shared<ProcessRegistry>,
    dns_owners: &Shared<HashMap<u16, (u32, Instant)>>,
) -> Result<bool, BoxError> {
    use aya::maps::perf::AsyncPerfEventArray;
    use aya::util::online_cpus;

    attach_tracepoint(bpf, "inet_sock_set_state", "sock")?;
    let udp = attach_kprobe(bpf, "kp_udp_sendmsg", "udp_sendmsg")
        .and_then(|()| attach_kprobe(bpf, "kp_udpv6_sendmsg", "udpv6_sendmsg"));
    if let Err(e) = &udp {
        eprintln!("UDP 出站采集不可用（{e}）");
    }

    let mut conns: AsyncPerfEventArray<_> =
        bpf.take_map("CONNS").ok_or("CONNS map 缺失")?.try_into()?;

    let state = Arc::new(ConnState {
        registry: registry.clone(),
        tcp_out: Default::default(),
        tcp_in: Default::default(),
        udp_out: Default::default(),
        listeners: Default::default(),
        dns_owners: dns_owners.clone(),
    });

    for cpu in online_cpus().map_err(|(_, e)| e)? {
        let mut buf = conns.open(cpu, None)?;
        let tx = tx.clone();
        let agent_id = agent_id.to_string();
        let state = state.clone();
        tokio::spawn(async move {
            let mut bufs = (0..8)
                .map(|_| bytes::BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
            loop {
                let Ok(batch) = buf.read_events(&mut bufs).await else {
                    return;
                };
                for b in bufs.iter().take(batch.read) {
                    if b.len() < size_of::<ConnEvent>() {
                        continue;
                    }
                    let ev = unsafe { std::ptr::read_unaligned(b.as_ptr() as *const ConnEvent) };
                    let Some(event) = to_conn_event(&agent_id, &state, &ev) else {
                        continue;
                    };
                    if !tx.send(event) {
                        return;
                    }
                }
            }
        });
    }
    Ok(udp.is_ok())
}

fn to_conn_event(agent_id: &str, state: &ConnState, ev: &ConnEvent) -> Option<AgentEvent> {
    let local = ip_of(ev.family, &ev.saddr);
    let remote = ip_of(ev.family, &ev.daddr);
    // DNS 查询不单独成网络事件（dnswatch 会报完整的问答），只记下源端口归哪个进程；
    // 解析器常在本机回环上（systemd-resolved、docker 内置 DNS），所以放在回环过滤之前
    if ev.kind == CONN_UDP_OUT && ev.dport == DNS_PORT {
        let mut owners = lock(&state.dns_owners);
        if owners.len() >= 4096 {
            owners.retain(|_, (_, t)| t.elapsed() < OWNER_TTL);
        }
        owners.insert(ev.sport, (ev.pid, Instant::now()));
        return None;
    }
    // 本机自娱自乐的连接没有检测价值；UDP 的组播、广播（mDNS、SSDP 之类）也只是噪声
    if remote.is_loopback() || remote.is_multicast() || remote == IpAddr::from([255, 255, 255, 255])
    {
        return None;
    }
    match ev.kind {
        CONN_TCP_IN => {
            // 握手在软中断里完成，内核给不出进程：按本机端口找监听它的服务进程
            if !lock(&state.tcp_in).should_report(remote, ev.sport) {
                return None;
            }
            // tracepoint 不分网络命名空间：目的是宿主机自己的地址才查宿主机的监听表。
            // 连到容器里服务的（LXC 有自己的地址）按端口查会错归到宿主机上同端口的进程，只认出是哪个容器
            let pid = if is_host_addr(local) {
                lock(&state.listeners).owner(ev.sport).map(|o| o.pid)
            } else {
                None
            };
            let mut info = conn_info(
                state,
                pid.unwrap_or(0),
                "tcp",
                remote,
                ev.dport,
                local,
                ev.sport,
            );
            info.inbound = true;
            // 域名回填只对出站有意义：入站的目的是本机，那个「域名」只是有人解析过本机地址
            info.hostname = None;
            if pid.is_none() {
                info.container = container::lxc_by_ip(local);
            }
            Some(netwatch::conn_event(agent_id, &info))
        }
        CONN_UDP_OUT => {
            // 从本机 UDP 服务端口发出的是服务给客户端的回包（NTP、syslog、corosync 之类），不算出站
            if lock(&state.listeners).serves_udp(ev.sport)
                || !lock(&state.udp_out).should_report(remote, ev.dport)
            {
                return None;
            }
            let info = conn_info(state, ev.pid, "udp", local, ev.sport, remote, ev.dport);
            Some(netwatch::conn_event(agent_id, &info))
        }
        CONN_TCP_OUT => {
            if !lock(&state.tcp_out).should_report(remote, ev.dport) {
                return None;
            }
            let info = conn_info(state, ev.pid, "tcp", local, ev.sport, remote, ev.dport);
            Some(netwatch::conn_event(agent_id, &info))
        }
        _ => None,
    }
}

/// 发起方在前：出站是本机 → 对端，入站是对端 → 本机服务。进程按 pid 查注册表，
/// 没登记的（极少数）连接发生时进程还在，现读 comm 与 cgroup
fn conn_info(
    state: &ConnState,
    pid: u32,
    proto: &'static str,
    src: IpAddr,
    sport: u16,
    dst: IpAddr,
    dport: u16,
) -> ConnInfo {
    let known = (pid != 0)
        .then(|| lock(&state.registry).known(pid))
        .flatten();
    let name = known
        .as_ref()
        .map(|k| k.name.clone())
        .filter(|n| !n.is_empty())
        .or_else(|| {
            (pid != 0)
                .then(|| std::fs::read_to_string(format!("/proc/{pid}/comm")).ok())
                .flatten()
                .map(|s| s.trim_end().to_string())
        });
    let container = match &known {
        Some(k) => k.container.clone(),
        None if pid != 0 => container::of(pid),
        None => None,
    };
    ConnInfo {
        proto,
        inbound: false,
        pid,
        guid: known.as_ref().map(|k| k.guid),
        exe: known.as_ref().and_then(|k| k.exe.clone()),
        name,
        src,
        sport,
        dst,
        dport,
        container,
        hostname: dnswatch::hostname_of(dst),
        command: known.as_ref().and_then(|k| k.command.clone()),
    }
}

/// 地址是不是宿主机自己网络命名空间里的地址（含回环）。地址会变（DHCP、新网卡），每分钟刷新
fn is_host_addr(ip: IpAddr) -> bool {
    static ADDRS: std::sync::OnceLock<Mutex<(Vec<IpAddr>, Option<Instant>)>> =
        std::sync::OnceLock::new();
    let mut addrs = lock(ADDRS.get_or_init(Default::default));
    if addrs
        .1
        .is_none_or(|t| t.elapsed() >= Duration::from_secs(60))
    {
        addrs.0 = if_addrs::get_if_addrs()
            .unwrap_or_default()
            .into_iter()
            .map(|i| i.addr.ip())
            .collect();
        addrs.1 = Some(Instant::now());
    }
    ip.is_loopback() || addrs.0.contains(&ip)
}

/// DNS 查询源端口的归属保留多久：抓包与 eBPF 事件走两条路，先后差不了几秒
const OWNER_TTL: Duration = Duration::from_secs(10);

/// dnswatch 用：源端口 → 最近从这个端口发 DNS 查询的进程
fn dns_resolver(
    registry: Shared<ProcessRegistry>,
    owners: Shared<HashMap<u16, (u32, Instant)>>,
) -> dnswatch::Resolver {
    Arc::new(move |port| {
        let (pid, at) = *lock(&owners).get(&port)?;
        if at.elapsed() >= OWNER_TTL {
            return None;
        }
        let known = lock(&registry).known(pid);
        Some(match known {
            Some(k) => Origin {
                pid,
                guid: Some(k.guid),
                name: Some(k.name).filter(|n| !n.is_empty()),
                exe: k.exe,
                container: k.container,
                command: k.command,
            },
            None => Origin {
                pid,
                guid: None,
                name: std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .ok()
                    .map(|s| s.trim_end().to_string()),
                exe: None,
                container: container::of(pid),
                command: None,
            },
        })
    })
}

/// 本机监听端口：TCP 端口 → 服务进程，UDP 服务端口集合。监听表很少变：TCP 查不到才重扫（每秒最多一次，
/// 刚起的服务马上就有入站），UDP 每 30 秒刷新。容器自己网络命名空间里的监听在这里看不到，那类入站不归属进程
#[derive(Default)]
struct Listeners {
    scanner: Scanner,
    tcp: HashMap<u16, Owner>,
    udp: std::collections::HashSet<u16>,
    scanned: Option<Instant>,
}

impl Listeners {
    fn refresh(&mut self, hit: bool, every: Duration) {
        let fresh = self.scanned.is_some_and(|t| t.elapsed() < every);
        if hit || fresh {
            return;
        }
        let listeners = self.scanner.scan();
        self.udp = listeners
            .iter()
            .filter(|l| l.proto == Proto::Udp)
            .map(|l| l.port)
            .collect();
        self.tcp = listeners
            .into_iter()
            .filter(|l| l.proto == Proto::Tcp)
            .filter_map(|l| Some((l.port, l.owner?)))
            .collect();
        self.scanned = Some(Instant::now());
    }

    fn owner(&mut self, port: u16) -> Option<&Owner> {
        self.refresh(self.tcp.contains_key(&port), Duration::from_secs(1));
        self.tcp.get(&port)
    }

    /// 端口是不是本机的 UDP 服务端口。临时端口不在监听表里（inventory_linux 已剔除）；按 30 秒周期刷新
    fn serves_udp(&mut self, port: u16) -> bool {
        self.refresh(false, Duration::from_secs(30));
        self.udp.contains(&port)
    }
}

fn ip_of(family: u16, bytes: &[u8; 16]) -> IpAddr {
    let ip = if family == AF_INET {
        IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]])
    } else {
        IpAddr::from(*bytes)
    };
    // 双栈套接字上的 IPv4 连接是 ::ffff:a.b.c.d，还原成 IPv4，与 sensor、DNS 应答对得上
    ip.to_canonical()
}

fn to_agent_event(
    agent_id: &str,
    registry: &mut ProcessRegistry,
    ev: &ExecEvent,
) -> Option<AgentEvent> {
    let name = cstr(&ev.comm);
    let exe = cstr(&ev.filename);
    // exec 瞬间从 /proc 补充命令行和父进程；短命进程可能已退场，拿不到就算了
    let cmd_line = std::fs::read(format!("/proc/{}/cmdline", ev.pid))
        .ok()
        .map(|b| {
            b.split(|c| *c == 0)
                .filter(|s| !s.is_empty())
                .map(String::from_utf8_lossy)
                .collect::<Vec<_>>()
                .join(" ")
        });
    let ppid = std::fs::read_to_string(format!("/proc/{}/status", ev.pid))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("PPid:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        });

    process_event(
        agent_id,
        registry,
        ACTIVITY_LAUNCH,
        ProcessInfo {
            pid: ev.pid,
            name: &name,
            exe: Some(exe.as_ref()),
            cmd_line: cmd_line.as_deref(),
            ppid,
            username: username_of(ev.pid),
            ..Default::default()
        },
    )
}

/// 退出事件只有 pid 与退出码（tracepoint 触发时进程已在退出途中），
/// 名字、路径、GUID 与容器走注册表复用启动时的登记。
fn to_exit_event(
    agent_id: &str,
    registry: &mut ProcessRegistry,
    ev: &ExitEvent,
) -> Option<AgentEvent> {
    process_event(
        agent_id,
        registry,
        ACTIVITY_TERMINATE,
        ProcessInfo {
            pid: ev.pid,
            exit_code: (ev.has_code != 0).then_some(ev.code as u32),
            ..Default::default()
        },
    )
}

fn cstr(bytes: &[u8]) -> std::borrow::Cow<'_, str> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end])
}
