//! eBPF 内核侧：tracepoint sched_process_exec 捕获所有 execve（含短命进程）；
//! tracepoint sched_process_exit 捕获进程退出，sys_enter_exit_group 记下退出码；
//! tracepoint sock:inet_sock_set_state 捕获 TCP 出站发起（SYN_SENT）与入站建立（SYN_RECV → ESTABLISHED）；
//! kprobe udp_sendmsg / udpv6_sendmsg 捕获 UDP 出站，内核里先按目标采样。

#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{kprobe, map, tracepoint},
    maps::{HashMap, LruHashMap, PerfEventArray},
    programs::{ProbeContext, TracePointContext},
};

// 与 userspace collector/linux.rs 中的定义保持一致
#[repr(C)]
pub struct ExecEvent {
    pub pid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}

#[map]
static EVENTS: PerfEventArray<ExecEvent> = PerfEventArray::new(0);

// /sys/kernel/tracing/events/sched/sched_process_exec/format:
//   field:__data_loc char[] filename;  offset:8;  size:4
const FILENAME_DATA_LOC_OFFSET: usize = 8;

#[tracepoint]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_exec(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_exec(ctx: &TracePointContext) -> Result<(), i64> {
    let mut event = ExecEvent {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        comm: [0; 16],
        filename: [0; 256],
    };
    if let Ok(comm) = bpf_get_current_comm() {
        event.comm = comm;
    }

    // __data_loc 低 16 位是 filename 相对事件起始的偏移
    let data_loc: u32 = unsafe { ctx.read_at(FILENAME_DATA_LOC_OFFSET)? };
    let offset = (data_loc & 0xffff) as usize;
    unsafe {
        let src = (ctx.as_ptr() as *const u8).add(offset);
        let _ = bpf_probe_read_kernel_str_bytes(src, &mut event.filename);
    }

    EVENTS.output(ctx, &event, 0);
    Ok(())
}

// 与 userspace collector/linux.rs 中的定义保持一致
#[repr(C)]
pub struct ExitEvent {
    pub pid: u32,
    /// exit_group 的参数；has_code 为 0 表示没走 exit_group（被信号杀掉等），退出码未知
    pub code: i32,
    pub has_code: u32,
}

#[map]
static EXITS: PerfEventArray<ExitEvent> = PerfEventArray::new(0);

/// exit_group 时记下退出码，主线程 sched_process_exit 时取走
#[map]
static EXIT_CODES: HashMap<u32, i32> = HashMap::with_max_entries(16384, 0);

// /sys/kernel/tracing/events/syscalls/sys_enter_exit_group/format:
//   field:long error_code;  offset:16;  size:8
const EXIT_GROUP_CODE_OFFSET: usize = 16;

#[tracepoint]
pub fn sys_enter_exit_group(ctx: TracePointContext) -> u32 {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let Ok(code) = (unsafe { ctx.read_at::<i64>(EXIT_GROUP_CODE_OFFSET) }) else {
        return 1;
    };
    // 进程退出码只取低 8 位，与 shell 看到的 $? 一致
    let _ = EXIT_CODES.insert(&tgid, &((code & 0xff) as i32), 0);
    0
}

#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    match try_exit(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_exit(ctx: &TracePointContext) -> Result<(), i64> {
    // sched_process_exit 每个线程退出都会触发，只有主线程（tid == tgid）退出才是进程退出
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if pid_tgid as u32 != tgid {
        return Ok(());
    }
    // 退出事件只需 pid 与退出码：血缘与进程细节由用户态注册表补全
    let code = unsafe { EXIT_CODES.get(&tgid).copied() };
    let _ = EXIT_CODES.remove(&tgid);
    let event = ExitEvent {
        pid: tgid,
        code: code.unwrap_or(0),
        has_code: code.is_some() as u32,
    };
    EXITS.output(ctx, &event, 0);
    Ok(())
}

// 与 userspace collector/linux.rs 中的定义保持一致
#[repr(C)]
pub struct ConnEvent {
    pub pid: u32,
    pub family: u16,
    pub sport: u16,
    pub dport: u16,
    /// CONN_* 之一。入站时 pid 为 0（握手在软中断里完成，没有进程上下文），
    /// sport/saddr 是本机服务端，dport/daddr 是对端
    pub kind: u16,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
}

pub const CONN_TCP_OUT: u16 = 0;
pub const CONN_TCP_IN: u16 = 1;
pub const CONN_UDP_OUT: u16 = 2;

#[map]
static CONNS: PerfEventArray<ConnEvent> = PerfEventArray::new(0);

/// SYN_SENT 时 tracepoint 的 sport 仍是 0。先按 socket 地址记住发起进程，
/// 等 ESTABLISHED（成功）或 CLOSE（失败）拿到内核分配的真实源端口再上报。
#[map]
static CONNECTING: HashMap<u64, u32> = HashMap::with_max_entries(16384, 0);

// /sys/kernel/tracing/events/sock/inet_sock_set_state/format
const OLDSTATE_OFFSET: usize = 16;
const NEWSTATE_OFFSET: usize = 20;
const SKADDR_OFFSET: usize = 8;
const SPORT_OFFSET: usize = 24;
const DPORT_OFFSET: usize = 26;
const FAMILY_OFFSET: usize = 28;
const PROTOCOL_OFFSET: usize = 30;
const SADDR_OFFSET: usize = 32;
const DADDR_OFFSET: usize = 36;
const SADDR6_OFFSET: usize = 40;
const DADDR6_OFFSET: usize = 56;

const TCP_SYN_SENT: i32 = 2;
const TCP_SYN_RECV: i32 = 3;
const TCP_ESTABLISHED: i32 = 1;
const TCP_CLOSE: i32 = 7;
const IPPROTO_TCP: u16 = 6;
const AF_INET: u16 = 2;

#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    match try_conn(&ctx) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

fn try_conn(ctx: &TracePointContext) -> Result<(), i64> {
    // SYN_SENT 必然在发起进程上下文，但此时源端口尚未写入 tracepoint。
    // 用 skaddr 关联到后续 ESTABLISHED/CLOSE，再输出完整五元组。
    let newstate: i32 = unsafe { ctx.read_at(NEWSTATE_OFFSET)? };
    let protocol: u16 = unsafe { ctx.read_at(PROTOCOL_OFFSET)? };
    if protocol != IPPROTO_TCP {
        return Ok(());
    }
    let skaddr: u64 = unsafe { ctx.read_at(SKADDR_OFFSET)? };
    if newstate == TCP_SYN_SENT {
        let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
        CONNECTING.insert(&skaddr, &pid, 0)?;
        return Ok(());
    }
    if newstate != TCP_ESTABLISHED && newstate != TCP_CLOSE {
        return Ok(());
    }
    // 被动打开：子套接字从 SYN_RECV 进入 ESTABLISHED，就是一条建立成功的入站连接
    let oldstate: i32 = unsafe { ctx.read_at(OLDSTATE_OFFSET)? };
    let (pid, kind) = if newstate == TCP_ESTABLISHED && oldstate == TCP_SYN_RECV {
        (0, CONN_TCP_IN)
    } else {
        let Some(pid) = (unsafe { CONNECTING.get(&skaddr).copied() }) else {
            return Ok(());
        };
        (pid, CONN_TCP_OUT)
    };

    let family: u16 = unsafe { ctx.read_at(FAMILY_OFFSET)? };
    let mut event = ConnEvent {
        pid,
        family,
        sport: unsafe { ctx.read_at(SPORT_OFFSET)? },
        dport: unsafe { ctx.read_at(DPORT_OFFSET)? },
        kind,
        saddr: [0; 16],
        daddr: [0; 16],
    };
    if family == AF_INET {
        let s: [u8; 4] = unsafe { ctx.read_at(SADDR_OFFSET)? };
        let d: [u8; 4] = unsafe { ctx.read_at(DADDR_OFFSET)? };
        event.saddr[..4].copy_from_slice(&s);
        event.daddr[..4].copy_from_slice(&d);
    } else {
        event.saddr = unsafe { ctx.read_at(SADDR6_OFFSET)? };
        event.daddr = unsafe { ctx.read_at(DADDR6_OFFSET)? };
    }

    CONNS.output(ctx, &event, 0);
    let _ = CONNECTING.remove(&skaddr);
    Ok(())
}

/// UDP 采样窗口：同一进程发往同一目标的数据报 60 秒内只报一次。DNS（目的端口 53）每次都报，
/// 用户态靠它的源端口把抓到的 DNS 报文归到进程
const UDP_WINDOW_NS: u64 = 60_000_000_000;
const DNS_PORT: u16 = 53;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UdpKey {
    pub tgid: u32,
    pub dport: u16,
    pub family: u16,
    pub daddr: [u8; 16],
}

#[map]
static UDP_SEEN: LruHashMap<UdpKey, u64> = LruHashMap::with_max_entries(8192, 0);

// include/net/sock.h struct sock_common 开头的布局多年未变：
//   skc_daddr 0、skc_rcv_saddr 4、skc_dport 12（网络序）、skc_num 14（主机序）、skc_family 16；
//   IPv6 地址紧跟在 skc_net 之后（发行版内核都开了 CONFIG_NET_NS 与 CONFIG_IPV6）
const SK_DADDR: usize = 0;
const SK_RCV_SADDR: usize = 4;
const SK_DPORT: usize = 12;
const SK_NUM: usize = 14;
const SK_FAMILY: usize = 16;
const SK_V6_DADDR: usize = 56;
const SK_V6_RCV_SADDR: usize = 72;
const AF_INET6: u16 = 10;

unsafe fn read<T>(base: *const u8, offset: usize) -> Result<T, i64> {
    unsafe { bpf_probe_read_kernel(base.add(offset) as *const T) }
}

#[kprobe]
pub fn kp_udp_sendmsg(ctx: ProbeContext) -> u32 {
    try_udp(&ctx).map_or(1, |()| 0)
}

#[kprobe]
pub fn kp_udpv6_sendmsg(ctx: ProbeContext) -> u32 {
    try_udp(&ctx).map_or(1, |()| 0)
}

/// udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)：目标优先取 msg_name
/// （sendto 未连接的套接字），没有再取套接字上 connect 的对端
fn try_udp(ctx: &ProbeContext) -> Result<(), i64> {
    let sk: *const u8 = ctx.arg(0).ok_or(1i64)?;
    let msg: *const u8 = ctx.arg(1).ok_or(1i64)?;
    let mut event = ConnEvent {
        pid: (bpf_get_current_pid_tgid() >> 32) as u32,
        family: unsafe { read(sk, SK_FAMILY)? },
        sport: unsafe { read(sk, SK_NUM)? },
        dport: u16::from_be(unsafe { read(sk, SK_DPORT)? }),
        kind: CONN_UDP_OUT,
        saddr: [0; 16],
        daddr: [0; 16],
    };
    if event.family == AF_INET {
        let s: [u8; 4] = unsafe { read(sk, SK_RCV_SADDR)? };
        let d: [u8; 4] = unsafe { read(sk, SK_DADDR)? };
        event.saddr[..4].copy_from_slice(&s);
        event.daddr[..4].copy_from_slice(&d);
    } else if event.family == AF_INET6 {
        event.saddr = unsafe { read(sk, SK_V6_RCV_SADDR)? };
        event.daddr = unsafe { read(sk, SK_V6_DADDR)? };
    } else {
        return Ok(());
    }
    // msghdr 第一个成员就是 msg_name；sockaddr_in 端口在 2、地址在 4，sockaddr_in6 地址在 8
    let name: *const u8 = unsafe { read(msg, 0)? };
    if !name.is_null() {
        let family: u16 = unsafe { read(name, 0)? };
        event.dport = u16::from_be(unsafe { read(name, 2)? });
        if family == AF_INET {
            let d: [u8; 4] = unsafe { read(name, 4)? };
            event.family = AF_INET;
            event.daddr = [0; 16];
            event.daddr[..4].copy_from_slice(&d);
        } else if family == AF_INET6 {
            event.family = AF_INET6;
            event.daddr = unsafe { read(name, 8)? };
        } else {
            return Ok(());
        }
    }
    // 本机 DNS 服务的回包（源端口 53）不是出站：每个客户端端口各一条，会把采样表冲垮
    if event.dport == 0 || event.sport == DNS_PORT {
        return Ok(());
    }
    if event.dport != DNS_PORT {
        let key = UdpKey {
            tgid: event.pid,
            dport: event.dport,
            family: event.family,
            daddr: event.daddr,
        };
        let now = unsafe { bpf_ktime_get_ns() };
        if let Some(last) = unsafe { UDP_SEEN.get(&key) }
            && now.wrapping_sub(*last) < UDP_WINDOW_NS
        {
            return Ok(());
        }
        let _ = UDP_SEEN.insert(&key, &now, 0);
    }
    CONNS.output(ctx, &event, 0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
