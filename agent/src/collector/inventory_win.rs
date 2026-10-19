//! Windows 监听表：IP Helper 的 GetExtendedTcpTable（仅 LISTEN）与
//! GetExtendedUdpTable，IPv4/IPv6 各取一次，表里直接带属主 pid；
//! 进程名与路径用 sysinfo 按 pid 补（与 seeded_registry 同一来源）。
//!
//! UDP 端口 ≥ 49152（Windows 默认动态端口区间）视为客户端套接字，不报。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
    MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID, MIB_UDP6TABLE_OWNER_PID,
    MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
    UDP_TABLE_OWNER_PID,
};

use super::EventSink;
use super::inventory::{self, Listener, Owner, Proto};

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;

/// Windows 默认动态（临时）端口区间下界
const EPHEMERAL_LOW: u16 = 49152;

pub fn spawn(agent_id: String, sink: EventSink) {
    let mut sys = System::new();
    inventory::spawn(agent_id, sink, move || scan(&mut sys));
}

/// 一行原始记录：(协议, 地址, 端口, pid)
type Row = (Proto, IpAddr, u16, u32);

fn scan(sys: &mut System) -> std::io::Result<Vec<Listener>> {
    let mut rows: Vec<Row> = Vec::new();

    let buf = fetch(|p, n| unsafe {
        // SAFETY: p 指向 n 字节可写缓冲（或首轮为空指针取长度），由 fetch 保证
        GetExtendedTcpTable(p, n, 0, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0)
    })?;
    rows.extend(
        read_rows::<MIB_TCPROW_OWNER_PID>(
            &buf,
            std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table),
        )
        .map(|r| {
            (
                Proto::Tcp,
                v4(r.dwLocalAddr),
                port(r.dwLocalPort),
                r.dwOwningPid,
            )
        }),
    );
    let buf = fetch(|p, n| unsafe {
        // SAFETY: 同上
        GetExtendedTcpTable(p, n, 0, AF_INET6, TCP_TABLE_OWNER_PID_LISTENER, 0)
    })?;
    rows.extend(
        read_rows::<MIB_TCP6ROW_OWNER_PID>(
            &buf,
            std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
        )
        .map(|r| {
            (
                Proto::Tcp,
                IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                port(r.dwLocalPort),
                r.dwOwningPid,
            )
        }),
    );
    let buf = fetch(|p, n| unsafe {
        // SAFETY: 同上
        GetExtendedUdpTable(p, n, 0, AF_INET, UDP_TABLE_OWNER_PID, 0)
    })?;
    rows.extend(
        read_rows::<MIB_UDPROW_OWNER_PID>(
            &buf,
            std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table),
        )
        .map(|r| {
            (
                Proto::Udp,
                v4(r.dwLocalAddr),
                port(r.dwLocalPort),
                r.dwOwningPid,
            )
        }),
    );
    let buf = fetch(|p, n| unsafe {
        // SAFETY: 同上
        GetExtendedUdpTable(p, n, 0, AF_INET6, UDP_TABLE_OWNER_PID, 0)
    })?;
    rows.extend(
        read_rows::<MIB_UDP6ROW_OWNER_PID>(
            &buf,
            std::mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
        )
        .map(|r| {
            (
                Proto::Udp,
                IpAddr::V6(Ipv6Addr::from(r.ucLocalAddr)),
                port(r.dwLocalPort),
                r.dwOwningPid,
            )
        }),
    );
    rows.retain(|&(proto, _, port, _)| proto == Proto::Tcp || port < EPHEMERAL_LOW);

    // pid 0 是 System Idle Process 的占位，不是真属主
    let pids: Vec<Pid> = rows
        .iter()
        .filter(|r| r.3 != 0)
        .map(|r| Pid::from_u32(r.3))
        .collect();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&pids),
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
    );
    Ok(rows
        .into_iter()
        .map(|(proto, addr, port, pid)| Listener {
            proto,
            addr,
            port,
            owner: owner_of(sys, pid),
        })
        .collect())
}

fn owner_of(sys: &System, pid: u32) -> Option<Owner> {
    if pid == 0 {
        return None;
    }
    let proc = sys.process(Pid::from_u32(pid))?;
    let name = proc.name().to_string_lossy().into_owned();
    if name.is_empty() {
        return None;
    }
    Some(Owner {
        pid,
        name,
        path: proc.exe().map(|p| p.to_string_lossy().into_owned()),
    })
}

/// dwLocalAddr 按网络序存放，内存字节即地址字节
fn v4(raw: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes()))
}

/// dwLocalPort 低 16 位是网络序端口
fn port(raw: u32) -> u16 {
    u16::from_be(raw as u16)
}

/// IP Helper 两段式取表：先问长度再取；表在两次调用间变大则重试几次。
/// 失败返回错误，调用方保留上次清单。缓冲用 u32 数组保证 4 字节对齐。
fn fetch(call: impl Fn(*mut core::ffi::c_void, *mut u32) -> u32) -> std::io::Result<Vec<u32>> {
    let mut size = 0u32;
    for _ in 0..4 {
        let mut buf = vec![0u32; (size as usize).div_ceil(4)];
        let ptr = if buf.is_empty() {
            std::ptr::null_mut()
        } else {
            buf.as_mut_ptr().cast()
        };
        match call(ptr, &mut size) {
            NO_ERROR if !buf.is_empty() => return Ok(buf),
            NO_ERROR | ERROR_INSUFFICIENT_BUFFER => continue,
            code => return Err(std::io::Error::from_raw_os_error(code as i32)),
        }
    }
    Err(std::io::Error::other("监听表读取连续变化，保留上次清单"))
}

/// 按表头条目数取行（行数组位于 offset 处，即表结构的 table 字段）；条目数超出缓冲的部分丢弃（不读越界）
fn read_rows<T: Copy>(buf: &[u32], offset: usize) -> impl Iterator<Item = T> + '_ {
    let bytes = std::mem::size_of_val(buf);
    let count = buf.first().copied().unwrap_or(0) as usize;
    let fits = bytes.saturating_sub(offset) / std::mem::size_of::<T>();
    (0..count.min(fits)).map(move |i| {
        // SAFETY: offset + (i+1)*size_of::<T>() ≤ bytes，读在缓冲内；
        // T 是纯数据的 C 结构，任意位模式都合法；read_unaligned 不依赖对齐
        unsafe {
            buf.as_ptr()
                .cast::<u8>()
                .add(offset + i * std::mem::size_of::<T>())
                .cast::<T>()
                .read_unaligned()
        }
    })
}
