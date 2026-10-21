//! Windows 网络采集：订阅 Microsoft-Windows-Kernel-Network provider，取 TCP 出站、TCP 入站与 UDP 出站，
//! 与 Linux eBPF 路径（inet_sock_set_state + udp_sendmsg）对称。
//!
//! 实机勘定（Win10 22H2，logman 打全事件对拍 TcpClient / TcpListener / UdpClient / curl）：
//! - 12 / 28 是 IPv4 / IPv6 的 TcpConnect，只在本机主动 connect 时触发；
//! - 15 / 31 是 TcpAccept：事件头记在 System 进程上，但 PID 字段是接受连接的监听进程；
//! - 42 / 58 是 UDP 发送，每个数据报一条，PID 字段是发送进程；
//! - 10/11/26/27 是 TCP 收发、13/29 断连、18/34 等是数据拷贝，都不要。
//!
//! 所有事件字段同为 PID/size/daddr/saddr/dport/sport：saddr/sport 恒为本机一侧，daddr/dport 恒为对端
//! （入站时也是），端口是网络字节序（抓到 dport=20480 即 htons(80)），用前要转主机序。
//!
//! UDP 每个数据报一条事件，回调里只做事件号判断、字段解析与采样表查询，同一目标 60s 只报一次。
//! 从本机 UDP 服务端口发出的是回包（w32time、RDP 的 UDP 传输之类），不算出站。
//! UDP 53 照报，且按进程采样：Windows 的 DNS 采集看的是系统解析器的 API 层，绕过它直接发 DNS 报文的程序
//! （nslookup、隧道工具）只能在这里看见，不能被 Dnscache 服务对同一台 DNS 服务器的查询压掉。
//!
//! 独立 trace session：订阅失败（provider 不存在、权限不够）只降级警告，绝不影响进程采集主路。

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{TraceError, UserTrace};

use super::inventory::Proto;
use super::netwatch::{self, ConnInfo, ConnSampler};
use super::{EventSink, ProcessRegistry, dnsnames, liveness};

// ETW 会话用固定名字：agent 被强杀或升级退出时会话不随进程消失，启动时先停掉同名旧会话；
// 用随机名每次重启都漏一个，系统总共 64 个会话名额迟早占满，之后采集就起不来
const SESSION: &str = "OpenXDR-Network";

const KERNEL_NETWORK_GUID: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const DNS_PORT: u16 = 53;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    TcpOut,
    TcpIn,
    UdpOut,
}

/// 事件号 → 要的连接类别（实机勘定，见模块头注释）
fn kind_of(event_id: u16) -> Option<Kind> {
    match event_id {
        12 | 28 => Some(Kind::TcpOut),
        15 | 31 => Some(Kind::TcpIn),
        42 | 58 => Some(Kind::UdpOut),
        _ => None,
    }
}

pub fn spawn(agent_id: String, sink: EventSink, registry: Arc<Mutex<ProcessRegistry>>) {
    // 采样表与 UDP 服务表在会话之外持有：失明重建会话后，同一目标不在采样窗口内重报
    let samplers = Arc::new(Mutex::new(Samplers::default()));
    let services = Arc::new(Mutex::new(UdpServices::default()));
    let health = sink.clone();
    let start = move || start(&agent_id, &sink, &registry, &samplers, &services);
    match start() {
        Ok(trace) => {
            eprintln!("网络采集: ETW Kernel-Network（TCP 出站与入站、UDP 出站，60s 采样）");
            liveness::spawn(
                health,
                &liveness::NETWORK,
                liveness::probe_network,
                trace,
                move || start().map_err(|e| format!("{e:?}")),
            );
        }
        Err(e) => {
            health.capability("network", "etw", "unavailable");
            eprintln!("网络采集不可用（{e:?}），进程采集不受影响");
        }
    }
}

/// 一条原始连接：本机一侧与对端，端口已转主机序
struct Raw {
    pid: u32,
    local: IpAddr,
    lport: u16,
    remote: IpAddr,
    rport: u16,
}

#[derive(Default)]
struct Samplers {
    tcp_out: ConnSampler,
    tcp_in: ConnSampler,
    udp_out: ConnSampler,
}

/// 起一个网络采集会话：先停掉同名旧会话再新建，句柄 drop 即停会话（停止口径见 etw_session）
fn start(
    agent_id: &str,
    sink: &EventSink,
    registry: &Arc<Mutex<ProcessRegistry>>,
    samplers: &Arc<Mutex<Samplers>>,
    services: &Arc<Mutex<UdpServices>>,
) -> Result<super::etw_session::Owned<UserTrace>, TraceError> {
    let health_sink = sink.clone();
    // ETW 回调要求 'static，采样表/注册表/出口全部按所有权（Arc）移进闭包；
    // 注册表由 mod.rs 传入，与进程采集共享
    let (agent_id, sink) = (agent_id.to_string(), sink.clone());
    let (registry, samplers, services) = (registry.clone(), samplers.clone(), services.clone());

    let provider = Provider::by_guid(KERNEL_NETWORK_GUID)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let Some(kind) = kind_of(record.event_id()) else {
                return;
            };
            // 活性按原始事件记：回环自检连接与被采样、过滤掉的连接都算
            liveness::pulse(liveness::Channel::Network);
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);
            let (Ok(pid), Ok(saddr), Ok(daddr), Ok(sport), Ok(dport)) = (
                parser.try_parse::<u32>("PID"),
                parser.try_parse::<IpAddr>("saddr"),
                parser.try_parse::<IpAddr>("daddr"),
                parser.try_parse::<u16>("sport"),
                parser.try_parse::<u16>("dport"),
            ) else {
                return;
            };
            let raw = Raw {
                pid,
                local: saddr.to_canonical(),
                lport: u16::from_be(sport),
                remote: daddr.to_canonical(),
                rport: u16::from_be(dport),
            };
            if !reportable(raw.local, raw.remote) {
                return;
            }
            if kind == Kind::UdpOut
                && services
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .serves(raw.lport)
            {
                return;
            }
            if !samplers
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .should_report(kind, &raw)
            {
                return;
            }
            // 进程没登记过（启动事件还没到，或早于 agent 启动）就现场占位，保证事件一定挂得上 GUID
            // 连接归到被折叠的进程上：压着的启动事件（连同被折叠的祖先）先补发
            let (known, revealed) = {
                let mut reg = registry.lock().unwrap_or_else(|e| e.into_inner());
                reg.reveal(raw.pid);
                let known = match reg.known(raw.pid) {
                    Some(k) => (k.guid, Some(k.name), k.exe, k.command),
                    None => (reg.placeholder(raw.pid), None, None, None),
                };
                (known, reg.take_outbox())
            };
            for event in revealed {
                sink.send(event);
            }
            sink.send(netwatch::conn_event(
                &agent_id,
                &conn_info(kind, &raw, known),
            ));
        })
        .build();

    let trace = super::etw_session::user_trace(SESSION, provider)?;
    health_sink.capability("network", "etw", "active");
    Ok(trace)
}

impl Samplers {
    /// 出站按（对端, 对端端口）、入站按（对端, 本机服务端口）采样，与 Linux 一致
    fn should_report(&mut self, kind: Kind, raw: &Raw) -> bool {
        match kind {
            Kind::TcpOut => self.tcp_out.should_report(raw.remote, raw.rport),
            Kind::TcpIn => self.tcp_in.should_report(raw.remote, raw.lport),
            // 发往 53 的按进程采样：Dnscache 服务每分钟都在问同一台 DNS 服务器，
            // 按目标采样会把绕过系统解析器、自己发 DNS 报文的进程一并压掉
            Kind::UdpOut if raw.rport == DNS_PORT => self
                .udp_out
                .should_report_for(raw.remote, raw.rport, raw.pid),
            Kind::UdpOut => self.udp_out.should_report(raw.remote, raw.rport),
        }
    }
}

/// 发起方在前：出站是本机 → 对端，入站是对端 → 本机服务（进程是监听它的服务进程）。
/// 域名回填只对出站有意义：入站的目的是本机
fn conn_info(
    kind: Kind,
    raw: &Raw,
    (guid, name, exe, command): (uuid::Uuid, Option<String>, Option<String>, Option<Arc<str>>),
) -> ConnInfo {
    let inbound = kind == Kind::TcpIn;
    let (src, sport, dst, dport) = if inbound {
        (raw.remote, raw.rport, raw.local, raw.lport)
    } else {
        (raw.local, raw.lport, raw.remote, raw.rport)
    };
    ConnInfo {
        proto: if kind == Kind::UdpOut { "udp" } else { "tcp" },
        inbound,
        pid: raw.pid,
        guid: Some(guid),
        name,
        exe,
        src,
        sport,
        dst,
        dport,
        container: None,
        hostname: (!inbound).then(|| dnsnames::hostname_of(dst)).flatten(),
        command,
    }
}

/// 本机自娱自乐、未绑定地址、组播与广播没有检测价值，不报
fn reportable(local: IpAddr, remote: IpAddr) -> bool {
    !local.is_loopback()
        && !remote.is_loopback()
        && !local.is_unspecified()
        && !remote.is_unspecified()
        && !remote.is_multicast()
        && remote != IpAddr::from([255, 255, 255, 255])
}

/// 本机 UDP 服务端口（监听表里的，临时端口 inventory_win 已剔除），30 秒刷新
#[derive(Default)]
struct UdpServices {
    sys: Option<sysinfo::System>,
    ports: HashSet<u16>,
    scanned: Option<Instant>,
}

impl UdpServices {
    fn serves(&mut self, port: u16) -> bool {
        if self
            .scanned
            .is_none_or(|t| t.elapsed() >= Duration::from_secs(30))
        {
            let sys = self.sys.get_or_insert_with(sysinfo::System::new);
            // 读不到监听表时保留上一份，不把服务回包误报成出站
            if let Ok(list) = super::inventory_win::scan(sys) {
                self.ports = list
                    .into_iter()
                    .filter(|l| l.proto == Proto::Udp)
                    .map(|l| l.port)
                    .collect();
            }
            self.scanned = Some(Instant::now());
        }
        self.ports.contains(&port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reportable_filters_noise() {
        let lan: IpAddr = "192.168.1.7".parse().unwrap();
        let web: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(reportable(lan, web), "普通出站应上报");
        assert!(!reportable("127.0.0.1".parse().unwrap(), web));
        assert!(!reportable(lan, "127.0.0.1".parse().unwrap()));
        assert!(!reportable(lan, "0.0.0.0".parse().unwrap()));
        assert!(!reportable("::".parse().unwrap(), web));
        assert!(!reportable(lan, "::1".parse().unwrap()));
        assert!(
            !reportable(lan, "239.255.255.250".parse().unwrap()),
            "SSDP 组播"
        );
        assert!(!reportable(lan, "255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn ports_are_network_byte_order() {
        // 实机勘定：连接 80 端口时原始字段值是 20480，18080 是 41030
        assert_eq!(u16::from_be(20480), 80);
        assert_eq!(u16::from_be(47873), 443);
        assert_eq!(u16::from_be(41030), 18080);
    }

    #[test]
    fn event_ids() {
        assert_eq!(kind_of(12), Some(Kind::TcpOut));
        assert_eq!(kind_of(28), Some(Kind::TcpOut));
        assert_eq!(kind_of(15), Some(Kind::TcpIn));
        assert_eq!(kind_of(31), Some(Kind::TcpIn));
        assert_eq!(kind_of(42), Some(Kind::UdpOut));
        assert_eq!(kind_of(58), Some(Kind::UdpOut));
        for id in [10, 11, 13, 18, 26, 27, 29, 43, 59] {
            assert_eq!(kind_of(id), None, "{id}");
        }
    }

    /// 入站：对端是发起方在前，进程是监听进程，不回填域名；出站本机在前
    #[test]
    fn direction_follows_initiator() {
        let raw = Raw {
            pid: 3056,
            local: "10.1.1.173".parse().unwrap(),
            lport: 18080,
            remote: "10.1.1.2".parse().unwrap(),
            rport: 51000,
        };
        let known = || (uuid::Uuid::new_v4(), Some("svc.exe".into()), None, None);
        let inbound = netwatch::conn_event("a", &conn_info(Kind::TcpIn, &raw, known()));
        assert_eq!(inbound.conn_tuple, "tcp:10.1.1.2:51000>10.1.1.173:18080");
        let v: serde_json::Value = serde_json::from_str(&inbound.raw_json).unwrap();
        assert_eq!(v["connection_info"]["direction"], "inbound");
        assert_eq!(v["process"]["pid"], 3056);

        dnsnames::remember("svc.example", raw.remote, Duration::from_secs(60));
        let udp = netwatch::conn_event("a", &conn_info(Kind::UdpOut, &raw, known()));
        assert_eq!(udp.conn_tuple, "udp:10.1.1.173:18080>10.1.1.2:51000");
        let v: serde_json::Value = serde_json::from_str(&udp.raw_json).unwrap();
        assert_eq!(v["connection_info"]["direction"], "outbound");
        assert_eq!(v["dst_endpoint"]["hostname"], "svc.example");
        let v: serde_json::Value = serde_json::from_str(&inbound.raw_json).unwrap();
        assert!(v["dst_endpoint"].get("hostname").is_none());
    }

    #[test]
    fn samplers_are_per_direction() {
        let raw = Raw {
            pid: 1,
            local: "10.0.0.2".parse().unwrap(),
            lport: 3389,
            remote: "10.0.0.9".parse().unwrap(),
            rport: 50000,
        };
        let mut s = Samplers::default();
        assert!(s.should_report(Kind::TcpIn, &raw));
        assert!(
            !s.should_report(
                Kind::TcpIn,
                &Raw {
                    rport: 50001,
                    ..raw
                }
            ),
            "同一对端连同一服务只报一次"
        );
        assert!(s.should_report(Kind::TcpOut, &raw));
        assert!(s.should_report(Kind::UdpOut, &raw));

        // 发往 53：Dnscache 先报过同一台服务器，自己发 DNS 报文的进程照样报一次
        let dns = |pid| Raw {
            pid,
            rport: DNS_PORT,
            ..raw
        };
        assert!(s.should_report(Kind::UdpOut, &dns(2148)));
        assert!(!s.should_report(Kind::UdpOut, &dns(2148)));
        assert!(
            s.should_report(Kind::UdpOut, &dns(4600)),
            "nslookup 不被 Dnscache 压掉"
        );
    }
}
