//! 本机 DNS 应答里见过的地址 → 域名。出站连接事件按目的地址回填 dst_endpoint.hostname：
//! Linux 由 AF_PACKET 抓到的应答喂，Windows 由 DNS-Client ETW 的查询结果喂。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 表上限，超过即清理过期项，防止查询风暴撑爆内存
const MAX_TRACKED: usize = 8192;

fn answers() -> &'static Mutex<HashMap<IpAddr, (String, Instant)>> {
    static ANSWERS: OnceLock<Mutex<HashMap<IpAddr, (String, Instant)>>> = OnceLock::new();
    ANSWERS.get_or_init(Default::default)
}

/// 记住 ip 是 name 解析出来的，ttl 内有效。同一地址后来的解析覆盖先前的
pub fn remember(name: &str, ip: IpAddr, ttl: Duration) {
    let now = Instant::now();
    let mut names = answers().lock().unwrap_or_else(|e| e.into_inner());
    if names.len() >= MAX_TRACKED {
        names.retain(|_, (_, until)| now < *until);
        if names.len() >= MAX_TRACKED {
            names.clear();
        }
    }
    names.insert(ip, (name.to_string(), now + ttl));
}

/// 目的地址最近一次被解析时的域名，没见过或已过期返回 None（默认构建没有连接采集，只有单测用到）
#[cfg_attr(all(target_os = "linux", not(feature = "ebpf")), allow(dead_code))]
pub fn hostname_of(ip: IpAddr) -> Option<String> {
    let names = answers().lock().unwrap_or_else(|e| e.into_inner());
    names
        .get(&ip)
        .filter(|(_, until)| Instant::now() < *until)
        .map(|(name, _)| name.clone())
}

/// DNS 记录类型的名字，事件里 query.type 与 answers[].type 用
pub fn qtype_name(t: u16) -> String {
    match t {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        t => format!("TYPE{t}"),
    }
}
