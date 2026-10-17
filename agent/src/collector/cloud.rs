//! 云环境识别：启动时探一次各家实例元数据服务（IMDS），认出厂商、实例 ID、
//! 地域与公网 IP，挂到资产清单事件上。
//!
//! 不引 HTTP crate：元数据服务都是链路本地明文 HTTP/1.1，手写一个只发一次
//! 请求、`Connection: close`、读到 EOF 的最小客户端足够。所有超时都很短，
//! 非云主机上整轮探测在一秒左右结束。
//!
//! 失败策略：任何一步拿不准（状态码不对、缺厂商特征头、值不合规）就当
//! "未识别"，宁可不报也不报错的云身份。

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cloud {
    pub provider: &'static str,
    pub instance_id: String,
    pub region: Option<String>,
    pub public_ip: Option<IpAddr>,
}

const CONNECT_TIMEOUT: Duration = Duration::from_millis(300);
const IO_TIMEOUT: Duration = Duration::from_secs(1);
/// 响应上限；元数据单项都很小，超出即视为异常
const MAX_RESPONSE: usize = 64 * 1024;
/// 单个元数据值长度上限
const MAX_VALUE_LEN: usize = 128;

/// AWS / Azure / GCP 共用的链路本地地址
const IMDS_LINK_LOCAL: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
const ALIYUN_IMDS: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 200);
const TENCENT_IMDS: Ipv4Addr = Ipv4Addr::new(169, 254, 0, 23);
const TENCENT_HOST: &str = "metadata.tencentyun.com";

/// 按顺序探测，认出一家即止；结果打一行日志。
pub fn detect() -> Option<Cloud> {
    let cloud = probe_link_local()
        .or_else(probe_aliyun)
        .or_else(probe_tencent);
    match &cloud {
        Some(c) => eprintln!("云环境: {} {}", c.provider, c.instance_id),
        None => eprintln!("云环境: 未识别"),
    }
    cloud
}

/// 169.254.169.254 能连上才逐家试 Azure → GCP → AWS
fn probe_link_local() -> Option<Cloud> {
    let addr = SocketAddr::from((IMDS_LINK_LOCAL, 80));
    TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).ok()?;
    let imds = Imds {
        addr,
        host: "169.254.169.254",
    };
    probe_azure(&imds)
        .or_else(|| probe_gcp(&imds))
        .or_else(|| probe_aws(&imds))
}

fn probe_azure(imds: &Imds) -> Option<Cloud> {
    let resp = imds.get(
        "/metadata/instance?api-version=2021-02-01",
        &[("Metadata", "true")],
    )?;
    parse_azure(&resp)
}

fn probe_gcp(imds: &Imds) -> Option<Cloud> {
    const FLAVOR: (&str, &str) = ("Metadata-Flavor", "Google");
    let id = imds.get("/computeMetadata/v1/instance/id", &[FLAVOR])?;
    // 缺 Metadata-Flavor: Google 回应头的不是 GCP（可能是兼容实现或中间设备）
    if id.header("metadata-flavor") != Some("Google") {
        return None;
    }
    let instance_id = id.value()?;
    let region = imds
        .get("/computeMetadata/v1/instance/zone", &[FLAVOR])
        .and_then(|r| r.value())
        .and_then(|z| gcp_region(&z));
    let public_ip = imds
        .get(
            "/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip",
            &[FLAVOR],
        )
        .and_then(|r| r.ip());
    Some(Cloud {
        provider: "gcp",
        instance_id,
        region,
        public_ip,
    })
}

/// IMDSv2 优先：先 PUT 拿令牌，拿不到（v1-only 或被禁）退回不带令牌的 GET
fn probe_aws(imds: &Imds) -> Option<Cloud> {
    let token = imds
        .request(
            "PUT",
            "/latest/api/token",
            &[("X-aws-ec2-metadata-token-ttl-seconds", "60")],
        )
        .and_then(|r| r.value());
    let auth: Vec<(&str, &str)> = token
        .as_deref()
        .map(|t| vec![("X-aws-ec2-metadata-token", t)])
        .unwrap_or_default();
    let get = |path: &str| imds.get(path, &auth);

    let instance_id = get("/latest/meta-data/instance-id")
        .and_then(|r| r.value())
        .filter(|id| is_aws_instance_id(id))?;
    // OpenStack 等在同一地址提供 EC2 兼容接口，实例 ID 格式一样，但没有 placement/region；
    // 拿不到 region 就不认作 AWS，宁可不报也不错报
    let region = get("/latest/meta-data/placement/region").and_then(|r| r.value())?;
    Some(Cloud {
        provider: "aws",
        instance_id,
        region: Some(region),
        public_ip: get("/latest/meta-data/public-ipv4").and_then(|r| r.ip()),
    })
}

fn probe_aliyun() -> Option<Cloud> {
    let imds = Imds {
        addr: SocketAddr::from((ALIYUN_IMDS, 80)),
        host: "100.100.100.200",
    };
    let get = |path: &str| imds.get(path, &[]);
    let instance_id = get("/latest/meta-data/instance-id")
        .and_then(|r| r.value())
        .filter(|id| id.starts_with("i-"))?;
    Some(Cloud {
        provider: "aliyun",
        instance_id,
        region: get("/latest/meta-data/region-id").and_then(|r| r.value()),
        public_ip: get("/latest/meta-data/eipv4")
            .and_then(|r| r.ip())
            .or_else(|| get("/latest/meta-data/public-ipv4").and_then(|r| r.ip())),
    })
}

fn probe_tencent() -> Option<Cloud> {
    let imds = Imds {
        addr: SocketAddr::from((TENCENT_IMDS, 80)),
        host: TENCENT_HOST,
    };
    let get = |path: &str| imds.get(path, &[]);
    let instance_id = get("/latest/meta-data/instance-id")
        .and_then(|r| r.value())
        .filter(|id| id.starts_with("ins-"))?;
    Some(Cloud {
        provider: "tencent",
        instance_id,
        region: get("/latest/meta-data/placement/region").and_then(|r| r.value()),
        public_ip: get("/latest/meta-data/public-ipv4").and_then(|r| r.ip()),
    })
}

/// 一个元数据服务端点
struct Imds {
    addr: SocketAddr,
    host: &'static str,
}

impl Imds {
    /// GET，且只认 200
    fn get(&self, path: &str, headers: &[(&str, &str)]) -> Option<Response> {
        self.request("GET", path, headers)
    }

    /// 发一次请求；连不上、超时、非 200、响应畸形一律 None
    fn request(&self, method: &str, path: &str, headers: &[(&str, &str)]) -> Option<Response> {
        let mut stream = TcpStream::connect_timeout(&self.addr, CONNECT_TIMEOUT).ok()?;
        stream.set_read_timeout(Some(IO_TIMEOUT)).ok()?;
        stream.set_write_timeout(Some(IO_TIMEOUT)).ok()?;
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\n",
            self.host
        );
        if method != "GET" {
            req.push_str("Content-Length: 0\r\n");
        }
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).ok()?;

        let mut raw = Vec::new();
        stream
            .take(MAX_RESPONSE as u64 + 1)
            .read_to_end(&mut raw)
            .ok()?;
        if raw.len() > MAX_RESPONSE {
            return None;
        }
        parse_response(&raw).filter(|r| r.status == 200)
    }
}

#[derive(Debug)]
struct Response {
    status: u16,
    /// 头名统一小写
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Response {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// 正文当作单个元数据值
    fn value(&self) -> Option<String> {
        validate(std::str::from_utf8(&self.body).ok()?)
    }

    fn ip(&self) -> Option<IpAddr> {
        self.value()?.parse().ok()
    }
}

/// 解析完整的 HTTP/1.x 响应：状态行 + 头 + 正文。
/// 正文按 chunked / Content-Length / 读到 EOF 三种方式取，长度对不上即失败。
fn parse_response(raw: &[u8]) -> Option<Response> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&raw[..split]).ok()?;
    let rest = &raw[split + 4..];

    let mut lines = head.split("\r\n");
    let mut status_line = lines.next()?.splitn(3, ' ');
    if !status_line.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let status = status_line.next()?.parse().ok()?;
    let headers = lines
        .map(|l| {
            let (k, v) = l.split_once(':')?;
            Some((k.trim().to_ascii_lowercase(), v.trim().to_string()))
        })
        .collect::<Option<Vec<_>>>()?;

    let mut resp = Response {
        status,
        headers,
        body: Vec::new(),
    };
    resp.body = if resp
        .header("transfer-encoding")
        .is_some_and(|te| te.eq_ignore_ascii_case("chunked"))
    {
        decode_chunked(rest)?
    } else if let Some(len) = resp.header("content-length") {
        rest.get(..len.parse::<usize>().ok()?)?.to_vec()
    } else {
        rest.to_vec()
    };
    Some(resp)
}

/// chunked 正文解码；缺块尾或缺终止块视为截断，失败
fn decode_chunked(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = data.windows(2).position(|w| w == b"\r\n")?;
        let size_line = std::str::from_utf8(&data[..eol]).ok()?;
        let size_hex = size_line.split(';').next()?.trim();
        let size = usize::from_str_radix(size_hex, 16).ok()?;
        data = &data[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(data.get(..size)?);
        data = data.get(size..)?.strip_prefix(b"\r\n")?;
    }
}

/// 元数据值校验：去首尾空白后非空、仅可见 ASCII、不超长
fn validate(s: &str) -> Option<String> {
    let s = s.trim();
    (!s.is_empty() && s.len() <= MAX_VALUE_LEN && s.bytes().all(|b| b.is_ascii_graphic()))
        .then(|| s.to_string())
}

/// AWS 实例 ID：i- 后跟 8 或 17 位十六进制。格式卡严一点，挡掉在
/// 169.254.169.254 上提供 EC2 兼容接口的其他平台的随意取值
fn is_aws_instance_id(id: &str) -> bool {
    id.strip_prefix("i-").is_some_and(|hex| {
        matches!(hex.len(), 8 | 17) && hex.bytes().all(|b| b.is_ascii_hexdigit())
    })
}

/// GCP zone 全路径 → 地域：projects/N/zones/us-central1-a → us-central1
fn gcp_region(zone: &str) -> Option<String> {
    let zone = zone.rsplit('/').next()?;
    let (region, suffix) = zone.rsplit_once('-')?;
    if region.is_empty() || suffix.is_empty() {
        return None;
    }
    validate(region)
}

/// Azure 实例元数据 JSON：要求 200 + 可解析 + vmId 非空
fn parse_azure(resp: &Response) -> Option<Cloud> {
    let v: Value = serde_json::from_slice(&resp.body).ok()?;
    let text = |p: &Value| p.as_str().and_then(validate);
    let instance_id = text(&v["compute"]["vmId"])?;
    Some(Cloud {
        provider: "azure",
        instance_id,
        region: text(&v["compute"]["location"]),
        public_ip: text(&v["network"]["interface"][0]["ipv4"]["ipAddress"][0]["publicIpAddress"])
            .and_then(|s| s.parse().ok()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(raw: &str) -> Response {
        parse_response(raw.as_bytes()).expect("响应应能解析")
    }

    #[test]
    fn parses_content_length_and_eof_bodies() {
        let r = resp(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 10\r\n\r\ni-abc12345trailing",
        );
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"i-abc12345");
        assert_eq!(r.header("content-type"), Some("text/plain"));

        let r = resp("HTTP/1.0 404 Not Found\r\nServer: x\r\n\r\nnot here");
        assert_eq!(r.status, 404);
        assert_eq!(r.body, b"not here");

        // Content-Length 比实际正文长：截断，失败
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\nshort").is_none());
        // 头没收完
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n").is_none());
        // 不是 HTTP
        assert!(parse_response(b"SSH-2.0-OpenSSH\r\n\r\n").is_none());
    }

    #[test]
    fn parses_chunked_body() {
        let r = resp(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nus-e\r\n5;ext=1\r\nast-1\r\n0\r\n\r\n",
        );
        assert_eq!(r.body, b"us-east-1");
        // 缺终止块：截断
        assert!(
            parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nus-e\r\n")
                .is_none()
        );
        // 块长不符
        assert!(
            parse_response(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nus\r\n0\r\n\r\n"
            )
            .is_none()
        );
    }

    #[test]
    fn gcp_flavor_header_is_case_insensitive_name() {
        let r = resp(
            "HTTP/1.1 200 OK\r\nmetadata-flavor: Google\r\nContent-Length: 19\r\n\r\n1234567890123456789",
        );
        assert_eq!(r.header("metadata-flavor"), Some("Google"));
        assert_eq!(r.value().as_deref(), Some("1234567890123456789"));
    }

    #[test]
    fn validates_values() {
        assert_eq!(validate("  i-abc\n").as_deref(), Some("i-abc"));
        assert!(validate("").is_none());
        assert!(validate("   \n").is_none());
        assert!(validate("a b").is_none(), "多段内容（如目录列表）不是单值");
        assert!(validate("line1\nline2").is_none());
        assert!(validate("中文").is_none());
        assert!(validate(&"x".repeat(129)).is_none());
        assert!(validate(&"x".repeat(128)).is_some());

        let ok = resp("HTTP/1.1 200 OK\r\n\r\n47.1.2.3\n");
        assert_eq!(ok.ip(), Some("47.1.2.3".parse().unwrap()));
        let bad = resp("HTTP/1.1 200 OK\r\n\r\n<html>error</html>");
        assert!(bad.ip().is_none());
    }

    #[test]
    fn aws_instance_id_format() {
        assert!(is_aws_instance_id("i-0123456789abcdef0"));
        assert!(is_aws_instance_id("i-1a2b3c4d"));
        assert!(!is_aws_instance_id("i-"));
        assert!(!is_aws_instance_id("i-xyz"));
        assert!(!is_aws_instance_id("ins-12345678"));
    }

    #[test]
    fn gcp_zone_to_region() {
        assert_eq!(
            gcp_region("projects/123456789/zones/us-central1-a").as_deref(),
            Some("us-central1")
        );
        assert_eq!(
            gcp_region("projects/1/zones/europe-west4-b").as_deref(),
            Some("europe-west4")
        );
        assert!(gcp_region("projects/1/zones/").is_none());
        assert!(gcp_region("nodash").is_none());
    }

    #[test]
    fn azure_json_extraction() {
        let body = r#"{
            "compute": {"vmId": "02aab8a4-74ef-476e-8182-f6d2ba4166a6", "location": "westus", "name": "vm1"},
            "network": {"interface": [{"ipv4": {"ipAddress": [{"privateIpAddress": "10.0.0.4", "publicIpAddress": "13.64.1.2"}]}}]}
        }"#;
        let r = resp(&format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ));
        assert_eq!(
            parse_azure(&r),
            Some(Cloud {
                provider: "azure",
                instance_id: "02aab8a4-74ef-476e-8182-f6d2ba4166a6".into(),
                region: Some("westus".into()),
                public_ip: Some("13.64.1.2".parse().unwrap()),
            })
        );

        // 无公网 IP 时 publicIpAddress 为空串
        let body = r#"{"compute":{"vmId":"abc","location":"eastus"},
            "network":{"interface":[{"ipv4":{"ipAddress":[{"publicIpAddress":""}]}}]}}"#;
        let c = parse_azure(&resp(&format!("HTTP/1.1 200 OK\r\n\r\n{body}"))).unwrap();
        assert_eq!(c.public_ip, None);
        assert_eq!(c.region.as_deref(), Some("eastus"));

        // vmId 缺失或为空、JSON 不可解析：都不认
        assert!(
            parse_azure(&resp(
                "HTTP/1.1 200 OK\r\n\r\n{\"compute\":{\"vmId\":\"\"}}"
            ))
            .is_none()
        );
        assert!(parse_azure(&resp("HTTP/1.1 200 OK\r\n\r\n{\"compute\":{}}")).is_none());
        assert!(parse_azure(&resp("HTTP/1.1 200 OK\r\n\r\nnot json")).is_none());
    }
}
