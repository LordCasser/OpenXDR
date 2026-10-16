//! 在线接入：私钥在本机生成、永不离开主机，server 只拿 CSR 签发主机绑定证书。
//!
//! 安装脚本负责 HTTP，agent 负责密码学与文件：
//!   openxdr-agent enroll-request <目录>  生成私钥，向 stdout 输出接入请求 JSON
//!   openxdr-agent enroll-apply <目录>    从 stdin 读 server 应答，写证书与 agent.env
//! 主机名与 agent 注册时用的是同一个来源，签出来的证书必然对得上。

use std::io::Read;
use std::path::Path;

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use serde::Deserialize;

pub fn hostname() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

/// 生成私钥（0600）与 CSR，返回接入请求 JSON。
pub fn request(dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    let host = hostname();
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("host:{host}"));
    params.distinguished_name = dn;
    let csr = params.serialize_request(&key)?.pem()?;
    write_private(&dir.join("agent.key"), key.serialize_pem().as_bytes())?;
    Ok(serde_json::json!({ "hostname": host, "os": std::env::consts::OS, "csr": csr }).to_string())
}

#[derive(Deserialize)]
struct Grant {
    server: String,
    #[serde(default)]
    ca: String,
    #[serde(default)]
    cert: String,
}

/// 写入 server 签发的证书与连接配置。server 未启用 mTLS 时应答里没有证书，只写地址。
pub fn apply(dir: &Path, mut input: impl Read) -> Result<(), Box<dyn std::error::Error>> {
    let mut body = String::new();
    input.read_to_string(&mut body)?;
    let grant: Grant =
        serde_json::from_str(&body).map_err(|e| format!("接入应答无法解析（{e}）：{body}"))?;
    if grant.server.is_empty() || grant.server.contains(['\n', '\r']) {
        return Err("接入应答缺少有效的 server 地址".into());
    }
    let mut env = format!("OPENXDR_SERVER={}\n", grant.server);
    if !grant.cert.is_empty() {
        let (ca, cert, key) = (
            dir.join("ca.crt"),
            dir.join("agent.crt"),
            dir.join("agent.key"),
        );
        if !key.exists() {
            return Err("缺少私钥，先执行 enroll-request".into());
        }
        std::fs::write(&ca, &grant.ca)?;
        std::fs::write(&cert, &grant.cert)?;
        env += &format!(
            "OPENXDR_CA={}\nOPENXDR_CERT={}\nOPENXDR_KEY={}\n",
            ca.display(),
            cert.display(),
            key.display()
        );
    }
    write_private(&dir.join("agent.env"), env.as_bytes())?;
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)
}

/// Windows 上目录 ACL 由安装脚本收紧到 SYSTEM 与管理员
#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
}

/// 默认配置文件位置：systemd 已经用 EnvironmentFile 读它，Windows 计划任务没有这种机制，由 agent 自己读。
pub fn default_env_file() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
        Path::new(&base).join("OpenXDR").join("agent.env")
    }
    #[cfg(not(windows))]
    {
        "/etc/openxdr/agent.env".into()
    }
}

/// 读 KEY=VALUE 配置文件，进程环境里已有的变量优先。文件不存在不是错误。
pub fn load_env_file(path: &Path) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    for (key, value) in parse_env(&text) {
        if std::env::var_os(key).is_none() {
            // SAFETY: 在 main 起任何线程之前调用
            unsafe { std::env::set_var(key, value) };
        }
    }
}

fn parse_env(text: &str) -> impl Iterator<Item = (&str, &str)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim(), v.trim()))
        .filter(|(k, _)| k.starts_with("OPENXDR_"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_then_apply_writes_config() {
        let dir = std::env::temp_dir().join(format!("openxdr-enroll-{}", std::process::id()));
        let req: serde_json::Value = serde_json::from_str(&request(&dir).unwrap()).unwrap();
        assert_eq!(req["hostname"], hostname());
        assert!(req["csr"].as_str().unwrap().contains("CERTIFICATE REQUEST"));
        assert!(dir.join("agent.key").exists());

        let grant = r#"{"server":"https://10.0.0.1:8081","ca":"CA","cert":"CERT"}"#;
        apply(&dir, grant.as_bytes()).unwrap();
        let env = std::fs::read_to_string(dir.join("agent.env")).unwrap();
        assert!(env.starts_with("OPENXDR_SERVER=https://10.0.0.1:8081\n"));
        assert!(env.contains("OPENXDR_KEY="));
        assert_eq!(
            std::fs::read_to_string(dir.join("agent.crt")).unwrap(),
            "CERT"
        );

        // 明文部署：只写地址
        apply(&dir, r#"{"server":"http://10.0.0.1:8081"}"#.as_bytes()).unwrap();
        let env = std::fs::read_to_string(dir.join("agent.env")).unwrap();
        assert_eq!(env, "OPENXDR_SERVER=http://10.0.0.1:8081\n");

        assert!(
            apply(&dir, "未授权".as_bytes()).is_err(),
            "非 JSON 应答应报错"
        );
        assert!(
            apply(&dir, r#"{"server":"x\nOPENXDR_KEY=/tmp/evil"}"#.as_bytes()).is_err(),
            "地址里带换行不能注入配置"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn parses_env_file() {
        let text = "# 注释\nOPENXDR_SERVER = https://x:8081\n\nPATH=/evil\nOPENXDR_CA=/etc/openxdr/ca.crt\n";
        let got: Vec<_> = parse_env(text).collect();
        assert_eq!(
            got,
            vec![
                ("OPENXDR_SERVER", "https://x:8081"),
                ("OPENXDR_CA", "/etc/openxdr/ca.crt")
            ]
        );
    }
}
