//! 操作系统显示名（发行版 + 版本），随设备清单（class 5001 的 `device.os`）上报，
//! server 物化到资产上、覆盖文档导入时声明的值。注册请求仍只上报 family
//! （`std::env::consts::OS`），Sigma 求值过滤与自动升级选包不受影响。
//!
//! Linux 读 os-release（麒麟、统信等国产发行版同样遵循 freedesktop 规范）；
//! Windows 读注册表 ProductName / DisplayVersion / build。解析逻辑全部是
//! 纯函数，Linux CI 上就能测；平台函数只做取数。

/// 显示名最长 128 字符，与 server 侧 assetmap 的清洗上限一致
const MAX_LEN: usize = 128;

/// 拿不到（无 os-release、注册表读失败）就返回 None——宁可缺，也不猜。
#[cfg(target_os = "linux")]
pub fn display() -> Option<String> {
    // 规范位置 /etc/os-release，个别发行版只放 /usr/lib/os-release
    for path in ["/etc/os-release", "/usr/lib/os-release"] {
        if let Ok(content) = std::fs::read_to_string(path)
            && let Some(name) = os_release_display(&content)
        {
            return Some(truncate(name));
        }
    }
    None
}

#[cfg(target_os = "windows")]
pub fn display() -> Option<String> {
    const CV: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    windows_display(
        reg_sz(CV, "ProductName"),
        // Win10 20H2 起是 DisplayVersion（如 22H2），更早只有 ReleaseId（如 2004）
        reg_sz(CV, "DisplayVersion").or_else(|| reg_sz(CV, "ReleaseId")),
        reg_sz(CV, "CurrentBuildNumber"),
    )
    .map(truncate)
}

/// 解析 os-release 内容：优先 PRETTY_NAME，其次 NAME（拼上 VERSION_ID）。
/// 只有 Linux 的 display() 会调用；Windows 目标下仅供单测编译
#[cfg(any(target_os = "linux", test))]
pub(crate) fn os_release_display(content: &str) -> Option<String> {
    let (mut pretty, mut name, mut version) = (None, None, None);
    for line in content.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let v = unquote(v.trim());
        match k.trim() {
            "PRETTY_NAME" => pretty = Some(v),
            "NAME" => name = Some(v),
            "VERSION_ID" => version = Some(v),
            _ => {}
        }
    }
    if pretty.as_deref().is_some_and(|s| !s.is_empty()) {
        return pretty;
    }
    match (
        name.filter(|s| !s.is_empty()),
        version.filter(|s| !s.is_empty()),
    ) {
        (Some(n), Some(v)) => Some(format!("{n} {v}")),
        (Some(n), None) => Some(n),
        _ => None,
    }
}

/// 组装 Windows 显示名：ProductName + 版本号 + build。只有 Windows 的
/// display() 会调用；Linux 目标下仅供单测编译
#[cfg(any(target_os = "windows", test))]
pub(crate) fn windows_display(
    product: Option<String>,
    version: Option<String>,
    build: Option<String>,
) -> Option<String> {
    let product = product.filter(|s| !s.trim().is_empty())?;
    let mut out = product.trim().to_string();
    if let Some(v) = version.filter(|s| !s.trim().is_empty()) {
        out.push(' ');
        out.push_str(v.trim());
    }
    if let Some(b) = build.filter(|s| !s.trim().is_empty()) {
        out.push_str(&format!(" (build {})", b.trim()));
    }
    Some(out)
}

#[cfg(any(target_os = "linux", test))]
fn unquote(v: &str) -> String {
    if v.len() >= 2
        && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')))
    {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

/// 按字符截断，避免把多字节字符切成一半（发行版名可能含中文，如「银河麒麟」）
fn truncate(s: String) -> String {
    if s.chars().count() <= MAX_LEN {
        return s;
    }
    s.chars().take(MAX_LEN).collect()
}

/// 读 HKLM 下的字符串值。只服务本模块这一处，不抽公共注册表封装。
#[cfg(target_os = "windows")]
fn reg_sz(key: &str, name: &str) -> Option<String> {
    use windows_sys::Win32::System::Registry::{
        HKEY_LOCAL_MACHINE, KEY_READ, REG_EXPAND_SZ, REG_SZ, RegCloseKey, RegOpenKeyExW,
        RegQueryValueExW,
    };
    let to_w = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let (key_w, name_w) = (to_w(key), to_w(name));
    let mut handle = std::ptr::null_mut();
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_w.as_ptr(), 0, KEY_READ, &mut handle) } != 0 {
        return None;
    }
    let mut kind = 0u32;
    let mut buf = [0u8; 512];
    let mut len = buf.len() as u32;
    let rc = unsafe {
        RegQueryValueExW(
            handle,
            name_w.as_ptr(),
            std::ptr::null(),
            &mut kind,
            buf.as_mut_ptr(),
            &mut len,
        )
    };
    unsafe { RegCloseKey(handle) };
    if rc != 0 || (kind != REG_SZ && kind != REG_EXPAND_SZ) {
        return None;
    }
    let words: Vec<u16> = buf[..(len as usize).min(buf.len())]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let text = String::from_utf16_lossy(&words);
    Some(text.trim_end_matches(['\0', '\r', '\n']).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_prefers_pretty_name() {
        let content = "NAME=\"Ubuntu\"\nVERSION=\"24.04.1 LTS\"\nID=ubuntu\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nVERSION_ID=\"24.04\"\n";
        assert_eq!(
            os_release_display(content),
            Some("Ubuntu 24.04.1 LTS".to_string())
        );
    }

    #[test]
    fn os_release_domestic_distributions() {
        // 银河麒麟服务器的 PRETTY_NAME 带「剑」等版本代号，统信走同一规范
        let kylin = "NAME=\"Kylin Linux Advanced Server\"\nVERSION_ID=\"V10\"\nPRETTY_NAME=\"Kylin Linux Advanced Server V10 (Sword)\"\nID=kylin\n";
        assert_eq!(
            os_release_display(kylin),
            Some("Kylin Linux Advanced Server V10 (Sword)".to_string())
        );
        let uos = "NAME=\"UnionTech OS Server\"\nVERSION_ID=\"20\"\nPRETTY_NAME=\"UnionTech OS Server 20E\"\nID=uos\n";
        assert_eq!(
            os_release_display(uos),
            Some("UnionTech OS Server 20E".to_string())
        );
    }

    #[test]
    fn os_release_falls_back_to_name_and_version() {
        let content = "NAME=Debian GNU/Linux\nVERSION_ID=12\nID=debian\n";
        assert_eq!(
            os_release_display(content),
            Some("Debian GNU/Linux 12".to_string())
        );
    }

    #[test]
    fn os_release_tolerates_crlf_and_spacing() {
        let content = "NAME = \"Rocky Linux\" \r\nVERSION_ID=\"9\"\r\n";
        assert_eq!(
            os_release_display(content),
            Some("Rocky Linux 9".to_string())
        );
    }

    #[test]
    fn os_release_without_name_is_none() {
        assert_eq!(os_release_display("VERSION_ID=1\nID=x\n"), None);
        assert_eq!(os_release_display(""), None);
    }

    #[test]
    fn windows_display_composes_parts() {
        assert_eq!(
            windows_display(
                Some("Windows 11 Pro".into()),
                Some("24H2".into()),
                Some("26100".into())
            ),
            Some("Windows 11 Pro 24H2 (build 26100)".to_string())
        );
        assert_eq!(
            windows_display(
                Some("Windows Server 2022 Standard".into()),
                None,
                Some("20348".into())
            ),
            Some("Windows Server 2022 Standard (build 20348)".to_string())
        );
        assert_eq!(
            windows_display(Some("Windows 10 企业版".into()), Some("22H2".into()), None),
            Some("Windows 10 企业版 22H2".to_string())
        );
        assert_eq!(
            windows_display(None, Some("24H2".into()), Some("26100".into())),
            None
        );
        assert_eq!(windows_display(Some("   ".into()), None, None), None);
    }

    #[test]
    fn truncate_cuts_by_char_not_byte() {
        let long = "银河麒麟操作系统".repeat(30); // 210 个字符
        let cut = truncate(long);
        assert_eq!(cut.chars().count(), MAX_LEN);
        // 每个汉字 3 字节，切口落在整字符边界上
        assert_eq!(cut.len() % 3, 0);
        assert_eq!(truncate("Ubuntu 24.04".to_string()), "Ubuntu 24.04");
    }
}
