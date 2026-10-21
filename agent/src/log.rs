//! 日志出口。全 crate 的 eprintln! 都经这里（main.rs 在所有模块之前定义同名宏，
//! 按文本作用域盖住 std 的，调用点不用改）。
//!
//! Linux 照旧写 stderr，由 systemd 交给 journald（自带时间与 pid）。Windows 上 agent 由 SYSTEM
//! 计划任务拉起，stderr 没人接，常驻模式下改写 `C:\ProgramData\OpenXDR\logs\agent.log`：
//! 每行带 UTC 时间与 pid，按大小滚动。写入是同步的——升级、身份变化之后紧跟着 exit，
//! 最后几行恰恰最要紧，不能留在后台线程的缓冲里随进程一起丢。
//! 目录建在 OpenXDR 目录下，继承安装脚本给它设的权限（只有 SYSTEM 与管理员）。

// 文件出口只有 Windows 用，其他平台只剩单测在用
#![cfg_attr(not(windows), allow(dead_code))]

use std::fmt;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// 单个文件上限，超过就滚动
const MAX_BYTES: u64 = 10 * 1024 * 1024;
/// 连同正在写的一共留几份：agent.log、agent.log.1 … agent.log.4
const KEEP: usize = 5;

static FILE: OnceLock<Mutex<Rotating>> = OnceLock::new();

/// 写一行日志：已切到文件就写文件，否则写 stderr
pub fn line(args: fmt::Arguments) {
    match FILE.get() {
        Some(file) => {
            let text = format!("{} [{}] {args}\n", utc_now(), std::process::id());
            file.lock()
                .unwrap_or_else(|e| e.into_inner())
                .write(text.as_bytes());
        }
        None => std::eprintln!("{args}"),
    }
}

/// Windows 常驻模式：之后的日志写到滚动文件，panic 也记进去。打不开就留在 stderr，
/// 不为日志耽误采集
#[cfg(windows)]
pub fn to_file() {
    let base = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
    let dir = Path::new(&base).join("OpenXDR").join("logs");
    let opened = std::fs::create_dir_all(&dir)
        .and_then(|()| Rotating::open(dir.join("agent.log"), MAX_BYTES, KEEP));
    match opened {
        Ok(file) => {
            let _ = FILE.set(Mutex::new(file));
            std::panic::set_hook(Box::new(|info| {
                let thread = std::thread::current();
                line(format_args!(
                    "线程 {} panic：{info}",
                    thread.name().unwrap_or("<unnamed>")
                ))
            }));
        }
        Err(e) => std::eprintln!("日志文件打不开（{e}），日志留在 stderr"),
    }
}

/// 按大小滚动的日志文件。多个实例（升级交接时新旧两个）可以同时追加同一个文件：
/// 各自记各自写了多少，谁先到上限谁滚动；另一个手里的句柄跟着改名后的文件走，
/// 到它自己的上限再滚动，行上的 pid 分得清是谁写的
struct Rotating {
    path: PathBuf,
    file: File,
    size: u64,
    max: u64,
    keep: usize,
}

impl Rotating {
    fn open(path: PathBuf, max: u64, keep: usize) -> std::io::Result<Self> {
        let file = append(&path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path,
            file,
            size,
            max,
            keep,
        })
    }

    fn write(&mut self, line: &[u8]) {
        let len = line.len() as u64;
        if self.size > 0 && self.size + len > self.max {
            self.rotate();
        }
        if self.file.write_all(line).is_ok() {
            self.size += len;
        }
    }

    /// 依次后挪一位，最老的一份被覆盖；改名失败（被别的进程占着）就作罢，
    /// 计数照样清零，下一轮上限再试，不每行都去碰文件系统
    fn rotate(&mut self) {
        for i in (1..self.keep).rev() {
            let _ = std::fs::rename(nth(&self.path, i - 1), nth(&self.path, i));
        }
        if let Ok(file) = append(&self.path) {
            self.file = file;
        }
        self.size = 0;
    }
}

/// 第 n 份：0 是正在写的 agent.log，之后是 agent.log.n
fn nth(path: &Path, n: usize) -> PathBuf {
    if n == 0 {
        return path.to_path_buf();
    }
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{n}"));
    name.into()
}

/// 追加打开；Windows 上 std 默认带 FILE_SHARE_DELETE，别的进程开着也能改名滚动
fn append(path: &Path) -> std::io::Result<File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
}

fn utc_now() -> String {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format_utc(since.as_secs(), since.subsec_millis())
}

/// Unix 秒 → `2026-10-21T02:07:30.123Z`（公历换算按 Howard Hinnant 的 civil_from_days）
fn format_utc(secs: u64, millis: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_format() {
        assert_eq!(format_utc(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_utc(951_782_400, 5), "2000-02-29T00:00:00.005Z");
        assert_eq!(format_utc(1_792_519_650, 123), "2026-10-20T18:07:30.123Z");
    }

    /// 写满就滚动：最多留 keep 份，最新的在 agent.log，越老编号越大，更老的被挤掉
    #[test]
    fn rotates_by_size() {
        let dir = std::env::temp_dir().join(format!("openxdr-log-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("agent.log");
        std::fs::write(&path, "旧内容\n").unwrap();
        let mut log = Rotating::open(path.clone(), 10, 3).unwrap();
        assert_eq!(
            log.size,
            "旧内容\n".len() as u64,
            "续写已有文件，从已有大小算起"
        );
        for i in 0..5 {
            log.write(format!("line{i}\n").as_bytes());
        }
        let read = |n| std::fs::read_to_string(nth(&path, n)).unwrap();
        assert_eq!(read(0), "line4\n");
        assert_eq!(read(1), "line3\n");
        assert_eq!(read(2), "line2\n");
        assert!(!nth(&path, 3).exists(), "超出份数的被挤掉");

        // 单行超过上限也照写，不陷入每行都滚动
        log.write(b"0123456789abcdef\n");
        assert_eq!(read(0), "0123456789abcdef\n");
        assert_eq!(read(1), "line4\n");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
