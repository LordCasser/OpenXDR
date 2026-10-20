//! 登录事件采集（Linux）：增量读 wtmp（成功登录）与 btmp（失败登录），
//! 另跟 journald 里的 sshd 日志。
//!
//! 账号是第二攻击面。syslog 转发只有部分环境配了，agent 直接读登录记录
//! 让认证可见性不依赖外部配置。从文件末尾开始增量读——存量历史不是事件。
//!
//! wtmp 只记分配了 tty 的会话，`ssh host cmd` 这种不开 pty 的远程执行根本
//! 不落 wtmp，而它恰恰是拿到密钥后最常见的用法；Debian 13 又把 wtmp 换成了
//! wtmpdb。所以 SSH 以 sshd 自己的日志为准：journal 可读时，wtmp/btmp 里带
//! 远端地址的记录交给 journal，避免同一次登录报两遍；journal 不可用时照旧。

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::pb::AgentEvent;

use super::{EventSink, sshsession};

/// OCSF Authentication
const CLASS_AUTH: u32 = 3002;

const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// glibc x86_64 的 utmp 记录布局
const RECORD_SIZE: usize = 384;
const MAX_RECORDS_PER_READ: usize = 1024;
const MAX_JOURNAL_LINE: usize = 16 * 1024;
const USER_PROCESS: i16 = 7;

pub fn spawn(agent_id: String, sink: EventSink) {
    std::thread::spawn(move || run(&agent_id, &sink));
}

struct Tail {
    path: &'static str,
    /// true = 该文件记录的是失败登录（btmp）
    failure: bool,
    offset: u64,
    identity: Option<(u64, u64)>,
}

fn run(agent_id: &str, sink: &EventSink) {
    let (mut child, journal) = spawn_sshd_journal(agent_id.to_string(), sink.clone());
    let mut tails = [
        Tail {
            path: "/var/log/wtmp",
            failure: false,
            offset: 0,
            identity: None,
        },
        Tail {
            path: "/var/log/btmp",
            failure: true,
            offset: 0,
            identity: None,
        },
    ];
    // 从当前末尾开始：agent 启动前的历史不重放
    for t in &mut tails {
        if let Ok(meta) = std::fs::metadata(t.path) {
            t.offset = meta.len() / RECORD_SIZE as u64 * RECORD_SIZE as u64;
            t.identity = Some((meta.dev(), meta.ino()));
        }
    }

    // 重连后旧的上报通道关闭，这一轮采集必须跟着退出，连同拉起的 journalctl，不能等下一条登录才发现
    'poll: while !sink.is_closed() {
        std::thread::sleep(POLL_INTERVAL);
        let mut readable = 0;
        for t in &mut tails {
            let ssh_via_journal = journal.load(Ordering::Relaxed);
            let records = match read_new(t) {
                Ok(records) => {
                    readable += 1;
                    records
                }
                Err(_) => continue,
            };
            for rec in records {
                if ssh_via_journal && !rec.host.is_empty() {
                    continue;
                }
                if !sink.send(auth_event(agent_id, &rec, t.failure)) {
                    break 'poll;
                }
            }
        }
        let live = journal.load(Ordering::Relaxed);
        sink.capability("auth", "wtmp-btmp-journald", auth_state(readable, live));
    }
    if let Some(c) = child.as_mut() {
        let _ = c.kill();
        let _ = c.wait();
    }
}

/// 跟 journald 的 sshd 日志，返回 journalctl 子进程（由调用方回收）与存活标志。
/// 标志在 journalctl 存活期间为 true，它退出（没有 systemd、无权读 journal）后 wtmp/btmp 接回远程登录。
fn spawn_sshd_journal(agent_id: String, sink: EventSink) -> (Option<Child>, Arc<AtomicBool>) {
    let alive = Arc::new(AtomicBool::new(false));
    // OpenSSH 9.8 起认证日志出自 sshd-session 进程
    let child = Command::new("journalctl")
        .args([
            "-f",
            "-n",
            "0",
            "-o",
            "json",
            "-t",
            "sshd",
            "-t",
            "sshd-session",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            eprintln!("登录采集: journalctl 不可用（{e}），SSH 登录只看 wtmp/btmp");
            return (None, alive);
        }
    };
    let Some(out) = child.stdout.take() else {
        return (Some(child), alive);
    };
    alive.store(true, Ordering::Relaxed);
    eprintln!("登录采集: wtmp/btmp + journald sshd");

    let flag = alive.clone();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(out);
        let mut rejected = 0u64;
        while let Ok(Some(line)) = read_journal_line(&mut reader) {
            if sink.is_closed() {
                break;
            }
            let Ok(line) = line else {
                rejected = rejected.saturating_add(1);
                if rejected.is_power_of_two() {
                    eprintln!("登录采集: 已拒绝 {rejected} 条超长或非 UTF-8 journal 行");
                }
                continue;
            };
            let Some(entry) = JournalEntry::parse(&line) else {
                continue;
            };
            let Some((mut rec, failure)) = parse_sshd(&entry.message) else {
                continue;
            };
            // 只有内核凭据证明出自 root 身份 sshd 的认证成功日志，才拿来给会话进程打登录归属
            if !failure
                && let Some(pid) = entry.sshd_pid()
                && let Some(login) = sshsession::parse_accepted(&entry.message)
            {
                sshsession::accepted(pid, login.clone());
                rec.login = Some(login);
            }
            if !sink.send(auth_event(&agent_id, &rec, failure)) {
                break;
            }
        }
        flag.store(false, Ordering::Relaxed);
        // 上报通道关了是正常收尾，不是降级
        if !sink.is_closed() {
            eprintln!("登录采集: journalctl 已退出，SSH 登录回落 wtmp/btmp");
        }
    });
    (Some(child), alive)
}

/// journalctl -o json 的一行。MESSAGE 与 SYSLOG_IDENTIFIER 由写日志的进程自己给，谁都能写；
/// _PID / _UID / _COMM 是 journald 从内核取的发送方凭据，客户端伪造不了
struct JournalEntry {
    message: String,
    pid: Option<u32>,
    uid: Option<u32>,
    comm: String,
}

impl JournalEntry {
    fn parse(line: &str) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_str(line).ok()?;
        // 非 UTF-8 的 MESSAGE 会编成字节数组，不是 sshd 的认证日志
        let message = v.get("MESSAGE")?.as_str()?.to_string();
        let field = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or_default();
        Some(Self {
            message,
            pid: field("_PID").parse().ok(),
            uid: field("_UID").parse().ok(),
            comm: field("_COMM").to_string(),
        })
    }

    /// 出自 root 身份 sshd 监控进程的日志返回它的 pid（OpenSSH 9.8 起是 sshd-session）
    fn sshd_pid(&self) -> Option<u32> {
        let sshd = self.comm == "sshd" || self.comm == "sshd-session";
        (self.uid == Some(0) && sshd).then_some(self.pid?)
    }
}

/// 每行最多保留 16 KiB；超限后排到换行，不能把截断前缀当作完整认证日志。
fn read_journal_line(reader: &mut impl BufRead) -> std::io::Result<Option<Result<String, ()>>> {
    let mut line = Vec::new();
    let mut rejected = false;
    let mut seen = false;
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            if !seen {
                return Ok(None);
            }
            break;
        }
        seen = true;
        let newline = chunk.iter().position(|&b| b == b'\n');
        let count = newline.map_or(chunk.len(), |n| n + 1);
        let content = newline.unwrap_or(count);
        if !rejected {
            if line.len() + content > MAX_JOURNAL_LINE {
                rejected = true;
                line.clear();
            } else {
                line.extend_from_slice(&chunk[..content]);
            }
        }
        reader.consume(count);
        if newline.is_some() {
            break;
        }
    }
    if rejected {
        return Ok(Some(Err(())));
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Ok(Some(String::from_utf8(line).map_err(|_| ())))
}

/// 解析 sshd 认证日志，返回 (记录, 是否失败)。
///
/// 无效用户只认 `Invalid user`：随后的 `Failed ... for invalid user` 是同一次尝试。
fn parse_sshd(msg: &str) -> Option<(LoginRecord, bool)> {
    if let Some(rest) = msg.strip_prefix("Accepted ") {
        return Some((sshd_record(rest.split_once(" for ")?.1)?, false));
    }
    if let Some(rest) = msg.strip_prefix("Invalid user ") {
        return Some((sshd_record(rest)?, true));
    }
    let rest = msg.strip_prefix("Failed ")?.split_once(" for ")?.1;
    if rest.starts_with("invalid user ") {
        return None;
    }
    Some((sshd_record(rest)?, true))
}

/// `<user> from <ip> port <n> ...`。用户名由对端控制，从右边切才不会被
/// 伪造的 " from 1.2.3.4" 骗走来源地址。
fn sshd_record(s: &str) -> Option<LoginRecord> {
    let (user, rest) = s.rsplit_once(" from ")?;
    let (host, _) = rest.split_once(" port ")?;
    Some(LoginRecord {
        user: user.to_string(),
        host: host.to_string(),
        line: "sshd".to_string(),
        login: None,
    })
}

struct LoginRecord {
    user: String,
    host: String,
    line: String,
    /// 核对过出处的 sshd 认证成功：认证方式与公钥指纹，事件里写成 login_session
    login: Option<sshsession::Login>,
}

/// 有界读取完整记录；inode 更换或文件缩短时从头读取当前文件。
fn read_new(t: &mut Tail) -> std::io::Result<Vec<LoginRecord>> {
    let mut f = File::open(t.path)?;
    let meta = f.metadata()?;
    let len = meta.len();
    let identity = (meta.dev(), meta.ino());
    if t.identity.is_some_and(|previous| previous != identity) || len < t.offset {
        t.offset = 0;
    }
    t.identity = Some(identity);
    if len == t.offset {
        return Ok(Vec::new());
    }
    f.seek(SeekFrom::Start(t.offset))?;
    let limit = (len - t.offset).min((RECORD_SIZE * MAX_RECORDS_PER_READ) as u64);
    let mut buf = Vec::with_capacity(limit as usize);
    f.take(limit).read_to_end(&mut buf)?;
    let whole = buf.len() - buf.len() % RECORD_SIZE;
    t.offset += whole as u64;
    Ok(buf[..whole]
        .as_chunks::<RECORD_SIZE>()
        .0
        .iter()
        .filter_map(|r| parse_record(r))
        .collect())
}

fn auth_state(readable: usize, journal: bool) -> &'static str {
    match (readable, journal) {
        (2, true) => "active",
        (0, false) => "unavailable",
        _ => "degraded",
    }
}

/// 解析一条 utmp 记录，非登录类型或空用户名返回 None。
fn parse_record(rec: &[u8]) -> Option<LoginRecord> {
    let ut_type = i16::from_le_bytes([rec[0], rec[1]]);
    if ut_type != USER_PROCESS {
        return None;
    }
    let user = cstr(&rec[44..76]);
    if user.is_empty() {
        return None;
    }
    Some(LoginRecord {
        user,
        host: cstr(&rec[76..332]),
        line: cstr(&rec[8..40]),
        login: None,
    })
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn auth_event(agent_id: &str, rec: &LoginRecord, failure: bool) -> AgentEvent {
    let mut raw = serde_json::json!({
        "activity_id": 1, // OCSF: Logon
        "status_id": if failure { 2 } else { 1 },
        "user": { "name": rec.user },
        "src_endpoint": { "ip": rec.host },
        "service": { "name": rec.line },
    });
    if let Some(login) = &rec.login {
        raw["login_session"] = login.to_json(None);
    }
    AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        class_uid: CLASS_AUTH,
        process_guid: String::new(),
        parent_process_guid: String::new(),
        username: rec.user.clone(),
        conn_tuple: String::new(),
        raw_json: raw.to_string(),
        dropped_events: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(ut_type: i16, user: &str, host: &str) -> Vec<u8> {
        let mut rec = vec![0u8; RECORD_SIZE];
        rec[..2].copy_from_slice(&ut_type.to_le_bytes());
        rec[8..8 + 5].copy_from_slice(b"pts/0");
        rec[44..44 + user.len()].copy_from_slice(user.as_bytes());
        rec[76..76 + host.len()].copy_from_slice(host.as_bytes());
        rec
    }

    #[test]
    fn parses_sshd_messages() {
        let (r, failed) = parse_sshd(
            "Accepted publickey for root from 10.1.1.35 port 51234 ssh2: ED25519 SHA256:abc",
        )
        .expect("应解析成功登录");
        assert!(!failed);
        assert_eq!((r.user.as_str(), r.host.as_str()), ("root", "10.1.1.35"));

        let (r, failed) = parse_sshd("Failed password for alice from 1.2.3.4 port 22 ssh2")
            .expect("应解析失败登录");
        assert!(failed);
        assert_eq!((r.user.as_str(), r.host.as_str()), ("alice", "1.2.3.4"));

        let (r, failed) =
            parse_sshd("Invalid user admin from 5.6.7.8 port 4444").expect("应解析无效用户");
        assert!(failed);
        assert_eq!((r.user.as_str(), r.host.as_str()), ("admin", "5.6.7.8"));

        assert!(
            parse_sshd("Failed password for invalid user admin from 5.6.7.8 port 4444 ssh2")
                .is_none(),
            "无效用户已由 Invalid user 计过"
        );
        assert!(parse_sshd("pam_unix(sshd:session): session opened for user root").is_none());
        assert!(parse_sshd("Connection closed by 10.1.1.35 port 51234").is_none());
    }

    /// 绑定会话只认内核凭据：MESSAGE 与标识谁都能写（logger -t sshd），_UID/_COMM 不能
    #[test]
    fn journal_entry_trusts_kernel_credentials_only() {
        let line = |uid: &str, comm: &str| {
            serde_json::json!({
                "MESSAGE": "Accepted publickey for root from 10.1.1.35 port 1 ssh2",
                "SYSLOG_IDENTIFIER": "sshd",
                "_PID": "4242",
                "_UID": uid,
                "_COMM": comm,
            })
            .to_string()
        };
        let e = JournalEntry::parse(&line("0", "sshd")).unwrap();
        assert_eq!(e.sshd_pid(), Some(4242));
        assert!(parse_sshd(&e.message).is_some());
        assert_eq!(
            JournalEntry::parse(&line("0", "sshd-session"))
                .unwrap()
                .sshd_pid(),
            Some(4242)
        );
        assert!(
            JournalEntry::parse(&line("1000", "sshd"))
                .unwrap()
                .sshd_pid()
                .is_none(),
            "非 root 写的不认"
        );
        assert!(
            JournalEntry::parse(&line("0", "logger"))
                .unwrap()
                .sshd_pid()
                .is_none(),
            "logger -t sshd 伪造的不认"
        );
        // 非 UTF-8 消息被 journald 编成字节数组
        assert!(JournalEntry::parse(r#"{"MESSAGE":[65,66],"_PID":"1"}"#).is_none());
        assert!(JournalEntry::parse("not json").is_none());
    }

    #[test]
    fn sshd_user_cannot_spoof_source() {
        let (r, _) =
            parse_sshd("Invalid user x from 6.6.6.6 port 1 from 1.2.3.4 port 5").expect("应解析");
        assert_eq!(r.host, "1.2.3.4");
        assert_eq!(r.user, "x from 6.6.6.6 port 1");
    }

    #[test]
    fn parses_login_record() {
        let rec = record(USER_PROCESS, "root", "10.0.0.99");
        let parsed = parse_record(&rec).expect("应解析出登录记录");
        assert_eq!(parsed.user, "root");
        assert_eq!(parsed.host, "10.0.0.99");
        assert_eq!(parsed.line, "pts/0");
    }

    #[test]
    fn skips_non_login_records() {
        assert!(
            parse_record(&record(8, "root", "")).is_none(),
            "登出记录应跳过"
        );
        assert!(
            parse_record(&record(USER_PROCESS, "", "")).is_none(),
            "空用户应跳过"
        );
    }

    #[test]
    fn tail_reads_incrementally_and_handles_rotation() {
        let path = std::env::temp_dir().join("openxdr_wtmp_test");
        let path_s: &'static str = Box::leak(path.to_str().unwrap().to_string().into_boxed_str());

        std::fs::write(&path, record(USER_PROCESS, "alice", "h1")).unwrap();
        let mut t = Tail {
            path: path_s,
            failure: false,
            offset: 0,
            identity: None,
        };

        let first = read_new(&mut t).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].user, "alice");
        assert!(read_new(&mut t).unwrap().is_empty(), "无新数据不应重复读");

        // 追加一条
        let mut data = std::fs::read(&path).unwrap();
        data.extend(record(USER_PROCESS, "bob", "h2"));
        std::fs::write(&path, &data).unwrap();
        let second = read_new(&mut t).unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].user, "bob");

        // 轮转：文件变小，从头读
        std::fs::write(&path, record(USER_PROCESS, "carol", "h3")).unwrap();
        let third = read_new(&mut t).unwrap();
        assert_eq!(third.len(), 1);
        assert_eq!(third[0].user, "carol");

        let _ = std::fs::remove_file(&path);
    }
}

#[cfg(test)]
mod tail_bounds_tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn journal_rejects_whole_bad_lines_and_recovers() {
        let accepted = "Accepted publickey for root from 127.0.0.1 port 22 ssh2";
        let mut data = format!("{accepted}{}\n", "x".repeat(MAX_JOURNAL_LINE)).into_bytes();
        data.extend_from_slice(&[0xff, b'\n']);
        data.extend_from_slice(format!("{accepted}\r\n").as_bytes());
        data.extend_from_slice(&vec![b'x'; MAX_JOURNAL_LINE]);
        let mut reader = BufReader::with_capacity(7, &data[..]);
        assert!(read_journal_line(&mut reader).unwrap().unwrap().is_err());
        assert!(read_journal_line(&mut reader).unwrap().unwrap().is_err());
        let line = read_journal_line(&mut reader).unwrap().unwrap().unwrap();
        assert_eq!(line, accepted);
        assert!(parse_sshd(&line).is_some());
        assert_eq!(
            read_journal_line(&mut reader)
                .unwrap()
                .unwrap()
                .unwrap()
                .len(),
            MAX_JOURNAL_LINE
        );
        assert!(read_journal_line(&mut reader).unwrap().is_none());
    }

    #[test]
    fn replacement_and_partial_records_are_read_without_unbounded_allocation() {
        let dir = std::env::temp_dir().join(format!("openxdr-auth-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("wtmp");
        let path_s = Box::leak(path.to_str().unwrap().to_owned().into_boxed_str());
        let mut row = vec![0u8; RECORD_SIZE];
        row[..2].copy_from_slice(&USER_PROCESS.to_le_bytes());
        row[44] = b'a';
        std::fs::write(&path, row.repeat(MAX_RECORDS_PER_READ + 2)).unwrap();
        let mut tail = Tail {
            path: path_s,
            failure: false,
            offset: 0,
            identity: None,
        };
        assert_eq!(read_new(&mut tail).unwrap().len(), MAX_RECORDS_PER_READ);
        assert_eq!(read_new(&mut tail).unwrap().len(), 2);
        assert!(read_new(&mut tail).unwrap().is_empty());
        // 替换为同样大小的新 inode，不能沿用旧 offset 跳过整份文件。
        let replacement = dir.join("replacement");
        row[44] = b'b';
        std::fs::write(&replacement, row.repeat(MAX_RECORDS_PER_READ + 2)).unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        let rows = read_new(&mut tail).unwrap();
        assert_eq!(rows.len(), MAX_RECORDS_PER_READ);
        assert_eq!(rows[0].user, "b");
        assert_eq!(read_new(&mut tail).unwrap().len(), 2);
        let offset = tail.offset;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        file.write_all(&row[..100]).unwrap();
        assert!(read_new(&mut tail).unwrap().is_empty());
        assert_eq!(tail.offset, offset);
        file.write_all(&row[100..]).unwrap();
        assert_eq!(read_new(&mut tail).unwrap().len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(test)]
mod health_tests {
    use super::*;
    #[test]
    fn partial_auth_sources_are_not_reported_as_complete() {
        assert_eq!(auth_state(0, false), "unavailable");
        assert_eq!(auth_state(0, true), "degraded");
        assert_eq!(auth_state(2, false), "degraded");
        assert_eq!(auth_state(2, true), "active");
    }
}
