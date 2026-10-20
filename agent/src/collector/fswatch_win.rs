//! 敏感文件监控（Windows）：ReadDirectoryChangesW，与 Linux fswatch 对称。
//!
//! 默认盯 System32\drivers\etc（hosts 劫持）与 System32\config
//! （SAM/SECURITY hive 所在——hive 被占用读不到内容，但文件变更可见）。
//! 每个监控目录一个线程，以可取消的重叠 I/O 等事件；不递归子目录（与 Linux 侧
//! 限深语义对齐，System32 下递归的 watch 开销也扛不住）。
//! ReadDirectoryChangesW 不提供肇事者进程，事件只有路径与动作——
//! 这些路径上的任何写入本身就值得一条告警。
//! 打不开/已消失的目录静默跳过，绝不让一个坏目录拖垮整体采集。

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_IO_PENDING, ERROR_NOTIFY_ENUM_DIR, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ACTION_ADDED, FILE_ACTION_MODIFIED, FILE_ACTION_REMOVED,
    FILE_ACTION_RENAMED_NEW_NAME, FILE_ACTION_RENAMED_OLD_NAME, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OVERLAPPED, FILE_LIST_DIRECTORY, FILE_NOTIFY_CHANGE_ATTRIBUTES,
    FILE_NOTIFY_CHANGE_FILE_NAME, FILE_NOTIFY_CHANGE_LAST_WRITE, FILE_NOTIFY_CHANGE_SECURITY,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, ReadDirectoryChangesW,
};

use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

use super::EventSink;
use crate::pb::AgentEvent;

/// OCSF File System Activity
const CLASS_FILE_ACTIVITY: u32 = 1001;

/// 监控的目录清单（不递归）；不存在的路径跳过。
/// 覆盖的持久化面：hosts/网络配置篡改、本地账号库（SAM/SECURITY hive）。
const WATCH_DIRS: &[&str] = &[
    r"C:\Windows\System32\drivers\etc",
    r"C:\Windows\System32\config",
];

/// 事件掩码：建/删/改名 + 内容/属性/安全描述符变更
const NOTIFY_FILTER: u32 = FILE_NOTIFY_CHANGE_FILE_NAME
    | FILE_NOTIFY_CHANGE_LAST_WRITE
    | FILE_NOTIFY_CHANGE_ATTRIBUTES
    | FILE_NOTIFY_CHANGE_SECURITY;

/// dirs 为空时用内置清单；非空表示按下发配置覆盖。
/// 返回成功盯上的目录数；一个都盯不上才报错。
pub fn spawn(agent_id: String, sink: EventSink, dirs: &[String]) -> io::Result<usize> {
    let targets: Vec<String> = if dirs.is_empty() {
        WATCH_DIRS.iter().map(|s| s.to_string()).collect()
    } else {
        dirs.to_vec()
    };
    let mut n = 0;
    for dir in targets {
        // 失败目录静默跳过（与 Linux 侧一致）
        let Some(handle) = open_dir(&dir) else {
            continue;
        };
        n += 1;
        let (a, s) = (agent_id.clone(), sink.clone());
        // HANDLE 是裸指针不实现 Send，按 usize 搬过线程边界再转回
        let handle = handle as usize;
        std::thread::spawn(move || watch_loop(handle as HANDLE, &dir, &a, &s));
    }
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::NotFound, "没有可监控的目录"));
    }
    // 自检目录单独一个监控句柄，活性检测改写其中的文件确认通道活着（事件按路径认出、不上报）。
    // 一个敏感目录都没盯上就不挂
    if let Some(dir) = super::liveness::canary_dir()
        && let Some(handle) = open_dir(dir)
    {
        let (a, s) = (agent_id.clone(), sink.clone());
        let handle = handle as usize;
        std::thread::spawn(move || watch_loop(handle as HANDLE, dir, &a, &s));
        super::liveness::spawn(sink.clone(), &super::liveness::FILES, move || {
            super::liveness::probe_files(dir)
        });
    }
    Ok(n)
}

/// 以目录方式打开监控根（FILE_FLAG_BACKUP_SEMANTICS 是开目录句柄的钥匙）。
fn open_dir(dir: &str) -> Option<HANDLE> {
    let path_w: Vec<u16> = dir.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: path_w 是以 0 结尾的 UTF-16 路径，调用期间存活；安全属性与模板句柄传空是 API 允许的用法；
    // 返回值在下面检查空与 INVALID_HANDLE_VALUE。
    let handle = unsafe {
        CreateFileW(
            path_w.as_ptr(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return None;
    }
    Some(handle)
}

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: OwnedHandle 只包裹 CreateFileW / CreateEventW 成功返回的句柄（构造前已检查），
        // 不可 Clone，Drop 只执行一次。
        unsafe { CloseHandle(self.0) };
    }
}

fn watch_loop(handle: HANDLE, dir: &str, agent_id: &str, sink: &EventSink) {
    let handle = OwnedHandle(handle);
    // SAFETY: 安全属性与名称传空指针（匿名、默认安全描述符）是 API 允许的用法；空句柄下面已检查。
    let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if event.is_null() {
        eprintln!(
            "文件监控: {dir} 无法创建完成事件：{}",
            io::Error::last_os_error()
        );
        return;
    }
    let event = OwnedHandle(event);
    // Windows 要求通知缓冲区 DWORD 对齐。
    let mut storage = vec![0u32; 16384];
    while !sink.is_closed() {
        let returned = match read_changes(handle.0, event.0, &mut storage, sink) {
            Ok(Some(n)) => n,
            Ok(None) => return,
            Err(err) if err.raw_os_error() == Some(ERROR_NOTIFY_ENUM_DIR as i32) => {
                eprintln!("文件监控: {dir} 事件溢出，部分变更丢失");
                continue;
            }
            Err(err) => {
                eprintln!("文件监控: {dir} 读取失败：{err}");
                return;
            }
        };
        if returned == 0 {
            eprintln!("文件监控: {dir} 通知缓冲区溢出，部分变更丢失");
            continue;
        }
        // SAFETY: read_changes 返回 Some(n) 时 I/O 已完成，内核不再写 storage，且已校验 n ≤ storage 的
        // 字节数；storage 是 Vec<u32>，按 u8 重新解释不受对齐限制，借用期间不被改动。
        let bytes = unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), returned) };
        for (action, name) in parse_records(bytes) {
            let Some(activity) = rdcw_activity(action) else {
                continue;
            };
            let path = format!("{}\\{}", dir.trim_end_matches('\\'), name);
            if super::liveness::files_pulse(&path) {
                continue;
            }
            if !sink.send(file_event(agent_id, &path, activity)) {
                return;
            }
        }
    }
}

fn read_changes(
    handle: HANDLE,
    event: HANDLE,
    storage: &mut [u32],
    sink: &EventSink,
) -> io::Result<Option<usize>> {
    let mut overlapped = OVERLAPPED {
        hEvent: event,
        // SAFETY: OVERLAPPED 只含整数、指针与联合体，全零是 API 要求的初值（hEvent 已在上一行显式给出）。
        ..unsafe { std::mem::zeroed() }
    };
    let size = std::mem::size_of_val(storage);
    // SAFETY: handle 是以 FILE_FLAG_OVERLAPPED 打开的目录句柄；storage 是 DWORD 对齐的独占缓冲，
    // 长度如实传入。异步 I/O 会在调用返回后继续写 storage 与 overlapped，所以下面每条
    // 返回路径都先等到 I/O 完成（或取消后完成）才离开本函数，借用不会悬空。
    let ok = unsafe {
        ReadDirectoryChangesW(
            handle,
            storage.as_mut_ptr().cast(),
            size as u32,
            0,
            NOTIFY_FILTER,
            std::ptr::null_mut(),
            &mut overlapped,
            None,
        )
    };
    // SAFETY: GetLastError 无参数，只读本线程的错误码。
    if ok == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
        return Err(io::Error::last_os_error());
    }
    let mut returned = 0;
    loop {
        if sink.is_closed() {
            // 取消仅发出请求，必须等待 I/O 完成后才能释放缓冲区及 OVERLAPPED。
            // SAFETY: handle 与 overlapped 正是上面发起的那次 I/O；CancelIoEx 只发取消请求，随后以 bWait = 1
            // 调 GetOverlappedResult 阻塞到 I/O 真正结束，之后 storage 与 overlapped 才可以释放。
            unsafe {
                CancelIoEx(handle, &overlapped);
                GetOverlappedResult(handle, &overlapped, &mut returned, 1);
            }
            return Ok(None);
        }
        // SAFETY: event 是 watch_loop 持有的有效事件句柄，等待不涉及内存。
        match unsafe { WaitForSingleObject(event, 250) } {
            WAIT_TIMEOUT => continue,
            WAIT_OBJECT_0 => break,
            _ => {
                let err = io::Error::last_os_error();
                // SAFETY: 同上：先取消，再阻塞等 I/O 结束，保证返回后内核不再写 storage 与 overlapped。
                unsafe {
                    CancelIoEx(handle, &overlapped);
                    GetOverlappedResult(handle, &overlapped, &mut returned, 1);
                }
                return Err(err);
            }
        }
    }
    // SAFETY: event 已触发表示 I/O 完成；overlapped 与 returned 都是本函数的栈变量，bWait = 0 只取结果。
    if unsafe { GetOverlappedResult(handle, &overlapped, &mut returned, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if returned as usize > size {
        return Err(io::Error::other("通知数据超过缓冲区"));
    }
    Ok(Some(returned as usize))
}

/// 解析一段 FILE_NOTIFY_INFORMATION 记录链，产出 (Action, 相对文件名)。
/// 记录布局固定（NextEntryOffset/Action/FileNameLength 三个 u32 头 +
/// UTF-16 文件名），逐字段按字节解析，不做指针强转，便于单测构造语料。
fn parse_records(buf: &[u8]) -> Vec<(u32, String)> {
    const HEADER_LEN: usize = 12;
    let mut out = Vec::new();
    let mut off = 0usize;
    loop {
        if off + HEADER_LEN > buf.len() {
            break;
        }
        let next = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        let action = u32::from_ne_bytes(buf[off + 4..off + 8].try_into().unwrap());
        let name_len = u32::from_ne_bytes(buf[off + 8..off + 12].try_into().unwrap()) as usize;
        if !name_len.is_multiple_of(2) || off + HEADER_LEN + name_len > buf.len() {
            break; // 长度越界说明缓冲不可信，剩下的整条丢弃
        }
        let chars: Vec<u16> = buf[off + HEADER_LEN..off + HEADER_LEN + name_len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_ne_bytes(c))
            .collect();
        out.push((action, String::from_utf16_lossy(&chars)));
        if next == 0 {
            break;
        }
        off += next;
    }
    out
}

/// RDCW Action -> OCSF File Activity：1 Create / 3 Update / 4 Delete。
/// 改名拆成删（旧名）+ 增（新名）两条，与 Linux 侧移出/移入的语义一致。
fn rdcw_activity(action: u32) -> Option<u8> {
    match action {
        FILE_ACTION_ADDED | FILE_ACTION_RENAMED_NEW_NAME => Some(1),
        FILE_ACTION_REMOVED | FILE_ACTION_RENAMED_OLD_NAME => Some(4),
        FILE_ACTION_MODIFIED => Some(3),
        _ => None,
    }
}

/// RDCW 不提供进程上下文，事件只有路径与动作（与 Linux inotify 路径一致）。
fn file_event(agent_id: &str, path: &str, activity: u8) -> AgentEvent {
    let raw = serde_json::json!({
        "activity_id": activity,
        "file": { "path": path },
    });
    AgentEvent {
        agent_id: agent_id.to_string(),
        ts_unix_ns: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as i64,
        class_uid: CLASS_FILE_ACTIVITY,
        process_guid: String::new(),
        parent_process_guid: String::new(),
        username: String::new(),
        conn_tuple: String::new(),
        raw_json: raw.to_string(),
        dropped_events: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicU64;
    use tokio::sync::mpsc;

    fn test_sink() -> (EventSink, mpsc::Receiver<AgentEvent>) {
        let (tx, rx) = mpsc::channel(16);
        (
            EventSink {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
                health: crate::health::Health::new(),
                generation: 0,
            },
            rx,
        )
    }

    fn temp_root(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("openxdr_fswatch_win_{tag}_{}", std::process::id()))
    }

    /// 按 FILE_NOTIFY_INFORMATION 的真实布局构造一条记录语料。
    fn build_record(next: u32, action: u32, name: &str) -> Vec<u8> {
        let wide: Vec<u16> = name.encode_utf16().collect();
        let mut b = Vec::new();
        b.extend_from_slice(&next.to_ne_bytes());
        b.extend_from_slice(&action.to_ne_bytes());
        b.extend_from_slice(&((wide.len() * 2) as u32).to_ne_bytes());
        for c in wide {
            b.extend_from_slice(&c.to_ne_bytes());
        }
        // 记录按 8 字节对齐，不足补零
        while b.len() % 8 != 0 {
            b.push(0);
        }
        b
    }

    #[test]
    fn parse_records_single_and_chain() {
        let one = build_record(0, FILE_ACTION_ADDED, "evil.exe");
        let recs = parse_records(&one);
        assert_eq!(recs, vec![(FILE_ACTION_ADDED, "evil.exe".to_string())]);

        // 两条记录串成链：第一条的 NextEntryOffset 指向第二条（按自身补齐后的长度）
        let mut second = build_record(0, FILE_ACTION_REMOVED, "gone.dll");
        let mut first = build_record(0, FILE_ACTION_MODIFIED, "hosts");
        let next = first.len() as u32;
        first[..4].copy_from_slice(&next.to_ne_bytes());
        first.append(&mut second);
        let recs = parse_records(&first);
        assert_eq!(
            recs,
            vec![
                (FILE_ACTION_MODIFIED, "hosts".to_string()),
                (FILE_ACTION_REMOVED, "gone.dll".to_string()),
            ]
        );
    }

    #[test]
    fn parse_records_drops_garbage() {
        // 名字长度越界：整条丢弃，不产出半个事件
        let mut bad = build_record(0, FILE_ACTION_ADDED, "x");
        bad[8] = 0xff;
        bad[9] = 0xff;
        assert!(parse_records(&bad).is_empty());

        // 缓冲在文件名中间截断：整条丢弃
        let rec = build_record(0, FILE_ACTION_ADDED, "evil.exe");
        assert!(parse_records(&rec[..16]).is_empty());
    }

    #[test]
    fn rdcw_activity_mapping() {
        assert_eq!(rdcw_activity(FILE_ACTION_ADDED), Some(1));
        assert_eq!(rdcw_activity(FILE_ACTION_RENAMED_NEW_NAME), Some(1));
        assert_eq!(rdcw_activity(FILE_ACTION_REMOVED), Some(4));
        assert_eq!(rdcw_activity(FILE_ACTION_RENAMED_OLD_NAME), Some(4));
        assert_eq!(rdcw_activity(FILE_ACTION_MODIFIED), Some(3));
        assert_eq!(rdcw_activity(0), None, "未知动作应跳过");
    }

    #[test]
    fn watch_reports_file_change() {
        let dir = temp_root("basic");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let dir_s = dir.to_str().unwrap().to_string();

        let (sink, mut rx) = test_sink();
        let handle = open_dir(&dir_s).expect("临时目录应可监控");
        let d = dir_s.clone();
        // HANDLE 不实现 Send，按 usize 搬过线程边界（与 spawn 内一致）
        let raw = handle as usize;
        let (done, finished) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            watch_loop(raw as HANDLE, &d, "agent-t", &sink);
            let _ = done.send(());
        });
        // 首次读取异步启动，用不同文件名重试，既不无限等也不依赖线程调度顺序。
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut index = 0;
        let ev = loop {
            std::fs::write(dir.join(format!("evil-{index}.txt")), b"x").unwrap();
            if let Ok(event) = rx.try_recv() {
                break event;
            }
            assert!(std::time::Instant::now() < deadline, "未收到文件事件");
            index += 1;
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(ev.class_uid, CLASS_FILE_ACTIVITY);
        assert!(ev.username.is_empty(), "RDCW 路径没有进程上下文");
        let v: serde_json::Value = serde_json::from_str(&ev.raw_json).unwrap();
        let path = v["file"]["path"].as_str().unwrap();
        assert!(std::path::Path::new(path).starts_with(&dir));
        assert!(matches!(v["activity_id"].as_u64(), Some(1 | 3)));
        assert!(v.get("process").is_none());

        rx.close();
        finished
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("关闭后采集线程应退出");
        worker.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn idle_watch_stops_without_file_changes() {
        let dir = temp_root("idle");
        std::fs::create_dir_all(&dir).unwrap();
        let (sink, mut rx) = test_sink();
        let path = dir.to_str().unwrap().to_owned();
        let raw = open_dir(&path).unwrap() as usize;
        let (done, finished) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            watch_loop(raw as HANDLE, &path, "agent-t", &sink);
            let _ = done.send(());
        });
        assert!(matches!(
            finished.recv_timeout(std::time::Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        rx.close();
        finished
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("空闲监控必须可以取消");
        worker.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_dirs_are_skipped() {
        assert!(open_dir(r"C:\nonexistent\openxdr").is_none());
        assert!(
            spawn(
                "agent-t".to_string(),
                test_sink().0,
                &[r"C:\nonexistent\openxdr".to_string()],
            )
            .is_err()
        );
    }
}
