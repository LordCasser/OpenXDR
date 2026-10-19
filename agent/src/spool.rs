//! 已落盘的批次只有收到完整 ACK 后才能删除；容量不足时拒绝追加，不淘汰旧证据。
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use prost::Message;
use sha2::{Digest, Sha256};

use crate::pb::AgentEvent;

const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;
const MAX_BATCH_EVENTS: usize = 500;
const HEADER: usize = 32;

#[derive(Clone, PartialEq, Message)]
struct StoredBatch {
    #[prost(message, repeated, tag = "1")]
    events: Vec<AgentEvent>,
}

pub struct Batch {
    pub sequence: u64,
    pub events: Vec<AgentEvent>,
}

pub struct Spool {
    dir: PathBuf,
    pub receipts: crate::receipts::Receipts,
    _lock: File,
    files: BTreeMap<u64, u64>,
    bytes: u64,
    limit: u64,
    next: u64,
}

impl Drop for Spool {
    fn drop(&mut self) {
        // 显式释放锁，避免并发启动子进程在 exec 前短暂持有同一文件描述。
        let _ = self._lock.unlock();
    }
}

impl Spool {
    pub fn open(dir: &Path, limit: u64) -> io::Result<Self> {
        if limit < MAX_BATCH_BYTES as u64 {
            return Err(invalid("缓存容量不能小于单批上限"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
            if fs::symlink_metadata(dir)?.permissions().mode() & 0o077 != 0 {
                return Err(invalid("缓存目录权限必须为 0700"));
            }
        }
        #[cfg(not(unix))]
        fs::create_dir_all(dir)?;
        if !fs::symlink_metadata(dir)?.is_dir() {
            return Err(invalid("缓存目录不能为符号链接"));
        }
        let lock_path = dir.join("lock");
        reject_symlink(&lock_path)?;
        let lock = private_file(&lock_path, false)?;
        lock.try_lock().map_err(io::Error::other)?;
        let mut spool = Self {
            receipts: crate::receipts::Receipts::open(&dir.join("receipts"))?,
            dir: dir.to_owned(),
            _lock: lock,
            files: BTreeMap::new(),
            bytes: 0,
            limit,
            next: 0,
        };
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "lock" || name == "session" || name == "receipts" {
                continue;
            }
            if name == "pending" || name == "session.pending" {
                reject_symlink(&entry.path())?;
                fs::remove_file(entry.path())?;
                continue;
            }
            let sequence = name
                .strip_suffix(".batch")
                .filter(|s| s.len() == 20 && s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or_else(|| invalid("缓存目录含未知文件"))?;
            let size = entry.metadata()?.len();
            read_batch(&entry.path())?;
            spool.files.insert(sequence, size);
            spool.bytes = spool
                .bytes
                .checked_add(size)
                .ok_or_else(|| invalid("缓存大小溢出"))?;
            spool.next = spool.next.max(
                sequence
                    .checked_add(1)
                    .ok_or_else(|| invalid("缓存序号耗尽"))?,
            );
        }
        sync_dir(dir)?;
        Ok(spool)
    }

    pub fn session(&self) -> io::Result<Option<crate::pb::RegisterResponse>> {
        let path = self.dir.join("session");
        reject_symlink(&path)?;
        let file = match File::open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > 1024 * 1024 {
            return Err(invalid("缓存注册配置过大"));
        }
        let session = crate::pb::RegisterResponse::decode(bytes.as_slice())
            .map_err(|_| invalid("缓存注册配置损坏"))?;
        if uuid::Uuid::parse_str(&session.agent_id).is_err() {
            return Err(invalid("缓存注册身份无效"));
        }
        Ok(Some(session))
    }

    pub fn save_session(&self, session: &crate::pb::RegisterResponse) -> io::Result<()> {
        if uuid::Uuid::parse_str(&session.agent_id).is_err() || session.encoded_len() > 1024 * 1024
        {
            return Err(invalid("注册配置无效或过大"));
        }
        let pending = self.dir.join("session.pending");
        let mut file = private_file(&pending, true)?;
        file.write_all(&session.encode_to_vec())?;
        file.sync_all()?;
        drop(file);
        replace_file(&pending, &self.dir.join("session"))?;
        sync_dir(&self.dir)
    }

    pub fn append(&mut self, events: Vec<AgentEvent>) -> io::Result<u64> {
        if events.is_empty() || events.len() > MAX_BATCH_EVENTS {
            return Err(invalid("批次必须包含 1 到 500 条事件"));
        }
        let batch = StoredBatch { events };
        let size = batch
            .encoded_len()
            .checked_add(HEADER)
            .ok_or_else(|| invalid("批次过大"))?;
        if size > MAX_BATCH_BYTES {
            return Err(invalid("批次超过 4 MiB"));
        }
        if self.bytes.saturating_add(size as u64) > self.limit || self.files.len() >= 8192 {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "缓存已满，旧证据保留",
            ));
        }
        let next = self
            .next
            .checked_add(1)
            .ok_or_else(|| invalid("缓存序号耗尽"))?;
        let payload = batch.encode_to_vec();
        let pending = self.dir.join("pending");
        let mut file = private_file(&pending, true)?;
        let write = (|| {
            file.write_all(&Sha256::digest(&payload))?;
            file.write_all(&payload)?;
            file.sync_all()
        })();
        drop(file);
        if let Err(err) = write {
            let _ = fs::remove_file(&pending);
            return Err(err);
        }
        let sequence = self.next;
        replace_file(&pending, &self.path(sequence))?;
        // rename 后即计入本进程索引；目录同步失败也不能覆盖已写入的批次。
        self.files.insert(sequence, size as u64);
        self.bytes += size as u64;
        self.next = next;
        sync_dir(&self.dir)?;
        Ok(sequence)
    }

    pub fn front(&self) -> io::Result<Option<Batch>> {
        self.files
            .first_key_value()
            .map(|(&sequence, _)| {
                Ok(Batch {
                    sequence,
                    events: read_batch(&self.path(sequence))?,
                })
            })
            .transpose()
    }

    /// 只能确认当前最老批次，且服务端接收条数必须与持久记录一致。
    pub fn acknowledge(&mut self, sequence: u64, received: u64) -> io::Result<()> {
        let batch = self.front()?.ok_or_else(|| invalid("缓存为空，无法确认"))?;
        if batch.sequence != sequence || batch.events.len() as u64 != received {
            return Err(invalid("ACK 与当前批次不匹配"));
        }
        fs::remove_file(self.path(sequence))?;
        self.bytes -= self.files.remove(&sequence).expect("front 已校验");
        sync_dir(&self.dir)
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn batches(&self) -> usize {
        self.files.len()
    }
    fn path(&self, sequence: u64) -> PathBuf {
        self.dir.join(format!("{sequence:020}.batch"))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) fn reject_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if !meta.is_file() => Err(invalid("缓存文件不是普通文件")),
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

pub(crate) fn private_file(path: &Path, exclusive: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(!exclusive).create_new(exclusive);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn read_batch(path: &Path) -> io::Result<Vec<AgentEvent>> {
    reject_symlink(path)?;
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_BATCH_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() <= HEADER
        || bytes.len() > MAX_BATCH_BYTES
        || Sha256::digest(&bytes[HEADER..])[..] != bytes[..HEADER]
    {
        return Err(invalid("持久批次损坏，保留原文件等待处理"));
    }
    let batch = StoredBatch::decode(&bytes[HEADER..]).map_err(|_| invalid("持久批次解码失败"))?;
    if batch.events.is_empty() || batch.events.len() > MAX_BATCH_EVENTS {
        return Err(invalid("持久批次条数无效"));
    }
    Ok(batch.events)
}

pub(crate) fn replace_file(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(not(windows))]
    fs::rename(from, to)?;
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };
        let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Temp(PathBuf);
    impl Temp {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!("openxdr-spool-test-{}", uuid::Uuid::new_v4())))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn event() -> AgentEvent {
        AgentEvent {
            agent_id: "agent".into(),
            raw_json: r#"{"process":"test"}"#.into(),
            ..Default::default()
        }
    }

    #[test]
    fn session_updates_survive_restart() {
        let dir = Temp::new();
        let spool = Spool::open(&dir.0, 8 << 20).unwrap();
        let mut session = crate::pb::RegisterResponse {
            agent_id: uuid::Uuid::new_v4().to_string(),
            config_json: "{}".into(),
            ..Default::default()
        };
        spool.save_session(&session).unwrap();
        session.config_json = r#"{"collectNetwork":false}"#.into();
        spool.save_session(&session).unwrap();
        drop(spool);
        let spool = Spool::open(&dir.0, 8 << 20).unwrap();
        assert_eq!(spool.session().unwrap(), Some(session));
    }

    #[test]
    fn restart_replays_until_exact_ack() {
        let dir = Temp::new();
        let mut spool = Spool::open(&dir.0, 8 << 20).unwrap();
        let id = spool.append(vec![event(), event()]).unwrap();
        let second = spool.append(vec![event()]).unwrap();
        assert!(spool.bytes() > 0);
        assert_eq!(spool.batches(), 2);
        assert!(spool.acknowledge(second, 1).is_err());
        assert!(spool.acknowledge(id, 1).is_err());
        drop(spool);
        let mut spool = Spool::open(&dir.0, 8 << 20).unwrap();
        assert_eq!(
            spool.front().unwrap().unwrap().events,
            vec![event(), event()]
        );
        spool.acknowledge(id, 2).unwrap();
        assert_eq!(spool.front().unwrap().unwrap().sequence, second);
        spool.acknowledge(second, 1).unwrap();
        assert_eq!(spool.bytes(), 0);
        assert!(spool.front().unwrap().is_none());
    }

    #[test]
    fn exclusive_owner_and_uncommitted_recovery() {
        let dir = Temp::new();
        let spool = Spool::open(&dir.0, 8 << 20).unwrap();
        assert!(Spool::open(&dir.0, 8 << 20).is_err());
        fs::write(dir.0.join("pending"), b"partial write").unwrap();
        let inherited = spool._lock.try_clone().unwrap();
        drop(spool);
        let spool = Spool::open(&dir.0, 8 << 20).unwrap();
        drop(inherited);
        assert!(Spool::open(&dir.0, 8 << 20).is_err());
        assert_eq!(spool.batches(), 0);
        assert!(!dir.0.join("pending").exists());
    }

    #[test]
    fn corruption_is_not_silently_discarded() {
        let dir = Temp::new();
        let mut spool = Spool::open(&dir.0, 8 << 20).unwrap();
        let id = spool.append(vec![event()]).unwrap();
        let path = spool.path(id);
        fs::write(&path, b"corrupt").unwrap();
        assert!(spool.front().is_err());
        assert!(spool.acknowledge(id, 1).is_err());
        drop(spool);
        assert!(Spool::open(&dir.0, 8 << 20).is_err());
        assert!(path.exists());
    }

    #[test]
    fn full_queue_preserves_old_batches() {
        let dir = Temp::new();
        let mut spool = Spool::open(&dir.0, 4 << 20).unwrap();
        let mut large = event();
        large.raw_json = "x".repeat(3 << 20);
        let id = spool.append(vec![large.clone()]).unwrap();
        assert_eq!(
            spool.append(vec![large.clone()]).unwrap_err().kind(),
            io::ErrorKind::StorageFull
        );
        assert_eq!(spool.front().unwrap().unwrap().events, vec![large]);
        spool.acknowledge(id, 1).unwrap();
        assert!(spool.append(vec![event()]).is_ok());
        assert!(spool.append(vec![]).is_err());
    }
}
