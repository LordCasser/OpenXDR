//! 文件隔离：把可疑文件移进 agent 状态目录下的隔离区，原位置不再有这个文件，内容原样留作证据。
//!
//! 每个隔离文件旁边存一份记录：原路径、大小、SHA-256、权限与属主，恢复时按原路径找最近一次隔离的那份，
//! 原路径已经有文件就拒绝覆盖。只处理普通文件，不碰符号链接、目录、伪文件系统和 agent 自己。

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::Outcome;
use crate::pb::Command;

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    path: String,
    size: u64,
    sha256: String,
    mode: u32,
    uid: u32,
    gid: u32,
    at: u64,
}

fn dir() -> PathBuf {
    crate::delivery::state_root().join("isolated-files")
}

pub fn quarantine(cmd: &Command) -> Outcome {
    match move_in(&dir(), Path::new(cmd.target.trim()), &cmd.id) {
        Ok(r) => Outcome::ok(format!(
            "已隔离 {}（{} 字节，SHA-256 {}）",
            r.path, r.size, r.sha256
        )),
        Err(e) => Outcome::failed(format!("隔离失败：{e}")),
    }
}

pub fn restore(cmd: &Command) -> Outcome {
    match move_out(&dir(), Path::new(cmd.target.trim())) {
        Ok(r) => Outcome::ok(format!("已恢复 {}（SHA-256 {}）", r.path, r.sha256)),
        Err(e) => Outcome::failed(format!("恢复失败：{e}")),
    }
}

fn refuse(path: &Path, store: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("路径必须是绝对路径".into());
    }
    #[cfg(unix)]
    for root in ["/proc", "/sys", "/dev", "/run"] {
        if path.starts_with(root) {
            return Err(format!("{root} 下的文件不能隔离"));
        }
    }
    if path.starts_with(store) || path.starts_with(crate::delivery::state_root()) {
        return Err("agent 自己的状态文件不能隔离".into());
    }
    if let Ok(exe) = std::env::current_exe()
        && fs::canonicalize(&exe).ok() == fs::canonicalize(path).ok()
    {
        return Err("不能隔离 agent 自身".into());
    }
    Ok(())
}

fn move_in(store: &Path, path: &Path, id: &str) -> Result<Record, String> {
    refuse(path, store)?;
    let meta = fs::symlink_metadata(path).map_err(|e| format!("{}：{e}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(format!(
            "{} 不是普通文件（符号链接、目录、设备不处理）",
            path.display()
        ));
    }
    let id = uuid::Uuid::parse_str(id).map_err(|_| "指令 ID 无效")?;
    create_private(store)?;
    let record = Record {
        path: path.display().to_string(),
        size: meta.len(),
        sha256: sha256(path).map_err(|e| format!("读取文件失败：{e}"))?,
        mode: mode(&meta),
        uid: owner(&meta).0,
        gid: owner(&meta).1,
        at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };
    let blob = store.join(format!("{id}.bin"));
    // 记录先落盘：文件挪走了却没记下从哪来，就恢复不回去了
    fs::write(
        store.join(format!("{id}.json")),
        serde_json::to_vec(&record).unwrap_or_default(),
    )
    .map_err(|e| format!("写隔离记录失败：{e}"))?;
    if let Err(e) = relocate(path, &blob) {
        let _ = fs::remove_file(store.join(format!("{id}.json")));
        return Err(format!("移动文件失败：{e}"));
    }
    lock_down(&blob);
    Ok(record)
}

fn move_out(store: &Path, path: &Path) -> Result<Record, String> {
    if !path.is_absolute() {
        return Err("路径必须是绝对路径".into());
    }
    let want = path.display().to_string();
    let mut latest: Option<(String, Record)> = None;
    for entry in fs::read_dir(store)
        .map_err(|_| format!("{want} 没有被隔离过"))?
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(id) = name.strip_suffix(".json") else {
            continue;
        };
        let Ok(r) = fs::read(entry.path())
            .map_err(|_| ())
            .and_then(|b| serde_json::from_slice::<Record>(&b).map_err(|_| ()))
        else {
            continue;
        };
        if r.path == want && latest.as_ref().is_none_or(|(_, l)| r.at >= l.at) {
            latest = Some((id.to_string(), r));
        }
    }
    let (id, record) = latest.ok_or_else(|| format!("{want} 没有被隔离过"))?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(format!("{want} 已经有文件，拒绝覆盖；先处理现有文件再恢复"));
    }
    let blob = store.join(format!("{id}.bin"));
    relocate(&blob, path).map_err(|e| format!("移回原位置失败：{e}"))?;
    restore_meta(path, &record);
    let _ = fs::remove_file(store.join(format!("{id}.json")));
    Ok(record)
}

/// 同一文件系统直接改名；跨文件系统先拷贝、核对大小再删原件
fn relocate(from: &Path, to: &Path) -> io::Result<()> {
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    let copied = fs::copy(from, to)?;
    if copied != fs::metadata(from)?.len() {
        let _ = fs::remove_file(to);
        return Err(io::Error::other("拷贝不完整"));
    }
    fs::remove_file(from)
}

fn sha256(path: &Path) -> io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

fn create_private(dir: &Path) -> Result<(), String> {
    #[cfg(unix)]
    let made = {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    };
    #[cfg(not(unix))]
    let made = fs::create_dir_all(dir);
    made.map_err(|e| format!("创建隔离区失败：{e}"))
}

#[cfg(unix)]
fn mode(m: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    m.permissions().mode()
}
#[cfg(not(unix))]
fn mode(_: &fs::Metadata) -> u32 {
    0
}
#[cfg(unix)]
fn owner(m: &fs::Metadata) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    (m.uid(), m.gid())
}
#[cfg(not(unix))]
fn owner(_: &fs::Metadata) -> (u32, u32) {
    (0, 0)
}

/// 隔离区里的文件去掉全部权限，谁也执行不了
fn lock_down(blob: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(blob, fs::Permissions::from_mode(0o000));
    }
    #[cfg(not(unix))]
    let _ = blob;
}

fn restore_meta(path: &Path, r: &Record) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::os::unix::fs::chown(path, Some(r.uid), Some(r.gid));
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(r.mode & 0o7777));
    }
    #[cfg(not(unix))]
    let _ = (path, r);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("openxdr-quarantine-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn quarantine_and_restore_round_trip() {
        let root = temp();
        let store = root.join("store");
        let file = root.join("payload.sh");
        fs::write(&file, b"#!/bin/sh\necho pwned\n").unwrap();
        let id = uuid::Uuid::new_v4().to_string();

        let r = move_in(&store, &file, &id).unwrap();
        assert!(!file.exists(), "原位置不应再有文件");
        assert_eq!(r.size, 21);
        assert_eq!(r.sha256.len(), 64);
        assert!(store.join(format!("{id}.bin")).exists());

        // 原位置又有了文件：拒绝覆盖
        fs::write(&file, b"new").unwrap();
        assert!(move_out(&store, &file).unwrap_err().contains("拒绝覆盖"));
        fs::remove_file(&file).unwrap();

        let back = move_out(&store, &file).unwrap();
        assert_eq!(back.sha256, r.sha256);
        assert_eq!(fs::read(&file).unwrap(), b"#!/bin/sh\necho pwned\n");
        assert!(
            move_out(&store, &file)
                .unwrap_err()
                .contains("没有被隔离过")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_non_regular_relative_and_pseudo() {
        let root = temp();
        let store = root.join("store");
        let id = uuid::Uuid::new_v4().to_string();
        assert!(
            move_in(&store, Path::new("relative.txt"), &id)
                .unwrap_err()
                .contains("绝对路径")
        );
        assert!(
            move_in(&store, &root, &id)
                .unwrap_err()
                .contains("不是普通文件")
        );
        #[cfg(unix)]
        {
            assert!(move_in(&store, Path::new("/proc/self/status"), &id).is_err());
            let link = root.join("link");
            std::os::unix::fs::symlink("/etc/hostname", &link).unwrap();
            assert!(
                move_in(&store, &link, &id)
                    .unwrap_err()
                    .contains("不是普通文件")
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}
