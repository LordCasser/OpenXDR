//! 指令执行前记录占位，执行后保存结果；只重传回执，绝不恢复执行。
use crate::{
    pb,
    spool::{private_file, reject_symlink, replace_file, sync_dir},
};
use prost::Message;
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

const MAX_RECORDS: usize = 256;
const MAX_BYTES: usize = 1024 * 1024;

pub struct Receipts {
    dir: PathBuf,
    records: BTreeMap<String, pb::CommandResult>,
    ready: BTreeSet<String>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn valid_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok_and(|v| !v.is_nil() && v.to_string() == id)
}

impl Receipts {
    pub fn open(dir: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().mode(0o700).create(dir).or_else(|e| {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    Ok(())
                } else {
                    Err(e)
                }
            })?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        if fs::symlink_metadata(dir)?.permissions().mode() & 0o077 != 0 {
            return Err(invalid("回执目录权限必须为 0700"));
        }
        if !fs::symlink_metadata(dir)?.is_dir() {
            return Err(invalid("回执目录不是普通目录"));
        }
        let mut store = Self {
            dir: dir.into(),
            records: BTreeMap::new(),
            ready: BTreeSet::new(),
        };
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            reject_symlink(&entry.path())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "pending" {
                fs::remove_file(entry.path())?;
                continue;
            }
            if !valid_id(&name) || store.records.len() >= MAX_RECORDS {
                return Err(invalid("回执目录内容或数量无效"));
            }
            let mut bytes = Vec::new();
            fs::File::open(entry.path())?
                .take(MAX_BYTES as u64 + 33)
                .read_to_end(&mut bytes)?;
            if bytes.len() <= 32
                || bytes.len() > MAX_BYTES + 32
                || Sha256::digest(&bytes[32..])[..] != bytes[..32]
            {
                return Err(invalid("回执损坏，保留原文件等待核实"));
            }
            let result =
                pb::CommandResult::decode(&bytes[32..]).map_err(|_| invalid("回执解码失败"))?;
            if result.command_id != name
                || !valid_id(&result.agent_id)
                || pb::command_result::Status::try_from(result.status).is_err()
            {
                return Err(invalid("回执身份或状态无效"));
            }
            if result.status != 0 {
                store.ready.insert(name.clone());
            }
            store.records.insert(name, result);
        }
        sync_dir(dir)?;
        let uncertain = store.records.values().filter(|r| r.status == 0).count();
        if uncertain > 0 {
            eprintln!("恢复 {uncertain} 条无持久结果的执行记录；禁止重执行，需人工核实");
        }
        Ok(store)
    }

    fn save(&mut self, result: pb::CommandResult) -> io::Result<()> {
        let bytes = result.encode_to_vec();
        if bytes.len() > MAX_BYTES {
            return Err(invalid("回执超过容量上限"));
        }
        let pending = self.dir.join("pending");
        reject_symlink(&pending)?;
        if pending.exists() {
            fs::remove_file(&pending)?;
        }
        let mut file = private_file(&pending, true)?;
        file.write_all(&Sha256::digest(&bytes))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        replace_file(&pending, &self.dir.join(&result.command_id))?;
        let id = result.command_id.clone();
        let terminal = result.status != 0;
        self.records.insert(id.clone(), result);
        sync_dir(&self.dir)?;
        if terminal {
            self.ready.insert(id);
        }
        Ok(())
    }

    pub fn reserve(&mut self, agent: &str, command: &str) -> io::Result<bool> {
        if !valid_id(agent) || !valid_id(command) {
            return Err(invalid("指令身份无效"));
        }
        if self.records.contains_key(command) {
            return Ok(false);
        }
        if self.records.len() >= MAX_RECORDS {
            return Err(invalid("回执缓存已满，拒绝执行新指令"));
        }
        self.save(pb::CommandResult {
            agent_id: agent.into(),
            command_id: command.into(),
            detail: "执行尚无持久结果，禁止自动重执行".into(),
            ..Default::default()
        })?;
        Ok(true)
    }

    pub fn finish(&mut self, result: pb::CommandResult) -> io::Result<()> {
        let stored = self
            .records
            .get(&result.command_id)
            .ok_or_else(|| invalid("指令未预留回执"))?;
        if stored == &result && stored.status != 0 {
            sync_dir(&self.dir)?;
            self.ready.insert(result.command_id);
            return Ok(());
        }
        if stored.agent_id != result.agent_id
            || stored.status != 0
            || !matches!(
                result.status(),
                pb::command_result::Status::Succeeded
                    | pb::command_result::Status::Failed
                    | pb::command_result::Status::Unsupported
            )
        {
            return Err(invalid("回执身份或终态冲突"));
        }
        self.save(result)
    }

    pub fn stats(&self) -> crate::health::ReceiptHealth {
        crate::health::ReceiptHealth {
            pending: self.ready.len(),
            incomplete: self.records.len() - self.ready.len(),
        }
    }

    pub fn pending(&self, agent: &str) -> io::Result<Vec<pb::CommandResult>> {
        if self.records.values().any(|r| r.agent_id != agent) {
            return Err(invalid("回执与注册身份不一致"));
        }
        Ok(self
            .records
            .values()
            .filter(|r| self.ready.contains(&r.command_id))
            .cloned()
            .collect())
    }

    pub fn acknowledge(&mut self, agent: &str, command: &str) -> io::Result<()> {
        let record = self
            .records
            .get(command)
            .ok_or_else(|| invalid("回执确认不存在"))?;
        if record.agent_id != agent || record.status == 0 {
            return Err(invalid("回执确认身份或状态无效"));
        }
        fs::remove_file(self.dir.join(command))?;
        self.records.remove(command);
        self.ready.remove(command);
        sync_dir(&self.dir)
    }
}

pub async fn upload_once(
    client: &mut pb::agent_service_client::AgentServiceClient<tonic::transport::Channel>,
    queue: &crate::delivery::Queue,
    agent: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let id = agent.to_owned();
    let pending = crate::delivery::access(queue, move |s| s.receipts.pending(&id)).await?;
    for result in pending {
        let command = result.command_id.clone();
        let id = agent.to_owned();
        let ack = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            client.report_command_result(result),
        )
        .await??
        .into_inner();
        if ack.command_id != command {
            return Err(invalid("服务端确认的指令不匹配，保留回执").into());
        }
        crate::delivery::access(queue, move |s| s.receipts.acknowledge(&id, &command)).await?;
    }
    Ok(())
}

pub async fn upload(
    mut client: pb::agent_service_client::AgentServiceClient<tonic::transport::Channel>,
    queue: crate::delivery::Queue,
    agent: String,
) {
    loop {
        if let Err(error) = upload_once(&mut client, &queue, &agent).await {
            eprintln!("回执上报失败，保留结果等待重传: {error}");
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_or_unwritable_queue_refuses_reservation_and_corruption_is_preserved() {
        let dir = std::env::temp_dir().join(format!("receipts-fault-{}", uuid::Uuid::new_v4()));
        let mut store = Receipts::open(&dir).unwrap();
        let agent = uuid::Uuid::new_v4().to_string();
        let command = uuid::Uuid::new_v4().to_string();
        fs::create_dir(dir.join("pending")).unwrap();
        assert!(store.reserve(&agent, &command).is_err());
        assert!(store.records.is_empty());
        fs::remove_dir(dir.join("pending")).unwrap();
        assert!(store.reserve(&agent, &command).unwrap());
        for _ in 1..MAX_RECORDS {
            assert!(
                store
                    .reserve(&agent, &uuid::Uuid::new_v4().to_string())
                    .unwrap()
            );
        }
        assert!(
            store
                .reserve(&agent, &uuid::Uuid::new_v4().to_string())
                .is_err()
        );
        drop(store);
        let store = Receipts::open(&dir).unwrap();
        assert_eq!(store.records.len(), MAX_RECORDS);
        drop(store);
        fs::write(dir.join(&command), b"corrupt").unwrap();
        assert!(Receipts::open(&dir).is_err());
        assert_eq!(fs::read(dir.join(command)).unwrap(), b"corrupt");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn restart_preserves_uncertainty_and_terminal_result() {
        let dir = std::env::temp_dir().join(format!("receipts-{}", uuid::Uuid::new_v4()));
        let agent = uuid::Uuid::new_v4().to_string();
        let command = uuid::Uuid::new_v4().to_string();
        let uncertain = uuid::Uuid::new_v4().to_string();
        let mut store = Receipts::open(&dir).unwrap();
        assert!(store.reserve(&agent, &uncertain).unwrap());
        assert!(store.reserve(&agent, &command).unwrap());
        store
            .finish(pb::CommandResult {
                agent_id: agent.clone(),
                command_id: command.clone(),
                status: 1,
                stdout: "evidence".into(),
                ..Default::default()
            })
            .unwrap();
        drop(store);
        let mut store = Receipts::open(&dir).unwrap();
        assert!(!store.reserve(&agent, &uncertain).unwrap());
        assert!(!store.reserve(&agent, &command).unwrap());
        assert!(store.acknowledge(&agent, &uncertain).is_err());
        assert!(store.pending(&uuid::Uuid::new_v4().to_string()).is_err());
        assert_eq!(store.pending(&agent).unwrap()[0].stdout, "evidence");
        assert_eq!(store.stats().pending, 1);
        assert_eq!(store.stats().incomplete, 1);
        store.acknowledge(&agent, &command).unwrap();
        drop(store);
        let store = Receipts::open(&dir).unwrap();
        assert!(store.pending(&agent).unwrap().is_empty());
        assert_eq!(store.records.len(), 1);
        fs::remove_dir_all(dir).unwrap();
    }
}
