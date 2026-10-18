//! 进程 GUID 注册表：pid 会被系统复用，GUID 不会。
//! 进程血缘全靠这张表——父进程的 GUID 从这里查，查不到说明父进程早于 agent 启动。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use uuid::Uuid;

/// 进程所在的容器或虚拟机（Linux 按 cgroup 识别），事件里原样写成 container 对象
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    /// docker / podman / containerd / cri-o / lxc / qemu / nspawn
    pub runtime: &'static str,
    /// 容器 ID（docker 系取前 12 位）或 Proxmox 的 VMID
    pub uid: String,
    pub name: Option<String>,
}

impl Container {
    pub fn to_json(&self) -> serde_json::Value {
        let mut v = serde_json::json!({ "runtime": self.runtime, "uid": self.uid });
        if let Some(name) = &self.name {
            v["name"] = name.as_str().into();
        }
        v
    }
}

/// 安全上限：条目随进程退出删除，正常只有存活进程；漏掉退出事件的条目超限时清掉最早的一半
const MAX_ENTRIES: usize = 1 << 16;

#[derive(Default)]
pub struct ProcessRegistry {
    guids: HashMap<u32, Entry>,
    seq: u64,
}

struct Entry {
    guid: Uuid,
    seq: u64,
    // 启动时记下名字与路径：退出探针触发时进程已在退出途中，只剩 pid 可查
    name: String,
    exe: Option<String>,
    started: Option<SystemTime>,
    container: Option<Arc<Container>>,
    command: Option<Arc<str>>,
}

/// 注册表里记得的进程身份，退出事件靠它说清是谁退出了。
pub struct Known {
    pub guid: Uuid,
    pub name: String,
    pub exe: Option<String>,
    pub started: Option<SystemTime>,
    pub container: Option<Arc<Container>>,
    /// 拉起它的平台指令 ID（指令进程及其后代）
    pub command: Option<Arc<str>>,
}

impl ProcessRegistry {
    /// 登记新进程，返回它的 GUID 和父进程 GUID（父未知则 None）。
    pub fn register(&mut self, pid: u32, ppid: Option<u32>) -> (Uuid, Option<Uuid>) {
        let parent = ppid.and_then(|p| self.guids.get(&p).map(|e| e.guid));
        let guid = Uuid::new_v4();
        crate::process_identity::record(pid, guid);

        self.seq += 1;
        let seq = self.seq;
        // pid 复用时新条目直接覆盖旧的，这正是我们要的语义
        self.guids.insert(
            pid,
            Entry {
                guid,
                seq,
                name: String::new(),
                exe: None,
                started: None,
                container: None,
                command: None,
            },
        );

        if self.guids.len() > MAX_ENTRIES {
            let cutoff = seq.saturating_sub(MAX_ENTRIES as u64 / 2);
            self.guids.retain(|_, e| e.seq > cutoff);
        }
        (guid, parent)
    }

    /// 预登记已存在的进程（agent 启动时的进程表快照），让后续子进程能找到父，
    /// 它们退出时也能报出名字。
    pub fn seed(&mut self, pid: u32, name: &str, exe: Option<&str>) {
        self.register(pid, None);
        self.describe(pid, name, exe);
    }

    /// 记下进程的名字与路径。
    pub fn describe(&mut self, pid: u32, name: &str, exe: Option<&str>) {
        if let Some(e) = self.guids.get_mut(&pid) {
            e.name = name.to_string();
            e.exe = exe.map(str::to_string);
        }
    }

    /// 记下启动时间（退出时算运行时长）、所在容器与拉起它的平台指令。
    pub fn annotate(
        &mut self,
        pid: u32,
        started: Option<SystemTime>,
        container: Option<Arc<Container>>,
        command: Option<Arc<str>>,
    ) {
        if let Some(e) = self.guids.get_mut(&pid) {
            e.started = started;
            e.container = container;
            e.command = command;
        }
    }

    /// pid 所属的平台指令，子进程沿血缘继承
    pub fn command_of(&self, pid: u32) -> Option<Arc<str>> {
        self.guids.get(&pid).and_then(|e| e.command.clone())
    }

    /// 进程退出后删掉登记。不删的话表满时会按登记先后清理，最先被清掉的恰恰是
    /// 早于 agent 启动的长驻服务，它们之后的网络连接就挂不回进程树了
    pub fn forget(&mut self, pid: u32) {
        self.guids.remove(&pid);
    }

    /// 查 pid 当前登记的身份。查不到说明既没见过它启动、也不在启动快照里。
    pub fn known(&self, pid: u32) -> Option<Known> {
        self.guids.get(&pid).map(|e| Known {
            guid: e.guid,
            name: e.name.clone(),
            exe: e.exe.clone(),
            started: e.started,
            container: e.container.clone(),
            command: e.command.clone(),
        })
    }

    /// 查 pid 当前的 GUID，未登记返回 None。网络事件靠它挂进进程血缘，
    /// 退出事件靠它复用启动时的 GUID。
    pub fn guid_of(&self, pid: u32) -> Option<Uuid> {
        self.guids.get(&pid).map(|e| e.guid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 血缘靠 GUID 串联：父进程的 register 返回值就是子进程的 parent。
    #[test]
    fn lineage_via_guid() {
        let mut reg = ProcessRegistry::default();
        let (g1, _) = reg.register(1, None);
        let (g2, parent2) = reg.register(2, Some(1));
        let (g3, parent3) = reg.register(3, Some(2));

        assert_eq!(parent2, Some(g1), "子进程父 GUID 应等于父进程 GUID");
        assert_eq!(parent3, Some(g2), "孙进程应连到直系父进程");
        assert_ne!(g1, g2);
        assert_ne!(g2, g3);
    }

    /// 父进程未登记（早于 agent 启动）→ 父 GUID 为 None。
    #[test]
    fn unknown_parent_is_none() {
        let mut reg = ProcessRegistry::default();
        let (g, parent) = reg.register(100, Some(999));
        assert!(parent.is_none());
        assert!(!g.is_nil());
    }

    /// pid 复用：同一 pid 再次登记覆盖旧 GUID，父句柄随之指向新条目。
    #[test]
    fn pid_reuse_overwrites() {
        let mut reg = ProcessRegistry::default();
        let (old, _) = reg.register(50, None);
        let (fresh, _) = reg.register(50, None);
        assert_ne!(old, fresh, "pid 复用必须换新 GUID");

        let (_, parent_of_child) = reg.register(51, Some(50));
        assert_eq!(parent_of_child, Some(fresh), "子进程应连到复用后的新 GUID");
    }

    /// seed 等价于预登记，让后续子进程能追溯，并记住名字与路径。
    #[test]
    fn seed_pregisters() {
        let mut reg = ProcessRegistry::default();
        reg.seed(7, "sshd", Some("/usr/sbin/sshd"));
        let (child, parent) = reg.register(8, Some(7));
        assert!(parent.is_some());
        assert_ne!(child, parent.unwrap());
        let known = reg.known(7).unwrap();
        assert_eq!(
            (known.name.as_str(), known.exe.as_deref()),
            ("sshd", Some("/usr/sbin/sshd"))
        );
        assert!(reg.known(9).is_none());
    }

    /// 退出后删掉登记；长驻进程不会因为短命进程多而被挤出注册表
    #[test]
    fn forget_and_long_lived_survive() {
        let mut reg = ProcessRegistry::default();
        reg.seed(1, "systemd", None);
        for pid in 2..(MAX_ENTRIES as u32 * 3) {
            reg.register(pid, Some(1));
            reg.forget(pid);
        }
        assert!(reg.known(1).is_some(), "长驻进程应一直在表里");
        assert!(reg.known(2).is_none());
    }

    /// 每次 register 分配独立 GUID。
    #[test]
    fn guids_are_distinct() {
        let mut reg = ProcessRegistry::default();
        let mut seen = std::collections::HashSet::new();
        for pid in 1..=1000u32 {
            let (g, _) = reg.register(pid, None);
            assert!(seen.insert(g), "GUID 不应重复");
        }
    }
}
