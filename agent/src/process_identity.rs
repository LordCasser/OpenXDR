//! 将采集时的 GUID 绑定到操作系统进程创建时间。处置必须同时匹配，PID 本身不是身份。
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

fn identities() -> &'static Mutex<HashMap<u32, (Uuid, u64)>> {
    static IDENTITIES: OnceLock<Mutex<HashMap<u32, (Uuid, u64)>>> = OnceLock::new();
    IDENTITIES.get_or_init(Default::default)
}

pub fn record(pid: u32, guid: Uuid) {
    let birth = Target::open(pid).and_then(|p| p.birth()).ok();
    let mut ids = identities().lock().unwrap_or_else(|e| e.into_inner());
    if ids.len() >= 65536 {
        ids.clear();
    }
    ids.remove(&pid);
    if let Some(birth) = birth {
        ids.insert(pid, (guid, birth));
    }
}

pub fn verified(pid: u32, guid: &str) -> Result<Target, String> {
    let target = Target::open(pid)?;
    let expected = Uuid::parse_str(guid).map_err(|_| "缺少合法的进程 GUID".to_string())?;
    let birth = target.birth()?;
    let ids = identities().lock().unwrap_or_else(|e| e.into_inner());
    if ids.get(&pid) != Some(&(expected, birth)) {
        return Err("进程身份不匹配或已过期，拒绝结束进程".into());
    }
    Ok(target)
}

#[cfg(target_os = "linux")]
pub struct Target {
    pid: u32,
    fd: std::os::fd::OwnedFd,
}

#[cfg(target_os = "linux")]
impl Target {
    fn open(pid: u32) -> Result<Self, String> {
        use std::os::fd::FromRawFd;
        // pidfd 固定进程实例，校验之后 PID 再被复用也不会误杀。
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            return Err(format!(
                "进程不存在或无法打开 pidfd: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self {
            pid,
            fd: unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) },
        })
    }
    fn birth(&self) -> Result<u64, String> {
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", self.pid))
            .map_err(|e| e.to_string())?;
        stat.rsplit_once(')')
            .and_then(|(_, fields)| fields.split_whitespace().nth(19))
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| "无法读取进程创建时间".into())
    }
    pub fn terminate(&self) -> Result<(), String> {
        use std::os::fd::AsRawFd;
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.fd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }
}

#[cfg(windows)]
pub struct Target(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Target {
    fn open(pid: u32) -> Result<Self, String> {
        use windows_sys::Win32::System::Threading::*;
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                0,
                pid,
            )
        };
        if handle.is_null() {
            return Err(format!(
                "进程不存在或无法打开: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self(handle))
    }
    fn birth(&self) -> Result<u64, String> {
        use windows_sys::Win32::{Foundation::FILETIME, System::Threading::GetProcessTimes};
        let (mut created, mut exited, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        if unsafe { GetProcessTimes(self.0, &mut created, &mut exited, &mut kernel, &mut user) }
            == 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
    }
    pub fn terminate(&self) -> Result<(), String> {
        if unsafe { windows_sys::Win32::System::Threading::TerminateProcess(self.0, 1) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for Target {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
pub struct Target;
#[cfg(not(any(target_os = "linux", windows)))]
impl Target {
    fn open(_: u32) -> Result<Self, String> {
        Err("当前平台不支持可靠进程身份校验".into())
    }
    fn birth(&self) -> Result<u64, String> {
        Err("不支持进程创建时间".into())
    }
    pub fn terminate(&self) -> Result<(), String> {
        Err("不支持结束进程".into())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn stale_guid_and_birth_are_rejected() {
        // 用自己的进程做只读校验，绝不调用 terminate。
        let pid = std::process::id();
        let guid = Uuid::new_v4();
        record(pid, guid);
        assert!(verified(pid, &guid.to_string()).is_ok());
        assert!(verified(pid, &Uuid::new_v4().to_string()).is_err());
        assert!(verified(pid, "").is_err());
        identities().lock().unwrap().insert(pid, (guid, 0));
        assert!(verified(pid, &guid.to_string()).is_err());
    }
}
