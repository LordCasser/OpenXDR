//! 同名 ETW 会话的停止口径。
//!
//! 会话名固定（见 windows.rs），新会话起来前先按名停掉同名旧会话；trace 句柄 drop 时按句柄停会话。
//! 实机验证过：旧会话已被按名停掉、同名新会话起来之后，再 drop 旧句柄，停掉的是新会话。
//! 配置切换时，上一轮采集的线程收尾与新一轮的启动并发，就会这样把新会话停掉——
//! 进程或 DNS 事件全停，进程通道要等活性检测约 6 分钟后才重建，DNS 没人兜。
//!
//! 这里给每个会话名记一个代次：每次按名停旧会话都加一，句柄只在自己仍是最新一代时才按句柄停；
//! 已被顶替的旧句柄直接放手——它的会话早被按名停掉，消费线程随之退出，只漏一个句柄和回调的内存。
//! 按名停、新建、按句柄停都在同一把锁里，不会交错。

use std::sync::Mutex;

static GENERATIONS: Mutex<Vec<(&'static str, u64)>> = Mutex::new(Vec::new());

/// 一个归本进程所有的命名会话；drop 时只在仍是该名字的最新一代时才真正停
pub struct Owned<T> {
    trace: Option<T>,
    name: &'static str,
    generation: u64,
}

/// 按名停掉同名旧会话，再新建一个。代次在按名停之前就加：新建失败时，
/// 更早的句柄也已经过期，不能再按句柄去停之后别人建的会话
pub fn start<T, E>(
    name: &'static str,
    stop_by_name: impl FnOnce(),
    create: impl FnOnce() -> Result<T, E>,
) -> Result<Owned<T>, E> {
    let mut generations = GENERATIONS.lock().unwrap_or_else(|e| e.into_inner());
    let generation = match generations.iter_mut().find(|(n, _)| *n == name) {
        Some((_, g)) => {
            *g += 1;
            *g
        }
        None => {
            generations.push((name, 1));
            1
        }
    };
    stop_by_name();
    let trace = create()?;
    Ok(Owned {
        trace: Some(trace),
        name,
        generation,
    })
}

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        let generations = GENERATIONS.lock().unwrap_or_else(|e| e.into_inner());
        let latest = generations
            .iter()
            .any(|(n, g)| *n == self.name && *g == self.generation);
        let trace = self.trace.take();
        if latest {
            drop(trace);
        } else {
            eprintln!("ETW 会话 {} 已被同名新会话顶替，旧句柄放手不停", self.name);
            std::mem::forget(trace);
        }
    }
}

/// 起一个命名的用户态实时会话
#[cfg(target_os = "windows")]
pub fn user_trace(
    name: &'static str,
    provider: ferrisetw::provider::Provider,
) -> Result<Owned<ferrisetw::trace::UserTrace>, ferrisetw::trace::TraceError> {
    use ferrisetw::trace::{UserTrace, stop_trace_by_name};
    start(
        name,
        || {
            let _ = stop_trace_by_name(name);
        },
        || {
            UserTrace::new()
                .named(name.to_string())
                .enable(provider)
                .start_and_process()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// 模拟 ETW：会话按名字登记，句柄是槽位号；按名停腾出槽位，新会话复用最小的空槽位，
    /// 按句柄停的是槽位上现在的会话——实机就是这么停错的
    #[derive(Default)]
    struct Etw {
        slots: Vec<Option<(&'static str, u32)>>,
        next_id: u32,
    }

    impl Etw {
        fn stop_by_name(&mut self, name: &str) {
            for slot in &mut self.slots {
                if slot.is_some_and(|(n, _)| n == name) {
                    *slot = None;
                }
            }
        }
        fn create(&mut self, name: &'static str) -> usize {
            self.next_id += 1;
            let session = Some((name, self.next_id));
            match self.slots.iter().position(Option::is_none) {
                Some(i) => {
                    self.slots[i] = session;
                    i
                }
                None => {
                    self.slots.push(session);
                    self.slots.len() - 1
                }
            }
        }
        fn running(&self, name: &str) -> Vec<u32> {
            self.slots
                .iter()
                .flatten()
                .filter(|(n, _)| *n == name)
                .map(|(_, id)| *id)
                .collect()
        }
    }

    /// 句柄：drop 即按槽位停
    struct Handle(usize, Rc<RefCell<Etw>>);
    impl Drop for Handle {
        fn drop(&mut self) {
            self.1.borrow_mut().slots[self.0] = None;
        }
    }

    fn open(etw: &Rc<RefCell<Etw>>, name: &'static str, fail: bool) -> Result<Owned<Handle>, ()> {
        start(
            name,
            || etw.borrow_mut().stop_by_name(name),
            || {
                if fail {
                    return Err(());
                }
                let slot = etw.borrow_mut().create(name);
                Ok(Handle(slot, etw.clone()))
            },
        )
    }

    /// 配置切换：新会话起来后旧一轮才收尾，旧句柄不能把新会话停掉
    #[test]
    fn stale_handle_leaves_new_session() {
        let etw = Rc::new(RefCell::new(Etw::default()));
        let old = open(&etw, "test-switch", false).unwrap();
        let new = open(&etw, "test-switch", false).unwrap();
        assert_eq!(etw.borrow().running("test-switch"), vec![2]);
        drop(old);
        assert_eq!(etw.borrow().running("test-switch"), vec![2], "新会话还在");
        drop(new);
        assert!(
            etw.borrow().running("test-switch").is_empty(),
            "最新一代照常停"
        );
    }

    /// 活性重建：先停旧的再起新的，照常按句柄停
    #[test]
    fn sequential_rebuild_stops_normally() {
        let etw = Rc::new(RefCell::new(Etw::default()));
        let first = open(&etw, "test-rebuild", false).unwrap();
        drop(first);
        assert!(etw.borrow().running("test-rebuild").is_empty());
        let second = open(&etw, "test-rebuild", false).unwrap();
        assert_eq!(etw.borrow().running("test-rebuild"), vec![2]);
        drop(second);
        assert!(etw.borrow().running("test-rebuild").is_empty());
    }

    /// 新建失败也算换代：旧句柄已过期，之后别人建的同名会话不能被它停掉
    #[test]
    fn failed_start_still_retires_old_handle() {
        let etw = Rc::new(RefCell::new(Etw::default()));
        let old = open(&etw, "test-fail", false).unwrap();
        assert!(open(&etw, "test-fail", true).is_err());
        let later = open(&etw, "test-fail", false).unwrap();
        drop(old);
        assert_eq!(etw.borrow().running("test-fail"), vec![2]);
        drop(later);
        assert!(etw.borrow().running("test-fail").is_empty());
    }

    /// 不同名字各算各的代次
    #[test]
    fn names_are_independent() {
        let etw = Rc::new(RefCell::new(Etw::default()));
        let a = open(&etw, "test-a", false).unwrap();
        let b = open(&etw, "test-b", false).unwrap();
        drop(a);
        assert!(etw.borrow().running("test-a").is_empty());
        assert_eq!(etw.borrow().running("test-b"), vec![2]);
        drop(b);
    }
}
