//! 使用 GUID 与创建时间验证身份，并通过稳定的系统句柄结束同一个进程实例。
use super::Outcome;
use crate::{pb::Command, process_identity};

pub fn kill(cmd: &Command) -> Outcome {
    if cmd.pid == 0 {
        return Outcome::failed("未指定 pid");
    }
    let target = match process_identity::verified(cmd.pid, &cmd.process_guid) {
        Ok(target) => target,
        Err(e) => return Outcome::failed(e),
    };
    match target.terminate() {
        Ok(()) => Outcome::ok(format!("已结束进程 {}", cmd.pid)),
        Err(e) => Outcome::failed(format!("结束进程 {} 失败: {e}", cmd.pid)),
    }
}
