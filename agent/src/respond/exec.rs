//! 命令执行：平台下发什么就执行什么，放行与审批全部在平台侧判定。
//!
//! 一次性执行、带超时、输出截断，不支持交互。Linux 交给 `sh -c`，Windows 交给
//! PowerShell。注意：后台子进程若继承了输出管道（`cmd &` 不重定向），读端会一直
//! 等到超时——与 ssh 的行为一致。

use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command as Proc};

use super::{Outcome, Output};
use crate::pb::{Command, command_result::Status};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// stdout / stderr 各自的保留上限。超出部分照样读掉丢弃，否则刷屏的命令会写满管道卡住
const OUTPUT_LIMIT: usize = 64 * 1024;

pub async fn run(cmd: &Command) -> Outcome {
    if cmd.cmd.is_empty() {
        return Outcome::failed("未指定命令");
    }
    let timeout = match cmd.timeout_ms {
        0 => DEFAULT_TIMEOUT,
        ms => Duration::from_millis(ms.into()),
    };

    let mut child = match shell(&cmd.cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return Outcome::failed(format!("启动失败: {e}")),
    };

    let (out, err) = (child.stdout.take(), child.stderr.take());
    let collected = tokio::time::timeout(timeout, async {
        tokio::join!(read_capped(out), read_capped(err), child.wait())
    })
    .await;

    let Ok(((stdout, out_cut), (stderr, err_cut), waited)) = collected else {
        kill_tree(&mut child).await;
        return Outcome::failed(format!("超过 {}s 未结束，已终止", timeout.as_secs()));
    };
    let code = match waited {
        Ok(status) => status.code().unwrap_or(-1), // 被信号终止没有退出码
        Err(e) => return Outcome::failed(format!("等待进程失败: {e}")),
    };
    Outcome {
        status: Status::Succeeded,
        detail: format!("退出码 {code}"),
        output: Output {
            exit_code: code,
            stdout,
            stderr,
            truncated: out_cut || err_cut,
        },
    }
}

/// 读完整个流，只保留前 OUTPUT_LIMIT 字节。
async fn read_capped(stream: Option<impl AsyncRead + Unpin>) -> (String, bool) {
    let Some(mut stream) = stream else {
        return (String::new(), false);
    };
    let (mut kept, mut cut, mut buf) = (Vec::new(), false, [0u8; 8192]);
    while let Ok(n @ 1..) = stream.read(&mut buf).await {
        let room = OUTPUT_LIMIT - kept.len();
        kept.extend_from_slice(&buf[..n.min(room)]);
        cut |= n > room;
    }
    (String::from_utf8_lossy(&kept).into_owned(), cut)
}

#[cfg(unix)]
fn shell(line: &str) -> Proc {
    let mut c = Proc::new("sh");
    // 独立进程组，超时时整组杀掉，不留孤儿
    c.arg("-c").arg(line).process_group(0);
    c
}

#[cfg(windows)]
fn shell(line: &str) -> Proc {
    let mut c = Proc::new("powershell.exe");
    // 中文 Windows 控制台默认 GBK，强制 UTF-8 输出，否则回传的是乱码
    let script = format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8; {line}");
    c.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
    c
}

/// Windows 上只杀 PowerShell 本身，它拉起的子进程不随之结束（原型阶段可接受）。
async fn kill_tree(child: &mut Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // SAFETY: kill 只读取参数；负 pid 表示整个进程组
        unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
    }
    let _ = child.kill().await;
}
