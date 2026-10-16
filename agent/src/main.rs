use std::time::Duration;

use tokio_stream::wrappers::ReceiverStream;

// 生成代码不归我们管，新版 clippy 对 tonic 的 async_trait 展开报 double_must_use
#[allow(clippy::double_must_use)]
pub mod pb {
    tonic::include_proto!("openxdr.agent.v1");
}

mod collector;
mod enroll;
mod process_identity;
mod respond;
mod tls;
mod upgrade;

use pb::agent_service_client::AgentServiceClient;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["version"] => println!("{}", env!("CARGO_PKG_VERSION")),
        ["enroll-request", dir] => match enroll::request(dir.as_ref()) {
            Ok(json) => println!("{json}"),
            Err(e) => exit(&format!("生成接入请求失败：{e}")),
        },
        ["enroll-apply", dir] => {
            if let Err(e) = enroll::apply(dir.as_ref(), std::io::stdin()) {
                exit(&format!("写入接入配置失败：{e}"));
            }
        }
        _ => {
            enroll::load_env_file(&enroll::default_env_file());
            agent();
        }
    }
}

fn exit(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(1)
}

#[tokio::main]
async fn agent() {
    let server = std::env::var("OPENXDR_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8081".into());

    loop {
        if let Err(e) = run(&server).await {
            eprintln!("link down: {e}, retrying in 5s");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn run(server: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = AgentServiceClient::new(tls::connect(server).await?);

    let resp = client
        .register(pb::RegisterRequest {
            hostname: enroll::hostname(),
            os: std::env::consts::OS.into(),
            ip_addrs: local_ips(),
            agent_version: env!("CARGO_PKG_VERSION").into(),
            arch: std::env::consts::ARCH.into(),
            binary_sha256: upgrade::self_sha256().into(),
        })
        .await?
        .into_inner();
    if !resp.upgrade_sha256.is_empty() {
        match upgrade::apply(&mut client, &resp.upgrade_platform, &resp.upgrade_sha256).await {
            Ok(()) => std::process::exit(upgrade::EXIT_UPGRADED),
            Err(e) => eprintln!("自动升级失败，继续运行当前版本：{e}"),
        }
    }
    let cfg = collector::Config::parse(&resp.config_json);
    println!("registered: agent_id={} config={cfg:?}", resp.agent_id);

    // 指令通道与事件上报并行：上报是长连接，不能让它挡住指令
    let commands = tokio::spawn(command_loop(client.clone(), resp.agent_id.clone()));

    let events = collector::spawn(resp.agent_id, cfg);
    let report = client.report_events(ReceiverStream::new(events)).await;
    commands.abort();
    report?;
    Ok(())
}

/// 常驻指令通道：先发一条带 agent_id 的空结果认领连接，
/// 之后逐条执行 server 推来的指令并回执。
async fn command_loop(client: AgentServiceClient<tonic::transport::Channel>, agent_id: String) {
    loop {
        command_stream(client.clone(), agent_id.clone()).await;
        eprintln!("指令通道断开，5 秒后重连");
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn command_stream(
    mut client: AgentServiceClient<tonic::transport::Channel>,
    agent_id: String,
) {
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    // 认领消息：只带 agent_id，command_id 为空
    if tx
        .send(pb::CommandResult {
            agent_id: agent_id.clone(),
            ..Default::default()
        })
        .await
        .is_err()
    {
        return;
    }

    let mut inbound = match client.commands(ReceiverStream::new(rx)).await {
        Ok(stream) => stream.into_inner(),
        Err(e) => {
            eprintln!("指令通道建立失败: {e}");
            return;
        }
    };

    while let Ok(Some(cmd)) = inbound.message().await {
        // exec 可能跑很久，并发执行；结束进程与隔离保持顺序，先隔离后解除不能颠倒
        if cmd.kind() == pb::CommandKind::Exec {
            tokio::spawn(run_command(agent_id.clone(), cmd, tx.clone()));
        } else if !run_command(agent_id.clone(), cmd, tx.clone()).await {
            return;
        }
    }
}

/// 执行一条指令并回执；回执通道已关闭时返回 false。
async fn run_command(
    agent_id: String,
    cmd: pb::Command,
    tx: tokio::sync::mpsc::Sender<pb::CommandResult>,
) -> bool {
    let result = respond::execute(&agent_id, &cmd).await;
    println!("执行指令 {}: {}", cmd.id, result.detail);
    tx.send(result).await.is_ok()
}

/// 本机非回环 IP。server 按这些地址把探针看到的网络流量归属到本资产，
/// 端点侧和流量侧的证据才能落到同一实体上。
fn local_ips() -> Vec<String> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback())
        .map(|i| i.addr.ip().to_string())
        .collect()
}

#[cfg(test)]
mod command_tests {
    use super::*;
    use pb::agent_service_server::{AgentService, AgentServiceServer};
    use tonic::{Request, Response, Status, Streaming};

    struct Server(tokio::sync::mpsc::Sender<()>);
    #[tonic::async_trait]
    impl AgentService for Server {
        async fn register(
            &self,
            _: Request<pb::RegisterRequest>,
        ) -> Result<Response<pb::RegisterResponse>, Status> {
            Err(Status::unimplemented("测试只使用指令流"))
        }
        async fn report_events(
            &self,
            _: Request<Streaming<pb::AgentEvent>>,
        ) -> Result<Response<pb::ReportAck>, Status> {
            Err(Status::unimplemented("测试不启动事件上报"))
        }
        type DownloadAgentStream =
            tokio_stream::Iter<std::vec::IntoIter<Result<pb::AgentChunk, Status>>>;
        async fn download_agent(
            &self,
            _: Request<pb::DownloadRequest>,
        ) -> Result<Response<Self::DownloadAgentStream>, Status> {
            Err(Status::unimplemented("测试不下载安装包"))
        }
        type CommandsStream = tokio_stream::Iter<std::vec::IntoIter<Result<pb::Command, Status>>>;
        async fn commands(
            &self,
            request: Request<Streaming<pb::CommandResult>>,
        ) -> Result<Response<Self::CommandsStream>, Status> {
            let first = request.into_inner().message().await?.unwrap();
            assert_eq!(first.agent_id, "reconnect-test");
            self.0.send(()).await.unwrap();
            // 正常关闭指令流，不断开 HTTP/2 连接。
            Ok(Response::new(tokio_stream::iter(Vec::new())))
        }
    }
    #[tokio::test]
    async fn command_stream_reconnects_without_event_stream_restart() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (connections, incoming) = tokio::sync::mpsc::channel(4);
        let accept = tokio::spawn(async move {
            loop {
                let socket = listener.accept().await.map(|(s, _)| s);
                if connections.send(socket).await.is_err() {
                    return;
                }
            }
        });
        let (seen, mut calls) = tokio::sync::mpsc::channel(4);
        let server = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(AgentServiceServer::new(Server(seen)))
                .serve_with_incoming(ReceiverStream::new(incoming)),
        );
        let client = AgentServiceClient::connect(format!("http://{addr}"))
            .await
            .unwrap();
        let commands = tokio::spawn(command_loop(client, "reconnect-test".into()));
        let result = tokio::time::timeout(Duration::from_secs(8), async {
            assert!(calls.recv().await.is_some());
            assert!(calls.recv().await.is_some());
        })
        .await;
        commands.abort();
        server.abort();
        accept.abort();
        result.unwrap();
    }
}
