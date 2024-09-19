use anyhow::Result;
use futures::stream::StreamExt;
use s2n_quic::provider::datagram::default::Endpoint;
use s2n_quic::Server;
use signal_hook::consts::signal::*;
use signal_hook_tokio::Signals;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{env, fmt};
use tokio::time::{self};

///
struct Parameters {
    pub server_crt_file_path: String,
    pub server_key_file_path: String,
    pub bind_address: SocketAddr,
    pub recv_timeout: u64,
    pub datagram_queue_len: usize,
}

impl Parameters {
    fn init() -> Self {
        let server_crt_file_path =
            env::var("SERVER_CRT_FILE_PATH").unwrap_or_else(|_e| "server.crt".to_string());

        let server_key_file_path =
            env::var("SERVER_KEY_FILE_PATH").unwrap_or_else(|_e| "server.key".to_string());

        let bind_address = env::var("BIND_ADDRESS")
            .map(|value| match value.parse::<SocketAddr>() {
                Ok(addr) => addr,
                Err(_e) => "[::]:443".parse::<SocketAddr>().unwrap(),
            })
            .unwrap_or_else(|_e| "[::]:443".parse::<SocketAddr>().unwrap());

        let recv_timeout = match env::var("RECV_TIMEOUT") {
            Ok(value) => match value.parse::<u64>() {
                Ok(num) => num,
                Err(_e) => 180,
            },
            Err(_e) => 180,
        };

        let datagram_queue_len = match env::var("DATAGRAM_QUEUE_LEN") {
            Ok(value) => match value.parse::<usize>() {
                Ok(num) => num,
                Err(_e) => 2048,
            },
            Err(_e) => 2048,
        };

        Parameters {
            server_crt_file_path: server_crt_file_path,
            server_key_file_path: server_key_file_path,
            bind_address: bind_address,
            recv_timeout: recv_timeout,
            datagram_queue_len: datagram_queue_len,
        }
    }
}

///
impl std::fmt::Display for Parameters {
    ///
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "server_crt_file_path={}\n", self.server_crt_file_path)?;
        write!(f, "server_key_file_path={}\n", self.server_key_file_path)?;
        write!(f, "bind_address={}\n", self.bind_address)?;
        write!(f, "recv_timeout={}\n", self.recv_timeout)
    }
}

async fn run_quic_server(
    running: Arc<AtomicBool>,
    bind_address: SocketAddr,
    server_cert_pem: String,
    server_key_pem: String,
    datagram_queue_len: usize,
) -> Result<()> {
    log::info!("server_cert_pem path={}", server_cert_pem);
    log::info!("server_key_pem path={}", server_key_pem);

    let datagram_provider = Endpoint::builder()
        .with_send_capacity(datagram_queue_len)?
        .build()?;

    let mut server = Server::builder()
        .with_tls((Path::new(&server_cert_pem), Path::new(&server_key_pem)))?
        .with_io(bind_address)?
        .with_datagram(datagram_provider)?
        .start()?;

    log::info!("QUIC Server is listening on {}", bind_address);

    while running.load(Ordering::SeqCst) {
        log::trace!("loop: run_quic_server");

        let one_sec_timer = time::sleep(Duration::from_secs(1));
        tokio::pin!(one_sec_timer);

        // クライアントからの接続を処理
        tokio::select! {
            () = &mut one_sec_timer => {
            }

            res = server.accept() => {
                match res {
                    Some(mut connection) => {
                        // クライアントからの接続を処理
                        // クライアントソケット一つ一つを処理するタスクをspawnするために、必要なArcのコンテナなどをclone
                        let client_addr = match connection.remote_addr() {
                            Ok(addr) => addr,
                            Err(_) => {
                                log::warn!("failed to remote_addr");
                                continue;
                            }
                        };

                        log::info!("quic accepted client addr={}", client_addr);

                        let _ = match connection.accept_bidirectional_stream().await {
                            Ok(Some(s)) => s,
                            Ok(None) => {
                                log::warn!(
                                    "failed to get bidirectional stream client_addr={}",
                                    client_addr
                                );
                                continue;
                            }
                            Err(e) => {
                                log::warn!(
                                    "failed to get bidirectional stream client_addr={}, e={}",
                                    client_addr,
                                    e
                                );
                                continue;
                            }
                        };

                        // コネクションの切断
                        connection.close(0u32.into());
                    }
                    None => {
                    }
                }
            }
        }
    }

    Ok(())
}

/// `run_server` は、TLSを使用した非同期TCPサーバーを実行します。
///
/// サーバーは、指定されたアドレスとポートでリッスンし、クライアントからの接続要求を処理します。
/// クライアントごとに新しいタスクが生成され、handle_client関数で処理されます。
///
/// サーバーは、SIGINT（Ctrl + C）シグナルを受信すると、クリーンアップを行い、終了します。
///
/// # Returns
///
/// この関数は、サーバーが正常に起動して実行された場合は `Ok(())` を返し、
/// 何らかのエラーが発生した場合は `Err(Box<dyn std::error::Error>)` を返します。
///
/// # Errors
///
/// この関数は、TLS設定の問題、ポートのバインドの失敗、信号ハンドリングの問題、
/// クライアント接続の処理中にエラーが発生した場合にエラーを返すことがあります。
///
/// # Examples
///
/// サーバーを実行するには、次のように `run_server` を呼び出します。
///
/// ```no_run
/// #[tokio::main]
/// async fn main() {
///     if let Err(e) = run_server().await {
///         eprintln!("Error: {}", e);
///     }
/// }
/// ```
async fn run_server(running: Arc<AtomicBool>) -> Result<()> {
    let params = Parameters::init();
    log::info!("parameters:\n{}", params);

    let quic_server_task = {
        let running = running.clone();
        let bind_address = params.bind_address.clone();
        let task = tokio::spawn(async move {
            match run_quic_server(
                running,
                bind_address,
                params.server_crt_file_path.clone(),
                params.server_key_file_path.clone(),
                params.datagram_queue_len,
            )
            .await
            {
                Ok(_) => {}
                Err(e) => {
                    log::warn!("error occurred run_quic_server e={}", e);
                }
            }
        });
        task
    };

    let _ = tokio::join!(quic_server_task);

    log::info!("Server shutdown complete");

    Ok(())
}

///
async fn handle_signals(running: Arc<AtomicBool>, mut signals: Signals) {
    while let Some(signal) = signals.next().await {
        match signal {
            SIGINT | SIGTERM | SIGQUIT => {
                running.store(false, Ordering::SeqCst);
                log::info!("Received signal, shutting down...");
                break;
            }
            _ => (),
        }
    }
}

/// This is main function of tokio
#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_micros()
        .init();

    let running = Arc::new(AtomicBool::new(true));
    let signals = Signals::new(&[SIGTERM, SIGINT, SIGQUIT])?;
    let handle = signals.handle();
    let signals_task = tokio::task::spawn(handle_signals(running.clone(), signals));

    run_server(running).await?;

    handle.close();
    signals_task.await?;

    Ok(())
}
