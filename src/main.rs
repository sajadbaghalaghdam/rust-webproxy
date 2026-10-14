//! webproxy — end-to-end encrypted HTTP tunnel.
//!
//! The same binary runs as `server` (next to the destination services, behind the CDN) or
//! as `client` (next to the applications); the role is chosen by `mode` in the config.

mod body;
mod cli;
mod client;
mod config;
mod crypto;
mod net;
mod proto;
mod server;
mod stats;
mod util;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::config::Config;

#[derive(Parser)]
#[command(name = "webproxy", version, about = "End-to-end encrypted HTTP tunnel that keeps traffic opaque to CDNs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum Mode {
    Server,
    Client,
}

#[derive(Subcommand)]
enum Command {
    /// Run the service; the server/client role comes from `mode` in the config file.
    Run {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Create the config file of a new server or client.
    Init {
        /// Role of this installation.
        #[arg(long, value_enum)]
        mode: Mode,
        /// Output file.
        #[arg(short, long)]
        out: PathBuf,
        /// Listen address (server default 0.0.0.0:8443, client default 127.0.0.1:8080).
        #[arg(long)]
        listen: Option<String>,
        /// [server] Name of the first paired client.
        #[arg(long, default_value = "client1")]
        name: String,
        /// [client] Tunnel URL of the server, e.g. https://cdn.example.com/api/v1/stream
        #[arg(long, required_if_eq("mode", "client"))]
        server_url: Option<String>,
        /// [client] File holding the pairing key printed by the server's `init` or `add-client`
        /// (takes precedence over --key / WEBPROXY_KEY).
        #[arg(long)]
        key_file: Option<PathBuf>,
        /// [client] The pairing key itself (prefer --key-file: arguments are visible to other users).
        #[arg(long, env = "WEBPROXY_KEY", hide_env_values = true)]
        key: Option<String>,
        /// [client] Destination for requests that don't name one, e.g. http://127.0.0.1:3000
        #[arg(long)]
        default_target: Option<String>,
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
    /// Pair a new client: add it to a server config and print its key.
    AddClient {
        #[arg(short, long)]
        config: PathBuf,
        #[arg(long)]
        name: String,
    },
    /// Print a new random pairing key.
    Keygen,
    /// Show live statistics of a running instance.
    Status {
        /// Config of the instance (its status_listen address is used).
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Status address instead of --config, e.g. 127.0.0.1:9901
        #[arg(long)]
        addr: Option<String>,
        /// Print the raw JSON.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Run { config } => run(&config),
        Command::Init { mode: Mode::Server, out, listen, name, force, .. } => {
            cli::init_server(&out, listen.as_deref().unwrap_or("0.0.0.0:8443"), &name, force)
        }
        Command::Init { mode: Mode::Client, out, listen, server_url, key_file, key, default_target, force, .. } => {
            let key = match (key_file, key) {
                (Some(path), _) => Ok(cli::KeySource::File(path)),
                (None, Some(value)) => Ok(cli::KeySource::Value(value)),
                (None, None) => Err("a client needs --key-file (or --key / WEBPROXY_KEY)".to_string()),
            };
            key.and_then(|key| {
                let init = cli::ClientInit { server_url: server_url.unwrap_or_default(), key, default_target };
                cli::init_client(&out, listen.as_deref().unwrap_or("127.0.0.1:8080"), &init, force)
            })
        }
        Command::AddClient { config, name } => cli::add_client(&config, &name),
        Command::Keygen => cli::keygen(),
        Command::Status { config, addr, json } => cli::status(config.as_deref(), addr.as_deref(), json),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(path: &Path) -> Result<(), String> {
    let cfg = config::load(path)?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("WEBPROXY_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    raise_open_file_limit();
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if cfg.workers() > 0 {
        builder.worker_threads(cfg.workers());
    }
    let rt = builder.enable_all().build().map_err(|e| format!("cannot start the runtime: {e}"))?;
    let result = rt.block_on(async {
        let (stop, stopped) = watch::channel(false);
        let service = async move {
            match cfg {
                Config::Server(c) => server::run(c, stopped).await,
                Config::Client(c) => client::run(c, stopped).await,
            }
        };
        tokio::pin!(service);
        tokio::select! {
            r = &mut service => r,
            () = shutdown_signal() => {
                info!("shutting down: no new connections, letting in-flight requests finish");
                let _ = stop.send(true);
                tokio::select! {
                    r = &mut service => r,
                    () = shutdown_signal() => {
                        warn!("second signal: exiting without waiting for in-flight requests");
                        Ok(())
                    }
                }
            }
        }
    });
    rt.shutdown_timeout(Duration::from_secs(1));
    result
}

/// Each tunnelled request needs a socket on both sides; lift the soft descriptor limit to
/// the hard limit so a default of 1024 does not cap the service.
#[cfg(unix)]
fn raise_open_file_limit() {
    match rlimit::increase_nofile_limit(u64::MAX) {
        Ok(limit) => tracing::debug!("open file limit: {limit}"),
        Err(e) => tracing::warn!("cannot raise the open file limit: {e}"),
    }
}

#[cfg(not(unix))]
fn raise_open_file_limit() {}

/// Ctrl-C, plus SIGTERM on Unix (systemd stop) and Ctrl-Break on Windows (service managers).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    #[cfg(windows)]
    {
        if let Ok(mut ctrl_break) = tokio::signal::windows::ctrl_break() {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = ctrl_break.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
