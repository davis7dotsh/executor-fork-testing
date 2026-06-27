use std::{
    net::SocketAddr,
    os::fd::{FromRawFd, OwnedFd, RawFd},
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use executor::{AppConfig, DEFAULT_BIND_ADDRESS, ExecutorApp, cli};
use ipnet::IpNet;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "executor", about = "The local Executor gateway", version)]
struct Cli {
    #[arg(
        long,
        global = true,
        env = "EXECUTOR_BASE_URL",
        default_value = cli::DEFAULT_BASE_URL
    )]
    base_url: String,
    #[arg(
        long,
        global = true,
        env = "EXECUTOR_API_TOKEN",
        hide_env_values = true
    )]
    api_token: Option<String>,
    #[arg(long, global = true)]
    json: bool,
    #[arg(
        long,
        global = true,
        help = "Allow API tokens over plaintext HTTP to a non-loopback server"
    )]
    allow_insecure_http: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Server(ServerArgs),
    Call(cli::CallArgs),
    Tools(cli::ToolsArgs),
    Open,
    Mcp,
    Service(executor::service::ServiceArgs),
    #[command(hide = true)]
    SandboxWorker(SandboxWorkerArgs),
}

#[derive(Args)]
struct SandboxWorkerArgs {
    #[arg(long)]
    ipc_fd: std::os::fd::RawFd,
    #[arg(long)]
    generation: u64,
}

#[derive(Args)]
struct ServerArgs {
    #[arg(long, default_value = DEFAULT_BIND_ADDRESS)]
    bind: SocketAddr,
    #[arg(long, env = "EXECUTOR_DATA_DIR")]
    data_dir: Option<PathBuf>,
    #[arg(long, env = "EXECUTOR_MASTER_KEY_FILE")]
    master_key_file: Option<PathBuf>,
    #[arg(long, env = "EXECUTOR_MCP_STDIO_TEMPLATES_FILE")]
    mcp_stdio_templates: Option<PathBuf>,
    #[arg(long, env = "EXECUTOR_PUBLIC_ORIGIN")]
    public_origin: Option<String>,
    #[arg(
        long = "trusted-proxy",
        env = "EXECUTOR_TRUSTED_PROXIES",
        value_delimiter = ',',
        value_name = "CIDR",
        help = "Trust X-Forwarded-For only from these proxy CIDRs (repeat or comma-separate)"
    )]
    trusted_proxies: Vec<IpNet>,
    #[arg(long)]
    allow_unsafe_http_non_loopback: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("executor=info")),
        )
        .init();

    let arguments = Cli::parse();
    let connection = cli::ConnectionOptions {
        base_url: arguments.base_url,
        api_token: arguments.api_token,
        json: arguments.json,
        allow_insecure_http: arguments.allow_insecure_http,
    };
    match arguments.command {
        Command::Server(args) => run_server(args).await,
        Command::Call(args) => cli::call(connection, args).await,
        Command::Tools(args) => cli::tools(connection, args).await,
        Command::Open => cli::open(&connection),
        Command::Mcp => cli::mcp(connection).await,
        Command::Service(args) => executor::service::execute(args)?.emit(),
        Command::SandboxWorker(args) => {
            let ipc = take_worker_socket(args.ipc_fd)?;
            executor::runtime::worker_main(ipc, args.generation)
                .await
                .map_err(anyhow::Error::from)
        }
    }
}

fn take_worker_socket(raw_fd: RawFd) -> Result<OwnedFd> {
    if raw_fd != 3 || unsafe { libc::fcntl(raw_fd, libc::F_GETFD) } == -1 {
        anyhow::bail!("sandbox IPC descriptor is invalid");
    }
    let mut socket_type = 0;
    let mut socket_type_length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let socket_result = unsafe {
        libc::getsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            std::ptr::from_mut(&mut socket_type).cast(),
            &mut socket_type_length,
        )
    };
    let mut peer = std::mem::MaybeUninit::<libc::sockaddr_storage>::uninit();
    let mut peer_length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let peer_result =
        unsafe { libc::getpeername(raw_fd, peer.as_mut_ptr().cast(), &mut peer_length) };
    if socket_result == -1 || socket_type != libc::SOCK_STREAM || peer_result == -1 {
        anyhow::bail!("sandbox IPC descriptor is not a connected stream socket");
    }
    let peer = unsafe { peer.assume_init() };
    if i32::from(peer.ss_family) != libc::AF_UNIX {
        anyhow::bail!("sandbox IPC descriptor is not a Unix socket");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
}

async fn run_server(args: ServerArgs) -> Result<()> {
    let mut config = match args.data_dir {
        Some(data_dir) => AppConfig::new(data_dir),
        None => AppConfig::system_default()?,
    };
    config = config
        .with_master_key_file(args.master_key_file)
        .with_mcp_stdio_templates_file(args.mcp_stdio_templates)
        .with_trusted_proxies(args.trusted_proxies);
    let listener = TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("could not bind Executor to {}", args.bind))?;
    let bound_address = listener
        .local_addr()
        .context("could not determine Executor's bound address")?;
    config = match args.public_origin {
        Some(public_origin) => config.with_origin(&public_origin)?,
        None => config.with_default_origin_for_bind(bound_address)?,
    };
    config.validate_bind(bound_address, args.allow_unsafe_http_non_loopback)?;
    let app = ExecutorApp::open(config.clone())
        .await
        .context("Executor could not initialize")?;

    if let Some(setup_token) = app.setup_token() {
        println!("Complete first-boot setup at:");
        println!("{}/setup#token={setup_token}", config.public_origin());
    }

    info!(address = %bound_address, "Executor is listening");
    let router = app.router();
    let shutdown = app.shutdown_handle();
    let server_result = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        shutdown.begin();
    })
    .await
    .context("Executor server stopped unexpectedly");
    app.shutdown().await;
    server_result
}

#[cfg(unix)]
async fn shutdown_signal() {
    let mut terminate =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(terminate) => terminate,
            Err(error) => {
                tracing::error!(error = %error, "could not listen for the terminate signal");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(error) = result {
                tracing::error!(error = %error, "could not listen for the interrupt signal");
            }
        }
        _ = terminate.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn parses_retained_client_commands_and_global_connection_flags() {
        let cli = Cli::try_parse_from([
            "executor",
            "--base-url",
            "http://localhost:9000",
            "--api-token",
            "secret",
            "--json",
            "call",
            "github",
            "issues_create",
            r#"{"title":"Bug"}"#,
        ])
        .expect("call command");
        assert_eq!(cli.base_url, "http://localhost:9000");
        assert_eq!(cli.api_token.as_deref(), Some("secret"));
        assert!(cli.json);
        let Command::Call(arguments) = cli.command else {
            panic!("expected call command");
        };
        assert_eq!(arguments.values.len(), 3);

        assert!(Cli::try_parse_from(["executor", "tools", "sources"]).is_ok());
        assert!(Cli::try_parse_from(["executor", "mcp"]).is_ok());
        assert!(Cli::try_parse_from(["executor", "open"]).is_ok());
        for action in ["status", "start", "stop", "restart", "remove"] {
            assert!(Cli::try_parse_from(["executor", "service", action]).is_ok());
        }
        assert!(Cli::try_parse_from(["executor", "service", "install", "--no-start"]).is_ok());
    }

    #[test]
    fn reports_the_cargo_package_version() {
        let Err(error) = Cli::try_parse_from(["executor", "--version"]) else {
            panic!("expected clap to display the version");
        };

        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
        assert_eq!(
            error.to_string(),
            format!("executor {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}
