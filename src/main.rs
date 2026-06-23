use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use executor::{AppConfig, DEFAULT_BIND_ADDRESS, ExecutorApp};
use ipnet::IpNet;
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "executor", about = "The local Executor gateway")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Server(ServerArgs),
}

#[derive(Args)]
struct ServerArgs {
    #[arg(long, default_value = DEFAULT_BIND_ADDRESS)]
    bind: SocketAddr,
    #[arg(long, env = "EXECUTOR_DATA_DIR")]
    data_dir: Option<PathBuf>,
    #[arg(long, env = "EXECUTOR_MASTER_KEY_FILE")]
    master_key_file: Option<PathBuf>,
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

    match Cli::parse().command {
        Command::Server(args) => run_server(args).await,
    }
}

async fn run_server(args: ServerArgs) -> Result<()> {
    let mut config = match args.data_dir {
        Some(data_dir) => AppConfig::new(data_dir),
        None => AppConfig::system_default()?,
    };
    config = config
        .with_master_key_file(args.master_key_file)
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
    axum::serve(
        listener,
        app.router()
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("Executor server stopped unexpectedly")
}
