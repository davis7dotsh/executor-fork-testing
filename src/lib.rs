use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::Router;
use directories::ProjectDirs;
use ipnet::IpNet;
use sqlx::SqlitePool;
use thiserror::Error;
use url::Url;

pub mod actor;
mod api;
pub mod approval;
pub mod catalog;
pub mod crypto;
mod database;
pub mod execution;
pub use approval::invocation;
pub mod openapi;
pub mod outbound;
pub(crate) mod protocols;
mod request_logs;
pub mod runtime;
mod tasks;
pub mod web_assets;

pub use database::DatabaseError;

pub const DEFAULT_BIND_ADDRESS: &str = "127.0.0.1:4788";
pub const DEFAULT_ORIGIN: &str = "http://127.0.0.1:4788";

#[derive(Clone)]
pub struct AppConfig {
    pub(crate) data_dir: PathBuf,
    pub(crate) master_key_file: Option<PathBuf>,
    pub(crate) origin: Url,
    pub(crate) session_ttl_seconds: i64,
    pub(crate) trusted_proxies: Arc<[IpNet]>,
    pub(crate) runtime_executable: Option<PathBuf>,
}

impl AppConfig {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            master_key_file: None,
            origin: Url::parse(DEFAULT_ORIGIN).expect("the default public origin is valid"),
            session_ttl_seconds: 8 * 60 * 60,
            trusted_proxies: Arc::from([]),
            runtime_executable: None,
        }
    }

    pub fn system_default() -> Result<Self, ConfigError> {
        let project_dirs =
            ProjectDirs::from("dev", "Executor", "Executor").ok_or(ConfigError::NoDataDirectory)?;
        Ok(Self::new(project_dirs.data_local_dir().to_path_buf()))
    }

    pub fn with_master_key_file(mut self, master_key_file: Option<PathBuf>) -> Self {
        self.master_key_file = master_key_file;
        self
    }

    pub fn with_trusted_proxies(mut self, trusted_proxies: Vec<IpNet>) -> Self {
        self.trusted_proxies = Arc::from(trusted_proxies);
        self
    }

    pub fn with_runtime_executable(mut self, executable: PathBuf) -> Self {
        self.runtime_executable = Some(executable);
        self
    }

    pub fn with_origin(mut self, origin: &str) -> Result<Self, ConfigError> {
        self.origin = parse_public_origin(origin)?;
        Ok(self)
    }

    pub fn with_default_origin_for_bind(self, bind: SocketAddr) -> Result<Self, ConfigError> {
        if bind.ip().is_unspecified() {
            return Err(ConfigError::PublicOriginRequiredForUnspecifiedBind(bind));
        }
        self.with_origin(&format!("http://{bind}"))
    }

    pub fn public_origin(&self) -> String {
        self.origin.origin().ascii_serialization()
    }

    pub fn validate_bind(
        &self,
        bind: SocketAddr,
        allow_unsafe_http_non_loopback: bool,
    ) -> Result<(), ConfigError> {
        if self.origin.scheme() == "http"
            && !bind.ip().is_loopback()
            && !allow_unsafe_http_non_loopback
        {
            return Err(ConfigError::UnsafePlaintextNonLoopbackBind(bind));
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not determine a platform data directory")]
    NoDataDirectory,
    #[error("the public origin is not a valid URL: {0}")]
    InvalidPublicOrigin(#[source] url::ParseError),
    #[error("the public origin must use http or https")]
    UnsupportedPublicOriginScheme,
    #[error("the public origin must contain only scheme, host, and optional port")]
    PublicOriginHasExtraComponents,
    #[error(
        "--public-origin is required when --bind uses unspecified address {0}; Executor cannot infer the browser-visible host"
    )]
    PublicOriginRequiredForUnspecifiedBind(SocketAddr),
    #[error(
        "refusing plaintext HTTP on non-loopback bind {0}; use --allow-unsafe-http-non-loopback only when transport security is provided elsewhere"
    )]
    UnsafePlaintextNonLoopbackBind(SocketAddr),
}

pub struct ExecutorApp {
    router: Router,
    setup_token: Option<String>,
    pool: SqlitePool,
    catalog: catalog::CatalogStore,
    tool_calls: invocation::ToolCallService,
    execution: execution::ExecutionService,
    api_tasks: tasks::TaskTracker,
}

impl ExecutorApp {
    pub async fn open(config: AppConfig) -> Result<Self, DatabaseError> {
        let opened = database::Database::open(&config).await?;
        let pool = opened.database.pool.clone();
        let catalog = catalog::CatalogStore::new(pool.clone(), opened.database.keyring.clone());
        let sources = protocols::SourceService::new(catalog.clone());
        let protocol_registry = sources.registry().clone();
        let request_logs =
            request_logs::RequestLogSink::new(opened.database.clone(), catalog.clone());
        let tool_calls = invocation::ToolCallService::new(
            catalog.clone(),
            protocol_registry,
            pool.clone(),
            opened.database.keyring.clone(),
            request_logs.clone(),
        );
        tool_calls.recover_startup().await?;
        let api_tasks = tasks::TaskTracker::default();
        let runtime =
            runtime::RuntimeManager::new(config.runtime_executable.clone().unwrap_or_else(|| {
                std::env::current_exe().unwrap_or_else(|_| PathBuf::from("executor"))
            }));
        let execution = execution::ExecutionService::new(runtime, tool_calls.clone());
        let dummy_password_hash = crypto::hash_password("executor-dummy-login-password")?;
        let router = api::router(
            opened.database,
            catalog.clone(),
            api::ApiServices::new(sources, tool_calls.clone(), execution.clone()),
            request_logs,
            api_tasks.clone(),
            &config,
            dummy_password_hash,
        );
        Ok(Self {
            router,
            setup_token: opened.setup_token,
            pool,
            catalog,
            tool_calls,
            execution,
            api_tasks,
        })
    }

    pub fn router(&self) -> Router {
        self.router.clone()
    }

    pub fn setup_token(&self) -> Option<&str> {
        self.setup_token.as_deref()
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub fn catalog(&self) -> &catalog::CatalogStore {
        &self.catalog
    }

    pub fn tool_calls(&self) -> &invocation::ToolCallService {
        &self.tool_calls
    }

    pub fn executions(&self) -> &execution::ExecutionService {
        &self.execution
    }

    pub async fn shutdown(self) {
        self.execution.shutdown().await;
        self.api_tasks.shutdown().await;
        self.tool_calls.shutdown().await;
        self.pool.close().await;
    }
}

impl Drop for ExecutorApp {
    fn drop(&mut self) {
        self.execution.cancel_all();
        self.api_tasks.abort_all();
        self.tool_calls.abort_background_tasks();
    }
}

fn parse_public_origin(origin: &str) -> Result<Url, ConfigError> {
    let parsed = Url::parse(origin).map_err(ConfigError::InvalidPublicOrigin)?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
        return Err(ConfigError::UnsupportedPublicOriginScheme);
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ConfigError::PublicOriginHasExtraComponents);
    }
    Ok(parsed)
}

pub(crate) fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time must be after the Unix epoch")
        .as_secs() as i64
}
