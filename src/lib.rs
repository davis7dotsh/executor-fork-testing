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

mod api;
pub mod catalog;
pub mod crypto;
mod database;
pub mod openapi;
pub mod outbound;
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
}

impl AppConfig {
    pub fn new(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            master_key_file: None,
            origin: Url::parse(DEFAULT_ORIGIN).expect("the default public origin is valid"),
            session_ttl_seconds: 8 * 60 * 60,
            trusted_proxies: Arc::from([]),
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
}

impl ExecutorApp {
    pub async fn open(config: AppConfig) -> Result<Self, DatabaseError> {
        let opened = database::Database::open(&config).await?;
        let pool = opened.database.pool.clone();
        let catalog = catalog::CatalogStore::new(pool.clone(), opened.database.keyring.clone());
        let dummy_password_hash = crypto::hash_password("executor-dummy-login-password")?;
        let router = api::router(
            opened.database,
            catalog.clone(),
            &config,
            dummy_password_hash,
        );
        Ok(Self {
            router,
            setup_token: opened.setup_token,
            pool,
            catalog,
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
