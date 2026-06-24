use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use sqlx::{
    SqlitePool,
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use thiserror::Error;

use crate::{
    AppConfig,
    approval::ApprovalError,
    crypto::{CryptoError, Keyring, generate_secret, load_or_create_master_key},
    unix_timestamp,
};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
const SENTINEL_KEY: &str = "boot_sentinel";
const SENTINEL_PLAINTEXT: &[u8] = b"executor-boot-sentinel-v1";
pub(crate) const SETUP_TOKEN_TTL_SECONDS: i64 = 15 * 60;

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error(transparent)]
    Approval(#[from] ApprovalError),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    McpTemplates(#[from] crate::mcp::upstream::stdio::StdioTemplateError),
    #[error("could not recover managed OAuth state")]
    OAuthInitialization,
    #[error("could not configure the SQLite database: {0}")]
    Configuration(#[source] sqlx::Error),
    #[error("could not run embedded SQLite migrations: {0}")]
    Migration(#[source] sqlx::migrate::MigrateError),
    #[error("the database boot sentinel is missing; refusing to guess the instance key")]
    MissingBootSentinel,
    #[error(
        "the database boot sentinel could not be authenticated; the master key is wrong or the database was modified"
    )]
    InvalidBootSentinel,
    #[error("could not initialize the setup claim: {0}")]
    SetupClaim(#[source] sqlx::Error),
    #[error("another Executor process is already using {0}")]
    AlreadyRunning(PathBuf),
    #[error("could not lock the Executor data directory at {path}: {source}")]
    InstanceLock {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not secure the SQLite database file at {path}: {source}")]
    SecureDatabaseFile {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[derive(Clone)]
pub(crate) struct Database {
    pub(crate) pool: SqlitePool,
    pub(crate) keyring: Keyring,
    _instance_lock: Arc<InstanceLock>,
}

struct InstanceLock {
    _file: File,
}

pub(crate) struct OpenedDatabase {
    pub(crate) database: Database,
    pub(crate) setup_token: Option<String>,
}

impl Database {
    pub(crate) async fn open(config: &AppConfig) -> Result<OpenedDatabase, DatabaseError> {
        let instance_lock = Arc::new(InstanceLock::acquire(&config.data_dir)?);
        let database_path = config.data_dir.join("executor.db");
        let database_existed = database_path.exists();
        let master_key = load_or_create_master_key(
            &config.data_dir,
            database_existed,
            config.master_key_file.as_deref(),
        )?;
        let keyring = Keyring::from_master_key(master_key)?;
        secure_database_file(&database_path)?;
        let options = sqlite_options(database_path)?;
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await
            .map_err(DatabaseError::Configuration)?;

        MIGRATOR
            .run(&pool)
            .await
            .map_err(DatabaseError::Migration)?;
        verify_or_create_sentinel(&pool, &keyring, database_existed).await?;
        let setup_token = issue_setup_token_if_needed(&pool, &keyring).await?;

        Ok(OpenedDatabase {
            database: Database {
                pool,
                keyring,
                _instance_lock: instance_lock,
            },
            setup_token,
        })
    }
}

impl InstanceLock {
    fn acquire(data_dir: &Path) -> Result<Self, DatabaseError> {
        fs::create_dir_all(data_dir).map_err(CryptoError::CreateDataDirectory)?;
        secure_data_directory(data_dir).map_err(CryptoError::CreateDataDirectory)?;
        let path = data_dir.join("executor.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        secure_open_options(&mut options);
        let file = options
            .open(&path)
            .map_err(|source| DatabaseError::InstanceLock {
                path: path.clone(),
                source,
            })?;
        secure_file_permissions(&path).map_err(|source| DatabaseError::InstanceLock {
            path: path.clone(),
            source,
        })?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => {
                Err(DatabaseError::AlreadyRunning(data_dir.to_path_buf()))
            }
            Err(std::fs::TryLockError::Error(source)) => {
                Err(DatabaseError::InstanceLock { path, source })
            }
        }
    }
}

fn sqlite_options(database_path: PathBuf) -> Result<SqliteConnectOptions, DatabaseError> {
    let url = format!("sqlite://{}", database_path.display());
    SqliteConnectOptions::from_str(&url)
        .map(|options| {
            options
                .create_if_missing(true)
                .foreign_keys(true)
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Full)
                .busy_timeout(Duration::from_secs(5))
        })
        .map_err(DatabaseError::Configuration)
}

async fn verify_or_create_sentinel(
    pool: &SqlitePool,
    keyring: &Keyring,
    database_existed: bool,
) -> Result<(), DatabaseError> {
    let sentinel =
        sqlx::query_scalar::<_, Vec<u8>>("SELECT value FROM instance_metadata WHERE key = ?")
            .bind(SENTINEL_KEY)
            .fetch_optional(pool)
            .await
            .map_err(DatabaseError::Configuration)?;

    match sentinel {
        Some(sealed) => {
            let plaintext = keyring
                .decrypt("boot-sentinel", "singleton", &sealed)
                .map_err(|_| DatabaseError::InvalidBootSentinel)?;
            if plaintext != SENTINEL_PLAINTEXT {
                return Err(DatabaseError::InvalidBootSentinel);
            }
            Ok(())
        }
        None if database_existed && application_state_exists(pool).await? => {
            Err(DatabaseError::MissingBootSentinel)
        }
        None => {
            let sealed = keyring.encrypt("boot-sentinel", "singleton", SENTINEL_PLAINTEXT)?;
            sqlx::query("INSERT INTO instance_metadata (key, value) VALUES (?, ?)")
                .bind(SENTINEL_KEY)
                .bind(sealed)
                .execute(pool)
                .await
                .map_err(DatabaseError::Configuration)?;
            Ok(())
        }
    }
}

async fn application_state_exists(pool: &SqlitePool) -> Result<bool, DatabaseError> {
    sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(SELECT 1 FROM setup_state) \
         OR EXISTS(SELECT 1 FROM admins) \
         OR EXISTS(SELECT 1 FROM admin_sessions) \
         OR EXISTS(SELECT 1 FROM api_tokens) \
         OR EXISTS(SELECT 1 FROM sources) \
         OR EXISTS(SELECT 1 FROM source_credentials) \
         OR EXISTS(SELECT 1 FROM source_artifacts) \
         OR EXISTS(SELECT 1 FROM tools) \
         OR EXISTS(SELECT 1 FROM request_logs) \
         OR EXISTS(SELECT 1 FROM audit_events) \
         OR EXISTS(SELECT 1 FROM approvals) \
         OR EXISTS(SELECT 1 FROM catalog_state WHERE id = 1 AND revision <> 0) \
         OR EXISTS(SELECT 1 FROM instance_metadata WHERE key <> ?)",
    )
    .bind(SENTINEL_KEY)
    .fetch_one(pool)
    .await
    .map(|exists| exists != 0)
    .map_err(DatabaseError::Configuration)
}

async fn issue_setup_token_if_needed(
    pool: &SqlitePool,
    keyring: &Keyring,
) -> Result<Option<String>, DatabaseError> {
    let has_admin =
        sqlx::query_scalar::<_, i64>("SELECT EXISTS(SELECT 1 FROM admins WHERE id = 1)")
            .fetch_one(pool)
            .await
            .map_err(DatabaseError::SetupClaim)?
            != 0;

    if has_admin {
        return Ok(None);
    }

    let token = generate_secret("set_");
    let digest = keyring.digest("setup-token", token.as_bytes());
    sqlx::query(
        "INSERT INTO setup_state (id, token_digest, created_at, used_at) VALUES (1, ?, ?, NULL) \
         ON CONFLICT(id) DO UPDATE SET token_digest = excluded.token_digest, created_at = excluded.created_at, used_at = NULL",
    )
    .bind(digest.to_vec())
    .bind(unix_timestamp())
    .execute(pool)
    .await
    .map_err(DatabaseError::SetupClaim)?;

    Ok(Some(token))
}

fn secure_database_file(path: &Path) -> Result<(), DatabaseError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    secure_open_options(&mut options);
    options
        .open(path)
        .map_err(|source| DatabaseError::SecureDatabaseFile {
            path: path.to_path_buf(),
            source,
        })?;
    secure_file_permissions(path).map_err(|source| DatabaseError::SecureDatabaseFile {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
fn secure_data_directory(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn secure_data_directory(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(unix)]
fn secure_open_options(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(0o600);
}

#[cfg(not(unix))]
fn secure_open_options(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn secure_file_permissions(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn secure_file_permissions(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}
