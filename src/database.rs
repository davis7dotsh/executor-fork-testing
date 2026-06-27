use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[cfg(unix)]
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_encode};
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
    #[error("the SQLite database path cannot be represented safely on this platform")]
    InvalidDatabasePath,
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
        let database_path = config.data_dir.join("executor.db");
        let options = sqlite_options(&database_path)?;
        let instance_lock = Arc::new(InstanceLock::acquire(&config.data_dir)?);
        let database_existed = database_path.exists();
        let master_key = load_or_create_master_key(
            &config.data_dir,
            database_existed,
            config.master_key_file.as_deref(),
        )?;
        let keyring = Keyring::from_master_key(master_key)?;
        secure_database_file(&database_path)?;
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
        crate::catalog::source_idempotency::recover_source_creation_idempotency(&pool)
            .await
            .map_err(DatabaseError::Configuration)?;
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

fn sqlite_options(database_path: &Path) -> Result<SqliteConnectOptions, DatabaseError> {
    Ok(SqliteConnectOptions::new()
        .filename(sqlite_filename(database_path)?)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(Duration::from_secs(5)))
}

#[cfg(unix)]
const SQLITE_URI_PATH_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC.remove(b'/');

#[cfg(unix)]
fn sqlite_filename(database_path: &Path) -> Result<PathBuf, DatabaseError> {
    use std::os::unix::ffi::OsStrExt;

    let path = database_path.as_os_str().as_bytes();
    if path.contains(&0) {
        return Err(DatabaseError::InvalidDatabasePath);
    }

    let prefix = if database_path.is_absolute() {
        "file://"
    } else {
        "file:"
    };
    Ok(PathBuf::from(format!(
        "{prefix}{}",
        percent_encode(path, SQLITE_URI_PATH_ENCODE_SET)
    )))
}

#[cfg(not(unix))]
fn sqlite_filename(database_path: &Path) -> Result<PathBuf, DatabaseError> {
    let path = database_path
        .to_str()
        .filter(|path| !path.contains('\0'))
        .ok_or(DatabaseError::InvalidDatabasePath)?;
    Ok(PathBuf::from(path))
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

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        ffi::{OsStr, OsString},
    };

    use super::*;

    async fn assert_database_path_round_trip(data_dir: &Path) {
        let config = AppConfig::new(data_dir.to_path_buf());
        let opened = Database::open(&config)
            .await
            .expect("database should open at the exact requested path");
        sqlx::query("INSERT INTO instance_metadata (key, value) VALUES ('path-test', X'01')")
            .execute(&opened.database.pool)
            .await
            .expect("path marker should be written");

        let locked = Database::open(&config).await;
        assert!(matches!(locked, Err(DatabaseError::AlreadyRunning(path)) if path == data_dir));

        opened.database.pool.close().await;
        drop(opened);

        let database_path = data_dir.join("executor.db");
        let header =
            fs::read(&database_path).expect("the intended database file should be readable");
        assert!(header.starts_with(b"SQLite format 3\0"));

        let reopened = Database::open(&config)
            .await
            .expect("database should restart from the same path");
        let marker = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT value FROM instance_metadata WHERE key = 'path-test'",
        )
        .fetch_one(&reopened.database.pool)
        .await
        .expect("restart should read the marker from the intended file");
        assert_eq!(marker, [1]);
        reopened.database.pool.close().await;
        drop(reopened);

        let actual_files = fs::read_dir(data_dir)
            .expect("data directory should be readable")
            .map(|entry| {
                entry
                    .expect("data directory entry should be readable")
                    .file_name()
            })
            .collect::<BTreeSet<_>>();
        let allowed_files = [
            "executor.db",
            "executor.db-shm",
            "executor.db-wal",
            "executor.lock",
            "master.key",
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<BTreeSet<_>>();
        assert!(actual_files.is_subset(&allowed_files));
        assert!(actual_files.contains(OsStr::new("executor.db")));
    }

    #[tokio::test]
    async fn sqlite_paths_preserve_reserved_space_and_unicode_characters() {
        let root = tempfile::tempdir().expect("temporary directory should be created");
        let names = [
            "percent%2Fdirectory",
            "question?directory",
            "hash#directory",
            "space directory",
            "unicode-雪-directory",
        ];

        for name in names {
            assert_database_path_round_trip(&root.path().join(name)).await;
        }

        let actual_directories = fs::read_dir(root.path())
            .expect("temporary root should be readable")
            .map(|entry| {
                entry
                    .expect("temporary root entry should be readable")
                    .file_name()
            })
            .collect::<BTreeSet<_>>();
        let expected_directories = names
            .into_iter()
            .map(OsString::from)
            .collect::<BTreeSet<_>>();
        assert_eq!(actual_directories, expected_directories);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sqlite_paths_preserve_non_utf8_bytes() {
        use std::os::unix::ffi::OsStringExt;

        let root = tempfile::tempdir().expect("temporary directory should be created");
        let name = OsString::from_vec(b"non-utf8-\xff-directory".to_vec());
        let data_dir = root.path().join(&name);

        assert_database_path_round_trip(&data_dir).await;

        let actual_directories = fs::read_dir(root.path())
            .expect("temporary root should be readable")
            .map(|entry| {
                entry
                    .expect("temporary root entry should be readable")
                    .file_name()
            })
            .collect::<Vec<_>>();
        assert_eq!(actual_directories, [name]);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn sqlite_paths_reject_embedded_nul_bytes_before_filesystem_writes() {
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let root = tempfile::tempdir().expect("temporary directory should be created");
        let mut path = root.path().as_os_str().as_bytes().to_vec();
        path.extend_from_slice(b"/bad\0path");
        let config = AppConfig::new(PathBuf::from(OsString::from_vec(path)));
        assert!(matches!(
            Database::open(&config).await,
            Err(DatabaseError::InvalidDatabasePath)
        ));
        assert_eq!(
            fs::read_dir(root.path())
                .expect("temporary root should be readable")
                .count(),
            0
        );
    }
}
