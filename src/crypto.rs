use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
};

use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{RngCore, rngs::OsRng as SystemOsRng};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

const MASTER_KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 24;
const ENVELOPE_VERSION: u8 = 1;

#[derive(Debug, Eq, PartialEq)]
enum KeyPublishOutcome {
    Published,
    Existing,
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("could not create the Executor data directory: {0}")]
    CreateDataDirectory(#[source] std::io::Error),
    #[error("the initialized database has no master key file at {0}")]
    MissingMasterKey(PathBuf),
    #[error("could not read the master key file at {path}: {source}")]
    ReadMasterKey {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("the master key file at {path} must contain exactly 32 bytes, found {length}")]
    InvalidMasterKeyLength { path: PathBuf, length: usize },
    #[error("could not create a master key file at {path}: {source}")]
    CreateMasterKey {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("could not derive an instance subkey")]
    KeyDerivation,
    #[error("could not encrypt protected data")]
    Encryption,
    #[error("could not decrypt protected data")]
    Decryption,
    #[error("unsupported protected-data envelope version {0}")]
    UnsupportedEnvelopeVersion(u8),
    #[error("could not hash the password")]
    PasswordHash,
}

#[derive(Clone)]
pub struct Keyring {
    encryption_key: [u8; 32],
    digest_key: [u8; 32],
}

impl Keyring {
    pub fn from_master_key(master_key: [u8; MASTER_KEY_LENGTH]) -> Result<Self, CryptoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(b"executor-instance-v1"), &master_key);
        let mut encryption_key = [0_u8; 32];
        let mut digest_key = [0_u8; 32];
        hkdf.expand(b"xchacha20poly1305-at-rest", &mut encryption_key)
            .map_err(|_| CryptoError::KeyDerivation)?;
        hkdf.expand(b"authentication-digests", &mut digest_key)
            .map_err(|_| CryptoError::KeyDerivation)?;

        Ok(Self {
            encryption_key,
            digest_key,
        })
    }

    pub fn random() -> Result<Self, CryptoError> {
        let mut master_key = [0_u8; MASTER_KEY_LENGTH];
        SystemOsRng.fill_bytes(&mut master_key);
        Self::from_master_key(master_key)
    }

    pub fn encrypt(
        &self,
        purpose: &str,
        record_id: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = XChaCha20Poly1305::new((&self.encryption_key).into());
        let mut nonce_bytes = [0_u8; NONCE_LENGTH];
        SystemOsRng.fill_bytes(&mut nonce_bytes);
        let aad = aad(purpose, record_id);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Encryption)?;

        let mut sealed = Vec::with_capacity(1 + NONCE_LENGTH + ciphertext.len());
        sealed.push(ENVELOPE_VERSION);
        sealed.extend_from_slice(&nonce_bytes);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    pub fn decrypt(
        &self,
        purpose: &str,
        record_id: &str,
        sealed: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let Some((&version, envelope)) = sealed.split_first() else {
            return Err(CryptoError::Decryption);
        };
        if version != ENVELOPE_VERSION {
            return Err(CryptoError::UnsupportedEnvelopeVersion(version));
        }
        if envelope.len() <= NONCE_LENGTH {
            return Err(CryptoError::Decryption);
        }

        let (nonce, ciphertext) = envelope.split_at(NONCE_LENGTH);
        let aad = aad(purpose, record_id);
        XChaCha20Poly1305::new((&self.encryption_key).into())
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::Decryption)
    }

    pub(crate) fn digest(&self, purpose: &str, secret: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.digest_key)
            .expect("HMAC accepts a 32-byte key");
        mac.update(b"executor:v1:");
        mac.update(purpose.as_bytes());
        mac.update(b":");
        mac.update(secret);
        mac.finalize().into_bytes().into()
    }

    pub(crate) fn digest_matches(&self, purpose: &str, secret: &[u8], expected: &[u8]) -> bool {
        self.digest(purpose, secret)
            .as_slice()
            .ct_eq(expected)
            .into()
    }
}

pub(crate) fn generate_secret(prefix: &str) -> String {
    let mut bytes = [0_u8; 32];
    SystemOsRng.fill_bytes(&mut bytes);
    format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn hash_password(password: &str) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| CryptoError::PasswordHash)
}

pub(crate) fn verify_password(password: &str, encoded_hash: &str) -> bool {
    let Ok(hash) = PasswordHash::new(encoded_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok()
}

pub(crate) fn load_or_create_master_key(
    data_dir: &Path,
    database_existed: bool,
    configured_path: Option<&Path>,
) -> Result<[u8; MASTER_KEY_LENGTH], CryptoError> {
    load_or_create_master_key_with_sync(
        data_dir,
        database_existed,
        configured_path,
        &sync_directory,
    )
}

fn load_or_create_master_key_with_sync(
    data_dir: &Path,
    database_existed: bool,
    configured_path: Option<&Path>,
    sync_parent: &impl Fn(&Path) -> Result<(), std::io::Error>,
) -> Result<[u8; MASTER_KEY_LENGTH], CryptoError> {
    fs::create_dir_all(data_dir).map_err(CryptoError::CreateDataDirectory)?;
    secure_directory(data_dir).map_err(CryptoError::CreateDataDirectory)?;

    let key_path = configured_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| data_dir.join("master.key"));

    if key_path.exists() {
        if configured_path.is_none() {
            let parent = key_path.parent().unwrap_or_else(|| Path::new("."));
            sync_parent(parent).map_err(|source| CryptoError::CreateMasterKey {
                path: key_path.clone(),
                source,
            })?;
        }
        return read_master_key(&key_path);
    }

    if configured_path.is_some() || database_existed {
        return Err(CryptoError::MissingMasterKey(key_path));
    }

    create_master_key_atomically(&key_path, sync_parent)
}

fn aad(purpose: &str, record_id: &str) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(24 + purpose.len() + record_id.len());
    encoded.extend_from_slice(b"executor-aad");
    encoded.push(ENVELOPE_VERSION);
    append_length_prefixed(&mut encoded, purpose.as_bytes());
    append_length_prefixed(&mut encoded, record_id.as_bytes());
    encoded
}

fn append_length_prefixed(encoded: &mut Vec<u8>, value: &[u8]) {
    encoded.extend_from_slice(&(value.len() as u64).to_be_bytes());
    encoded.extend_from_slice(value);
}

fn read_master_key(path: &Path) -> Result<[u8; MASTER_KEY_LENGTH], CryptoError> {
    let bytes = fs::read(path).map_err(|source| CryptoError::ReadMasterKey {
        path: path.to_path_buf(),
        source,
    })?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| CryptoError::InvalidMasterKeyLength {
            path: path.to_path_buf(),
            length: bytes.len(),
        })
}

fn create_master_key_atomically(
    path: &Path,
    sync_parent: &impl Fn(&Path) -> Result<(), std::io::Error>,
) -> Result<[u8; MASTER_KEY_LENGTH], CryptoError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(CryptoError::CreateDataDirectory)?;
    secure_directory(parent).map_err(CryptoError::CreateDataDirectory)?;

    let mut key = [0_u8; MASTER_KEY_LENGTH];
    SystemOsRng.fill_bytes(&mut key);
    let temporary_path = parent.join(format!(".master-key-{}.tmp", Uuid::new_v4()));

    let create_result = (|| -> Result<KeyPublishOutcome, std::io::Error> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        secure_file_options(&mut options);
        let mut file = options.open(&temporary_path)?;
        file.write_all(&key)?;
        file.sync_all()?;
        publish_master_key(&temporary_path, path, parent, sync_parent)
    })();

    match create_result {
        Ok(KeyPublishOutcome::Published) => Ok(key),
        Ok(KeyPublishOutcome::Existing) => {
            sync_parent(parent).map_err(|source| CryptoError::CreateMasterKey {
                path: path.to_path_buf(),
                source,
            })?;
            read_master_key(path)
        }
        Err(source) => Err(CryptoError::CreateMasterKey {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn publish_master_key(
    temporary_path: &Path,
    path: &Path,
    parent: &Path,
    sync_parent: &impl Fn(&Path) -> Result<(), std::io::Error>,
) -> Result<KeyPublishOutcome, std::io::Error> {
    match fs::hard_link(temporary_path, path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            fs::remove_file(temporary_path)?;
            return Ok(KeyPublishOutcome::Existing);
        }
        Err(error) => {
            let _ = fs::remove_file(temporary_path);
            return Err(error);
        }
    }

    if let Err(error) = sync_parent(parent) {
        let _ = fs::remove_file(temporary_path);
        return Err(error);
    }
    fs::remove_file(temporary_path)?;
    sync_parent(parent)?;
    Ok(KeyPublishOutcome::Published)
}

fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    fs::File::open(path)?.sync_all()
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn secure_directory(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(unix)]
fn secure_file_options(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;

    options.mode(0o600);
}

#[cfg(not(unix))]
fn secure_file_options(_options: &mut OpenOptions) {}

#[cfg(test)]
mod tests {
    use super::{
        CryptoError, KeyPublishOutcome, load_or_create_master_key_with_sync, publish_master_key,
    };
    use std::{cell::Cell, fs, io::ErrorKind};

    #[test]
    fn parent_sync_failures_are_propagated_after_key_publication() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let temporary_path = directory.path().join("temporary.key");
        let key_path = directory.path().join("master.key");
        fs::write(&temporary_path, [1_u8; 32]).expect("temporary key should be written");

        let error = publish_master_key(&temporary_path, &key_path, directory.path(), &|_| {
            Err(std::io::Error::other("injected directory sync failure"))
        })
        .expect_err("directory sync failure must be returned");
        assert_eq!(error.kind(), ErrorKind::Other);
        assert!(key_path.exists());
    }

    #[test]
    fn only_an_already_existing_link_uses_the_existing_key_path() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let temporary_path = directory.path().join("temporary.key");
        let key_path = directory.path().join("master.key");
        fs::write(&temporary_path, [1_u8; 32]).expect("temporary key should be written");
        fs::write(&key_path, [2_u8; 32]).expect("existing key should be written");

        let outcome = publish_master_key(&temporary_path, &key_path, directory.path(), &|_| {
            panic!("an existing link must not run the publication sync path")
        })
        .expect("already existing key should be detected");
        assert_eq!(outcome, KeyPublishOutcome::Existing);
        assert!(!temporary_path.exists());
        assert_eq!(
            fs::read(key_path).expect("existing key should be readable"),
            [2_u8; 32]
        );
    }

    #[test]
    fn failed_publication_sync_is_retried_before_the_existing_key_is_read() {
        let directory = tempfile::tempdir().expect("temporary directory should be created");
        let sync_attempts = Cell::new(0);
        let sync_parent = |_: &std::path::Path| {
            let attempt = sync_attempts.get() + 1;
            sync_attempts.set(attempt);
            if attempt <= 2 {
                Err(std::io::Error::other("injected directory sync failure"))
            } else {
                Ok(())
            }
        };

        let first =
            load_or_create_master_key_with_sync(directory.path(), false, None, &sync_parent)
                .expect_err("the publication sync failure must be returned");
        assert!(matches!(first, CryptoError::CreateMasterKey { .. }));
        assert!(directory.path().join("master.key").exists());
        assert_eq!(sync_attempts.get(), 1);

        let second =
            load_or_create_master_key_with_sync(directory.path(), false, None, &sync_parent)
                .expect_err("the next open must retry and return the sync failure");
        assert!(matches!(second, CryptoError::CreateMasterKey { .. }));
        assert_eq!(sync_attempts.get(), 2);

        let key = load_or_create_master_key_with_sync(directory.path(), false, None, &sync_parent)
            .expect("the key may be read only after the parent sync succeeds");
        assert_eq!(sync_attempts.get(), 3);
        assert_eq!(
            fs::read(directory.path().join("master.key"))
                .expect("the published key should be readable"),
            key
        );
    }
}
