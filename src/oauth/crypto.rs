use thiserror::Error;

use crate::crypto::{CryptoError, Keyring, generate_secret};

use super::model::OAuthSecretSet;

const CONNECTION_SECRET_PURPOSE: &str = "oauth-connection-secret-v1";
const AUTHORIZATION_STATE_PURPOSE: &str = "oauth-authorization-state-v1";
const AUTHORIZATION_CLAIM_PURPOSE: &str = "oauth-authorization-claim-v1";
const PKCE_VERIFIER_PURPOSE: &str = "oauth-pkce-verifier-v1";
const REFRESH_LEASE_PURPOSE: &str = "oauth-refresh-lease-v1";

#[derive(Debug, Error)]
pub(crate) enum OAuthCryptoError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("could not encode protected OAuth data")]
    Encode(#[source] serde_json::Error),
    #[error("could not decode protected OAuth data")]
    Decode(#[source] serde_json::Error),
    #[error("the protected OAuth text was not valid UTF-8")]
    InvalidUtf8,
}

#[derive(Clone)]
pub(crate) struct OAuthCrypto {
    keyring: Keyring,
}

impl OAuthCrypto {
    pub(crate) fn new(keyring: Keyring) -> Self {
        Self { keyring }
    }

    pub(crate) fn new_state(&self) -> String {
        generate_secret("oas_")
    }

    pub(crate) fn new_claim_token(&self) -> String {
        generate_secret("oac_")
    }

    pub(crate) fn new_refresh_lease_token(&self) -> String {
        generate_secret("oar_")
    }

    pub(crate) fn new_pkce_verifier(&self) -> String {
        generate_secret("")
    }

    pub(crate) fn state_digest(&self, state: &str) -> [u8; 32] {
        self.keyring
            .digest(AUTHORIZATION_STATE_PURPOSE, state.as_bytes())
    }

    pub(crate) fn authorization_claim_digest(&self, claim: &str) -> [u8; 32] {
        self.keyring
            .digest(AUTHORIZATION_CLAIM_PURPOSE, claim.as_bytes())
    }

    pub(crate) fn refresh_lease_digest(&self, lease: &str) -> [u8; 32] {
        self.keyring.digest(REFRESH_LEASE_PURPOSE, lease.as_bytes())
    }

    pub(crate) fn seal_pkce_verifier(
        &self,
        transaction_id: &str,
        verifier: &str,
    ) -> Result<Vec<u8>, OAuthCryptoError> {
        self.keyring
            .encrypt(PKCE_VERIFIER_PURPOSE, transaction_id, verifier.as_bytes())
            .map_err(Into::into)
    }

    pub(crate) fn open_pkce_verifier(
        &self,
        transaction_id: &str,
        ciphertext: &[u8],
    ) -> Result<String, OAuthCryptoError> {
        let plaintext = self
            .keyring
            .decrypt(PKCE_VERIFIER_PURPOSE, transaction_id, ciphertext)?;
        String::from_utf8(plaintext).map_err(|_| OAuthCryptoError::InvalidUtf8)
    }

    pub(crate) fn seal_secrets(
        &self,
        connection_id: &str,
        revision: i64,
        secrets: &OAuthSecretSet,
    ) -> Result<Vec<u8>, OAuthCryptoError> {
        let plaintext = serde_json::to_vec(secrets).map_err(OAuthCryptoError::Encode)?;
        self.keyring
            .encrypt(
                CONNECTION_SECRET_PURPOSE,
                &secret_record_id(connection_id, revision),
                &plaintext,
            )
            .map_err(Into::into)
    }

    pub(crate) fn open_secrets(
        &self,
        connection_id: &str,
        revision: i64,
        ciphertext: &[u8],
    ) -> Result<OAuthSecretSet, OAuthCryptoError> {
        let plaintext = self.keyring.decrypt(
            CONNECTION_SECRET_PURPOSE,
            &secret_record_id(connection_id, revision),
            ciphertext,
        )?;
        serde_json::from_slice(&plaintext).map_err(OAuthCryptoError::Decode)
    }
}

fn secret_record_id(connection_id: &str, revision: i64) -> String {
    format!("{connection_id}:{revision}")
}

#[cfg(test)]
mod tests {
    use crate::crypto::Keyring;

    use super::{OAuthCrypto, OAuthSecretSet};

    #[test]
    fn secret_envelopes_are_bound_to_connection_and_revision() {
        let crypto = OAuthCrypto::new(Keyring::from_master_key([3; 32]).unwrap());
        let secrets = OAuthSecretSet {
            client_secret: Some("client-secret".into()),
            access_token: Some("access-token".into()),
            refresh_token: Some("refresh-token".into()),
            token_type: Some("Bearer".into()),
            granted_scopes: vec!["read".into()],
            access_token_expires_at: Some(42),
        };
        let ciphertext = crypto.seal_secrets("connection-a", 1, &secrets).unwrap();

        let opened = crypto.open_secrets("connection-a", 1, &ciphertext).unwrap();
        assert_eq!(opened.access_token.as_deref(), Some("access-token"));
        assert!(crypto.open_secrets("connection-b", 1, &ciphertext).is_err());
        assert!(crypto.open_secrets("connection-a", 2, &ciphertext).is_err());
    }

    #[test]
    fn pkce_envelopes_are_bound_to_the_authorization_transaction() {
        let crypto = OAuthCrypto::new(Keyring::from_master_key([4; 32]).unwrap());
        let ciphertext = crypto
            .seal_pkce_verifier("transaction-a", "verifier")
            .unwrap();
        assert_eq!(
            crypto
                .open_pkce_verifier("transaction-a", &ciphertext)
                .unwrap(),
            "verifier"
        );
        assert!(
            crypto
                .open_pkce_verifier("transaction-b", &ciphertext)
                .is_err()
        );
    }
}
