use executor::crypto::{CryptoError, Keyring};

#[test]
fn xchacha_ciphertext_rejects_tampering_and_wrong_aad() {
    let keyring = Keyring::from_master_key([7_u8; 32]).expect("key derivation should succeed");
    let sealed = keyring
        .encrypt("oauth-token", "source-1", b"refresh-secret")
        .expect("encryption should succeed");
    assert_eq!(sealed.first(), Some(&1));

    let plaintext = keyring
        .decrypt("oauth-token", "source-1", &sealed)
        .expect("matching AAD should decrypt");
    assert_eq!(plaintext, b"refresh-secret");

    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(
        keyring
            .decrypt("oauth-token", "source-1", &tampered)
            .is_err()
    );
    assert!(keyring.decrypt("oauth-token", "source-2", &sealed).is_err());
    assert!(keyring.decrypt("api-key", "source-1", &sealed).is_err());
}

#[test]
fn envelope_rejects_unsupported_versions() {
    let keyring = Keyring::from_master_key([7_u8; 32]).expect("key derivation should succeed");
    let mut sealed = keyring
        .encrypt("credential", "record-1", b"secret")
        .expect("encryption should succeed");
    sealed[0] = 99;

    assert!(matches!(
        keyring.decrypt("credential", "record-1", &sealed),
        Err(CryptoError::UnsupportedEnvelopeVersion(99))
    ));
}

#[test]
fn structured_aad_has_no_delimiter_collisions() {
    let keyring = Keyring::from_master_key([7_u8; 32]).expect("key derivation should succeed");
    let sealed = keyring
        .encrypt("a:b", "c", b"secret")
        .expect("encryption should succeed");

    assert!(keyring.decrypt("a", "b:c", &sealed).is_err());
}

#[test]
fn a_different_master_key_cannot_decrypt_ciphertext() {
    let first = Keyring::from_master_key([1_u8; 32]).expect("key derivation should succeed");
    let second = Keyring::from_master_key([2_u8; 32]).expect("key derivation should succeed");
    let sealed = first
        .encrypt("credential", "record-1", b"secret")
        .expect("encryption should succeed");

    assert!(second.decrypt("credential", "record-1", &sealed).is_err());
}
