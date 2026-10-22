//! Key generation, envelope encryption, and signing.
//!
//! Each key gets a random 32-byte DEK. The private key is encrypted with the
//! DEK, and the DEK is wrapped with the unsealed KEK. Both AEAD
//! operations bind the key metadata into the AAD.

use std::collections::BTreeMap;
use std::sync::Arc;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use rand::rngs::OsRng;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::storage::{
    AuditEntry, AuditResult, Curve, KeyId, KeyMetadata, KeyRecord, KeyState, KeyStore, NewKey,
    Page, SignatureAlgorithm, StorageError,
};
use crate::unseal::{UnsealError, UnsealManager};

const DEK_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const ED25519_SEED_LEN: usize = 32;
const PRIVATE_AAD_DOMAIN: &[u8] = b"signer.key.private.v1";
const DEK_AAD_DOMAIN: &[u8] = b"signer.key.dek.v1";

/// Errors returned by the keystore.
#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("service is sealed")]
    Sealed,

    #[error("key not found")]
    NotFound,

    #[error("key already exists")]
    Conflict,

    #[error("key is not active")]
    KeyNotActive,

    #[error("unsupported curve/algorithm: {0}")]
    Unsupported(String),

    #[error("invalid curve/algorithm pair")]
    InvalidAlgorithmPair,

    #[error("invalid key material")]
    InvalidMaterial,

    #[error("stored key is corrupt")]
    Corrupt,

    #[error("storage operation failed")]
    Storage(#[source] StorageError),

    #[error("audit write failed")]
    Audit(#[source] StorageError),

    #[error("internal keystore error")]
    Internal,
}

impl From<StorageError> for KeystoreError {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::NotFound => Self::NotFound,
            StorageError::Conflict => Self::Conflict,
            other => Self::Storage(other),
        }
    }
}

/// Key operations backed by storage and the unsealed KEK.
pub struct Keystore {
    store: Arc<dyn KeyStore>,
    unseal: Arc<UnsealManager>,
}

impl Keystore {
    pub fn new(store: Arc<dyn KeyStore>, unseal: Arc<UnsealManager>) -> Self {
        Self { store, unseal }
    }

    /// Generate an Ed25519 key, encrypt it, and persist it.
    ///
    /// The key is created directly in `Active` state. There is no activation
    /// RPC in v0.1; approval workflows can be added later.
    pub async fn create_key(
        &self,
        curve: Curve,
        algorithm: SignatureAlgorithm,
        labels: BTreeMap<String, String>,
        actor: &str,
    ) -> Result<KeyMetadata, KeystoreError> {
        if let Err(error) = ensure_ed25519(curve, algorithm) {
            let _ = self
                .audit(
                    actor,
                    "CreateKey",
                    None,
                    AuditResult::Denied,
                    failure_metadata("unsupported_algorithm"),
                )
                .await;
            return Err(error);
        }

        let id = Uuid::new_v4();
        let mut seed = Zeroizing::new([0u8; ED25519_SEED_LEN]);
        OsRng.fill_bytes(&mut seed[..]);
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes().to_vec();

        let encrypted = match self
            .unseal
            .with_kek(|kek| encrypt_ed25519(kek, id, curve, algorithm, &public_key, &seed[..]))
        {
            Ok(Ok(encrypted)) => encrypted,
            Ok(Err(error)) => {
                let _ = self
                    .audit(
                        actor,
                        "CreateKey",
                        None,
                        AuditResult::Error,
                        failure_metadata("encryption_failed"),
                    )
                    .await;
                return Err(error);
            }
            Err(error) => {
                let _ = self
                    .audit(
                        actor,
                        "CreateKey",
                        None,
                        AuditResult::Denied,
                        failure_metadata("sealed"),
                    )
                    .await;
                return Err(map_unseal(error));
            }
        };

        let new_key = NewKey {
            id,
            curve,
            algorithm,
            public_key,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce,
            wrapped_dek: encrypted.wrapped_dek,
            dek_nonce: encrypted.dek_nonce,
            state: KeyState::Active,
            labels,
        };
        let audit = AuditEntry {
            actor: actor.to_string(),
            action: "CreateKey".to_string(),
            key_id: Some(id),
            session_id: None,
            result: AuditResult::Ok,
            metadata: key_metadata(curve, algorithm),
        };

        // The key insert and its audit entry commit or roll back together.
        let record = match self.store.insert_key_with_audit(new_key, &audit).await {
            Ok(record) => record,
            Err(error) => {
                let _ = self
                    .audit(
                        actor,
                        "CreateKey",
                        Some(id),
                        AuditResult::Error,
                        failure_metadata("storage_failed"),
                    )
                    .await;
                return Err(error.into());
            }
        };

        Ok(KeyMetadata::from(&record))
    }

    pub async fn get_public_key(&self, id: KeyId) -> Result<KeyMetadata, KeystoreError> {
        let record = self
            .store
            .get_key(id)
            .await?
            .ok_or(KeystoreError::NotFound)?;
        Ok(KeyMetadata::from(&record))
    }

    pub async fn list_keys(&self, page: Page) -> Result<Vec<KeyMetadata>, KeystoreError> {
        Ok(self.store.list_keys(page).await?)
    }

    /// Sign a raw message with an active Ed25519 key.
    pub async fn sign(
        &self,
        id: KeyId,
        payload: &[u8],
        actor: &str,
        request_id: Option<&str>,
    ) -> Result<Vec<u8>, KeystoreError> {
        let record = match self.store.get_key(id).await {
            Ok(Some(record)) => record,
            Ok(None) => {
                let _ = self
                    .audit(
                        actor,
                        "Sign",
                        Some(id),
                        AuditResult::Denied,
                        sign_failure_metadata(None, payload.len(), request_id, "not_found"),
                    )
                    .await;
                return Err(KeystoreError::NotFound);
            }
            Err(error) => {
                let _ = self
                    .audit(
                        actor,
                        "Sign",
                        Some(id),
                        AuditResult::Error,
                        sign_failure_metadata(None, payload.len(), request_id, "storage_failed"),
                    )
                    .await;
                return Err(error.into());
            }
        };

        if record.state != KeyState::Active {
            let _ = self
                .audit(
                    actor,
                    "Sign",
                    Some(id),
                    AuditResult::Denied,
                    sign_failure_metadata(Some(&record), payload.len(), request_id, "not_active"),
                )
                .await;
            return Err(KeystoreError::KeyNotActive);
        }
        if let Err(error) = ensure_ed25519(record.curve, record.algorithm) {
            let _ = self
                .audit(
                    actor,
                    "Sign",
                    Some(id),
                    AuditResult::Denied,
                    sign_failure_metadata(
                        Some(&record),
                        payload.len(),
                        request_id,
                        "unsupported_algorithm",
                    ),
                )
                .await;
            return Err(error);
        }

        let seed = match self.unseal.with_kek(|kek| decrypt_ed25519(kek, &record)) {
            Ok(Ok(seed)) => seed,
            Ok(Err(error)) => {
                let _ = self
                    .audit(
                        actor,
                        "Sign",
                        Some(id),
                        AuditResult::Error,
                        sign_failure_metadata(
                            Some(&record),
                            payload.len(),
                            request_id,
                            "decrypt_failed",
                        ),
                    )
                    .await;
                return Err(error);
            }
            Err(error) => {
                let _ = self
                    .audit(
                        actor,
                        "Sign",
                        Some(id),
                        AuditResult::Denied,
                        sign_failure_metadata(Some(&record), payload.len(), request_id, "sealed"),
                    )
                    .await;
                return Err(map_unseal(error));
            }
        };

        let signing_key = SigningKey::from_bytes(&seed);
        let signature = signing_key.sign(payload).to_bytes().to_vec();

        // Signing is in-memory; the audit insert is the commit point. If it
        // fails, the signature is not returned to the caller.
        self.audit(
            actor,
            "Sign",
            Some(id),
            AuditResult::Ok,
            sign_metadata(Some(&record), payload.len(), request_id),
        )
        .await?;

        Ok(signature)
    }

    async fn audit(
        &self,
        actor: &str,
        action: &str,
        key_id: Option<KeyId>,
        result: AuditResult,
        metadata: BTreeMap<String, String>,
    ) -> Result<(), KeystoreError> {
        self.store
            .append_audit(&AuditEntry {
                actor: actor.to_string(),
                action: action.to_string(),
                key_id,
                session_id: None,
                result,
                metadata,
            })
            .await
            .map_err(KeystoreError::Audit)
    }
}

fn key_metadata(curve: Curve, algorithm: SignatureAlgorithm) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert("curve".to_string(), curve.as_str().to_string());
    metadata.insert("algorithm".to_string(), algorithm.as_str().to_string());
    metadata
}

fn failure_metadata(reason: &str) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert("reason".to_string(), reason.to_string());
    metadata
}

fn sign_metadata(
    record: Option<&KeyRecord>,
    payload_len: usize,
    request_id: Option<&str>,
) -> BTreeMap<String, String> {
    let mut metadata = record
        .map(|record| key_metadata(record.curve, record.algorithm))
        .unwrap_or_default();
    metadata.insert("payload_len".to_string(), payload_len.to_string());

    if let Some(request_id) = request_id.filter(|value| !value.is_empty()) {
        if request_id.len() <= 128 {
            metadata.insert("request_id".to_string(), request_id.to_string());
        } else {
            metadata.insert("request_id_omitted".to_string(), "too_long".to_string());
        }
    }

    metadata
}

fn sign_failure_metadata(
    record: Option<&KeyRecord>,
    payload_len: usize,
    request_id: Option<&str>,
    reason: &str,
) -> BTreeMap<String, String> {
    let mut metadata = sign_metadata(record, payload_len, request_id);
    metadata.insert("reason".to_string(), reason.to_string());
    metadata
}

struct EncryptedKey {
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    wrapped_dek: Vec<u8>,
    dek_nonce: Vec<u8>,
}

fn encrypt_ed25519(
    kek: &[u8; 32],
    id: KeyId,
    curve: Curve,
    algorithm: SignatureAlgorithm,
    public_key: &[u8],
    seed: &[u8],
) -> Result<EncryptedKey, KeystoreError> {
    if seed.len() != ED25519_SEED_LEN {
        return Err(KeystoreError::InvalidMaterial);
    }

    let binding = key_binding(id, curve, algorithm, public_key)?;
    let private_aad = envelope_aad(PRIVATE_AAD_DOMAIN, &binding);
    let dek_aad = envelope_aad(DEK_AAD_DOMAIN, &binding);

    let mut dek = Zeroizing::new([0u8; DEK_LEN]);
    OsRng.fill_bytes(&mut dek[..]);

    let private_cipher =
        XChaCha20Poly1305::new_from_slice(&dek[..]).map_err(|_| KeystoreError::Internal)?;
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = private_cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: seed,
                aad: &private_aad,
            },
        )
        .map_err(|_| KeystoreError::Internal)?;

    let kek_cipher = XChaCha20Poly1305::new_from_slice(kek).map_err(|_| KeystoreError::Internal)?;
    let mut dek_nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut dek_nonce);
    let wrapped_dek = kek_cipher
        .encrypt(
            XNonce::from_slice(&dek_nonce),
            Payload {
                msg: &dek[..],
                aad: &dek_aad,
            },
        )
        .map_err(|_| KeystoreError::Internal)?;

    Ok(EncryptedKey {
        ciphertext,
        nonce: nonce.to_vec(),
        wrapped_dek,
        dek_nonce: dek_nonce.to_vec(),
    })
}

fn decrypt_ed25519(
    kek: &[u8; 32],
    record: &KeyRecord,
) -> Result<Zeroizing<[u8; ED25519_SEED_LEN]>, KeystoreError> {
    if record.nonce.len() != NONCE_LEN || record.dek_nonce.len() != NONCE_LEN {
        return Err(KeystoreError::Corrupt);
    }

    let binding = key_binding(
        record.id,
        record.curve,
        record.algorithm,
        &record.public_key,
    )?;
    let private_aad = envelope_aad(PRIVATE_AAD_DOMAIN, &binding);
    let dek_aad = envelope_aad(DEK_AAD_DOMAIN, &binding);

    let kek_cipher = XChaCha20Poly1305::new_from_slice(kek).map_err(|_| KeystoreError::Internal)?;
    let dek = kek_cipher
        .decrypt(
            XNonce::from_slice(&record.dek_nonce),
            Payload {
                msg: &record.wrapped_dek,
                aad: &dek_aad,
            },
        )
        .map_err(|_| KeystoreError::Corrupt)?;
    let dek = Zeroizing::new(dek);
    if dek.len() != DEK_LEN {
        return Err(KeystoreError::Corrupt);
    }

    let private_cipher =
        XChaCha20Poly1305::new_from_slice(&dek[..]).map_err(|_| KeystoreError::Internal)?;
    let seed = private_cipher
        .decrypt(
            XNonce::from_slice(&record.nonce),
            Payload {
                msg: &record.ciphertext,
                aad: &private_aad,
            },
        )
        .map_err(|_| KeystoreError::Corrupt)?;
    let seed = Zeroizing::new(seed);
    let seed: [u8; ED25519_SEED_LEN] = seed
        .as_slice()
        .try_into()
        .map_err(|_| KeystoreError::Corrupt)?;

    Ok(Zeroizing::new(seed))
}

fn ensure_ed25519(curve: Curve, algorithm: SignatureAlgorithm) -> Result<(), KeystoreError> {
    match (curve, algorithm) {
        (Curve::Edwards25519, SignatureAlgorithm::EdDsa) => Ok(()),
        (Curve::Secp256k1, SignatureAlgorithm::Ecdsa) => Err(KeystoreError::Unsupported(
            "secp256k1/ECDSA is not implemented yet".to_string(),
        )),
        _ => Err(KeystoreError::InvalidAlgorithmPair),
    }
}

fn key_binding(
    id: KeyId,
    curve: Curve,
    algorithm: SignatureAlgorithm,
    public_key: &[u8],
) -> Result<Vec<u8>, KeystoreError> {
    let public_key_len =
        u16::try_from(public_key.len()).map_err(|_| KeystoreError::InvalidMaterial)?;

    let mut binding = Vec::with_capacity(16 + 1 + 1 + 2 + public_key.len());
    binding.extend_from_slice(id.as_bytes());
    binding.push(curve_tag(curve));
    binding.push(algorithm_tag(algorithm));
    binding.extend_from_slice(&public_key_len.to_le_bytes());
    binding.extend_from_slice(public_key);
    Ok(binding)
}

fn envelope_aad(domain: &[u8], binding: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(domain.len() + binding.len());
    aad.extend_from_slice(domain);
    aad.extend_from_slice(binding);
    aad
}

fn curve_tag(curve: Curve) -> u8 {
    match curve {
        Curve::Secp256k1 => 1,
        Curve::Edwards25519 => 2,
    }
}

fn algorithm_tag(algorithm: SignatureAlgorithm) -> u8 {
    match algorithm {
        SignatureAlgorithm::Ecdsa => 1,
        SignatureAlgorithm::EdDsa => 2,
    }
}

fn map_unseal(error: UnsealError) -> KeystoreError {
    match error {
        UnsealError::Sealed => KeystoreError::Sealed,
        _ => KeystoreError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn record(id: KeyId, public_key: &[u8], encrypted: EncryptedKey) -> KeyRecord {
        let now = OffsetDateTime::now_utc();
        KeyRecord {
            id,
            curve: Curve::Edwards25519,
            algorithm: SignatureAlgorithm::EdDsa,
            public_key: public_key.to_vec(),
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce,
            wrapped_dek: encrypted.wrapped_dek,
            dek_nonce: encrypted.dek_nonce,
            state: KeyState::Active,
            labels: BTreeMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn envelope_roundtrip_binds_metadata() {
        let kek = [7u8; 32];
        let id = Uuid::new_v4();
        let seed = [9u8; 32];
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();

        let encrypted = encrypt_ed25519(
            &kek,
            id,
            Curve::Edwards25519,
            SignatureAlgorithm::EdDsa,
            &public_key,
            &seed,
        )
        .unwrap();

        let decrypted = decrypt_ed25519(&kek, &record(id, &public_key, encrypted)).unwrap();
        assert_eq!(&*decrypted, &seed);
    }

    #[tokio::test]
    async fn key_operations_write_audit_entries() {
        use crate::storage::SqliteStore;
        use crate::unseal::{HolderIndex, UnsealConfig, UnsealManager};

        let holder_key = SigningKey::from_bytes(&[1u8; 32]);
        let holders = vec![HolderIndex {
            id: "holder-1".to_string(),
            index: 1,
            ed25519_public: hex::encode(holder_key.verifying_key().to_bytes()),
        }];
        let (manager, _, _) = UnsealManager::bootstrap(UnsealConfig::new(1, 1), holders).unwrap();
        manager.force_unseal_for_test([7u8; 32]);

        let store = Arc::new(SqliteStore::connect("sqlite::memory:").await.unwrap());
        let keystore = Keystore::new(store.clone(), Arc::new(manager));

        let key = keystore
            .create_key(
                Curve::Edwards25519,
                SignatureAlgorithm::EdDsa,
                BTreeMap::new(),
                "test-actor",
            )
            .await
            .unwrap();
        keystore
            .sign(key.id, b"payload", "test-actor", Some("req-1"))
            .await
            .unwrap();

        let unknown = Uuid::new_v4();
        assert!(matches!(
            keystore.sign(unknown, b"payload", "test-actor", None).await,
            Err(KeystoreError::NotFound)
        ));

        let rows: Vec<(String, String, Option<String>, String, String)> = sqlx::query_as(
            "SELECT actor, action, key_id, result, metadata FROM audit_log ORDER BY id",
        )
        .fetch_all(store.pool())
        .await
        .unwrap();

        assert_eq!(rows.len(), 3);
        let key_id = key.id.to_string();
        assert_eq!(rows[0].0, "test-actor");
        assert_eq!(rows[0].1, "CreateKey");
        assert_eq!(rows[0].2.as_deref(), Some(key_id.as_str()));
        assert_eq!(rows[0].3, "ok");
        assert_eq!(rows[1].1, "Sign");
        assert_eq!(rows[1].3, "ok");
        assert!(rows[1].4.contains("\"request_id\":\"req-1\""));
        assert!(rows[1].4.contains("\"payload_len\":\"7\""));
        assert_eq!(rows[2].1, "Sign");
        let unknown_id = unknown.to_string();
        assert_eq!(rows[2].2.as_deref(), Some(unknown_id.as_str()));
        assert_eq!(rows[2].3, "denied");
        assert!(rows[2].4.contains("\"reason\":\"not_found\""));
    }

    #[tokio::test]
    async fn create_key_rolls_back_when_audit_write_fails() {
        use crate::storage::SqliteStore;
        use crate::unseal::{HolderIndex, UnsealConfig, UnsealManager};

        let holder_key = SigningKey::from_bytes(&[1u8; 32]);
        let holders = vec![HolderIndex {
            id: "holder-1".to_string(),
            index: 1,
            ed25519_public: hex::encode(holder_key.verifying_key().to_bytes()),
        }];
        let (manager, _, _) = UnsealManager::bootstrap(UnsealConfig::new(1, 1), holders).unwrap();
        manager.force_unseal_for_test([7u8; 32]);

        let store = Arc::new(SqliteStore::connect("sqlite::memory:").await.unwrap());
        sqlx::query("DROP TABLE audit_log")
            .execute(store.pool())
            .await
            .unwrap();
        let keystore = Keystore::new(store.clone(), Arc::new(manager));

        let result = keystore
            .create_key(
                Curve::Edwards25519,
                SignatureAlgorithm::EdDsa,
                BTreeMap::new(),
                "test-actor",
            )
            .await;
        assert!(result.is_err());

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM keys")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn envelope_rejects_wrong_kek_and_tampering() {
        let kek = [7u8; 32];
        let other_kek = [8u8; 32];
        let id = Uuid::new_v4();
        let seed = [9u8; 32];
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let encrypted = encrypt_ed25519(
            &kek,
            id,
            Curve::Edwards25519,
            SignatureAlgorithm::EdDsa,
            &public_key,
            &seed,
        )
        .unwrap();

        assert!(matches!(
            decrypt_ed25519(&other_kek, &record(id, &public_key, encrypted)),
            Err(KeystoreError::Corrupt)
        ));

        let encrypted = encrypt_ed25519(
            &kek,
            id,
            Curve::Edwards25519,
            SignatureAlgorithm::EdDsa,
            &public_key,
            &seed,
        )
        .unwrap();
        let mut wrong_public_key = public_key;
        wrong_public_key[0] ^= 1;
        assert!(matches!(
            decrypt_ed25519(&kek, &record(id, &wrong_public_key, encrypted)),
            Err(KeystoreError::Corrupt)
        ));

        let mut encrypted = encrypt_ed25519(
            &kek,
            id,
            Curve::Edwards25519,
            SignatureAlgorithm::EdDsa,
            &public_key,
            &seed,
        )
        .unwrap();
        let last = encrypted.ciphertext.len() - 1;
        encrypted.ciphertext[last] ^= 1;
        assert!(matches!(
            decrypt_ed25519(&kek, &record(id, &public_key, encrypted)),
            Err(KeystoreError::Corrupt)
        ));
    }
}
