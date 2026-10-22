//! Key generation, envelope encryption, and signing.
//!
//! Each key gets a random 32-byte DEK. The private key is encrypted with the
//! DEK, and the DEK is wrapped with the unsealed KEK. Both AEAD
//! operations bind the key metadata into the AAD.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, RwLock};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey as Ed25519SigningKey};
use k256::ecdsa::SigningKey as EcdsaSigningKey;
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
const PRIVATE_KEY_LEN: usize = 32;
const PRIVATE_AAD_DOMAIN: &[u8] = b"signer.key.private.v1";
const DEK_AAD_DOMAIN: &[u8] = b"signer.key.dek.v1";
const KEY_CACHE_CAPACITY: usize = 1024;

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

    #[error("invalid curve/algorithm pair")]
    InvalidAlgorithmPair,

    #[error("invalid key material")]
    InvalidMaterial,

    #[error("ECDSA payload must be a 32-byte digest")]
    InvalidPayload,

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
    /// Cached `KeyRecord`s contain only ciphertext and wrapped DEKs, never
    /// plaintext private keys. Keys are immutable after creation in v0.1, so
    /// entries do not expire; future rotation/state changes must invalidate.
    key_cache: RwLock<HashMap<KeyId, Arc<KeyRecord>>>,
    sign_audit: bool,
}

impl Keystore {
    pub fn new(store: Arc<dyn KeyStore>, unseal: Arc<UnsealManager>) -> Self {
        Self {
            store,
            unseal,
            key_cache: RwLock::new(HashMap::new()),
            sign_audit: true,
        }
    }

    /// Enable or disable Sign audit records. Intended for controlled
    /// benchmarks; production deployments should keep Sign audit enabled.
    pub fn with_sign_audit(mut self, enabled: bool) -> Self {
        self.sign_audit = enabled;
        self
    }

    fn cached_key(&self, id: KeyId) -> Option<Arc<KeyRecord>> {
        let cache = self
            .key_cache
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.get(&id).cloned()
    }

    fn remember_key(&self, record: Arc<KeyRecord>) {
        let mut cache = self
            .key_cache
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if cache.len() >= KEY_CACHE_CAPACITY && !cache.contains_key(&record.id) {
            // Simple bound: evict an arbitrary entry when the cache is full.
            if let Some(victim) = cache.keys().next().copied() {
                cache.remove(&victim);
            }
        }
        cache.insert(record.id, record);
    }

    /// Generate an Ed25519 or secp256k1 key, encrypt it, and persist it.
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
        let (private_key, public_key) = match generate_key(curve, algorithm) {
            Ok(key) => key,
            Err(error) => {
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
        };

        let id = Uuid::new_v4();
        let encrypted = match self.unseal.with_kek(|kek| {
            encrypt_key_material(kek, id, curve, algorithm, &public_key, &private_key[..])
        }) {
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

        let record = Arc::new(record);
        self.remember_key(Arc::clone(&record));
        Ok(KeyMetadata::from(record.as_ref()))
    }

    pub async fn get_public_key(&self, id: KeyId) -> Result<KeyMetadata, KeystoreError> {
        let record = match self.cached_key(id) {
            Some(record) => record,
            None => {
                let record = self
                    .store
                    .get_key(id)
                    .await?
                    .ok_or(KeystoreError::NotFound)?;
                let record = Arc::new(record);
                self.remember_key(Arc::clone(&record));
                record
            }
        };
        Ok(KeyMetadata::from(record.as_ref()))
    }

    pub async fn list_keys(&self, page: Page) -> Result<Vec<KeyMetadata>, KeystoreError> {
        Ok(self.store.list_keys(page).await?)
    }

    /// Sign with an active Ed25519 key or secp256k1 ECDSA key.
    pub async fn sign(
        &self,
        id: KeyId,
        payload: &[u8],
        actor: &str,
        request_id: Option<&str>,
    ) -> Result<Vec<u8>, KeystoreError> {
        let record = match self.cached_key(id) {
            Some(record) => record,
            None => match self.store.get_key(id).await {
                Ok(Some(record)) => {
                    let record = Arc::new(record);
                    self.remember_key(Arc::clone(&record));
                    record
                }
                Ok(None) => {
                    let _ = self
                        .sign_audit(
                            actor,
                            Some(id),
                            AuditResult::Denied,
                            sign_failure_metadata(None, payload.len(), request_id, "not_found"),
                        )
                        .await;
                    return Err(KeystoreError::NotFound);
                }
                Err(error) => {
                    let _ = self
                        .sign_audit(
                            actor,
                            Some(id),
                            AuditResult::Error,
                            sign_failure_metadata(
                                None,
                                payload.len(),
                                request_id,
                                "storage_failed",
                            ),
                        )
                        .await;
                    return Err(error.into());
                }
            },
        };

        if record.state != KeyState::Active {
            let _ = self
                .sign_audit(
                    actor,
                    Some(id),
                    AuditResult::Denied,
                    sign_failure_metadata(
                        Some(record.as_ref()),
                        payload.len(),
                        request_id,
                        "not_active",
                    ),
                )
                .await;
            return Err(KeystoreError::KeyNotActive);
        }
        if let Err(error) = ensure_supported(record.curve, record.algorithm) {
            let _ = self
                .sign_audit(
                    actor,
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
        if record.algorithm == SignatureAlgorithm::Ecdsa && payload.len() != 32 {
            let _ = self
                .sign_audit(
                    actor,
                    Some(id),
                    AuditResult::Denied,
                    sign_failure_metadata(
                        Some(&record),
                        payload.len(),
                        request_id,
                        "invalid_payload",
                    ),
                )
                .await;
            return Err(KeystoreError::InvalidPayload);
        }

        let private_key = match self
            .unseal
            .with_kek(|kek| decrypt_key_material(kek, &record))
        {
            Ok(Ok(private_key)) => private_key,
            Ok(Err(error)) => {
                let _ = self
                    .sign_audit(
                        actor,
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
                    .sign_audit(
                        actor,
                        Some(id),
                        AuditResult::Denied,
                        sign_failure_metadata(
                            Some(record.as_ref()),
                            payload.len(),
                            request_id,
                            "sealed",
                        ),
                    )
                    .await;
                return Err(map_unseal(error));
            }
        };

        let signature = match (record.curve, record.algorithm) {
            (Curve::Edwards25519, SignatureAlgorithm::EdDsa) => {
                let signing_key = Ed25519SigningKey::from_bytes(&private_key);
                signing_key.sign(payload).to_bytes().to_vec()
            }
            (Curve::Secp256k1, SignatureAlgorithm::Ecdsa) => {
                match sign_ecdsa(&private_key, payload) {
                    Ok(signature) => signature,
                    Err(error) => {
                        let _ = self
                            .sign_audit(
                                actor,
                                Some(id),
                                AuditResult::Error,
                                sign_failure_metadata(
                                    Some(&record),
                                    payload.len(),
                                    request_id,
                                    "ecdsa_sign_failed",
                                ),
                            )
                            .await;
                        return Err(error);
                    }
                }
            }
            _ => return Err(KeystoreError::InvalidAlgorithmPair),
        };

        // Signing is in-memory; the audit insert is the commit point. If it
        // fails, the signature is not returned to the caller.
        self.sign_audit(
            actor,
            Some(id),
            AuditResult::Ok,
            sign_metadata(Some(record.as_ref()), payload.len(), request_id),
        )
        .await?;

        Ok(signature)
    }

    async fn sign_audit(
        &self,
        actor: &str,
        key_id: Option<KeyId>,
        result: AuditResult,
        metadata: BTreeMap<String, String>,
    ) -> Result<(), KeystoreError> {
        if !self.sign_audit {
            return Ok(());
        }
        self.audit(actor, "Sign", key_id, result, metadata).await
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

fn encrypt_key_material(
    kek: &[u8; 32],
    id: KeyId,
    curve: Curve,
    algorithm: SignatureAlgorithm,
    public_key: &[u8],
    private_key: &[u8],
) -> Result<EncryptedKey, KeystoreError> {
    if private_key.len() != PRIVATE_KEY_LEN {
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
                msg: private_key,
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

fn decrypt_key_material(
    kek: &[u8; 32],
    record: &KeyRecord,
) -> Result<Zeroizing<[u8; PRIVATE_KEY_LEN]>, KeystoreError> {
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
    let private_key = private_cipher
        .decrypt(
            XNonce::from_slice(&record.nonce),
            Payload {
                msg: &record.ciphertext,
                aad: &private_aad,
            },
        )
        .map_err(|_| KeystoreError::Corrupt)?;
    let private_key = Zeroizing::new(private_key);
    let private_key: [u8; PRIVATE_KEY_LEN] = private_key
        .as_slice()
        .try_into()
        .map_err(|_| KeystoreError::Corrupt)?;

    Ok(Zeroizing::new(private_key))
}

fn ensure_supported(curve: Curve, algorithm: SignatureAlgorithm) -> Result<(), KeystoreError> {
    match (curve, algorithm) {
        (Curve::Edwards25519, SignatureAlgorithm::EdDsa)
        | (Curve::Secp256k1, SignatureAlgorithm::Ecdsa) => Ok(()),
        _ => Err(KeystoreError::InvalidAlgorithmPair),
    }
}

fn generate_key(
    curve: Curve,
    algorithm: SignatureAlgorithm,
) -> Result<(Zeroizing<[u8; PRIVATE_KEY_LEN]>, Vec<u8>), KeystoreError> {
    match (curve, algorithm) {
        (Curve::Edwards25519, SignatureAlgorithm::EdDsa) => {
            let mut seed = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
            OsRng.fill_bytes(&mut seed[..]);
            let signing_key = Ed25519SigningKey::from_bytes(&seed);
            let public_key = signing_key.verifying_key().to_bytes().to_vec();
            Ok((seed, public_key))
        }
        (Curve::Secp256k1, SignatureAlgorithm::Ecdsa) => loop {
            let mut scalar = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
            OsRng.fill_bytes(&mut scalar[..]);
            let signing_key = match EcdsaSigningKey::from_slice(&scalar[..]) {
                Ok(signing_key) => signing_key,
                Err(_) => continue,
            };

            let mut private_key = Zeroizing::new([0u8; PRIVATE_KEY_LEN]);
            private_key.copy_from_slice(&signing_key.to_bytes());
            let public_key = signing_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec();
            return Ok((private_key, public_key));
        },
        _ => Err(KeystoreError::InvalidAlgorithmPair),
    }
}

fn sign_ecdsa(
    private_key: &[u8; PRIVATE_KEY_LEN],
    digest: &[u8],
) -> Result<Vec<u8>, KeystoreError> {
    if digest.len() != 32 {
        return Err(KeystoreError::InvalidPayload);
    }

    let signing_key =
        EcdsaSigningKey::from_slice(private_key).map_err(|_| KeystoreError::Corrupt)?;
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(digest)
        .map_err(|_| KeystoreError::Internal)?;

    // Ethereum uses low-s signatures. Negating s also flips the y parity bit
    // of the recovery id.
    let mut recovery = recovery_id.to_byte();
    let signature = match signature.normalize_s() {
        Some(normalized) => {
            recovery ^= 1;
            normalized
        }
        None => signature,
    };
    if recovery > 1 {
        return Err(KeystoreError::Internal);
    }

    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(27 + recovery);
    Ok(bytes)
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

    fn record_for(
        id: KeyId,
        curve: Curve,
        algorithm: SignatureAlgorithm,
        public_key: &[u8],
        encrypted: EncryptedKey,
    ) -> KeyRecord {
        let now = OffsetDateTime::now_utc();
        KeyRecord {
            id,
            curve,
            algorithm,
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

    fn record(id: KeyId, public_key: &[u8], encrypted: EncryptedKey) -> KeyRecord {
        record_for(
            id,
            Curve::Edwards25519,
            SignatureAlgorithm::EdDsa,
            public_key,
            encrypted,
        )
    }

    #[test]
    fn envelope_roundtrip_binds_metadata() {
        let kek = [7u8; 32];
        let id = Uuid::new_v4();
        let seed = [9u8; 32];
        let public_key = Ed25519SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();

        let encrypted = encrypt_key_material(
            &kek,
            id,
            Curve::Edwards25519,
            SignatureAlgorithm::EdDsa,
            &public_key,
            &seed,
        )
        .unwrap();

        let decrypted = decrypt_key_material(&kek, &record(id, &public_key, encrypted)).unwrap();
        assert_eq!(&*decrypted, &seed);
    }

    #[tokio::test]
    async fn key_operations_write_audit_entries() {
        use crate::storage::SqliteStore;
        use crate::unseal::{HolderIndex, UnsealConfig, UnsealManager};

        let holder_key = Ed25519SigningKey::from_bytes(&[1u8; 32]);
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
    async fn sign_audit_can_be_disabled_without_disabling_create_key_audit() {
        use crate::storage::SqliteStore;
        use crate::unseal::{HolderIndex, UnsealConfig, UnsealManager};

        let holder_key = Ed25519SigningKey::from_bytes(&[1u8; 32]);
        let holders = vec![HolderIndex {
            id: "holder-1".to_string(),
            index: 1,
            ed25519_public: hex::encode(holder_key.verifying_key().to_bytes()),
        }];
        let (manager, _, _) = UnsealManager::bootstrap(UnsealConfig::new(1, 1), holders).unwrap();
        manager.force_unseal_for_test([7u8; 32]);

        let store = Arc::new(SqliteStore::connect("sqlite::memory:").await.unwrap());
        let keystore = Keystore::new(store.clone(), Arc::new(manager)).with_sign_audit(false);

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
        assert!(matches!(
            keystore
                .sign(Uuid::new_v4(), b"payload", "test-actor", None)
                .await,
            Err(KeystoreError::NotFound)
        ));

        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT action, result FROM audit_log ORDER BY id")
                .fetch_all(store.pool())
                .await
                .unwrap();
        assert_eq!(rows, vec![("CreateKey".to_string(), "ok".to_string())]);
    }

    #[tokio::test]
    async fn sign_uses_cached_encrypted_key_record() {
        use crate::storage::SqliteStore;
        use crate::unseal::{HolderIndex, UnsealConfig, UnsealManager};

        let holder_key = Ed25519SigningKey::from_bytes(&[1u8; 32]);
        let holders = vec![HolderIndex {
            id: "holder-1".to_string(),
            index: 1,
            ed25519_public: hex::encode(holder_key.verifying_key().to_bytes()),
        }];
        let (manager, _, _) = UnsealManager::bootstrap(UnsealConfig::new(1, 1), holders).unwrap();
        manager.force_unseal_for_test([7u8; 32]);
        let manager = Arc::new(manager);

        let store = Arc::new(SqliteStore::connect("sqlite::memory:").await.unwrap());
        let warm = Keystore::new(store.clone(), Arc::clone(&manager));
        let cold = Keystore::new(store.clone(), Arc::clone(&manager));

        let warm_key = warm
            .create_key(
                Curve::Edwards25519,
                SignatureAlgorithm::EdDsa,
                BTreeMap::new(),
                "test-actor",
            )
            .await
            .unwrap();
        let miss_key = warm
            .create_key(
                Curve::Edwards25519,
                SignatureAlgorithm::EdDsa,
                BTreeMap::new(),
                "test-actor",
            )
            .await
            .unwrap();

        // Populate the cold cache through a normal storage read.
        cold.sign(miss_key.id, b"payload", "test-actor", None)
            .await
            .unwrap();

        for id in [warm_key.id, miss_key.id] {
            sqlx::query("DELETE FROM keys WHERE id = ?")
                .bind(id.to_string())
                .execute(store.pool())
                .await
                .unwrap();
        }

        // CreateKey populated `warm`; sign must not touch the now-missing row.
        assert_eq!(
            warm.sign(warm_key.id, b"payload", "test-actor", None)
                .await
                .unwrap()
                .len(),
            64
        );
        // `cold` loaded miss_key on its first sign and must keep serving it.
        assert_eq!(
            cold.sign(miss_key.id, b"payload", "test-actor", None)
                .await
                .unwrap()
                .len(),
            64
        );
        // `cold` never saw warm_key, so it must still hit storage and fail.
        assert!(matches!(
            cold.sign(warm_key.id, b"payload", "test-actor", None).await,
            Err(KeystoreError::NotFound)
        ));
    }

    #[tokio::test]
    async fn create_key_rolls_back_when_audit_write_fails() {
        use crate::storage::SqliteStore;
        use crate::unseal::{HolderIndex, UnsealConfig, UnsealManager};

        let holder_key = Ed25519SigningKey::from_bytes(&[1u8; 32]);
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
    fn secp256k1_envelope_and_signature_roundtrip() {
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        use k256::ecdsa::{Signature as EcdsaSignature, SigningKey as EcdsaSigningKey};

        let kek = [7u8; 32];
        let id = Uuid::new_v4();
        let signing_key = EcdsaSigningKey::from_slice(&[1u8; 32]).unwrap();
        let mut private_key = [0u8; PRIVATE_KEY_LEN];
        private_key.copy_from_slice(&signing_key.to_bytes());
        let public_key = signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();

        let encrypted = encrypt_key_material(
            &kek,
            id,
            Curve::Secp256k1,
            SignatureAlgorithm::Ecdsa,
            &public_key,
            &private_key,
        )
        .unwrap();
        let record = record_for(
            id,
            Curve::Secp256k1,
            SignatureAlgorithm::Ecdsa,
            &public_key,
            encrypted,
        );
        let decrypted = decrypt_key_material(&kek, &record).unwrap();
        assert_eq!(&*decrypted, &private_key);

        let digest = [9u8; 32];
        let signature_bytes = sign_ecdsa(&decrypted, &digest).unwrap();
        assert_eq!(signature_bytes.len(), 65);

        let signature = EcdsaSignature::from_slice(&signature_bytes[..64]).unwrap();
        assert!(signature.normalize_s().is_none());
        signing_key
            .verifying_key()
            .verify_prehash(&digest, &signature)
            .unwrap();
    }

    #[test]
    fn envelope_rejects_wrong_kek_and_tampering() {
        let kek = [7u8; 32];
        let other_kek = [8u8; 32];
        let id = Uuid::new_v4();
        let seed = [9u8; 32];
        let public_key = Ed25519SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let encrypted = encrypt_key_material(
            &kek,
            id,
            Curve::Edwards25519,
            SignatureAlgorithm::EdDsa,
            &public_key,
            &seed,
        )
        .unwrap();

        assert!(matches!(
            decrypt_key_material(&other_kek, &record(id, &public_key, encrypted)),
            Err(KeystoreError::Corrupt)
        ));

        let encrypted = encrypt_key_material(
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
            decrypt_key_material(&kek, &record(id, &wrong_public_key, encrypted)),
            Err(KeystoreError::Corrupt)
        ));

        let mut encrypted = encrypt_key_material(
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
            decrypt_key_material(&kek, &record(id, &public_key, encrypted)),
            Err(KeystoreError::Corrupt)
        ));
    }
}
