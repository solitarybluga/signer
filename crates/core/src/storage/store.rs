use std::time::Duration;

use async_trait::async_trait;

use super::model::{
    AuditEntry, KeyId, KeyMetadata, KeyRecord, KeyState, NewKey, Page, SessionId,
    SignatureAlgorithm, UnsealSession,
};

/// Connection pool settings shared by the SQLite and PostgreSQL stores.
#[derive(Debug, Clone, Copy)]
pub struct PoolConfig {
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout: Duration,
    pub idle_timeout: Option<Duration>,
    pub max_lifetime: Option<Duration>,
    pub sqlite_busy_timeout: Duration,
}

impl PoolConfig {
    pub fn sqlite_default() -> Self {
        Self {
            max_connections: 1,
            min_connections: 0,
            acquire_timeout: Duration::from_secs(5),
            idle_timeout: Some(Duration::from_secs(600)),
            max_lifetime: Some(Duration::from_secs(1800)),
            sqlite_busy_timeout: Duration::from_secs(5),
        }
    }

    pub fn postgres_default() -> Self {
        Self {
            max_connections: 10,
            min_connections: 0,
            acquire_timeout: Duration::from_secs(5),
            idle_timeout: Some(Duration::from_secs(600)),
            max_lifetime: Some(Duration::from_secs(1800)),
            sqlite_busy_timeout: Duration::from_secs(5),
        }
    }
}

/// Storage-layer errors.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("record not found")]
    NotFound,

    #[error("duplicate key material")]
    Conflict,

    #[error("storage unavailable: {0}")]
    Unavailable(String),

    #[error("corrupt stored data: {0}")]
    Corrupt(String),

    #[error("internal storage error: {0}")]
    Internal(String),
}

/// Persistence interface for keys and audit records.
///
/// Implementations only ever see ciphertext and must not perform any
/// cryptographic operations.
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Insert a new key. Returns [`StorageError::Conflict`] if the public key
    /// already exists.
    async fn insert_key(&self, key: NewKey) -> Result<KeyRecord, StorageError>;

    /// Insert a key and its audit entry atomically.
    async fn insert_key_with_audit(
        &self,
        key: NewKey,
        audit: &AuditEntry,
    ) -> Result<KeyRecord, StorageError>;

    /// Load a key record (including ciphertext) by ID.
    async fn get_key(&self, id: KeyId) -> Result<Option<KeyRecord>, StorageError>;

    /// List key metadata with pagination.
    async fn list_keys(&self, page: Page) -> Result<Vec<KeyMetadata>, StorageError>;

    /// Update the key state.
    async fn update_key_state(&self, id: KeyId, state: KeyState) -> Result<(), StorageError>;

    /// Find a key ID by public key; used for duplicate detection during import.
    async fn find_key_id_by_public_key(
        &self,
        curve: super::model::Curve,
        algorithm: SignatureAlgorithm,
        public_key: &[u8],
    ) -> Result<Option<KeyId>, StorageError>;

    /// Insert an unseal session.
    async fn insert_unseal_session(&self, session: &UnsealSession) -> Result<(), StorageError>;

    /// Load an unseal session.
    async fn get_unseal_session(
        &self,
        id: SessionId,
    ) -> Result<Option<UnsealSession>, StorageError>;

    /// Update an unseal session (collected shares, state, and so on).
    async fn update_unseal_session(&self, session: &UnsealSession) -> Result<(), StorageError>;

    /// Append an audit event.
    async fn append_audit(&self, entry: &AuditEntry) -> Result<(), StorageError>;
}
