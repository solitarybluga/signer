use std::collections::BTreeMap;

use time::OffsetDateTime;
use uuid::Uuid;

/// Key identifier.
pub type KeyId = Uuid;

/// Unseal session identifier.
pub type SessionId = Uuid;

/// Elliptic curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    Secp256k1,
    Edwards25519,
}

impl Curve {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Secp256k1 => "secp256k1",
            Self::Edwards25519 => "edwards25519",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "secp256k1" => Some(Self::Secp256k1),
            "edwards25519" => Some(Self::Edwards25519),
            _ => None,
        }
    }
}

/// Signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Ecdsa,
    EdDsa,
}

impl SignatureAlgorithm {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ecdsa => "ecdsa",
            Self::EdDsa => "eddsa",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ecdsa" => Some(Self::Ecdsa),
            "eddsa" => Some(Self::EdDsa),
            _ => None,
        }
    }
}

/// Key state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    Created,
    Active,
    Rotating,
    Destroyed,
}

impl KeyState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Destroyed => "destroyed",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "created" => Some(Self::Created),
            "active" => Some(Self::Active),
            "rotating" => Some(Self::Rotating),
            "destroyed" => Some(Self::Destroyed),
            _ => None,
        }
    }
}

/// Unseal session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsealState {
    Collecting,
    Unsealed,
    Expired,
    Failed,
}

impl UnsealState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Unsealed => "unsealed",
            Self::Expired => "expired",
            Self::Failed => "failed",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "collecting" => Some(Self::Collecting),
            "unsealed" => Some(Self::Unsealed),
            "expired" => Some(Self::Expired),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// Audit result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditResult {
    Ok,
    Denied,
    Error,
}

impl AuditResult {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Denied => "denied",
            Self::Error => "error",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ok" => Some(Self::Ok),
            "denied" => Some(Self::Denied),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

/// Full record written to storage when a key is created.
///
/// Contains ciphertext and the wrapped DEK; the caller must have encrypted
/// everything already.
#[derive(Clone)]
pub struct NewKey {
    pub id: KeyId,
    pub curve: Curve,
    pub algorithm: SignatureAlgorithm,
    pub public_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub dek_nonce: Vec<u8>,
    pub state: KeyState,
    pub labels: BTreeMap<String, String>,
}

impl std::fmt::Debug for NewKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewKey")
            .field("id", &self.id)
            .field("curve", &self.curve)
            .field("algorithm", &self.algorithm)
            .field("public_key_len", &self.public_key.len())
            .field("state", &self.state)
            .field("labels", &self.labels)
            .finish_non_exhaustive()
    }
}

/// Key record read from storage, including ciphertext fields.
///
/// This type must never appear in logs, serialized output, or API responses.
#[derive(Clone)]
pub struct KeyRecord {
    pub id: KeyId,
    pub curve: Curve,
    pub algorithm: SignatureAlgorithm,
    pub public_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub dek_nonce: Vec<u8>,
    pub state: KeyState,
    pub labels: BTreeMap<String, String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl std::fmt::Debug for KeyRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRecord")
            .field("id", &self.id)
            .field("curve", &self.curve)
            .field("algorithm", &self.algorithm)
            .field("public_key_len", &self.public_key.len())
            .field("state", &self.state)
            .field("labels", &self.labels)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish_non_exhaustive()
    }
}

/// Key metadata safe to return to callers (contains no ciphertext).
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub id: KeyId,
    pub curve: Curve,
    pub algorithm: SignatureAlgorithm,
    pub public_key: Vec<u8>,
    pub state: KeyState,
    pub labels: BTreeMap<String, String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl From<&KeyRecord> for KeyMetadata {
    fn from(record: &KeyRecord) -> Self {
        Self {
            id: record.id,
            curve: record.curve,
            algorithm: record.algorithm,
            public_key: record.public_key.clone(),
            state: record.state,
            labels: record.labels.clone(),
            created_at: record.created_at,
            updated_at: record.updated_at,
        }
    }
}

/// Pagination parameters.
#[derive(Debug, Clone, Copy)]
pub struct Page {
    pub limit: u32,
    pub offset: u32,
}

impl Default for Page {
    fn default() -> Self {
        Self {
            limit: 50,
            offset: 0,
        }
    }
}

/// Unseal session.
#[derive(Debug, Clone)]
pub struct UnsealSession {
    pub id: SessionId,
    pub nonce: Vec<u8>,
    pub threshold: u32,
    pub shares_collected: u32,
    pub state: UnsealState,
    pub expires_at: OffsetDateTime,
    pub created_at: OffsetDateTime,
}

/// Audit event to be written. The database assigns the ID and timestamp.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub actor: String,
    pub action: String,
    pub key_id: Option<KeyId>,
    pub session_id: Option<SessionId>,
    pub result: AuditResult,
    pub metadata: BTreeMap<String, String>,
}
