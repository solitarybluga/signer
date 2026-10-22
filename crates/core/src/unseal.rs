//! Quorum unsealing with Ristretto255 Feldman VSS.
//!
//! v0.1 keeps the unsealed KEK in process memory. Share transport encryption,
//! holder authentication, and holder signatures are handled by the API layer in
//! a later iteration.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use signer_share::HolderKeypair;
use signer_vss::{self, VssCommitments};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub use signer_vss::VssError;

const KEK_LEN: usize = 32;
const CHECK_NONCE_LEN: usize = 24;
const CHECK_PLAINTEXT: &[u8] = b"signer-kek-check-v1";
const CHECK_AAD: &[u8] = b"signer.kek.check.v1";
const KEK_CHECK_VERSION: u8 = 3;

/// Unseal session identifier.
pub type SessionId = Uuid;

/// Holder registration entry used for share-index and signature binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HolderIndex {
    pub id: String,
    pub index: u8,
    /// Hex-encoded Ed25519 public key used to authenticate submissions.
    pub ed25519_public: String,
}

#[derive(Debug, Clone)]
struct HolderRegistration {
    index: u8,
    verifying_key: VerifyingKey,
}

/// One encrypted, signed share submission.
pub struct ShareSubmission<'a> {
    pub holder_id: &'a str,
    pub share_index: Option<u8>,
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
    pub signature: &'a [u8],
}

/// State of an unseal session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Collecting,
    Unsealed,
    Expired,
    Failed,
}

impl SessionState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Collecting => "collecting",
            Self::Unsealed => "unsealed",
            Self::Expired => "expired",
            Self::Failed => "failed",
        }
    }
}

/// Ciphertext that verifies a reconstructed KEK without storing the KEK.
#[derive(Debug, Clone)]
pub struct KekCheck {
    nonce: [u8; CHECK_NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl KekCheck {
    /// Rebuild a check from persisted parts.
    pub fn from_parts(
        nonce: [u8; CHECK_NONCE_LEN],
        ciphertext: Vec<u8>,
    ) -> Result<Self, UnsealError> {
        if ciphertext.len() != CHECK_PLAINTEXT.len() + 16 {
            return Err(UnsealError::InvalidConfig(
                "invalid KEK check ciphertext length",
            ));
        }
        Ok(Self { nonce, ciphertext })
    }

    pub fn nonce(&self) -> [u8; CHECK_NONCE_LEN] {
        self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

/// Persisted KEK check plus the VSS setup and holder registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KekCheckFile {
    #[serde(default = "default_kek_check_version")]
    pub version: u8,
    #[serde(with = "hex_bytes")]
    pub nonce: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub ciphertext: Vec<u8>,
    pub threshold: u8,
    pub total_shares: u8,
    #[serde(default)]
    pub vss: VssCommitments,
    #[serde(default)]
    pub holders: Vec<HolderIndex>,
}

fn default_kek_check_version() -> u8 {
    1
}

impl KekCheckFile {
    pub fn from_check(
        check: &KekCheck,
        threshold: u8,
        total_shares: u8,
        vss: VssCommitments,
        holders: Vec<HolderIndex>,
    ) -> Self {
        Self {
            version: KEK_CHECK_VERSION,
            nonce: check.nonce.to_vec(),
            ciphertext: check.ciphertext.clone(),
            threshold,
            total_shares,
            vss,
            holders,
        }
    }

    pub fn into_parts(
        self,
    ) -> Result<(KekCheck, u8, u8, VssCommitments, Vec<HolderIndex>), UnsealError> {
        if self.version != KEK_CHECK_VERSION {
            return Err(UnsealError::InvalidConfig(
                "unsupported KEK check version; run signer-admin init again",
            ));
        }

        let nonce: [u8; CHECK_NONCE_LEN] = self
            .nonce
            .try_into()
            .map_err(|_| UnsealError::InvalidConfig("invalid KEK check nonce length"))?;
        let check = KekCheck::from_parts(nonce, self.ciphertext)?;

        if self.threshold == 0 || self.total_shares == 0 || self.threshold > self.total_shares {
            return Err(UnsealError::InvalidConfig(
                "invalid threshold configuration",
            ));
        }
        if self.vss.len() != self.threshold as usize {
            return Err(UnsealError::InvalidConfig(
                "VSS commitment count does not match threshold",
            ));
        }
        self.vss
            .decode()
            .map_err(|_| UnsealError::InvalidConfig("invalid VSS commitments"))?;
        validate_holders(self.total_shares, &self.holders)?;

        Ok((
            check,
            self.threshold,
            self.total_shares,
            self.vss,
            self.holders,
        ))
    }
}

/// Unseal configuration.
#[derive(Debug, Clone)]
pub struct UnsealConfig {
    pub threshold: u8,
    pub total_shares: u8,
    pub session_ttl: Duration,
}

impl UnsealConfig {
    pub fn new(threshold: u8, total_shares: u8) -> Self {
        Self {
            threshold,
            total_shares,
            session_ttl: Duration::minutes(10),
        }
    }

    fn validate(&self) -> Result<(), UnsealError> {
        if self.threshold == 0 {
            return Err(UnsealError::InvalidConfig("threshold must be at least 1"));
        }
        if self.total_shares == 0 {
            return Err(UnsealError::InvalidConfig(
                "total_shares must be at least 1",
            ));
        }
        if self.threshold > self.total_shares {
            return Err(UnsealError::InvalidConfig(
                "threshold cannot exceed total_shares",
            ));
        }
        if self.session_ttl <= Duration::ZERO {
            return Err(UnsealError::InvalidConfig("session_ttl must be positive"));
        }
        Ok(())
    }
}

/// Session metadata safe to return to callers.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub id: SessionId,
    pub nonce: [u8; 32],
    pub session_public_key: [u8; 32],
    pub threshold: u8,
    pub shares_collected: u32,
    pub state: SessionState,
    pub expires_at: OffsetDateTime,
}

/// Result of submitting a share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsealOutcome {
    Collected {
        shares_collected: u32,
        threshold: u8,
    },
    Unsealed,
}

/// Unseal errors.
#[derive(Debug, Error)]
pub enum UnsealError {
    #[error("invalid unseal configuration: {0}")]
    InvalidConfig(&'static str),

    #[error("service is already unsealed")]
    AlreadyUnsealed,

    #[error("service is sealed")]
    Sealed,

    #[error("unseal session not found")]
    SessionNotFound,

    #[error("unseal session expired")]
    SessionExpired,

    #[error("unseal session is no longer collecting")]
    SessionClosed,

    #[error("share holder is not registered: {0}")]
    UnknownHolder(String),

    #[error("duplicate share holder: {0}")]
    DuplicateHolder(String),

    #[error("duplicate share index: {0}")]
    DuplicateIndex(u8),

    #[error("share index does not match the holder registration")]
    IndexMismatch,

    #[error("session nonce does not match")]
    InvalidNonce,

    #[error("share holder signature is invalid")]
    InvalidSignature,

    #[error("invalid share: {0}")]
    InvalidShare(String),

    #[error("share failed VSS verification: {0}")]
    VssRejected(String),

    #[error("failed to recover the KEK: {0}")]
    RecoveryFailed(String),

    #[error("recovered KEK failed verification")]
    InvalidKek,

    #[error("internal unseal error: {0}")]
    Internal(String),
}

struct VerifiedShare {
    index: u8,
    data: Zeroizing<Vec<u8>>,
}

struct Session {
    id: SessionId,
    nonce: [u8; 32],
    session_keypair: HolderKeypair,
    session_public_key: [u8; 32],
    threshold: u8,
    shares: HashMap<String, VerifiedShare>,
    shares_collected: u32,
    state: SessionState,
    expires_at: OffsetDateTime,
}

impl Session {
    fn info(&self) -> SessionInfo {
        SessionInfo {
            id: self.id,
            nonce: self.nonce,
            session_public_key: self.session_public_key,
            threshold: self.threshold,
            shares_collected: self.shares_collected,
            state: self.state,
            expires_at: self.expires_at,
        }
    }
}

enum Phase {
    Sealed,
    Unsealed { kek: Zeroizing<[u8; KEK_LEN]> },
}

struct Inner {
    phase: Phase,
    sessions: HashMap<SessionId, Session>,
    check: KekCheck,
    vss: VssCommitments,
    holders: HashMap<String, HolderRegistration>,
}

/// Result of bootstrapping a ceremony: sealed manager, plaintext shares, and commitments.
pub type BootstrapResult = (UnsealManager, signer_vss::VssShares, VssCommitments);

/// Coordinates unseal sessions and holds the KEK while unsealed.
pub struct UnsealManager {
    config: UnsealConfig,
    inner: Mutex<Inner>,
}

impl UnsealManager {
    /// Generate a fresh KEK, split it with VSS, and return a sealed manager.
    ///
    /// The plaintext shares are returned once and must be distributed to the
    /// share holders; the manager keeps no copy of them.
    pub fn bootstrap(
        config: UnsealConfig,
        holders: Vec<HolderIndex>,
    ) -> Result<BootstrapResult, UnsealError> {
        config.validate()?;
        let holder_map = validate_holders(config.total_shares, &holders)?;

        let secret = signer_vss::generate_secret().map_err(|error| {
            UnsealError::Internal(format!("VSS secret generation failed: {error}"))
        })?;
        let (shares, commitments) =
            signer_vss::split_secret(&secret, config.threshold, config.total_shares)
                .map_err(|error| UnsealError::Internal(format!("VSS split failed: {error}")))?;
        let check = make_check(&secret)?;

        let manager = Self {
            config,
            inner: Mutex::new(Inner {
                phase: Phase::Sealed,
                sessions: HashMap::new(),
                check,
                vss: commitments.clone(),
                holders: holder_map,
            }),
        };

        Ok((manager, shares, commitments))
    }

    /// Build a sealed manager from a persisted KEK check and VSS setup.
    pub fn from_check(
        config: UnsealConfig,
        check: KekCheck,
        vss: VssCommitments,
        holders: Vec<HolderIndex>,
    ) -> Result<Self, UnsealError> {
        config.validate()?;
        let holder_map = validate_holders(config.total_shares, &holders)?;
        if vss.len() != config.threshold as usize {
            return Err(UnsealError::InvalidConfig(
                "VSS commitment count does not match threshold",
            ));
        }
        vss.decode()
            .map_err(|_| UnsealError::InvalidConfig("invalid VSS commitments"))?;

        Ok(Self {
            config,
            inner: Mutex::new(Inner {
                phase: Phase::Sealed,
                sessions: HashMap::new(),
                check,
                vss,
                holders: holder_map,
            }),
        })
    }

    /// Start a new unseal session.
    pub fn start_session(&self) -> Result<SessionInfo, UnsealError> {
        let mut inner = self.lock();
        if matches!(&inner.phase, Phase::Unsealed { .. }) {
            return Err(UnsealError::AlreadyUnsealed);
        }

        let session_keypair = HolderKeypair::generate();
        let session_public_key = *session_keypair.public_bytes();
        let session = Session {
            id: Uuid::new_v4(),
            nonce: random_array::<32>(),
            session_keypair,
            session_public_key,
            threshold: self.config.threshold,
            shares: HashMap::new(),
            shares_collected: 0,
            state: SessionState::Collecting,
            expires_at: OffsetDateTime::now_utc() + self.config.session_ttl,
        };
        let info = session.info();
        inner.sessions.insert(session.id, session);
        Ok(info)
    }

    /// Submit one encrypted, signed share for a session.
    ///
    /// The submission must be bound to the session nonce, signed by the
    /// registered holder Ed25519 key, and encrypted to the session X25519 key.
    pub fn submit_share(
        &self,
        session_id: SessionId,
        submission: ShareSubmission<'_>,
    ) -> Result<UnsealOutcome, UnsealError> {
        if submission.holder_id.is_empty() {
            return Err(UnsealError::InvalidShare("holder id is empty".into()));
        }
        if submission.nonce.len() != 32 {
            return Err(UnsealError::InvalidNonce);
        }
        if submission.signature.len() != 64 {
            return Err(UnsealError::InvalidSignature);
        }
        let requested_index = submission
            .share_index
            .ok_or_else(|| UnsealError::InvalidShare("share_index is required".into()))?;
        if requested_index == 0 {
            return Err(UnsealError::InvalidShare("share index is zero".into()));
        }

        let mut inner = self.lock();
        if matches!(&inner.phase, Phase::Unsealed { .. }) {
            return Err(UnsealError::AlreadyUnsealed);
        }

        let registration = inner
            .holders
            .get(submission.holder_id)
            .cloned()
            .ok_or_else(|| UnsealError::UnknownHolder(submission.holder_id.to_string()))?;
        if requested_index != registration.index {
            return Err(UnsealError::IndexMismatch);
        }

        let vss = inner.vss.clone();
        let check = inner.check.clone();
        let kek = {
            let session = inner
                .sessions
                .get_mut(&session_id)
                .ok_or(UnsealError::SessionNotFound)?;

            if session.state != SessionState::Collecting {
                return Err(UnsealError::SessionClosed);
            }
            if OffsetDateTime::now_utc() >= session.expires_at {
                session.state = SessionState::Expired;
                session.shares.clear();
                return Err(UnsealError::SessionExpired);
            }
            if submission.nonce != session.nonce {
                return Err(UnsealError::InvalidNonce);
            }

            if session.shares.contains_key(submission.holder_id) {
                return Err(UnsealError::DuplicateHolder(
                    submission.holder_id.to_string(),
                ));
            }
            if session
                .shares
                .values()
                .any(|share| share.index == requested_index)
            {
                return Err(UnsealError::DuplicateIndex(requested_index));
            }

            let context = signer_share::submission_context(
                &session.id.to_string(),
                &session.nonce,
                &session.session_public_key,
                submission.holder_id,
                requested_index,
            )
            .map_err(|_| UnsealError::Internal("failed to build submission context".into()))?;

            let signing_input =
                signer_share::submission_signing_input(&context, submission.ciphertext);
            let signature = Signature::from_slice(submission.signature)
                .map_err(|_| UnsealError::InvalidSignature)?;
            registration
                .verifying_key
                .verify_strict(&signing_input, &signature)
                .map_err(|_| UnsealError::InvalidSignature)?;

            let session_secret = Zeroizing::new(*session.session_keypair.secret_bytes());
            let plaintext = signer_share::decrypt_share_with_context(
                &session_secret,
                submission.ciphertext,
                &context,
            )
            .map_err(|_| UnsealError::InvalidShare("failed to decrypt share".into()))?;

            if plaintext.len() != signer_vss::SHARE_LEN {
                return Err(UnsealError::InvalidShare(
                    "decrypted share must be exactly 33 bytes".into(),
                ));
            }
            if plaintext[0] != requested_index {
                return Err(UnsealError::IndexMismatch);
            }
            signer_vss::verify_share(&vss, &plaintext)
                .map_err(|error| UnsealError::VssRejected(error.to_string()))?;

            session.shares.insert(
                submission.holder_id.to_string(),
                VerifiedShare {
                    index: requested_index,
                    data: plaintext,
                },
            );
            session.shares_collected = session.shares.len() as u32;

            if session.shares.len() < session.threshold as usize {
                return Ok(UnsealOutcome::Collected {
                    shares_collected: session.shares_collected,
                    threshold: session.threshold,
                });
            }

            let mut raw_shares: Vec<Vec<u8>> = session
                .shares
                .values()
                .map(|share| share.data.to_vec())
                .collect();
            let recovered = signer_vss::recover_secret(&vss, &raw_shares);
            for raw in &mut raw_shares {
                raw.zeroize();
            }

            let recovered = match recovered {
                Ok(value) => value,
                Err(error) => {
                    session.state = SessionState::Failed;
                    session.shares.clear();
                    return Err(UnsealError::VssRejected(error.to_string()));
                }
            };

            if !verify_check(&recovered, &check) {
                session.state = SessionState::Failed;
                session.shares.clear();
                return Err(UnsealError::InvalidKek);
            }

            session.state = SessionState::Unsealed;
            session.shares.clear();
            recovered
        };

        inner.phase = Phase::Unsealed { kek };
        Ok(UnsealOutcome::Unsealed)
    }

    /// Return the status of a session, expiring it if needed.
    pub fn status(&self, session_id: SessionId) -> Result<SessionInfo, UnsealError> {
        let mut inner = self.lock();
        let session = inner
            .sessions
            .get_mut(&session_id)
            .ok_or(UnsealError::SessionNotFound)?;

        if session.state == SessionState::Collecting
            && OffsetDateTime::now_utc() >= session.expires_at
        {
            session.state = SessionState::Expired;
            session.shares.clear();
        }

        Ok(session.info())
    }

    /// Whether the service currently holds an unsealed KEK.
    pub fn is_unsealed(&self) -> bool {
        let inner = self.lock();
        matches!(&inner.phase, Phase::Unsealed { .. })
    }

    /// Run a closure with the unsealed KEK. The KEK never leaves the closure.
    pub fn with_kek<T>(&self, f: impl FnOnce(&[u8; KEK_LEN]) -> T) -> Result<T, UnsealError> {
        let inner = self.lock();
        match &inner.phase {
            Phase::Unsealed { kek } => Ok(f(kek)),
            Phase::Sealed => Err(UnsealError::Sealed),
        }
    }

    /// Return a copy of the KEK check for persistence.
    pub fn check(&self) -> KekCheck {
        self.lock().check.clone()
    }

    /// Wipe the KEK and all session shares, returning to the sealed state.
    pub fn seal(&self) {
        let mut inner = self.lock();
        inner.phase = Phase::Sealed;
        inner.sessions.clear();
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn validate_holders(
    total_shares: u8,
    holders: &[HolderIndex],
) -> Result<HashMap<String, HolderRegistration>, UnsealError> {
    if holders.len() != total_shares as usize {
        return Err(UnsealError::InvalidConfig(
            "holder registry size does not match total_shares",
        ));
    }

    let mut ids = HashSet::new();
    let mut indices = HashSet::new();
    let mut map = HashMap::with_capacity(holders.len());

    for holder in holders {
        if holder.id.is_empty() {
            return Err(UnsealError::InvalidConfig("holder id is empty"));
        }
        if holder.index == 0 || holder.index > total_shares {
            return Err(UnsealError::InvalidConfig("holder index is out of range"));
        }
        if !ids.insert(holder.id.clone()) || !indices.insert(holder.index) {
            return Err(UnsealError::InvalidConfig(
                "duplicate holder id or index in registry",
            ));
        }

        let key_bytes: [u8; 32] = hex::decode(holder.ed25519_public.trim())
            .map_err(|_| UnsealError::InvalidConfig("invalid holder Ed25519 public key"))?
            .try_into()
            .map_err(|_| {
                UnsealError::InvalidConfig("holder Ed25519 public key must be 32 bytes")
            })?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|_| UnsealError::InvalidConfig("invalid holder Ed25519 public key"))?;

        map.insert(
            holder.id.clone(),
            HolderRegistration {
                index: holder.index,
                verifying_key,
            },
        );
    }

    Ok(map)
}

fn random_array<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes);
    bytes
}

fn make_check(kek: &[u8; KEK_LEN]) -> Result<KekCheck, UnsealError> {
    let cipher = XChaCha20Poly1305::new_from_slice(kek)
        .map_err(|_| UnsealError::Internal("invalid KEK length".into()))?;
    let nonce = random_array::<CHECK_NONCE_LEN>();
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: CHECK_PLAINTEXT,
                aad: CHECK_AAD,
            },
        )
        .map_err(|_| UnsealError::Internal("failed to encrypt the KEK check".into()))?;

    Ok(KekCheck { nonce, ciphertext })
}

fn verify_check(kek: &[u8; KEK_LEN], check: &KekCheck) -> bool {
    let Ok(cipher) = XChaCha20Poly1305::new_from_slice(kek) else {
        return false;
    };
    let Ok(plaintext) = cipher.decrypt(
        XNonce::from_slice(&check.nonce),
        Payload {
            msg: &check.ciphertext,
            aad: CHECK_AAD,
        },
    ) else {
        return false;
    };

    plaintext.as_slice() == CHECK_PLAINTEXT
}

mod hex_bytes {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum HexOrBytes {
        Hex(String),
        Bytes(Vec<u8>),
    }

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match HexOrBytes::deserialize(deserializer)? {
            HexOrBytes::Hex(value) => hex::decode(value).map_err(D::Error::custom),
            HexOrBytes::Bytes(value) => Ok(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;
    use signer_share::{
        HolderKeypair, decrypt_share, encrypt_share, encrypt_share_with_context,
        submission_context, submission_signing_input,
    };

    struct TestHolder {
        id: String,
        index: u8,
        signing_key: ed25519_dalek::SigningKey,
    }

    impl TestHolder {
        fn new(index: u8) -> Self {
            let seed = random_array::<32>();
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            Self {
                id: format!("holder-{index}"),
                index,
                signing_key,
            }
        }

        fn holder_index(&self) -> HolderIndex {
            HolderIndex {
                id: self.id.clone(),
                index: self.index,
                ed25519_public: hex::encode(self.signing_key.verifying_key().to_bytes()),
            }
        }
    }

    struct TestManager {
        manager: UnsealManager,
        shares: Vec<Zeroizing<Vec<u8>>>,
        commitments: VssCommitments,
        holders: Vec<HolderIndex>,
        signers: Vec<TestHolder>,
    }

    fn test_holders(total: u8) -> Vec<TestHolder> {
        (1..=total).map(TestHolder::new).collect()
    }

    fn manager_for(threshold: u8, total: u8) -> TestManager {
        let signers = test_holders(total);
        let holders: Vec<HolderIndex> = signers.iter().map(TestHolder::holder_index).collect();
        let (manager, shares, commitments) =
            UnsealManager::bootstrap(UnsealConfig::new(threshold, total), holders.clone()).unwrap();
        TestManager {
            manager,
            shares,
            commitments,
            holders,
            signers,
        }
    }

    fn manager() -> TestManager {
        manager_for(2, 3)
    }

    fn encrypted_submission(
        holder: &TestHolder,
        session: &SessionInfo,
        share: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let context = submission_context(
            &session.id.to_string(),
            &session.nonce,
            &session.session_public_key,
            &holder.id,
            holder.index,
        )
        .unwrap();
        let ciphertext =
            encrypt_share_with_context(&session.session_public_key, share, &context).unwrap();
        let signing_input = submission_signing_input(&context, &ciphertext);
        let signature = holder.signing_key.sign(&signing_input).to_bytes().to_vec();
        (ciphertext, signature)
    }

    fn submit(
        manager: &UnsealManager,
        session: &SessionInfo,
        holder: &TestHolder,
        share: &[u8],
    ) -> Result<UnsealOutcome, UnsealError> {
        let (ciphertext, signature) = encrypted_submission(holder, session, share);
        manager.submit_share(
            session.id,
            ShareSubmission {
                holder_id: &holder.id,
                share_index: Some(holder.index),
                nonce: &session.nonce,
                ciphertext: &ciphertext,
                signature: &signature,
            },
        )
    }

    #[test]
    fn kek_check_file_roundtrip() {
        let fixture = manager();
        let check = fixture.manager.check();
        let file = KekCheckFile::from_check(
            &check,
            2,
            3,
            fixture.commitments.clone(),
            fixture.holders.clone(),
        );
        let encoded = serde_json::to_vec(&file).unwrap();
        let decoded: KekCheckFile = serde_json::from_slice(&encoded).unwrap();
        let (decoded_check, threshold, total_shares, decoded_vss, decoded_holders) =
            decoded.into_parts().unwrap();

        assert_eq!(threshold, 2);
        assert_eq!(total_shares, 3);
        assert_eq!(decoded_check.ciphertext(), check.ciphertext());
        assert_eq!(decoded_vss, fixture.commitments);
        assert_eq!(decoded_holders, fixture.holders);
        assert!(
            decoded_holders
                .iter()
                .all(|holder| !holder.ed25519_public.is_empty())
        );
    }

    #[test]
    fn old_kek_check_version_is_rejected() {
        let fixture = manager();
        let mut file = KekCheckFile::from_check(
            &fixture.manager.check(),
            2,
            3,
            fixture.commitments.clone(),
            fixture.holders.clone(),
        );
        file.version = 1;
        assert!(matches!(
            file.into_parts(),
            Err(UnsealError::InvalidConfig(_))
        ));

        let v1 = r#"{
            "nonce": "000000000000000000000000000000000000000000000000",
            "ciphertext": "0000000000000000000000000000000000000000000000000000000000000000000000",
            "threshold": 2,
            "total_shares": 3
        }"#;
        let file: KekCheckFile = serde_json::from_str(v1).unwrap();
        assert!(matches!(
            file.into_parts(),
            Err(UnsealError::InvalidConfig(_))
        ));
    }

    #[test]
    fn encrypted_share_envelopes_unseal() {
        let fixture = manager();
        let session = fixture.manager.start_session().unwrap();
        let recipient_keys: Vec<HolderKeypair> = fixture
            .shares
            .iter()
            .map(|_| HolderKeypair::generate())
            .collect();

        let envelopes: Vec<Vec<u8>> = fixture
            .shares
            .iter()
            .zip(&recipient_keys)
            .map(|(share, holder)| encrypt_share(holder.public_bytes(), &share[..]).unwrap())
            .collect();

        for index in 0..2 {
            let share =
                decrypt_share(recipient_keys[index].secret_bytes(), &envelopes[index]).unwrap();
            submit(
                &fixture.manager,
                &session,
                &fixture.signers[index],
                &share[..],
            )
            .unwrap();
        }

        assert!(fixture.manager.is_unsealed());
    }

    #[test]
    fn bootstrap_generates_the_requested_shares() {
        let fixture = manager();
        assert_eq!(fixture.shares.len(), 3);
        assert_eq!(fixture.commitments.len(), 2);
        assert_eq!(fixture.holders.len(), 3);
        assert!(fixture.shares.iter().all(|share| share.len() == 33));
        assert!(!fixture.manager.is_unsealed());
    }

    #[test]
    fn rejects_invalid_configuration() {
        let signers = test_holders(3);
        let holders: Vec<HolderIndex> = signers.iter().map(TestHolder::holder_index).collect();

        assert!(matches!(
            UnsealManager::bootstrap(UnsealConfig::new(0, 3), holders.clone()),
            Err(UnsealError::InvalidConfig(_))
        ));
        assert!(matches!(
            UnsealManager::bootstrap(UnsealConfig::new(4, 3), holders.clone()),
            Err(UnsealError::InvalidConfig(_))
        ));

        let mut config = UnsealConfig::new(2, 3);
        config.session_ttl = Duration::ZERO;
        assert!(matches!(
            UnsealManager::bootstrap(config, holders),
            Err(UnsealError::InvalidConfig(_))
        ));
    }

    #[test]
    fn unseals_at_threshold_and_seals_again() {
        let fixture = manager();
        let session = fixture.manager.start_session().unwrap();
        assert_eq!(session.threshold, 2);
        assert_eq!(session.nonce.len(), 32);
        assert_eq!(session.session_public_key.len(), 32);

        let outcome = submit(
            &fixture.manager,
            &session,
            &fixture.signers[0],
            &fixture.shares[0][..],
        )
        .unwrap();
        assert_eq!(
            outcome,
            UnsealOutcome::Collected {
                shares_collected: 1,
                threshold: 2,
            }
        );
        assert_eq!(
            fixture.manager.status(session.id).unwrap().state,
            SessionState::Collecting
        );

        let outcome = submit(
            &fixture.manager,
            &session,
            &fixture.signers[1],
            &fixture.shares[1][..],
        )
        .unwrap();
        assert_eq!(outcome, UnsealOutcome::Unsealed);
        assert!(fixture.manager.is_unsealed());
        assert_eq!(fixture.manager.with_kek(|kek| kek.len()).unwrap(), KEK_LEN);

        fixture.manager.seal();
        assert!(!fixture.manager.is_unsealed());
        assert!(matches!(
            fixture.manager.with_kek(|_| ()),
            Err(UnsealError::Sealed)
        ));
    }

    #[test]
    fn rejects_duplicate_holders() {
        let fixture = manager();
        let session = fixture.manager.start_session().unwrap();

        submit(
            &fixture.manager,
            &session,
            &fixture.signers[0],
            &fixture.shares[0][..],
        )
        .unwrap();
        let err = submit(
            &fixture.manager,
            &session,
            &fixture.signers[0],
            &fixture.shares[0][..],
        )
        .unwrap_err();

        assert!(matches!(err, UnsealError::DuplicateHolder(_)));
        assert_eq!(
            fixture.manager.status(session.id).unwrap().shares_collected,
            1
        );
    }

    #[test]
    fn rejects_wrong_shares_and_stays_collecting() {
        let subject = manager();
        let other = manager();
        let session = subject.manager.start_session().unwrap();

        let err = submit(
            &subject.manager,
            &session,
            &subject.signers[0],
            &other.shares[0][..],
        )
        .unwrap_err();
        assert!(matches!(err, UnsealError::VssRejected(_)));
        assert!(!subject.manager.is_unsealed());
        let status = subject.manager.status(session.id).unwrap();
        assert_eq!(status.state, SessionState::Collecting);
        assert_eq!(status.shares_collected, 0);
    }

    #[test]
    fn rejects_unknown_holder_and_session() {
        let fixture = manager();
        let session = fixture.manager.start_session().unwrap();
        let outsider = TestHolder::new(4);
        let err = submit(
            &fixture.manager,
            &session,
            &outsider,
            &fixture.shares[0][..],
        )
        .unwrap_err();
        assert!(matches!(err, UnsealError::UnknownHolder(_)));

        let other = manager();
        let foreign_session = other.manager.start_session().unwrap();
        let err = submit(
            &fixture.manager,
            &foreign_session,
            &fixture.signers[0],
            &fixture.shares[0][..],
        )
        .unwrap_err();
        assert!(matches!(err, UnsealError::SessionNotFound));
    }

    #[test]
    fn rejects_invalid_nonce_and_signature() {
        let fixture = manager();
        let session = fixture.manager.start_session().unwrap();
        let (ciphertext, signature) =
            encrypted_submission(&fixture.signers[0], &session, &fixture.shares[0][..]);

        let err = fixture
            .manager
            .submit_share(
                session.id,
                ShareSubmission {
                    holder_id: &fixture.signers[0].id,
                    share_index: Some(1),
                    nonce: &[0u8; 32],
                    ciphertext: &ciphertext,
                    signature: &signature,
                },
            )
            .unwrap_err();
        assert!(matches!(err, UnsealError::InvalidNonce));

        let mut bad_signature = signature.clone();
        bad_signature[0] ^= 1;
        let err = fixture
            .manager
            .submit_share(
                session.id,
                ShareSubmission {
                    holder_id: &fixture.signers[0].id,
                    share_index: Some(1),
                    nonce: &session.nonce,
                    ciphertext: &ciphertext,
                    signature: &bad_signature,
                },
            )
            .unwrap_err();
        assert!(matches!(err, UnsealError::InvalidSignature));
    }

    #[test]
    fn rejects_index_mismatch() {
        let fixture = manager();
        let session = fixture.manager.start_session().unwrap();
        let (ciphertext, signature) =
            encrypted_submission(&fixture.signers[0], &session, &fixture.shares[1][..]);

        let err = fixture
            .manager
            .submit_share(
                session.id,
                ShareSubmission {
                    holder_id: &fixture.signers[0].id,
                    share_index: Some(1),
                    nonce: &session.nonce,
                    ciphertext: &ciphertext,
                    signature: &signature,
                },
            )
            .unwrap_err();
        assert!(matches!(err, UnsealError::IndexMismatch));

        let err = fixture
            .manager
            .submit_share(
                session.id,
                ShareSubmission {
                    holder_id: &fixture.signers[0].id,
                    share_index: Some(2),
                    nonce: &session.nonce,
                    ciphertext: &ciphertext,
                    signature: &signature,
                },
            )
            .unwrap_err();
        assert!(matches!(err, UnsealError::IndexMismatch));
    }

    #[test]
    fn rejects_invalid_decrypted_share_length() {
        let fixture = manager();
        let session = fixture.manager.start_session().unwrap();
        let (ciphertext, signature) = encrypted_submission(&fixture.signers[0], &session, &[1u8]);

        let err = fixture
            .manager
            .submit_share(
                session.id,
                ShareSubmission {
                    holder_id: &fixture.signers[0].id,
                    share_index: Some(1),
                    nonce: &session.nonce,
                    ciphertext: &ciphertext,
                    signature: &signature,
                },
            )
            .unwrap_err();
        assert!(matches!(err, UnsealError::InvalidShare(_)));
    }

    #[test]
    fn cannot_start_another_session_once_unsealed() {
        let fixture = manager();
        let session = fixture.manager.start_session().unwrap();
        submit(
            &fixture.manager,
            &session,
            &fixture.signers[0],
            &fixture.shares[0][..],
        )
        .unwrap();
        submit(
            &fixture.manager,
            &session,
            &fixture.signers[1],
            &fixture.shares[1][..],
        )
        .unwrap();

        assert!(matches!(
            fixture.manager.start_session(),
            Err(UnsealError::AlreadyUnsealed)
        ));
    }
}
