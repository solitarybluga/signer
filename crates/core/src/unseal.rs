//! Quorum unsealing with Ristretto255 Feldman VSS.
//!
//! v0.1 keeps the unsealed KEK in process memory. Share transport encryption,
//! holder authentication, and holder signatures are handled by the API layer in
//! a later iteration.

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
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
const KEK_CHECK_VERSION: u8 = 2;

/// Unseal session identifier.
pub type SessionId = Uuid;

/// Holder registration entry used for share-index binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HolderIndex {
    pub id: String,
    pub index: u8,
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
    holders: HashMap<String, u8>,
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

        let session = Session {
            id: Uuid::new_v4(),
            nonce: random_array::<32>(),
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

    /// Submit one share for a session.
    ///
    /// Share transport encryption and holder authentication are enforced by the
    /// API layer; this method verifies the holder registration and VSS
    /// consistency before counting the share.
    pub fn submit_share(
        &self,
        session_id: SessionId,
        holder_id: &str,
        share_index: Option<u8>,
        share_bytes: &[u8],
    ) -> Result<UnsealOutcome, UnsealError> {
        if holder_id.is_empty() {
            return Err(UnsealError::InvalidShare("holder id is empty".into()));
        }
        if share_bytes.len() != signer_vss::SHARE_LEN {
            return Err(UnsealError::InvalidShare(
                "share must be exactly 33 bytes".into(),
            ));
        }

        let embedded_index = share_bytes[0];
        if embedded_index == 0 {
            return Err(UnsealError::InvalidShare("share index is zero".into()));
        }
        if let Some(index) = share_index {
            if index != embedded_index {
                return Err(UnsealError::IndexMismatch);
            }
        }

        let mut inner = self.lock();
        if matches!(&inner.phase, Phase::Unsealed { .. }) {
            return Err(UnsealError::AlreadyUnsealed);
        }

        let registered_index = *inner
            .holders
            .get(holder_id)
            .ok_or_else(|| UnsealError::UnknownHolder(holder_id.to_string()))?;
        if embedded_index != registered_index {
            return Err(UnsealError::IndexMismatch);
        }

        let vss = inner.vss.clone();
        signer_vss::verify_share(&vss, share_bytes)
            .map_err(|error| UnsealError::VssRejected(error.to_string()))?;

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

            if session.shares.contains_key(holder_id) {
                return Err(UnsealError::DuplicateHolder(holder_id.to_string()));
            }
            if session
                .shares
                .values()
                .any(|share| share.index == embedded_index)
            {
                return Err(UnsealError::DuplicateIndex(embedded_index));
            }

            session.shares.insert(
                holder_id.to_string(),
                VerifiedShare {
                    index: embedded_index,
                    data: Zeroizing::new(share_bytes.to_vec()),
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
) -> Result<HashMap<String, u8>, UnsealError> {
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
        map.insert(holder.id.clone(), holder.index);
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
    use signer_share::{HolderKeypair, decrypt_share, encrypt_share};

    fn holders(total: u8) -> Vec<HolderIndex> {
        (1..=total)
            .map(|index| HolderIndex {
                id: format!("holder-{index}"),
                index,
            })
            .collect()
    }

    fn manager() -> (
        UnsealManager,
        Vec<Zeroizing<Vec<u8>>>,
        VssCommitments,
        Vec<HolderIndex>,
    ) {
        let holders = holders(3);
        let (manager, shares, commitments) =
            UnsealManager::bootstrap(UnsealConfig::new(2, 3), holders.clone()).unwrap();
        (manager, shares, commitments, holders)
    }

    #[test]
    fn kek_check_file_roundtrip() {
        let (manager, _, commitments, holders) = manager();
        let check = manager.check();
        let file = KekCheckFile::from_check(&check, 2, 3, commitments.clone(), holders.clone());
        let encoded = serde_json::to_vec(&file).unwrap();
        let decoded: KekCheckFile = serde_json::from_slice(&encoded).unwrap();
        let (decoded_check, threshold, total_shares, decoded_vss, decoded_holders) =
            decoded.into_parts().unwrap();

        assert_eq!(threshold, 2);
        assert_eq!(total_shares, 3);
        assert_eq!(decoded_check.ciphertext(), check.ciphertext());
        assert_eq!(decoded_vss, commitments);
        assert_eq!(decoded_holders, holders);
    }

    #[test]
    fn old_kek_check_version_is_rejected() {
        let (manager, _, commitments, holders) = manager();
        let mut file = KekCheckFile::from_check(&manager.check(), 2, 3, commitments, holders);
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
        let config = UnsealConfig::new(2, 3);
        let holders = holders(3);
        let (manager, shares, commitments) =
            UnsealManager::bootstrap(config.clone(), holders.clone()).unwrap();
        let check = manager.check();
        let recipient_keys: Vec<HolderKeypair> = (0..shares.len())
            .map(|_| HolderKeypair::generate())
            .collect();

        let envelopes: Vec<Vec<u8>> = shares
            .iter()
            .zip(&recipient_keys)
            .map(|(share, holder)| encrypt_share(holder.public_bytes(), share).unwrap())
            .collect();

        let manager = UnsealManager::from_check(config, check, commitments, holders).unwrap();
        let session = manager.start_session().unwrap();

        for (index, holder) in recipient_keys.iter().take(2).enumerate() {
            let share = decrypt_share(holder.secret_bytes(), &envelopes[index]).unwrap();
            manager
                .submit_share(
                    session.id,
                    &format!("holder-{}", index + 1),
                    Some((index + 1) as u8),
                    share.as_slice(),
                )
                .unwrap();
        }

        assert!(manager.is_unsealed());
    }

    #[test]
    fn bootstrap_generates_the_requested_shares() {
        let (manager, shares, commitments, holders) = manager();
        assert_eq!(shares.len(), 3);
        assert_eq!(commitments.len(), 2);
        assert_eq!(holders.len(), 3);
        assert!(shares.iter().all(|share| share.len() == 33));
        assert!(!manager.is_unsealed());
    }

    #[test]
    fn rejects_invalid_configuration() {
        let three = holders(3);
        assert!(matches!(
            UnsealManager::bootstrap(UnsealConfig::new(0, 3), three.clone()),
            Err(UnsealError::InvalidConfig(_))
        ));
        assert!(matches!(
            UnsealManager::bootstrap(UnsealConfig::new(4, 3), three.clone()),
            Err(UnsealError::InvalidConfig(_))
        ));

        let mut config = UnsealConfig::new(2, 3);
        config.session_ttl = Duration::ZERO;
        assert!(matches!(
            UnsealManager::bootstrap(config, three),
            Err(UnsealError::InvalidConfig(_))
        ));
    }

    #[test]
    fn unseals_at_threshold_and_seals_again() {
        let (manager, shares, _, _) = manager();
        let session = manager.start_session().unwrap();
        assert_eq!(session.threshold, 2);
        assert_eq!(session.nonce.len(), 32);

        let outcome = manager
            .submit_share(session.id, "holder-1", None, shares[0].as_slice())
            .unwrap();
        assert_eq!(
            outcome,
            UnsealOutcome::Collected {
                shares_collected: 1,
                threshold: 2,
            }
        );
        assert_eq!(
            manager.status(session.id).unwrap().state,
            SessionState::Collecting
        );

        let outcome = manager
            .submit_share(session.id, "holder-2", None, shares[1].as_slice())
            .unwrap();
        assert_eq!(outcome, UnsealOutcome::Unsealed);
        assert!(manager.is_unsealed());
        assert_eq!(manager.with_kek(|kek| kek.len()).unwrap(), KEK_LEN);

        manager.seal();
        assert!(!manager.is_unsealed());
        assert!(matches!(manager.with_kek(|_| ()), Err(UnsealError::Sealed)));
    }

    #[test]
    fn rejects_duplicate_holders() {
        let (manager, shares, _, _) = manager();
        let session = manager.start_session().unwrap();

        manager
            .submit_share(session.id, "holder-1", None, shares[0].as_slice())
            .unwrap();
        let err = manager
            .submit_share(session.id, "holder-1", None, shares[0].as_slice())
            .unwrap_err();

        assert!(matches!(err, UnsealError::DuplicateHolder(_)));
        assert_eq!(manager.status(session.id).unwrap().shares_collected, 1);
    }

    #[test]
    fn rejects_wrong_shares_and_stays_collecting() {
        let (subject, _, _, _) = manager();
        let (_, other_shares, _, _) = manager();
        let session = subject.start_session().unwrap();

        let err = subject
            .submit_share(session.id, "holder-1", None, other_shares[0].as_slice())
            .unwrap_err();
        assert!(matches!(err, UnsealError::VssRejected(_)));
        assert!(!subject.is_unsealed());
        let status = subject.status(session.id).unwrap();
        assert_eq!(status.state, SessionState::Collecting);
        assert_eq!(status.shares_collected, 0);
    }

    #[test]
    fn rejects_invalid_share_bytes_unknown_sessions_and_unknown_holders() {
        let (manager, shares, _, _) = manager();
        let session = manager.start_session().unwrap();

        let err = manager
            .submit_share(session.id, "holder-1", None, &[0u8; 1])
            .unwrap_err();
        assert!(matches!(err, UnsealError::InvalidShare(_)));

        let err = manager
            .submit_share(Uuid::new_v4(), "holder-1", None, shares[0].as_slice())
            .unwrap_err();
        assert!(matches!(err, UnsealError::SessionNotFound));

        let err = manager
            .submit_share(session.id, "mallory", None, shares[0].as_slice())
            .unwrap_err();
        assert!(matches!(err, UnsealError::UnknownHolder(_)));
    }

    #[test]
    fn rejects_index_mismatch() {
        let (manager, shares, _, _) = manager();
        let session = manager.start_session().unwrap();

        let err = manager
            .submit_share(session.id, "holder-1", None, shares[1].as_slice())
            .unwrap_err();
        assert!(matches!(err, UnsealError::IndexMismatch));

        let err = manager
            .submit_share(session.id, "holder-1", Some(2), shares[0].as_slice())
            .unwrap_err();
        assert!(matches!(err, UnsealError::IndexMismatch));
    }

    #[test]
    fn cannot_start_another_session_once_unsealed() {
        let (manager, shares, _, _) = manager();
        let session = manager.start_session().unwrap();
        manager
            .submit_share(session.id, "holder-1", None, shares[0].as_slice())
            .unwrap();
        manager
            .submit_share(session.id, "holder-2", None, shares[1].as_slice())
            .unwrap();

        assert!(matches!(
            manager.start_session(),
            Err(UnsealError::AlreadyUnsealed)
        ));
    }
}
