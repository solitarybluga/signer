//! Quorum unsealing: Shamir shares, unseal sessions, and KEK recovery.
//!
//! v0.1 keeps the unsealed KEK in process memory. Share transport encryption,
//! holder authentication, and VSS commitments are handled by the API layer in a
//! later iteration.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sharks::{Share, Sharks};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::Zeroizing;

const KEK_LEN: usize = 32;
const CHECK_NONCE_LEN: usize = 24;
const CHECK_PLAINTEXT: &[u8] = b"signer-kek-check-v1";
const CHECK_AAD: &[u8] = b"signer.kek.check.v1";

/// Unseal session identifier.
pub type SessionId = Uuid;

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

/// Persisted KEK check and the quorum parameters it was created with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KekCheckFile {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub threshold: u8,
    pub total_shares: u8,
}

impl KekCheckFile {
    pub fn from_check(check: &KekCheck, threshold: u8, total_shares: u8) -> Self {
        Self {
            nonce: check.nonce.to_vec(),
            ciphertext: check.ciphertext.clone(),
            threshold,
            total_shares,
        }
    }

    pub fn into_parts(self) -> Result<(KekCheck, u8, u8), UnsealError> {
        let nonce: [u8; CHECK_NONCE_LEN] = self
            .nonce
            .try_into()
            .map_err(|_| UnsealError::InvalidConfig("invalid KEK check nonce length"))?;
        let check = KekCheck::from_parts(nonce, self.ciphertext)?;
        Ok((check, self.threshold, self.total_shares))
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

    #[error("duplicate share holder: {0}")]
    DuplicateHolder(String),

    #[error("invalid share: {0}")]
    InvalidShare(String),

    #[error("failed to recover the KEK: {0}")]
    RecoveryFailed(String),

    #[error("recovered KEK failed verification")]
    InvalidKek,

    #[error("internal unseal error: {0}")]
    Internal(String),
}

struct Session {
    id: SessionId,
    nonce: [u8; 32],
    threshold: u8,
    shares: HashMap<String, Share>,
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
}

/// Coordinates unseal sessions and holds the KEK while unsealed.
pub struct UnsealManager {
    config: UnsealConfig,
    inner: Mutex<Inner>,
}

impl UnsealManager {
    /// Generate a fresh KEK, split it into shares, and return a sealed manager.
    ///
    /// The plaintext shares are returned once and must be distributed to the
    /// share holders; the manager keeps no copy of them.
    pub fn bootstrap(config: UnsealConfig) -> Result<(Self, Vec<Vec<u8>>), UnsealError> {
        config.validate()?;

        let kek = Zeroizing::new(random_array::<KEK_LEN>());
        let check = make_check(&kek)?;

        let dealer = Sharks(config.threshold).dealer(&kek[..]);
        let shares: Vec<Vec<u8>> = dealer
            .take(config.total_shares as usize)
            .map(|share| Vec::from(&share))
            .collect();

        if shares.len() != config.total_shares as usize {
            return Err(UnsealError::Internal(
                "failed to generate the requested number of shares".into(),
            ));
        }

        let manager = Self {
            config,
            inner: Mutex::new(Inner {
                phase: Phase::Sealed,
                sessions: HashMap::new(),
                check,
            }),
        };

        Ok((manager, shares))
    }

    /// Build a sealed manager from a persisted KEK check.
    pub fn from_check(config: UnsealConfig, check: KekCheck) -> Result<Self, UnsealError> {
        config.validate()?;
        Ok(Self {
            config,
            inner: Mutex::new(Inner {
                phase: Phase::Sealed,
                sessions: HashMap::new(),
                check,
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
    /// API layer; this method assumes the caller already authenticated the holder.
    pub fn submit_share(
        &self,
        session_id: SessionId,
        holder_id: &str,
        share_bytes: &[u8],
    ) -> Result<UnsealOutcome, UnsealError> {
        if holder_id.is_empty() {
            return Err(UnsealError::InvalidShare("holder id is empty".into()));
        }

        let mut inner = self.lock();
        if matches!(&inner.phase, Phase::Unsealed { .. }) {
            return Err(UnsealError::AlreadyUnsealed);
        }

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

            let share = Share::try_from(share_bytes)
                .map_err(|e| UnsealError::InvalidShare(e.to_string()))?;

            if session.shares.contains_key(holder_id) {
                return Err(UnsealError::DuplicateHolder(holder_id.to_string()));
            }
            session.shares.insert(holder_id.to_string(), share);
            session.shares_collected = session.shares.len() as u32;

            if session.shares.len() < session.threshold as usize {
                return Ok(UnsealOutcome::Collected {
                    shares_collected: session.shares_collected,
                    threshold: session.threshold,
                });
            }

            let recovered = match Sharks(session.threshold).recover(session.shares.values()) {
                Ok(secret) => Zeroizing::new(secret),
                Err(e) => {
                    session.state = SessionState::Failed;
                    session.shares.clear();
                    return Err(UnsealError::RecoveryFailed(e.to_string()));
                }
            };

            if recovered.len() != KEK_LEN {
                session.state = SessionState::Failed;
                session.shares.clear();
                return Err(UnsealError::InvalidKek);
            }

            let mut kek = Zeroizing::new([0u8; KEK_LEN]);
            kek.copy_from_slice(&recovered[..]);

            if !verify_check(&kek, &check) {
                session.state = SessionState::Failed;
                session.shares.clear();
                return Err(UnsealError::InvalidKek);
            }

            session.state = SessionState::Unsealed;
            session.shares.clear();
            kek
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

#[cfg(test)]
mod tests {
    use super::*;
    use signer_share::{HolderKeypair, decrypt_share, encrypt_share};

    fn manager() -> (UnsealManager, Vec<Vec<u8>>) {
        UnsealManager::bootstrap(UnsealConfig::new(2, 3)).unwrap()
    }

    #[test]
    fn kek_check_file_roundtrip() {
        let (manager, _) = manager();
        let check = manager.check();
        let file = KekCheckFile::from_check(&check, 2, 3);
        let encoded = serde_json::to_vec(&file).unwrap();
        let decoded: KekCheckFile = serde_json::from_slice(&encoded).unwrap();
        let (decoded_check, threshold, total_shares) = decoded.into_parts().unwrap();

        assert_eq!(threshold, 2);
        assert_eq!(total_shares, 3);
        assert_eq!(decoded_check.ciphertext(), check.ciphertext());
    }

    #[test]
    fn encrypted_share_envelopes_unseal() {
        let config = UnsealConfig::new(2, 3);
        let (manager, shares) = UnsealManager::bootstrap(config.clone()).unwrap();
        let check = manager.check();
        let holders: Vec<HolderKeypair> = (0..shares.len())
            .map(|_| HolderKeypair::generate())
            .collect();

        let envelopes: Vec<Vec<u8>> = shares
            .iter()
            .zip(&holders)
            .map(|(share, holder)| encrypt_share(holder.public_bytes(), share).unwrap())
            .collect();

        let manager = UnsealManager::from_check(config, check).unwrap();
        let session = manager.start_session().unwrap();

        for (index, holder) in holders.iter().take(2).enumerate() {
            let share = decrypt_share(holder.secret_bytes(), &envelopes[index]).unwrap();
            manager
                .submit_share(session.id, &format!("holder-{index}"), share.as_slice())
                .unwrap();
        }

        assert!(manager.is_unsealed());
    }

    #[test]
    fn bootstrap_generates_the_requested_shares() {
        let (manager, shares) = manager();
        assert_eq!(shares.len(), 3);
        assert!(shares.iter().all(|share| share.len() == KEK_LEN + 1));
        assert!(!manager.is_unsealed());
    }

    #[test]
    fn rejects_invalid_configuration() {
        assert!(matches!(
            UnsealManager::bootstrap(UnsealConfig::new(0, 3)),
            Err(UnsealError::InvalidConfig(_))
        ));
        assert!(matches!(
            UnsealManager::bootstrap(UnsealConfig::new(4, 3)),
            Err(UnsealError::InvalidConfig(_))
        ));

        let mut config = UnsealConfig::new(2, 3);
        config.session_ttl = Duration::ZERO;
        assert!(matches!(
            UnsealManager::bootstrap(config),
            Err(UnsealError::InvalidConfig(_))
        ));
    }

    #[test]
    fn unseals_at_threshold_and_seals_again() {
        let (manager, shares) = manager();
        let session = manager.start_session().unwrap();
        assert_eq!(session.threshold, 2);
        assert_eq!(session.nonce.len(), 32);

        let outcome = manager
            .submit_share(session.id, "holder-1", &shares[0])
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
            .submit_share(session.id, "holder-2", &shares[1])
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
        let (manager, shares) = manager();
        let session = manager.start_session().unwrap();

        manager
            .submit_share(session.id, "holder-1", &shares[0])
            .unwrap();
        let err = manager
            .submit_share(session.id, "holder-1", &shares[1])
            .unwrap_err();

        assert!(matches!(err, UnsealError::DuplicateHolder(_)));
        assert_eq!(manager.status(session.id).unwrap().shares_collected, 1);
    }

    #[test]
    fn rejects_wrong_shares_and_stays_sealed() {
        let (subject, _) = manager();
        let (_, other_shares) = manager();
        let session = subject.start_session().unwrap();

        subject
            .submit_share(session.id, "holder-1", &other_shares[0])
            .unwrap();
        let err = subject
            .submit_share(session.id, "holder-2", &other_shares[1])
            .unwrap_err();

        assert!(matches!(err, UnsealError::InvalidKek));
        assert!(!subject.is_unsealed());
        assert_eq!(
            subject.status(session.id).unwrap().state,
            SessionState::Failed
        );
    }

    #[test]
    fn rejects_invalid_share_bytes_and_unknown_sessions() {
        let (manager, _) = manager();
        let session = manager.start_session().unwrap();

        let err = manager
            .submit_share(session.id, "holder-1", &[0u8; 1])
            .unwrap_err();
        assert!(matches!(err, UnsealError::InvalidShare(_)));

        let err = manager
            .submit_share(Uuid::new_v4(), "holder-1", &[0u8; 33])
            .unwrap_err();
        assert!(matches!(err, UnsealError::SessionNotFound));
    }

    #[test]
    fn cannot_start_another_session_once_unsealed() {
        let (manager, shares) = manager();
        let session = manager.start_session().unwrap();
        manager
            .submit_share(session.id, "holder-1", &shares[0])
            .unwrap();
        manager
            .submit_share(session.id, "holder-2", &shares[1])
            .unwrap();

        assert!(matches!(
            manager.start_session(),
            Err(UnsealError::AlreadyUnsealed)
        ));
    }
}
