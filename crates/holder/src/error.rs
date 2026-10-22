//! Error types for holder-side identity and share storage.

use thiserror::Error;

/// Errors returned by holder identity, vault, and manifest operations.
///
/// Error messages never contain key material, passphrases, or share bytes.
#[derive(Debug, Error)]
pub enum HolderError {
    #[error("invalid holder id")]
    InvalidHolderId,

    #[error("invalid ceremony id")]
    InvalidCeremonyId,

    #[error("passphrase must not be empty")]
    EmptyPassphrase,

    #[error("invalid identity file")]
    InvalidIdentity,

    #[error("invalid share vault")]
    InvalidVault,

    #[error("invalid passphrase or corrupted file")]
    InvalidPassphraseOrCorrupt,

    #[error("invalid public bundle")]
    InvalidPublicBundle,

    #[error("invalid manifest")]
    InvalidManifest,

    #[error("manifest signature verification failed")]
    InvalidManifestSignature,

    #[error("operator public key fingerprint mismatch")]
    OperatorFingerprintMismatch,

    #[error("holder entry is missing from the manifest")]
    HolderNotInManifest,

    #[error("holder entry does not match the identity")]
    HolderMismatch,

    #[error("share envelope hash mismatch")]
    EnvelopeHashMismatch,

    #[error("invalid share")]
    InvalidShare,

    #[error("share index does not match")]
    IndexMismatch,

    #[error("share failed VSS verification")]
    VssRejected,

    #[error("invalid KDF parameters")]
    InvalidKdfParams,

    #[error("file already exists")]
    AlreadyExists,

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("share envelope error: {0}")]
    Share(#[from] signer_share::ShareError),

    #[error("cryptographic operation failed")]
    Crypto,
}
