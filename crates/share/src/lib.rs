//! Encrypted share envelopes for offline distribution and online submission.
//!
//! A share is encrypted to a recipient's X25519 public key using an ephemeral
//! X25519 exchange, HKDF-SHA256, and XChaCha20-Poly1305. Version 1 is used for
//! offline distribution; version 2 binds a caller-supplied context (session,
//! holder, index) into the AEAD.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const MAGIC: [u8; 4] = *b"SSHR";
const VERSION_V1: u8 = 1;
const VERSION_V2: u8 = 2;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 4 + 1 + 32 + NONCE_LEN;
const TAG_LEN: usize = 16;
const HKDF_INFO_V1: &[u8] = b"signer-share-envelope-v1";
const HKDF_INFO_V2: &[u8] = b"signer-share-envelope-v2";
const ENVELOPE_AAD_V2: &[u8] = b"signer-share-envelope-v2";
const SUBMIT_CONTEXT_DOMAIN: &[u8] = b"signer.unseal.submit.v2";
const SUBMIT_SIGNING_DOMAIN: &[u8] = b"signer.unseal.submit.sig.v2";

/// Errors returned by share envelope operations.
#[derive(Debug, Error)]
pub enum ShareError {
    #[error("share envelope is too short")]
    TooShort,

    #[error("invalid share envelope magic")]
    InvalidMagic,

    #[error("unsupported share envelope version")]
    UnsupportedVersion,

    #[error("invalid submission context")]
    InvalidContext,

    #[error("share key derivation failed")]
    KeyDerivation,

    #[error("share encryption failed")]
    Encrypt,

    #[error("share decryption failed")]
    Decrypt,
}

/// Build the AEAD/signature context for an online unseal submission.
pub fn submission_context(
    session_id: &str,
    nonce: &[u8; 32],
    session_public_key: &[u8; 32],
    holder_id: &str,
    share_index: u8,
) -> Result<Vec<u8>, ShareError> {
    let session_len = u8::try_from(session_id.len()).map_err(|_| ShareError::InvalidContext)?;
    let holder_len = u8::try_from(holder_id.len()).map_err(|_| ShareError::InvalidContext)?;

    let mut context = Vec::with_capacity(
        SUBMIT_CONTEXT_DOMAIN.len() + 1 + session_id.len() + 32 + 32 + 1 + holder_id.len() + 1,
    );
    context.extend_from_slice(SUBMIT_CONTEXT_DOMAIN);
    context.push(session_len);
    context.extend_from_slice(session_id.as_bytes());
    context.extend_from_slice(nonce);
    context.extend_from_slice(session_public_key);
    context.push(holder_len);
    context.extend_from_slice(holder_id.as_bytes());
    context.push(share_index);
    Ok(context)
}

/// Build the Ed25519 signing input for an encrypted share submission.
pub fn submission_signing_input(context: &[u8], share_ciphertext: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(SUBMIT_SIGNING_DOMAIN.len() + 64);
    input.extend_from_slice(SUBMIT_SIGNING_DOMAIN);
    input.extend_from_slice(&Sha256::digest(context));
    input.extend_from_slice(&Sha256::digest(share_ciphertext));
    input
}

/// An X25519 keypair used to protect one holder's share.
pub struct HolderKeypair {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl HolderKeypair {
    /// Generate a fresh keypair from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut secret);
        Self::from_secret_bytes(secret)
    }

    /// Rebuild a keypair from a stored 32-byte secret.
    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        let static_secret = StaticSecret::from(secret);
        let public = PublicKey::from(&static_secret).to_bytes();

        Self {
            secret: Zeroizing::new(secret),
            public,
        }
    }

    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }
}

/// Encrypt a plaintext Shamir share to a holder's public key (offline v1).
pub fn encrypt_share(recipient_public: &[u8; 32], share: &[u8]) -> Result<Vec<u8>, ShareError> {
    let aad = envelope_aad(VERSION_V1);
    encrypt_envelope(recipient_public, share, VERSION_V1, &aad, HKDF_INFO_V1)
}

/// Encrypt a share for an online submission, binding the caller's context.
pub fn encrypt_share_with_context(
    recipient_public: &[u8; 32],
    share: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, ShareError> {
    let aad = envelope_aad_v2(context);
    encrypt_envelope(recipient_public, share, VERSION_V2, &aad, HKDF_INFO_V2)
}

/// Decrypt a v1 share envelope with the holder's 32-byte X25519 secret.
pub fn decrypt_share(
    recipient_secret: &[u8; 32],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ShareError> {
    let aad = envelope_aad(VERSION_V1);
    decrypt_envelope(recipient_secret, envelope, VERSION_V1, &aad, HKDF_INFO_V1)
}

/// Decrypt a v2 share envelope, checking the caller-supplied context.
pub fn decrypt_share_with_context(
    recipient_secret: &[u8; 32],
    envelope: &[u8],
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ShareError> {
    let aad = envelope_aad_v2(context);
    decrypt_envelope(recipient_secret, envelope, VERSION_V2, &aad, HKDF_INFO_V2)
}

fn encrypt_envelope(
    recipient_public: &[u8; 32],
    share: &[u8],
    version: u8,
    aad: &[u8],
    hkdf_info: &[u8],
) -> Result<Vec<u8>, ShareError> {
    let mut ephemeral_bytes = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut ephemeral_bytes);

    let ephemeral_secret = StaticSecret::from(ephemeral_bytes);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let recipient = PublicKey::from(*recipient_public);
    let shared = ephemeral_secret.diffie_hellman(&recipient);

    let key = derive_key(
        shared.as_bytes(),
        ephemeral_public.as_bytes(),
        recipient_public,
        hkdf_info,
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| ShareError::Encrypt)?;

    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: share, aad })
        .map_err(|_| ShareError::Encrypt)?;

    let mut envelope = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    envelope.extend_from_slice(&MAGIC);
    envelope.push(version);
    envelope.extend_from_slice(ephemeral_public.as_bytes());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);

    Ok(envelope)
}

fn decrypt_envelope(
    recipient_secret: &[u8; 32],
    envelope: &[u8],
    expected_version: u8,
    aad: &[u8],
    hkdf_info: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ShareError> {
    if envelope.len() < HEADER_LEN + TAG_LEN {
        return Err(ShareError::TooShort);
    }
    if envelope[..4] != MAGIC {
        return Err(ShareError::InvalidMagic);
    }
    if envelope[4] != expected_version {
        return Err(ShareError::UnsupportedVersion);
    }

    let mut ephemeral_public = [0u8; 32];
    ephemeral_public.copy_from_slice(&envelope[5..37]);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&envelope[37..HEADER_LEN]);

    let static_secret = StaticSecret::from(*recipient_secret);
    let recipient_public = PublicKey::from(&static_secret).to_bytes();
    let shared = static_secret.diffie_hellman(&PublicKey::from(ephemeral_public));

    let key = derive_key(
        shared.as_bytes(),
        &ephemeral_public,
        &recipient_public,
        hkdf_info,
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| ShareError::Decrypt)?;

    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &envelope[HEADER_LEN..],
                aad,
            },
        )
        .map_err(|_| ShareError::Decrypt)?;

    Ok(Zeroizing::new(plaintext))
}

fn derive_key(
    shared: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
    hkdf_info: &[u8],
) -> Result<Zeroizing<[u8; 32]>, ShareError> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral_public);
    salt[32..].copy_from_slice(recipient_public);

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(hkdf_info, &mut key[..])
        .map_err(|_| ShareError::KeyDerivation)?;

    Ok(key)
}

fn envelope_aad(version: u8) -> Vec<u8> {
    let mut aad = Vec::with_capacity(5);
    aad.extend_from_slice(&MAGIC);
    aad.push(version);
    aad
}

fn envelope_aad_v2(context: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ENVELOPE_AAD_V2.len() + context.len());
    aad.extend_from_slice(ENVELOPE_AAD_V2);
    aad.extend_from_slice(context);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_envelope_roundtrip() {
        let holder = HolderKeypair::generate();
        let share = vec![7, 8, 9, 10, 11];

        let envelope = encrypt_share(holder.public_bytes(), &share).unwrap();
        let decrypted = decrypt_share(holder.secret_bytes(), &envelope).unwrap();

        assert_eq!(decrypted.as_slice(), share.as_slice());
    }

    #[test]
    fn wrong_holder_key_is_rejected() {
        let holder = HolderKeypair::generate();
        let other = HolderKeypair::generate();
        let envelope = encrypt_share(holder.public_bytes(), &[1, 2, 3]).unwrap();

        let error = decrypt_share(other.secret_bytes(), &envelope).unwrap_err();
        assert!(matches!(error, ShareError::Decrypt));
    }

    #[test]
    fn tampered_envelope_is_rejected() {
        let holder = HolderKeypair::generate();
        let mut envelope = encrypt_share(holder.public_bytes(), &[1, 2, 3]).unwrap();

        let last = envelope.len() - 1;
        envelope[last] ^= 0x01;

        let error = decrypt_share(holder.secret_bytes(), &envelope).unwrap_err();
        assert!(matches!(error, ShareError::Decrypt));
    }

    #[test]
    fn malformed_envelope_is_rejected() {
        let holder = HolderKeypair::generate();

        assert!(matches!(
            decrypt_share(holder.secret_bytes(), &[0u8; 4]),
            Err(ShareError::TooShort)
        ));

        let mut envelope = vec![0u8; HEADER_LEN + TAG_LEN];
        envelope[..4].copy_from_slice(b"NOPE");
        assert!(matches!(
            decrypt_share(holder.secret_bytes(), &envelope),
            Err(ShareError::InvalidMagic)
        ));
    }

    #[test]
    fn context_envelope_roundtrip_and_context_mismatch() {
        let holder = HolderKeypair::generate();
        let share = vec![1, 2, 3, 4];
        let nonce = [7u8; 32];
        let session_public = [9u8; 32];
        let context = submission_context("session-1", &nonce, &session_public, "alice", 1).unwrap();

        let envelope = encrypt_share_with_context(holder.public_bytes(), &share, &context).unwrap();
        let decrypted =
            decrypt_share_with_context(holder.secret_bytes(), &envelope, &context).unwrap();
        assert_eq!(decrypted.as_slice(), share.as_slice());

        let wrong = submission_context("session-1", &nonce, &session_public, "alice", 2).unwrap();
        assert!(matches!(
            decrypt_share_with_context(holder.secret_bytes(), &envelope, &wrong),
            Err(ShareError::Decrypt)
        ));

        assert!(matches!(
            decrypt_share(holder.secret_bytes(), &envelope),
            Err(ShareError::UnsupportedVersion)
        ));
    }

    #[test]
    fn signing_input_binds_context_and_ciphertext() {
        let context = submission_context("session-1", &[7u8; 32], &[9u8; 32], "alice", 1).unwrap();
        let input_a = submission_signing_input(&context, b"ciphertext-a");
        let input_b = submission_signing_input(&context, b"ciphertext-b");
        assert_ne!(input_a, input_b);

        let other = submission_context("session-1", &[7u8; 32], &[9u8; 32], "bob", 1).unwrap();
        assert_ne!(
            submission_signing_input(&context, b"same"),
            submission_signing_input(&other, b"same")
        );
    }
}
