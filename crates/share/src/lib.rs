//! Encrypted share envelopes for offline distribution.
//!
//! A share is encrypted to a holder's X25519 public key using an ephemeral
//! X25519 exchange, HKDF-SHA256, and XChaCha20-Poly1305. The holder decrypts
//! the envelope with the matching private key before submitting the share.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const MAGIC: [u8; 4] = *b"SSHR";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 4 + 1 + 32 + NONCE_LEN;
const TAG_LEN: usize = 16;
const HKDF_INFO: &[u8] = b"signer-share-envelope-v1";

/// Errors returned by share envelope operations.
#[derive(Debug, Error)]
pub enum ShareError {
    #[error("share envelope is too short")]
    TooShort,

    #[error("invalid share envelope magic")]
    InvalidMagic,

    #[error("unsupported share envelope version")]
    UnsupportedVersion,

    #[error("share key derivation failed")]
    KeyDerivation,

    #[error("share encryption failed")]
    Encrypt,

    #[error("share decryption failed")]
    Decrypt,
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

/// Encrypt a plaintext Shamir share to a holder's public key.
pub fn encrypt_share(recipient_public: &[u8; 32], share: &[u8]) -> Result<Vec<u8>, ShareError> {
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
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| ShareError::Encrypt)?;

    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let aad = envelope_aad();
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: share,
                aad: &aad,
            },
        )
        .map_err(|_| ShareError::Encrypt)?;

    let mut envelope = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    envelope.extend_from_slice(&MAGIC);
    envelope.push(VERSION);
    envelope.extend_from_slice(ephemeral_public.as_bytes());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);

    Ok(envelope)
}

/// Decrypt a share envelope with the holder's 32-byte X25519 secret.
pub fn decrypt_share(
    recipient_secret: &[u8; 32],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ShareError> {
    if envelope.len() < HEADER_LEN + TAG_LEN {
        return Err(ShareError::TooShort);
    }
    if envelope[..4] != MAGIC {
        return Err(ShareError::InvalidMagic);
    }
    if envelope[4] != VERSION {
        return Err(ShareError::UnsupportedVersion);
    }

    let mut ephemeral_public = [0u8; 32];
    ephemeral_public.copy_from_slice(&envelope[5..37]);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&envelope[37..HEADER_LEN]);

    let static_secret = StaticSecret::from(*recipient_secret);
    let recipient_public = PublicKey::from(&static_secret).to_bytes();
    let shared = static_secret.diffie_hellman(&PublicKey::from(ephemeral_public));

    let key = derive_key(shared.as_bytes(), &ephemeral_public, &recipient_public)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| ShareError::Decrypt)?;

    let aad = envelope_aad();
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &envelope[HEADER_LEN..],
                aad: &aad,
            },
        )
        .map_err(|_| ShareError::Decrypt)?;

    Ok(Zeroizing::new(plaintext))
}

fn derive_key(
    shared: &[u8; 32],
    ephemeral_public: &[u8; 32],
    recipient_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, ShareError> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral_public);
    salt[32..].copy_from_slice(recipient_public);

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(HKDF_INFO, &mut key[..])
        .map_err(|_| ShareError::KeyDerivation)?;

    Ok(key)
}

fn envelope_aad() -> [u8; 5] {
    let mut aad = [0u8; 5];
    aad[..4].copy_from_slice(&MAGIC);
    aad[4] = VERSION;
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
}
