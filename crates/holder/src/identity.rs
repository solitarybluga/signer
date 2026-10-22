//! Holder identity: Ed25519 signing key plus X25519 encryption key.

use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::HolderError;
use crate::file::{
    Cursor, FORMAT_VERSION, IDENTITY_MAGIC, KdfParams, MAX_HOLDER_ID_LEN, NONCE_LEN, SALT_LEN,
    derive_key, random_array, read_file, validate_holder_id, write_atomic,
};

const IDENTITY_TRANSCRIPT: &[u8] = b"signer.holder.identity.v1";
const IDENTITY_SECRET_LEN: usize = 32 + 32;
const MIN_FILE_LEN: usize = 4 + 1 + 12 + SALT_LEN + NONCE_LEN + 16;

/// Decoded public key material from a holder's public bundle.
#[derive(Clone, Debug)]
pub struct PublicKeyMaterial {
    pub holder_id: String,
    pub ed25519_public: [u8; 32],
    pub x25519_public: [u8; 32],
}

/// Public information a holder gives to the operator for registration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicBundle {
    pub version: u8,
    pub holder_id: String,
    pub ed25519_public: String,
    pub x25519_public: String,
    pub self_signature: String,
}

impl PublicBundle {
    pub fn to_json_pretty(&self) -> Result<String, HolderError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    pub fn from_json(value: &str) -> Result<Self, HolderError> {
        serde_json::from_str(value).map_err(|_| HolderError::InvalidPublicBundle)
    }

    /// Decode the public bundle and verify its self-signature.
    pub fn verify(&self) -> Result<PublicKeyMaterial, HolderError> {
        let material = self.material()?;
        let transcript = identity_transcript(
            &material.holder_id,
            &material.ed25519_public,
            &material.x25519_public,
        );
        let signature = Signature::from_slice(
            &decode_hex_exact::<64>(&self.self_signature)
                .ok_or(HolderError::InvalidPublicBundle)?,
        )
        .map_err(|_| HolderError::InvalidPublicBundle)?;
        let verifying_key = VerifyingKey::from_bytes(&material.ed25519_public)
            .map_err(|_| HolderError::InvalidPublicBundle)?;
        verifying_key
            .verify_strict(&transcript, &signature)
            .map_err(|_| HolderError::InvalidPublicBundle)?;
        Ok(material)
    }

    pub fn material(&self) -> Result<PublicKeyMaterial, HolderError> {
        if self.version != FORMAT_VERSION {
            return Err(HolderError::InvalidPublicBundle);
        }
        validate_holder_id(&self.holder_id)?;

        let ed25519_public =
            decode_hex_exact::<32>(&self.ed25519_public).ok_or(HolderError::InvalidPublicBundle)?;
        let x25519_public =
            decode_hex_exact::<32>(&self.x25519_public).ok_or(HolderError::InvalidPublicBundle)?;

        Ok(PublicKeyMaterial {
            holder_id: self.holder_id.clone(),
            ed25519_public,
            x25519_public,
        })
    }

    pub fn fingerprint(&self) -> Result<String, HolderError> {
        let material = self.material()?;
        Ok(crate::file::public_fingerprint(
            &material.ed25519_public,
            &material.x25519_public,
        ))
    }
}

/// Holder private identity. Secret material is zeroized on drop.
pub struct HolderIdentity {
    holder_id: String,
    signing_key: SigningKey,
    x25519_secret: StaticSecret,
}

impl HolderIdentity {
    /// Generate a fresh Ed25519 + X25519 identity.
    pub fn generate(holder_id: &str) -> Result<Self, HolderError> {
        validate_holder_id(holder_id)?;

        let mut ed_seed = random_array::<32>();
        let signing_key = SigningKey::from_bytes(&ed_seed);
        ed_seed.zeroize();

        let mut x_seed = random_array::<32>();
        let x25519_secret = StaticSecret::from(x_seed);
        x_seed.zeroize();

        Ok(Self {
            holder_id: holder_id.to_string(),
            signing_key,
            x25519_secret,
        })
    }

    pub fn holder_id(&self) -> &str {
        &self.holder_id
    }

    pub fn ed25519_public(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub fn x25519_public(&self) -> [u8; 32] {
        PublicKey::from(&self.x25519_secret).to_bytes()
    }

    pub fn public_bundle(&self) -> PublicBundle {
        let ed25519_public = self.ed25519_public();
        let x25519_public = self.x25519_public();
        let transcript = identity_transcript(&self.holder_id, &ed25519_public, &x25519_public);
        let signature = self.signing_key.sign(&transcript);

        PublicBundle {
            version: FORMAT_VERSION,
            holder_id: self.holder_id.clone(),
            ed25519_public: hex::encode(ed25519_public),
            x25519_public: hex::encode(x25519_public),
            self_signature: hex::encode(signature.to_bytes()),
        }
    }

    /// Sign a message with the holder's Ed25519 identity key.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Decrypt a v1 share envelope with this holder's X25519 secret.
    pub fn decrypt_share(&self, envelope: &[u8]) -> Result<Zeroizing<Vec<u8>>, HolderError> {
        let secret = Zeroizing::new(self.x25519_secret.to_bytes());
        Ok(signer_share::decrypt_share(&secret, envelope)?)
    }

    /// Encrypt this identity to `path` and return the matching public bundle.
    pub fn save_encrypted(
        &self,
        path: &Path,
        passphrase: &str,
    ) -> Result<PublicBundle, HolderError> {
        let params = KdfParams::default();
        let salt = random_array::<SALT_LEN>();
        let nonce = random_array::<NONCE_LEN>();

        let mut header = Vec::with_capacity(MIN_FILE_LEN);
        header.extend_from_slice(&IDENTITY_MAGIC);
        header.push(FORMAT_VERSION);
        params.write_to(&mut header);
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);

        let id_len =
            u16::try_from(self.holder_id.len()).map_err(|_| HolderError::InvalidHolderId)?;

        let mut plaintext = Zeroizing::new(Vec::with_capacity(
            2 + self.holder_id.len() + IDENTITY_SECRET_LEN,
        ));
        plaintext.extend_from_slice(&id_len.to_le_bytes());
        plaintext.extend_from_slice(self.holder_id.as_bytes());
        let ed_secret = Zeroizing::new(self.signing_key.to_bytes());
        plaintext.extend_from_slice(&ed_secret[..]);
        let x_secret = Zeroizing::new(self.x25519_secret.to_bytes());
        plaintext.extend_from_slice(&x_secret[..]);

        let key = derive_key(passphrase, &salt, params)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| HolderError::Crypto)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| HolderError::Crypto)?;
        plaintext.zeroize();

        let mut file = header;
        file.extend_from_slice(&ciphertext);
        write_atomic(path, &file, false)?;

        Ok(self.public_bundle())
    }

    /// Load and decrypt an identity file.
    pub fn load_encrypted(path: &Path, passphrase: &str) -> Result<Self, HolderError> {
        let data = read_file(path)?;
        if data.len() < MIN_FILE_LEN {
            return Err(HolderError::InvalidIdentity);
        }

        let mut cursor = Cursor::new(&data);
        let magic = cursor.take(4).map_err(|_| HolderError::InvalidIdentity)?;
        if magic != IDENTITY_MAGIC {
            return Err(HolderError::InvalidIdentity);
        }
        let version = cursor.u8().map_err(|_| HolderError::InvalidIdentity)?;
        if version != FORMAT_VERSION {
            return Err(HolderError::InvalidIdentity);
        }

        let params = KdfParams {
            m_cost: cursor.u32().map_err(|_| HolderError::InvalidIdentity)?,
            t_cost: cursor.u32().map_err(|_| HolderError::InvalidIdentity)?,
            p_cost: cursor.u32().map_err(|_| HolderError::InvalidIdentity)?,
        };
        params.validate()?;

        let salt: [u8; SALT_LEN] = cursor
            .take(SALT_LEN)
            .map_err(|_| HolderError::InvalidIdentity)?
            .try_into()
            .map_err(|_| HolderError::InvalidIdentity)?;
        let nonce: [u8; NONCE_LEN] = cursor
            .take(NONCE_LEN)
            .map_err(|_| HolderError::InvalidIdentity)?
            .try_into()
            .map_err(|_| HolderError::InvalidIdentity)?;
        let header_len = cursor.position();

        let key = derive_key(passphrase, &salt, params)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| HolderError::Crypto)?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &data[header_len..],
                    aad: &data[..header_len],
                },
            )
            .map_err(|_| HolderError::InvalidPassphraseOrCorrupt)?;
        let plaintext = Zeroizing::new(plaintext);

        let mut cursor = Cursor::new(&plaintext);
        let id_len = cursor.u16().map_err(|_| HolderError::InvalidIdentity)? as usize;
        if id_len == 0 || id_len > MAX_HOLDER_ID_LEN {
            return Err(HolderError::InvalidIdentity);
        }
        let holder_id = String::from_utf8(
            cursor
                .take(id_len)
                .map_err(|_| HolderError::InvalidIdentity)?
                .to_vec(),
        )
        .map_err(|_| HolderError::InvalidIdentity)?;
        validate_holder_id(&holder_id)?;

        let mut ed_secret = Zeroizing::new([0u8; 32]);
        ed_secret.copy_from_slice(cursor.take(32).map_err(|_| HolderError::InvalidIdentity)?);
        let mut x_secret = Zeroizing::new([0u8; 32]);
        x_secret.copy_from_slice(cursor.take(32).map_err(|_| HolderError::InvalidIdentity)?);
        if cursor.remaining() != 0 {
            return Err(HolderError::InvalidIdentity);
        }

        let signing_key = SigningKey::from_bytes(&ed_secret);
        let x25519_secret = StaticSecret::from(*x_secret);

        Ok(Self {
            holder_id,
            signing_key,
            x25519_secret,
        })
    }
}

fn identity_transcript(
    holder_id: &str,
    ed25519_public: &[u8; 32],
    x25519_public: &[u8; 32],
) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(IDENTITY_TRANSCRIPT.len() + 2 + holder_id.len() + 64);
    transcript.extend_from_slice(IDENTITY_TRANSCRIPT);
    transcript.extend_from_slice(&(holder_id.len() as u16).to_le_bytes());
    transcript.extend_from_slice(holder_id.as_bytes());
    transcript.extend_from_slice(ed25519_public);
    transcript.extend_from_slice(x25519_public);
    transcript
}

fn decode_hex_exact<const N: usize>(value: &str) -> Option<[u8; N]> {
    hex::decode(value.trim()).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        (dir, path)
    }

    #[test]
    fn identity_roundtrip_and_public_bundle() {
        let identity = HolderIdentity::generate("alice").unwrap();
        let bundle = identity.public_bundle();
        bundle.verify().unwrap();
        assert_eq!(bundle.holder_id, "alice");
        assert_eq!(bundle.fingerprint().unwrap().len(), 64);

        let (_dir, path) = temp_path("alice.key");
        identity
            .save_encrypted(&path, "correct horse battery staple")
            .unwrap();

        let loaded = HolderIdentity::load_encrypted(&path, "correct horse battery staple").unwrap();
        assert_eq!(loaded.holder_id(), "alice");
        assert_eq!(loaded.ed25519_public(), identity.ed25519_public());
        assert_eq!(loaded.x25519_public(), identity.x25519_public());
    }

    #[test]
    fn identity_signs_with_the_ed25519_key() {
        use ed25519_dalek::Verifier;

        let identity = HolderIdentity::generate("alice").unwrap();
        let message = b"signer.unseal.submit";
        let signature = ed25519_dalek::Signature::from_bytes(&identity.sign(message));
        let verifying_key = VerifyingKey::from_bytes(&identity.ed25519_public()).unwrap();

        verifying_key.verify(message, &signature).unwrap();
        assert!(verifying_key.verify(b"other message", &signature).is_err());
    }

    #[test]
    fn wrong_passphrase_and_tamper_are_rejected() {
        let identity = HolderIdentity::generate("alice").unwrap();
        let (dir, path) = temp_path("alice.key");
        identity.save_encrypted(&path, "passphrase-1").unwrap();

        assert!(matches!(
            HolderIdentity::load_encrypted(&path, "passphrase-2"),
            Err(HolderError::InvalidPassphraseOrCorrupt)
        ));

        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let tampered = dir.path().join("tampered.key");
        std::fs::write(&tampered, bytes).unwrap();
        assert!(matches!(
            HolderIdentity::load_encrypted(&tampered, "passphrase-1"),
            Err(HolderError::InvalidPassphraseOrCorrupt)
        ));
    }

    #[test]
    fn public_bundle_tamper_is_rejected() {
        let identity = HolderIdentity::generate("alice").unwrap();
        let mut bundle = identity.public_bundle();
        bundle.x25519_public = hex::encode([9u8; 32]);
        assert!(bundle.verify().is_err());
    }
}
