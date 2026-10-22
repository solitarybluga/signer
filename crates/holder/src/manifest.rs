//! Operator-signed manifest describing a share distribution ceremony.

use std::collections::HashSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use signer_vss::VssCommitments;

use zeroize::Zeroize;

use crate::error::HolderError;
use crate::file::{random_array, sha256, validate_ceremony_id, validate_holder_id};

/// One holder entry in a ceremony manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HolderEntry {
    pub id: String,
    pub index: u8,
    pub x25519_public: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ed25519_public: Option<String>,
    pub envelope_sha256: String,
}

/// Signed share distribution manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u8,
    pub ceremony_id: String,
    pub threshold: u8,
    pub total_shares: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vss: Option<VssCommitments>,
    pub holders: Vec<HolderEntry>,
}

impl Manifest {
    /// Serialize the exact bytes an operator must sign.
    pub fn encode(&self) -> Result<Vec<u8>, HolderError> {
        self.validate()?;
        Ok(serde_json::to_vec_pretty(self)?)
    }

    /// Validate structure, VSS commitments, and holder key encodings.
    pub fn validate(&self) -> Result<(), HolderError> {
        if self.version != 1 && self.version != 2 {
            return Err(HolderError::InvalidManifest);
        }
        validate_ceremony_id(&self.ceremony_id).map_err(|_| HolderError::InvalidManifest)?;

        if self.threshold == 0 || self.total_shares == 0 || self.threshold > self.total_shares {
            return Err(HolderError::InvalidManifest);
        }
        if self.holders.len() != self.total_shares as usize {
            return Err(HolderError::InvalidManifest);
        }

        match (&self.vss, self.version) {
            (None, 1) => {}
            (Some(vss), 2) => {
                if vss.len() != self.threshold as usize || vss.decode().is_err() {
                    return Err(HolderError::InvalidManifest);
                }
            }
            _ => return Err(HolderError::InvalidManifest),
        }

        let mut ids = HashSet::new();
        let mut indices = HashSet::new();
        for holder in &self.holders {
            validate_holder_id(&holder.id).map_err(|_| HolderError::InvalidManifest)?;
            if holder.index == 0 || holder.index > self.total_shares {
                return Err(HolderError::InvalidManifest);
            }
            if !ids.insert(holder.id.clone()) || !indices.insert(holder.index) {
                return Err(HolderError::InvalidManifest);
            }
            if decode_hex_exact::<32>(&holder.x25519_public).is_none() {
                return Err(HolderError::InvalidManifest);
            }
            if decode_hex_exact::<32>(&holder.envelope_sha256).is_none() {
                return Err(HolderError::InvalidManifest);
            }
            if let Some(value) = &holder.ed25519_public {
                if decode_hex_exact::<32>(value).is_none() {
                    return Err(HolderError::InvalidManifest);
                }
            }
        }

        Ok(())
    }

    /// Find this identity's entry and check its public key material.
    pub fn find_holder(
        &self,
        holder_id: &str,
        x25519_public: &[u8; 32],
        ed25519_public: &[u8; 32],
    ) -> Result<&HolderEntry, HolderError> {
        let entry = self
            .holders
            .iter()
            .find(|holder| holder.id == holder_id)
            .ok_or(HolderError::HolderNotInManifest)?;

        let manifest_x25519 =
            decode_hex_exact::<32>(&entry.x25519_public).ok_or(HolderError::InvalidManifest)?;
        if manifest_x25519 != *x25519_public {
            return Err(HolderError::HolderMismatch);
        }

        if let Some(value) = &entry.ed25519_public {
            let manifest_ed25519 =
                decode_hex_exact::<32>(value).ok_or(HolderError::InvalidManifest)?;
            if manifest_ed25519 != *ed25519_public {
                return Err(HolderError::HolderMismatch);
            }
        }

        Ok(entry)
    }

    /// Check that an envelope's SHA-256 matches the signed entry.
    pub fn verify_envelope(&self, entry: &HolderEntry, envelope: &[u8]) -> Result<(), HolderError> {
        let expected =
            decode_hex_exact::<32>(&entry.envelope_sha256).ok_or(HolderError::InvalidManifest)?;
        if sha256(envelope) != expected {
            return Err(HolderError::EnvelopeHashMismatch);
        }
        Ok(())
    }

    /// Verify a decrypted share against the signed VSS commitments.
    pub fn verify_share(&self, entry: &HolderEntry, share: &[u8]) -> Result<(), HolderError> {
        let vss = self.vss.as_ref().ok_or(HolderError::InvalidManifest)?;
        if share.first().copied() != Some(entry.index) {
            return Err(HolderError::IndexMismatch);
        }
        signer_vss::verify_share(vss, share).map_err(|_| HolderError::VssRejected)
    }
}

/// Sign the exact manifest bytes with an operator Ed25519 secret key.
pub fn sign_manifest(bytes: &[u8], operator_secret: &[u8; 32]) -> Result<Vec<u8>, HolderError> {
    let signing_key = SigningKey::from_bytes(operator_secret);
    Ok(signing_key.sign(bytes).to_bytes().to_vec())
}

/// Derive the operator public key from its 32-byte secret.
pub fn operator_public(operator_secret: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(operator_secret)
        .verifying_key()
        .to_bytes()
}

/// Stable fingerprint of an operator public key for out-of-band verification.
pub fn operator_fingerprint(operator_public: &[u8; 32]) -> String {
    let mut transcript = Vec::with_capacity(31 + 32);
    transcript.extend_from_slice(b"signer.operator.fingerprint.v1");
    transcript.extend_from_slice(operator_public);
    hex::encode(sha256(&transcript))
}

/// Verify a detached operator signature and parse the manifest.
pub fn verify_manifest(
    bytes: &[u8],
    signature: &[u8],
    operator_public: &[u8; 32],
) -> Result<Manifest, HolderError> {
    let signature =
        Signature::from_slice(signature).map_err(|_| HolderError::InvalidManifestSignature)?;
    let verifying_key = VerifyingKey::from_bytes(operator_public)
        .map_err(|_| HolderError::InvalidManifestSignature)?;
    verifying_key
        .verify_strict(bytes, &signature)
        .map_err(|_| HolderError::InvalidManifestSignature)?;

    let manifest: Manifest =
        serde_json::from_slice(bytes).map_err(|_| HolderError::InvalidManifest)?;
    manifest.validate()?;
    Ok(manifest)
}

pub fn decode_operator_public(value: &str) -> Result<[u8; 32], HolderError> {
    decode_hex_exact::<32>(value).ok_or(HolderError::InvalidManifestSignature)
}

pub fn decode_signature(value: &str) -> Result<[u8; 64], HolderError> {
    decode_hex_exact::<64>(value).ok_or(HolderError::InvalidManifestSignature)
}

pub fn manifest_hash(bytes: &[u8]) -> [u8; 32] {
    sha256(bytes)
}

/// Generate an operator Ed25519 keypair: (secret, public).
pub fn generate_operator_key() -> Result<([u8; 32], [u8; 32]), HolderError> {
    let mut seed = random_array::<32>();
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    let secret = signing_key.to_bytes();
    let public = signing_key.verifying_key().to_bytes();
    Ok((secret, public))
}

fn decode_hex_exact<const N: usize>(value: &str) -> Option<[u8; N]> {
    hex::decode(value.trim()).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest {
            version: 1,
            ceremony_id: "ceremony-1".to_string(),
            threshold: 2,
            total_shares: 3,
            vss: None,
            holders: vec![
                HolderEntry {
                    id: "alice".to_string(),
                    index: 1,
                    x25519_public: hex::encode([1u8; 32]),
                    ed25519_public: Some(hex::encode([2u8; 32])),
                    envelope_sha256: hex::encode([3u8; 32]),
                },
                HolderEntry {
                    id: "bob".to_string(),
                    index: 2,
                    x25519_public: hex::encode([4u8; 32]),
                    ed25519_public: None,
                    envelope_sha256: hex::encode([5u8; 32]),
                },
                HolderEntry {
                    id: "carol".to_string(),
                    index: 3,
                    x25519_public: hex::encode([6u8; 32]),
                    ed25519_public: None,
                    envelope_sha256: hex::encode([7u8; 32]),
                },
            ],
        }
    }

    #[test]
    fn sign_verify_and_find_holder() {
        let (secret, public) = generate_operator_key().unwrap();
        let manifest = manifest();
        let bytes = manifest.encode().unwrap();
        let signature = sign_manifest(&bytes, &secret).unwrap();

        let verified = verify_manifest(&bytes, &signature, &public).unwrap();
        let entry = verified
            .find_holder("alice", &[1u8; 32], &[2u8; 32])
            .unwrap();
        assert_eq!(entry.index, 1);
        assert!(
            verified
                .find_holder("alice", &[9u8; 32], &[2u8; 32])
                .is_err()
        );
        assert!(
            verified
                .find_holder("mallory", &[1u8; 32], &[2u8; 32])
                .is_err()
        );
    }

    #[test]
    fn tampered_manifest_or_signature_is_rejected() {
        let (secret, public) = generate_operator_key().unwrap();
        let bytes = manifest().encode().unwrap();
        let signature = sign_manifest(&bytes, &secret).unwrap();

        let mut tampered = bytes.clone();
        tampered.push(b' ');
        assert!(matches!(
            verify_manifest(&tampered, &signature, &public),
            Err(HolderError::InvalidManifestSignature)
        ));

        assert!(matches!(
            verify_manifest(&bytes, &[0u8; 64], &public),
            Err(HolderError::InvalidManifestSignature)
        ));
    }

    #[test]
    fn duplicate_indices_are_rejected() {
        let mut manifest = manifest();
        manifest.holders[1].index = 1;
        assert!(matches!(
            manifest.validate(),
            Err(HolderError::InvalidManifest)
        ));
    }

    #[test]
    fn operator_fingerprint_is_stable() {
        let (_, public) = generate_operator_key().unwrap();
        let fingerprint = operator_fingerprint(&public);
        assert_eq!(fingerprint.len(), 64);
        assert_eq!(fingerprint, operator_fingerprint(&public));
        assert_ne!(fingerprint, operator_fingerprint(&[0u8; 32]));
    }
}
