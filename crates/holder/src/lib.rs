//! Holder-side identity, share import, and encrypted local vaults.
//!
//! This crate contains no networking and no database dependencies. It is used
//! by the desktop client and the admin CLI.

pub mod error;
pub mod file;
pub mod identity;
pub mod manifest;
pub mod vault;

pub use error::HolderError;
pub use file::{KdfParams, public_fingerprint, sha256_hex, validate_holder_id, write_atomic};
pub use identity::{HolderIdentity, PublicBundle, PublicKeyMaterial};
pub use manifest::{
    HolderEntry, Manifest, decode_operator_public, decode_signature, generate_operator_key,
    manifest_hash, operator_fingerprint, operator_public, sign_manifest, verify_manifest,
};
pub use vault::{ShareVault, VaultInfo, VaultSource};

use std::path::Path;

use zeroize::Zeroizing;

use crate::file::SHARE_LEN;

/// Detached operator data needed to verify a share package.
pub struct ManifestPackage<'a> {
    pub manifest_bytes: &'a [u8],
    pub signature: &'a [u8],
    pub operator_public: &'a [u8; 32],
}

/// A decrypted share plus the metadata needed to seal it into a vault.
pub struct ImportedShare {
    pub share: Zeroizing<Vec<u8>>,
    pub holder_id: String,
    pub index: u8,
    pub source: VaultSource,
    pub ceremony_id: Option<String>,
    pub manifest_hash: Option<[u8; 32]>,
    pub operator_fingerprint: Option<String>,
}

impl ImportedShare {
    /// Encrypt this share to a vault file. The passphrase should be the same
    /// one used for the holder identity, but the vault uses an independent salt.
    pub fn seal(&self, path: &Path, passphrase: &str) -> Result<VaultInfo, HolderError> {
        ShareVault::seal(
            path,
            passphrase,
            &self.share,
            &self.holder_id,
            self.index,
            self.ceremony_id.as_deref(),
            self.manifest_hash,
            self.source,
        )
    }
}

/// Verify (when a package is supplied) and decrypt one share envelope.
///
/// Without a manifest package this is the legacy v1 import path: the envelope
/// and share index are checked, but there is no operator signature to verify.
pub fn import_share(
    identity: &HolderIdentity,
    envelope: &[u8],
    package: Option<ManifestPackage<'_>>,
) -> Result<ImportedShare, HolderError> {
    let share = identity.decrypt_share(envelope)?;
    if share.len() != SHARE_LEN {
        return Err(HolderError::InvalidShare);
    }
    if share[0] == 0 {
        return Err(HolderError::InvalidShare);
    }

    match package {
        Some(package) => {
            let manifest = verify_manifest(
                package.manifest_bytes,
                package.signature,
                package.operator_public,
            )?;
            let entry = manifest.find_holder(
                identity.holder_id(),
                &identity.x25519_public(),
                &identity.ed25519_public(),
            )?;
            manifest.verify_envelope(entry, envelope)?;

            if share[0] != entry.index {
                return Err(HolderError::IndexMismatch);
            }

            Ok(ImportedShare {
                share,
                holder_id: identity.holder_id().to_string(),
                index: entry.index,
                source: VaultSource::Manifest,
                ceremony_id: Some(manifest.ceremony_id.clone()),
                manifest_hash: Some(manifest_hash(package.manifest_bytes)),
                operator_fingerprint: Some(operator_fingerprint(package.operator_public)),
            })
        }
        None => {
            let index = share[0];
            Ok(ImportedShare {
                share,
                holder_id: identity.holder_id().to_string(),
                index,
                source: VaultSource::Legacy,
                ceremony_id: None,
                manifest_hash: None,
                operator_fingerprint: None,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::sha256_hex;
    use crate::manifest::{HolderEntry, Manifest, generate_operator_key, sign_manifest};

    fn share(index: u8) -> Vec<u8> {
        let mut share = vec![0u8; SHARE_LEN];
        share[0] = index;
        share[1..].fill(7);
        share
    }

    #[test]
    fn imports_legacy_and_manifest_share() {
        let identity = HolderIdentity::generate("alice").unwrap();
        let envelope = signer_share::encrypt_share(&identity.x25519_public(), &share(1)).unwrap();

        let legacy = import_share(&identity, &envelope, None).unwrap();
        assert_eq!(legacy.index, 1);
        assert_eq!(legacy.source, VaultSource::Legacy);
        assert_eq!(legacy.manifest_hash, None);

        let (secret, public) = generate_operator_key().unwrap();
        let manifest = Manifest {
            version: 1,
            ceremony_id: "ceremony-1".to_string(),
            threshold: 1,
            total_shares: 1,
            holders: vec![HolderEntry {
                id: "alice".to_string(),
                index: 1,
                x25519_public: hex::encode(identity.x25519_public()),
                ed25519_public: Some(hex::encode(identity.ed25519_public())),
                envelope_sha256: sha256_hex(&envelope),
            }],
        };
        let bytes = manifest.encode().unwrap();
        let signature = sign_manifest(&bytes, &secret).unwrap();

        let imported = import_share(
            &identity,
            &envelope,
            Some(ManifestPackage {
                manifest_bytes: &bytes,
                signature: &signature,
                operator_public: &public,
            }),
        )
        .unwrap();
        assert_eq!(imported.index, 1);
        assert_eq!(imported.source, VaultSource::Manifest);
        assert_eq!(imported.ceremony_id.as_deref(), Some("ceremony-1"));
        assert_eq!(imported.manifest_hash, Some(manifest_hash(&bytes)));
        assert_eq!(
            imported.operator_fingerprint,
            Some(operator_fingerprint(&public))
        );
    }

    #[test]
    fn rejects_envelope_hash_mismatch() {
        let identity = HolderIdentity::generate("alice").unwrap();
        let envelope = signer_share::encrypt_share(&identity.x25519_public(), &share(1)).unwrap();
        let (secret, public) = generate_operator_key().unwrap();
        let manifest = Manifest {
            version: 1,
            ceremony_id: "ceremony-1".to_string(),
            threshold: 1,
            total_shares: 1,
            holders: vec![HolderEntry {
                id: "alice".to_string(),
                index: 1,
                x25519_public: hex::encode(identity.x25519_public()),
                ed25519_public: None,
                envelope_sha256: sha256_hex(b"different envelope"),
            }],
        };
        let bytes = manifest.encode().unwrap();
        let signature = sign_manifest(&bytes, &secret).unwrap();

        let result = import_share(
            &identity,
            &envelope,
            Some(ManifestPackage {
                manifest_bytes: &bytes,
                signature: &signature,
                operator_public: &public,
            }),
        );
        assert!(matches!(result, Err(HolderError::EnvelopeHashMismatch)));
    }
}
