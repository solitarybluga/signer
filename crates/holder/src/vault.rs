//! Passphrase-encrypted local storage for a holder's Shamir share.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::error::HolderError;
use crate::file::{
    Cursor, FORMAT_VERSION, KdfParams, MAX_CEREMONY_ID_LEN, MAX_HOLDER_ID_LEN, NONCE_LEN, SALT_LEN,
    SHARE_LEN, VAULT_MAGIC, derive_key, random_array, read_file, validate_ceremony_id,
    validate_holder_id, write_atomic,
};

const MIN_FILE_LEN: usize = 4 + 1 + 12 + SALT_LEN + NONCE_LEN + 1 + 1 + 1 + 1 + 32 + 8 + 16;
const MANIFEST_HASH_LEN: usize = 32;

/// How the share in a vault was obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultSource {
    /// Legacy v1 envelope imported without an operator-signed manifest.
    Legacy,
    /// Envelope hash and holder entry were verified against a signed manifest.
    Manifest,
}

impl VaultSource {
    fn as_u8(self) -> u8 {
        match self {
            Self::Legacy => 1,
            Self::Manifest => 2,
        }
    }

    fn parse(value: u8) -> Result<Self, HolderError> {
        match value {
            1 => Ok(Self::Legacy),
            2 => Ok(Self::Manifest),
            _ => Err(HolderError::InvalidVault),
        }
    }
}

/// Public metadata stored in a vault header.
#[derive(Clone, Debug, Serialize)]
pub struct VaultInfo {
    pub holder_id: String,
    pub index: u8,
    pub source: VaultSource,
    pub ceremony_id: Option<String>,
    pub manifest_hash: Option<String>,
    pub created_at: u64,
}

/// Sealed share vault.
pub struct ShareVault;

impl ShareVault {
    /// Encrypt a 33-byte Shamir share to a vault file.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        path: &Path,
        passphrase: &str,
        share: &[u8],
        holder_id: &str,
        index: u8,
        ceremony_id: Option<&str>,
        manifest_hash: Option<[u8; MANIFEST_HASH_LEN]>,
        source: VaultSource,
    ) -> Result<VaultInfo, HolderError> {
        validate_holder_id(holder_id)?;
        if index == 0 {
            return Err(HolderError::IndexMismatch);
        }
        if share.len() != SHARE_LEN {
            return Err(HolderError::InvalidShare);
        }
        if share[0] != index {
            return Err(HolderError::IndexMismatch);
        }

        match (source, ceremony_id, manifest_hash) {
            (VaultSource::Legacy, None, None) => {}
            (VaultSource::Manifest, Some(ceremony), Some(hash)) => {
                validate_ceremony_id(ceremony)?;
                if hash.iter().all(|byte| *byte == 0) {
                    return Err(HolderError::InvalidVault);
                }
            }
            _ => return Err(HolderError::InvalidVault),
        }

        let ceremony_id = ceremony_id.unwrap_or("");
        if ceremony_id.len() > MAX_CEREMONY_ID_LEN || holder_id.len() > MAX_HOLDER_ID_LEN {
            return Err(HolderError::InvalidVault);
        }

        let params = KdfParams::default();
        let salt = random_array::<SALT_LEN>();
        let nonce = random_array::<NONCE_LEN>();
        let manifest_hash = manifest_hash.unwrap_or([0u8; MANIFEST_HASH_LEN]);
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);

        let mut header = Vec::with_capacity(MIN_FILE_LEN);
        header.extend_from_slice(&VAULT_MAGIC);
        header.push(FORMAT_VERSION);
        params.write_to(&mut header);
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);
        header.push(source.as_u8());
        header.push(index);
        header.push(ceremony_id.len() as u8);
        header.extend_from_slice(ceremony_id.as_bytes());
        header.push(holder_id.len() as u8);
        header.extend_from_slice(holder_id.as_bytes());
        header.extend_from_slice(&manifest_hash);
        header.extend_from_slice(&created_at.to_le_bytes());

        let key = derive_key(passphrase, &salt, params)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| HolderError::Crypto)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: share,
                    aad: &header,
                },
            )
            .map_err(|_| HolderError::Crypto)?;

        let mut file = header;
        file.extend_from_slice(&ciphertext);
        write_atomic(path, &file, false)?;

        Ok(info_from_parts(
            holder_id.to_string(),
            index,
            source,
            ceremony_id,
            manifest_hash,
            created_at,
        ))
    }

    /// Decrypt a vault and return its metadata plus plaintext share.
    pub fn open(
        path: &Path,
        passphrase: &str,
    ) -> Result<(VaultInfo, Zeroizing<Vec<u8>>), HolderError> {
        let data = read_file(path)?;
        let parsed = parse_header(&data)?;

        let key = derive_key(passphrase, &parsed.salt, parsed.params)?;
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| HolderError::Crypto)?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&parsed.nonce),
                Payload {
                    msg: &data[parsed.header_len..],
                    aad: &data[..parsed.header_len],
                },
            )
            .map_err(|_| HolderError::InvalidPassphraseOrCorrupt)?;
        let plaintext = Zeroizing::new(plaintext);

        if plaintext.len() != SHARE_LEN || plaintext[0] != parsed.info.index {
            return Err(HolderError::InvalidShare);
        }

        Ok((parsed.info, plaintext))
    }

    /// Read vault metadata without requiring the passphrase.
    pub fn info(path: &Path) -> Result<VaultInfo, HolderError> {
        let data = read_file(path)?;
        Ok(parse_header(&data)?.info)
    }
}

struct ParsedHeader {
    info: VaultInfo,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    header_len: usize,
}

fn parse_header(data: &[u8]) -> Result<ParsedHeader, HolderError> {
    if data.len() < MIN_FILE_LEN {
        return Err(HolderError::InvalidVault);
    }

    let mut cursor = Cursor::new(data);
    let magic = cursor.take(4).map_err(|_| HolderError::InvalidVault)?;
    if magic != VAULT_MAGIC {
        return Err(HolderError::InvalidVault);
    }
    let version = cursor.u8().map_err(|_| HolderError::InvalidVault)?;
    if version != FORMAT_VERSION {
        return Err(HolderError::InvalidVault);
    }

    let params = KdfParams {
        m_cost: cursor.u32().map_err(|_| HolderError::InvalidVault)?,
        t_cost: cursor.u32().map_err(|_| HolderError::InvalidVault)?,
        p_cost: cursor.u32().map_err(|_| HolderError::InvalidVault)?,
    };
    params.validate()?;

    let salt: [u8; SALT_LEN] = cursor
        .take(SALT_LEN)
        .map_err(|_| HolderError::InvalidVault)?
        .try_into()
        .map_err(|_| HolderError::InvalidVault)?;
    let nonce: [u8; NONCE_LEN] = cursor
        .take(NONCE_LEN)
        .map_err(|_| HolderError::InvalidVault)?
        .try_into()
        .map_err(|_| HolderError::InvalidVault)?;

    let source = VaultSource::parse(cursor.u8().map_err(|_| HolderError::InvalidVault)?)?;
    let index = cursor.u8().map_err(|_| HolderError::InvalidVault)?;
    if index == 0 {
        return Err(HolderError::InvalidVault);
    }

    let ceremony_len = cursor.u8().map_err(|_| HolderError::InvalidVault)? as usize;
    if ceremony_len > MAX_CEREMONY_ID_LEN {
        return Err(HolderError::InvalidVault);
    }
    let ceremony_id = String::from_utf8(
        cursor
            .take(ceremony_len)
            .map_err(|_| HolderError::InvalidVault)?
            .to_vec(),
    )
    .map_err(|_| HolderError::InvalidVault)?;

    let holder_len = cursor.u8().map_err(|_| HolderError::InvalidVault)? as usize;
    if holder_len == 0 || holder_len > MAX_HOLDER_ID_LEN {
        return Err(HolderError::InvalidVault);
    }
    let holder_id = String::from_utf8(
        cursor
            .take(holder_len)
            .map_err(|_| HolderError::InvalidVault)?
            .to_vec(),
    )
    .map_err(|_| HolderError::InvalidVault)?;
    validate_holder_id(&holder_id).map_err(|_| HolderError::InvalidVault)?;

    let manifest_hash: [u8; MANIFEST_HASH_LEN] = cursor
        .take(MANIFEST_HASH_LEN)
        .map_err(|_| HolderError::InvalidVault)?
        .try_into()
        .map_err(|_| HolderError::InvalidVault)?;
    let created_at = cursor.u64().map_err(|_| HolderError::InvalidVault)?;
    let header_len = cursor.position();

    if cursor.remaining() < 16 {
        return Err(HolderError::InvalidVault);
    }

    let ceremony_id = if ceremony_id.is_empty() {
        None
    } else {
        validate_ceremony_id(&ceremony_id).map_err(|_| HolderError::InvalidVault)?;
        Some(ceremony_id)
    };

    let manifest_is_zero = manifest_hash.iter().all(|byte| *byte == 0);
    match (source, &ceremony_id, manifest_is_zero) {
        (VaultSource::Legacy, None, true) => {}
        (VaultSource::Manifest, Some(_), false) => {}
        _ => return Err(HolderError::InvalidVault),
    }

    let info = info_from_parts(
        holder_id,
        index,
        source,
        ceremony_id.as_deref().unwrap_or(""),
        manifest_hash,
        created_at,
    );

    Ok(ParsedHeader {
        info,
        params,
        salt,
        nonce,
        header_len,
    })
}

fn info_from_parts(
    holder_id: String,
    index: u8,
    source: VaultSource,
    ceremony_id: &str,
    manifest_hash: [u8; MANIFEST_HASH_LEN],
    created_at: u64,
) -> VaultInfo {
    VaultInfo {
        holder_id,
        index,
        source,
        ceremony_id: if ceremony_id.is_empty() {
            None
        } else {
            Some(ceremony_id.to_string())
        },
        manifest_hash: if manifest_hash.iter().all(|byte| *byte == 0) {
            None
        } else {
            Some(hex::encode(manifest_hash))
        },
        created_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(index: u8) -> Vec<u8> {
        let mut share = vec![index; SHARE_LEN];
        share[0] = index;
        share
    }

    #[test]
    fn legacy_vault_roundtrip_and_info() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alice.share.vault");
        let info = ShareVault::seal(
            &path,
            "passphrase-1",
            &share(2),
            "alice",
            2,
            None,
            None,
            VaultSource::Legacy,
        )
        .unwrap();
        assert_eq!(info.source, VaultSource::Legacy);
        assert_eq!(info.index, 2);

        let header_only = ShareVault::info(&path).unwrap();
        assert_eq!(header_only.holder_id, "alice");
        assert_eq!(header_only.ceremony_id, None);

        let (opened, plaintext) = ShareVault::open(&path, "passphrase-1").unwrap();
        assert_eq!(opened.index, 2);
        assert_eq!(plaintext.as_slice(), share(2).as_slice());
    }

    #[test]
    fn manifest_vault_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alice.share.vault");
        let manifest_hash = [7u8; 32];
        ShareVault::seal(
            &path,
            "passphrase-1",
            &share(1),
            "alice",
            1,
            Some("ceremony-1"),
            Some(manifest_hash),
            VaultSource::Manifest,
        )
        .unwrap();

        let info = ShareVault::info(&path).unwrap();
        assert_eq!(info.source, VaultSource::Manifest);
        assert_eq!(info.ceremony_id.as_deref(), Some("ceremony-1"));
        assert_eq!(info.manifest_hash, Some(hex::encode(manifest_hash)));
    }

    #[test]
    fn wrong_passphrase_tamper_and_index_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alice.share.vault");
        ShareVault::seal(
            &path,
            "passphrase-1",
            &share(1),
            "alice",
            1,
            None,
            None,
            VaultSource::Legacy,
        )
        .unwrap();

        assert!(matches!(
            ShareVault::open(&path, "passphrase-2"),
            Err(HolderError::InvalidPassphraseOrCorrupt)
        ));

        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let tampered = dir.path().join("tampered.vault");
        std::fs::write(&tampered, bytes).unwrap();
        assert!(matches!(
            ShareVault::open(&tampered, "passphrase-1"),
            Err(HolderError::InvalidPassphraseOrCorrupt)
        ));

        let wrong_index = dir.path().join("wrong-index.vault");
        assert!(matches!(
            ShareVault::seal(
                &wrong_index,
                "passphrase-1",
                &share(2),
                "alice",
                1,
                None,
                None,
                VaultSource::Legacy,
            ),
            Err(HolderError::IndexMismatch)
        ));
    }
}
