//! Shared file formats, KDF helpers, and safe on-disk writes.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::HolderError;

pub(crate) const IDENTITY_MAGIC: [u8; 4] = *b"SHK2";
pub(crate) const VAULT_MAGIC: [u8; 4] = *b"SHV1";
pub(crate) const FORMAT_VERSION: u8 = 1;
pub(crate) const SALT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const KEY_LEN: usize = 32;
pub(crate) const SHARE_LEN: usize = 33;
pub(crate) const MAX_HOLDER_ID_LEN: usize = 64;
pub(crate) const MAX_CEREMONY_ID_LEN: usize = 64;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Argon2id parameters embedded in identity and vault files.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

impl KdfParams {
    pub(crate) fn validate(self) -> Result<(), HolderError> {
        if !(8 * 1024..=256 * 1024).contains(&self.m_cost) {
            return Err(HolderError::InvalidKdfParams);
        }
        if !(1..=10).contains(&self.t_cost) {
            return Err(HolderError::InvalidKdfParams);
        }
        if !(1..=4).contains(&self.p_cost) {
            return Err(HolderError::InvalidKdfParams);
        }
        Ok(())
    }

    pub(crate) fn write_to(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.m_cost.to_le_bytes());
        out.extend_from_slice(&self.t_cost.to_le_bytes());
        out.extend_from_slice(&self.p_cost.to_le_bytes());
    }
}

pub(crate) fn derive_key(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>, HolderError> {
    if passphrase.is_empty() {
        return Err(HolderError::EmptyPassphrase);
    }
    params.validate()?;

    let argon_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| HolderError::InvalidKdfParams)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key[..])
        .map_err(|_| HolderError::Crypto)?;

    Ok(key)
}

pub(crate) fn random_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

pub(crate) fn read_file(path: &Path) -> Result<Vec<u8>, HolderError> {
    fs::read(path).map_err(HolderError::from)
}

/// Write a file through a temporary sibling and rename it into place.
///
/// Existing files are preserved unless `overwrite` is true.
pub fn write_atomic(path: &Path, data: &[u8], overwrite: bool) -> Result<(), HolderError> {
    if path.exists() && !overwrite {
        return Err(HolderError::AlreadyExists);
    }

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let file_name = path.file_name().ok_or_else(|| {
        HolderError::Io(std::io::Error::new(
            ErrorKind::InvalidInput,
            "path has no file name",
        ))
    })?;

    let tmp = unique_sibling(
        parent,
        &format!(
            ".{}.holder-tmp",
            file_name.to_string_lossy().replace(['/', '\\'], "_")
        ),
    );

    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        let mut file = options.open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);

        if path.exists() {
            if !overwrite {
                return Err(HolderError::AlreadyExists);
            }
            fs::remove_file(path)?;
        }

        fs::rename(&tmp, path)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }

    result
}

fn unique_sibling(parent: &Path, prefix: &str) -> PathBuf {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    parent.join(format!("{prefix}-{}-{counter}", std::process::id()))
}

pub fn validate_holder_id(value: &str) -> Result<(), HolderError> {
    if value.is_empty() || value.len() > MAX_HOLDER_ID_LEN {
        return Err(HolderError::InvalidHolderId);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(HolderError::InvalidHolderId);
    }
    Ok(())
}

pub(crate) fn validate_ceremony_id(value: &str) -> Result<(), HolderError> {
    if value.is_empty() || value.len() > MAX_CEREMONY_ID_LEN {
        return Err(HolderError::InvalidCeremonyId);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(HolderError::InvalidCeremonyId);
    }
    Ok(())
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

pub fn public_fingerprint(ed25519_public: &[u8; 32], x25519_public: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"signer.holder.fingerprint.v1");
    hasher.update(ed25519_public);
    hasher.update(x25519_public);
    hex::encode(hasher.finalize())
}

pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], ()> {
        let end = self.position.checked_add(len).ok_or(())?;
        let slice = self.data.get(self.position..end).ok_or(())?;
        self.position = end;
        Ok(slice)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, ()> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, ()> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| ())?;
        Ok(u16::from_le_bytes(bytes))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, ()> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| ())?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, ()> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| ())?;
        Ok(u64::from_le_bytes(bytes))
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    pub(crate) fn position(&self) -> usize {
        self.position
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holder_id_validation() {
        assert!(validate_holder_id("alice").is_ok());
        assert!(validate_holder_id("holder-1").is_ok());
        assert!(validate_holder_id("../evil").is_err());
        assert!(validate_holder_id("").is_err());
        assert!(validate_holder_id(&"a".repeat(65)).is_err());
    }

    #[test]
    fn atomic_write_refuses_overwrite_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");

        write_atomic(&path, b"one", false).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"one");
        assert!(matches!(
            write_atomic(&path, b"two", false),
            Err(HolderError::AlreadyExists)
        ));

        write_atomic(&path, b"two", true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two");
    }
}
