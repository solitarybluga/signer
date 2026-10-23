//! Client certificate permission bits.
//!
//! The bit assignments below are a protocol: append-only, never reordered or
//! reused. Reserved bits must be zero; a certificate that sets one is rejected
//! instead of being interpreted with partial or future semantics.

/// Default SAN URI prefix for the audit principal.
pub const DEFAULT_PRINCIPAL_URI_PREFIX: &str = "signer://principal/";
/// Default SAN URI prefix for holder bindings.
pub const DEFAULT_HOLDER_URI_PREFIX: &str = "signer://holder/";
/// Default SAN URI prefix for the permission bitmask.
pub const DEFAULT_PERMISSION_URI_PREFIX: &str = "signer://permissions/";

/// Maximum length of a principal or holder identifier.
pub const MAX_IDENTITY_LEN: usize = 128;

/// `unseal.start`: StartUnseal.
pub const UNSEAL_START: u64 = 1 << 0;
/// `unseal.submit`: SubmitUnsealShare.
pub const UNSEAL_SUBMIT: u64 = 1 << 1;
/// `unseal.status`: GetUnsealStatus.
pub const UNSEAL_STATUS: u64 = 1 << 2;
/// `unseal.seal`: Seal.
pub const UNSEAL_SEAL: u64 = 1 << 3;
/// `key.create`: CreateKey.
pub const KEY_CREATE: u64 = 1 << 4;
/// `key.import`: ImportKey (still unimplemented).
pub const KEY_IMPORT: u64 = 1 << 5;
/// `key.read`: GetPublicKey and ListKeys.
pub const KEY_READ: u64 = 1 << 6;
/// `key.sign`: Sign.
pub const KEY_SIGN: u64 = 1 << 7;

/// Bits currently understood by this build.
///
/// Bits 8..=63 are reserved and must be zero. Future `key.destroy` (bit 8) and
/// `audit.read` (bit 9) assignments may be added here once the corresponding
/// RPCs and checks exist; until then, certificates carrying those bits are
/// rejected.
pub const KNOWN_MASK: u64 = UNSEAL_START
    | UNSEAL_SUBMIT
    | UNSEAL_STATUS
    | UNSEAL_SEAL
    | KEY_CREATE
    | KEY_IMPORT
    | KEY_READ
    | KEY_SIGN;

/// One authorization bit used by an RPC handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    UnsealStart,
    UnsealSubmit,
    UnsealStatus,
    UnsealSeal,
    KeyCreate,
    KeyImport,
    KeyRead,
    KeySign,
}

impl Permission {
    pub const fn bit(self) -> u64 {
        match self {
            Self::UnsealStart => UNSEAL_START,
            Self::UnsealSubmit => UNSEAL_SUBMIT,
            Self::UnsealStatus => UNSEAL_STATUS,
            Self::UnsealSeal => UNSEAL_SEAL,
            Self::KeyCreate => KEY_CREATE,
            Self::KeyImport => KEY_IMPORT,
            Self::KeyRead => KEY_READ,
            Self::KeySign => KEY_SIGN,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsealStart => "unseal.start",
            Self::UnsealSubmit => "unseal.submit",
            Self::UnsealStatus => "unseal.status",
            Self::UnsealSeal => "unseal.seal",
            Self::KeyCreate => "key.create",
            Self::KeyImport => "key.import",
            Self::KeyRead => "key.read",
            Self::KeySign => "key.sign",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "unseal.start" => Some(Self::UnsealStart),
            "unseal.submit" => Some(Self::UnsealSubmit),
            "unseal.status" => Some(Self::UnsealStatus),
            "unseal.seal" => Some(Self::UnsealSeal),
            "key.create" => Some(Self::KeyCreate),
            "key.import" => Some(Self::KeyImport),
            "key.read" => Some(Self::KeyRead),
            "key.sign" => Some(Self::KeySign),
            _ => None,
        }
    }

    pub const fn all() -> &'static [Self] {
        &[
            Self::UnsealStart,
            Self::UnsealSubmit,
            Self::UnsealStatus,
            Self::UnsealSeal,
            Self::KeyCreate,
            Self::KeyImport,
            Self::KeyRead,
            Self::KeySign,
        ]
    }
}

/// A validated u64 permission mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermissionSet(u64);

impl PermissionSet {
    /// No permissions. This is *not* a wildcard.
    pub const NONE: Self = Self(0);

    /// Build a set from a raw mask, rejecting reserved bits.
    pub const fn from_known_mask(mask: u64) -> Option<Self> {
        if mask & !KNOWN_MASK == 0 {
            Some(Self(mask))
        } else {
            None
        }
    }

    /// Parse the value part of `signer://permissions/<value>`.
    ///
    /// Accepts an optional `0x` prefix and 1..=16 hexadecimal digits. Values
    /// longer than 16 digits are rejected instead of being truncated.
    pub fn parse(value: &str) -> Result<Self, PermissionMaskError> {
        let hex = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .unwrap_or(value);

        if hex.is_empty() || hex.len() > 16 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(PermissionMaskError::InvalidFormat);
        }

        let mask = u64::from_str_radix(hex, 16).map_err(|_| PermissionMaskError::InvalidFormat)?;
        Self::from_known_mask(mask).ok_or(PermissionMaskError::ReservedBits)
    }

    /// Parse a comma-separated list of permission names.
    ///
    /// An empty string means no permissions. Whitespace around names is
    /// ignored; unknown or empty names are rejected.
    pub fn parse_list(value: &str) -> Result<Self, PermissionNameError> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(Self::NONE);
        }

        let mut mask = 0;
        for name in value.split(',') {
            let name = name.trim();
            if name.is_empty() {
                return Err(PermissionNameError::EmptyName);
            }
            let permission =
                Permission::from_name(name).ok_or_else(|| PermissionNameError::Unknown {
                    name: name.to_string(),
                })?;
            mask |= permission.bit();
        }
        Ok(Self(mask))
    }

    pub const fn contains(self, permission: Permission) -> bool {
        self.0 & permission.bit() != 0
    }

    /// Raw mask value. Only known bits can be present in a `PermissionSet`.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Permission names present in the set, in protocol bit order.
    pub fn names(self) -> Vec<&'static str> {
        Permission::all()
            .iter()
            .filter(|permission| self.contains(**permission))
            .map(|permission| permission.as_str())
            .collect()
    }

    /// Canonical SAN URI value: `0x` followed by 16 lowercase hex digits.
    pub fn uri_value(self) -> String {
        format!("0x{:016x}", self.0)
    }
}

/// Error returned when parsing a permission mask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PermissionMaskError {
    #[error("invalid permission mask format")]
    InvalidFormat,
    #[error("permission mask sets reserved bits")]
    ReservedBits,
}

/// Error returned when parsing permission names.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PermissionNameError {
    #[error("unknown permission: {name}")]
    Unknown { name: String },
    #[error("empty permission name")]
    EmptyName,
}

/// Returns whether `value` is a valid principal or holder identifier.
///
/// Identifiers are non-empty, at most [`MAX_IDENTITY_LEN`] bytes and contain no
/// control characters. They are embedded verbatim in X.509 SAN URIs.
pub fn is_valid_identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_IDENTITY_LEN && !value.chars().any(char::is_control)
}

/// Build the principal SAN URI using the default prefix.
pub fn principal_uri(principal: &str) -> String {
    format!("{DEFAULT_PRINCIPAL_URI_PREFIX}{principal}")
}

/// Build a holder SAN URI using the default prefix.
pub fn holder_uri(holder_id: &str) -> String {
    format!("{DEFAULT_HOLDER_URI_PREFIX}{holder_id}")
}

/// Build the permission SAN URI using the default prefix.
pub fn permission_uri(permissions: PermissionSet) -> String {
    format!("{DEFAULT_PERMISSION_URI_PREFIX}{}", permissions.uri_value())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_bits_are_stable_and_disjoint() {
        let mut seen = 0;
        for permission in Permission::all() {
            let bit = permission.bit();
            assert_eq!(bit.count_ones(), 1);
            assert_eq!(seen & bit, 0, "duplicate bit for {}", permission.as_str());
            seen |= bit;
        }
        assert_eq!(seen, KNOWN_MASK);
        assert_eq!(KNOWN_MASK, 0x0000_0000_0000_00ff);
    }

    #[test]
    fn parses_short_and_prefixed_masks() {
        assert_eq!(PermissionSet::parse("1").unwrap().bits(), UNSEAL_START);
        assert_eq!(
            PermissionSet::parse("0x00000000000000c0").unwrap().bits(),
            KEY_SIGN | KEY_READ
        );
        assert_eq!(PermissionSet::parse("0XFF").unwrap().bits(), 0xff);
        assert_eq!(PermissionSet::parse("0").unwrap(), PermissionSet::NONE);
    }

    #[test]
    fn rejects_reserved_bits_and_malformed_masks() {
        for value in [
            "0x100",               // bit 8, reserved for future key.destroy
            "0x200",               // bit 9, reserved for future audit.read
            "0x400",               // bit 10
            "0x8000000000000000",  // bit 63
            "0xffffffffffffffff",  // all ones
            "0x10000000000000000", // 17 hex digits
            "",
            "0x",
            "-1",
            "0xzz",
            " 1",
        ] {
            assert!(PermissionSet::parse(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn parses_permission_names() {
        let set =
            PermissionSet::parse_list("key.read, key.sign,unseal.start").expect("valid names");
        assert_eq!(set.bits(), KEY_READ | KEY_SIGN | UNSEAL_START);
        assert_eq!(set.names(), vec!["unseal.start", "key.read", "key.sign"]);
        assert_eq!(PermissionSet::parse_list("").unwrap(), PermissionSet::NONE);
        assert!(PermissionSet::parse_list("key.read,").is_err());
        assert!(PermissionSet::parse_list("key.export").is_err());
    }

    #[test]
    fn builds_canonical_san_uris() {
        let set = PermissionSet::parse_list("key.read,key.sign").unwrap();
        assert_eq!(set.uri_value(), "0x00000000000000c0");
        assert_eq!(principal_uri("alice"), "signer://principal/alice");
        assert_eq!(holder_uri("holder-1"), "signer://holder/holder-1");
        assert_eq!(
            permission_uri(set),
            "signer://permissions/0x00000000000000c0"
        );
    }

    #[test]
    fn validates_identity_names() {
        assert!(is_valid_identity("alice"));
        assert!(!is_valid_identity(""));
        assert!(!is_valid_identity("ali\nce"));
        assert!(!is_valid_identity(&"a".repeat(MAX_IDENTITY_LEN + 1)));
    }

    #[test]
    fn contains_only_known_bits() {
        let set = PermissionSet::parse("0xc0").unwrap();
        assert!(set.contains(Permission::KeySign));
        assert!(set.contains(Permission::KeyRead));
        assert!(!set.contains(Permission::KeyCreate));
        assert_eq!(PermissionSet::NONE.bits(), 0);
    }
}
