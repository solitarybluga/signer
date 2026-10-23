//! Client certificate permission bits.
//!
//! The bit assignments below are a protocol: append-only, never reordered or
//! reused. Reserved bits must be zero; a certificate that sets one is rejected
//! instead of being interpreted with partial or future semantics.

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

/// Bits currently understood by this server.
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

    #[cfg(test)]
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

    pub const fn contains(self, permission: Permission) -> bool {
        self.0 & permission.bit() != 0
    }

    #[cfg(test)]
    pub const fn bits(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionMaskError {
    InvalidFormat,
    ReservedBits,
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
    fn contains_only_known_bits() {
        let set = PermissionSet::parse("0xc0").unwrap();
        assert!(set.contains(Permission::KeySign));
        assert!(set.contains(Permission::KeyRead));
        assert!(!set.contains(Permission::KeyCreate));
        assert_eq!(PermissionSet::NONE.bits(), 0);
    }
}
