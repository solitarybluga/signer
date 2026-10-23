//! Re-export the shared permission protocol definitions.
//!
//! The bit assignments live in `signer-permissions` so the server, the CA
//! issuer and the desktop client all use exactly one mapping.

pub use signer_permissions::*;
