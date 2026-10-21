//! Storage models and persistence interfaces.
//!
//! This module defines data structures and storage contracts only; it contains
//! no cryptographic logic.

mod convert;
mod model;
mod postgres;
mod sqlite;
mod store;

pub use model::{
    AuditEntry, AuditResult, Curve, KeyId, KeyMetadata, KeyRecord, KeyState, NewKey, Page,
    SessionId, SignatureAlgorithm, UnsealSession, UnsealState,
};
pub use postgres::PostgresStore;
pub use sqlite::SqliteStore;
pub use store::{KeyStore, StorageError};
