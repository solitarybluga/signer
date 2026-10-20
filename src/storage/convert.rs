use std::collections::BTreeMap;

use sqlx::error::DatabaseError;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use super::model::{AuditResult, Curve, KeyState, SignatureAlgorithm, UnsealState};
use super::store::StorageError;

pub(crate) fn parse_curve(value: &str) -> Result<Curve, StorageError> {
    Curve::parse(value).ok_or_else(|| StorageError::Corrupt(format!("unknown curve: {value}")))
}

pub(crate) fn parse_signature_algorithm(value: &str) -> Result<SignatureAlgorithm, StorageError> {
    SignatureAlgorithm::parse(value)
        .ok_or_else(|| StorageError::Corrupt(format!("unknown signature algorithm: {value}")))
}

pub(crate) fn parse_key_state(value: &str) -> Result<KeyState, StorageError> {
    KeyState::parse(value)
        .ok_or_else(|| StorageError::Corrupt(format!("unknown key state: {value}")))
}

pub(crate) fn parse_unseal_state(value: &str) -> Result<UnsealState, StorageError> {
    UnsealState::parse(value)
        .ok_or_else(|| StorageError::Corrupt(format!("unknown unseal state: {value}")))
}

pub(crate) fn parse_audit_result(value: &str) -> Result<AuditResult, StorageError> {
    AuditResult::parse(value)
        .ok_or_else(|| StorageError::Corrupt(format!("unknown audit result: {value}")))
}

pub(crate) fn parse_uuid(value: &str) -> Result<Uuid, StorageError> {
    Uuid::parse_str(value).map_err(|e| StorageError::Corrupt(format!("invalid UUID: {e}")))
}

pub(crate) fn parse_time(value: &str) -> Result<OffsetDateTime, StorageError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|e| StorageError::Corrupt(format!("invalid timestamp: {e}")))
}

pub(crate) fn format_time(value: OffsetDateTime) -> Result<String, StorageError> {
    value
        .format(&Rfc3339)
        .map_err(|e| StorageError::Internal(format!("failed to format timestamp: {e}")))
}

pub(crate) fn parse_labels(value: &str) -> Result<BTreeMap<String, String>, StorageError> {
    serde_json::from_str(value)
        .map_err(|e| StorageError::Corrupt(format!("invalid labels JSON: {e}")))
}

pub(crate) fn format_labels(labels: &BTreeMap<String, String>) -> Result<String, StorageError> {
    serde_json::to_string(labels)
        .map_err(|e| StorageError::Internal(format!("failed to serialize labels: {e}")))
}

/// Map sqlx errors to storage errors so upper layers stay database-agnostic.
pub(crate) fn map_sqlx_error(err: sqlx::Error) -> StorageError {
    match &err {
        sqlx::Error::RowNotFound => StorageError::NotFound,
        sqlx::Error::Database(db) if db.is_unique_violation() => StorageError::Conflict,
        sqlx::Error::Decode(_) => StorageError::Corrupt(err.to_string()),
        _ => StorageError::Unavailable(err.to_string()),
    }
}
