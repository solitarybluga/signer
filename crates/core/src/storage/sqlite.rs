use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use time::OffsetDateTime;

use super::convert::{
    format_labels, format_time, map_sqlx_error, parse_curve, parse_key_state, parse_labels,
    parse_signature_algorithm, parse_time, parse_unseal_state, parse_uuid,
};
use super::model::{
    AuditEntry, Curve, KeyId, KeyMetadata, KeyRecord, KeyState, NewKey, Page, SessionId,
    SignatureAlgorithm, UnsealSession,
};
use super::store::{KeyStore, StorageError};

/// SQLite-backed storage for single-node deployments and tests.
///
/// The pool is limited to a single connection: SQLite has a single writer, so
/// this avoids write contention.
pub struct SqliteStore {
    pool: SqlitePool,
}

impl SqliteStore {
    /// Open the database (creating it if needed) and run migrations.
    pub async fn connect(database_url: &str) -> Result<Self, StorageError> {
        let options = SqliteConnectOptions::from_str(database_url)
            .map_err(map_sqlx_error)?
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(map_sqlx_error)?;

        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    /// Build a store from an existing connection pool.
    pub fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Run the migrations under `migrations/sqlite`.
    pub async fn migrate(&self) -> Result<(), StorageError> {
        sqlx::migrate!("../../migrations/sqlite")
            .run(&self.pool)
            .await
            .map_err(|e| StorageError::Internal(e.to_string()))
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[derive(sqlx::FromRow)]
struct SqliteKeyRow {
    id: String,
    curve: String,
    algorithm: String,
    public_key: Vec<u8>,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    wrapped_dek: Vec<u8>,
    dek_nonce: Vec<u8>,
    state: String,
    labels: String,
    created_at: String,
    updated_at: String,
}

impl TryFrom<SqliteKeyRow> for KeyRecord {
    type Error = StorageError;

    fn try_from(row: SqliteKeyRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: parse_uuid(&row.id)?,
            curve: parse_curve(&row.curve)?,
            algorithm: parse_signature_algorithm(&row.algorithm)?,
            public_key: row.public_key,
            ciphertext: row.ciphertext,
            nonce: row.nonce,
            wrapped_dek: row.wrapped_dek,
            dek_nonce: row.dek_nonce,
            state: parse_key_state(&row.state)?,
            labels: parse_labels(&row.labels)?,
            created_at: parse_time(&row.created_at)?,
            updated_at: parse_time(&row.updated_at)?,
        })
    }
}

#[derive(sqlx::FromRow)]
struct SqliteKeyMetadataRow {
    id: String,
    curve: String,
    algorithm: String,
    public_key: Vec<u8>,
    state: String,
    labels: String,
    created_at: String,
    updated_at: String,
}

impl TryFrom<SqliteKeyMetadataRow> for KeyMetadata {
    type Error = StorageError;

    fn try_from(row: SqliteKeyMetadataRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: parse_uuid(&row.id)?,
            curve: parse_curve(&row.curve)?,
            algorithm: parse_signature_algorithm(&row.algorithm)?,
            public_key: row.public_key,
            state: parse_key_state(&row.state)?,
            labels: parse_labels(&row.labels)?,
            created_at: parse_time(&row.created_at)?,
            updated_at: parse_time(&row.updated_at)?,
        })
    }
}

#[derive(sqlx::FromRow)]
struct SqliteSessionRow {
    id: String,
    nonce: Vec<u8>,
    threshold: i64,
    shares_collected: i64,
    state: String,
    expires_at: String,
    created_at: String,
}

impl TryFrom<SqliteSessionRow> for UnsealSession {
    type Error = StorageError;

    fn try_from(row: SqliteSessionRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: parse_uuid(&row.id)?,
            nonce: row.nonce,
            threshold: u32::try_from(row.threshold)
                .map_err(|_| StorageError::Corrupt("threshold exceeds the u32 range".into()))?,
            shares_collected: u32::try_from(row.shares_collected).map_err(|_| {
                StorageError::Corrupt("shares_collected exceeds the u32 range".into())
            })?,
            state: parse_unseal_state(&row.state)?,
            expires_at: parse_time(&row.expires_at)?,
            created_at: parse_time(&row.created_at)?,
        })
    }
}

const INSERT_KEY: &str = r#"
INSERT INTO keys (
    id, curve, algorithm, public_key, ciphertext, nonce, wrapped_dek, dek_nonce,
    state, labels, created_at, updated_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING
    id, curve, algorithm, public_key, ciphertext, nonce, wrapped_dek, dek_nonce,
    state, labels, created_at, updated_at
"#;

const SELECT_KEY: &str = r#"
SELECT
    id, curve, algorithm, public_key, ciphertext, nonce, wrapped_dek, dek_nonce,
    state, labels, created_at, updated_at
FROM keys
WHERE id = ?
"#;

const SELECT_KEY_METADATA: &str = r#"
SELECT id, curve, algorithm, public_key, state, labels, created_at, updated_at
FROM keys
ORDER BY created_at DESC, id ASC
LIMIT ? OFFSET ?
"#;

const INSERT_SESSION: &str = r#"
INSERT INTO unseal_sessions (
    id, nonce, threshold, shares_collected, state, expires_at, created_at
)
VALUES (?, ?, ?, ?, ?, ?, ?)
"#;

const SELECT_SESSION: &str = r#"
SELECT id, nonce, threshold, shares_collected, state, expires_at, created_at
FROM unseal_sessions
WHERE id = ?
"#;

const INSERT_AUDIT: &str = r#"
INSERT INTO audit_log (ts, actor, action, key_id, session_id, result, metadata)
VALUES (?, ?, ?, ?, ?, ?, ?)
"#;

#[async_trait]
impl KeyStore for SqliteStore {
    async fn insert_key(&self, key: NewKey) -> Result<KeyRecord, StorageError> {
        let now = format_time(OffsetDateTime::now_utc())?;
        let labels = format_labels(&key.labels)?;

        let row = sqlx::query_as::<_, SqliteKeyRow>(INSERT_KEY)
            .bind(key.id.to_string())
            .bind(key.curve.as_str())
            .bind(key.algorithm.as_str())
            .bind(&key.public_key)
            .bind(&key.ciphertext)
            .bind(&key.nonce)
            .bind(&key.wrapped_dek)
            .bind(&key.dek_nonce)
            .bind(key.state.as_str())
            .bind(labels)
            .bind(&now)
            .bind(&now)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        KeyRecord::try_from(row)
    }

    async fn get_key(&self, id: KeyId) -> Result<Option<KeyRecord>, StorageError> {
        let row = sqlx::query_as::<_, SqliteKeyRow>(SELECT_KEY)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        row.map(KeyRecord::try_from).transpose()
    }

    async fn list_keys(&self, page: Page) -> Result<Vec<KeyMetadata>, StorageError> {
        let limit = i64::from(page.limit.clamp(1, 200));
        let offset = i64::from(page.offset);

        let rows = sqlx::query_as::<_, SqliteKeyMetadataRow>(SELECT_KEY_METADATA)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        rows.into_iter().map(KeyMetadata::try_from).collect()
    }

    async fn update_key_state(&self, id: KeyId, state: KeyState) -> Result<(), StorageError> {
        let now = format_time(OffsetDateTime::now_utc())?;

        let result = sqlx::query("UPDATE keys SET state = ?, updated_at = ? WHERE id = ?")
            .bind(state.as_str())
            .bind(now)
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    async fn find_key_id_by_public_key(
        &self,
        curve: Curve,
        algorithm: SignatureAlgorithm,
        public_key: &[u8],
    ) -> Result<Option<KeyId>, StorageError> {
        let id = sqlx::query_scalar::<_, String>(
            "SELECT id FROM keys WHERE curve = ? AND algorithm = ? AND public_key = ?",
        )
        .bind(curve.as_str())
        .bind(algorithm.as_str())
        .bind(public_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        id.map(|value| parse_uuid(&value)).transpose()
    }

    async fn insert_unseal_session(&self, session: &UnsealSession) -> Result<(), StorageError> {
        let created_at = format_time(session.created_at)?;
        let expires_at = format_time(session.expires_at)?;

        sqlx::query(INSERT_SESSION)
            .bind(session.id.to_string())
            .bind(&session.nonce)
            .bind(i64::from(session.threshold))
            .bind(i64::from(session.shares_collected))
            .bind(session.state.as_str())
            .bind(expires_at)
            .bind(created_at)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_unseal_session(
        &self,
        id: SessionId,
    ) -> Result<Option<UnsealSession>, StorageError> {
        let row = sqlx::query_as::<_, SqliteSessionRow>(SELECT_SESSION)
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        row.map(UnsealSession::try_from).transpose()
    }

    async fn update_unseal_session(&self, session: &UnsealSession) -> Result<(), StorageError> {
        let result =
            sqlx::query("UPDATE unseal_sessions SET shares_collected = ?, state = ? WHERE id = ?")
                .bind(i64::from(session.shares_collected))
                .bind(session.state.as_str())
                .bind(session.id.to_string())
                .execute(&self.pool)
                .await
                .map_err(map_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    async fn append_audit(&self, entry: &AuditEntry) -> Result<(), StorageError> {
        let ts = format_time(OffsetDateTime::now_utc())?;
        let metadata = format_labels(&entry.metadata)?;

        sqlx::query(INSERT_AUDIT)
            .bind(ts)
            .bind(&entry.actor)
            .bind(&entry.action)
            .bind(entry.key_id.map(|id| id.to_string()))
            .bind(entry.session_id.map(|id| id.to_string()))
            .bind(entry.result.as_str())
            .bind(metadata)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::model::{AuditResult, UnsealState};
    use std::collections::BTreeMap;
    use uuid::Uuid;

    fn test_key() -> NewKey {
        let mut labels = BTreeMap::new();
        labels.insert("env".to_string(), "test".to_string());

        NewKey {
            id: Uuid::new_v4(),
            curve: Curve::Secp256k1,
            algorithm: SignatureAlgorithm::Ecdsa,
            public_key: vec![1, 2, 3, 4],
            ciphertext: vec![9, 9, 9],
            nonce: vec![7; 24],
            wrapped_dek: vec![8; 48],
            dek_nonce: vec![6; 24],
            state: KeyState::Created,
            labels,
        }
    }

    #[tokio::test]
    async fn key_roundtrip_conflict_and_metadata() {
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();
        let key = test_key();
        let id = key.id;

        let record = store.insert_key(key.clone()).await.unwrap();
        assert_eq!(record.id, id);
        assert_eq!(record.public_key, vec![1, 2, 3, 4]);
        assert_eq!(record.labels.get("env").map(String::as_str), Some("test"));

        let debug = format!("{record:?}");
        assert!(!debug.contains("ciphertext"));
        assert!(!debug.contains("wrapped_dek"));

        let fetched = store.get_key(id).await.unwrap().expect("key exists");
        assert_eq!(fetched.curve, Curve::Secp256k1);
        assert_eq!(fetched.algorithm, SignatureAlgorithm::Ecdsa);

        let listed = store.list_keys(Page::default()).await.unwrap();
        assert_eq!(listed.len(), 1);

        let found = store
            .find_key_id_by_public_key(Curve::Secp256k1, SignatureAlgorithm::Ecdsa, &[1, 2, 3, 4])
            .await
            .unwrap();
        assert_eq!(found, Some(id));

        let mut duplicate = test_key();
        duplicate.public_key = vec![1, 2, 3, 4];
        let err = store.insert_key(duplicate).await.unwrap_err();
        assert!(matches!(err, StorageError::Conflict));

        store.update_key_state(id, KeyState::Active).await.unwrap();
        assert_eq!(
            store.get_key(id).await.unwrap().unwrap().state,
            KeyState::Active
        );
    }

    #[tokio::test]
    async fn unseal_session_roundtrip() {
        let store = SqliteStore::connect("sqlite::memory:").await.unwrap();

        let session = UnsealSession {
            id: Uuid::new_v4(),
            nonce: vec![5; 32],
            threshold: 3,
            shares_collected: 1,
            state: UnsealState::Collecting,
            expires_at: OffsetDateTime::now_utc() + time::Duration::minutes(10),
            created_at: OffsetDateTime::now_utc(),
        };

        store.insert_unseal_session(&session).await.unwrap();

        let mut loaded = store
            .get_unseal_session(session.id)
            .await
            .unwrap()
            .expect("session exists");
        assert_eq!(loaded.threshold, 3);
        assert_eq!(loaded.shares_collected, 1);
        assert_eq!(loaded.state, UnsealState::Collecting);

        loaded.shares_collected = 3;
        loaded.state = UnsealState::Unsealed;
        store.update_unseal_session(&loaded).await.unwrap();

        let reloaded = store
            .get_unseal_session(session.id)
            .await
            .unwrap()
            .expect("session still exists");
        assert_eq!(reloaded.shares_collected, 3);
        assert_eq!(reloaded.state, UnsealState::Unsealed);

        store
            .append_audit(&AuditEntry {
                actor: "operator".to_string(),
                action: "key.unsealed".to_string(),
                key_id: None,
                session_id: Some(session.id),
                result: AuditResult::Ok,
                metadata: BTreeMap::from([("shares".to_string(), "3".to_string())]),
            })
            .await
            .unwrap();
    }
}
