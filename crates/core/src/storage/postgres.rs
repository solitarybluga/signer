use std::collections::BTreeMap;

use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::types::Json;
use time::OffsetDateTime;
use uuid::Uuid;

use super::convert::{
    map_sqlx_error, parse_curve, parse_key_state, parse_signature_algorithm, parse_unseal_state,
};
use super::model::{
    AuditEntry, Curve, KeyId, KeyMetadata, KeyRecord, KeyState, NewKey, Page, SessionId,
    SignatureAlgorithm, UnsealSession,
};
use super::store::{KeyStore, StorageError};

/// PostgreSQL-backed storage for multi-instance / HA deployments.
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    /// Connect to the database and run migrations.
    pub async fn connect(database_url: &str) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .map_err(map_sqlx_error)?;

        let store = Self { pool };
        store.migrate().await?;
        Ok(store)
    }

    /// Build a store from an existing connection pool.
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Run the migrations under `migrations/postgres`.
    pub async fn migrate(&self) -> Result<(), StorageError> {
        sqlx::migrate!("../../migrations/postgres")
            .run(&self.pool)
            .await
            .map_err(|e| StorageError::Internal(e.to_string()))
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[derive(sqlx::FromRow)]
struct PgKeyRow {
    id: Uuid,
    curve: String,
    algorithm: String,
    public_key: Vec<u8>,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    wrapped_dek: Vec<u8>,
    dek_nonce: Vec<u8>,
    state: String,
    labels: Json<BTreeMap<String, String>>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl TryFrom<PgKeyRow> for KeyRecord {
    type Error = StorageError;

    fn try_from(row: PgKeyRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            curve: parse_curve(&row.curve)?,
            algorithm: parse_signature_algorithm(&row.algorithm)?,
            public_key: row.public_key,
            ciphertext: row.ciphertext,
            nonce: row.nonce,
            wrapped_dek: row.wrapped_dek,
            dek_nonce: row.dek_nonce,
            state: parse_key_state(&row.state)?,
            labels: row.labels.0,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct PgKeyMetadataRow {
    id: Uuid,
    curve: String,
    algorithm: String,
    public_key: Vec<u8>,
    state: String,
    labels: Json<BTreeMap<String, String>>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl TryFrom<PgKeyMetadataRow> for KeyMetadata {
    type Error = StorageError;

    fn try_from(row: PgKeyMetadataRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            curve: parse_curve(&row.curve)?,
            algorithm: parse_signature_algorithm(&row.algorithm)?,
            public_key: row.public_key,
            state: parse_key_state(&row.state)?,
            labels: row.labels.0,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct PgSessionRow {
    id: Uuid,
    nonce: Vec<u8>,
    threshold: i32,
    shares_collected: i32,
    state: String,
    expires_at: OffsetDateTime,
    created_at: OffsetDateTime,
}

impl TryFrom<PgSessionRow> for UnsealSession {
    type Error = StorageError;

    fn try_from(row: PgSessionRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            nonce: row.nonce,
            threshold: u32::try_from(row.threshold)
                .map_err(|_| StorageError::Corrupt("threshold is negative".into()))?,
            shares_collected: u32::try_from(row.shares_collected)
                .map_err(|_| StorageError::Corrupt("shares_collected is negative".into()))?,
            state: parse_unseal_state(&row.state)?,
            expires_at: row.expires_at,
            created_at: row.created_at,
        })
    }
}

const INSERT_KEY: &str = r#"
INSERT INTO keys (
    id, curve, algorithm, public_key, ciphertext, nonce, wrapped_dek, dek_nonce, state, labels
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING
    id, curve, algorithm, public_key, ciphertext, nonce, wrapped_dek, dek_nonce,
    state, labels, created_at, updated_at
"#;

const SELECT_KEY: &str = r#"
SELECT
    id, curve, algorithm, public_key, ciphertext, nonce, wrapped_dek, dek_nonce,
    state, labels, created_at, updated_at
FROM keys
WHERE id = $1
"#;

const SELECT_KEY_METADATA: &str = r#"
SELECT id, curve, algorithm, public_key, state, labels, created_at, updated_at
FROM keys
ORDER BY created_at DESC, id ASC
LIMIT $1 OFFSET $2
"#;

const INSERT_SESSION: &str = r#"
INSERT INTO unseal_sessions (id, nonce, threshold, shares_collected, state, expires_at)
VALUES ($1, $2, $3, $4, $5, $6)
"#;

const SELECT_SESSION: &str = r#"
SELECT id, nonce, threshold, shares_collected, state, expires_at, created_at
FROM unseal_sessions
WHERE id = $1
"#;

const INSERT_AUDIT: &str = r#"
INSERT INTO audit_log (actor, action, key_id, session_id, result, metadata)
VALUES ($1, $2, $3, $4, $5, $6)
"#;

#[async_trait]
impl KeyStore for PostgresStore {
    async fn insert_key(&self, key: NewKey) -> Result<KeyRecord, StorageError> {
        let row = sqlx::query_as::<_, PgKeyRow>(INSERT_KEY)
            .bind(key.id)
            .bind(key.curve.as_str())
            .bind(key.algorithm.as_str())
            .bind(&key.public_key)
            .bind(&key.ciphertext)
            .bind(&key.nonce)
            .bind(&key.wrapped_dek)
            .bind(&key.dek_nonce)
            .bind(key.state.as_str())
            .bind(Json(key.labels.clone()))
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        KeyRecord::try_from(row)
    }

    async fn get_key(&self, id: KeyId) -> Result<Option<KeyRecord>, StorageError> {
        let row = sqlx::query_as::<_, PgKeyRow>(SELECT_KEY)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        row.map(KeyRecord::try_from).transpose()
    }

    async fn list_keys(&self, page: Page) -> Result<Vec<KeyMetadata>, StorageError> {
        let limit = i64::from(page.limit.clamp(1, 200));
        let offset = i64::from(page.offset);

        let rows = sqlx::query_as::<_, PgKeyMetadataRow>(SELECT_KEY_METADATA)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        rows.into_iter().map(KeyMetadata::try_from).collect()
    }

    async fn update_key_state(&self, id: KeyId, state: KeyState) -> Result<(), StorageError> {
        let result = sqlx::query("UPDATE keys SET state = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(state.as_str())
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
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM keys WHERE curve = $1 AND algorithm = $2 AND public_key = $3",
        )
        .bind(curve.as_str())
        .bind(algorithm.as_str())
        .bind(public_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx_error)
    }

    async fn insert_unseal_session(&self, session: &UnsealSession) -> Result<(), StorageError> {
        let threshold = i32::try_from(session.threshold)
            .map_err(|_| StorageError::Internal("threshold exceeds the i32 range".into()))?;
        let shares_collected = i32::try_from(session.shares_collected)
            .map_err(|_| StorageError::Internal("shares_collected exceeds the i32 range".into()))?;

        sqlx::query(INSERT_SESSION)
            .bind(session.id)
            .bind(&session.nonce)
            .bind(threshold)
            .bind(shares_collected)
            .bind(session.state.as_str())
            .bind(session.expires_at)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        Ok(())
    }

    async fn get_unseal_session(
        &self,
        id: SessionId,
    ) -> Result<Option<UnsealSession>, StorageError> {
        let row = sqlx::query_as::<_, PgSessionRow>(SELECT_SESSION)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

        row.map(UnsealSession::try_from).transpose()
    }

    async fn update_unseal_session(&self, session: &UnsealSession) -> Result<(), StorageError> {
        let shares_collected = i32::try_from(session.shares_collected)
            .map_err(|_| StorageError::Internal("shares_collected exceeds the i32 range".into()))?;

        let result = sqlx::query(
            "UPDATE unseal_sessions SET shares_collected = $2, state = $3 WHERE id = $1",
        )
        .bind(session.id)
        .bind(shares_collected)
        .bind(session.state.as_str())
        .execute(&self.pool)
        .await
        .map_err(map_sqlx_error)?;

        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound);
        }
        Ok(())
    }

    async fn append_audit(&self, entry: &AuditEntry) -> Result<(), StorageError> {
        sqlx::query(INSERT_AUDIT)
            .bind(&entry.actor)
            .bind(&entry.action)
            .bind(entry.key_id)
            .bind(entry.session_id)
            .bind(entry.result.as_str())
            .bind(Json(entry.metadata.clone()))
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
    use testcontainers::ImageExt;
    use testcontainers::runners::AsyncRunner;
    use testcontainers_modules::postgres::Postgres;

    fn test_key(public_key: Vec<u8>) -> NewKey {
        let mut labels = BTreeMap::new();
        labels.insert("env".to_string(), "test".to_string());

        NewKey {
            id: Uuid::new_v4(),
            curve: Curve::Secp256k1,
            algorithm: SignatureAlgorithm::Ecdsa,
            public_key,
            ciphertext: vec![9, 9, 9],
            nonce: vec![7; 24],
            wrapped_dek: vec![8; 48],
            dek_nonce: vec![6; 24],
            state: KeyState::Created,
            labels,
        }
    }

    /// Starts PostgreSQL through testcontainers; Docker must be available locally.
    #[tokio::test]
    async fn postgres_roundtrip() {
        let container = Postgres::default()
            .with_tag("16-alpine")
            .start()
            .await
            .expect("failed to start the PostgreSQL container (Docker is required)");
        let port = container
            .get_host_port_ipv4(5432)
            .await
            .expect("failed to get the PostgreSQL host port");
        let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");

        let store = PostgresStore::connect(&url).await.unwrap();

        let public_key = Uuid::new_v4().as_bytes().to_vec();
        let key = test_key(public_key.clone());
        let id = key.id;

        let record = store.insert_key(key.clone()).await.unwrap();
        assert_eq!(record.id, id);
        assert_eq!(record.labels.get("env").map(String::as_str), Some("test"));

        let fetched = store.get_key(id).await.unwrap().expect("key exists");
        assert_eq!(fetched.curve, Curve::Secp256k1);
        assert_eq!(fetched.algorithm, SignatureAlgorithm::Ecdsa);

        assert_eq!(
            store
                .find_key_id_by_public_key(
                    Curve::Secp256k1,
                    SignatureAlgorithm::Ecdsa,
                    &public_key,
                )
                .await
                .unwrap(),
            Some(id)
        );

        let duplicate = test_key(key.public_key.clone());
        let err = store.insert_key(duplicate).await.unwrap_err();
        assert!(matches!(err, StorageError::Conflict));

        store.update_key_state(id, KeyState::Active).await.unwrap();
        assert_eq!(
            store.get_key(id).await.unwrap().unwrap().state,
            KeyState::Active
        );

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
        assert_eq!(loaded.state, UnsealState::Collecting);

        loaded.shares_collected = 3;
        loaded.state = UnsealState::Unsealed;
        store.update_unseal_session(&loaded).await.unwrap();
        assert_eq!(
            store
                .get_unseal_session(session.id)
                .await
                .unwrap()
                .unwrap()
                .state,
            UnsealState::Unsealed
        );

        store
            .append_audit(&AuditEntry {
                actor: "operator".to_string(),
                action: "key.unsealed".to_string(),
                key_id: Some(id),
                session_id: Some(session.id),
                result: AuditResult::Ok,
                metadata: BTreeMap::from([("shares".to_string(), "3".to_string())]),
            })
            .await
            .unwrap();
    }
}
