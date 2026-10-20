# 存储

> 状态：草稿。

## 需求

- 支持 ACID 事务与密钥 ID 唯一约束。
- 多个 signer 实例可安全并发访问。
- 静态加密由应用层完成；数据库只存密文。
- 备份与时间点恢复要简单可靠。
- 单机开发后端不依赖外部服务。

## 后端

| 后端 | 并发 | 高可用 | 使用场景 |
| --- | --- | --- | --- |
| SQLite | 单写者 | 无 | 开发、单机演示 |
| PostgreSQL | 多写者 | 流复制 / Patroni | 集群 |

LevelDB 是一类常见的嵌入式存储方案。它没有复制能力，也无法多实例共享，因此无法提供高可用。见 [ADR-0001](adr/0001-tech-stack.md)。

## Trait

```rust
#[async_trait]
pub trait KeyStore: Send + Sync {
    async fn insert_key(&self, key: NewKey) -> Result<KeyRecord, StorageError>;
    async fn get_key(&self, id: KeyId) -> Result<Option<KeyRecord>, StorageError>;
    async fn list_keys(&self, page: Page) -> Result<Vec<KeyMetadata>, StorageError>;
    async fn update_key_state(&self, id: KeyId, state: KeyState) -> Result<(), StorageError>;
    async fn find_key_id_by_public_key(
        &self,
        curve: Curve,
        algorithm: SignatureAlgorithm,
        public_key: &[u8],
    ) -> Result<Option<KeyId>, StorageError>;
    async fn insert_unseal_session(&self, session: &UnsealSession) -> Result<(), StorageError>;
    async fn get_unseal_session(&self, id: SessionId) -> Result<Option<UnsealSession>, StorageError>;
    async fn update_unseal_session(&self, session: &UnsealSession) -> Result<(), StorageError>;
    async fn append_audit(&self, entry: &AuditEntry) -> Result<(), StorageError>;
}
```

实现位于 `src/storage/postgres.rs` 与 `src/storage/sqlite.rs`。

trait 不得暴露明文密钥材料。加密发生在 `keystore` 组件中，存储层只看到不透明字节。

## 表结构

### `keys`

| 列 | 类型 | 说明 |
| --- | --- | --- |
| `id` | uuid / text | 主键 |
| `curve` | text | `secp256k1` 或 `edwards25519` |
| `algorithm` | text | `ecdsa` 或 `eddsa` |
| `public_key` | bytea | 验签需要 |
| `ciphertext` | bytea | 用 DEK 加密后的私钥 |
| `nonce` | bytea | 加密私钥的 AEAD nonce |
| `wrapped_dek` | bytea | 用 KEK 包裹后的 DEK |
| `dek_nonce` | bytea | 包裹 DEK 的 AEAD nonce |
| `state` | text | `created` / `active` / `rotating` / `destroyed` |
| `created_at`, `updated_at` | timestamptz | UTC |

数据库只保存两层密文；没有 KEK 或明文 DEK，任何字段都无法解密私钥。对 `(curve, algorithm, public_key)` 建唯一索引，防止重复导入。

### `unseal_sessions`

| 列 | 类型 | 说明 |
| --- | --- | --- |
| `id` | uuid | 主键 |
| `nonce` | bytea | 会话绑定 |
| `threshold` | int | 所需份额数 |
| `state` | text | `collecting` / `unsealed` / `expired` / `failed` |
| `expires_at` | timestamptz | 短有效期 |

说明：会话目前也持久化，便于后续支持断点续传与审计；如改为纯内存实现，必须保证重启后会话一律失效。

### `audit_log`

| 列 | 类型 | 说明 |
| --- | --- | --- |
| `id` | bigserial | 主键 |
| `ts` | timestamptz | 默认 now() |
| `actor` | text | 已认证身份 |
| `action` | text | 如 `sign.requested` |
| `key_id` | uuid | 可空 |
| `result` | text | `ok` / `denied` / `error` |
| `metadata` | jsonb | 绝不能包含秘密 |

## 并发与锁

- 密钥生命周期操作（`rotate`、`destroy`）使用行锁或 advisory lock。
- 签名读取无锁；已解封的密钥在轮换前不可变。
- 多实例部署必须保证单个密钥的破坏性操作只有一个实例执行。

## 迁移

- 使用 sqlx 迁移，按方言分目录：`migrations/postgres/`、`migrations/sqlite/`。
- 迁移只允许向前，并在两种后端上测试（如支持）。
- 应用启动时通过 `sqlx::migrate!` 自动执行。

## 备份与恢复

- 备份数据库，不备份 KEK 与份额。
- 每季度在预发环境演练一次恢复。
- 明确可接受的数据丢失（RPO）与停机时间（RTO）。

## 待决问题

- [ ] 审计 metadata 用 JSONB，还是规范化以便跨数据库迁移？
- [ ] SQLite 不支持 advisory lock，是否只允许单写者模式？
- [ ] `audit_log` 的保留策略与分区方案？
