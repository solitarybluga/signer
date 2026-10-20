-- signer v0.1 initial schema (SQLite)
-- Timestamps are stored as RFC3339 text; IDs are stored as UUID strings.

CREATE TABLE keys (
    id            TEXT PRIMARY KEY,
    curve         TEXT NOT NULL CHECK (curve IN ('secp256k1', 'edwards25519')),
    algorithm     TEXT NOT NULL CHECK (algorithm IN ('ecdsa', 'eddsa')),
    public_key    BLOB NOT NULL,
    ciphertext    BLOB NOT NULL,
    nonce         BLOB NOT NULL,
    wrapped_dek   BLOB NOT NULL,
    dek_nonce     BLOB NOT NULL,
    state         TEXT NOT NULL DEFAULT 'created'
                  CHECK (state IN ('created', 'active', 'rotating', 'destroyed')),
    labels        TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (curve, algorithm, public_key)
);

CREATE INDEX keys_state_idx ON keys (state);

CREATE TABLE unseal_sessions (
    id                TEXT PRIMARY KEY,
    nonce             BLOB NOT NULL,
    threshold         INTEGER NOT NULL CHECK (threshold > 0),
    shares_collected  INTEGER NOT NULL DEFAULT 0 CHECK (shares_collected >= 0),
    state             TEXT NOT NULL DEFAULT 'collecting'
                      CHECK (state IN ('collecting', 'unsealed', 'expired', 'failed')),
    expires_at        TEXT NOT NULL,
    created_at        TEXT NOT NULL
);

-- The audit log has no foreign key: records must survive key destruction.
CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    key_id      TEXT,
    session_id  TEXT,
    result      TEXT NOT NULL CHECK (result IN ('ok', 'denied', 'error')),
    metadata    TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX audit_log_ts_idx ON audit_log (ts);
CREATE INDEX audit_log_key_idx ON audit_log (key_id);
