-- signer v0.1 initial schema (PostgreSQL)

CREATE TABLE keys (
    id            UUID        PRIMARY KEY,
    curve         TEXT        NOT NULL CHECK (curve IN ('secp256k1', 'edwards25519')),
    algorithm     TEXT        NOT NULL CHECK (algorithm IN ('ecdsa', 'eddsa')),
    public_key    BYTEA       NOT NULL,
    ciphertext    BYTEA       NOT NULL,
    nonce         BYTEA       NOT NULL,
    wrapped_dek   BYTEA       NOT NULL,
    dek_nonce     BYTEA       NOT NULL,
    state         TEXT        NOT NULL DEFAULT 'created'
                              CHECK (state IN ('created', 'active', 'rotating', 'destroyed')),
    labels        JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT keys_public_key_unique UNIQUE (curve, algorithm, public_key)
);

CREATE INDEX keys_state_idx ON keys (state);

CREATE TABLE unseal_sessions (
    id                UUID        PRIMARY KEY,
    nonce             BYTEA       NOT NULL,
    threshold         INTEGER     NOT NULL CHECK (threshold > 0),
    shares_collected  INTEGER     NOT NULL DEFAULT 0 CHECK (shares_collected >= 0),
    state             TEXT        NOT NULL DEFAULT 'collecting'
                                  CHECK (state IN ('collecting', 'unsealed', 'expired', 'failed')),
    expires_at        TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The audit log has no foreign key: records must survive key destruction.
CREATE TABLE audit_log (
    id          BIGSERIAL   PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor       TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    key_id      UUID,
    session_id  UUID,
    result      TEXT        NOT NULL CHECK (result IN ('ok', 'denied', 'error')),
    metadata    JSONB       NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX audit_log_ts_idx ON audit_log (ts);
CREATE INDEX audit_log_key_idx ON audit_log (key_id);
