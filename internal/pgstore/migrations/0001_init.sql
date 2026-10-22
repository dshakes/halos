-- 0001: shared state for HA halo-server and halo-shadow (ADR-0021).
-- Forward-only: never edit a released migration; add the next number.

-- Append-only record logs, one stream per halo-server store (devices,
-- requests, session-revocations, killswitch, controller-state). Appends to a
-- stream are serialized by an advisory lock, so ids commit in order and a
-- replica tailing "id > cursor" never skips a row.
CREATE TABLE halo_journal (
    id         BIGSERIAL PRIMARY KEY,
    stream     TEXT        NOT NULL,
    rkey       TEXT,
    body       BYTEA       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX halo_journal_stream_id ON halo_journal (stream, id);
CREATE INDEX halo_journal_stream_key ON halo_journal (stream, rkey) WHERE rkey IS NOT NULL;

-- Short-lived single-use state: enrollment tokens, consumed OIDC states,
-- server-side sessions, approval claims.
CREATE TABLE halo_kv (
    ns         TEXT        NOT NULL,
    rkey       TEXT        NOT NULL,
    val        BYTEA       NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (ns, rkey)
);
CREATE INDEX halo_kv_expires ON halo_kv (expires_at);

-- The hash-chained audit log. seq is the primary key, so even a broken
-- writer cannot fork the chain: two entries can never share a sequence.
-- Appends lock the single head row (SELECT ... FOR UPDATE).
CREATE TABLE halo_audit (
    seq   BIGINT      PRIMARY KEY,
    hash  TEXT        NOT NULL UNIQUE,
    prev  TEXT        NOT NULL,
    entry BYTEA       NOT NULL,
    at    TIMESTAMPTZ NOT NULL
);
CREATE TABLE halo_audit_head (
    id   BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    seq  BIGINT  NOT NULL,
    hash TEXT    NOT NULL
);
INSERT INTO halo_audit_head (id, seq, hash) VALUES (true, 0, '');

-- Latest fleet report per reporter, plus a bounded per-reporter history.
CREATE TABLE halo_reports (
    rkey       TEXT        PRIMARY KEY,
    hostname   TEXT        NOT NULL,
    report     BYTEA       NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE halo_report_history (
    id     BIGSERIAL PRIMARY KEY,
    rkey   TEXT      NOT NULL,
    report BYTEA     NOT NULL
);
CREATE INDEX halo_report_history_key ON halo_report_history (rkey, id);

-- Whole documents (rollout state, one per rollout).
CREATE TABLE halo_docs (
    kind       TEXT        NOT NULL,
    name       TEXT        NOT NULL,
    body       BYTEA       NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (kind, name)
);

-- Leader leases. token is the fencing token: it grows every time the lease
-- changes hands, and fenced writes check it.
CREATE TABLE halo_leases (
    name       TEXT        PRIMARY KEY,
    holder     TEXT        NOT NULL,
    token      BIGINT      NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

-- halo-shadow pairs: body is the exact FileStore JSONL row (sealed with
-- AES-GCM when a pair key is configured).
CREATE TABLE halo_shadow_pairs (
    id   TEXT        PRIMARY KEY,
    at   TIMESTAMPTZ NOT NULL,
    body BYTEA       NOT NULL
);
CREATE INDEX halo_shadow_pairs_at ON halo_shadow_pairs (at);

-- Global halo-shadow spend: reserve with a conditional UPDATE, settle later.
-- A reservation whose worker died is reaped at expiry and charged in full.
CREATE TABLE halo_shadow_budget (
    scope    TEXT             PRIMARY KEY,
    spent    DOUBLE PRECISION NOT NULL DEFAULT 0,
    reserved DOUBLE PRECISION NOT NULL DEFAULT 0
);
CREATE TABLE halo_shadow_reservations (
    id         TEXT             PRIMARY KEY,
    scope      TEXT             NOT NULL,
    amount     DOUBLE PRECISION NOT NULL,
    expires_at TIMESTAMPTZ      NOT NULL
);
CREATE INDEX halo_shadow_reservations_scope ON halo_shadow_reservations (scope, expires_at);
