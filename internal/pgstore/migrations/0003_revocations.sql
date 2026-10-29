-- min-binary-schema: 1
-- 0003: credential revocations (ADR-0026), shared by every halo-server
-- replica. A binary at schema 2 ignores the table (it predates revocation).

-- One row per revoked jti (kind 'jti') or per subject epoch (kind
-- 'subject': every credential issued at or before epoch, unix seconds, is
-- dead). A row lives until expires_at, past which no credential it could
-- match is still valid; reads skip expired rows and writes prune them.
-- record is the revocation as halo-server encodes it (who, why, when).
CREATE TABLE halo_revocations (
    kind       TEXT        NOT NULL,
    rkey       TEXT        NOT NULL,
    epoch      BIGINT      NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    record     BYTEA       NOT NULL,
    PRIMARY KEY (kind, rkey)
);
CREATE INDEX halo_revocations_expires ON halo_revocations (expires_at);
