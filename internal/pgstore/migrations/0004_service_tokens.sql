-- min-binary-schema: 1
-- 0004: service-account API tokens (ADR-0036), shared by every halo-server
-- replica. A binary at schema 3 ignores the table (it predates the tokens and
-- accepts none).

-- One row per token. id is the token's public id (embedded in the token);
-- hash is the SHA-256 of the whole token, compared in constant time; the
-- token itself is never stored. A row is checked on every request that
-- presents its token, so a revocation on any replica holds on every replica
-- at once. Rows are pruned 30 days after they expire; record is the token's
-- metadata as halo-server encodes it (name, role, owner, who created and
-- revoked it, when, why).
CREATE TABLE halo_service_tokens (
    id         TEXT        PRIMARY KEY,
    hash       BYTEA       NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked    BOOLEAN     NOT NULL DEFAULT FALSE,
    record     BYTEA       NOT NULL
);
CREATE INDEX halo_service_tokens_expires ON halo_service_tokens (expires_at);
