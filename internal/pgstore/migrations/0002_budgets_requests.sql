-- 0002: gateway budget ledger (ADR-0017) and the pending access-request
-- uniqueness claim, shared by every halo-server replica (ADR-0021).

-- One row per counter bucket: budget name, counter key ("user:<id>", "org",
-- ...) and the bucket's start (unix seconds). Usage is added in place.
CREATE TABLE halo_budget_buckets (
    budget TEXT             NOT NULL,
    rkey   TEXT             NOT NULL,
    bucket BIGINT           NOT NULL,
    usd    DOUBLE PRECISION NOT NULL DEFAULT 0,
    tokens BIGINT           NOT NULL DEFAULT 0,
    PRIMARY KEY (budget, rkey, bucket)
);

-- Usage batch ids already applied: the primary key makes a retried batch a
-- no-op even when two replicas receive it at once.
CREATE TABLE halo_budget_batches (
    batch      TEXT        PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX halo_budget_batches_applied ON halo_budget_batches (applied_at);

-- At most one pending access request per (user, kind, item): the primary key
-- is the uniqueness check, request_id names the request holding it.
CREATE TABLE halo_request_pending (
    dedupe     TEXT PRIMARY KEY,
    request_id TEXT        NOT NULL,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
