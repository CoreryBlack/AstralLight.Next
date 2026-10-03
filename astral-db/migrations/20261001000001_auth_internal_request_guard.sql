-- Durable internal request guard for Redis-free Gateway authentication.
--
-- ADDITIVE migration (Rust-owned). replaces the Redis SET NX EX replay and
-- idempotency markers used by the Gateway internal session route with durable
-- MySQL rows: the UNIQUE KEY (guard_scope, guard_key) is the distributed
-- mutex, and expires_at carries the TTL (callers purge expired rows before
-- re-claiming, which reproduces SET NX EX semantics across nodes).
--
-- No raw credentials or secrets are stored. `marker` values are opaque
-- markers ("1", "processing:{sha256}", "completed:{sha256}") with the same
-- shape as the previous Redis values.
--
-- NOTE: written as part of the Redis-free session path change; NOT executed
-- by the implementation task. Deployment must run migrations per
-- Docs/迁移/README.md (preflight + backup/restore drill) before enabling the
-- Redis-free Gateway authentication path.

CREATE TABLE IF NOT EXISTS auth_internal_request_guard (
    guard_id   BIGINT NOT NULL AUTO_INCREMENT,
    guard_scope VARCHAR(64) NOT NULL,
    guard_key  VARCHAR(255) NOT NULL,
    marker     VARCHAR(128) NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (guard_id),
    UNIQUE KEY uk_airg_scope_key (guard_scope, guard_key),
    KEY idx_airg_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
