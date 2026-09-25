-- Rust-owned cross-city authorization schema (durable records only).
--
-- This migration creates the six Rust-owned tables that carry the cross-city
-- durable state (operation / vote / city-state / gate / outbox / inbox). It is
-- additive and idempotent: every statement is a creator guarded by IF NOT
-- EXISTS, so the explicit Rust migration job can safely retry after an
-- interrupted DDL batch. It does not backfill, alter, or drop anything, and it
-- does not wire any runtime: cross-city mode stays default-off
-- (CROSS_CITY_MODE_DEFAULT_ENABLED = false in astral-types) and no service
-- reads or writes these tables until a later, separately reviewed change set
-- connects them. Creating the schema does not enable the feature.
--
-- Canonical identity and hash boundary (must match the astral-types
-- cross_city contracts):
-- 1. operation_id columns store the canonical text form of the typed
--    cross-city operation id: lowercase hyphenated 36-character UUID, exactly
--    as produced and enforced by the contract's operation-id normalization.
--    Never uppercase, braced, urn: or binary re-encodings.
-- 2. All *_digest / content_hash / lease_token_hash BINARY(32) columns store
--    raw SHA-256 digests. The cross-city typed contracts derive every digest
--    (proposal / frontier / mutation / evidence / certificate / agreement) as
--    a lowercase 64-character hex SHA-256 string; writers decode the hex into
--    32 raw bytes, readers re-encode to compare. No other algorithm or length
--    may be stored in these columns.
-- 3. DATETIME columns are UTC wall-clock values and the session time_zone
--    must stay '+00:00'. Contract expiry instants (UTC Unix seconds) convert
--    at the repository boundary exactly like the other auth DATETIME columns.
--
-- State machines are deliberately NOT encoded as CHECK constraints or
-- triggers: the closed operation-state set (PROPOSED / VOTING / AGREED /
-- PREPARING / PREPARED / ACTIVATING / IN_DOUBT / ACTIVE / REJECTED / DEFERRED
-- / QUARANTINED / EXPIRED), the closed decision set (ALLOW / DENY), the
-- two-city agreement rule, and every transition rule are owned and enforced
-- by astral-types plus the future PolicyEngine-side gate. The database
-- enforces exactly the durable guarantees a schema can prove: primary keys,
-- unique keys, scope/tenant indexes and lease-scan indexes. The fail-closed
-- defaults below are chosen so a row that skipped its writer can never widen
-- authorization: the gate defaults to BLOCKED, an operation to PROPOSED, and
-- work items to PENDING.
--
-- Foreign keys are intentionally omitted. Cross-city evidence must remain
-- queryable and auditable after any related row expires or is removed, and
-- the future repository must enforce operation/vote/city-state/gate/outbox/
-- inbox consistency inside its own transaction boundaries plus generation and
-- token fences, not through cascading DDL that would couple independent
-- durable writes into one source transaction. Referential validation is
-- therefore a repository responsibility: a missing parent row must surface as
-- a fail-closed write error, never as a cascade or a silent skip.
--
-- Identifier length bound: city_id / source_city_id / destination_city_id /
-- node_id / nonce are VARCHAR(191) so the composite unique and scan keys stay
-- far below the InnoDB 3072-byte index-key limit under utf8mb4. Identifiers
-- longer than this schema bound are rejected at the repository boundary
-- (fail-closed write error), which is strictly safer than a prefix-indexed
-- longer column that could collide on a truncated prefix.
--
-- Outbox routing direction: authorization_cross_city_outbox carries explicit
-- source_city_id / destination_city_id columns as durable routing evidence
-- (source_city_id mirrors the inbox field name); an ambiguous city_id is
-- deliberately not used. The direction-scoped scan indexes (source_city_id,
-- phase) and (destination_city_id, phase) back send-queue and delivery
-- monitoring per city and phase; the message-id primary key keeps every send
-- idempotent.
--
-- Vote anti-overwrite: authorization_cross_city_vote rows are insert-only
-- durable evidence. UNIQUE KEY uk_accv_node (operation_id, city_id, node_id)
-- admits exactly one row per node, so a second write for the same node fails
-- instead of replacing it, and UNIQUE KEY uk_accv_nonce (operation_id, nonce)
-- makes a nonce single-use inside one operation across cities. Repositories
-- must issue plain INSERTs and treat duplicate-key errors as durable conflicts
-- to audit - never as upserts over evidence columns. A divergent frontier or
-- nonce for the same operation+city therefore surfaces as an auditable
-- conflict, never as a silent swap of stored evidence.
--
-- Rollback (structure only; rehearse before use): the six tables own no
-- baseline data, so reverse-order drops are sufficient and re-applying this
-- migration afterwards is the documented forward path:
--   DROP TABLE authorization_cross_city_inbox
--   DROP TABLE authorization_cross_city_outbox
--   DROP TABLE authorization_cross_city_gate
--   DROP TABLE authorization_cross_city_city_state
--   DROP TABLE authorization_cross_city_vote
--   DROP TABLE authorization_cross_city_operation

CREATE TABLE IF NOT EXISTS authorization_cross_city_operation (
    operation_id           CHAR(36) NOT NULL COMMENT 'canonical cross-city operation_id: lowercase hyphenated UUID',
    scope_digest           BINARY(32) NOT NULL,
    request_digest         BINARY(32) NOT NULL,
    mutation_digest        BINARY(32) NOT NULL,
    base_frontier_digest   BINARY(32) NOT NULL,
    base_source_generation BIGINT NOT NULL,
    base_revoke_fence      BIGINT NOT NULL DEFAULT 0,
    target_generation      BIGINT NOT NULL,
    target_revoke_fence    BIGINT NOT NULL DEFAULT 0,
    proposal_digest        BINARY(32) NOT NULL,
    compiler_version       VARCHAR(64) NOT NULL,
    policy_version         VARCHAR(64) NOT NULL,
    home_city              VARCHAR(191) NOT NULL,
    coordinator_epoch      BIGINT NOT NULL DEFAULT 1 COMMENT 'monotonic coordinator epoch fence',
    state                  VARCHAR(32) NOT NULL DEFAULT 'PROPOSED' COMMENT 'closed set owned by astral-types; no CHECK by design',
    agreement_digest       BINARY(32) NULL COMMENT 'agreement certificate digest once two cities certified',
    expires_at             DATETIME NOT NULL,
    last_error             VARCHAR(512) NULL,
    created_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at             DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (operation_id),
    KEY idx_acco_state_expiry (state, expires_at, operation_id),
    KEY idx_acco_home_city (home_city, state, operation_id),
    KEY idx_acco_scope_target (scope_digest, target_generation)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Durable cross-city authorization operation root (default-off subsystem)';

CREATE TABLE IF NOT EXISTS authorization_cross_city_vote (
    vote_id         BIGINT NOT NULL AUTO_INCREMENT,
    operation_id    CHAR(36) NOT NULL,
    city_id         VARCHAR(191) NOT NULL,
    node_id         VARCHAR(191) NOT NULL,
    node_epoch      BIGINT NOT NULL,
    decision        VARCHAR(16) NOT NULL COMMENT 'ALLOW or DENY; no default so every recorded decision is explicit',
    proposal_digest BINARY(32) NOT NULL,
    frontier_digest BINARY(32) NOT NULL,
    mutation_digest BINARY(32) NOT NULL,
    evidence_digest BINARY(32) NOT NULL,
    nonce           VARCHAR(191) NOT NULL,
    signature       VARCHAR(4096) NOT NULL COMMENT 'opaque node signature over evidence_digest',
    expires_at      DATETIME NOT NULL,
    observed_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (vote_id),
    UNIQUE KEY uk_accv_node (operation_id, city_id, node_id),
    UNIQUE KEY uk_accv_nonce (operation_id, nonce),
    KEY idx_accv_decision (operation_id, decision, city_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Insert-only per-node cross-city vote evidence; duplicate keys are durable conflicts, never overwrites';

CREATE TABLE IF NOT EXISTS authorization_cross_city_city_state (
    state_id           BIGINT NOT NULL AUTO_INCREMENT,
    operation_id       CHAR(36) NOT NULL,
    city_id            VARCHAR(191) NOT NULL,
    phase              VARCHAR(32) NOT NULL DEFAULT 'PROPOSED' COMMENT 'city-side phase mirror of the operation state set',
    local_base_digest  BINARY(32) NOT NULL,
    commit_digest      BINARY(32) NULL,
    pointer_digest     BINARY(32) NULL,
    certificate_digest BINARY(32) NULL COMMENT 'city vote certificate digest once the city certified',
    lease_owner        VARCHAR(128) NULL,
    lease_token_hash   BINARY(32) NULL,
    lease_expires_at   DATETIME NULL,
    last_error         VARCHAR(512) NULL,
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (state_id),
    UNIQUE KEY uk_accc_operation_city (operation_id, city_id),
    KEY idx_accc_phase_lease (phase, lease_expires_at, state_id),
    KEY idx_accc_city (city_id, operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Per-city durable phase and lease holder for one cross-city operation';

CREATE TABLE IF NOT EXISTS authorization_cross_city_gate (
    gate_id            BIGINT NOT NULL AUTO_INCREMENT,
    tenant_id          BIGINT NOT NULL,
    aggregate_type     VARCHAR(32) NOT NULL,
    aggregate_id       BIGINT NOT NULL,
    operation_id       CHAR(36) NOT NULL,
    certificate_digest BINARY(32) NOT NULL COMMENT 'agreement/vote certificate digest bound to the gate transition',
    target_generation  BIGINT NOT NULL,
    revoke_fence       BIGINT NOT NULL DEFAULT 0,
    state              VARCHAR(32) NOT NULL DEFAULT 'BLOCKED' COMMENT 'SYNCING/ACTIVE/BLOCKED; BLOCKED is the fail-closed default',
    content_hash       BINARY(32) NOT NULL,
    created_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (gate_id),
    UNIQUE KEY uk_accg_scope (tenant_id, aggregate_type, aggregate_id),
    KEY idx_accg_state (state, updated_at, gate_id),
    KEY idx_accg_operation (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Per-aggregate cross-city synchronization gate; BLOCKED unless explicitly enabled';

CREATE TABLE IF NOT EXISTS authorization_cross_city_outbox (
    message_id          VARCHAR(128) NOT NULL,
    operation_id        CHAR(36) NOT NULL,
    source_city_id      VARCHAR(191) NOT NULL COMMENT 'sending city; durable routing evidence, mirrors inbox source_city_id',
    destination_city_id VARCHAR(191) NOT NULL COMMENT 'target city; durable routing evidence',
    phase               VARCHAR(32) NOT NULL,
    payload_digest      BINARY(32) NOT NULL,
    payload             MEDIUMBLOB NOT NULL,
    status              VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempts            INT NOT NULL DEFAULT 0,
    next_attempt_at     DATETIME NULL,
    lease_owner         VARCHAR(128) NULL,
    lease_token_hash    BINARY(32) NULL,
    lease_expires_at    DATETIME NULL,
    last_error          VARCHAR(512) NULL,
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (message_id),
    KEY idx_accob_pending (status, next_attempt_at, created_at),
    KEY idx_accob_lease (status, lease_expires_at, message_id),
    KEY idx_accob_operation (operation_id),
    KEY idx_accob_source (source_city_id, phase),
    KEY idx_accob_destination (destination_city_id, phase)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Cross-city outbound durable work item keyed by message id (explicit source/destination routing)';

CREATE TABLE IF NOT EXISTS authorization_cross_city_inbox (
    message_id       VARCHAR(128) NOT NULL,
    operation_id     CHAR(36) NOT NULL,
    source_city_id   VARCHAR(191) NOT NULL,
    phase            VARCHAR(32) NOT NULL,
    payload_digest   BINARY(32) NOT NULL,
    status           VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    attempts         INT NOT NULL DEFAULT 0,
    lease_owner      VARCHAR(128) NULL,
    lease_token_hash BINARY(32) NULL,
    lease_expires_at DATETIME NULL,
    received_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    processed_at     DATETIME NULL,
    last_error       VARCHAR(512) NULL,
    updated_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (message_id),
    KEY idx_accib_lease (status, lease_expires_at, message_id),
    KEY idx_accib_operation (operation_id),
    KEY idx_accib_source (source_city_id, phase)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Cross-city inbound durable work item keyed by message id (idempotent receive)';
