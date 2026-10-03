-- Rust-owned cross-city runtime proof schema (durable records only).
--
-- This migration creates the five additional tables that carry the cross-city
-- RUNTIME PROOF state for the default-off cross-city subsystem described by
-- the astral-types cross-city contracts:
--
-- - authorization_cross_city_node_key: the durable node key registry. One row
--   per exact (city_id, node_id, node_epoch) carries the exact Ed25519 public
--   key (raw 32 bytes) and a revoked flag. A revoked row is never usable: the
--   repository resolver treats revoked or missing identities exactly like an
--   unregistered identity (fail-closed UNKNOWN key), never guessing a
--   neighboring epoch, node, or city. Key material enters only through the
--   repository boundary; no code path may substitute an in-memory map.
-- - authorization_cross_city_vote_reservation: the durable replay reservation
--   ledger. The unique replay key (city_id, node_id, node_epoch, nonce,
--   evidence_digest) is EXACTLY the cross-city signature boundary's replay
--   identity. The reservation INSERT and the verified vote INSERT share ONE
--   short source transaction: either both commit or neither does, so a stored
--   vote can never exist without its proof of cryptographic verification.
-- - authorization_cross_city_commit_receipt: insert-only, signed durable
--   receipts proving a city durably applied the mutation to its own source
--   (external-city source-apply evidence). Every receipt binds the exact
--   operation, proposal, generation, revoke fence, coordinator epoch, and the
--   signed node evidence; activation minting consumes ONLY these durable
--   rows - never a confirm message, a cache entry, or a boolean.
-- - authorization_cross_city_operation_activation: one durable mint record
--   per activated operation (primary key = operation_id), pinning the
--   agreement digest, the derived commit digest, the scope digest, target
--   generation/fence, and the coordinator epoch under which the commit was
--   confirmed. The row is the idempotency + audit witness of the mint
--   primitive.
-- - authorization_cross_city_authority_scope: the explicit authoritative
--   city-scope registry. Each row declares that ONE city is authoritative for
--   ONE authorization scope digest. A city without a registered authoritative
--   row for the operation's scope is refused (fail-closed): independent-city
--   data-source boundaries are never guessed, never inferred from vote or
--   transport liveness, and never widened by an absent configuration.
--
-- Like `20260831000002_cross_city_schema.sql`, this migration is additive and
-- idempotent: every statement is a creator guarded by IF NOT EXISTS, so the
-- explicit Rust migration job can safely retry after an interrupted DDL
-- batch. It does not backfill, alter, or drop anything, and it does not wire
-- any runtime: cross-city mode stays default-off
-- (CROSS_CITY_MODE_DEFAULT_ENABLED = false in astral-types), the coordinator
-- is constructed disabled unless an explicit, auditable enablement decision
-- is made, and missing configuration is refused, never defaulted.
--
-- Canonical identity and hash boundary (identical to the sibling migration):
-- 1. operation_id columns store the canonical text form of the typed
--    cross-city operation id: lowercase hyphenated 36-character UUID.
-- 2. Every *_digest BINARY(32) column stores a raw SHA-256 digest; the wire
--    form is the lowercase 64-character hex string.
-- 3. DATETIME columns are UTC wall-clock values and the session time_zone
--    must stay '+00:00'.
--
-- State machines stay OUT of the schema: no CHECK constraints and no
-- triggers. The closed operation-state set, the two-city agreement rule, and
-- every transition rule are owned by astral-types plus the repository layer.
-- Fail-closed defaults: a reservation/receipt/activation row that skipped its
-- writer can never widen authorization, because writers (not readers) create
-- these rows and every reader re-validates bindings fail-closed.
--
-- Foreign keys are intentionally omitted (same rationale as the sibling
-- migration): evidence must stay queryable and auditable after any related
-- row expires, and consistency is enforced by the repositories inside their
-- own transaction boundaries with the fixed lock order
-- operation -> (vote | city_state | gate | receipt | reservation). A missing
-- parent row surfaces as a fail-closed write error, never as a cascade or a
-- silent skip.
--
-- Identifier length bound: city_id / node_id / nonce are VARCHAR(191) so the
-- composite unique keys stay far below the InnoDB 3072-byte index-key limit
-- under utf8mb4. Over-long identifiers are rejected at the repository
-- boundary (fail-closed write error) before any SQL runs.
--
-- Anti-overwrite: all three evidence tables are INSERT-ONLY.
-- authorization_cross_city_vote_reservation carries UNIQUE KEY
-- uk_accvr_replay_key over the exact replay identity, so a replayed evidence
-- fails the reservation INSERT itself - the earliest possible durable
-- blocking point - and repositories treat duplicate-key errors as durable
-- conflicts to audit, never as upserts. authorization_cross_city_commit_receipt
-- carries UNIQUE KEY uk_acccr_node (operation_id, city_id, node_id) so one
-- node can never silently replace its own receipt, and UNIQUE KEY
-- uk_acccr_nonce (operation_id, nonce) so a nonce is single-use per
-- operation. authorization_cross_city_operation_activation carries the
-- operation id as its PRIMARY KEY, so a second mint for one operation can
-- only ever re-produce the SAME durable record; any disagreement is an
-- immutable conflict, never an overwrite.
--
-- Rollback (structure only; rehearse before use): the five tables own no
-- baseline data, so reverse-order drops are sufficient and re-applying this
-- migration afterwards is the documented forward path:
--   DROP TABLE authorization_cross_city_authority_scope
--   DROP TABLE authorization_cross_city_operation_activation
--   DROP TABLE authorization_cross_city_commit_receipt
--   DROP TABLE authorization_cross_city_vote_reservation
--   DROP TABLE authorization_cross_city_node_key

CREATE TABLE IF NOT EXISTS authorization_cross_city_node_key (
    node_key_id    BIGINT NOT NULL AUTO_INCREMENT,
    city_id        VARCHAR(191) NOT NULL,
    node_id        VARCHAR(191) NOT NULL,
    node_epoch     BIGINT NOT NULL COMMENT 'positive epoch of the node software/state',
    public_key     BINARY(32) NOT NULL COMMENT 'exact raw Ed25519 public key of this identity',
    revoked        TINYINT(1) NOT NULL DEFAULT 0 COMMENT '1 = key withdrawn; resolver fails closed on revoked identities',
    registered_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at     DATETIME NULL,
    revoked_reason VARCHAR(512) NULL,
    PRIMARY KEY (node_key_id),
    UNIQUE KEY uk_accnk_identity (city_id, node_id, node_epoch),
    KEY idx_accnk_revoked (revoked, node_key_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Durable cross-city node key registry keyed by exact city/node/epoch identity (default-off subsystem)';

CREATE TABLE IF NOT EXISTS authorization_cross_city_vote_reservation (
    reservation_id  BIGINT NOT NULL AUTO_INCREMENT,
    operation_id    CHAR(36) NOT NULL COMMENT 'operation the evidence was admitted for (audit binding)',
    city_id         VARCHAR(191) NOT NULL,
    node_id         VARCHAR(191) NOT NULL,
    node_epoch      BIGINT NOT NULL,
    nonce           VARCHAR(191) NOT NULL,
    evidence_digest BINARY(32) NOT NULL,
    reserved_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (reservation_id),
    UNIQUE KEY uk_accvr_replay_key (city_id, node_id, node_epoch, nonce, evidence_digest),
    KEY idx_accvr_operation (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Durable replay reservation over the exact signature-boundary replay key; committed in the same transaction as the vote insert';

CREATE TABLE IF NOT EXISTS authorization_cross_city_commit_receipt (
    receipt_id        BIGINT NOT NULL AUTO_INCREMENT,
    operation_id      CHAR(36) NOT NULL,
    city_id           VARCHAR(191) NOT NULL,
    node_id           VARCHAR(191) NOT NULL,
    node_epoch        BIGINT NOT NULL,
    decision          VARCHAR(16) NOT NULL COMMENT 'ALLOW only; no default so every recorded decision is explicit',
    proposal_digest   BINARY(32) NOT NULL,
    evidence_digest   BINARY(32) NOT NULL COMMENT 'digest of the signed node evidence inside this receipt',
    target_generation BIGINT NOT NULL,
    revoke_fence      BIGINT NOT NULL DEFAULT 0,
    coordinator_epoch BIGINT NOT NULL,
    nonce             VARCHAR(191) NOT NULL,
    signature         VARCHAR(4096) NOT NULL COMMENT 'opaque node signature over the evidence digest',
    observed_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (receipt_id),
    UNIQUE KEY uk_acccr_node (operation_id, city_id, node_id),
    UNIQUE KEY uk_acccr_nonce (operation_id, nonce),
    KEY idx_acccr_operation_city (operation_id, city_id, decision)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Insert-only signed durable source-apply receipt per city/node; the only activation-mint input (default-off subsystem)';

CREATE TABLE IF NOT EXISTS authorization_cross_city_operation_activation (
    operation_id      CHAR(36) NOT NULL COMMENT 'canonical cross-city operation_id; one durable mint record per operation',
    agreement_digest  BINARY(32) NOT NULL,
    commit_digest     BINARY(32) NOT NULL COMMENT 'canonical digest derived from the durable two-city commit receipts at mint time',
    scope_digest      BINARY(32) NOT NULL,
    target_generation BIGINT NOT NULL,
    revoke_fence      BIGINT NOT NULL DEFAULT 0,
    coordinator_epoch BIGINT NOT NULL,
    minted_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (operation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Durable idempotency+audit witness of one commit-confirmed activation mint per operation (default-off subsystem)';

CREATE TABLE IF NOT EXISTS authorization_cross_city_authority_scope (
    scope_id      BIGINT NOT NULL AUTO_INCREMENT,
    city_id       VARCHAR(191) NOT NULL,
    scope_digest  BINARY(32) NOT NULL COMMENT 'digest of the authorization scope the city is authoritative for',
    authoritative TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'only an explicit 1 admits the city for the scope; absent rows are refused',
    registered_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (scope_id),
    UNIQUE KEY uk_accas_city_scope (city_id, scope_digest),
    KEY idx_accas_scope (scope_digest, authoritative)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Explicit authoritative city-scope registry; missing configuration is refused, never guessed (default-off subsystem)';
