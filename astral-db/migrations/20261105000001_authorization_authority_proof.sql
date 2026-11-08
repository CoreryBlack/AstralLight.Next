-- Durable storage for externally issued authorization-fence proofs.
--
-- This migration creates verification records only. It does not mint a proof,
-- advance an authority frontier, or grant any application permission. The
-- authority writer must own the frontier/proof write transaction and publish a
-- fully signed, request-bound proof before a reader can consume it.
--
-- Proof rows are immutable by contract. The reader reserves a separate
-- authority-specific replay key in auth_internal_request_guard; a duplicate or
-- unknown reservation result never becomes an authorization success.

CREATE TABLE IF NOT EXISTS authorization_authority_frontier (
    frontier_id BIGINT NOT NULL,
    authority_id VARCHAR(128) NOT NULL,
    authority_term BIGINT NOT NULL,
    global_fence_sequence BIGINT NOT NULL,
    key_id VARCHAR(128) NOT NULL,
    key_epoch BIGINT NOT NULL,
    status VARCHAR(16) NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (frontier_id),
    UNIQUE KEY uk_aaf_authority (authority_id),
    KEY idx_aaf_status (status, updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS authorization_authority_proof (
    proof_id VARCHAR(128) NOT NULL,
    request_nonce VARCHAR(255) NOT NULL,
    authorization_edition SMALLINT UNSIGNED NOT NULL,
    authority_id VARCHAR(128) NOT NULL,
    authority_term BIGINT NOT NULL,
    global_fence_sequence BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    card_id BIGINT NOT NULL,
    scope_user_id BIGINT NULL,
    scope_domain_kind VARCHAR(16) NOT NULL,
    scope_domain_id BIGINT NULL,
    scope_generation BIGINT NOT NULL,
    revoke_watermark BIGINT NOT NULL,
    snapshot_hash BINARY(32) NOT NULL,
    parent_hash BINARY(32) NULL,
    operation_id VARCHAR(128) NOT NULL,
    event_id VARCHAR(128) NOT NULL,
    key_id VARCHAR(128) NOT NULL,
    key_epoch BIGINT NOT NULL,
    issued_at BIGINT NOT NULL,
    not_before BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    signature BINARY(64) NOT NULL,
    status VARCHAR(16) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (proof_id),
    UNIQUE KEY uk_aap_request_nonce (request_nonce),
    KEY idx_aap_scope_frontier (tenant_id, card_id, scope_generation, global_fence_sequence),
    KEY idx_aap_operation_event (operation_id, event_id),
    KEY idx_aap_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- A signed lease from the external arbiter. The authority signer consumes one
-- READY lease exactly once while inserting the corresponding proof. The lease
-- is a capability, not a source of global ordering; its term/fence must match
-- the locked frontier before it can be consumed.
CREATE TABLE IF NOT EXISTS authorization_authority_issuance_lease (
    lease_id VARCHAR(128) NOT NULL,
    request_nonce VARCHAR(255) NOT NULL,
    authorization_edition SMALLINT UNSIGNED NOT NULL,
    authority_id VARCHAR(128) NOT NULL,
    authority_term BIGINT NOT NULL,
    global_fence_sequence BIGINT NOT NULL,
    previous_authority_term BIGINT NOT NULL,
    previous_global_fence_sequence BIGINT NOT NULL,
    previous_key_id VARCHAR(128) NOT NULL,
    previous_key_epoch BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    card_id BIGINT NOT NULL,
    scope_user_id BIGINT NULL,
    scope_domain_kind VARCHAR(16) NOT NULL,
    scope_domain_id BIGINT NULL,
    scope_generation BIGINT NOT NULL,
    revoke_watermark BIGINT NOT NULL,
    snapshot_hash BINARY(32) NOT NULL,
    parent_hash BINARY(32) NULL,
    operation_id VARCHAR(128) NOT NULL,
    event_id VARCHAR(128) NOT NULL,
    key_id VARCHAR(128) NOT NULL,
    key_epoch BIGINT NOT NULL,
    issued_at BIGINT NOT NULL,
    not_before BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    arbiter_id VARCHAR(128) NOT NULL,
    arbiter_key_id VARCHAR(128) NOT NULL,
    arbiter_key_epoch BIGINT NOT NULL,
    arbiter_signature BINARY(64) NOT NULL,
    status VARCHAR(16) NOT NULL,
    consumed_at BIGINT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (lease_id),
    UNIQUE KEY uk_aail_request_nonce (request_nonce),
    KEY idx_aail_frontier (authority_id, authority_term, global_fence_sequence),
    KEY idx_aail_operation_event (operation_id, event_id),
    KEY idx_aail_expiry (expires_at),
    KEY idx_aail_status (status, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
