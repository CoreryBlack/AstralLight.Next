-- V7 local projections of the independent quorum. No row here grants authority.
-- Startup and request owners populate these only after pinned-chain verification.
CREATE TABLE IF NOT EXISTS authorization_global_projection (
    projection_id BIGINT NOT NULL,
    authority_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    authority_term BIGINT NOT NULL,
    global_fence_sequence BIGINT NOT NULL,
    key_epoch BIGINT NOT NULL,
    chain_digest BINARY(32) NOT NULL,
    frontier_json JSON NOT NULL,
    observed_at BIGINT NOT NULL,
    PRIMARY KEY (projection_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS authorization_scope_certificate (
    scope_hash BINARY(32) NOT NULL,
    certificate_hash BINARY(32) NOT NULL,
    certificate_json JSON NOT NULL,
    observed_at BIGINT NOT NULL,
    PRIMARY KEY (scope_hash),
    UNIQUE KEY uk_asc_certificate (certificate_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS authorization_request_proof (
    proof_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    request_nonce VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    scope_hash BINARY(32) NOT NULL,
    certificate_hash BINARY(32) NOT NULL,
    request_digest BINARY(32) NOT NULL,
    proof_json JSON NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY (proof_id),
    UNIQUE KEY uk_arp_nonce (request_nonce),
    KEY idx_arp_expiry (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS authorization_source_reservation (
    operation_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    proof_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    request_digest BINARY(32) NOT NULL,
    reservation_json JSON NOT NULL,
    disposition VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (operation_id),
    UNIQUE KEY uk_asr_proof (proof_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
