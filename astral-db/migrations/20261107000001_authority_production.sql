-- V7 admission consumption belongs to the same transaction as its source write.
-- No existing proof, source, migration checksum, or generation is rewritten.
-- Unknown source COMMIT must reconcile this exact identity before any retry.
CREATE TABLE IF NOT EXISTS authorization_admission_use (
    proof_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    request_nonce VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    operation_id VARCHAR(128) NOT NULL,
    event_id VARCHAR(128) NOT NULL,
    authority_id VARCHAR(128) NOT NULL,
    authority_term BIGINT NOT NULL,
    global_fence_sequence BIGINT NOT NULL,
    key_epoch BIGINT NOT NULL,
    proof_digest BINARY(32) NOT NULL,
    consumed_at BIGINT NOT NULL,
    PRIMARY KEY (proof_id),
    UNIQUE KEY uk_aau_request_nonce (request_nonce),
    KEY idx_aau_operation_event (operation_id, event_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
