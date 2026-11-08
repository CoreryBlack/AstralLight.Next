-- Non-authorization business owners commit this result with their own mutation.
-- Admission proof consumption remains in authorization_admission_use.
CREATE TABLE IF NOT EXISTS protected_mutation_operation (
    operation_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    resource VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    request_digest BINARY(32) NOT NULL,
    result_json JSON NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (operation_id, resource),
    KEY idx_pmo_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
