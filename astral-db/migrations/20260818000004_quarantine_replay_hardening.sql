-- Harden the Rust-owned audit quarantine replay boundary without mutating the
-- already-pushed 20260818000003 checksum.
--
-- Existing plaintext lease values are invalidated before the new hash/fencing
-- columns are used. Legacy REPLAYING rows are returned to QUARANTINED because
-- they have no operation identity that can be safely recovered. Operators must
-- create an explicit REPLAY_REQUESTED marker before a worker can claim them.
-- Conditional DDL remains compatible with MySQL 5.7 and 8.0.

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'audit_quarantine'
      AND COLUMN_NAME = 'replay_lease_token_hash'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE audit_quarantine ADD COLUMN replay_lease_token_hash BINARY(32) NULL AFTER replay_lease_owner',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'audit_quarantine'
      AND COLUMN_NAME = 'replay_lease_generation'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE audit_quarantine ADD COLUMN replay_lease_generation BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER replay_lease_token_hash',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'audit_quarantine'
      AND COLUMN_NAME = 'replay_operation_id_hash'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE audit_quarantine ADD COLUMN replay_operation_id_hash BINARY(32) NULL AFTER replay_lease_generation',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'audit_quarantine'
      AND COLUMN_NAME = 'replay_requested_by'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE audit_quarantine ADD COLUMN replay_requested_by VARCHAR(128) NULL AFTER replay_operation_id_hash',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'audit_quarantine'
      AND COLUMN_NAME = 'replay_requested_at'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE audit_quarantine ADD COLUMN replay_requested_at DATETIME NULL AFTER replay_requested_by',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

-- Invalidate secrets written by the old implementation. Never migrate a
-- plaintext token into a new hash column because its original operation and
-- fencing generation are not recoverable.
UPDATE audit_quarantine
SET replay_lease_token = NULL,
    replay_lease_token_hash = NULL,
    replay_lease_generation = replay_lease_generation + 1
WHERE replay_lease_token IS NOT NULL;

-- Old REPLAYING rows cannot be confirmed safely after token invalidation. Put
-- them back into the ordinary quarantine state; an operator must request a new
-- replay with an explicit operation identity.
UPDATE audit_quarantine
SET status = 'QUARANTINED',
    replay_lease_owner = NULL,
    replay_lease_token_hash = NULL,
    replay_lease_expires_at = NULL,
    replay_operation_id_hash = NULL,
    replay_requested_by = NULL,
    replay_requested_at = NULL,
    replayed_at = NULL
WHERE status = 'REPLAYING';

SET @astral_index = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = DATABASE()
      AND TABLE_NAME = 'audit_quarantine'
      AND INDEX_NAME = 'idx_aq_replay_request'
);
SET @astral_sql = IF(
    @astral_index = 0,
    'ALTER TABLE audit_quarantine ADD INDEX idx_aq_replay_request (status, replay_requested_at, id)',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;
