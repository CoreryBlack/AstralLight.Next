-- Additive recovery evidence for CURRENT V6 switch-card operations.
-- Never edit an applied migration; this migration only extends the durable
-- operation contract used by the Identity recovery worker.
--
-- MySQL 8 has no ADD COLUMN IF NOT EXISTS syntax. Each additive column is
-- guarded by an information_schema probe and a prepared DDL/no-op statement.
SET @aso_db = DATABASE();

SET @aso_column_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @aso_db AND TABLE_NAME = 'auth_session_operation'
      AND COLUMN_NAME = 'selected_identity_card_id');
SET @aso_ddl = IF(@aso_column_count = 0,
    'ALTER TABLE auth_session_operation ADD COLUMN selected_identity_card_id BIGINT DEFAULT NULL',
    'SELECT 1 AS selected_identity_card_id_already_present');
PREPARE aso_stmt FROM @aso_ddl; EXECUTE aso_stmt; DEALLOCATE PREPARE aso_stmt;

SET @aso_column_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @aso_db AND TABLE_NAME = 'auth_session_operation'
      AND COLUMN_NAME = 'source_card_id');
SET @aso_ddl = IF(@aso_column_count = 0,
    'ALTER TABLE auth_session_operation ADD COLUMN source_card_id BIGINT DEFAULT NULL',
    'SELECT 1 AS source_card_id_already_present');
PREPARE aso_stmt FROM @aso_ddl; EXECUTE aso_stmt; DEALLOCATE PREPARE aso_stmt;

SET @aso_column_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @aso_db AND TABLE_NAME = 'auth_session_operation'
      AND COLUMN_NAME = 'previous_session_version');
SET @aso_ddl = IF(@aso_column_count = 0,
    'ALTER TABLE auth_session_operation ADD COLUMN previous_session_version BIGINT DEFAULT NULL',
    'SELECT 1 AS previous_session_version_already_present');
PREPARE aso_stmt FROM @aso_ddl; EXECUTE aso_stmt; DEALLOCATE PREPARE aso_stmt;

SET @aso_column_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @aso_db AND TABLE_NAME = 'auth_session_operation'
      AND COLUMN_NAME = 'previous_session_epoch');
SET @aso_ddl = IF(@aso_column_count = 0,
    'ALTER TABLE auth_session_operation ADD COLUMN previous_session_epoch BIGINT DEFAULT NULL',
    'SELECT 1 AS previous_session_epoch_already_present');
PREPARE aso_stmt FROM @aso_ddl; EXECUTE aso_stmt; DEALLOCATE PREPARE aso_stmt;

SET @aso_column_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @aso_db AND TABLE_NAME = 'auth_session_operation'
      AND COLUMN_NAME = 'expected_session_version');
SET @aso_ddl = IF(@aso_column_count = 0,
    'ALTER TABLE auth_session_operation ADD COLUMN expected_session_version BIGINT DEFAULT NULL',
    'SELECT 1 AS expected_session_version_already_present');
PREPARE aso_stmt FROM @aso_ddl; EXECUTE aso_stmt; DEALLOCATE PREPARE aso_stmt;

SET @aso_column_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @aso_db AND TABLE_NAME = 'auth_session_operation'
      AND COLUMN_NAME = 'expected_session_epoch');
SET @aso_ddl = IF(@aso_column_count = 0,
    'ALTER TABLE auth_session_operation ADD COLUMN expected_session_epoch BIGINT DEFAULT NULL',
    'SELECT 1 AS expected_session_epoch_already_present');
PREPARE aso_stmt FROM @aso_ddl; EXECUTE aso_stmt; DEALLOCATE PREPARE aso_stmt;

SET @aso_column_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @aso_db AND TABLE_NAME = 'auth_session_operation'
      AND COLUMN_NAME = 'device_id');
SET @aso_ddl = IF(@aso_column_count = 0,
    'ALTER TABLE auth_session_operation ADD COLUMN device_id VARCHAR(255) DEFAULT NULL',
    'SELECT 1 AS device_id_already_present');
PREPARE aso_stmt FROM @aso_ddl; EXECUTE aso_stmt; DEALLOCATE PREPARE aso_stmt;

SET @aso_column_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @aso_db AND TABLE_NAME = 'auth_session_operation'
      AND COLUMN_NAME = 'new_refresh_token_hash');
SET @aso_ddl = IF(@aso_column_count = 0,
    'ALTER TABLE auth_session_operation ADD COLUMN new_refresh_token_hash CHAR(64) DEFAULT NULL',
    'SELECT 1 AS new_refresh_token_hash_already_present');
PREPARE aso_stmt FROM @aso_ddl; EXECUTE aso_stmt; DEALLOCATE PREPARE aso_stmt;

SET @aso_column_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @aso_db AND TABLE_NAME = 'auth_session_operation'
      AND COLUMN_NAME = 'new_refresh_expires_at');
SET @aso_ddl = IF(@aso_column_count = 0,
    'ALTER TABLE auth_session_operation ADD COLUMN new_refresh_expires_at DATETIME DEFAULT NULL',
    'SELECT 1 AS new_refresh_expires_at_already_present');
PREPARE aso_stmt FROM @aso_ddl; EXECUTE aso_stmt; DEALLOCATE PREPARE aso_stmt;

SET @aso_column_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @aso_db AND TABLE_NAME = 'auth_session_operation'
      AND COLUMN_NAME = 'recovery_attempts');
SET @aso_ddl = IF(@aso_column_count = 0,
    'ALTER TABLE auth_session_operation ADD COLUMN recovery_attempts INT NOT NULL DEFAULT 0',
    'SELECT 1 AS recovery_attempts_already_present');
PREPARE aso_stmt FROM @aso_ddl; EXECUTE aso_stmt; DEALLOCATE PREPARE aso_stmt;

SET @aso_column_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @aso_db AND TABLE_NAME = 'auth_session_operation'
      AND COLUMN_NAME = 'recovery_claim_owner');
SET @aso_ddl = IF(@aso_column_count = 0,
    'ALTER TABLE auth_session_operation ADD COLUMN recovery_claim_owner VARCHAR(64) DEFAULT NULL',
    'SELECT 1 AS recovery_claim_owner_already_present');
PREPARE aso_stmt FROM @aso_ddl; EXECUTE aso_stmt; DEALLOCATE PREPARE aso_stmt;

SET @aso_column_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @aso_db AND TABLE_NAME = 'auth_session_operation'
      AND COLUMN_NAME = 'recovery_claim_expires_at');
SET @aso_ddl = IF(@aso_column_count = 0,
    'ALTER TABLE auth_session_operation ADD COLUMN recovery_claim_expires_at DATETIME DEFAULT NULL',
    'SELECT 1 AS recovery_claim_expires_at_already_present');
PREPARE aso_stmt FROM @aso_ddl; EXECUTE aso_stmt; DEALLOCATE PREPARE aso_stmt;

SET @aso_column_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @aso_db AND TABLE_NAME = 'auth_session_operation'
      AND COLUMN_NAME = 'last_error');
SET @aso_ddl = IF(@aso_column_count = 0,
    'ALTER TABLE auth_session_operation ADD COLUMN last_error VARCHAR(255) DEFAULT NULL',
    'SELECT 1 AS last_error_already_present');
PREPARE aso_stmt FROM @aso_ddl; EXECUTE aso_stmt; DEALLOCATE PREPARE aso_stmt;

-- MySQL 8 does not support CREATE INDEX IF NOT EXISTS; repair the index
-- idempotently without changing any historical migration.
SET @aso_index_count = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @aso_db
      AND TABLE_NAME = 'auth_session_operation'
      AND INDEX_NAME = 'idx_aso_recovery_status'
);
SET @aso_ddl = IF(
    @aso_index_count = 0,
    'CREATE INDEX idx_aso_recovery_status ON auth_session_operation (status, updated_at, recovery_attempts)',
    'SELECT 1 AS aso_recovery_index_already_present'
);
PREPARE aso_stmt FROM @aso_ddl;
EXECUTE aso_stmt;
DEALLOCATE PREPARE aso_stmt;
