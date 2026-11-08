-- Retain the complete validated V7 independent-completion response atomically
-- with the source outcome terminal CAS. NULL legacy rows are not terminal proof.
-- Apply only through the explicit migration job after stop/drain and preflight.
-- Interrupted execution is reentrant; existing columns must pass exact contracts.
-- Recovery preserves these receipts and reconciles stable reservation identities.
-- Rollback uses a compatible forward-fix; dropping these columns loses evidence.

SET @astral_db = DATABASE();

SET @astral_column = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authority_source_outcome'
      AND COLUMN_NAME = 'authority_terminal_kind'
);
SET @astral_sql = IF(
    @astral_column = 0,
    'ALTER TABLE authority_source_outcome ADD COLUMN authority_terminal_kind VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

SET @astral_column = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authority_source_outcome'
      AND COLUMN_NAME = 'authority_terminal_response'
);
SET @astral_sql = IF(
    @astral_column = 0,
    'ALTER TABLE authority_source_outcome ADD COLUMN authority_terminal_response JSON NULL',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

SET @astral_column = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authority_source_outcome'
      AND COLUMN_NAME = 'authority_terminal_response_digest'
);
SET @astral_sql = IF(
    @astral_column = 0,
    'ALTER TABLE authority_source_outcome ADD COLUMN authority_terminal_response_digest BINARY(32) NULL',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;
