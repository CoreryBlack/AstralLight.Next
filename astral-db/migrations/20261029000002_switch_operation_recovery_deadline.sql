-- Add bounded durable recovery retention for CURRENT V6 switch-card operations.
-- This is additive and forward-only; it does not rewrite or remove historical facts.
-- MySQL 8 has no ADD COLUMN IF NOT EXISTS syntax, so the additive column is
-- guarded by an information_schema probe and a prepared DDL/no-op statement.
SET @aso_db = DATABASE();
SET @aso_column_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @aso_db AND TABLE_NAME = 'auth_session_operation'
      AND COLUMN_NAME = 'recovery_expires_at');
SET @aso_ddl = IF(@aso_column_count = 0,
    'ALTER TABLE auth_session_operation ADD COLUMN recovery_expires_at DATETIME DEFAULT NULL AFTER response_expires_at',
    'SELECT 1 AS recovery_expires_at_already_present');
PREPARE aso_stmt FROM @aso_ddl;
EXECUTE aso_stmt;
DEALLOCATE PREPARE aso_stmt;
