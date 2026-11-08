-- Persist the exact authority snapshot represented by the durable frontier.
--
-- The first authority migration predates parent-hash enforcement and therefore
-- cannot be edited without invalidating its immutable artifact checksum. This
-- additive migration keeps the bootstrap frontier NULL while requiring every
-- non-bootstrap SERVING frontier to carry a 32-byte snapshot identity.
--
-- The conditional DDL makes an interrupted additive batch rerunnable by the
-- explicit migration job without rewriting existing frontier data.
SET @astral_db = DATABASE();

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_authority_frontier'
      AND COLUMN_NAME = 'snapshot_hash'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE authorization_authority_frontier ADD COLUMN snapshot_hash BINARY(32) NULL AFTER key_epoch',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;
