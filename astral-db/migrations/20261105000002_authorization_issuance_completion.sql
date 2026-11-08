-- Bind an issuance lease to a verified durable publication before it can be
-- consumed by the authority signer. Existing rows remain conservative: a lease
-- without completion metadata is not READY and cannot mint a proof.
--
-- Every statement is conditional so an interrupted additive DDL batch can be
-- rerun by the explicit migration job without changing existing data.
SET @astral_db = DATABASE();

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_authority_issuance_lease'
      AND COLUMN_NAME = 'publication_completion_hash'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE authorization_authority_issuance_lease ADD COLUMN publication_completion_hash BINARY(32) NULL AFTER arbiter_signature',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_authority_issuance_lease'
      AND COLUMN_NAME = 'publication_completion_generation'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE authorization_authority_issuance_lease ADD COLUMN publication_completion_generation BIGINT NULL AFTER publication_completion_hash',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_authority_issuance_lease'
      AND COLUMN_NAME = 'publication_completion_revoke_watermark'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE authorization_authority_issuance_lease ADD COLUMN publication_completion_revoke_watermark BIGINT NULL AFTER publication_completion_generation',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_authority_issuance_lease'
      AND COLUMN_NAME = 'publication_completion_at'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE authorization_authority_issuance_lease ADD COLUMN publication_completion_at BIGINT NULL AFTER publication_completion_revoke_watermark',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;
