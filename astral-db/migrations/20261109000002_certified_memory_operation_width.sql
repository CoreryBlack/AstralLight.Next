-- V7 CertifiedMemory completion operation identity width expansion.
--
-- The completion ledger creator remains additive and source-pinned. This
-- ALTER-only migration widens only its operation identity from VARCHAR(64) to
-- VARCHAR(128); no index is created, renamed, or dropped.
SET @astral_db = DATABASE();
SET @astral_width = (
    SELECT CASE
        WHEN COUNT(*) = 1
             AND LOWER(MAX(COLUMN_TYPE)) = 'varchar(128)'
             AND MAX(IS_NULLABLE) = 'NO'
             AND MAX(CHARACTER_SET_NAME) = 'ascii'
             AND MAX(COLLATION_NAME) = 'ascii_bin'
             AND COUNT(COLUMN_DEFAULT) = 0 THEN 128
        WHEN COUNT(*) = 1
             AND LOWER(MAX(COLUMN_TYPE)) = 'varchar(64)'
             AND MAX(IS_NULLABLE) = 'NO'
             AND MAX(CHARACTER_SET_NAME) = 'ascii'
             AND MAX(COLLATION_NAME) = 'ascii_bin'
             AND COUNT(COLUMN_DEFAULT) = 0 THEN 64
        ELSE 0
    END
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authority_certified_memory_completion'
      AND COLUMN_NAME = 'operation_id'
);
SET @astral_sql = IF(
    @astral_width = 128,
    'SELECT 1',
    IF(
        @astral_width = 64,
        'ALTER TABLE authority_certified_memory_completion MODIFY COLUMN operation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL',
        'SELECT * FROM'
    )
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;
