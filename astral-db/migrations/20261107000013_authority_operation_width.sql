-- V7 operation identity width expansion.
--
-- The immutable creator migrations retain their original VARCHAR(64) columns.
-- This migration widens only the exact legacy shape to VARCHAR(128). An exact
-- final shape is a no-op; every unknown, missing, or drifted state fails closed
-- through a deliberately invalid prepared SELECT. The Rust preflight checks
-- the complete historical index shape before SQLx executes this ALTER-only
-- migration. MODIFY COLUMN preserves those indexes and this migration never
-- creates, renames, or drops an index.

SET @astral_db = DATABASE();

-- verification_challenge.operation_id; preserve uk_vch_operation(operation_id, purpose).
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
      AND TABLE_NAME = 'verification_challenge'
      AND COLUMN_NAME = 'operation_id'
);
SET @astral_sql = IF(
    @astral_width = 128,
    'SELECT 1',
    IF(
        @astral_width = 64,
        'ALTER TABLE verification_challenge MODIFY COLUMN operation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL',
        'SELECT * FROM'
    )
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

-- protected_mutation_operation.operation_id; preserve PRIMARY(operation_id, resource).
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
      AND TABLE_NAME = 'protected_mutation_operation'
      AND COLUMN_NAME = 'operation_id'
);
SET @astral_sql = IF(
    @astral_width = 128,
    'SELECT 1',
    IF(
        @astral_width = 64,
        'ALTER TABLE protected_mutation_operation MODIFY COLUMN operation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL',
        'SELECT * FROM'
    )
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

-- authorization_source_reservation.operation_id; preserve PRIMARY(operation_id)
-- and uk_asr_proof(proof_id).
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
      AND TABLE_NAME = 'authorization_source_reservation'
      AND COLUMN_NAME = 'operation_id'
);
SET @astral_sql = IF(
    @astral_width = 128,
    'SELECT 1',
    IF(
        @astral_width = 64,
        'ALTER TABLE authorization_source_reservation MODIFY COLUMN operation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL',
        'SELECT * FROM'
    )
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

-- authority_source_outcome.operation_id; preserve idx_aso_operation(operation_id).
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
      AND TABLE_NAME = 'authority_source_outcome'
      AND COLUMN_NAME = 'operation_id'
);
SET @astral_sql = IF(
    @astral_width = 128,
    'SELECT 1',
    IF(
        @astral_width = 64,
        'ALTER TABLE authority_source_outcome MODIFY COLUMN operation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL',
        'SELECT * FROM'
    )
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

-- authorization_scope_certificate_history.operation_id; preserve
-- idx_asch_reservation(reservation_id, operation_id).
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
      AND TABLE_NAME = 'authorization_scope_certificate_history'
      AND COLUMN_NAME = 'operation_id'
);
SET @astral_sql = IF(
    @astral_width = 128,
    'SELECT 1',
    IF(
        @astral_width = 64,
        'ALTER TABLE authorization_scope_certificate_history MODIFY COLUMN operation_id VARCHAR(128) CHARACTER SET ascii COLLATE ascii_bin NOT NULL',
        'SELECT * FROM'
    )
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

-- The historical operation_audit_correlation.operation_id is physically
-- async_operation_item.operation_id in migration 20261003000002. Preserve its
-- utf8mb4/utf8mb4_unicode_ci column contract and uk_async_operation_item_operation.
SET @astral_width = (
    SELECT CASE
        WHEN COUNT(*) = 1
             AND LOWER(MAX(COLUMN_TYPE)) = 'varchar(128)'
             AND MAX(IS_NULLABLE) = 'NO'
             AND MAX(CHARACTER_SET_NAME) = 'utf8mb4'
             AND MAX(COLLATION_NAME) = 'utf8mb4_unicode_ci'
             AND COUNT(COLUMN_DEFAULT) = 0 THEN 128
        WHEN COUNT(*) = 1
             AND LOWER(MAX(COLUMN_TYPE)) = 'varchar(64)'
             AND MAX(IS_NULLABLE) = 'NO'
             AND MAX(CHARACTER_SET_NAME) = 'utf8mb4'
             AND MAX(COLLATION_NAME) = 'utf8mb4_unicode_ci'
             AND COUNT(COLUMN_DEFAULT) = 0 THEN 64
        ELSE 0
    END
    FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'async_operation_item'
      AND COLUMN_NAME = 'operation_id'
);
SET @astral_sql = IF(
    @astral_width = 128,
    'SELECT 1',
    IF(
        @astral_width = 64,
        'ALTER TABLE async_operation_item MODIFY COLUMN operation_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL',
        'SELECT * FROM'
    )
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;
