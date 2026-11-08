-- Additive commerce compatibility column for package billing semantics.
-- Existing rows intentionally remain NULL: no historical billing cycle is
-- inferred, backfilled, or reclassified by this migration.
--
-- Preflight/postcondition: the exact artifact contract in
-- astral-db/src/migration/commerce_billing_cycle.rs pins this SQL's SHA-384,
-- nullable ASCII column shape, and the absence of indexes. The explicit Rust
-- migration job owns execution; agents do not apply this DDL.
--
-- Forward-fix rollback note: dropping this column would make package cycle
-- evidence unavailable and therefore fail closed for purchase; preserve a
-- backup of the column before any approved rollback.

SET @astral_db = DATABASE();
SET @astral_column = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'platform_package'
      AND COLUMN_NAME = 'billing_cycle'
);
SET @astral_sql = IF(
    @astral_column = 0,
    'ALTER TABLE platform_package \
       ADD COLUMN billing_cycle VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NULL \
       COMMENT ''MONTHLY | QUARTERLY | YEARLY | ONETIME; legacy NULL remains unknown'' \
       AFTER description',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;
