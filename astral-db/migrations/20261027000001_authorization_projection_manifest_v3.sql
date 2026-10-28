-- V3 is the only accepted authorization manifest seal format. Existing
-- manifests without a v3 digest-version and UTC-second sealed_at timestamp are
-- unproven and must be reconciled explicitly; never infer or backfill a seal.
-- The explicit migration preflight additionally verifies the exact ordered
-- schema contract before SQLx may write migration history.

SET @astral_manifest_v3_table_count = (
    SELECT COUNT(*)
    FROM information_schema.TABLES
    WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY)
      AND CAST(TABLE_NAME AS BINARY) = CAST('authorization_projection_manifest' AS BINARY)
      AND CAST(TABLE_TYPE AS BINARY) = CAST('BASE TABLE' AS BINARY)
);

SET @astral_manifest_v3_version_column_count = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY)
      AND CAST(TABLE_NAME AS BINARY) = CAST('authorization_projection_manifest' AS BINARY)
      AND CAST(COLUMN_NAME AS BINARY) = CAST('manifest_digest_version' AS BINARY)
);

SET @astral_manifest_v3_sealed_column_count = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY)
      AND CAST(TABLE_NAME AS BINARY) = CAST('authorization_projection_manifest' AS BINARY)
      AND CAST(COLUMN_NAME AS BINARY) = CAST('sealed_at' AS BINARY)
);

SET @astral_manifest_v3_existing_column_count = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS
    WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY)
      AND CAST(TABLE_NAME AS BINARY) = CAST('authorization_projection_manifest' AS BINARY)
);

SET @astral_manifest_v3_revoke_fence_exact_count = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS AS fence_column
    WHERE CAST(fence_column.TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY)
      AND CAST(fence_column.TABLE_NAME AS BINARY) = CAST('authorization_projection_manifest' AS BINARY)
      AND CAST(fence_column.COLUMN_NAME AS BINARY) = CAST('revoke_fence' AS BINARY)
      AND LOWER(fence_column.COLUMN_TYPE) = 'bigint'
      AND CAST(fence_column.IS_NULLABLE AS BINARY) = CAST('NO' AS BINARY)
      AND CAST(fence_column.COLUMN_DEFAULT AS CHAR CHARACTER SET utf8mb4) = '0'
      AND fence_column.ORDINAL_POSITION = @astral_manifest_v3_existing_column_count
);

SET @astral_manifest_v3_row_count = 0;
SET @astral_manifest_v3_row_probe = IF(
    @astral_manifest_v3_table_count = 1,
    'SELECT COUNT(*) INTO @astral_manifest_v3_row_count FROM authorization_projection_manifest',
    'SELECT 1'
);
PREPARE astral_manifest_v3_stmt FROM @astral_manifest_v3_row_probe;
EXECUTE astral_manifest_v3_stmt;
DEALLOCATE PREPARE astral_manifest_v3_stmt;

SET @astral_manifest_v3_invalid_row_count = 0;
SET @astral_manifest_v3_invalid_row_probe = IF(
    @astral_manifest_v3_table_count = 1
        AND @astral_manifest_v3_version_column_count = 1
        AND @astral_manifest_v3_sealed_column_count = 1,
    'SELECT COUNT(*) INTO @astral_manifest_v3_invalid_row_count FROM authorization_projection_manifest WHERE manifest_digest_version IS NULL OR manifest_digest_version <> 3 OR sealed_at IS NULL OR YEAR(sealed_at) NOT BETWEEN 1000 AND 9999 OR MONTH(sealed_at) NOT BETWEEN 1 AND 12 OR DAY(sealed_at) NOT BETWEEN 1 AND 31 OR LAST_DAY(sealed_at) IS NULL OR DAY(sealed_at) > DAY(LAST_DAY(sealed_at))',
    'SELECT 1'
);
PREPARE astral_manifest_v3_stmt FROM @astral_manifest_v3_invalid_row_probe;
EXECUTE astral_manifest_v3_stmt;
DEALLOCATE PREPARE astral_manifest_v3_stmt;

SET @astral_manifest_v3_lineage_tail_count = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS AS parent_column
    JOIN information_schema.COLUMNS AS fence_column
      ON CAST(fence_column.TABLE_SCHEMA AS BINARY) = CAST(parent_column.TABLE_SCHEMA AS BINARY)
     AND CAST(fence_column.TABLE_NAME AS BINARY) = CAST(parent_column.TABLE_NAME AS BINARY)
     AND CAST(fence_column.COLUMN_NAME AS BINARY) = CAST('revoke_fence' AS BINARY)
     AND fence_column.ORDINAL_POSITION = parent_column.ORDINAL_POSITION + 1
    JOIN information_schema.COLUMNS AS parent_anchor
      ON CAST(parent_anchor.TABLE_SCHEMA AS BINARY) = CAST(parent_column.TABLE_SCHEMA AS BINARY)
     AND CAST(parent_anchor.TABLE_NAME AS BINARY) = CAST(parent_column.TABLE_NAME AS BINARY)
     AND CAST(parent_anchor.COLUMN_NAME AS BINARY) = CAST('updated_at' AS BINARY)
     AND parent_column.ORDINAL_POSITION = parent_anchor.ORDINAL_POSITION + 1
    WHERE CAST(parent_column.TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY)
      AND CAST(parent_column.TABLE_NAME AS BINARY) = CAST('authorization_projection_manifest' AS BINARY)
      AND CAST(parent_column.COLUMN_NAME AS BINARY) = CAST('parent_manifest_id' AS BINARY)
      AND LOWER(parent_column.COLUMN_TYPE) = 'bigint'
      AND CAST(parent_column.IS_NULLABLE AS BINARY) = CAST('YES' AS BINARY)
      AND parent_column.COLUMN_DEFAULT IS NULL
      AND LOWER(fence_column.COLUMN_TYPE) = 'bigint'
      AND CAST(fence_column.IS_NULLABLE AS BINARY) = CAST('NO' AS BINARY)
      AND CAST(fence_column.COLUMN_DEFAULT AS CHAR CHARACTER SET utf8mb4) = '0'
      AND (
          fence_column.ORDINAL_POSITION = @astral_manifest_v3_existing_column_count
          OR fence_column.ORDINAL_POSITION + 2 = @astral_manifest_v3_existing_column_count
      )
);

SET @astral_manifest_v3_exact_tail_count = (
    SELECT COUNT(*)
    FROM information_schema.COLUMNS AS version_column
    JOIN information_schema.COLUMNS AS sealed_column
      ON CAST(sealed_column.TABLE_SCHEMA AS BINARY) = CAST(version_column.TABLE_SCHEMA AS BINARY)
     AND CAST(sealed_column.TABLE_NAME AS BINARY) = CAST(version_column.TABLE_NAME AS BINARY)
     AND CAST(sealed_column.COLUMN_NAME AS BINARY) = CAST('sealed_at' AS BINARY)
    JOIN information_schema.COLUMNS AS previous_column
      ON CAST(previous_column.TABLE_SCHEMA AS BINARY) = CAST(version_column.TABLE_SCHEMA AS BINARY)
     AND CAST(previous_column.TABLE_NAME AS BINARY) = CAST(version_column.TABLE_NAME AS BINARY)
     AND previous_column.ORDINAL_POSITION = version_column.ORDINAL_POSITION - 1
    WHERE CAST(version_column.TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY)
      AND CAST(version_column.TABLE_NAME AS BINARY) = CAST('authorization_projection_manifest' AS BINARY)
      AND CAST(version_column.COLUMN_NAME AS BINARY) = CAST('manifest_digest_version' AS BINARY)
      AND LOWER(version_column.COLUMN_TYPE) = 'smallint unsigned'
      AND CAST(version_column.IS_NULLABLE AS BINARY) = CAST('NO' AS BINARY)
      AND version_column.COLUMN_DEFAULT IS NULL
      AND version_column.CHARACTER_SET_NAME IS NULL
      AND version_column.COLLATION_NAME IS NULL
      AND LOWER(sealed_column.COLUMN_TYPE) = 'datetime'
      AND CAST(sealed_column.IS_NULLABLE AS BINARY) = CAST('NO' AS BINARY)
      AND sealed_column.COLUMN_DEFAULT IS NULL
      AND sealed_column.CHARACTER_SET_NAME IS NULL
      AND sealed_column.COLLATION_NAME IS NULL
      AND CAST(previous_column.COLUMN_NAME AS BINARY) = CAST('revoke_fence' AS BINARY)
      AND sealed_column.ORDINAL_POSITION = version_column.ORDINAL_POSITION + 1
      AND sealed_column.ORDINAL_POSITION = (
          SELECT MAX(tail_column.ORDINAL_POSITION)
          FROM information_schema.COLUMNS AS tail_column
          WHERE CAST(tail_column.TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY)
            AND CAST(tail_column.TABLE_NAME AS BINARY) = CAST('authorization_projection_manifest' AS BINARY)
      )
);

-- Add both columns in one ALTER only when the table is empty. A complete v3
-- tail with valid rows is a harmless retry; a legacy row, partial tail, or any
-- metadata/value drift deliberately prepares an invalid statement and stops.
SET @astral_manifest_v3_ddl = IF(
    @astral_manifest_v3_table_count = 1
        AND @astral_manifest_v3_version_column_count = 0
        AND @astral_manifest_v3_sealed_column_count = 0
        AND @astral_manifest_v3_revoke_fence_exact_count = 1
        AND @astral_manifest_v3_lineage_tail_count = 1
        AND @astral_manifest_v3_row_count = 0,
    'ALTER TABLE authorization_projection_manifest ADD COLUMN manifest_digest_version SMALLINT UNSIGNED NOT NULL, ADD COLUMN sealed_at DATETIME NOT NULL',
    IF(
        @astral_manifest_v3_table_count = 1
            AND @astral_manifest_v3_version_column_count = 1
            AND @astral_manifest_v3_sealed_column_count = 1
            AND @astral_manifest_v3_exact_tail_count = 1
            AND @astral_manifest_v3_lineage_tail_count = 1
            AND @astral_manifest_v3_invalid_row_count = 0,
        'SELECT 1',
        'ALTER TABLE authorization_projection_manifest ADD COLUMN'
    )
);
PREPARE astral_manifest_v3_stmt FROM @astral_manifest_v3_ddl;
EXECUTE astral_manifest_v3_stmt;
DEALLOCATE PREPARE astral_manifest_v3_stmt;
