-- Persist proof-derived authorization provenance separately from the business payload.
--
-- NULL is intentional: internal freshness/session invalidations do not claim user
-- authorization provenance. Evidence invalidations must carry canonical metadata
-- produced from a verified admission before they can be appended.
--
-- Each statement is conditional so an interrupted additive DDL batch can be
-- rerun by the explicit migration job without rewriting historical messages.
SET @astral_db = DATABASE();

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'al_message_outbox'
      AND COLUMN_NAME = 'authority_metadata_json'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE al_message_outbox ADD COLUMN authority_metadata_json MEDIUMTEXT NULL AFTER headers_json',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_invalidation_inbox'
      AND COLUMN_NAME = 'authority_metadata_json'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE authorization_invalidation_inbox ADD COLUMN authority_metadata_json MEDIUMTEXT NULL AFTER payload_json',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;
