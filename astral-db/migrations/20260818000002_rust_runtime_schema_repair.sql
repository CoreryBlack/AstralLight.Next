-- Rust-only repair for runtime tables created by earlier migrations.
--
-- Do not edit an earlier tracked migration to repair an already-applied schema:
-- sqlx checksums are immutable.  Every column/index operation below first
-- inspects information_schema so this migration is safe to retry.  A missing
-- primary key or table is intentionally not synthesized; the final contract
-- guard fails before sqlx can record this migration as applied.
--
-- MySQL 5.7-compatible conditional DDL is used instead of ADD COLUMN IF NOT
-- EXISTS.  DDL is not treated as transactional: the migration lock serializes
-- runners, and a failed retry re-checks each item before continuing.

SET @astral_db = DATABASE();

-- Refuse to mutate an unknown table shape.  In particular, do not add nullable
-- identity/message columns to a populated table: their values cannot be
-- reconstructed without risking audit or idempotency corruption.
SET @astral_missing =
    (SELECT IF(COUNT(*) = 0, 1, 0) FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND TABLE_TYPE = 'BASE TABLE')
  + (SELECT IF(COUNT(*) = 0, 1, 0) FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'mq_idempotent_log' AND TABLE_TYPE = 'BASE TABLE')
  + (SELECT IF(COUNT(*) = 0, 1, 0) FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND TABLE_TYPE = 'BASE TABLE')
  + (SELECT IF(COUNT(*) = 0, 1, 0) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'id')
  + (SELECT IF(COUNT(*) = 0, 1, 0) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'mq_idempotent_log' AND COLUMN_NAME = 'id')
  + (SELECT IF(COUNT(*) = 0, 1, 0) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'id');
SET @astral_sql = IF(@astral_missing = 0, 'SELECT 1', 'THIS IS AN INTENTIONAL SCHEMA CONTRACT FAILURE');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- A populated table with a missing identity/message column cannot be repaired
-- deterministically.  Empty partial tables can receive the canonical NOT NULL
-- columns below; rows with defaultable fields remain preservable.
SET @astral_unsafe =
    (SELECT IF(COUNT(*) > 0 AND (SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'user_id') = 0, 1, 0) FROM audit_log)
  + (SELECT IF(COUNT(*) > 0 AND (SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'action') = 0, 1, 0) FROM audit_log)
  + (SELECT IF(COUNT(*) > 0 AND (SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'resource') = 0, 1, 0) FROM audit_log)
  + (SELECT IF(COUNT(*) > 0 AND (SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'decision') = 0, 1, 0) FROM audit_log)
  + (SELECT IF(COUNT(*) > 0 AND (SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'mq_idempotent_log' AND COLUMN_NAME = 'message_type') = 0, 1, 0) FROM mq_idempotent_log)
  + (SELECT IF(COUNT(*) > 0 AND (SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'mq_idempotent_log' AND COLUMN_NAME = 'message_id') = 0, 1, 0) FROM mq_idempotent_log)
  + (SELECT IF(COUNT(*) > 0 AND (SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'entity_id') = 0, 1, 0) FROM pending_compensation)
  + (SELECT IF(COUNT(*) > 0 AND (SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'op_type') = 0, 1, 0) FROM pending_compensation);
SET @astral_sql = IF(@astral_unsafe = 0, 'SELECT 1', 'THIS IS AN INTENTIONAL SCHEMA CONTRACT FAILURE');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- audit_log: add any columns absent from the historical governance table.
SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'user_id');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE audit_log ADD COLUMN user_id BIGINT NOT NULL', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'action');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE audit_log ADD COLUMN action VARCHAR(64) NOT NULL', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'resource');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE audit_log ADD COLUMN resource VARCHAR(256) NOT NULL', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'decision');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE audit_log ADD COLUMN decision VARCHAR(16) NOT NULL', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'reason');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE audit_log ADD COLUMN reason VARCHAR(256) NULL', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'card_id');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE audit_log ADD COLUMN card_id BIGINT NULL', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'detail');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE audit_log ADD COLUMN detail TEXT NULL', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'created_at');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE audit_log ADD COLUMN created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'event_type');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE audit_log ADD COLUMN event_type VARCHAR(32) NULL', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'source_ip');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE audit_log ADD COLUMN source_ip VARCHAR(64) NULL', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'request_id');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE audit_log ADD COLUMN request_id VARCHAR(64) NULL', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'domain_id');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE audit_log ADD COLUMN domain_id BIGINT NULL', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'tenant_id');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE audit_log ADD COLUMN tenant_id BIGINT NULL', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- audit_log indexes. A same-name index with a different shape is not accepted:
-- attempting the ADD then fails closed instead of silently accepting drift.
SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log'
      AND INDEX_NAME = 'idx_al_user' AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'user_id' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0, 'ALTER TABLE audit_log ADD INDEX idx_al_user (user_id)', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log'
      AND INDEX_NAME = 'idx_al_action' AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'action' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0, 'ALTER TABLE audit_log ADD INDEX idx_al_action (action)', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log'
      AND INDEX_NAME = 'idx_al_created' AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'created_at' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0, 'ALTER TABLE audit_log ADD INDEX idx_al_created (created_at)', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log'
      AND INDEX_NAME = 'idx_al_event_type' AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'event_type' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0, 'ALTER TABLE audit_log ADD INDEX idx_al_event_type (event_type)', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log'
      AND INDEX_NAME = 'idx_al_tenant' AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'tenant_id' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0, 'ALTER TABLE audit_log ADD INDEX idx_al_tenant (tenant_id)', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log'
      AND INDEX_NAME = 'idx_al_card' AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'card_id' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0, 'ALTER TABLE audit_log ADD INDEX idx_al_card (card_id)', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log'
      AND INDEX_NAME = 'idx_al_decision' AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'decision' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0, 'ALTER TABLE audit_log ADD INDEX idx_al_decision (decision)', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- mq_idempotent_log: preserve existing rows while filling absent columns.
SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'mq_idempotent_log' AND COLUMN_NAME = 'message_type');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE mq_idempotent_log ADD COLUMN message_type VARCHAR(64) NOT NULL', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'mq_idempotent_log' AND COLUMN_NAME = 'message_id');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE mq_idempotent_log ADD COLUMN message_id VARCHAR(64) NOT NULL', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'mq_idempotent_log' AND COLUMN_NAME = 'status');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE mq_idempotent_log ADD COLUMN status VARCHAR(32) NOT NULL DEFAULT ''PROCESSED''', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'mq_idempotent_log' AND COLUMN_NAME = 'created_at');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE mq_idempotent_log ADD COLUMN created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'mq_idempotent_log'
      AND INDEX_NAME = 'uk_mq_msg' AND NON_UNIQUE = 0
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 2
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'message_type' THEN 1 ELSE 0 END) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 2 AND COLUMN_NAME = 'message_id' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0, 'ALTER TABLE mq_idempotent_log ADD UNIQUE INDEX uk_mq_msg (message_type, message_id)', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- pending_compensation: preserve rows while filling absent retry columns.
SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'entity_id');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE pending_compensation ADD COLUMN entity_id BIGINT NOT NULL', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'op_type');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE pending_compensation ADD COLUMN op_type VARCHAR(64) NOT NULL', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'error_msg');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE pending_compensation ADD COLUMN error_msg TEXT NULL', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'status');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE pending_compensation ADD COLUMN status VARCHAR(32) NOT NULL DEFAULT ''PENDING''', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'retry_count');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE pending_compensation ADD COLUMN retry_count INT NULL DEFAULT 0', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'created_at');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE pending_compensation ADD COLUMN created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'updated_at');
SET @astral_sql = IF(@astral_count = 0, 'ALTER TABLE pending_compensation ADD COLUMN updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation'
      AND INDEX_NAME = 'idx_status' AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'status' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0, 'ALTER TABLE pending_compensation ADD INDEX idx_status (status)', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_index = (SELECT COUNT(*) FROM (
    SELECT INDEX_NAME FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation'
      AND INDEX_NAME = 'idx_entity' AND NON_UNIQUE = 1
    GROUP BY INDEX_NAME
    HAVING COUNT(*) = 1
       AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'entity_id' THEN 1 ELSE 0 END) = 1
) AS matching_index);
SET @astral_sql = IF(@astral_index = 0, 'ALTER TABLE pending_compensation ADD INDEX idx_entity (entity_id)', 'SELECT 1');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- The final guard prevents an incomplete table from being recorded as applied.
-- Identity keys are intentionally never guessed.  DDL is non-transactional in
-- MySQL, so a failed guard may leave additive columns/indexes behind; retrying
-- this migration is safe because every operation above is conditional.
SET @astral_missing =
    (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'id')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'user_id')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'action')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'resource')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'decision')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'reason')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'card_id')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'event_type')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'source_ip')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'request_id')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'domain_id')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'tenant_id')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'detail')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND COLUMN_NAME = 'created_at')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'mq_idempotent_log' AND COLUMN_NAME = 'id')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'mq_idempotent_log' AND COLUMN_NAME = 'message_type')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'mq_idempotent_log' AND COLUMN_NAME = 'message_id')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'mq_idempotent_log' AND COLUMN_NAME = 'status')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'mq_idempotent_log' AND COLUMN_NAME = 'created_at')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'id')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'entity_id')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'op_type')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'error_msg')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'status')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'retry_count')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'created_at')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND COLUMN_NAME = 'updated_at');
SET @astral_missing = @astral_missing
  + (SELECT IF(COUNT(*) = 1 AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'id' THEN 1 ELSE 0 END) = 1, 0, 1)
       FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND INDEX_NAME = 'PRIMARY')
  + (SELECT IF(COUNT(*) = 1 AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'id' THEN 1 ELSE 0 END) = 1, 0, 1)
       FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'mq_idempotent_log' AND INDEX_NAME = 'PRIMARY')
  + (SELECT IF(COUNT(*) = 1 AND MAX(CASE WHEN SEQ_IN_INDEX = 1 AND COLUMN_NAME = 'id' THEN 1 ELSE 0 END) = 1, 0, 1)
       FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND INDEX_NAME = 'PRIMARY')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND INDEX_NAME = 'idx_al_user')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND INDEX_NAME = 'idx_al_action')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND INDEX_NAME = 'idx_al_created')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND INDEX_NAME = 'idx_al_event_type')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND INDEX_NAME = 'idx_al_tenant')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND INDEX_NAME = 'idx_al_card')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'audit_log' AND INDEX_NAME = 'idx_al_decision')
  + (SELECT IF(COUNT(*) = 2, 0, 1) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'mq_idempotent_log' AND INDEX_NAME = 'uk_mq_msg')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND INDEX_NAME = 'idx_status')
  + (SELECT IF(COUNT(*) = 1, 0, 1) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'pending_compensation' AND INDEX_NAME = 'idx_entity');
SET @astral_sql = IF(@astral_missing = 0, 'SELECT 1', 'THIS IS AN INTENTIONAL SCHEMA CONTRACT FAILURE');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;
