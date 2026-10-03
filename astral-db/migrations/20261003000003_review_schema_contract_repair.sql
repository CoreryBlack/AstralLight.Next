-- Forward-only schema contract repair for schema review gaps.
--
-- This migration does not delete or rewrite durable records. Before SQLx runs it,
-- migration.rs checks every proposed PRIMARY/UNIQUE key for duplicate data and
-- refuses incompatible existing columns/tables. The UNIQUE/PRIMARY DDL below is
-- still the final race-safe guard: MySQL will reject a duplicate introduced after
-- preflight rather than dropping or selecting rows.
--
-- Creator history remains authoritative. If any cross-city proof table or the
-- ORG_SCOPE operation ledger is missing after its creator migration was recorded,
-- the runner refuses this migration and requires data/schema recovery. Recreating
-- an empty replay-proof table would not restore the evidence it used to contain.
-- The local message scope counter is different: it is a monotonic derived high
-- watermark, safely reconstructed below from durable outbox scope_sequence values.

SET @astral_db = DATABASE();

-- 1. The nullable per-scope sequence was first introduced by 20261001000005.
--    Add it only when absent; a present but incompatible definition is drift and
--    is rejected by migration.rs rather than coerced or narrowed here.
SET @scope_sequence_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'al_message_outbox'
      AND COLUMN_NAME = 'scope_sequence');
SET @astral_sql = IF(@scope_sequence_count = 0,
    'ALTER TABLE al_message_outbox ADD COLUMN scope_sequence BIGINT DEFAULT NULL COMMENT ''per-scope commit-order sequence allocated in the append transaction; NULL = legacy row or row without ordering_key''',
    'SELECT 1 AS scope_sequence_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- 2. Exact non-unique ascending scope FIFO index. A same-name incompatible index
--    is left untouched and rejected by startup validation; no index is dropped.
SET @scope_index_count = (
    SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'al_message_outbox'
      AND INDEX_NAME = 'idx_al_message_scope_order');
SET @astral_sql = IF(@scope_index_count = 0,
    'ALTER TABLE al_message_outbox ADD KEY idx_al_message_scope_order (queue_name, ordering_key, scope_sequence)',
    'SELECT 1 AS scope_order_index_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- 3. Create the exact monotonic high-watermark table when absent. If an existing
--    table has incompatible shape, migration.rs rejects it before any DDL.
CREATE TABLE IF NOT EXISTS al_message_scope_counter (
    scope_key     VARCHAR(400) NOT NULL
        COMMENT 'queue_name + 0x1F + ordering_key; per-scope sequence identity',
    last_sequence BIGINT NOT NULL DEFAULT 0
        COMMENT 'highest scope_sequence allocated for this scope; never decreases',
    updated_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (scope_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. If an interrupted/older creator left the counter without its primary key,
--    add it only after the Rust preflight has proved there are no duplicate keys.
SET @scope_counter_pk_count = (
    SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'al_message_scope_counter'
      AND INDEX_NAME = 'PRIMARY');
SET @astral_sql = IF(@scope_counter_pk_count = 0,
    'ALTER TABLE al_message_scope_counter ADD PRIMARY KEY (scope_key)',
    'SELECT 1 AS scope_counter_primary_key_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- 5. Reconstruct/advance the counter from durable sequences. GREATEST is
--    intentionally monotonic so retries or concurrent appends never decrement it.
INSERT INTO al_message_scope_counter (scope_key, last_sequence)
SELECT CONCAT(queue_name, CHAR(31), ordering_key), MAX(scope_sequence)
FROM al_message_outbox
WHERE ordering_key IS NOT NULL AND scope_sequence IS NOT NULL
GROUP BY queue_name, ordering_key
ON DUPLICATE KEY UPDATE last_sequence = GREATEST(last_sequence, VALUES(last_sequence));

-- 6. ORG_SCOPE idempotency identity: add the exact operation_id primary key only
--    when no PRIMARY index exists. A wrong existing PRIMARY shape is drift and is
--    never rewritten here.
SET @org_operation_pk_count = (
    SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'org_scope_operation'
      AND INDEX_NAME = 'PRIMARY');
SET @astral_sql = IF(@org_operation_pk_count = 0,
    'ALTER TABLE org_scope_operation ADD PRIMARY KEY (operation_id)',
    'SELECT 1 AS org_operation_primary_key_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- 7. Cross-city runtime proof indexes. All are additive. Duplicate-bearing
--    histories are rejected by the runner's read-only GROUP BY preflight and by
--    MySQL's unique-key enforcement if data races after that preflight.
SET @idx_count = (SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_cross_city_node_key' AND INDEX_NAME = 'PRIMARY');
SET @astral_sql = IF(@idx_count = 0, 'ALTER TABLE authorization_cross_city_node_key ADD PRIMARY KEY (node_key_id)', 'SELECT 1 AS accnk_primary_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;
SET @idx_count = (SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_cross_city_node_key' AND INDEX_NAME = 'uk_accnk_identity');
SET @astral_sql = IF(@idx_count = 0, 'ALTER TABLE authorization_cross_city_node_key ADD UNIQUE KEY uk_accnk_identity (city_id, node_id, node_epoch)', 'SELECT 1 AS accnk_identity_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;
SET @idx_count = (SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_cross_city_node_key' AND INDEX_NAME = 'idx_accnk_revoked');
SET @astral_sql = IF(@idx_count = 0, 'ALTER TABLE authorization_cross_city_node_key ADD KEY idx_accnk_revoked (revoked, node_key_id)', 'SELECT 1 AS accnk_revoked_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @idx_count = (SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_cross_city_vote_reservation' AND INDEX_NAME = 'PRIMARY');
SET @astral_sql = IF(@idx_count = 0, 'ALTER TABLE authorization_cross_city_vote_reservation ADD PRIMARY KEY (reservation_id)', 'SELECT 1 AS accvr_primary_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;
SET @idx_count = (SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_cross_city_vote_reservation' AND INDEX_NAME = 'uk_accvr_replay_key');
SET @astral_sql = IF(@idx_count = 0, 'ALTER TABLE authorization_cross_city_vote_reservation ADD UNIQUE KEY uk_accvr_replay_key (city_id, node_id, node_epoch, nonce, evidence_digest)', 'SELECT 1 AS accvr_replay_key_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;
SET @idx_count = (SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_cross_city_vote_reservation' AND INDEX_NAME = 'idx_accvr_operation');
SET @astral_sql = IF(@idx_count = 0, 'ALTER TABLE authorization_cross_city_vote_reservation ADD KEY idx_accvr_operation (operation_id)', 'SELECT 1 AS accvr_operation_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @idx_count = (SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_cross_city_commit_receipt' AND INDEX_NAME = 'PRIMARY');
SET @astral_sql = IF(@idx_count = 0, 'ALTER TABLE authorization_cross_city_commit_receipt ADD PRIMARY KEY (receipt_id)', 'SELECT 1 AS acccr_primary_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;
SET @idx_count = (SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_cross_city_commit_receipt' AND INDEX_NAME = 'uk_acccr_node');
SET @astral_sql = IF(@idx_count = 0, 'ALTER TABLE authorization_cross_city_commit_receipt ADD UNIQUE KEY uk_acccr_node (operation_id, city_id, node_id)', 'SELECT 1 AS acccr_node_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;
SET @idx_count = (SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_cross_city_commit_receipt' AND INDEX_NAME = 'uk_acccr_nonce');
SET @astral_sql = IF(@idx_count = 0, 'ALTER TABLE authorization_cross_city_commit_receipt ADD UNIQUE KEY uk_acccr_nonce (operation_id, nonce)', 'SELECT 1 AS acccr_nonce_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;
SET @idx_count = (SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_cross_city_commit_receipt' AND INDEX_NAME = 'idx_acccr_operation_city');
SET @astral_sql = IF(@idx_count = 0, 'ALTER TABLE authorization_cross_city_commit_receipt ADD KEY idx_acccr_operation_city (operation_id, city_id, decision)', 'SELECT 1 AS acccr_operation_city_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @idx_count = (SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_cross_city_operation_activation' AND INDEX_NAME = 'PRIMARY');
SET @astral_sql = IF(@idx_count = 0, 'ALTER TABLE authorization_cross_city_operation_activation ADD PRIMARY KEY (operation_id)', 'SELECT 1 AS accoa_primary_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @idx_count = (SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_cross_city_authority_scope' AND INDEX_NAME = 'PRIMARY');
SET @astral_sql = IF(@idx_count = 0, 'ALTER TABLE authorization_cross_city_authority_scope ADD PRIMARY KEY (scope_id)', 'SELECT 1 AS accas_primary_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;
SET @idx_count = (SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_cross_city_authority_scope' AND INDEX_NAME = 'uk_accas_city_scope');
SET @astral_sql = IF(@idx_count = 0, 'ALTER TABLE authorization_cross_city_authority_scope ADD UNIQUE KEY uk_accas_city_scope (city_id, scope_digest)', 'SELECT 1 AS accas_city_scope_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;
SET @idx_count = (SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @astral_db AND TABLE_NAME = 'authorization_cross_city_authority_scope' AND INDEX_NAME = 'idx_accas_scope');
SET @astral_sql = IF(@idx_count = 0, 'ALTER TABLE authorization_cross_city_authority_scope ADD KEY idx_accas_scope (scope_digest, authoritative)', 'SELECT 1 AS accas_scope_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;
