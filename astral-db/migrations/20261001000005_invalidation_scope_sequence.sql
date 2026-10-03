-- Per-scope FIFO commit-order sequence for al_message_outbox (fully additive).
--
-- Problem being fixed: the previous per-scope FIFO guard compared rows by
-- (created_at, message_id). Neither value is the source-transaction commit
-- order: rows committed microseconds apart can share the same DATETIME(6)
-- timestamp, and message_id lexicographic order says nothing about commit
-- order. Two invalidations for the same ordering-key scope could therefore be
-- relayed out of commit order.
--
-- Fix: an explicit per-scope monotonically increasing sequence allocated by
-- `astral_db::local_message_repository` inside the SAME transaction that
-- appends the outbox row. The scope-counter row is locked (INSERT ... ON
-- DUPLICATE KEY UPDATE / SELECT ... FOR UPDATE) until the caller's transaction
-- commits, so `scope_sequence` order == commit order for every scope. A
-- duplicate message_id whose full provenance matches is idempotent and never
-- allocates a new sequence value.
--
-- Scope definition: one counter per (queue_name, ordering_key) pair, keyed as
-- `queue_name` + 0x1F + `ordering_key` (ordering_key is never NULL for a
-- scoped row). Size bound: queue_name <= 128 + ordering_key <= 256 chars plus
-- one separator = 385 chars, within the VARCHAR(400) / InnoDB 3072-byte index
-- limit under utf8mb4.
--
-- Legacy/conservative NULL handling: rows without an ordering_key keep
-- scope_sequence NULL and never allocate a counter value. Pre-migration rows
-- also keep NULL. Wherever either side of a FIFO comparison is NULL the claim
-- guard falls back to the legacy (created_at, message_id) comparison, so the
-- guard stays total and conservative for mixed data.
--
-- IN_DOUBT contract: `scope_sequence` says nothing about IN_DOUBT recovery.
-- IN_DOUBT rows are never reclaimed by time and never reset to PENDING by
-- time; only the explicit provenance-matched CAS
-- (`LocalMessageRepository::reconcile_in_doubt`) may settle them. An IN_DOUBT
-- row keeps blocking its scope's FIFO guard until reconciled (fail-closed).
--
-- Transport ownership (comment contract, aligned with the repository module
-- docs): `al_message_outbox` is the durable recovery/outbox journal for typed
-- invalidations, NOT the local transport authority. The composite runtime's
-- LocalBus direct publish path is the transport; this table owns only the
-- durable state machine the recovery relay and the reconciliation interface
-- advance.
--
-- Rollback (after draining/reconciling in-flight rows):
--   ALTER TABLE al_message_outbox DROP KEY idx_al_message_scope_order;
--   ALTER TABLE al_message_outbox DROP COLUMN scope_sequence;
--   DROP TABLE al_message_scope_counter;
-- Legacy NULL handling keeps pre-migration readers functional during rollback.

SET @db = (SELECT DATABASE());

-- 1. scope_sequence column on the outbox (NULL = legacy row or no scope).
SET @c1 = (SELECT COUNT(*) FROM information_schema.COLUMNS
           WHERE TABLE_SCHEMA = @db
             AND TABLE_NAME = 'al_message_outbox'
             AND COLUMN_NAME = 'scope_sequence');
SET @s1 = IF(@c1 = 0,
    'ALTER TABLE al_message_outbox ADD COLUMN scope_sequence BIGINT DEFAULT NULL COMMENT ''per-scope commit-order sequence allocated in the append transaction; NULL = legacy row or row without ordering_key''',
    'SELECT 1');
PREPARE p1 FROM @s1; EXECUTE p1; DEALLOCATE PREPARE p1;

-- 2. Scope-order covering index for the FIFO claim guard.
SET @idx1 = (SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS
             WHERE TABLE_SCHEMA = @db
               AND TABLE_NAME = 'al_message_outbox'
               AND INDEX_NAME = 'idx_al_message_scope_order');
SET @si1 = IF(@idx1 = 0,
    'ALTER TABLE al_message_outbox ADD KEY idx_al_message_scope_order (queue_name, ordering_key, scope_sequence)',
    'SELECT 1');
PREPARE pi1 FROM @si1; EXECUTE pi1; DEALLOCATE PREPARE pi1;

-- 3. Per-scope commit-order counter. Rows are only ever written by the
--    outbox append paths inside the caller's transaction; no other writer
--    exists. Counter values are never rewritten or decremented.
CREATE TABLE IF NOT EXISTS al_message_scope_counter (
    scope_key     VARCHAR(400) NOT NULL
        COMMENT 'queue_name + 0x1F + ordering_key; see migration header for the size bound',
    last_sequence BIGINT NOT NULL DEFAULT 0
        COMMENT 'highest scope_sequence allocated for this scope',
    updated_at    DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
        ON UPDATE CURRENT_TIMESTAMP(6),
    PRIMARY KEY (scope_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
