-- Password-reset delivery binding (taskId authority-v7-peripheral-20261107,
-- post-review fix; approved additive artifact, NEVER executed by agents).
--
-- Binds every password_reset_token row to its shared delivery intent so the
-- reset credential is PENDING-by-construction:
--
--   * delivery_message_id  — the stable `al_delivery_intent.message_id` the
--     credential was dispatched under (DeliveryOwner::message_id_for_operation);
--   * operation_id         — the caller operation id (audit correlation,
--     mirrors al_delivery_intent.operation_id).
--
-- Consumption contract: the reset consumption UPDATE joins
-- al_delivery_intent on message_id (index probe) and requires, in the same
-- password update transaction: state = 'DELIVERED' plus BYTE-EXACT equality
-- of both bindings via CAST(... AS BINARY) for message_id AND operation_id
-- (the intent columns are utf8mb4_unicode_ci while the binding columns are
-- ascii_bin; a raw `=` would coerce to case/pad-insensitive matching).
-- Old rows (columns NULL — CAST(NULL) never satisfies a predicate) and rows
-- whose delivery is not durably DELIVERED or whose operation binding is
-- missing/mismatched can NEVER be consumed — no automatic backfill, and none
-- is planned.
--
-- Preflight: each guarded statement below re-checks information_schema, so an
-- interrupted additive batch can be rerun by the explicit migration job
-- without rewriting historical rows.
-- Postcondition: the exact-artifact contract
-- (astral-db/src/migration/password_reset_delivery_binding.rs) pins both
-- columns and the index against this file's canonical LF SHA-384.
-- Rollback (forward-fix, commented): the binding values are NOT recoverable
-- from this script — rows bound before rollback lose their delivery evidence
-- association and their tokens can no longer be consumed (fail-closed):
--   ALTER TABLE password_reset_token DROP INDEX idx_prt_delivery_message;
--   ALTER TABLE password_reset_token DROP COLUMN operation_id;
--   ALTER TABLE password_reset_token DROP COLUMN delivery_message_id;
-- Back up the two columns before rollback if consumption continuity matters.

SET @astral_db = DATABASE();

-- Guarded additive column: delivery_message_id (delivery intent identity).
SET @astral_column = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'password_reset_token'
      AND COLUMN_NAME = 'delivery_message_id'
);
SET @astral_sql = IF(
    @astral_column = 0,
    'ALTER TABLE password_reset_token \
       ADD COLUMN delivery_message_id VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL \
       COMMENT ''al_delivery_intent.message_id this credential was dispatched under'' \
       AFTER card_number',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

-- Guarded additive column: operation_id (stable caller operation correlation).
SET @astral_column = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'password_reset_token'
      AND COLUMN_NAME = 'operation_id'
);
SET @astral_sql = IF(
    @astral_column = 0,
    'ALTER TABLE password_reset_token \
       ADD COLUMN operation_id VARCHAR(192) CHARACTER SET ascii COLLATE ascii_bin NULL \
       COMMENT ''caller operation id; audit + delivery intent correlation'' \
       AFTER delivery_message_id',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

-- Guarded additive index: consumption-gate lookups by delivery binding.
SET @astral_index = (
    SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'password_reset_token'
      AND INDEX_NAME = 'idx_prt_delivery_message'
);
SET @astral_sql = IF(
    @astral_index = 0,
    'ALTER TABLE password_reset_token \
       ADD INDEX idx_prt_delivery_message (delivery_message_id)',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;
