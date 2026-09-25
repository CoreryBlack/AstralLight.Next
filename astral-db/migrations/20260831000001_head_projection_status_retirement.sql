-- Retire the legacy projection-status columns on authorization_projection_head
-- (projected_generation / projection_status) after the CARD/RULE_SET snapshot
-- chain decommission (20260827000002).
--
-- Rationale:
--   * The only authoritative CARD/RULE_SET projection read path is the new
--     delta chain (authorization_projection_current / manifest / delta event /
--     outbox terminal state). The legacy CARD/RULE_SET projection worker is
--     retired and never advances these columns again, so on CARD/RULE_SET rows
--     they are permanently stale (PENDING / projected=0) and only mislead
--     monitoring into reading legacy status as new-chain health.
--   * The ELIGIBILITY consumer is re-homed in the same change set: the worker
--     no longer advances head READY, the eligibility cache fence compares
--     (source_generation, revoke_fence) only, and the PolicyEngine
--     ProjectionGate readiness is "head exists with source_generation > 0".
--   * `source_generation` / `revoke_fence` / `last_event_id` STAY: they are the
--     live durable write-side anchors (operation identity derivation, FOR
--     UPDATE serialization, writer correlation) for CARD/RULE_SET/ELIGIBILITY.
--
-- Prototype scope decision (user-approved 2026-08-31): the pre-DROP backup and
-- rollback rehearsal required for production migrations are waived; the
-- rollback block below rebuilds structure only. Re-applying this migration
-- after a rollback is the documented forward path.
--
-- Safety properties:
--   - Guarded: each statement applies only when the object still exists.
--   - Idempotent: repeated execution converges to the same state (absent).
--   - Deploy order: apply WITH (or before) binaries of the same change set;
--     code of the same change set never references the dropped columns.

SET @astral_db = DATABASE();

-- Drop the two status indexes first (guarded).
SET @astral_idx_count = (
    SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_projection_head'
      AND INDEX_NAME = 'idx_aph_status');
SET @astral_sql = IF(@astral_idx_count = 1,
    'ALTER TABLE authorization_projection_head DROP INDEX idx_aph_status',
    'SELECT 1 AS idx_aph_status_already_absent');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_idx_count = (
    SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_projection_head'
      AND INDEX_NAME = 'idx_aph_generation');
SET @astral_sql = IF(@astral_idx_count = 1,
    'ALTER TABLE authorization_projection_head DROP INDEX idx_aph_generation',
    'SELECT 1 AS idx_aph_generation_already_absent');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- Drop the two legacy status columns (guarded).
SET @astral_col_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_projection_head'
      AND COLUMN_NAME = 'projected_generation');
SET @astral_sql = IF(@astral_col_count = 1,
    'ALTER TABLE authorization_projection_head DROP COLUMN projected_generation',
    'SELECT 1 AS projected_generation_already_absent');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @astral_col_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_projection_head'
      AND COLUMN_NAME = 'projection_status');
SET @astral_sql = IF(@astral_col_count = 1,
    'ALTER TABLE authorization_projection_head DROP COLUMN projection_status',
    'SELECT 1 AS projection_status_already_absent');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- ===== ROLLBACK (commented; prototype waiver applies, rehearse before use) =====
--
-- Structure-only rebuild. The dropped status history cannot be restored: rows
-- come back with their declared defaults (projected_generation=0,
-- projection_status='READY'), which matches the pre-retirement "no worker
-- advancement" reality for CARD/RULE_SET but does NOT reproduce the last
-- ELIGIBILITY READY values. Downgrading code of this change set together with
-- the rollback re-enables the legacy READY semantics against those defaults.
--
-- ALTER TABLE authorization_projection_head
--     ADD COLUMN projected_generation BIGINT NOT NULL DEFAULT 0 AFTER source_generation,
--     ADD COLUMN projection_status VARCHAR(32) NOT NULL DEFAULT 'READY' AFTER revoke_fence;
-- ALTER TABLE authorization_projection_head
--     ADD KEY idx_aph_status (projection_status, updated_at),
--     ADD KEY idx_aph_generation (aggregate_type, source_generation, projected_generation);
