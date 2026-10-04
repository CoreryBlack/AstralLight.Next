-- Remove only redundant non-unique generation indexes. The unique indexes
-- uk_aip_target_generation and uk_apm_generation retain the same ordered keys.
--
-- Run only through the explicitly approved migration job with its schema
-- preflight and migration lock. Each DROP is conditional so partial DDL can
-- be re-entered only after an explicit, approved recovery decision.
--
-- Recovery: reconcile both tables and preserve migration history. SQLx writes
-- success=0 before MySQL DDL; a later failure leaves a dirty row and the normal
-- job refuses rerun. Conditional SQL does not authorize clearing that row or
-- automatic replay. Dirty/unknown outcomes require separate reviewed recovery
-- with schema, checksum and history proof before this job can run again.
-- An older binary still requires the old index shape: do not downgrade
-- directly. Rebuilding the ordinary indexes requires an approved compensation
-- migration and a compatible exact-shape resolver; manually recreating them
-- after this version is recorded is schema drift.

SET @astral_db = DATABASE();

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_impact_plan'
      AND INDEX_NAME = 'idx_aip_aggregate'
);
SET @astral_sql = IF(
    @astral_count > 0,
    'ALTER TABLE authorization_impact_plan DROP INDEX idx_aip_aggregate',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_projection_manifest'
      AND INDEX_NAME = 'idx_apm_aggregate'
);
SET @astral_sql = IF(
    @astral_count > 0,
    'ALTER TABLE authorization_projection_manifest DROP INDEX idx_apm_aggregate',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;
