-- Durable source-freshness classification for authorization delta events.
--
-- `invalidates_published_evidence = 1` means an unfinished delta can leave a
-- previously published manifest authorizing access that the source mutation has
-- removed or narrowed. Readers must therefore remain PENDING until the row is
-- SUCCEEDED. The classification is written by the source transaction from the
-- existing authorization-content comparison; it is intentionally not inferred
-- from a card-wide revoke fence on the read path.
--
-- The default is deliberately fail-closed. Existing non-terminal rows and any
-- writer not yet upgraded to bind the column remain blocking until their state
-- is durably reconciled. New writers explicitly store 0 only for ADD and
-- provenance-only/no-op UPDATE deltas, preserving the P3 write-storm contract.
--
-- This migration is additive and idempotent. It appends one column, performs
-- no data rewrite, creates no index, and leaves the creator migration checksum
-- untouched. The explicit Rust migration job is its only execution path.

SET @astral_db = DATABASE();

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_delta_event'
      AND COLUMN_NAME = 'invalidates_published_evidence'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE authorization_delta_event ADD COLUMN invalidates_published_evidence TINYINT NOT NULL DEFAULT 1',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;
