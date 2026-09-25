-- Rust-owned Phase 2 additive schema for authorization projection lineage and
-- revoke-fence persistence.
--
-- This migration is ADDITIVE and IDEMPOTENT only. It appends six columns to
-- existing Rust-owned tables; it never backfills, rewrites, drops or deletes
-- data, adds no foreign keys, no CHECK constraints and no indexes, and it does
-- not touch the immutable checksum or creator statements of
-- 20260825000002_incremental_projection_archive.sql.
--
-- The two fence lines this migration makes durable:
-- 1. Lineage: `authorization_projection_manifest.parent_manifest_id` records
--    the sealed parent manifest of generation *g* explicitly. The first
--    generation of an aggregate stores NULL; every subsequent generation
--    stores the locked current manifest id with generation = target - 1 and
--    the same aggregate scope. Staging and replay verification compare this
--    column byte-for-byte instead of re-deriving lineage implicitly.
-- 2. Revoke fences:
--    - `authorization_projection_manifest.revoke_fence` — the fence value a
--      generation was published under (pinned again by the publish promotion).
--    - `authorization_projection_current.revoke_fence` — the authoritative
--      previous fence of the live pointer. Publications must present evidence
--      equal to it and move it atomically inside the pointer CAS.
--    - `authorization_projection_current.revoke_fence_proven` — a monotonic
--      proof latch. The latch value — never the numeric fence — identifies
--      legacy unproven history: `revoke_fence_proven = 0` means the row
--      predates this Rust contract and requires explicit backfill/rehearsal;
--      `1` means the pointer was written by the Rust publication path. A
--      numeric fence of zero is valid and authoritative when the latch is 1
--      (a proven zero may later advance to a positive fence), and the latch
--      itself is never inferred from a numeric fence.
--    - `authorization_archive_outbox.archived_revoke_fence` and
--      `authorization_archive_manifest.archived_revoke_fence` — copied from
--      the locked parent manifest/current evidence when archive intent and
--      proof are written; callers may never guess them.
--
-- ZERO-SENTINEL CONTRACT (must stay aligned with astral-db repository code):
-- a numeric fence of `0` is the safe initial value meaning "no revoke
-- observed" once the durable proof latch (`revoke_fence_proven = 1`)
-- certifies the row was written by this contract; a proven zero is
-- authoritative evidence and may later advance to a positive fence. The
-- latch — never the numeric value — identifies legacy unproven history: a
-- row still carrying `revoke_fence_proven = 0` predates this contract, and
-- its numeric fence (including zero) is NOT evidence of historical
-- completeness. Such an unproven row fails closed and demands an explicit
-- backfill/rehearsal pass instead of inferring history. An unproven/unknown
-- state never widens authorization anywhere; every consumer treats unknown
-- as PENDING/DENY.
--
-- Every statement is conditional (information_schema probe plus PREPARE/
-- EXECUTE) so an interrupted DDL batch converges safely on retry while the
-- explicit Rust migration job remains the only execution path; application
-- startup stays strictly read-only. Columns are appended at the table tail
-- (no AFTER clause) so the pre-existing column layout keeps its positions.

SET @astral_db = DATABASE();

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_projection_manifest'
      AND COLUMN_NAME = 'parent_manifest_id'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE authorization_projection_manifest ADD COLUMN parent_manifest_id BIGINT NULL',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_projection_manifest'
      AND COLUMN_NAME = 'revoke_fence'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE authorization_projection_manifest ADD COLUMN revoke_fence BIGINT NOT NULL DEFAULT 0',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_projection_current'
      AND COLUMN_NAME = 'revoke_fence'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE authorization_projection_current ADD COLUMN revoke_fence BIGINT NOT NULL DEFAULT 0',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_projection_current'
      AND COLUMN_NAME = 'revoke_fence_proven'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE authorization_projection_current ADD COLUMN revoke_fence_proven BIGINT NOT NULL DEFAULT 0',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_archive_outbox'
      AND COLUMN_NAME = 'archived_revoke_fence'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE authorization_archive_outbox ADD COLUMN archived_revoke_fence BIGINT NOT NULL DEFAULT 0',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;

SET @astral_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'authorization_archive_manifest'
      AND COLUMN_NAME = 'archived_revoke_fence'
);
SET @astral_sql = IF(
    @astral_count = 0,
    'ALTER TABLE authorization_archive_manifest ADD COLUMN archived_revoke_fence BIGINT NOT NULL DEFAULT 0',
    'SELECT 1'
);
PREPARE astral_stmt FROM @astral_sql;
EXECUTE astral_stmt;
DEALLOCATE PREPARE astral_stmt;
