-- Dual-card separation (v5 contract): identity_card must not carry
-- organization ownership — tenant_id / domain_id belong to user_card only.
--
-- Contract sources:
--   - AGENTS.md §3.2: identity_card 表示认证身份，user_card 表示授权载体，
--     两者不得混用；租户边界归 user_card。
--   - Docs/sql/v5_astrallight_schema_2026-08-10.sql identity_card 表注释：
--     "不承担组织归属（tenant/domain 由 user_card 承载）"。
--
-- Why this migration exists: the platform-v4 canonical baseline
-- (Docs/sql/full_schema_v4.sql) still creates identity_card with
-- domain_id / tenant_id, KEY idx_ic_domain and FOREIGN KEY fk_ic_domain.
-- The Rust runtime never reads or writes these columns
-- (astral-identity/src/srv/card_repository.rs: "不再要求
-- identity_card.tenant_id/domain_id 与请求 scope 匹配"), and
-- astral-identity/tests/integration.rs::test_identity_card_crud enforces
-- their absence via information_schema (CI run 33292694691).
--
-- Safety properties:
--   - Guarded: each artifact is dropped only while it exists.
--   - Idempotent / re-entrant: repeated execution converges to the same
--     state (columns absent); a pre-cleaned database records no-op rows.
--   - Scope: identity_card only. user_card / platform_domain / the
--     identity auth columns (card_id / user_id / status / token_version /
--     expires_at / disabled_reason / last_used_at) are untouched.
--   - Rollback (forward-fix, commented below): re-adds the nullable legacy
--     columns, index and foreign key. The dropped VALUES are not recoverable
--     from this script — restoration of historical tenancy stamps requires a
--     pre-migration backup of identity_card. No Rust authorization path ever
--     consumed these columns, so their loss cannot widen or alter any
--     PolicyEngine decision.

SET @astral_db = DATABASE();

-- Guard + drop: fk_ic_domain (identity_card -> platform_domain).
SET @astral_fk_count = (
    SELECT COUNT(*) FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = @astral_db
      AND TABLE_NAME = 'identity_card'
      AND CONSTRAINT_NAME = 'fk_ic_domain'
      AND CONSTRAINT_TYPE = 'FOREIGN KEY');
SET @astral_sql = IF(@astral_fk_count = 1,
    'ALTER TABLE identity_card DROP FOREIGN KEY fk_ic_domain',
    'SELECT 1 AS fk_ic_domain_already_absent');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- Guard + drop: idx_ic_domain.
SET @astral_idx_count = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'identity_card'
      AND INDEX_NAME = 'idx_ic_domain');
SET @astral_sql = IF(@astral_idx_count > 0,
    'ALTER TABLE identity_card DROP INDEX idx_ic_domain',
    'SELECT 1 AS idx_ic_domain_already_absent');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- Guard + drop: domain_id column.
SET @astral_col_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'identity_card'
      AND COLUMN_NAME = 'domain_id');
SET @astral_sql = IF(@astral_col_count = 1,
    'ALTER TABLE identity_card DROP COLUMN domain_id',
    'SELECT 1 AS domain_id_already_absent');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- Guard + drop: tenant_id column.
SET @astral_col_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'identity_card'
      AND COLUMN_NAME = 'tenant_id');
SET @astral_sql = IF(@astral_col_count = 1,
    'ALTER TABLE identity_card DROP COLUMN tenant_id',
    'SELECT 1 AS tenant_id_already_absent');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

-- ===== ROLLBACK (forward-fix; manual, approved change window only) =====
-- Restores the legacy v4 shapes so historical tooling that still expects the
-- tenancy columns can run. Values are NULL after rebuild (see header).
-- ALTER TABLE identity_card
--   ADD COLUMN domain_id BIGINT NULL COMMENT '默认领域上下文 (pre-v5 legacy, re-added)',
--   ADD COLUMN tenant_id BIGINT NULL,
--   ADD INDEX idx_ic_domain (domain_id),
--   ADD CONSTRAINT fk_ic_domain FOREIGN KEY (domain_id)
--     REFERENCES platform_domain (domain_id) ON DELETE SET NULL;
