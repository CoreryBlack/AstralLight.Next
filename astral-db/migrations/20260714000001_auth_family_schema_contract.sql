-- Canonical forward migration for auth token families and device sessions.
--
-- The canonical contract is intentionally numeric:
--   auth_token_family.family_id       BIGINT AUTO_INCREMENT PRIMARY KEY
--   auth_token_family.family_key      VARCHAR(255) UNIQUE
--   auth_device_session.session_id    BIGINT AUTO_INCREMENT PRIMARY KEY
--   auth_device_session.family_id     BIGINT FK -> auth_token_family.family_id
--
-- Older Rust deployments used auth_token_family.id + VARCHAR family_id and
-- auth_device_session.id + BIGINT epoch timestamps.  This migration preserves
-- their keys as family_key/metadata and expires sessions that cannot be mapped
-- to a family.  No credentials or raw tokens are introduced.

SET @db = DATABASE();

-- Drop the old family FK, if one was created by a partial deployment.  It is
-- recreated after the referenced columns have their canonical types.
SET @fk = (
    SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = @db
      AND TABLE_NAME = 'auth_device_session'
      AND CONSTRAINT_NAME = 'fk_ads_family'
);
SET @sql = IF(@fk > 0,
    'ALTER TABLE auth_device_session DROP FOREIGN KEY fk_ads_family',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- ===== auth_token_family: convert id/VARCHAR family_id to canonical IDs =====
SET @has_old_id = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'auth_token_family'
      AND COLUMN_NAME = 'id'
);
SET @has_family_id = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'auth_token_family'
      AND COLUMN_NAME = 'family_id'
);
SET @family_id_is_text = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'auth_token_family'
      AND COLUMN_NAME = 'family_id'
      AND DATA_TYPE IN ('char', 'varchar', 'text', 'tinytext', 'mediumtext', 'longtext')
);
SET @has_family_key = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'auth_token_family'
      AND COLUMN_NAME = 'family_key'
);
SET @sql = IF(@has_family_key = 0,
    'ALTER TABLE auth_token_family ADD COLUMN family_key VARCHAR(255) NULL AFTER user_id',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @has_family_key = 1;

-- Preserve the old business key before renaming the old VARCHAR column.
SET @sql = IF(@family_id_is_text > 0 AND @has_old_id > 0,
    'UPDATE auth_token_family SET family_key = COALESCE(NULLIF(family_key, ''''), NULLIF(family_id, ''''), CONCAT(''legacy-'', id)) WHERE family_key IS NULL OR family_key = ''''',
    IF(@has_family_key > 0,
       'UPDATE auth_token_family SET family_key = COALESCE(NULLIF(family_key, ''''), CONCAT(''legacy-'', family_id)) WHERE family_key IS NULL OR family_key = ''''',
       'SELECT 1'));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- The old unique indexes use the old family_id column and must be removed
-- before that column is renamed.
SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'auth_token_family' AND INDEX_NAME = 'uk_atf_family');
SET @sql = IF(@idx > 0, 'ALTER TABLE auth_token_family DROP INDEX uk_atf_family', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'auth_token_family' AND INDEX_NAME = 'uk_atf_family_id');
SET @sql = IF(@idx > 0, 'ALTER TABLE auth_token_family DROP INDEX uk_atf_family_id', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Keep the legacy numeric PK only as a temporary mapping column.  A fresh
-- canonical table already has family_id BIGINT and skips this block.
SET @sql = IF(@has_old_id > 0 AND @family_id_is_text > 0,
    'ALTER TABLE auth_token_family CHANGE COLUMN id legacy_family_id BIGINT NOT NULL, CHANGE COLUMN family_id legacy_family_key VARCHAR(255) NOT NULL',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @sql = IF(@has_old_id > 0 AND @family_id_is_text > 0,
    'ALTER TABLE auth_token_family MODIFY COLUMN legacy_family_id BIGINT NOT NULL',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @sql = IF(@has_old_id > 0 AND @family_id_is_text > 0,
    'ALTER TABLE auth_token_family DROP PRIMARY KEY, ADD COLUMN family_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY FIRST',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Add/normalize the remaining canonical family columns.
SET @n = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_token_family' AND COLUMN_NAME='issued_at');
SET @sql = IF(@n=0, 'ALTER TABLE auth_token_family ADD COLUMN issued_at DATETIME NULL AFTER status', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @has_created_at = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_token_family' AND COLUMN_NAME='created_at');
SET @sql = IF(@has_created_at > 0,
    'UPDATE auth_token_family SET issued_at = COALESCE(issued_at, created_at, CURRENT_TIMESTAMP)',
    'UPDATE auth_token_family SET issued_at = COALESCE(issued_at, CURRENT_TIMESTAMP)');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
ALTER TABLE auth_token_family MODIFY COLUMN issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;

SET @n = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_token_family' AND COLUMN_NAME='expires_at');
SET @sql = IF(@n=0, 'ALTER TABLE auth_token_family ADD COLUMN expires_at DATETIME NULL', 'ALTER TABLE auth_token_family MODIFY COLUMN expires_at DATETIME NULL');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @n = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_token_family' AND COLUMN_NAME='revoked_at');
SET @sql = IF(@n=0, 'ALTER TABLE auth_token_family ADD COLUMN revoked_at DATETIME NULL', 'ALTER TABLE auth_token_family MODIFY COLUMN revoked_at DATETIME NULL');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @n = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_token_family' AND COLUMN_NAME='revoked_reason');
SET @sql = IF(@n=0, 'ALTER TABLE auth_token_family ADD COLUMN revoked_reason VARCHAR(512) NULL', 'ALTER TABLE auth_token_family MODIFY COLUMN revoked_reason VARCHAR(512) NULL');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @n = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_token_family' AND COLUMN_NAME='metadata_json');
SET @sql = IF(@n=0, 'ALTER TABLE auth_token_family ADD COLUMN metadata_json JSON NULL', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
ALTER TABLE auth_token_family MODIFY COLUMN family_key VARCHAR(255) NOT NULL;

-- ===== auth_device_session: canonical names/types and family mapping =====
SET @has_session_id = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND COLUMN_NAME='session_id');
SET @has_session_legacy_id = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND COLUMN_NAME='id');
SET @sql = IF(@has_session_id=0 AND @has_session_legacy_id>0,
    'ALTER TABLE auth_device_session CHANGE COLUMN id session_id BIGINT NOT NULL AUTO_INCREMENT',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @n = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND COLUMN_NAME='family_id');
SET @sql = IF(@n=0, 'ALTER TABLE auth_device_session ADD COLUMN family_id BIGINT NULL AFTER session_id', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @n = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND COLUMN_NAME='family_id_new');
SET @sql = IF(@n=0, 'ALTER TABLE auth_device_session ADD COLUMN family_id_new BIGINT NULL AFTER session_id', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Map both old VARCHAR family keys and old numeric storage IDs.  The direct
-- numeric mapping also makes this safe for partially migrated installations.
UPDATE auth_device_session s
JOIN auth_token_family f ON CAST(s.family_id AS CHAR) = f.family_key
SET s.family_id_new = f.family_id
WHERE s.family_id IS NOT NULL;
SET @has_legacy_family_id = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_token_family' AND COLUMN_NAME='legacy_family_id');
SET @sql = IF(@has_legacy_family_id > 0,
    'UPDATE auth_device_session s JOIN auth_token_family f ON CAST(s.family_id AS UNSIGNED) = f.legacy_family_id SET s.family_id_new = f.family_id WHERE s.family_id IS NOT NULL AND s.family_id REGEXP ''^[0-9]+$''',
    'UPDATE auth_device_session s JOIN auth_token_family f ON s.family_id = f.family_id SET s.family_id_new = f.family_id WHERE s.family_id IS NOT NULL');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Retain otherwise unusable historical rows as EXPIRED sessions, each under a
-- synthetic EXPIRED family.  This keeps the new FK valid without inventing a
-- usable credential or silently turning an old session back on.
INSERT INTO auth_token_family (user_id, family_key, status, issued_at, metadata_json)
SELECT s.user_id, CONCAT('legacy-session-', s.session_id), 'EXPIRED', CURRENT_TIMESTAMP,
       JSON_OBJECT('source', 'auth_family_schema_contract', 'reason', 'unmapped_session')
FROM auth_device_session s
WHERE s.family_id_new IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM auth_token_family f
      WHERE f.family_key = CONCAT('legacy-session-', s.session_id)
  );
UPDATE auth_device_session s
JOIN auth_token_family f ON f.family_key = CONCAT('legacy-session-', s.session_id)
SET s.family_id_new = f.family_id, s.status = 'EXPIRED'
WHERE s.family_id_new IS NULL;

-- Replace the old family_id column with the canonical BIGINT column. Drop
-- the legacy index first because MySQL will not drop an indexed column.
SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND INDEX_NAME='idx_ads_family');
SET @sql = IF(@idx > 0, 'ALTER TABLE auth_device_session DROP INDEX idx_ads_family', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
ALTER TABLE auth_device_session DROP COLUMN family_id;
ALTER TABLE auth_device_session CHANGE COLUMN family_id_new family_id BIGINT NOT NULL AFTER session_id;

-- Add columns that were absent in the original Phase 5 table.
SET @n = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND COLUMN_NAME='device_type');
SET @sql = IF(@n=0, 'ALTER TABLE auth_device_session ADD COLUMN device_type VARCHAR(64) NULL AFTER device_id', 'ALTER TABLE auth_device_session MODIFY COLUMN device_type VARCHAR(64) NULL');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @n = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND COLUMN_NAME='client_app_id');
SET @sql = IF(@n=0, 'ALTER TABLE auth_device_session ADD COLUMN client_app_id VARCHAR(128) NULL', 'ALTER TABLE auth_device_session MODIFY COLUMN client_app_id VARCHAR(128) NULL');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @n = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND COLUMN_NAME='channel_code');
SET @sql = IF(@n=0, 'ALTER TABLE auth_device_session ADD COLUMN channel_code VARCHAR(64) NULL', 'ALTER TABLE auth_device_session MODIFY COLUMN channel_code VARCHAR(64) NULL');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @has_current_card = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND COLUMN_NAME='current_user_card_id');
SET @has_card_id = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND COLUMN_NAME='card_id');
SET @renamed_card_id = IF(@has_current_card=0 AND @has_card_id>0, 1, 0);
SET @sql = IF(@renamed_card_id=1,
    'ALTER TABLE auth_device_session CHANGE COLUMN card_id current_user_card_id BIGINT NULL',
    IF(@has_current_card=0, 'ALTER TABLE auth_device_session ADD COLUMN current_user_card_id BIGINT NULL', 'SELECT 1'));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @has_current_card = 1;
SET @sql = IF(@renamed_card_id=0 AND @has_card_id>0,
    'UPDATE auth_device_session SET current_user_card_id = COALESCE(current_user_card_id, card_id)',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @sql = IF(@renamed_card_id=0 AND @has_card_id>0,
    'ALTER TABLE auth_device_session DROP COLUMN card_id',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @n = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND COLUMN_NAME='refresh_expires_at');
SET @refresh_is_epoch = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND COLUMN_NAME='refresh_expires_at' AND DATA_TYPE IN ('bigint','int','integer','smallint','mediumint','tinyint','decimal'));
SET @refresh_new_exists = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND COLUMN_NAME='refresh_expires_at_new');
SET @sql = IF(@n=0,
    'ALTER TABLE auth_device_session ADD COLUMN refresh_expires_at DATETIME NULL',
    IF(@refresh_is_epoch>0 AND @refresh_new_exists=0,
       'ALTER TABLE auth_device_session ADD COLUMN refresh_expires_at_new DATETIME NULL',
       IF(@refresh_is_epoch=0, 'ALTER TABLE auth_device_session MODIFY COLUMN refresh_expires_at DATETIME NULL', 'SELECT 1')));
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @sql = IF(@refresh_is_epoch>0,
    'UPDATE auth_device_session SET refresh_expires_at_new = FROM_UNIXTIME(NULLIF(refresh_expires_at, 0))',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @sql = IF(@refresh_is_epoch>0,
    'ALTER TABLE auth_device_session DROP COLUMN refresh_expires_at, CHANGE COLUMN refresh_expires_at_new refresh_expires_at DATETIME NULL',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @n = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND COLUMN_NAME='last_seen_at');
SET @sql = IF(@n=0, 'ALTER TABLE auth_device_session ADD COLUMN last_seen_at DATETIME NULL', 'ALTER TABLE auth_device_session MODIFY COLUMN last_seen_at DATETIME NULL');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @n = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND COLUMN_NAME='revoked_at');
SET @sql = IF(@n=0, 'ALTER TABLE auth_device_session ADD COLUMN revoked_at DATETIME NULL', 'ALTER TABLE auth_device_session MODIFY COLUMN revoked_at DATETIME NULL');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @n = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND COLUMN_NAME='revoked_reason');
SET @sql = IF(@n=0, 'ALTER TABLE auth_device_session ADD COLUMN revoked_reason VARCHAR(512) NULL', 'ALTER TABLE auth_device_session MODIFY COLUMN revoked_reason VARCHAR(512) NULL');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @n = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND COLUMN_NAME='created_at');
SET @sql = IF(@n=0, 'ALTER TABLE auth_device_session ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP', 'ALTER TABLE auth_device_session MODIFY COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @n = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND COLUMN_NAME='updated_at');
SET @sql = IF(@n=0, 'ALTER TABLE auth_device_session ADD COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP', 'ALTER TABLE auth_device_session MODIFY COLUMN updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Original Phase 5 allowed an empty device id.  The canonical contract is
-- non-null; preserve those rows as an explicit unknown device.
UPDATE auth_device_session SET device_id = 'unknown' WHERE device_id IS NULL OR device_id = '';
ALTER TABLE auth_device_session MODIFY COLUMN device_id VARCHAR(255) NOT NULL;
ALTER TABLE auth_device_session MODIFY COLUMN refresh_token_hash VARCHAR(255) NOT NULL;
ALTER TABLE auth_device_session MODIFY COLUMN session_id BIGINT NOT NULL AUTO_INCREMENT;

-- Remove migration-only columns and legacy family columns after all mappings.
SET @has_legacy_key = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_token_family' AND COLUMN_NAME='legacy_family_key');
SET @sql = IF(@has_legacy_key > 0, 'ALTER TABLE auth_token_family DROP COLUMN legacy_family_key', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @has_legacy_id = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_token_family' AND COLUMN_NAME='legacy_family_id');
SET @sql = IF(@has_legacy_id > 0, 'ALTER TABLE auth_token_family DROP COLUMN legacy_family_id', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @has_card = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_token_family' AND COLUMN_NAME='card_id');
SET @sql = IF(@has_card > 0, 'ALTER TABLE auth_token_family DROP COLUMN card_id', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @has_created_at = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_token_family' AND COLUMN_NAME='created_at');
SET @sql = IF(@has_created_at > 0, 'ALTER TABLE auth_token_family DROP COLUMN created_at', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Canonical indexes and FK.  The referenced key and child key are both
-- BIGINT, so the resilience DDL's session_id FK is usable as well.
SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_token_family' AND INDEX_NAME='uk_atf_family_key');
SET @sql = IF(@idx=0, 'ALTER TABLE auth_token_family ADD UNIQUE KEY uk_atf_family_key (family_key)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_token_family' AND INDEX_NAME='idx_atf_user');
SET @sql = IF(@idx=0, 'ALTER TABLE auth_token_family ADD KEY idx_atf_user (user_id)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_token_family' AND INDEX_NAME='idx_atf_status');
SET @sql = IF(@idx=0, 'ALTER TABLE auth_token_family ADD KEY idx_atf_status (status)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND INDEX_NAME='idx_ads_family');
SET @sql = IF(@idx=0, 'ALTER TABLE auth_device_session ADD KEY idx_ads_family (family_id)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND INDEX_NAME='uk_ads_refresh_token');
SET @sql = IF(@idx=0, 'ALTER TABLE auth_device_session ADD UNIQUE KEY uk_ads_refresh_token (refresh_token_hash)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND INDEX_NAME='idx_ads_user_device');
SET @sql = IF(@idx=0, 'ALTER TABLE auth_device_session ADD KEY idx_ads_user_device (user_id, device_id)', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @fk = (SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=@db AND TABLE_NAME='auth_device_session' AND CONSTRAINT_NAME='fk_ads_family');
SET @sql = IF(@fk=0, 'ALTER TABLE auth_device_session ADD CONSTRAINT fk_ads_family FOREIGN KEY (family_id) REFERENCES auth_token_family (family_id) ON DELETE CASCADE', 'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Durable session state shared with Java.  The state/version/epoch triple is
-- the CAS fence used by refresh rotation, card switching, and revocation.
ALTER TABLE auth_device_session
    ADD COLUMN IF NOT EXISTS session_state VARCHAR(32) NOT NULL DEFAULT 'ACTIVE' AFTER current_user_card_id;
ALTER TABLE auth_device_session
    ADD COLUMN IF NOT EXISTS session_version BIGINT NOT NULL DEFAULT 1 AFTER session_state;
ALTER TABLE auth_device_session
    ADD COLUMN IF NOT EXISTS session_epoch BIGINT NOT NULL DEFAULT 1 AFTER session_version;
UPDATE auth_device_session
SET session_state = CASE
        WHEN session_state IS NULL OR session_state = '' THEN COALESCE(NULLIF(status, ''), 'ACTIVE')
        ELSE session_state
    END,
    session_version = CASE WHEN session_version IS NULL OR session_version < 1 THEN 1 ELSE session_version END,
    session_epoch = CASE WHEN session_epoch IS NULL OR session_epoch < 1 THEN 1 ELSE session_epoch END;
