-- Identity credential and MFA replay/attempt fences.
-- Existing credentials start at revision 1; only password changes advance it.
SET @db = DATABASE();
SET @n = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'user_local_credential'
      AND COLUMN_NAME = 'credential_version'
);
SET @sql = IF(
    @n = 0,
    'ALTER TABLE user_local_credential ADD COLUMN credential_version BIGINT NOT NULL DEFAULT 1 AFTER password_hash',
    'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Store the last accepted TOTP time-step so the same factor code cannot be
-- replayed for another login or the standalone verification endpoint.
SET @n = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'user_mfa'
      AND COLUMN_NAME = 'last_totp_counter'
);
SET @sql = IF(
    @n = 0,
    'ALTER TABLE user_mfa ADD COLUMN last_totp_counter BIGINT NULL AFTER last_used_at',
    'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Pending attempts reserve one of the bounded verification slots. This makes
-- the rate limit race-safe across Identity replicas and preserves a failure
-- when a request is abandoned after claiming a slot.
SET @n = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'mfa_attempt_log'
      AND COLUMN_NAME = 'attempt_code'
);
SET @sql = IF(
    @n = 0,
    'ALTER TABLE mfa_attempt_log ADD COLUMN attempt_code VARCHAR(64) NULL AFTER mfa_type',
    'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @n = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'mfa_attempt_log'
      AND COLUMN_NAME = 'status'
);
SET @sql = IF(
    @n = 0,
    'ALTER TABLE mfa_attempt_log ADD COLUMN status VARCHAR(32) NOT NULL DEFAULT ''UNKNOWN'' AFTER attempt_code',
    'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @n = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'mfa_attempt_log'
      AND COLUMN_NAME = 'user_agent'
);
SET @sql = IF(
    @n = 0,
    'ALTER TABLE mfa_attempt_log ADD COLUMN user_agent VARCHAR(512) NULL AFTER ip',
    'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db
      AND TABLE_NAME = 'mfa_attempt_log'
      AND INDEX_NAME = 'uk_mal_attempt_code'
);
SET @sql = IF(
    @idx = 0,
    'ALTER TABLE mfa_attempt_log ADD UNIQUE KEY uk_mal_attempt_code (attempt_code)',
    'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db
      AND TABLE_NAME = 'mfa_attempt_log'
      AND INDEX_NAME = 'idx_mal_user_attempt_status'
);
SET @sql = IF(
    @idx = 0,
    'ALTER TABLE mfa_attempt_log ADD KEY idx_mal_user_attempt_status (user_id, attempted_at, success, status)',
    'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @n = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'auth_device_session'
      AND COLUMN_NAME = 'credential_version'
);
SET @sql = IF(
    @n = 0,
    'ALTER TABLE auth_device_session ADD COLUMN credential_version BIGINT NULL',
    'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db
      AND TABLE_NAME = 'auth_device_session'
      AND INDEX_NAME = 'idx_ads_user_credential_version'
);
SET @sql = IF(
    @idx = 0,
    'ALTER TABLE auth_device_session ADD KEY idx_ads_user_credential_version (user_id, credential_version, status)',
    'SELECT 1'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

