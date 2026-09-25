-- Rust-owned platform-v4 schema extension and school-to-tenant cutover.
--
-- This migration is executed only by the explicit `astral-migrate` job. It
-- preserves schools as a read-only archive and makes tenant_id the runtime
-- isolation key for migrated Learn data.

ALTER TABLE tenant
    ADD COLUMN IF NOT EXISTS org_id BIGINT NULL AFTER settings_json;
ALTER TABLE tenant
    ADD COLUMN IF NOT EXISTS country VARCHAR(16) NULL AFTER org_id;
ALTER TABLE tenant
    ADD COLUMN IF NOT EXISTS province VARCHAR(64) NULL AFTER country;
ALTER TABLE tenant
    ADD COLUMN IF NOT EXISTS city VARCHAR(64) NULL AFTER province;
ALTER TABLE tenant
    ADD COLUMN IF NOT EXISTS district VARCHAR(64) NULL AFTER city;
ALTER TABLE tenant
    ADD COLUMN IF NOT EXISTS address VARCHAR(512) NULL AFTER district;
ALTER TABLE tenant
    ADD COLUMN IF NOT EXISTS postal_code VARCHAR(32) NULL AFTER address;
ALTER TABLE tenant
    ADD COLUMN IF NOT EXISTS website VARCHAR(512) NULL AFTER postal_code;
ALTER TABLE tenant
    ADD COLUMN IF NOT EXISTS description TEXT NULL AFTER website;
ALTER TABLE tenant
    ADD COLUMN IF NOT EXISTS verified TINYINT(1) NOT NULL DEFAULT 0 AFTER description;

CREATE TABLE IF NOT EXISTS school_tenant_migration (
    school_id BIGINT NOT NULL,
    tenant_id BIGINT NOT NULL,
    tenant_code VARCHAR(64) NOT NULL,
    migration_status VARCHAR(32) NOT NULL DEFAULT 'MIGRATED',
    migrated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    verified_at DATETIME NULL,
    rollback_note VARCHAR(512) NULL,
    PRIMARY KEY (school_id),
    UNIQUE KEY uk_school_tenant_migration_tenant (tenant_id),
    UNIQUE KEY uk_school_tenant_migration_code (tenant_code),
    KEY idx_school_tenant_migration_status (migration_status),
    CONSTRAINT fk_school_tenant_migration_school
        FOREIGN KEY (school_id) REFERENCES schools (id) ON DELETE RESTRICT,
    CONSTRAINT fk_school_tenant_migration_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenant (tenant_id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Schools to tenants migration audit mapping';

ALTER TABLE school_members
    ADD COLUMN IF NOT EXISTS tenant_id BIGINT NULL AFTER school_id;
ALTER TABLE user_profiles
    ADD COLUMN IF NOT EXISTS tenant_id BIGINT NULL AFTER school_id;
ALTER TABLE leaderboards
    ADD COLUMN IF NOT EXISTS tenant_id BIGINT NULL AFTER school_id;

SET @db = DATABASE();
SET @idx = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'school_members'
      AND INDEX_NAME = 'idx_school_members_tenant'
);
SET @sql = IF(@idx = 0,
    'ALTER TABLE school_members ADD KEY idx_school_members_tenant (tenant_id)',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'user_profiles'
      AND INDEX_NAME = 'idx_user_profiles_tenant'
);
SET @sql = IF(@idx = 0,
    'ALTER TABLE user_profiles ADD KEY idx_user_profiles_tenant (tenant_id)',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @idx = (
    SELECT COUNT(*) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'leaderboards'
      AND INDEX_NAME = 'idx_leaderboards_tenant'
);
SET @sql = IF(@idx = 0,
    'ALTER TABLE leaderboards ADD KEY idx_leaderboards_tenant (tenant_id)',
    'SELECT 1');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- One archived school maps to exactly one stable tenant. Existing tenants are
-- reused by deterministic school-derived codes, so this operation is replay-safe.
INSERT INTO tenant (
    tenant_code, tenant_name, tenant_type, status,
    contact_person, contact_phone, contact_email,
    country, province, city, district, address, postal_code,
    logo_url, website, description, settings_json, verified
)
SELECT
    CONCAT('SCHOOL-', s.id),
    s.name,
    'LEARN_SCHOOL',
    CASE WHEN s.status = 'ACTIVE' THEN 'ACTIVE' ELSE 'DISABLED' END,
    s.contact_person, s.contact_phone, s.contact_email,
    s.country, s.province, s.city, s.district, s.address, s.postal_code,
    s.logo_url, s.website, s.description, s.settings, COALESCE(s.verified, 0)
FROM schools s
ON DUPLICATE KEY UPDATE
    tenant_name = VALUES(tenant_name),
    tenant_type = VALUES(tenant_type),
    status = VALUES(status),
    contact_person = VALUES(contact_person),
    contact_phone = VALUES(contact_phone),
    contact_email = VALUES(contact_email),
    country = VALUES(country),
    province = VALUES(province),
    city = VALUES(city),
    district = VALUES(district),
    address = VALUES(address),
    postal_code = VALUES(postal_code),
    logo_url = VALUES(logo_url),
    website = VALUES(website),
    description = VALUES(description),
    settings_json = VALUES(settings_json),
    verified = VALUES(verified);

INSERT INTO school_tenant_migration (school_id, tenant_id, tenant_code, migration_status, migrated_at)
SELECT s.id, t.tenant_id, CONCAT('SCHOOL-', s.id), 'MIGRATED', CURRENT_TIMESTAMP
FROM schools s
JOIN tenant t ON t.tenant_code = CONCAT('SCHOOL-', s.id)
ON DUPLICATE KEY UPDATE
    tenant_id = VALUES(tenant_id),
    tenant_code = VALUES(tenant_code),
    migration_status = 'MIGRATED',
    migrated_at = CURRENT_TIMESTAMP;

UPDATE schools s
JOIN school_tenant_migration m ON m.school_id = s.id
SET s.tenant_id = m.tenant_id
WHERE s.tenant_id IS NULL OR s.tenant_id <> m.tenant_id;

UPDATE school_members sm
JOIN school_tenant_migration m ON m.school_id = sm.school_id
SET sm.tenant_id = m.tenant_id
WHERE sm.tenant_id IS NULL OR sm.tenant_id <> m.tenant_id;

UPDATE user_profiles upf
JOIN school_tenant_migration m ON m.school_id = upf.school_id
SET upf.tenant_id = m.tenant_id
WHERE upf.tenant_id IS NULL OR upf.tenant_id <> m.tenant_id;

UPDATE leaderboards lb
JOIN school_tenant_migration m ON m.school_id = lb.school_id
SET lb.tenant_id = m.tenant_id
WHERE lb.tenant_id IS NULL OR lb.tenant_id <> m.tenant_id;

UPDATE school_tenant_migration m
JOIN schools s ON s.id = m.school_id
SET m.verified_at = CURRENT_TIMESTAMP,
    m.migration_status = 'VERIFIED'
WHERE s.tenant_id = m.tenant_id;
