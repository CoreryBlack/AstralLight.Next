-- Isolated rehearsal rollback for the school-to-tenant association.
--
-- This script deliberately preserves archived school records, generated Tenant
-- rows, and migration audit rows. It only clears tenant_id backfills and marks
-- the audit mapping rolled back, so the idempotent Rust migration can be
-- rehearsed again. It refuses shared or production-like database names.

DELIMITER //

CREATE PROCEDURE rollback_school_tenant_cutover()
BEGIN
    IF COALESCE(@ASTRAL_MIGRATION_REHEARSAL, '') <> '1'
       OR DATABASE() NOT REGEXP '^astral_.*(test|rehearsal).*' THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'school-to-tenant rollback requires an isolated rehearsal database';
    END IF;

    UPDATE school_members sm
    JOIN school_tenant_migration m ON m.school_id = sm.school_id
    SET sm.tenant_id = NULL
    WHERE m.migration_status IN ('MIGRATED', 'VERIFIED');

    UPDATE user_profiles upf
    JOIN school_tenant_migration m ON m.school_id = upf.school_id
    SET upf.tenant_id = NULL
    WHERE m.migration_status IN ('MIGRATED', 'VERIFIED');

    UPDATE leaderboards lb
    JOIN school_tenant_migration m ON m.school_id = lb.school_id
    SET lb.tenant_id = NULL
    WHERE m.migration_status IN ('MIGRATED', 'VERIFIED');

    UPDATE schools s
    JOIN school_tenant_migration m ON m.school_id = s.id
    SET s.tenant_id = NULL
    WHERE m.migration_status IN ('MIGRATED', 'VERIFIED');

    UPDATE school_tenant_migration
    SET migration_status = 'ROLLED_BACK',
        rollback_note = 'isolated rehearsal rollback',
        verified_at = NULL
    WHERE migration_status IN ('MIGRATED', 'VERIFIED');
END//

START TRANSACTION//
CALL rollback_school_tenant_cutover()//
COMMIT//
DROP PROCEDURE rollback_school_tenant_cutover//

DELIMITER ;
