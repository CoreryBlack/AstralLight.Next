-- Add an explicit discriminator and atomic course-scoped identity for Learn's
-- synthetic system assignments. Historical assignments remain NULL and are not
-- inferred from title, status, id, or submission rows.
--
-- The binary collation makes the reserved DEFAULT_GRADE marker exact and
-- case-sensitive. Multiple ordinary assignments with NULL system_role remain
-- valid under MySQL's UNIQUE NULL semantics.

SET @astral_db = DATABASE();

SET @system_role_count = (
    SELECT COUNT(*) FROM information_schema.COLUMNS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'learn_assignment'
      AND COLUMN_NAME = 'system_role');
SET @astral_sql = IF(@system_role_count = 0,
    'ALTER TABLE learn_assignment ADD COLUMN system_role VARCHAR(32) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NULL DEFAULT NULL',
    'SELECT 1 AS system_role_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;

SET @system_role_index_count = (
    SELECT COUNT(DISTINCT INDEX_NAME) FROM information_schema.STATISTICS
    WHERE TABLE_SCHEMA = @astral_db
      AND TABLE_NAME = 'learn_assignment'
      AND INDEX_NAME = 'uk_learn_assignment_course_system_role');
SET @astral_sql = IF(@system_role_index_count = 0,
    'ALTER TABLE learn_assignment ADD UNIQUE KEY uk_learn_assignment_course_system_role (course_id, system_role)',
    'SELECT 1 AS system_role_index_already_present');
PREPARE astral_stmt FROM @astral_sql; EXECUTE astral_stmt; DEALLOCATE PREPARE astral_stmt;
