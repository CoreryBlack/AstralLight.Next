-- DomainControl 拆分后的 6 张业务表
-- 对齐 Java DomainControlController 拆分为 7 个独立 Controller 的数据模型
--
-- 注意：
-- - `domain` 表已在 00001_baseline.sql 创建，这里仅补充缺失的 code/updated_at 列
-- - `user_card` 表已在 00001_baseline.sql 创建，本迁移不重建
-- - 其余 5 张表为本迁移新增

-- ===== 1. domain 表补充列（code + updated_at）=====
-- 对齐 Java DomainController：name, code, org_id, status, created_at, updated_at
SET @db = (SELECT DATABASE());
-- 幂等添加列 code + updated_at
SET @db = (SELECT DATABASE());

SET @col1 = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'domain' AND COLUMN_NAME = 'code');
SET @sql1 = IF(@col1 = 0, 'ALTER TABLE domain ADD COLUMN code VARCHAR(128) NULL AFTER name', 'SELECT 1 AS code_exists');
PREPARE stmt1 FROM @sql1; EXECUTE stmt1; DEALLOCATE PREPARE stmt1;

SET @col2 = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'domain' AND COLUMN_NAME = 'updated_at');
SET @sql2 = IF(@col2 = 0, 'ALTER TABLE domain ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP AFTER created_at', 'SELECT 1 AS updated_at_exists');
PREPARE stmt2 FROM @sql2; EXECUTE stmt2; DEALLOCATE PREPARE stmt2;
SET @idx = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = (SELECT DATABASE()) AND TABLE_NAME = 'domain' AND INDEX_NAME = 'uk_domain_code');
SET @sql_idx = IF(@idx = 0, 'ALTER TABLE domain ADD UNIQUE INDEX uk_domain_code (code)', 'SELECT 1 AS uk_domain_code_exists');
PREPARE stmt_idx FROM @sql_idx; EXECUTE stmt_idx; DEALLOCATE PREPARE stmt_idx;

-- ===== 2. resource_type_registry 资源类型注册表 =====
-- 对齐 Java ResourceTypeController + ResourceRegistry 持久化
CREATE TABLE IF NOT EXISTS resource_type_registry (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    resource_type VARCHAR(128) NOT NULL COMMENT '资源类型编码（如 learn_subject）',
    actions_json TEXT NOT NULL COMMENT '合法动作集合 JSON 数组，如 ["read","create"]',
    description VARCHAR(512) COMMENT '资源类型描述',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_rtr_resource_type (resource_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== 3. permission_action 权限动作表 =====
-- 对齐 Java PermissionActionController
CREATE TABLE IF NOT EXISTS permission_action (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    action_code VARCHAR(64) NOT NULL COMMENT '动作编码（如 read/create/update/delete/scan）',
    description VARCHAR(512) COMMENT '动作描述',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uk_pa_action_code (action_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 初始化标准动作（已由 Java schema 种子数据存在，跳过）
-- INSERT IGNORE INTO permission_action (action_code, description) VALUES
--     ('read', '读取'),
--     ('create', '创建'),
--     ('update', '更新'),
--     ('delete', '删除'),
--     ('import', '导入'),
--     ('export', '导出'),
--     ('approve', '审批'),
--     ('publish', '发布'),
--     ('scan', '扫描'),
--     ('bind-permission', '绑定权限'),
--     ('write', '写入（create+update+delete 别名）');

-- ===== 4. identity_user_level_definition 用户等级定义表 =====
-- 对齐 Java UserLevelController + identity_user_level_definition 表
CREATE TABLE IF NOT EXISTS identity_user_level_definition (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    domain_id BIGINT NOT NULL COMMENT '所属域ID',
    level_name VARCHAR(128) NOT NULL COMMENT '等级名称（如 初级/中级/高级）',
    level_code VARCHAR(64) NOT NULL COMMENT '等级编码（如 L1/L2/L3）',
    level_value INT NOT NULL DEFAULT 0 COMMENT '等级数值（越大等级越高）',
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' COMMENT '状态：ACTIVE / INACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_iuld_domain (domain_id),
    INDEX idx_iuld_status (status),
    UNIQUE KEY uk_iuld_domain_code (domain_id, level_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== 5. identity_user_grading 用户分级表 =====
-- 对齐 Java UserGradingController + identity_user_grading 表
CREATE TABLE IF NOT EXISTS identity_user_grading (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL COMMENT '用户ID',
    level_id BIGINT NOT NULL COMMENT '等级定义ID（关联 identity_user_level_definition.id）',
    domain_id BIGINT NOT NULL COMMENT '所属域ID',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_iug_user (user_id),
    INDEX idx_iug_domain (domain_id),
    INDEX idx_iug_level (level_id),
    UNIQUE KEY uk_iug_user_domain (user_id, domain_id),
    FOREIGN KEY (level_id) REFERENCES identity_user_level_definition(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== 6. identity_level_template 等级模板表 =====
-- 对齐 Java LevelTemplateController + identity_level_template 表
CREATE TABLE IF NOT EXISTS identity_level_template (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL COMMENT '模板名称',
    description TEXT COMMENT '模板描述',
    levels_json TEXT NOT NULL COMMENT '等级定义 JSON 数组，含 level_name/level_code/level_value',
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' COMMENT '状态：ACTIVE / INACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_ilt_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
