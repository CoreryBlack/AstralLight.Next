-- TrustGraph 业务表（平台套餐、部门、继承配置、跨组织授权）
-- 对齐 Java AstralGeneral + AstralTrustGraph 模块的业务表结构

-- ===== 平台套餐表 =====
CREATE TABLE IF NOT EXISTS platform_package (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price BIGINT COMMENT '套餐价格，单位：分',
    billing_cycle VARCHAR(32) COMMENT '计费周期：MONTHLY / YEARLY / ONE_TIME',
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' COMMENT '状态：ACTIVE / INACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_pp_status (status),
    INDEX idx_pp_billing_cycle (billing_cycle)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== 部门表 =====
CREATE TABLE IF NOT EXISTS department (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    parent_id BIGINT COMMENT '父部门ID（NULL 表示顶级部门）',
    domain_id BIGINT COMMENT '所属域ID',
    head_user_id BIGINT COMMENT '部门负责人用户ID',
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' COMMENT '状态：ACTIVE / INACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_dept_parent (parent_id),
    INDEX idx_dept_domain (domain_id),
    INDEX idx_dept_status (status),
    FOREIGN KEY (parent_id) REFERENCES department(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== 权限继承配置表 =====
CREATE TABLE IF NOT EXISTS permission_inheritance_config (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    resource_type VARCHAR(128) NOT NULL COMMENT '资源类型',
    inheritance_mode VARCHAR(32) NOT NULL DEFAULT 'NONE' COMMENT '继承模式：NONE / PARENT_ONLY / CUMULATIVE',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE INDEX idx_pic_resource_type (resource_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 初始化默认继承配置（已由 Java schema 种子数据存在，跳过）
-- INSERT IGNORE INTO permission_inheritance_config (resource_type, inheritance_mode) VALUES
--     ('learn_subject', 'PARENT_ONLY'),
--     ('learn_question', 'NONE'),
--     ('learn_exam', 'NONE'),
--     ('permission_rule', 'NONE'),
--     ('platform_tenant', 'CUMULATIVE');

-- ===== 跨组织授权表 =====
CREATE TABLE IF NOT EXISTS cross_org_grant (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    from_org_id BIGINT NOT NULL COMMENT '授权方组织ID',
    to_org_id BIGINT NOT NULL COMMENT '被授权方组织ID',
    resource VARCHAR(256) NOT NULL COMMENT '授权的资源类型',
    action VARCHAR(64) NOT NULL COMMENT '授权的动作',
    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' COMMENT '状态：ACTIVE / REVOKED / EXPIRED',
    expires_at TIMESTAMP NULL COMMENT '过期时间（NULL 表示永不过期）',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_cog_from (from_org_id),
    INDEX idx_cog_to (to_org_id),
    INDEX idx_cog_status (status),
    INDEX idx_cog_resource_action (resource, action),
    UNIQUE INDEX idx_cog_unique (from_org_id, to_org_id, resource, action, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
