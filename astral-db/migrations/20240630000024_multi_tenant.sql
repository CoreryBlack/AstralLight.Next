-- I-3: 多租户补充表（对齐 Java 多租户数据层基线）
--
-- 本迁移实现：
-- (1) tenant 表扩展：parent_tenant_id / path / depth 层级字段
-- (2) 5 张新租户表：tenant_domain_map / tenant_members / tenant_invitation
--     tenant_purchase / tenant_audit_log
--
-- Java 基线对照:
-- - TenantDomainMap.java: AstralGeneral/entity/platform/TenantDomainMap.java
-- - TenantMember.java:    AstralGeneral/entity/platform/TenantMember.java
-- - TenantInvitation.java: AstralGeneral/entity/platform/TenantInvitation.java
-- - TenantPurchase.java:  AstralGeneral/entity/platform/TenantPurchase.java
-- - TenantAuditLog.java:  AstralGeneral/entity/platform/TenantAuditLog.java

-- ===== (1) 扩展 tenant 表：添加层级字段 =====

SET @db = (SELECT DATABASE());
SET @col = (SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'tenant' AND COLUMN_NAME = 'parent_tenant_id');
SET @sql = IF(@col = 0, 'ALTER TABLE tenant ADD COLUMN parent_tenant_id BIGINT NULL AFTER status, ADD COLUMN path VARCHAR(1024) NOT NULL DEFAULT '''', ADD COLUMN depth INT NOT NULL DEFAULT 0', 'SELECT 1 AS parent_tenant_id_exists');
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @db = (SELECT DATABASE());
SET @idx1 = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'tenant' AND INDEX_NAME = 'idx_tenant_parent');
SET @sql1 = IF(@idx1 = 0, 'ALTER TABLE tenant ADD INDEX idx_tenant_parent (parent_tenant_id)', 'SELECT 1 AS idx_tenant_parent_exists');
PREPARE stmt1 FROM @sql1; EXECUTE stmt1; DEALLOCATE PREPARE stmt1;

SET @idx2 = (SELECT COUNT(*) FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'tenant' AND INDEX_NAME = 'idx_tenant_path');
SET @sql2 = IF(@idx2 = 0, 'ALTER TABLE tenant ADD INDEX idx_tenant_path (path(255))', 'SELECT 1 AS idx_tenant_path_exists');
PREPARE stmt2 FROM @sql2; EXECUTE stmt2; DEALLOCATE PREPARE stmt2;

-- ===== (2) 创建 tenant_domain_map 表 =====
--
-- 租户与域的关联映射。一个租户可以关联到多个域，一个域也可以被多个租户使用。
-- 用于多租户环境中域共享场景。

CREATE TABLE IF NOT EXISTS tenant_domain_map (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    domain_id BIGINT NOT NULL,
    is_primary TINYINT NOT NULL DEFAULT 0 COMMENT '是否是主域',
    mapping_type VARCHAR(32) NOT NULL DEFAULT 'OWNED' COMMENT 'OWNED | SHARED | ISOLATED',
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenant(id) ON DELETE CASCADE,
    FOREIGN KEY (domain_id) REFERENCES domain(id) ON DELETE CASCADE,
    UNIQUE KEY uk_tdm_tenant_domain (tenant_id, domain_id),
    INDEX idx_tdm_domain (domain_id),
    INDEX idx_tdm_tenant (tenant_id),
    INDEX idx_tdm_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== (3) 创建 tenant_members 表 =====
--
-- 租户成员表。记录用户与租户的成员关系及角色权限。
-- 一个用户可以是多个租户的成员。

CREATE TABLE IF NOT EXISTS tenant_members (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    role VARCHAR(64) NOT NULL DEFAULT 'MEMBER' COMMENT 'OWNER | ADMIN | MEMBER | GUEST',
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE' COMMENT 'ACTIVE | SUSPENDED | LEFT',
    display_name VARCHAR(255),
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    left_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenant(id) ON DELETE CASCADE,
    UNIQUE KEY uk_tm_tenant_user (tenant_id, user_id),
    INDEX idx_tm_user (user_id),
    INDEX idx_tm_role (role),
    INDEX idx_tm_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== (4) 创建 tenant_invitation 表 =====
--
-- 租户邀请表。记录邀请用户加入租户的请求。

CREATE TABLE IF NOT EXISTS tenant_invitation (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    inviter_id BIGINT NOT NULL COMMENT '发起邀请的用户',
    invitee_email VARCHAR(255),
    invitee_user_id BIGINT COMMENT '被邀请用户ID（注册用户直接邀请）',
    token VARCHAR(255) NOT NULL COMMENT '邀请令牌',
    role VARCHAR(64) NOT NULL DEFAULT 'MEMBER',
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING' COMMENT 'PENDING | ACCEPTED | DECLINED | CANCELED | EXPIRED',
    expires_at TIMESTAMP NULL,
    message TEXT,
    accepted_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenant(id) ON DELETE CASCADE,
    UNIQUE KEY uk_ti_token (token),
    INDEX idx_ti_tenant (tenant_id),
    INDEX idx_ti_inviter (inviter_id),
    INDEX idx_ti_invitee_user (invitee_user_id),
    INDEX idx_ti_email (invitee_email(191)),
    INDEX idx_ti_status (status),
    INDEX idx_ti_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== (5) 创建 tenant_purchase 表 =====
--
-- 租户购买/订阅记录表。追踪租户的套餐、订单、支付状态。

CREATE TABLE IF NOT EXISTS tenant_purchase (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    plan_id BIGINT COMMENT '套餐/产品ID',
    plan_name VARCHAR(255) NOT NULL COMMENT '快照套餐名称',
    amount DECIMAL(18,2) NOT NULL DEFAULT 0.00,
    currency VARCHAR(8) NOT NULL DEFAULT 'CNY',
    billing_cycle VARCHAR(32) NOT NULL DEFAULT 'MONTHLY' COMMENT 'MONTHLY | QUARTERLY | YEARLY | ONETIME',
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING' COMMENT 'PENDING | PAID | FAILED | REFUNDED | CANCELED',
    payment_method VARCHAR(64),
    payment_channel VARCHAR(64),
    transaction_id VARCHAR(255) COMMENT '第三方支付交易ID',
    period_start TIMESTAMP NULL,
    period_end TIMESTAMP NULL,
    paid_at TIMESTAMP NULL,
    refunded_at TIMESTAMP NULL,
    remark TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenant(id) ON DELETE CASCADE,
    INDEX idx_tp_tenant (tenant_id),
    INDEX idx_tp_status (status),
    INDEX idx_tp_transaction (transaction_id(191)),
    INDEX idx_tp_plan (plan_id),
    INDEX idx_tp_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===== (6) 创建 tenant_audit_log 表 =====
--
-- 租户审计日志表。记录租户级别的重要操作事件。
-- 与全局 audit_log 区别：此处仅记录租户管理操作，与租户生命周期强相关。

CREATE TABLE IF NOT EXISTS tenant_audit_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    tenant_id BIGINT NOT NULL,
    actor_id BIGINT COMMENT '操作人用户ID',
    actor_name VARCHAR(255) COMMENT '操作人姓名/显示名',
    action VARCHAR(128) NOT NULL COMMENT '操作标识',
    action_label VARCHAR(255) COMMENT '操作标签（用于展示）',
    target_type VARCHAR(64) COMMENT '目标实体类型',
    target_id VARCHAR(128) COMMENT '目标实体ID',
    detail TEXT COMMENT '操作详情 JSON',
    result VARCHAR(32) NOT NULL DEFAULT 'SUCCESS' COMMENT 'SUCCESS | FAILURE | BLOCKED',
    reason VARCHAR(1024),
    source_ip VARCHAR(64),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenant(id) ON DELETE CASCADE,
    INDEX idx_tal_tenant (tenant_id),
    INDEX idx_tal_action (action),
    INDEX idx_tal_actor (actor_id),
    INDEX idx_tal_target (target_type, target_id(64)),
    INDEX idx_tal_created (created_at),
    INDEX idx_tal_result (result)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
