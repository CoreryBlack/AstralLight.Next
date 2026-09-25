-- Phase 2: 权限治理扩展表
-- 审批流、审计日志、策略模板、委托管理

-- 权限审批请求
CREATE TABLE IF NOT EXISTS permission_request (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    requester_id BIGINT NOT NULL,
    resource VARCHAR(256) NOT NULL,
    action VARCHAR(64) NOT NULL,
    reason TEXT,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    reviewer_id BIGINT,
    review_comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_pr_requester (requester_id),
    INDEX idx_pr_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 审计日志
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    action VARCHAR(64) NOT NULL,
    resource VARCHAR(256) NOT NULL,
    decision VARCHAR(16) NOT NULL,
    reason VARCHAR(256),
    card_id BIGINT,
    detail TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_al_user (user_id),
    INDEX idx_al_action (action),
    INDEX idx_al_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 管理员分组
CREATE TABLE IF NOT EXISTS admin_group (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    scope VARCHAR(32) NOT NULL DEFAULT 'GLOBAL',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ag_scope (scope)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 管理员分组→用户关联
CREATE TABLE IF NOT EXISTS admin_group_member (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    group_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uk_agm_group_user (group_id, user_id),
    FOREIGN KEY (group_id) REFERENCES admin_group(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 权限委托
CREATE TABLE IF NOT EXISTS delegation (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    delegator_id BIGINT NOT NULL,
    delegate_id BIGINT NOT NULL,
    resource VARCHAR(256) NOT NULL,
    action VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_dlg_delegator (delegator_id),
    INDEX idx_dlg_delegate (delegate_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
