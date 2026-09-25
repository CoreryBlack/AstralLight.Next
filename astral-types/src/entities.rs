//! AstralLight 核心实体类型
//!
//! 跨模块共享的数据库实体映射。使用 sqlx `FromRow` 派生宏进行 DB 行映射。
//! 所有实体统一使用 `#[serde(rename_all = "camelCase")]` 对齐 Java/前端 camelCase 命名。

/// 组织（学校/机构/企业）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Organization {
    pub id: Option<i64>,
    pub name: String,
    pub code: String,
    pub status: String, // ACTIVE | DISABLED
}

/// 域（组织下的分区，用于多租户隔离）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Domain {
    pub id: Option<i64>,
    pub org_id: i64,
    pub name: String,
    pub status: String,
}

/// 租户（含层级字段，支持多级租户树）
///
/// 层级结构通过 materialized path 实现：
/// - `parentTenantId`: 父租户 ID（根租户为 NULL）
/// - `path`: 层级路径，如 "/1/5/12"
/// - `depth`: 层级深度，根租户=0
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tenant {
    pub id: Option<i64>,
    pub domain_id: i64,
    pub name: String,
    pub status: String, // ACTIVE | SUSPENDED | TERMINATED
    pub parent_tenant_id: Option<i64>,
    pub path: String,
    pub depth: i32,
}

/// 身份卡（身份证）—— 每人一张
///
/// 严格对齐 `platform_v4.identity_card` 表结构：
/// - `card_id` (PK, BIGINT AUTO_INCREMENT)
/// - `user_id` (UNIQUE, FK → platform_user)
/// - `domain_id` (默认领域上下文)
/// - `status` (ACTIVE|DISABLED|EXPIRED)
/// - `token_version` (Token 版本号，用于撤销)
/// - `expires_at` (身份证过期时间)
/// - `disabled_reason` (禁用原因)
/// - `last_used_at` (最后使用时间)
/// - `created_at`, `updated_at`
///
/// 注意：登录凭证（password_hash / login_name）不在本表，
/// 在 `user_local_credential` 表中；用户基础信息（display_name / email / phone）
/// 在 `platform_user` 表中。登录流程需 JOIN 三表。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityCard {
    pub card_id: Option<i64>,
    pub user_id: i64,
    pub status: String,
    pub token_version: Option<i64>,
    pub expires_at: Option<String>,
    pub disabled_reason: Option<String>,
    pub last_used_at: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// 用户本地凭证（对齐 `platform_v4.user_local_credential`）
///
/// 存储 login_name + password_hash，与 `platform_user` 一对一。
/// 登录流程通过 login_name 查询本表，再 JOIN platform_user 获取用户信息。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserLocalCredential {
    pub credential_id: Option<i64>,
    pub user_id: i64,
    pub login_name: Option<String>,
    pub password_hash: String,
    pub password_algo: Option<String>,
    pub password_set_at: Option<String>,
    pub password_updated_at: Option<String>,
    pub must_change_password: Option<bool>,
    pub status: Option<String>,
    pub last_login_at: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// 平台用户（对齐 `platform_v4.platform_user`）
///
/// 存储用户基础信息：display_name, email, phone, status 等。
/// `user_id` 与 `identity_card.user_id` 一对一。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformUser {
    pub user_id: Option<i64>,
    pub user_no: Option<String>,
    pub display_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub avatar_url: Option<String>,
    pub source_type: Option<String>,
    pub status: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub deleted_at: Option<String>,
}

/// 用户卡（员工证/医疗证）—— 每人多张，权限绑定在此
///
/// 严格对齐 `platform_v4.user_card` 表结构：
/// - `card_id` (PK), `user_id`, `domain_id`, `card_type`, `card_status`
/// - `template_id`, `level_id`, `priority`, `is_primary`
/// - `valid_from`, `valid_until`, `created_at`, `updated_at`, `tenant_id`
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserCard {
    pub card_id: Option<i64>,
    pub user_id: Option<i64>,
    pub domain_id: Option<i64>,
    pub card_type: String,
    pub card_status: String,
    pub template_id: Option<i64>,
    pub level_id: Option<i64>,
    pub priority: Option<i32>,
    pub is_primary: Option<bool>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub tenant_id: Option<i64>,
}

/// 用户卡模板（对齐 `platform_v4.user_card_template`）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserCardTemplate {
    pub template_id: Option<i64>,
    pub domain_id: i64,
    pub tenant_id: Option<i64>,
    pub parent_template_id: Option<i64>,
    pub template_code: String,
    pub template_name: String,
    pub card_type: String,
    pub template_scope: Option<String>,
    pub version_no: Option<i32>,
    pub default_priority: Option<i32>,
    pub default_roles_json: Option<String>,
    pub resource_scope_json: Option<String>,
    pub status: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// 身份等级模板（对齐 `platform_v4.identity_level_template`，已废弃于 user_card 权限模型）
#[deprecated(note = "user_card 权限不再基于身份等级模板，仅用于数据兼容")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityLevelTemplate {
    pub template_id: Option<i64>,
    pub template_code: String,
    pub template_name: String,
    pub domain_id: i64,
    pub principal_type: Option<String>,
    pub grant_type: Option<String>,
    pub level_no: i32,
    pub user_card_template_id: Option<i64>,
    pub status: Option<String>,
    pub version_no: Option<i32>,
    pub force_cover: Option<bool>,
    pub description: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// 权限规则模板条目（对齐 `platform_v4.permission_rule_template`）
///
/// 模板级规则定义，发放时实例化到 `permission_rule` 表。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRuleTemplate {
    pub template_rule_id: Option<i64>,
    pub template_id: i64,
    pub resource_type: String,
    pub resource_id: Option<i64>,
    pub action_code: String,
    pub effect: String,
    pub condition_json: Option<String>,
    pub priority: Option<i32>,
    pub enabled: Option<bool>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// 卡片规则集引用
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardRuleSetRef {
    pub id: Option<i64>,
    pub card_id: i64,
    pub rule_set_id: i64,
    pub ref_type: String, // BASE | OVERLAY
}

/// 角色定义（已废弃于规则模型，仅用于数据兼容）
#[deprecated(note = "权限模型已迁移到 RuleSet 规则模式")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DomainRole {
    pub id: Option<i64>,
    pub domain_id: i64,
    pub role_name: String,
    pub role_code: String,
}

// ===== P0 实体（被迁移差距修复直接依赖）=====

/// Token 家族（用于 refresh token 窃取检测，对齐 canonical auth_token_family）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthTokenFamily {
    pub family_id: i64,
    pub user_id: i64,
    pub family_key: String,
    pub status: String, // ACTIVE | EXPIRED | REVOKED
    pub issued_at: Option<time::PrimitiveDateTime>,
    pub expires_at: Option<time::PrimitiveDateTime>,
    pub revoked_at: Option<time::PrimitiveDateTime>,
    pub revoked_reason: Option<String>,
    pub metadata_json: Option<String>,
}

/// 审计日志（对齐 Java AuthAuditLog）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLog {
    pub id: Option<i64>,
    pub user_id: Option<i64>,
    pub card_id: Option<i64>,
    pub action: String,
    pub resource: String,
    pub decision: String,
    pub reason: Option<String>,
    pub detail: Option<String>,
    pub event_type: Option<String>,
    pub source_ip: Option<String>,
    pub request_id: Option<String>,
    pub domain_id: Option<i64>,
    pub tenant_id: Option<i64>,
    pub created_at: Option<i64>,
}

/// 用户（对齐 Java User）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub id: Option<i64>,
    pub user_id: i64,
    pub username: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub status: String,
    pub domain_id: Option<i64>,
    pub tenant_id: Option<i64>,
}

/// 用户身份（对齐 Java UserIdentity）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserIdentity {
    pub id: Option<i64>,
    pub user_id: i64,
    pub identity_type: String,
    pub identifier: String,
    pub credential: Option<String>,
    pub verified: bool,
}

/// 聊天投递记录（对齐 Java ChatMessageDelivery）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatDeliveryRecord {
    pub id: Option<i64>,
    pub message_id: i64,
    pub recipient_id: i64,
    pub status: String, // PENDING | DELIVERED | READ | FAILED
    pub delivered_at: Option<i64>,
    pub read_at: Option<i64>,
    pub retry_count: i32,
    pub failure_reason: Option<String>,
}

/// 聊天会话（对齐 Java ChatConversation）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChatConversation {
    pub id: Option<i64>,
    pub conversation_type: String, // DIRECT | GROUP
    pub name: Option<String>,
    pub last_message_id: Option<i64>,
    pub last_message_at: Option<i64>,
    pub domain_id: Option<i64>,
    pub tenant_id: Option<i64>,
    pub status: String,
}

/// 用户 MFA 配置（对齐 Java UserMfa）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserMfa {
    pub id: Option<i64>,
    pub user_id: i64,
    pub mfa_type: String, // "TOTP" | "RECOVERY_CODES"
    pub secret_enc: Option<Vec<u8>>,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub is_enabled: bool,
    pub is_primary: bool,
    pub backup_codes_hash: Option<String>, // JSON 数组
    pub backup_codes_used: i32,
    pub verified_at: Option<i64>,
    pub last_used_at: Option<i64>,
}

/// MFA 尝试日志（对齐 Java MfaAttemptLog）
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MfaAttemptLog {
    pub id: Option<i64>,
    pub user_id: i64,
    pub mfa_type: String,
    pub success: bool,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub failure_reason: Option<String>,
}

// ===== P2 补充实体（I-3: 补齐缺失的关键实体，对齐 Java 对应类型）=====
//
// Java 基线对照: AstralGeneral/entity/platform/ 下 ~34 个实体
// Rust 原 18 个 → 现补充 6 个关键实体 → 共 24 个

/// 规则集容器（对齐 Java RuleSet）
///
/// Java 基线: AstralGeneral/entity/platform/RuleSet.java
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSet {
    pub id: Option<i64>,
    pub name: String,
    pub ref_type: String, // BASE | OVERLAY
    pub description: Option<String>,
    pub is_active: bool,
    pub version: i64,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

/// 规则集条目（对齐 Java RuleSetEntry）
///
/// Java 基线: AstralGeneral/entity/platform/RuleSetEntry.java
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetEntry {
    pub id: Option<i64>,
    pub rule_set_id: i64,
    pub effect: String, // ALLOW | DENY
    pub resource: Option<String>,
    pub action: Option<String>,
    pub condition_json: Option<String>,
    pub priority: i32,
    pub created_at: Option<i64>,
}

/// 规则集快照（对齐 Java RuleSetSnapshot）
///
/// Java 基线: AstralGeneral/entity/platform/RuleSetSnapshot.java
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSetSnapshotEntity {
    pub id: Option<i64>,
    pub rule_set_id: i64,
    pub is_active: bool,
    pub version: i64,
    pub created_at: Option<i64>,
}

/// SoD 职责分离策略（对齐 Java SodPolicy）
///
/// Java 基线: AstralGeneral/entity/platform/SodPolicy.java
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SodPolicyEntity {
    pub policy_id: Option<i64>,
    pub policy_name: String,
    pub description: Option<String>,
    pub conflict_type: String, // STATIC | DYNAMIC
    pub resource_type: Option<String>,
    pub action_code: Option<String>,
    pub permission_a: Option<String>,
    pub permission_b: Option<String>,
    pub condition_script: Option<String>,
    pub status: String, // ACTIVE | INACTIVE
}

/// 权限委托（对齐 Java PermissionDelegation）
///
/// Java 基线: AstralGeneral/entity/platform/PermissionDelegation.java
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionDelegation {
    pub id: Option<i64>,
    pub delegator_id: i64,
    pub delegate_id: i64,
    pub resource: String,
    pub action: String,
    pub expires_at: Option<i64>,
    pub status: String, // ACTIVE | REVOKED | EXPIRED
    pub created_at: Option<i64>,
}

/// 权限命中统计（对齐 Java PermissionHitStat）
///
/// Java 基线: AstralGeneral/entity/platform/PermissionHitStat.java
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionHitStat {
    pub id: Option<i64>,
    pub card_id: i64,
    pub resource_type: String,
    pub action_code: String,
    pub hit_count: i64,
    pub last_hit_at: Option<i64>,
    pub rule_source: Option<String>, // RULE_SET | PERMISSION_RULE | TEMPLATE
}

// ===== I-3: 多租户补充实体（对齐 Java 多租户数据层基线）=====
//
// Java 基线对照:
// - TenantDomainMap.java: AstralGeneral/entity/platform/TenantDomainMap.java
// - TenantMember.java:    AstralGeneral/entity/platform/TenantMember.java
// - TenantInvitation.java: AstralGeneral/entity/platform/TenantInvitation.java
// - TenantPurchase.java:  AstralGeneral/entity/platform/TenantPurchase.java
// - TenantAuditLog.java:  AstralGeneral/entity/platform/TenantAuditLog.java

/// 租户-域关联映射（对齐 Java TenantDomainMap）
///
/// 一个租户可以关联到多个域，一个域也可以被多个租户使用。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantDomainMap {
    pub id: Option<i64>,
    pub tenant_id: i64,
    pub domain_id: i64,
    pub is_primary: bool,
    pub mapping_type: String, // OWNED | SHARED | ISOLATED
    pub status: String,       // ACTIVE
}

/// 租户成员（对齐 Java TenantMember）
///
/// 记录用户与租户的成员关系及角色权限。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantMember {
    pub id: Option<i64>,
    pub tenant_id: i64,
    pub user_id: i64,
    pub role: String,   // OWNER | ADMIN | MEMBER | GUEST
    pub status: String, // ACTIVE | SUSPENDED | LEFT
    pub display_name: Option<String>,
    pub joined_at: Option<i64>,
    pub left_at: Option<i64>,
}

/// 租户邀请（对齐 Java TenantInvitation）
///
/// 记录邀请用户加入租户的请求。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantInvitation {
    pub id: Option<i64>,
    pub tenant_id: i64,
    pub inviter_id: i64,
    pub invitee_email: Option<String>,
    pub invitee_user_id: Option<i64>,
    pub token: String,
    pub role: String,   // MEMBER | ADMIN
    pub status: String, // PENDING | ACCEPTED | DECLINED | CANCELED | EXPIRED
    pub expires_at: Option<i64>,
    pub message: Option<String>,
    pub accepted_at: Option<i64>,
}

/// 租户购买/订阅记录（对齐 Java TenantPurchase）
///
/// 追踪租户的套餐、订单、支付状态。
/// `amount` 以最小货币单位存储（人民币：分，美元：美分），避免浮点精度问题。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantPurchase {
    pub id: Option<i64>,
    pub tenant_id: i64,
    pub plan_id: Option<i64>,
    pub plan_name: String,
    pub amount: i64,
    pub currency: String,      // CNY | USD
    pub billing_cycle: String, // MONTHLY | QUARTERLY | YEARLY | ONETIME
    pub status: String,        // PENDING | PAID | FAILED | REFUNDED | CANCELED
    pub payment_method: Option<String>,
    pub payment_channel: Option<String>,
    pub transaction_id: Option<String>,
    pub period_start: Option<i64>,
    pub period_end: Option<i64>,
    pub paid_at: Option<i64>,
    pub refunded_at: Option<i64>,
    pub remark: Option<String>,
}

/// 租户审计日志（对齐 Java TenantAuditLog）
///
/// 记录租户级别的重要操作事件，与租户生命周期强相关。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantAuditLog {
    pub id: Option<i64>,
    pub tenant_id: i64,
    pub actor_id: Option<i64>,
    pub actor_name: Option<String>,
    pub action: String,
    pub action_label: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub detail: Option<String>,
    pub result: String, // SUCCESS | FAILURE | BLOCKED
    pub reason: Option<String>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: Option<i64>,
}

/// 密码策略
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordPolicy {
    pub id: Option<i64>,
    pub name: String,
    pub min_length: i32,
    pub max_length: Option<i32>,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
    pub special_chars: Option<String>,
    pub max_retries: i32,
    pub lockout_minutes: i32,
    pub password_expiry_days: Option<i32>,
    pub history_count: i32,
    pub is_default: bool,
    pub status: String,
}

/// 安全事件
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEvent {
    pub id: Option<i64>,
    pub user_id: Option<i64>,
    pub event_type: String,
    pub severity: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub detail: Option<String>,
    pub resolved: bool,
    pub created_at: Option<i64>,
}

/// OAuth 提供商
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OauthProvider {
    pub id: Option<i64>,
    pub provider_name: String,
    pub client_id: String,
    pub client_secret_encrypted: Option<String>,
    pub authorize_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub scope: Option<String>,
    pub enabled: bool,
    pub created_at: Option<i64>,
}

/// 学校
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct School {
    pub id: Option<i64>,
    pub name: String,
    pub code: Option<String>,
    pub province: Option<String>,
    pub city: Option<String>,
    pub district: Option<String>,
    pub address: Option<String>,
    pub school_type: Option<String>,
    pub logo_url: Option<String>,
    pub contact_phone: Option<String>,
    pub contact_email: Option<String>,
    pub status: String,
    pub created_at: Option<i64>,
}
