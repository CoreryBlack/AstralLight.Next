//! TrustGraph API 模块
//!
//! 历史上本模块还承载仿真专用的卡级已发布证据读取与统一 ALLOW-only 匹配器；
//! 按用户授权的 V6/V7 评估与结构退役，该模拟/匹配代码已随
//! `simulation.rs` 一并移除。SoD 等其他诊断读面使用
//! `astral-trustgraph/src/repository/sod_repository.rs` 的独立实现，不受
//! 本次退役影响。

use axum::http::HeaderMap;

use astral_common::error::AppError;
use astral_types::AstralError;

use crate::AppState;

/// 平台管理边界：仅允许已验证身份对应的 ACTIVE GlobalAdmin 操作。
///
/// RuleSet/domain 等平台对象在当前基线 schema 中无法始终证明 tenant/domain 归属，
/// 因此不能仅凭普通路由权限或 caller-supplied scope 放行跨范围管理。
/// 该守卫只使用 Gateway 注入的 x-user-id，并通过 repository 查询 ACTIVE 状态；
/// 不解析角色字符串，也不绕过 PolicyEngine 作为业务授权入口。
pub(crate) async fn require_platform_admin(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<i64, AppError> {
    let user_id = headers
        .get("x-user-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| AppError(AstralError::Auth("platform_admin_identity_required".into())))?;

    let active = state
        .global_admin_repository
        .is_active_admin(user_id)
        .await
        .map_err(AppError::from)?;
    if !active {
        return Err(AppError(AstralError::Permission(
            "PLATFORM_ADMIN_REQUIRED".into(),
        )));
    }
    Ok(user_id)
}

pub mod approval;
pub mod audit;
pub mod audit_replay;
pub mod audit_service;
pub mod authorization_observations;
pub mod cross_org_grants;
pub mod delegation;
pub mod departments;
pub mod inheritance;
pub(crate) mod integrations;
pub mod org_authorities;
pub mod permission_check;
pub mod personal_permissions;
pub mod platform_packages;
pub mod rule_sets;
pub mod rules;
pub mod side_effects;
pub mod simulation;
pub mod sod;
pub mod stats;
pub mod templates;
pub mod tenants;
// DomainControl 拆分后的 7 个独立模块（对齐 Java DomainControlController 拆分）
pub mod domains;
pub mod level_templates;
pub mod permission_actions;
pub mod resource_types;
pub mod user_cards;
pub mod user_gradings;
pub mod user_levels;
// 统一异步操作追踪
pub mod async_tracker;
// 卡片模板 CRUD（对齐 Java DomainControlController 中 card-templates 部分）
pub mod card_templates;
// 全局管理员管理（对齐 Java GlobalAdminController）
pub mod global_admin;
// 内部测试控制面（S1-S15 分布式实验；默认关闭、fail-closed、只读 worker-id 探针，
// 安全不变式见模块文档）
pub mod test_control;
