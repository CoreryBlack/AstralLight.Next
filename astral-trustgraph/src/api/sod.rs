//! SoD 职责分离管理 API — HTTP adapter
//!
//! 对齐 Java `SodService` + `SodController`。
//! 数据访问在 `repository::sod_repository`；冲突比对（内存循环）保留在 handler。

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_db::validate_dynamic_sod_condition_script;
use astral_types::AstralError;

use crate::repository::sod_repository::{SodPolicyRecord, SodViolationRecord};
use crate::AppState;

// ===== 数据模型 =====

/// SoD 策略响应 DTO（对齐 Java SodPolicy camelCase）
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SodPolicy {
    pub policy_id: Option<i64>,
    pub policy_name: String,
    pub description: Option<String>,
    pub conflict_type: String, // "STATIC" | "DYNAMIC"
    pub resource_type: Option<String>,
    pub action_code: Option<String>,
    pub permission_a: Option<String>,     // 冲突权限 A（STATIC 用）
    pub permission_b: Option<String>,     // 冲突权限 B（STATIC 用）
    pub condition_script: Option<String>, // DYNAMIC 条件脚本
    pub status: String,                   // "ACTIVE" | "INACTIVE"
    pub limit_count: Option<i32>,         // DYNAMIC 频次限制
    pub limit_window: Option<String>,     // DYNAMIC 时间窗口
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
}

impl From<SodPolicyRecord> for SodPolicy {
    fn from(r: SodPolicyRecord) -> Self {
        Self {
            policy_id: r.policy_id,
            policy_name: r.policy_name,
            description: r.description,
            conflict_type: r.conflict_type,
            resource_type: r.resource_type,
            action_code: r.action_code,
            permission_a: r.permission_a,
            permission_b: r.permission_b,
            condition_script: r.condition_script,
            status: r.status,
            limit_count: r.limit_count,
            limit_window: r.limit_window,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

impl From<&SodPolicy> for SodPolicyRecord {
    fn from(p: &SodPolicy) -> Self {
        Self {
            policy_id: p.policy_id,
            policy_name: p.policy_name.clone(),
            description: p.description.clone(),
            conflict_type: p.conflict_type.clone(),
            resource_type: p.resource_type.clone(),
            action_code: p.action_code.clone(),
            permission_a: p.permission_a.clone(),
            permission_b: p.permission_b.clone(),
            condition_script: p.condition_script.clone(),
            status: p.status.clone(),
            limit_count: p.limit_count,
            limit_window: p.limit_window.clone(),
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

/// SoD 违规记录响应 DTO
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SodViolation {
    pub violation_id: Option<i64>,
    pub policy_id: i64,
    pub policy_name: String,
    pub card_id: i64,
    pub user_id: Option<i64>,
    pub operator_id: Option<i64>,
    pub violation_type: String, // "STATIC" | "DYNAMIC"
    pub details_json: Option<String>,
    pub blocked: bool,
    pub created_at: Option<OffsetDateTime>,
}

impl From<SodViolationRecord> for SodViolation {
    fn from(r: SodViolationRecord) -> Self {
        Self {
            violation_id: r.violation_id,
            policy_id: r.policy_id,
            policy_name: r.policy_name,
            card_id: r.card_id,
            user_id: r.user_id,
            operator_id: r.operator_id,
            violation_type: r.violation_type,
            details_json: r.details_json,
            blocked: r.blocked,
            created_at: r.created_at,
        }
    }
}

/// 检测冲突请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectConflictRequest {
    pub card_id: i64,
}

/// 验证授权请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantValidationRequest {
    pub card_id: i64,
    pub resource_type: String,
    pub action_code: String,
}

// ===== 路由 =====

pub fn sod_routes() -> Router<AppState> {
    Router::new()
        .route("/sod-policies", get(list_policies))
        .route("/sod-policies", post(create_policy))
        .route("/sod-policies/{id}", get(get_policy))
        .route("/sod-policies/{id}", put(update_policy))
        .route("/sod-policies/{id}", delete(delete_policy))
        .route("/sod-policies/violations", get(list_violations))
        .route("/sod-policies/detect", post(detect_conflicts))
        .route("/sod-policies/validate-grant", post(validate_grant))
}

// ===== 策略 CRUD =====

fn validate_sod_policy(policy: &SodPolicy) -> Result<(), AppError> {
    if policy.policy_name.trim().is_empty() {
        return Err(AppError(AstralError::Validation(
            "policy_name is required".into(),
        )));
    }
    match policy.conflict_type.as_str() {
        "STATIC" => {
            if policy.permission_a.as_deref().is_none_or(str::is_empty)
                || policy.permission_b.as_deref().is_none_or(str::is_empty)
            {
                return Err(AppError(AstralError::Validation(
                    "STATIC SoD policies require permission_a and permission_b".into(),
                )));
            }
        }
        "DYNAMIC" => {
            let script = policy.condition_script.as_deref().ok_or_else(|| {
                AppError(AstralError::Validation(
                    "DYNAMIC SoD policies require condition_script".into(),
                ))
            })?;
            if script.len() > astral_db::MAX_DYNAMIC_CONDITION_SCRIPT_BYTES {
                return Err(AppError(AstralError::Validation(
                    "condition_script exceeds configured size limit".into(),
                )));
            }
            validate_dynamic_sod_condition_script(script).map_err(AppError)?;
        }
        _ => {
            return Err(AppError(AstralError::Validation(
                "conflict_type must be STATIC or DYNAMIC".into(),
            )))
        }
    }
    Ok(())
}

async fn list_policies(
    State(state): State<AppState>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<SodPolicy>>>, AppError> {
    let total = state.sod_repository.count_policies().await?;
    let rows = state
        .sod_repository
        .list_policies(page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(SodPolicy::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

async fn create_policy(
    State(state): State<AppState>,
    Json(req): Json<SodPolicy>,
) -> Result<Json<ApiResponse<SodPolicy>>, AppError> {
    // 校验必填字段
    if req.policy_name.is_empty() {
        return Err(AppError(AstralError::Validation(
            "policy_name is required".into(),
        )));
    }
    if req.conflict_type != "STATIC" && req.conflict_type != "DYNAMIC" {
        return Err(AppError(AstralError::Validation(
            "conflict_type must be STATIC or DYNAMIC".into(),
        )));
    }
    validate_sod_policy(&req)?;

    let record = SodPolicyRecord::from(&req);
    let id = state.sod_repository.create_policy(&record).await?;
    tracing::info!(policy_id = id, policy_name = %req.policy_name, "SoD policy created");
    Ok(Json(ApiResponse::success(SodPolicy {
        policy_id: Some(id),
        status: "ACTIVE".to_string(),
        ..req
    })))
}

async fn get_policy(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<SodPolicy>>, AppError> {
    let row = state
        .sod_repository
        .get_policy(id)
        .await?
        .map(SodPolicy::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("SoD policy {id} not found"))))?;
    Ok(Json(ApiResponse::success(row)))
}

async fn update_policy(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<SodPolicy>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    validate_sod_policy(&req)?;
    let record = SodPolicyRecord::from(&req);
    state.sod_repository.update_policy(id, &record).await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_policy(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    state.sod_repository.delete_policy(id).await?;
    tracing::warn!(policy_id = id, "SoD policy deleted");
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

// ===== 违规查询 =====

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViolationQuery {
    pub policy_id: Option<i64>,
}

async fn list_violations(
    State(state): State<AppState>,
    Query(q): Query<ViolationQuery>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<SodViolation>>>, AppError> {
    let total = state.sod_repository.count_violations(q.policy_id).await?;
    let rows = state
        .sod_repository
        .list_violations(q.policy_id, page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(SodViolation::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

// ===== 冲突检测 =====

/// POST /main/api/v1/sod-policies/detect — 检测指定卡片的 SoD 冲突
async fn detect_conflicts(
    State(state): State<AppState>,
    Json(req): Json<DetectConflictRequest>,
) -> Result<Json<ApiResponse<Vec<SodViolation>>>, AppError> {
    let card_id = req.card_id;

    // 1. 获取卡片当前权限（快照 + MANUAL 规则）
    let card_perms = state.sod_repository.card_permissions(card_id).await?;

    // 2. 获取活跃的 STATIC 策略
    let policies = state.sod_repository.list_active_policies().await?;

    // 3. 检测冲突
    let mut violations = Vec::new();
    for policy in &policies {
        let perm_a = policy.permission_a.as_deref().unwrap_or("");
        let perm_b = policy.permission_b.as_deref().unwrap_or("");

        let has_a = card_perms.iter().any(|(r, a)| format!("{r}:{a}") == perm_a);
        let has_b = card_perms.iter().any(|(r, a)| format!("{r}:{a}") == perm_b);

        if has_a && has_b {
            // 记录违规
            let detail = serde_json::json!({
                "permission_a": perm_a,
                "permission_b": perm_b,
                "card_id": card_id,
            });

            let violation_id = state
                .sod_repository
                .insert_violation(&SodViolationRecord {
                    violation_id: None,
                    policy_id: policy.policy_id.unwrap_or(0),
                    policy_name: policy.policy_name.clone(),
                    card_id,
                    user_id: None,
                    operator_id: None,
                    violation_type: "STATIC".into(),
                    details_json: Some(detail.to_string()),
                    blocked: true,
                    created_at: None,
                })
                .await?;

            violations.push(SodViolation {
                violation_id: Some(violation_id),
                policy_id: policy.policy_id.unwrap_or(0),
                policy_name: policy.policy_name.clone(),
                card_id,
                user_id: None,
                operator_id: None,
                violation_type: "STATIC".into(),
                details_json: Some(detail.to_string()),
                blocked: true,
                created_at: Some(OffsetDateTime::now_utc()),
            });
        }
    }

    if !violations.is_empty() {
        tracing::warn!(card_id, count = violations.len(), "SoD conflicts detected");
    }

    Ok(Json(ApiResponse::success(violations)))
}

/// POST /main/api/v1/sod-policies/validate-grant — 校验授权是否会导致 SoD 冲突
async fn validate_grant(
    State(state): State<AppState>,
    Json(req): Json<GrantValidationRequest>,
) -> Result<Json<ApiResponse<GrantValidationResult>>, AppError> {
    let perm_key = format!("{}:{}", req.resource_type, req.action_code);

    // 获取所有活跃的 STATIC 策略
    let policies = state.sod_repository.list_active_policies().await?;

    // 检查要授予的权限是否与任何策略的 permission_a 或 permission_b 匹配
    let conflicting_policy = policies.iter().find(|p| {
        p.permission_a.as_deref() == Some(&perm_key) || p.permission_b.as_deref() == Some(&perm_key)
    });

    if let Some(policy) = conflicting_policy {
        // 找到候选策略，检查卡片是否持有冲突权限
        let partner_perm = if policy.permission_a.as_deref() == Some(&perm_key) {
            policy.permission_b.as_deref()
        } else {
            policy.permission_a.as_deref()
        };

        if let Some(partner) = partner_perm {
            // 解析 resource:action
            let parts: Vec<&str> = partner.splitn(2, ':').collect();
            if parts.len() == 2 {
                let has_conflict = state
                    .sod_repository
                    .card_has_permission(req.card_id, parts[0], parts[1])
                    .await?;

                if has_conflict {
                    tracing::warn!(
                        card_id = req.card_id,
                        granted = %perm_key,
                        conflicts_with = partner,
                        "SoD grant validation failed"
                    );
                    return Ok(Json(ApiResponse::success(GrantValidationResult {
                        allowed: false,
                        conflict_policy: Some(policy.policy_name.clone()),
                        conflict_permission: Some(partner.to_string()),
                    })));
                }
            }
        }
    }

    Ok(Json(ApiResponse::success(GrantValidationResult {
        allowed: true,
        conflict_policy: None,
        conflict_permission: None,
    })))
}

#[cfg(test)]
mod tests {
    use super::{validate_sod_policy, SodPolicy};

    fn dynamic_policy(script: Option<&str>) -> SodPolicy {
        SodPolicy {
            policy_id: None,
            policy_name: "owner-self-approval".into(),
            description: None,
            conflict_type: "DYNAMIC".into(),
            resource_type: Some("approval".into()),
            action_code: Some("approve".into()),
            permission_a: None,
            permission_b: None,
            condition_script: script.map(str::to_owned),
            status: "ACTIVE".into(),
            limit_count: None,
            limit_window: None,
            created_at: None,
            updated_at: None,
        }
    }

    #[test]
    fn dynamic_sod_write_rejects_unknown_operator_or_script() {
        assert!(
            validate_sod_policy(&dynamic_policy(Some("resourceOwnerId == currentUserId"))).is_ok()
        );
        for script in [
            None,
            Some("resourceOwnerId != currentUserId"),
            Some("resourceOwnerId == currentUserId || true"),
            Some("resourceOwnerId == unknown"),
        ] {
            assert!(validate_sod_policy(&dynamic_policy(script)).is_err());
        }
    }
}

/// 授权校验结果
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantValidationResult {
    pub allowed: bool,
    pub conflict_policy: Option<String>,
    pub conflict_permission: Option<String>,
}
