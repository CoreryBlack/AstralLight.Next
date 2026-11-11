//! 用户卡管理 API（DomainController 拆分模块 7/7）— HTTP adapter
//!
//! 数据访问在 `repository::user_card_repository`，写路径 rebuild/evict 副作用
//! 编排在 `service::user_card_service`。HTTP 层仅解析参数、组装 DTO、包装响应。

use axum::extract::{Extension, Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::{AstralError, AuthorizationAdmission, PolicyContext};

use crate::api::async_tracker::{self, AsyncTask};
use crate::repository::user_card_repository::{
    NewUserCard, UserCardFilter, UserCardPatch, UserCardRecord,
};
use crate::AppState;

// ===== Row / DTO =====

/// user_card 响应 DTO（对齐 Java UserCardDetailDto + 前端 UserCardDetail）
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserCardDto {
    pub card_id: i64,
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
    pub card_name: Option<String>,
    pub template_code: Option<String>,
    pub template_name: Option<String>,
    pub level_code: Option<String>,
    pub level_name: Option<String>,
    pub level_no: Option<i32>,
    pub action_codes: Vec<String>,
}

/// 解析逗号分隔字符串为 Vec
fn parse_csv(s: Option<String>) -> Vec<String> {
    s.as_ref()
        .map(|s| {
            s.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

impl From<UserCardRecord> for UserCardDto {
    fn from(r: UserCardRecord) -> Self {
        Self {
            card_id: r.card_id,
            user_id: r.user_id,
            domain_id: r.domain_id,
            card_type: r.card_type,
            card_status: r.card_status,
            template_id: r.template_id,
            level_id: r.level_id,
            priority: r.priority,
            is_primary: r.is_primary,
            valid_from: r.valid_from,
            valid_until: r.valid_until,
            created_at: r.created_at,
            updated_at: r.updated_at,
            tenant_id: r.tenant_id,
            card_name: r.card_name,
            template_code: r.template_code,
            template_name: r.template_name,
            level_code: r.level_code,
            level_name: r.level_name,
            level_no: r.level_no,
            action_codes: parse_csv(r.action_codes),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserCardRequest {
    pub user_id: Option<i64>,
    pub template_id: Option<i64>,
    pub level_id: Option<i64>,
    pub card_type: Option<String>,
    pub domain_id: Option<i64>,
    pub tenant_id: Option<i64>,
    pub priority: Option<i32>,
    pub is_primary: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateUserCardRequest {
    pub card_status: Option<String>,
    pub priority: Option<i32>,
    pub is_primary: Option<bool>,
    pub level_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserCardQuery {
    pub user_id: Option<i64>,
    pub template_id: Option<i64>,
    pub card_status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BindCardRequest {
    pub card_id: i64,
    pub user_id: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchBindCardRequest {
    pub card_ids: Vec<i64>,
    pub user_id: i64,
}

/// 冲突检测结果
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictDetectionResult {
    pub user_id: i64,
    pub conflicts: Vec<ConflictItem>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictItem {
    pub card_id: i64,
    pub template_id: Option<i64>,
    pub card_type: String,
    pub reason: String,
}

// ===== 管理范围校验（对齐 Java CardManagementScopeServiceImpl） =====

const SCOPE_DENIED: &str = "CARD_MANAGEMENT_SCOPE_DENIED";

/// 已验证的管理范围：与操作者（或 GlobalAdmin 目标卡）tenant/domain 绑定。
#[derive(Debug, Clone, Copy)]
struct ManagementScope {
    tenant_id: i64,
    domain_id: i64,
}

fn parse_header_id(headers: &HeaderMap, name: &str) -> Option<i64> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
}

fn scope_denied() -> AppError {
    AppError(AstralError::Permission(SCOPE_DENIED.into()))
}

/// 纯范围判定：操作者 tenant/domain 与目标一致即放行；
/// 否则仅 GlobalAdmin 例外放行。目标 NULL 由调用方在读取卡后拒绝。
fn scope_allows(
    operator: &ManagementScope,
    target_tenant_id: i64,
    target_domain_id: i64,
    is_global_admin: bool,
) -> bool {
    if operator.tenant_id == target_tenant_id && operator.domain_id == target_domain_id {
        return true;
    }
    is_global_admin
}

/// 列表/创建使用的范围：操作者必须携带 user/tenant/domain 上下文。
///
/// 对齐 Java `requireCardManagementScope`：operator 缺 tenant/domain 直接拒绝；
/// GlobalAdmin 例外仅放宽"目标 == 操作者"的相等性，仍要求操作者上下文存在。
/// scope 只接受 user-card 上下文（中间件已强制注入），禁止回退 identity tenant/domain。
fn require_management_context(headers: &HeaderMap) -> Result<ManagementScope, AppError> {
    if parse_header_id(headers, "x-user-id").is_none() {
        return Err(scope_denied());
    }
    let tenant_id = parse_header_id(headers, "x-user-card-tenant-id").ok_or_else(scope_denied)?;
    let domain_id = parse_header_id(headers, "x-user-card-domain-id").ok_or_else(scope_denied)?;
    Ok(ManagementScope {
        tenant_id,
        domain_id,
    })
}

/// 单卡管理范围：目标卡 tenant/domain 必须与操作者一致；GlobalAdmin 例外放行。
async fn require_card_scope(
    state: &AppState,
    headers: &HeaderMap,
    card: &UserCardRecord,
) -> Result<ManagementScope, AppError> {
    let user_id = parse_header_id(headers, "x-user-id").ok_or_else(scope_denied)?;
    let operator = require_management_context(headers)?;
    let card_tenant = card.tenant_id.ok_or_else(scope_denied)?;
    let card_domain = card.domain_id.ok_or_else(scope_denied)?;
    if scope_allows(
        &operator,
        card_tenant,
        card_domain,
        state
            .global_admin_repository
            .is_active_admin(user_id)
            .await?,
    ) {
        return Ok(operator);
    }
    Err(scope_denied())
}

/// 创建/更新目标范围：请求目标 tenant/domain 必须与操作者一致（GlobalAdmin 例外）。
async fn require_target_scope(
    state: &AppState,
    headers: &HeaderMap,
    target_tenant_id: i64,
    target_domain_id: i64,
) -> Result<(), AppError> {
    let user_id = parse_header_id(headers, "x-user-id").ok_or_else(scope_denied)?;
    let operator = require_management_context(headers)?;
    if scope_allows(
        &operator,
        target_tenant_id,
        target_domain_id,
        state
            .global_admin_repository
            .is_active_admin(user_id)
            .await?,
    ) {
        return Ok(());
    }
    Err(scope_denied())
}

async fn require_target_user(
    state: &AppState,
    user_id: i64,
    tenant_id: i64,
    domain_id: i64,
) -> Result<(), AppError> {
    let valid: Vec<i64> = sqlx::query_scalar(
        "SELECT u.user_id FROM platform_user u \
         INNER JOIN identity_card ic ON ic.user_id = u.user_id \
            AND ic.status = 'ACTIVE' \
            AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
         INNER JOIN tenant t ON t.tenant_id = ? AND t.status = 'ACTIVE' \
         INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = t.tenant_id \
            AND tdm.domain_id = ? AND tdm.status = 'ACTIVE' \
         INNER JOIN tenant_user_map tum ON tum.tenant_id = t.tenant_id \
            AND tum.user_id = u.user_id AND tum.status = 'ACTIVE' \
         WHERE u.user_id = ? AND u.status = 'ACTIVE' AND u.deleted_at IS NULL",
    )
    .bind(tenant_id)
    .bind(domain_id)
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| scope_denied())?;
    if valid.as_slice() != [user_id] {
        return Err(scope_denied());
    }
    Ok(())
}

pub fn user_card_routes() -> Router<AppState> {
    Router::new()
        .route("/user-cards", get(list_user_cards))
        .route("/user-cards", post(create_user_card))
        .route("/user-cards/{id}", get(get_user_card))
        .route("/user-cards/{id}", put(update_user_card))
        .route("/user-cards/{id}", delete(delete_user_card))
        .route("/user-cards/{id}/restore", put(restore_user_card))
        .route("/user-cards/{id}/bind", post(bind_card))
        .route("/user-cards/{id}/bind/async", post(bind_card_async))
        .route(
            "/user-cards/{id}/conflict-detection",
            post(conflict_detection),
        )
}

// ===== Handlers =====

/// GET /main/api/v1/user-cards — 列表（限定操作者 tenant/domain 范围，分页）
async fn list_user_cards(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<UserCardQuery>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<UserCardDto>>>, AppError> {
    let scope = require_management_context(&headers)?;
    let filter = UserCardFilter {
        user_id: q.user_id,
        template_id: q.template_id,
        card_status: q.card_status.as_ref().map(|s| s.to_uppercase()),
        tenant_id: Some(scope.tenant_id),
        domain_id: Some(scope.domain_id),
    };
    let total = state.user_card_repository.count_cards(&filter).await?;
    let rows = state
        .user_card_repository
        .list_cards(&filter, page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(UserCardDto::from)
        .collect();
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// GET /main/api/v1/user-cards/{id} — 查询（校验管理范围）
async fn get_user_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<UserCardDto>>, AppError> {
    let row = state
        .user_card_repository
        .get_card(id)
        .await?
        .ok_or_else(|| AppError(AstralError::NotFound(format!("user_card {id}"))))?;
    require_card_scope(&state, &headers, &row).await?;
    Ok(Json(ApiResponse::success(UserCardDto::from(row))))
}

/// POST /main/api/v1/user-cards — 创建（目标 tenant/domain 必须处于管理范围）
async fn create_user_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(admission): Extension<AuthorizationAdmission>,
    Json(req): Json<CreateUserCardRequest>,
) -> Result<Json<ApiResponse<UserCardDto>>, AppError> {
    let target_tenant_id = req.tenant_id.ok_or_else(scope_denied)?;
    let target_domain_id = req.domain_id.ok_or_else(scope_denied)?;
    let target_user_id = req.user_id.ok_or_else(scope_denied)?;
    if target_user_id <= 0 {
        return Err(scope_denied());
    }
    require_target_user(&state, target_user_id, target_tenant_id, target_domain_id).await?;
    require_target_scope(&state, &headers, target_tenant_id, target_domain_id).await?;

    let row = state
        .user_card_service
        .create_card(
            &NewUserCard {
                user_id: req.user_id,
                domain_id: Some(target_domain_id),
                card_type: req.card_type.unwrap_or_else(|| "STANDARD".into()),
                template_id: req.template_id,
                level_id: req.level_id,
                priority: req.priority.unwrap_or(100),
                is_primary: req.is_primary.unwrap_or(false),
                tenant_id: Some(target_tenant_id),
                // 显式携带时先过统一安全校验再复用为 durable operation id；
                // 缺失/空白由 repository 以锁定代次确定性派生，无随机 fallback。
                request_operation_id: headers
                    .get("x-request-id")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
            },
            admission,
        )
        .await?;
    Ok(Json(ApiResponse::success(UserCardDto::from(row))))
}

/// PUT /main/api/v1/user-cards/{id} — 更新（校验管理范围，禁止跨 tenant/domain 转移）
async fn update_user_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateUserCardRequest>,
) -> Result<Json<ApiResponse<UserCardDto>>, AppError> {
    let existing = state
        .user_card_repository
        .get_card(id)
        .await?
        .ok_or_else(|| AppError(AstralError::NotFound(format!("user_card {id}"))))?;
    require_card_scope(&state, &headers, &existing).await?;

    // 状态白名单校验（对齐现有 handler 语义；repository 状态机会再以锁定行
    // 状态自包含 fail-closed 复核迁移方向）
    let card_status = match req.card_status.as_ref() {
        Some(raw) => {
            let upper = raw.to_uppercase();
            // Java canonical 状态以 ACTIVE/DISABLED 为主；保留 INACTIVE/SUSPENDED 读取。
            let valid = ["ACTIVE", "INACTIVE", "DISABLED", "SUSPENDED"];
            if !valid.contains(&upper.as_str()) {
                return Err(AppError(AstralError::Validation(format!(
                    "card_status must be one of {valid:?}"
                ))));
            }
            Some(upper)
        }
        None => None,
    };

    // 状态变更是授权 source mutation：actor（Gateway 已验证 x-user-id，
    // require_card_scope 已强制存在）与可选 x-request-id 由本 handler 传播进
    // patch，repository 以其稳定 operation 身份落 CARD REVOKE 元数据与同事务
    // 审计关联；携带状态却不可归属的更新在 repository fail-closed 拒绝。
    // 通用 update 只能离开 ACTIVE —— 恢复 DISABLED 卡必须走 /restore 专用入口，
    // 绑定激活必须走 /bind 守卫入口（见 repository 状态机文档）。
    let patch = UserCardPatch {
        card_status,
        priority: req.priority,
        is_primary: req.is_primary,
        level_id: req.level_id,
        actor_id: parse_header_id(&headers, "x-user-id"),
        // 显式携带时先过统一安全校验再复用为 durable operation id；
        // 缺失/空白由 repository 以锁定代次确定性派生，无随机 fallback。
        request_operation_id: headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
    };
    state
        .user_card_service
        .update_card(id, &patch, admission)
        .await?;

    let row = state
        .user_card_repository
        .get_card(id)
        .await?
        .map(UserCardDto::from)
        .ok_or_else(|| AppError(AstralError::NotFound(format!("user_card {id}"))))?;

    tracing::info!(id, "user card updated");
    Ok(Json(ApiResponse::success(row)))
}

/// DELETE /main/api/v1/user-cards/{id} — 删除（校验管理范围，级联清理权限规则与快照）
async fn delete_user_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let existing = state
        .user_card_repository
        .get_card(id)
        .await?
        .ok_or_else(|| AppError(AstralError::NotFound(format!("user_card {id}"))))?;
    require_card_scope(&state, &headers, &existing).await?;

    let result = state.user_card_service.delete_card(id, admission).await?;
    if !result.exists {
        return Err(AppError(AstralError::NotFound(format!("user_card {id}"))));
    }

    Ok(Json(ApiResponse::success(serde_json::json!({
        "cardId": id,
        "cardStatus": "DISABLED",
        "cascade": {
            "permission_rule": result.permission_rule_deleted,
            "permission_rule_snapshot": result.snapshot_deleted,
            "card_rule_set_ref": result.rule_set_ref_deleted,
        }
    }))))
}

/// POST /main/api/v1/user-cards/{id}/restore — 恢复已删除卡（校验管理范围）
async fn restore_user_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<UserCardDto>>, AppError> {
    let existing = state
        .user_card_repository
        .get_card(id)
        .await?
        .ok_or_else(|| AppError(AstralError::NotFound(format!("user_card {id}"))))?;
    require_card_scope(&state, &headers, &existing).await?;

    let row = state.user_card_service.restore_card(id, admission).await?;
    Ok(Json(ApiResponse::success(UserCardDto::from(row))))
}

/// POST /main/api/v1/user-cards/{id}/bind — 绑定卡到用户（校验管理范围）
async fn bind_card(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(id): Path<i64>,
    Json(req): Json<BindCardRequest>,
) -> Result<Json<ApiResponse<UserCardDto>>, AppError> {
    if req.card_id != id {
        return Err(AppError(AstralError::Validation(
            "card_id must match path id".into(),
        )));
    }
    let existing = state
        .user_card_repository
        .get_card(id)
        .await?
        .ok_or_else(|| AppError(AstralError::NotFound(format!("user_card {id}"))))?;
    require_card_scope(&state, &headers, &existing).await?;
    let target_tenant_id = existing.tenant_id.ok_or_else(scope_denied)?;
    let target_domain_id = existing.domain_id.ok_or_else(scope_denied)?;
    require_target_user(&state, req.user_id, target_tenant_id, target_domain_id).await?;

    let row = state
        .user_card_service
        .bind_card(id, req.user_id, admission)
        .await?;
    Ok(Json(ApiResponse::success(UserCardDto::from(row))))
}

/// POST /main/api/v1/user-cards/{id}/bind/async — 异步批量绑定
///
/// 注册即受保护业务变更：中间件为该精确路由签发的 ProtectedBusiness
/// admission 在 tracker 拥有的**同一事务**内被消费（protected ledger/result/
/// audit），其 durable result_json 绑定冻结的精确有序 item 集。此后 worker
/// 对每个 item 独立执行 fresh 策略 + SoD + host fence + reserve —— 每个
/// item 各自是 AuthorizationSource、各自持有 operation_id 与一次性消费
/// 预算；请求级 proof 绝不被重建、克隆或拆分为多个 item 预算。请求者身份
/// 一律取自中间件验证过的 PolicyContext，绝不读伪造头。
async fn bind_card_async(
    State(state): State<AppState>,
    Extension(policy): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(id): Path<i64>,
    Json(req): Json<BatchBindCardRequest>,
) -> Result<Json<ApiResponse<AsyncTask>>, AppError> {
    if req.card_ids.is_empty() || req.card_ids.len() > async_tracker::MAX_CARD_BIND_ITEMS {
        return Err(AppError(AstralError::Validation(format!(
            "card bind batch must contain between 1 and {} cards",
            async_tracker::MAX_CARD_BIND_ITEMS,
        ))));
    }
    if !req.card_ids.contains(&id) {
        return Err(AppError(AstralError::Validation(
            "path id must be included in card_ids".into(),
        )));
    }
    if req.user_id <= 0 {
        return Err(AppError(AstralError::Validation(
            "target user_id must be positive".into(),
        )));
    }

    // 冻结精确有序 item 集：tenant/domain 快照来自服务端卡行（非客户端可控
    // 事实），tracker 校验强制唯一并按 card_id 排序。此处**不做**授权判定 ——
    // 每个 item 的真实授权由 worker 的 fresh 评估独立完成。
    let mut items = Vec::with_capacity(req.card_ids.len());
    for card_id in &req.card_ids {
        let card = state
            .user_card_repository
            .get_card(*card_id)
            .await?
            .ok_or_else(|| AppError(AstralError::NotFound(format!("user_card {card_id}"))))?;
        let tenant_id = card.tenant_id.ok_or_else(scope_denied)?;
        let domain_id = card.domain_id.ok_or_else(scope_denied)?;
        items.push(async_tracker::CardBindItemInput {
            card_id: *card_id,
            tenant_id,
            domain_id,
        });
    }
    items.sort_by_key(|item| item.card_id);

    // authorization anchor 快照同样来自服务端卡行；活跃 GlobalAdmin 可以
    // 合法提交跨租户批量 —— 锚点元组随注册持久化并在 item 事务中复核。
    let anchor = state
        .user_card_repository
        .get_card(id)
        .await?
        .ok_or_else(|| AppError(AstralError::NotFound(format!("user_card {id}"))))?;
    let authorization_target_tenant_id = anchor.tenant_id.ok_or_else(scope_denied)?;
    let authorization_target_domain_id = anchor.domain_id.ok_or_else(scope_denied)?;

    // 验证过的请求者身份来自 PolicyContext（Gateway 验签链），绝不来自可
    // 伪造的 x-user-* 头。
    let requester_user_id = policy.user_id.ok_or_else(scope_denied)?;
    let requester_card_id = policy.card_id.ok_or_else(scope_denied)?;
    let requester_tenant_id = policy.tenant_id.ok_or_else(scope_denied)?;
    let requester_domain_id = policy.domain_id.ok_or_else(scope_denied)?;

    // 父级受保护变更上下文：把中间件验证的请求与它的 ProtectedBusiness
    // admission 绑定为一个可消费边界（digest 含 request_mutation_kind）。
    // 该上下文进入 tracker 拥有的注册未来，在冻结 item 集的同一事务内被
    // begin/finish 消费 —— HTTP 栈上不再保留可克隆的 admission 句柄。
    let parent = astral_db::ProtectedMutationContext::from_policy_context(
        &policy,
        admission,
        policy.request_operation_id.as_deref(),
        "domain",
        "update",
        policy.target_id,
    )
    .map_err(AppError::from)?;

    // tracker 并发准许（BatchAdmissionPermit）仍是纯业务门：只限制在途
    // owned 任务数。它不是授权能力；逐 item 授权在 worker 中 fresh 评估。
    let batch_permit = async_tracker::tracker()
        .reserve_admission()
        .await
        .map_err(AppError::from)?;
    let task_id = async_tracker::generate_task_id("uc_bind");
    let total = items.len();
    let registration = async_tracker::CardBindRegistration {
        task_id: task_id.clone(),
        requester_user_id,
        requester_card_id,
        requester_tenant_id,
        requester_domain_id,
        authorization_target_card_id: id,
        authorization_target_tenant_id,
        authorization_target_domain_id,
        target_user_id: req.user_id,
        items,
    };
    let service = state.user_card_service.clone();
    let app = state.clone();
    let db = state.db.clone();
    let tid = task_id.clone();
    // item 上下文锚：注册验证过的父 PolicyContext（仅承载不可变注册事实与
    // 请求 digest；不承载任何可克隆授权句柄）。
    let parent_context = policy.clone();
    let user_id = req.user_id;
    let stop_requested = async_tracker::tracker().stop_requested().await;
    let task = async_tracker::tracker()
        .register_card_bind_and_spawn(&state.db, batch_permit, registration, parent, async move {
            let work_result: Result<(), String> = async {
                async_tracker::start_card_bind(&db, &tid)
                    .await
                    .map_err(|error| format!("could not start durable card-bind task: {error}"))?;
                let pending = async_tracker::list_pending_card_bind_items(&db, &tid)
                    .await
                    .map_err(|error| format!("could not load durable card-bind items: {error}"))?;
                for candidate in pending {
                    if stop_requested.load(std::sync::atomic::Ordering::Acquire) {
                        async_tracker::mark_card_bind_remaining_in_doubt(
                            &db,
                            &tid,
                            "worker shutdown requested before remaining items started",
                        )
                        .await
                        .map_err(|error| format!("could not persist shutdown IN_DOUBT: {error}"))?;
                        break;
                    }
                    let Some(item) = async_tracker::mark_card_bind_item_running(&db, &tid, candidate.card_id)
                        .await
                        .map_err(|error| format!("could not mark item RUNNING: {error}"))?
                    else {
                        continue;
                    };
                    // FRESH per-item admission：独立策略 + SoD + host fence +
                    // reserve。每项各自 AuthorizationSource、各自 operation_id
                    //（durable 冻结集派生），失败分类与既有合同一致。
                    let (admission, source_abort) = match crate::service::user_card_batch_admission::admit_item(
                        &app,
                        &parent_context,
                        &tid,
                        &item.operation_id,
                        item.card_id,
                        user_id,
                        item.tenant_id,
                        item.domain_id,
                    )
                    .await
                    {
                        Ok(admission) => admission,
                        Err(error) => {
                            let message = error.to_string();
                            tracing::warn!(task_id = %tid, card_id = item.card_id, error = %message, "batch item fresh admission refused");
                            let outcome = if matches!(
                                error,
                                AstralError::Validation(_)
                                    | AstralError::Auth(_)
                                    | AstralError::Permission(_)
                                    | AstralError::NotFound(_)
                            ) {
                                "FAILED"
                            } else {
                                "IN_DOUBT"
                            };
                            let mut completion_proven = false;
                            if let Err(persist) = async_tracker::fail_card_bind_item(
                                &db,
                                &tid,
                                item.card_id,
                                outcome,
                                &message,
                            )
                            .await
                            {
                                let item_state = async_tracker::get_task(&db, &tid)
                                    .await
                                    .ok()
                                    .flatten()
                                    .and_then(|task| task.items.into_iter().find(|child| child.card_id == item.card_id));
                                completion_proven = item_state
                                    .is_some_and(|child| child.status == "COMPLETED");
                                if !completion_proven {
                                    return Err(format!("{message}; could not prove child outcome: {persist}"));
                                }
                            }
                            if outcome == "IN_DOUBT" && !completion_proven {
                                return Err(format!("batch child outcome is unknown: {message}"));
                            }
                            continue;
                        }
                    };
                    match service
                        .bind_card_async_batch_item(
                            item.card_id,
                            user_id,
                            requester_user_id,
                            requester_card_id,
                            requester_tenant_id,
                            requester_domain_id,
                            &tid,
                            &item.operation_id,
                            item.tenant_id,
                            item.domain_id,
                            // 该 item 自己 fresh 评估并 reserve 的一次性
                            // admission（AuthorizationSource）：按值移交，
                            // 由 item 的 source 事务在 COMMIT 前对牌并恰好
                            // 消费一次。
                            admission,
                        )
                        .await
                    {
                        Ok(receipts) => {
                            if !crate::service::sync_publish::wait_for_committed_receipts(
                                &db, &receipts,
                            )
                            .await
                            {
                                let message =
                                    "post-commit CARD/ELIGIBILITY/invalidation completion was not proven";
                                if let Err(persist) = async_tracker::fail_card_bind_item(
                                    &db,
                                    &tid,
                                    item.card_id,
                                    "IN_DOUBT",
                                    message,
                                )
                                .await
                                {
                                    return Err(format!(
                                        "{message}; could not persist IN_DOUBT: {persist}"
                                    ));
                                }
                                continue;
                            }
                            // 集成点（main 的 source-outcome agent）：如需
                            // stage/finalize API，在“COMMIT 回执已证明”与
                            // complete_card_bind_item 之间接入；在 API 落地
                            // 前不得伪造任何完成证明。
                            if let Err(error) = async_tracker::complete_card_bind_item(
                                &db,
                                &tid,
                                item.card_id,
                                &item.operation_id,
                                item.tenant_id,
                                item.domain_id,
                            )
                            .await
                            {
                                let message = format!(
                                    "card bind tracker completion is unknown after source commit: {error}"
                                );
                                if let Err(persist) = async_tracker::fail_card_bind_item(
                                    &db,
                                    &tid,
                                    item.card_id,
                                    "IN_DOUBT",
                                    &message,
                                )
                                .await
                                {
                                    return Err(format!(
                                        "{message}; could not persist IN_DOUBT: {persist}"
                                    ));
                                }
                            }
                        }
                        Err(error) => {
                            let message = error.to_string();
                            tracing::warn!(task_id = %tid, card_id = item.card_id, error = %message, "failed to bind card");
                            let abort_result = match app.authorization_fence_provider.as_ref() {
                                Some(provider) => crate::service::user_card_batch_admission::abort_after_admission_drift(
                                    provider,
                                    &source_abort,
                                    "batch_item_failed",
                                )
                                .await
                                .to_string(),
                                None => "source reservation abort UNKNOWN: authority provider unavailable".to_owned(),
                            };
                            let message = format!("{message}; {abort_result}");
                            // A failed call may still have committed. Keep the item
                            // in doubt until its durable reservation is reconciled.
                            let outcome = "IN_DOUBT";
                            let mut completion_proven = false;
                            if let Err(persist) = async_tracker::fail_card_bind_item(
                                &db,
                                &tid,
                                item.card_id,
                                outcome,
                                &message,
                            )
                            .await
                            {
                                let item_state = async_tracker::get_task(&db, &tid)
                                    .await
                                    .ok()
                                    .flatten()
                                    .and_then(|task| task.items.into_iter().find(|child| child.card_id == item.card_id));
                                completion_proven = item_state
                                    .is_some_and(|child| child.status == "COMPLETED");
                                if !completion_proven {
                                    return Err(format!("{message}; could not prove child outcome: {persist}"));
                                }
                            }
                            if outcome == "IN_DOUBT" && !completion_proven {
                                return Err(format!("batch child outcome is unknown: {message}"));
                            }
                        }
                    }
                }
                Ok(())
            }
            .await;

            if let Err(error) = &work_result {
                if let Err(persist) = async_tracker::mark_card_bind_remaining_in_doubt(&db, &tid, error).await {
                    tracing::error!(task_id = %tid, error = %persist, "failed to persist unknown batch outcomes");
                }
            }
            let finish_result = async_tracker::finish_card_bind(
                &db,
                &tid,
                stop_requested.load(std::sync::atomic::Ordering::Acquire) || work_result.is_err(),
            )
            .await;
            if let Err(error) = finish_result {
                let message = format!("could not finalize durable card-bind state: {error}");
                if let Err(persist) = async_tracker::mark_card_bind_remaining_in_doubt(&db, &tid, &message).await {
                    return Err(format!("{message}; could not persist IN_DOUBT: {persist}"));
                }
                return Err(message);
            }
            work_result
        })
        .await
        .map_err(AppError::from)?;

    tracing::info!(task_id = %task_id, total, user_id, "async batch bind started");
    Ok(Json(ApiResponse::success(task)))
}

/// POST /main/api/v1/user-cards/{id}/conflict-detection — 冲突检测（限定管理范围）
///
/// 检查同一用户持有的多张卡是否存在模板/类型冲突。
/// 冲突定义：同一 user_id 下有多张 ACTIVE 卡使用相同 card_type 但不同 template_id。
async fn conflict_detection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<i64>,
) -> Result<Json<ApiResponse<ConflictDetectionResult>>, AppError> {
    if user_id <= 0 {
        return Err(AppError(AstralError::Validation(
            "user_id is required".into(),
        )));
    }
    let scope = require_management_context(&headers)?;
    let filter = UserCardFilter {
        user_id: Some(user_id),
        template_id: None,
        card_status: Some("ACTIVE".into()),
        tenant_id: Some(scope.tenant_id),
        domain_id: Some(scope.domain_id),
    };

    let cards = state.user_card_repository.find_conflicts(&filter).await?;

    // 冲突检测：同 card_type 不同 template_id 的 ACTIVE 卡
    use std::collections::HashMap;
    let mut by_type: HashMap<String, Vec<&UserCardRecord>> = HashMap::new();
    for card in &cards {
        by_type
            .entry(card.card_type.clone())
            .or_default()
            .push(card);
    }

    let mut conflicts = Vec::new();
    for (card_type, group) in &by_type {
        let distinct_templates: std::collections::HashSet<Option<i64>> =
            group.iter().map(|c| c.template_id).collect();
        if distinct_templates.len() > 1 {
            // 冲突：同类型不同模板
            for card in group {
                conflicts.push(ConflictItem {
                    card_id: card.card_id,
                    template_id: card.template_id,
                    card_type: card_type.clone(),
                    reason: "conflicting card_type across different templates".into(),
                });
            }
        }
    }

    Ok(Json(ApiResponse::success(ConflictDetectionResult {
        user_id,
        conflicts,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(tenant_id: i64, domain_id: i64) -> ManagementScope {
        ManagementScope {
            tenant_id,
            domain_id,
        }
    }

    #[test]
    fn scope_allows_same_tenant_and_domain() {
        let operator = scope(10, 20);
        assert!(scope_allows(&operator, 10, 20, false));
    }

    #[test]
    fn scope_denies_cross_tenant_without_global_admin() {
        let operator = scope(10, 20);
        assert!(!scope_allows(&operator, 11, 20, false));
    }

    #[test]
    fn scope_denies_cross_domain_without_global_admin() {
        let operator = scope(10, 20);
        assert!(!scope_allows(&operator, 10, 21, false));
    }

    #[test]
    fn scope_allows_cross_tenant_for_global_admin() {
        let operator = scope(10, 20);
        assert!(scope_allows(&operator, 11, 30, true));
    }

    #[test]
    fn scope_denies_same_scope_mismatch_for_global_admin() {
        // GlobalAdmin 例外仅放宽跨范围；同范围仍返回 true。
        let operator = scope(10, 20);
        assert!(scope_allows(&operator, 10, 20, true));
    }

    fn headers_with(user: Option<i64>, tenant: Option<i64>, domain: Option<i64>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = user {
            headers.insert("x-user-id", value.to_string().parse().unwrap());
        }
        if let Some(value) = tenant {
            headers.insert("x-user-card-tenant-id", value.to_string().parse().unwrap());
        }
        if let Some(value) = domain {
            headers.insert("x-user-card-domain-id", value.to_string().parse().unwrap());
        }
        headers
    }

    /// 只携带 identity 头（无 user-card scope）时，管理范围必须拒绝——
    /// 禁止回退 identity tenant/domain 到授权 scope。
    fn headers_identity_only(
        user: Option<i64>,
        tenant: Option<i64>,
        domain: Option<i64>,
    ) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = user {
            headers.insert("x-user-id", value.to_string().parse().unwrap());
        }
        if let Some(value) = tenant {
            headers.insert("x-identity-tenant-id", value.to_string().parse().unwrap());
        }
        if let Some(value) = domain {
            headers.insert("x-identity-domain-id", value.to_string().parse().unwrap());
        }
        headers
    }

    #[test]
    fn management_context_requires_all_identities() {
        assert!(require_management_context(&headers_with(Some(1), Some(10), Some(20))).is_ok());
        assert!(require_management_context(&headers_with(None, Some(10), Some(20))).is_err());
        assert!(require_management_context(&headers_with(Some(1), None, Some(20))).is_err());
        assert!(require_management_context(&headers_with(Some(1), Some(10), None)).is_err());
        assert!(require_management_context(&headers_with(Some(1), Some(0), Some(20))).is_err());
        // identity-only 头不得回退为授权 scope（禁止 identity→user-card 回退）
        assert!(
            require_management_context(&headers_identity_only(Some(1), Some(10), Some(20)))
                .is_err()
        );
    }

    #[test]
    fn parse_header_id_rejects_non_positive() {
        let headers = headers_with(Some(1), Some(10), Some(20));
        assert_eq!(parse_header_id(&headers, "x-user-id"), Some(1));
        assert_eq!(parse_header_id(&headers, "x-user-card-tenant-id"), Some(10));
        assert_eq!(parse_header_id(&headers, "x-user-card-domain-id"), Some(20));
        assert_eq!(parse_header_id(&headers, "x-user-card-id"), None);
        assert_eq!(parse_header_id(&headers, "x-identity-tenant-id"), None);
    }

    /// 结构守卫：update handler 必须把 Gateway 已验证的 actor（x-user-id）与
    /// 可选 request id（x-request-id）传播进 UserCardPatch —— 状态变更是授权
    /// source mutation，repository 以 fail-closed 归属校验与状态机收口，本层
    /// 不得丢弃调用者身份。
    #[test]
    fn update_handler_propagates_actor_and_request_operation_id() {
        let handler = include_str!("user_cards.rs")
            .split("async fn update_user_card")
            .nth(1)
            .and_then(|rest| rest.split("async fn delete_user_card").next())
            .expect("update handler body must exist");
        let whitelist = handler
            .find("card_status must be one of")
            .expect("status whitelist validation must stay in the handler");
        let actor = handler
            .find("actor_id: parse_header_id(&headers, \"x-user-id\")")
            .expect("verified x-user-id must be propagated as the mutation actor");
        let request_id = handler
            .find("request_operation_id: headers")
            .expect("optional x-request-id must be propagated for operation identity");
        let service_call = handler
            .find(".update_card(id, &patch, admission)")
            .expect("the patch and proof-bound admission must flow through the service");
        assert!(
            whitelist < actor && actor < request_id && request_id < service_call,
            "identity propagation must accompany the validated patch into the service call"
        );
    }

    /// 结构守卫（回归）：异步批量绑定**不得**把请求级 proof admission 线程
    /// 化进 worker 或按 item 重建预算。注册必须走 ProtectedMutationContext
    /// （ProtectedBusiness admission 在 tracker 拥有的同一事务内消费），worker
    /// 对每个 item 调用 fresh 的 `admit_item`（独立策略+SoD+fence+reserve），
    /// 并把该项自己的 admission 按值移交给 source 事务。曾回归为把一个
    /// admission 克隆成 N 个 item 预算 —— 正是本守卫禁止的重建形态。
    #[test]
    fn async_bind_handler_registers_protected_and_evaluates_items_fresh() {
        let handler = include_str!("user_cards.rs")
            .split("async fn bind_card_async(")
            .nth(1)
            .and_then(|rest| rest.split("async fn conflict_detection").next())
            .expect("bind_card_async handler body must exist");
        assert!(
            handler.contains("Extension(policy): Extension<PolicyContext>"),
            "handler must bind the middleware-verified policy context"
        );
        assert!(
            handler.contains("ProtectedMutationContext::from_policy_context"),
            "registration must build the protected mutation boundary from the verified context"
        );
        assert!(
            handler.contains("register_card_bind_and_spawn(&state.db, batch_permit, registration, parent,"),
            "the protected registration (with its parent context) must run in the tracker-owned future"
        );
        assert!(
            handler.contains("user_card_batch_admission::admit_item("),
            "each batch item must be freshly admitted (policy + SoD + fence + reserve)"
        );
        // 请求级 admission 只作为注册边界的输入进入受保护上下文；worker 循环
        // 内不得出现对它的引用、克隆或线程化。
        let loop_body = handler
            .rsplit("for candidate in pending")
            .next()
            .expect("worker loop must exist");
        assert!(
            !loop_body.contains("&admission"),
            "the request admission must never be threaded into items"
        );
        assert!(
            !loop_body.contains("admission.clone()"),
            "cloning an admission would forge a new one-shot budget: forbidden reconstruction"
        );
        assert!(
            !handler.contains("UserPending"),
            "handler must not construct a UserPending capability fallback"
        );
        assert!(
            !handler.contains("parse_header_id"),
            "requester identity must come from the verified policy context, not spoofable headers"
        );
    }
}
