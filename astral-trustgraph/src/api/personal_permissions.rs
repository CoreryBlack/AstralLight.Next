//! 用户个人权限管理 API — HTTP adapter
//!
//! 对齐 Java `UserPersonalPermissionsController`。
//! 数据访问在 `repository::rule_repository`，grant/revoke 的 rebuild 副作用
//! 编排在 `service::personal_permission_service`。
//!
//! 管理范围门禁（对齐 Java `CardManagementScopeServiceImpl`）：
//! - list/grant/revoke 都必须把目标用户**实际受影响的卡**绑定到 Gateway 已验证
//!   的操作者 tenant/domain scope；唯一例外是 ACTIVE GlobalAdmin。
//!   目标卡 tenant/domain 缺失按不匹配处理（fail-closed）。
//! - 单卡门禁复用 canonical `crate::api::rules::require_card_scope`；
//!   list 聚合目标用户全部 ACTIVE 卡的规则，用同一规则的多卡形式
//!   （`list_scope_allows`）逐卡判定，任一卡越界即整体拒绝，杜绝跨租户/域行泄漏。
//! - revoke 解析 MANUAL 规则**实际承载卡**后再做范围校验，
//!   禁止退化成"只看用户第一张活跃卡"。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_types::AstralError;

use crate::repository::global_admin_repository::GlobalAdminRepository;
use crate::repository::grant_ledger_adapter::DirectRuleMutationContext;
use crate::repository::rule_repository::RuleRecord;
use crate::repository::user_card_repository::{UserCardFilter, UserCardRepository};
use crate::AppState;

/// 从 Gateway 已验证身份头构造 direct 规则 mutation 上下文（actor 必须为正）。
fn mutation_context(headers: &HeaderMap) -> Result<DirectRuleMutationContext, AppError> {
    let actor_id = headers
        .get("x-user-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            AppError(AstralError::Permission(
                "verified user context is required".into(),
            ))
        })?;
    let request_id_header = headers.get("x-request-id").and_then(|v| v.to_str().ok());
    DirectRuleMutationContext::user(actor_id, request_id_header).map_err(AppError::from)
}

// ===== 管理范围门禁（对齐 rules.rs / user_cards.rs 的既有模式） =====

const SCOPE_DENIED: &str = "CARD_MANAGEMENT_SCOPE_DENIED";

fn scope_denied() -> AppError {
    AppError(AstralError::Permission(SCOPE_DENIED.into()))
}

fn parse_header_id(headers: &HeaderMap, name: &str) -> Option<i64> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
}

/// 已验证的管理范围：操作者必须携带 user/tenant/domain 上下文。
///
/// 对齐 Java `requireCardManagementScope`：operator 缺 tenant/domain 直接拒绝；
/// scope 只接受 user-card 上下文（中间件已强制注入），禁止回退 identity
/// tenant/domain。与 `rules::require_management_context` 同一规则（该函数为
/// 模块私有，此处按 user_cards.rs 既有先例持有本地纯副本）。
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

/// 已验证的管理范围（操作者 tenant/domain 绑定）。
#[derive(Debug, Clone, Copy)]
struct ManagementScope {
    tenant_id: i64,
    domain_id: i64,
}

/// list 聚合范围判定（`rules::require_card_scope` 同一规则的多卡形式）：
/// 目标用户每张 ACTIVE 卡的 tenant/domain 必须与操作者一致；任一卡越界时仅
/// ACTIVE GlobalAdmin 例外放行；卡 tenant/domain 缺失按不匹配处理
/// （fail-closed —— 与 `require_card_scope` 对 NULL 卡边界的拒绝一致，
/// GlobalAdmin 也不例外）。
fn list_scope_allows(
    operator_tenant: i64,
    operator_domain: i64,
    cards: &[(Option<i64>, Option<i64>)],
    is_global_admin: bool,
) -> bool {
    for &(tenant_id, domain_id) in cards {
        let Some(tenant) = tenant_id else {
            return false;
        };
        let Some(domain) = domain_id else {
            return false;
        };
        if tenant == operator_tenant && domain == operator_domain {
            continue;
        }
        if !is_global_admin {
            return false;
        }
    }
    true
}

/// list 分页枚举 ACTIVE 卡的页大小与防御性页数上限（超出按 fail-closed 拒绝，
/// 绝不对未校验范围的卡放行聚合列表）。
const LIST_SCOPE_PAGE_SIZE: i64 = 200;
const LIST_SCOPE_MAX_PAGES: i64 = 50;

/// 个人权限列表的范围门：目标用户的**全部 ACTIVE 卡**都必须处于操作者
/// tenant/domain scope（或操作者为 ACTIVE GlobalAdmin）。
///
/// 列表聚合了该用户全部活跃卡的 CARD_ONLY/MANUAL 规则，因此必须逐卡校验；
/// 任一卡越界即整体拒绝，不允许跨租户/域泄漏部分行。
async fn require_user_permission_list_scope(
    user_card_repo: &dyn UserCardRepository,
    global_admin_repo: &dyn GlobalAdminRepository,
    headers: &HeaderMap,
    user_id: i64,
) -> Result<(), AppError> {
    let operator = require_management_context(headers)?;
    let admin_user = parse_header_id(headers, "x-user-id").ok_or_else(scope_denied)?;
    let mut cards: Vec<(Option<i64>, Option<i64>)> = Vec::new();
    let mut offset = 0i64;
    for _ in 0..LIST_SCOPE_MAX_PAGES {
        let page = user_card_repo
            .list_cards(
                &UserCardFilter {
                    user_id: Some(user_id),
                    card_status: Some("ACTIVE".into()),
                    ..UserCardFilter::default()
                },
                LIST_SCOPE_PAGE_SIZE,
                offset,
            )
            .await
            .map_err(AppError::from)?;
        let page_len = page.len() as i64;
        cards.extend(
            page.into_iter()
                .map(|card| (card.tenant_id, card.domain_id)),
        );
        if page_len < LIST_SCOPE_PAGE_SIZE {
            let is_global_admin = global_admin_repo
                .is_active_admin(admin_user)
                .await
                .map_err(AppError::from)?;
            if list_scope_allows(
                operator.tenant_id,
                operator.domain_id,
                &cards,
                is_global_admin,
            ) {
                return Ok(());
            }
            return Err(scope_denied());
        }
        offset += LIST_SCOPE_PAGE_SIZE;
    }
    // 超出枚举上限：无法证明全部卡都在范围内，fail-closed 拒绝。
    Err(scope_denied())
}

// ===== 数据模型 =====

/// 用户有效权限（聚合 user_card + permission_rule）
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserPermission {
    pub rule_id: i64,
    pub card_id: i64,
    pub resource_type: String,
    pub action_code: String,
    pub effect: String,
    pub source_type: String,
    pub priority: i32,
}

impl From<RuleRecord> for UserPermission {
    fn from(r: RuleRecord) -> Self {
        Self {
            rule_id: r.rule_id,
            card_id: r.card_id,
            resource_type: r.resource_type,
            action_code: r.action_code,
            effect: r.effect,
            source_type: r.source_type,
            priority: r.priority,
        }
    }
}

/// 授予权限请求
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantPermissionRequest {
    pub resource_type: String,
    pub action_code: String,
    pub effect: Option<String>,
    pub priority: Option<i32>,
}

// ===== 路由注册 =====

pub fn personal_permission_routes() -> Router<AppState> {
    Router::new()
        .route("/users/{user_id}/permissions", get(list_user_permissions))
        .route("/users/{user_id}/permissions", post(grant_user_permission))
        .route(
            "/users/{user_id}/permissions/{rule_id}",
            delete(revoke_user_permission),
        )
}

// ===== Handlers =====

/// GET /main/api/v1/users/{user_id}/permissions — 列出用户有效权限
async fn list_user_permissions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<i64>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<UserPermission>>>, AppError> {
    // 范围门：目标用户全部 ACTIVE 卡绑定到操作者 tenant/domain（GlobalAdmin 例外）
    require_user_permission_list_scope(
        state.user_card_repository.as_ref(),
        state.global_admin_repository.as_ref(),
        &headers,
        user_id,
    )
    .await?;

    let total = state.rule_repository.count_user_rules(user_id).await?;
    let rows = state
        .rule_repository
        .list_user_rules(user_id, page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(UserPermission::from)
        .collect();

    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

/// POST /main/api/v1/users/{user_id}/permissions — 授予用户权限
async fn grant_user_permission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<i64>,
    Json(req): Json<GrantPermissionRequest>,
) -> Result<Json<ApiResponse<UserPermission>>, AppError> {
    // 查找用户第一张活跃卡（对齐 platform_v4：card_id PK, card_status）；
    // 该卡就是本次 grant 的实际受影响卡，写入前必须绑定到操作者范围。
    let card = state
        .user_card_repository
        .find_active_card_for_user(user_id)
        .await?
        .ok_or_else(|| {
            AppError(AstralError::Validation(format!(
                "no active user_card found for user {user_id}"
            )))
        })?;

    // canonical 单卡管理范围门（tenant/domain 比对 + ACTIVE GlobalAdmin 例外）
    crate::api::rules::require_card_scope(&state, &headers, card).await?;

    // fail-closed（service 内先于任何 source mutation）：canonical 授权只接受
    // ALLOW（大小写归一）且 resource/action 必须命中 ResourceRegistry；
    // 空值/未知值/DENY/未注册资源一律在写入前拒绝。
    let outcome = state
        .personal_permission_service
        .grant(
            card,
            &req.resource_type,
            &req.action_code,
            req.effect.as_deref().unwrap_or("ALLOW"),
            req.priority,
            &mutation_context(&headers)?,
        )
        .await?;

    // 响应回显 service 归一化后的持久化值（trim + ALLOW），不回显原始入参。
    Ok(Json(ApiResponse::success(UserPermission {
        rule_id: outcome.rule_id,
        card_id: outcome.card_id,
        resource_type: outcome.resource_type,
        action_code: outcome.action_code,
        effect: outcome.effect,
        source_type: "MANUAL".into(),
        priority: outcome.priority,
    })))
}

/// DELETE /main/api/v1/users/{user_id}/permissions/{rule_id} — 撤销用户权限
async fn revoke_user_permission(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((user_id, rule_id)): Path<(i64, i64)>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    // 对齐 rules.rs `require_rule_scope`：先解析规则**实际承载卡**
    // （MANUAL/CARD_ONLY 且属于该用户），再校验操作者对该卡的管理范围。
    // 禁止退化成"用户第一张活跃卡"的范围判定 —— 规则可能不在那张卡上。
    let manual_card = state
        .rule_repository
        .find_manual_rule_card_for_user(rule_id, user_id)
        .await?
        .ok_or_else(scope_denied)?;

    crate::api::rules::require_card_scope(&state, &headers, manual_card).await?;

    state
        .personal_permission_service
        .revoke(user_id, rule_id, &mutation_context(&headers)?)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::repository::global_admin_repository::{
        DisableOutcome, GlobalAdminGrantOutcome, GlobalAdminRecord,
    };
    use crate::repository::user_card_repository::{
        DeleteCascadeResult, NewUserCard, UserCardPatch, UserCardRecord,
    };
    use async_trait::async_trait;
    use std::sync::Mutex;

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

    // ===== 纯范围判定 =====

    #[test]
    fn list_scope_allows_same_tenant_and_domain() {
        let cards = vec![(Some(10), Some(20)), (Some(10), Some(20))];
        assert!(list_scope_allows(10, 20, &cards, false));
    }

    #[test]
    fn list_scope_denies_cross_tenant_without_global_admin() {
        let cards = vec![(Some(10), Some(20)), (Some(11), Some(20))];
        assert!(!list_scope_allows(10, 20, &cards, false));
    }

    #[test]
    fn list_scope_denies_cross_domain_without_global_admin() {
        let cards = vec![(Some(10), Some(20)), (Some(10), Some(21))];
        assert!(!list_scope_allows(10, 20, &cards, false));
    }

    #[test]
    fn list_scope_allows_cross_scope_for_global_admin() {
        let cards = vec![(Some(11), Some(30))];
        assert!(list_scope_allows(10, 20, &cards, true));
    }

    #[test]
    fn list_scope_fails_closed_on_missing_card_boundary_even_for_global_admin() {
        // 卡 tenant/domain 缺失按不匹配处理：与 require_card_scope 的 NULL 拒绝
        // 一致，GlobalAdmin 例外不得绕过（对齐 require_card_scope 的检查顺序）。
        assert!(!list_scope_allows(10, 20, &[(None, Some(20))], true));
        assert!(!list_scope_allows(10, 20, &[(Some(10), None)], true));
        assert!(!list_scope_allows(10, 20, &[(None, None)], false));
    }

    #[test]
    fn list_scope_allows_empty_card_set() {
        // 目标用户无 ACTIVE 卡：无可泄漏行，放行空列表
        assert!(list_scope_allows(10, 20, &[], false));
    }

    // ===== 管理上下文 / mutation 上下文 =====

    #[test]
    fn management_context_requires_all_identities() {
        assert!(require_management_context(&headers_with(Some(1), Some(10), Some(20))).is_ok());
        assert!(require_management_context(&headers_with(None, Some(10), Some(20))).is_err());
        assert!(require_management_context(&headers_with(Some(1), None, Some(20))).is_err());
        assert!(require_management_context(&headers_with(Some(1), Some(10), None)).is_err());
        assert!(require_management_context(&headers_with(Some(1), Some(0), Some(20))).is_err());
    }

    #[test]
    fn mutation_context_requires_positive_verified_actor() {
        let ok = mutation_context(&headers_with(Some(17), Some(10), Some(20)))
            .expect("positive actor must be accepted");
        assert_eq!(ok.actor_user_id, 17);

        let missing = mutation_context(&headers_with(None, Some(10), Some(20)))
            .expect_err("missing actor must be rejected");
        assert!(matches!(missing, AppError(AstralError::Permission(_))));

        let zero = mutation_context(&headers_with(Some(0), Some(10), Some(20)))
            .expect_err("non-positive actor must be rejected");
        assert!(matches!(zero, AppError(AstralError::Permission(_))));
    }

    // ===== list 范围门（fake 仓储行为验证） =====

    fn card_record(card_id: i64, tenant_id: Option<i64>, domain_id: Option<i64>) -> UserCardRecord {
        UserCardRecord {
            card_id,
            user_id: Some(5),
            domain_id,
            card_type: "MAIN".into(),
            card_status: "ACTIVE".into(),
            template_id: None,
            level_id: None,
            priority: None,
            is_primary: None,
            valid_from: None,
            valid_until: None,
            created_at: None,
            updated_at: None,
            tenant_id,
            card_name: None,
            template_code: None,
            template_name: None,
            level_code: None,
            level_name: None,
            level_no: None,
            action_codes: None,
        }
    }

    /// Fake UserCardRepository：分页返回预置 ACTIVE 卡（记录调用）。
    struct FakeUserCardRepository {
        cards: Vec<UserCardRecord>,
        /// 非 None 时无视预置卡，恒返回满页（用于枚举上限 fail-closed 验证）
        always_full_page: bool,
        calls: Mutex<Vec<String>>,
    }

    impl FakeUserCardRepository {
        fn new(cards: Vec<UserCardRecord>) -> Self {
            Self {
                cards,
                always_full_page: false,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn always_full_page() -> Self {
            Self {
                cards: Vec::new(),
                always_full_page: true,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl UserCardRepository for FakeUserCardRepository {
        async fn count_cards(&self, _filter: &UserCardFilter) -> Result<i64, AstralError> {
            self.calls.lock().unwrap().push("count_cards".into());
            Ok(0)
        }

        async fn list_cards(
            &self,
            _filter: &UserCardFilter,
            limit: i64,
            offset: i64,
        ) -> Result<Vec<UserCardRecord>, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("list_cards:{limit}:{offset}"));
            if self.always_full_page {
                return Ok(vec![card_record(1, Some(10), Some(20)); limit as usize]);
            }
            Ok(self
                .cards
                .iter()
                .skip(offset.max(0) as usize)
                .take(limit.max(0) as usize)
                .cloned()
                .collect())
        }

        async fn get_card(&self, card_id: i64) -> Result<Option<UserCardRecord>, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("get_card:{card_id}"));
            Ok(self.cards.iter().find(|c| c.card_id == card_id).cloned())
        }

        async fn create_card(&self, _new: &NewUserCard) -> Result<i64, AstralError> {
            self.calls.lock().unwrap().push("create_card".into());
            Ok(0)
        }

        async fn update_card(
            &self,
            _card_id: i64,
            _patch: &UserCardPatch,
        ) -> Result<(), AstralError> {
            self.calls.lock().unwrap().push("update_card".into());
            Ok(())
        }

        async fn delete_with_cascade(
            &self,
            _card_id: i64,
        ) -> Result<DeleteCascadeResult, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push("delete_with_cascade".into());
            Ok(DeleteCascadeResult {
                exists: false,
                permission_rule_deleted: 0,
                snapshot_deleted: 0,
                rule_set_ref_deleted: 0,
            })
        }

        async fn restore_card(&self, _card_id: i64) -> Result<bool, AstralError> {
            self.calls.lock().unwrap().push("restore_card".into());
            Ok(false)
        }

        async fn bind_card(&self, _card_id: i64, _user_id: i64) -> Result<bool, AstralError> {
            self.calls.lock().unwrap().push("bind_card".into());
            Ok(false)
        }

        async fn bind_card_async_one(
            &self,
            _card_id: i64,
            _user_id: i64,
        ) -> Result<bool, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push("bind_card_async_one".into());
            Ok(false)
        }

        async fn find_conflicts(
            &self,
            _filter: &UserCardFilter,
        ) -> Result<Vec<UserCardRecord>, AstralError> {
            self.calls.lock().unwrap().push("find_conflicts".into());
            Ok(vec![])
        }

        async fn find_active_card_for_user(
            &self,
            user_id: i64,
        ) -> Result<Option<i64>, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("find_active_card_for_user:{user_id}"));
            Ok(self.cards.first().map(|c| c.card_id))
        }
    }

    /// Fake GlobalAdminRepository：可配置 ACTIVE 判定（记录调用）。
    struct FakeGlobalAdminRepository {
        is_admin: bool,
        calls: Mutex<Vec<String>>,
    }

    impl FakeGlobalAdminRepository {
        fn new(is_admin: bool) -> Self {
            Self {
                is_admin,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl GlobalAdminRepository for FakeGlobalAdminRepository {
        async fn list_admins(
            &self,
            _status: Option<&str>,
        ) -> Result<Vec<GlobalAdminRecord>, AstralError> {
            self.calls.lock().unwrap().push("list_admins".into());
            Ok(vec![])
        }

        async fn count_active(&self) -> Result<i64, AstralError> {
            self.calls.lock().unwrap().push("count_active".into());
            Ok(0)
        }

        async fn count_all(&self) -> Result<i64, AstralError> {
            self.calls.lock().unwrap().push("count_all".into());
            Ok(0)
        }

        async fn get_by_user_id(
            &self,
            _user_id: i64,
        ) -> Result<Option<GlobalAdminRecord>, AstralError> {
            self.calls.lock().unwrap().push("get_by_user_id".into());
            Ok(None)
        }

        async fn get_by_id(&self, _id: i64) -> Result<Option<GlobalAdminRecord>, AstralError> {
            self.calls.lock().unwrap().push("get_by_id".into());
            Ok(None)
        }

        async fn is_active_admin(&self, user_id: i64) -> Result<bool, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("is_active_admin:{user_id}"));
            Ok(self.is_admin)
        }

        async fn grant_with_superadmin_privilege(
            &self,
            _user_id: i64,
            _granted_by: i64,
            _reason: Option<&str>,
            _template_id: i64,
            _rule_set_id: i64,
        ) -> Result<GlobalAdminGrantOutcome, AstralError> {
            self.calls
                .lock()
                .unwrap()
                .push("grant_with_superadmin_privilege".into());
            Ok(GlobalAdminGrantOutcome {
                admin_id: 0,
                card_id: 0,
                projection_ready: false,
            })
        }

        async fn disable_protected(
            &self,
            _id: i64,
            _user_id: i64,
            _granted_by: i64,
            _reason: Option<&str>,
        ) -> Result<DisableOutcome, AstralError> {
            self.calls.lock().unwrap().push("disable_protected".into());
            Ok(DisableOutcome::UpdateFailed)
        }
    }

    fn assert_scope_denied(error: AppError) {
        assert!(
            matches!(error, AppError(AstralError::Permission(ref message)) if message == SCOPE_DENIED),
            "expected scope denial, got {error:?}"
        );
    }

    #[tokio::test]
    async fn list_scope_denies_cross_tenant_target_without_global_admin() {
        let cards = FakeUserCardRepository::new(vec![card_record(7, Some(11), Some(20))]);
        let admin = FakeGlobalAdminRepository::new(false);

        let error = require_user_permission_list_scope(
            &cards,
            &admin,
            &headers_with(Some(1), Some(10), Some(20)),
            5,
        )
        .await
        .expect_err("cross-tenant target must be denied");

        assert_scope_denied(error);
        assert_eq!(admin.calls(), vec!["is_active_admin:1"]);
    }

    #[tokio::test]
    async fn list_scope_denies_cross_domain_target_without_global_admin() {
        let cards = FakeUserCardRepository::new(vec![card_record(7, Some(10), Some(21))]);
        let admin = FakeGlobalAdminRepository::new(false);

        let error = require_user_permission_list_scope(
            &cards,
            &admin,
            &headers_with(Some(1), Some(10), Some(20)),
            5,
        )
        .await
        .expect_err("cross-domain target must be denied");

        assert_scope_denied(error);
    }

    #[tokio::test]
    async fn list_scope_allows_same_scope_target() {
        let cards = FakeUserCardRepository::new(vec![
            card_record(7, Some(10), Some(20)),
            card_record(8, Some(10), Some(20)),
        ]);
        let admin = FakeGlobalAdminRepository::new(false);

        require_user_permission_list_scope(
            &cards,
            &admin,
            &headers_with(Some(1), Some(10), Some(20)),
            5,
        )
        .await
        .expect("same-scope target must be allowed");
    }

    #[tokio::test]
    async fn list_scope_allows_cross_scope_for_active_global_admin() {
        let cards = FakeUserCardRepository::new(vec![card_record(7, Some(11), Some(30))]);
        let admin = FakeGlobalAdminRepository::new(true);

        require_user_permission_list_scope(
            &cards,
            &admin,
            &headers_with(Some(1), Some(10), Some(20)),
            5,
        )
        .await
        .expect("ACTIVE GlobalAdmin exception must allow cross-scope list");
    }

    #[tokio::test]
    async fn list_scope_allows_target_without_active_cards() {
        let cards = FakeUserCardRepository::new(vec![]);
        let admin = FakeGlobalAdminRepository::new(false);

        require_user_permission_list_scope(
            &cards,
            &admin,
            &headers_with(Some(1), Some(10), Some(20)),
            5,
        )
        .await
        .expect("target without ACTIVE cards has no leakable rows");
    }

    #[tokio::test]
    async fn list_scope_denies_out_of_scope_card_on_later_page() {
        // 第 1 页恰为满页且全部同范围，越界卡只出现在第 2 页 ——
        // 分页枚举必须覆盖到，不得提前放行。
        let mut records: Vec<UserCardRecord> = (0..LIST_SCOPE_PAGE_SIZE)
            .map(|i| card_record(1000 + i, Some(10), Some(20)))
            .collect();
        records.push(card_record(9999, Some(11), Some(20)));
        let cards = FakeUserCardRepository::new(records);
        let admin = FakeGlobalAdminRepository::new(false);

        let error = require_user_permission_list_scope(
            &cards,
            &admin,
            &headers_with(Some(1), Some(10), Some(20)),
            5,
        )
        .await
        .expect_err("out-of-scope card on a later page must be denied");

        assert_scope_denied(error);
        assert!(cards.calls().contains(&format!(
            "list_cards:{}:{}",
            LIST_SCOPE_PAGE_SIZE, LIST_SCOPE_PAGE_SIZE
        )));
    }

    #[tokio::test]
    async fn list_scope_fails_closed_when_enumeration_exceeds_bound() {
        // 恒返回满页 = 枚举永不完结：超过防御性页数上限必须 fail-closed 拒绝，
        // 即使已见到的卡都在范围内。
        let cards = FakeUserCardRepository::always_full_page();
        let admin = FakeGlobalAdminRepository::new(false);

        let error = require_user_permission_list_scope(
            &cards,
            &admin,
            &headers_with(Some(1), Some(10), Some(20)),
            5,
        )
        .await
        .expect_err("unbounded enumeration must fail closed");

        assert_scope_denied(error);
        assert_eq!(
            cards.calls().len(),
            LIST_SCOPE_MAX_PAGES as usize,
            "enumeration must stop at the defensive page bound"
        );
    }

    // ===== 结构守卫：handler 必须按序接入门禁（对齐 user_cards.rs 先例） =====

    fn handler_body(source: &str, start: &str, end: &str) -> String {
        let body = source
            .split(start)
            .nth(1)
            .unwrap_or_else(|| panic!("{start} must exist"));
        match end {
            "" => body.to_string(),
            _ => body
                .split(end)
                .next()
                .unwrap_or_else(|| panic!("{end} must exist"))
                .to_string(),
        }
    }

    #[test]
    fn list_handler_applies_user_scope_gate_before_any_repository_read() {
        let source = include_str!("personal_permissions.rs");
        let body = handler_body(
            source,
            "async fn list_user_permissions",
            "async fn grant_user_permission",
        );
        let gate = body
            .find("require_user_permission_list_scope(")
            .expect("list handler must call the user scope gate");
        let count = body
            .find("count_user_rules")
            .expect("list handler must read rules through the repository");
        assert!(
            gate < count,
            "the user scope gate must run before any rule read"
        );
    }

    #[test]
    fn grant_handler_binds_affected_card_to_scope_before_mutation() {
        let source = include_str!("personal_permissions.rs");
        let body = handler_body(
            source,
            "async fn grant_user_permission",
            "async fn revoke_user_permission",
        );
        let card = body
            .find("find_active_card_for_user")
            .expect("grant must resolve the actual affected (first ACTIVE) card");
        let scope = body
            .find("crate::api::rules::require_card_scope")
            .expect("grant must reuse the canonical card scope gate");
        let grant = body
            .find("personal_permission_service\n            .grant(")
            .or_else(|| body.find(".grant("))
            .expect("grant must flow through the service");
        assert!(
            card < scope && scope < grant,
            "scope check must run after card resolution and before the service mutation"
        );
    }

    #[test]
    fn revoke_handler_scope_checks_actual_manual_rule_card_not_first_active_card() {
        let source = include_str!("personal_permissions.rs");
        let body = handler_body(source, "async fn revoke_user_permission", "#[cfg(test)]");
        // 撤销禁止用"用户第一张活跃卡"做范围判定
        assert!(
            !body.contains("find_active_card_for_user"),
            "revoke must not fall back to the user's first active card"
        );
        let manual = body
            .find("find_manual_rule_card_for_user")
            .expect("revoke must resolve the actual MANUAL rule card");
        let scope = body
            .find("crate::api::rules::require_card_scope")
            .expect("revoke must reuse the canonical card scope gate");
        let revoke = body
            .find(".revoke(")
            .expect("revoke must flow through the service");
        assert!(
            manual < scope && scope < revoke,
            "the actual MANUAL rule card must be scope-checked before the service mutation"
        );
    }
}
