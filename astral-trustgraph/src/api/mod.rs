//! TrustGraph API 模块

use axum::http::HeaderMap;
use sqlx::MySqlPool;

use astral_common::error::AppError;
use astral_db::{
    cached_load_published_card_grant_evidence, sod_load_card_tenant, AuthorizationEvidenceError,
};
use astral_types::{
    get_alias_sources, parse_resource_key, AstralError, CanonicalGrant, DomainScopeRequirement,
    GrantEffect, GrantState, PolicyContext, PublishedCardAuthorization, PublishedCardEvidenceScope,
};

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

// ===== 诊断端点共享：卡级已发布证据读取 + 统一 ALLOW-only 匹配器 =====
//
// consistency_monitor（一致性巡检）与 simulation（what-if 仿真）共用同一数据
// 源与匹配语义，避免两份实现漂移：
// - 数据源：Rust-owned published card evidence（读取经
//   `astral_db::cached_load_published_card_grant_evidence`：进程内 evidence
//   缓存 + 指针对牌，miss/漂移回源严格 reader——后者在单个短事务内 FOR
//   UPDATE 锁定当前指针并整链校验）；不存在 legacy 快照 / raw source 回退；
// - 匹配器：`policy_engine` 内部同名私有 fn（engine.rs
//   `match_published_effective_grant`，未导出）的 trustgraph 镜像；复用
//   astral-types 导出的 `parse_resource_key` / `get_alias_sources`，
//   与 PolicyEngine strict gate 的 ALLOW 判定语义保持一致。

/// 已发布证据不可读的结构化观测（诊断端点专用）。
///
/// 诊断端点把"不可读"如实呈现为"新链不可用"观测 / fail-closed DENY 结论，
/// 而不是 panic 或 500；本类型绝不参与放行语义。
#[derive(Debug, Clone)]
pub(crate) struct PublishedEvidenceUnavailable {
    /// 稳定状态码（`published_card_evidence_*` 前缀，供日志/观测关联）。
    pub code: &'static str,
    /// reader 返回的原始 detail（已含 `code=published_card_evidence.*` 细分）。
    pub detail: String,
}

impl PublishedEvidenceUnavailable {
    /// 组装为可写入观测字段/响应 reason 的稳定字符串。
    pub(crate) fn observation(&self) -> String {
        format!("{};detail={}", self.code, self.detail)
    }
}

/// 按 [`AuthorizationEvidenceError`] 族映射稳定状态码。
///
/// 对齐 SoD 读路径（astral-db `sod_evidence_error_message`）的族划分：
/// NotReady/InvalidRequest/Query → pending 族，Corrupt → corrupt 族。
fn published_evidence_error_code(error: &AuthorizationEvidenceError) -> &'static str {
    match error {
        AuthorizationEvidenceError::NotReady(_) => "published_card_evidence_not_ready",
        AuthorizationEvidenceError::Corrupt(_) => "published_card_evidence_corrupt",
        AuthorizationEvidenceError::InvalidRequest(_) => "published_card_evidence_invalid_scope",
        AuthorizationEvidenceError::Query(_) => "published_card_evidence_query_failed",
    }
}

/// 诊断读路径共享的卡级已发布证据读取（fail-closed 不 panic）。
///
/// - tenant 定位输入：`sod_load_card_tenant`（`user_card.tenant_id`；行缺失或
///   非正 → 不可读观测，绝不折算成空证据——空证据会伪装成"无授权"放行对比）；
/// - 卡级 lens：`user_filter: None` + `DomainScopeRequirement::Unconstrained`
///   （先例：astral-db `permission_query::load_card_permission_summaries` 与
///   `sod_check::check_sod_conflict`）；请求侧 user/domain 边界由匹配器施加；
/// - 读取经进程内 evidence 缓存 + 指针对牌（miss/漂移回源严格 reader）；
///   Ready 证据再过一次合同校验（纵深防御，对齐 SoD/卡摘要读路径）；形状
///   矛盾 → corrupt 观测。
pub(crate) async fn load_diagnostic_card_evidence(
    db: &MySqlPool,
    card_id: i64,
) -> Result<PublishedCardAuthorization, PublishedEvidenceUnavailable> {
    let tenant_id = match sod_load_card_tenant(db, card_id).await {
        Ok(tenant_id) => tenant_id,
        Err(error) => {
            tracing::warn!(
                card_id,
                error = %error,
                "diagnostic read path: card tenant unavailable"
            );
            return Err(PublishedEvidenceUnavailable {
                code: "published_card_evidence_invalid_scope",
                detail: error.to_string(),
            });
        }
    };

    let scope = PublishedCardEvidenceScope {
        tenant_id,
        card_id,
        user_filter: None,
        domain: DomainScopeRequirement::Unconstrained,
    };
    let evidence = match cached_load_published_card_grant_evidence(db, &scope).await {
        Ok(evidence) => evidence,
        Err(error) => {
            tracing::warn!(
                card_id,
                error = %error,
                "diagnostic read path: published card evidence unavailable"
            );
            return Err(PublishedEvidenceUnavailable {
                code: published_evidence_error_code(&error),
                detail: error.to_string(),
            });
        }
    };
    if let Err(contract_error) = evidence.validate() {
        tracing::warn!(
            card_id,
            error = %contract_error,
            "diagnostic read path: published card evidence failed contract validation"
        );
        return Err(PublishedEvidenceUnavailable {
            code: "published_card_evidence_corrupt",
            detail: contract_error.to_string(),
        });
    }
    Ok(evidence)
}

/// 统一 ALLOW-only 匹配器：在已发布证据的 `effective_grants` 中找第一条同时
/// 满足身份/有效期/资源/动作约束的 grant（evidence 顺序确定性遍历，首中即胜）。
///
/// 与 `policy_engine::engine` 的私有匹配器（engine.rs
/// `match_published_effective_grant`）语义逐行对齐；该函数未从 policy-engine
/// 导出，故按同语义镜像并复用 astral-types 导出的 `parse_resource_key` /
/// `get_alias_sources`。若上游匹配语义演进，必须同步本镜像（上游由
/// policy-engine 自身测试锚定，本镜像由本文件测试锚定）。
///
/// # 匹配语义（fail-closed，与 PolicyEngine strict gate 一致）
///
/// - 身份：grant 的 `card_id`/`user_id`/`tenant_id` 必须与请求完全一致；请求
///   携带 domain 时 grant 必须属于同一 domain。
/// - 有效期：以本次证据读取的统一 UTC 时钟（`read_unix_seconds`）为准。
/// - 状态/效果：合同只允许 ACTIVE+ALLOW 进入 effective 集合；漂移一律不匹配。
/// - 资源（`parse_resource_key` 语义）：对象请求（`type:id`）可命中同一对象的
///   对象级 grant 或类型级 grant（`type:*`/裸 `type`/`*`）；类型级请求
///   （`type:*`）绝不命中对象级 grant，只命中类型级 grant（含全局 `*`）。
/// - 动作：exact → `write` 别名（write→create/update/delete）→ `'*'`。
pub(crate) fn match_published_effective_grant<'a>(
    ctx: &PolicyContext,
    evidence: &'a PublishedCardAuthorization,
    resource_key: &str,
) -> Option<&'a CanonicalGrant> {
    let card_id = ctx.card_id.unwrap_or(0);
    let request_tenant = ctx.tenant_id.unwrap_or(0);
    let (request_type, request_id) = parse_resource_key(resource_key);
    let type_level_request = request_id.is_none();
    let now = evidence.read_unix_seconds;

    evidence.effective_grants.iter().find(|grant| {
        // 身份/租户边界：grant 必须属于本次请求的卡、用户、租户。
        if grant.card_id != card_id
            || ctx.user_id.is_none_or(|user_id| grant.user_id != user_id)
            || grant.tenant.tenant_id != request_tenant
        {
            return false;
        }
        // domain 边界：请求携带 domain 时 grant 必须属于同一 domain。
        if let Some(domain_id) = ctx.domain_id {
            if grant.tenant.domain_id != Some(domain_id) {
                return false;
            }
        }
        // 有效期（统一 UTC 时钟）。
        if !grant.validity.is_valid_at(now) {
            return false;
        }
        // 合同只允许 ACTIVE+ALLOW 形态进入 effective_grants；漂移 fail-closed。
        if grant.state != GrantState::Active || grant.effect != GrantEffect::Allow {
            return false;
        }
        // 资源匹配：类型级 grant 通配本类型，`*` 全局通配；对象级 grant 只命中
        // 同一对象；类型级请求绝不命中对象级 grant。
        let (grant_type, grant_id) = parse_resource_key(&grant.resource);
        if grant_type != request_type && grant_type != "*" {
            return false;
        }
        if type_level_request {
            if grant_id.is_some() {
                return false;
            }
        } else if grant_id.is_some() && grant_id != request_id {
            return false;
        }
        // 动作匹配：exact / write 别名 / '*'。
        let action = ctx.action.as_str();
        grant.action == action
            || grant.action == "*"
            || get_alias_sources(action).contains(&grant.action.as_str())
    })
}

pub mod approval;
pub mod arbiter;
pub mod audit;
pub mod audit_replay;
pub mod audit_service;
pub mod consistency_monitor;
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

#[cfg(test)]
mod evidence_matcher_tests {
    use super::*;
    use astral_types::{
        BindingLayer, GrantId, GrantProvenance, GrantRevision, GrantSourceKind,
        PublishedCardAuthorizationGate, PublishedEvidenceGateStatus, TenantScope, ValidityWindow,
    };

    /// 统一读取时钟（测试证据的 `read_unix_seconds`）。
    const NOW: i64 = 1_800_000_000;

    fn direct_grant(
        tenant_id: i64,
        domain_id: Option<i64>,
        card_id: i64,
        user_id: i64,
        resource: &str,
        action: &str,
        validity: ValidityWindow,
    ) -> CanonicalGrant {
        CanonicalGrant {
            grant_id: GrantId::random(),
            revision: GrantRevision::new(1).expect("revision 1 must be valid"),
            state: GrantState::Active,
            source_kind: GrantSourceKind::Direct,
            binding_layer: BindingLayer::None,
            tenant: TenantScope::new(tenant_id, domain_id).expect("tenant scope must be valid"),
            card_id,
            user_id,
            resource: resource.to_string(),
            action: action.to_string(),
            effect: GrantEffect::Allow,
            validity,
            provenance: GrantProvenance {
                source_id: "direct-grant-diag".to_string(),
                source_entry: None,
                binding_id: None,
                delegation_id: None,
                operation_id: "op-diag-matcher-test".to_string(),
                event_id: None,
                actor_user_id: None,
            },
        }
    }

    fn ready_evidence(card_id: i64, grants: Vec<CanonicalGrant>) -> PublishedCardAuthorization {
        PublishedCardAuthorization {
            tenant_id: 1,
            card_id,
            read_unix_seconds: NOW,
            gate: PublishedCardAuthorizationGate {
                status: PublishedEvidenceGateStatus::Ready,
                aggregate_manifest_count: 0,
                verified_record_count: 0,
                effective_grant_count: grants.len(),
                not_in_effective_count: 0,
                equivalent_duplicate_collapsed_count: 0,
            },
            manifests: vec![],
            records: vec![],
            effective_grants: grants,
        }
    }

    fn ctx(
        user_id: Option<i64>,
        domain_id: Option<i64>,
        tenant_id: Option<i64>,
        resource: &str,
        action: &str,
    ) -> PolicyContext {
        PolicyContext::builder()
            .user_id(user_id)
            .card_id(Some(7))
            .tenant_id(tenant_id)
            .domain_id(domain_id)
            .resource(Some(resource.to_string()))
            .action(action.to_string())
            .build()
    }

    // ===== 资源匹配（parse_resource_key 语义） =====

    #[test]
    fn object_request_matches_object_and_type_level_grants() {
        let evidence = ready_evidence(
            7,
            vec![
                direct_grant(
                    1,
                    None,
                    7,
                    1,
                    "learn_subject:42",
                    "read",
                    ValidityWindow::perpetual(),
                ),
                direct_grant(
                    1,
                    None,
                    7,
                    1,
                    "learn_subject:*",
                    "read",
                    ValidityWindow::perpetual(),
                ),
            ],
        );
        // 对象请求命中对象级 grant（首中即胜）。
        assert!(match_published_effective_grant(
            &ctx(Some(1), None, Some(1), "learn_subject:42", "read"),
            &evidence,
            "learn_subject:42"
        )
        .is_some());
        // 对象请求同样命中类型级 grant。
        assert!(match_published_effective_grant(
            &ctx(Some(1), None, Some(1), "learn_subject:43", "read"),
            &evidence,
            "learn_subject:43"
        )
        .is_some());
        // 其它类型不命中。
        assert!(match_published_effective_grant(
            &ctx(Some(1), None, Some(1), "approval:42", "read"),
            &evidence,
            "approval:42"
        )
        .is_none());
    }

    #[test]
    fn type_level_request_never_matches_object_level_grant() {
        let evidence = ready_evidence(
            7,
            vec![direct_grant(
                1,
                None,
                7,
                1,
                "learn_subject:42",
                "read",
                ValidityWindow::perpetual(),
            )],
        );
        // 类型级请求（"learn_subject" / "learn_subject:*"）绝不命中对象级 grant。
        assert!(match_published_effective_grant(
            &ctx(Some(1), None, Some(1), "learn_subject", "read"),
            &evidence,
            "learn_subject"
        )
        .is_none());
        assert!(match_published_effective_grant(
            &ctx(Some(1), None, Some(1), "learn_subject", "read"),
            &evidence,
            "learn_subject:*"
        )
        .is_none());
    }

    #[test]
    fn global_wildcard_grant_matches_any_request() {
        let evidence = ready_evidence(
            7,
            vec![direct_grant(
                1,
                None,
                7,
                1,
                "*",
                "read",
                ValidityWindow::perpetual(),
            )],
        );
        assert!(match_published_effective_grant(
            &ctx(Some(1), None, Some(1), "learn_subject:42", "read"),
            &evidence,
            "learn_subject:42"
        )
        .is_some());
        assert!(match_published_effective_grant(
            &ctx(Some(1), None, Some(1), "approval", "read"),
            &evidence,
            "approval"
        )
        .is_some());
    }

    // ===== 身份/租户/domain 边界 =====

    #[test]
    fn identity_boundaries_are_enforced() {
        let evidence = ready_evidence(
            7,
            vec![direct_grant(
                1,
                None,
                7,
                1,
                "learn_subject:*",
                "read",
                ValidityWindow::perpetual(),
            )],
        );
        // user 不一致 → 不命中；请求不携带 user 一律不命中（与 engine 匹配器
        // 的 `is_none_or` 语义逐行一致：strict gate 的请求恒携带 user）。
        assert!(match_published_effective_grant(
            &ctx(Some(2), None, Some(1), "learn_subject:1", "read"),
            &evidence,
            "learn_subject:1"
        )
        .is_none());
        assert!(match_published_effective_grant(
            &ctx(None, None, Some(1), "learn_subject:1", "read"),
            &evidence,
            "learn_subject:1"
        )
        .is_none());
        // tenant 不一致 → 不命中。
        assert!(match_published_effective_grant(
            &ctx(Some(1), None, Some(2), "learn_subject:1", "read"),
            &evidence,
            "learn_subject:1"
        )
        .is_none());
        // card 不一致（证据属卡 7，请求卡 8）→ 不命中。
        let other_card_ctx = PolicyContext::builder()
            .user_id(Some(1))
            .card_id(Some(8))
            .tenant_id(Some(1))
            .resource(Some("learn_subject:1".to_string()))
            .action("read".to_string())
            .build();
        assert!(
            match_published_effective_grant(&other_card_ctx, &evidence, "learn_subject:1")
                .is_none()
        );
    }

    #[test]
    fn domain_boundary_is_enforced_when_request_carries_domain() {
        let domain_grant = direct_grant(
            1,
            Some(5),
            7,
            1,
            "learn_subject:*",
            "read",
            ValidityWindow::perpetual(),
        );
        let evidence = ready_evidence(7, vec![domain_grant]);
        // 请求携带同 domain → 命中。
        assert!(match_published_effective_grant(
            &ctx(Some(1), Some(5), Some(1), "learn_subject:1", "read"),
            &evidence,
            "learn_subject:1"
        )
        .is_some());
        // 请求携带不同 domain → 不命中。
        assert!(match_published_effective_grant(
            &ctx(Some(1), Some(6), Some(1), "learn_subject:1", "read"),
            &evidence,
            "learn_subject:1"
        )
        .is_none());
    }

    // ===== 有效期 / 动作匹配 =====

    #[test]
    fn validity_window_uses_evidence_read_clock() {
        let evidence = ready_evidence(
            7,
            vec![direct_grant(
                1,
                None,
                7,
                1,
                "learn_subject:*",
                "read",
                ValidityWindow::between(NOW - 100, NOW - 1),
            )],
        );
        // 已过期（以 evidence.read_unix_seconds 为唯一时钟）→ 不命中。
        assert!(match_published_effective_grant(
            &ctx(Some(1), None, Some(1), "learn_subject:1", "read"),
            &evidence,
            "learn_subject:1"
        )
        .is_none());
    }

    #[test]
    fn action_matching_supports_exact_alias_and_wildcard() {
        let evidence = ready_evidence(
            7,
            vec![direct_grant(
                1,
                None,
                7,
                1,
                "learn_subject:*",
                "write",
                ValidityWindow::perpetual(),
            )],
        );
        // write 别名展开：create/update/delete 请求可命中 write grant。
        for action in ["create", "update", "delete"] {
            assert!(
                match_published_effective_grant(
                    &ctx(Some(1), None, Some(1), "learn_subject:1", action),
                    &evidence,
                    "learn_subject:1"
                )
                .is_some(),
                "action {action} must match via write alias"
            );
        }
        assert!(match_published_effective_grant(
            &ctx(Some(1), None, Some(1), "learn_subject:1", "read"),
            &evidence,
            "learn_subject:1"
        )
        .is_none());

        // 通配动作 grant 命中任意请求动作。
        let wildcard = ready_evidence(
            7,
            vec![direct_grant(
                1,
                None,
                7,
                1,
                "learn_subject:*",
                "*",
                ValidityWindow::perpetual(),
            )],
        );
        assert!(match_published_effective_grant(
            &ctx(Some(1), None, Some(1), "learn_subject:1", "read"),
            &wildcard,
            "learn_subject:1"
        )
        .is_some());
    }
}
