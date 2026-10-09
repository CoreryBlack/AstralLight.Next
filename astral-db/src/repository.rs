//! SqlxRuleRepository — policy-engine 的 RuleRepository sqlx 实现
//!
//! 查询策略（读链切换批次 3 后）：
//! 1. 正式授权（strict gate）：`load_published_card_authorization` 读取
//!    Rust-owned published card evidence，不触碰 L1/L2/L2.5 读取器或任何
//!    raw/source/cache 回退。
//! 2. L2：`load_permission_rules` 已随 CARD 快照链退役（trait 保留，生产实现
//!    返回空集 fail-closed）；realtime oracle raw 读取器保留给一致性巡检，
//!    其 gate 只剩 source_generation/revoke_fence 版本栅栏（旧链状态列已
//!    随迁移 20260831000001 删除）。
//! 3. 旧 MAX(version_no) `load_rule_set_snapshots` 读取器及其 `perm:refs`
//!    cache-aside 载荷（RefsCacheWrapper）已随旧读链下线（trait 默认空集，
//!    引擎不消费）。
//! 4. 【读链切换批次 3.5】旧 L1 快照胜者读取器 `load_snapshot_winners`
//!    （JOIN 冻结的 rule_set_snapshot + RuleSet 依赖门禁）随规则集快照残役
//!    清理退役：trait 默认空集（fail-closed），引擎 strict/realtime 均不消费；
//!    `load_rule_set_dependency_statuses` 依赖门禁读取器同步退役（生产实现
//!    不再 override，trait 默认 `Ok(None)` 仅兼容 astral-cache 装饰器转发）。

use astral_types::org_scope::OrgAdmissionResult;
use astral_types::{PolicyContext, PublishedCardAuthorization, PublishedCardEvidenceScope};
use policy_engine::{
    OrgAuthorityRead, PermissionRule, ProjectionGate, RuleRepository, RuleSetEntry, RuleSetSnapshot,
};
use sqlx::MySqlPool;
use time::{Duration, OffsetDateTime, PrimitiveDateTime};

use crate::eligibility::CardEligibilityService;
use crate::org_scope_repository::{
    probe_org_scope_gate, OrgAdmissionQuery, OrgScopeGateState, OrgScopeRepository,
    SqlxOrgScopeRepository,
};

/// 数据库操作错误
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("Database query failed: {0}")]
    Query(#[from] sqlx::Error),

    #[error("Row mapping failed: {0}")]
    Mapping(String),
}

/// sqlx 实现的 RuleRepository
pub struct SqlxRuleRepository {
    pool: MySqlPool,
    /// Default-off ORG_SCOPE admission switch, frozen by the process that constructs
    /// this repository. A managed tenant remains fail-closed when this is false.
    org_scope_enabled: bool,
}

impl SqlxRuleRepository {
    /// Creates a production repository with ORG_SCOPE admission disabled.
    ///
    /// Call [`Self::with_org_scope_enabled`] only after the hosting process has
    /// parsed its deployment configuration successfully. Keeping the default
    /// disabled means a managed tenant cannot silently fall back to legacy card
    /// evidence in a service that has not opted into the organization runtime.
    pub fn new(pool: MySqlPool) -> Self {
        Self {
            pool,
            org_scope_enabled: false,
        }
    }

    /// Freezes the deployment-approved ORG_SCOPE admission state into this
    /// repository instance. This is deliberately not read from the environment
    /// on each authorization request.
    pub fn with_org_scope_enabled(mut self, enabled: bool) -> Self {
        self.org_scope_enabled = enabled;
        self
    }

    /// 从环境变量 `DATABASE_URL` 创建连接池
    pub async fn from_env() -> Result<Self, sqlx::Error> {
        let url = std::env::var("DATABASE_URL").map_err(|_| {
            sqlx::Error::Configuration(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "DATABASE_URL is required",
            )))
        })?;
        let pool = crate::connect_configured_pool(&url).await?;
        Ok(Self::new(pool))
    }
}

/// Predicate used by user-facing audit views. Internal scheduler lifecycle
/// evidence remains durable and queryable by its event type, but must not be
/// counted as a user request or authorization audit entry.
pub const USER_VISIBLE_AUDIT_PREDICATE: &str = "decision <> 'INTERNAL'";

fn user_visible_audit_from_clause() -> String {
    format!("FROM audit_log WHERE {USER_VISIBLE_AUDIT_PREDICATE}")
}

/// 运行期物理双卡资格校验所需的最小上下文。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CardActiveContext {
    pub user_id: i64,
    pub identity_card_id: i64,
    pub user_card_id: i64,
    pub user_card_tenant_id: i64,
    pub user_card_domain_id: i64,
}

impl CardActiveContext {
    pub(crate) fn is_positive(&self) -> bool {
        self.user_id > 0
            && self.identity_card_id > 0
            && self.user_card_id > 0
            && self.user_card_tenant_id > 0
            && self.user_card_domain_id > 0
    }
}

fn projection_gate_from_row(row: Option<(i64, i64)>) -> ProjectionGate {
    match row {
        // 旧链状态列（projected_generation/projection_status）已退役（迁移
        // 20260831000001）：ready 语义收敛为"投影通道存在且至少有一个事件"。
        // CARD 消费权威在新链 pointer/manifest；本 gate 保留 source_generation
        // + revoke_fence 作为 ALLOW 复检与一致性巡检的版本栅栏。
        Some((source_generation, revoke_fence)) => ProjectionGate {
            ready: source_generation > 0,
            source_generation,
            revoke_fence,
        },
        None => ProjectionGate {
            ready: false,
            source_generation: 0,
            revoke_fence: 0,
        },
    }
}

/// 读取卡片投影版本栅栏。head 缺失（ready=false）由引擎统一返回
/// AUTHORIZATION_PENDING；查询失败必须向上游暴露。
async fn load_projection_gate(
    pool: &MySqlPool,
    card_id: i64,
) -> Result<Option<ProjectionGate>, astral_types::PolicyError> {
    let row: Option<(i64, i64)> = sqlx::query_as(
        "SELECT source_generation, revoke_fence \
         FROM authorization_projection_head \
         WHERE aggregate_type = 'CARD' AND aggregate_id = ?",
    )
    .bind(card_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| astral_types::PolicyError::Repository(e.to_string()))?;

    Ok(Some(projection_gate_from_row(row)))
}

/// Map the strict published-card evidence error vocabulary onto EXISTING
/// `PolicyError` variants without ever inventing an "empty result" success.
///
/// Every variant keeps a stable family code prefix so callers can classify
/// pending vs. corrupt vs. transport failure from the message alone, while the
/// reader's own `code=published_card_evidence.*` fragments are preserved
/// verbatim for audit correlation. NotReady/Corrupt/Query map onto
/// `Repository` (PENDING/DENY semantics upstream); InvalidRequest is a caller
/// contract fault and maps onto `InvalidContext`.
fn published_card_evidence_error_to_policy_error(
    error: crate::authorization_projection_repository::AuthorizationEvidenceError,
) -> astral_types::PolicyError {
    use crate::authorization_projection_repository::AuthorizationEvidenceError as EvidenceError;
    match error {
        EvidenceError::NotReady(message) => astral_types::PolicyError::Repository(format!(
            "published_card_evidence_not_ready;{message}"
        )),
        EvidenceError::Corrupt(message) => astral_types::PolicyError::Repository(format!(
            "published_card_evidence_corrupt;{message}"
        )),
        EvidenceError::InvalidRequest(message) => astral_types::PolicyError::InvalidContext(
            format!("published_card_evidence_invalid_request;{message}"),
        ),
        EvidenceError::Query(query) => astral_types::PolicyError::Repository(format!(
            "published_card_evidence_query_failed;{query}"
        )),
    }
}

fn projection_is_readable(gate: Option<&ProjectionGate>) -> bool {
    gate.is_some_and(|gate| gate.ready && gate.source_generation > 0)
}

fn unix_now_seconds() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// 运行期物理双卡校验，带时间感知资格缓存（委托 `CardEligibilityService`）。
///
/// PolicyEngine 的 CARD_CONTEXT 只负责校验物理双卡事实；正式授权读取
/// 仍由 CARD projection gate 独立门禁。因此默认不要求 ELIGIBILITY head READY，
/// 以兼容尚未建立资格投影的历史卡；授权 gate 未 READY 时仍由引擎拒绝。
pub async fn check_card_active_cached(
    pool: &MySqlPool,
    context: &CardActiveContext,
) -> Result<bool, astral_types::PolicyError> {
    check_card_active_cached_with_options(pool, context, 300, 60, false).await
}

/// 物理卡校验的可配置入口。Chat 使用更短 TTL 并要求投影 READY；PolicyEngine
/// 使用默认参数，以便由引擎自身返回 AUTHORIZATION_PENDING。
///
/// 投影门禁使用 ELIGIBILITY head（`authorization_projection_head` 中
/// `aggregate_type='ELIGIBILITY'`）；head 缺失或未 READY 时按配置拒绝。
pub async fn check_card_active_cached_with_options(
    pool: &MySqlPool,
    context: &CardActiveContext,
    base_ttl_seconds: u64,
    jitter_max_seconds: u64,
    require_projection_ready: bool,
) -> Result<bool, astral_types::PolicyError> {
    CardEligibilityService::check_cached(
        pool,
        context,
        astral_types::CardEligibilityCheckOptions {
            base_ttl_seconds,
            jitter_max_seconds,
            require_projection_ready,
        },
    )
    .await
}

fn parse_condition_json(
    condition_json: Option<String>,
) -> Result<Option<serde_json::Value>, astral_types::PolicyError> {
    condition_json
        .map(|json| {
            serde_json::from_str(&json).map_err(|error| {
                astral_types::PolicyError::Repository(format!("malformed condition_json: {error}"))
            })
        })
        .transpose()
}

#[async_trait::async_trait]
impl RuleRepository for SqlxRuleRepository {
    /// 生产 repository：正式授权必须走 Rust-owned published evidence strict
    /// gate。`PolicyEngine.evaluate()` 据此在 AUTHN/CARD_CONTEXT 之后读取
    /// [`RuleRepository::load_published_card_authorization`]，并且该请求不再
    /// 触碰 L1/L2/L2.5 读取器或任何 raw/source/cache 回退。
    fn requires_published_card_evidence(&self) -> bool {
        true
    }

    async fn load_org_authorization(
        &self,
        ctx: &PolicyContext,
    ) -> Result<OrgAuthorityRead, astral_types::PolicyError> {
        let (Some(tenant_id), Some(user_id), Some(identity_card_id), Some(card_id)) = (
            ctx.tenant_id,
            ctx.user_id,
            ctx.identity_card_id,
            ctx.card_id,
        ) else {
            return Ok(OrgAuthorityRead::Pending {
                code: "org_scope.pending.context_missing".to_owned(),
            });
        };

        match probe_org_scope_gate(&self.pool, tenant_id).await {
            OrgScopeGateState::SchemaUnmanaged | OrgScopeGateState::TenantUnmanaged => {
                Ok(OrgAuthorityRead::Unmanaged)
            }
            OrgScopeGateState::Pending => Ok(OrgAuthorityRead::Unavailable {
                code: "org_scope.pending.gate_unavailable".to_owned(),
            }),
            OrgScopeGateState::TenantManaged { .. } if !self.org_scope_enabled => {
                Ok(OrgAuthorityRead::Disabled)
            }
            OrgScopeGateState::TenantManaged { .. } => {
                let org_repository = SqlxOrgScopeRepository::new(self.pool.clone());
                let query = OrgAdmissionQuery {
                    tenant_id,
                    user_id,
                    card_id,
                    identity_card_id: Some(identity_card_id),
                    now_unix_seconds: unix_now_seconds(),
                };
                match org_repository.load_admission_evidence(&query).await {
                    Ok(OrgAdmissionResult::Evidence(evidence)) => {
                        Ok(OrgAuthorityRead::Ready(evidence))
                    }
                    Ok(OrgAdmissionResult::Pending { code, .. }) => Ok(OrgAuthorityRead::Pending {
                        code: code.as_machine_code().to_owned(),
                    }),
                    Err(error) => {
                        tracing::warn!(
                            tenant_id,
                            user_id,
                            card_id,
                            error = %error,
                            "org scope evidence read unavailable; failing closed"
                        );
                        Ok(OrgAuthorityRead::Unavailable {
                            code: "org_scope.pending.reader_unavailable".to_owned(),
                        })
                    }
                }
            }
        }
    }

    /// 检查卡片上下文是否有效（含状态/用户/有效期交叉校验）。
    ///
    /// 物理双卡校验与时间感知缓存统一由共享 helper 承担，避免 Chat
    /// WebSocket 和 PolicyEngine 各自维护一套资格 SQL。
    async fn check_card_active(
        &self,
        ctx: &PolicyContext,
    ) -> Result<bool, astral_types::PolicyError> {
        let Some(user_id) = ctx.user_id else {
            return Ok(false);
        };
        let Some(identity_card_id) = ctx.identity_card_id else {
            return Ok(false);
        };
        let Some(user_card_id) = ctx.card_id else {
            return Ok(false);
        };
        let Some(user_card_tenant_id) = ctx.tenant_id else {
            return Ok(false);
        };
        let Some(user_card_domain_id) = ctx.domain_id else {
            return Ok(false);
        };
        check_card_active_cached(
            &self.pool,
            &CardActiveContext {
                user_id,
                identity_card_id,
                user_card_id,
                user_card_tenant_id,
                user_card_domain_id,
            },
        )
        .await
    }

    /// Global control-plane authority is source-of-truth state, not a card
    /// grant or a cached management-scope convenience. This deliberately bypasses
    /// TrustGraph's five-second handler cache so a formal policy decision observes
    /// an ACTIVE row at both the ownership gate and its final ALLOW recheck.
    async fn is_active_global_admin(
        &self,
        user_id: i64,
    ) -> Result<bool, astral_types::PolicyError> {
        if user_id <= 0 {
            return Ok(false);
        }
        crate::is_active_global_admin(&self.pool, user_id)
            .await
            .map_err(|error| {
                astral_types::PolicyError::Repository(format!(
                    "global_admin_gate_query_failed;{error}"
                ))
            })
    }

    async fn load_permission_rules(
        &self,
        card_id: i64,
    ) -> Result<Vec<PermissionRule>, astral_types::PolicyError> {
        // 【读链切换批次 3.5 + 20260831000001 退役】CARD 快照读取器随
        // permission_rule_snapshot 表删除退役；旧实现受 head READY 门禁保护，
        // 但 worker 退役后 head 永不 READY，任何可达调用方的有效行为都是
        // 空集。生产实现固定返回空集（fail-closed），正式授权读取只走
        // `load_published_card_authorization`，原始表巡检走
        // `load_permission_rules_raw`。
        let _ = card_id;
        Ok(vec![])
    }

    // 【读链切换批次 3.5 退役】旧 L1 快照胜者读取器 `load_snapshot_winners`
    // （JOIN 冻结表 rule_set_snapshot + RuleSet 依赖门禁）不再由本仓库实现：
    // trait 默认空集 fail-closed，strict 生产路径与 realtime raw oracle 均不消费。

    /// 一致性检查专用：加载原始 rule_set_entry（跳过快照表）
    async fn load_rule_set_entries_raw(
        &self,
        card_id: i64,
    ) -> Result<Vec<RuleSetSnapshot>, astral_types::PolicyError> {
        #[derive(Debug, sqlx::FromRow)]
        struct RawEntryRow {
            rule_set_id: i64,
            ref_type: String,
            effect: String,
            resource_type: Option<String>,
            resource_id: Option<i64>,
            action_code: Option<String>,
            condition_json: Option<String>,
        }

        let rows = sqlx::query_as::<_, RawEntryRow>(
            "SELECT crs.rule_set_id, crs.ref_type, \
                    rse.effect, rse.resource_type, rse.resource_id, rse.action_code, rse.condition_json \
             FROM card_rule_set_ref crs \
             JOIN rule_set_entry rse ON rse.rule_set_id = crs.rule_set_id \
             WHERE crs.card_id = ? AND rse.enabled = 1 \
               AND (rse.valid_from IS NULL OR rse.valid_from <= UTC_TIMESTAMP()) \
               AND (rse.valid_to IS NULL OR rse.valid_to >= UTC_TIMESTAMP()) \
             ORDER BY crs.ref_type, rse.priority DESC, rse.effect DESC",
        )
        .bind(card_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| astral_types::PolicyError::Repository(e.to_string()))?;

        let mut snapshots: std::collections::BTreeMap<i64, RuleSetSnapshot> =
            std::collections::BTreeMap::new();
        for r in &rows {
            let condition = parse_condition_json(r.condition_json.clone())?;
            let entry = RuleSetEntry {
                effect: match r.effect.as_str() {
                    "ALLOW" => astral_types::Effect::Allow,
                    "DENY" => astral_types::Effect::Deny,
                    _ => astral_types::Effect::NotMatch,
                },
                resource: r
                    .resource_type
                    .as_ref()
                    .map(|resource| match r.resource_id {
                        Some(id) => format!("{resource}:{id}"),
                        None => format!("{resource}:*"),
                    }),
                action: r.action_code.clone(),
                condition,
            };
            snapshots
                .entry(r.rule_set_id)
                .or_insert_with(|| RuleSetSnapshot {
                    rule_set_id: r.rule_set_id,
                    ref_type: r.ref_type.clone(),
                    entries: vec![],
                })
                .entries
                .push(entry);
        }

        Ok(snapshots.into_values().collect())
    }

    /// 一致性检查专用：加载原始 permission_rule（跳过快照表和 permission_rule_snapshot）
    async fn load_permission_rules_raw(
        &self,
        card_id: i64,
    ) -> Result<Vec<PermissionRule>, astral_types::PolicyError> {
        // 等同于 load_permission_rules 但不查 permission_rule_snapshot
        // 对齐 Java evaluateRules：单查询候选集（对象+类型）+ priority DESC, effect DESC
        // + valid 窗口 + MANUAL/DELEGATION；resource_id 保留对象级粒度
        let rows = sqlx::query_as::<_, PermissionRuleRow>(
            "SELECT pr.rule_id, pr.effect, pr.resource_type, pr.resource_id, pr.action_code, pr.condition_json \
             FROM permission_rule pr \
             WHERE pr.card_id = ? AND pr.source_type IN ('MANUAL', 'DELEGATION') AND pr.enabled = 1 \
               AND (pr.valid_from IS NULL OR pr.valid_from <= UTC_TIMESTAMP()) \
               AND (pr.valid_to IS NULL OR pr.valid_to >= UTC_TIMESTAMP()) \
             ORDER BY pr.priority DESC, pr.effect DESC",
        )
        .bind(card_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| astral_types::PolicyError::Repository(e.to_string()))?;

        let rules = rows
            .into_iter()
            .map(|r| {
                let condition = parse_condition_json(r.condition_json)?;
                Ok(PermissionRule {
                    id: r.rule_id,
                    effect: match r.effect.as_str() {
                        "ALLOW" => astral_types::Effect::Allow,
                        "DENY" => astral_types::Effect::Deny,
                        _ => astral_types::Effect::NotMatch,
                    },
                    resource: match r.resource_id {
                        Some(id) => format!("{}:{id}", r.resource_type),
                        None => r.resource_type,
                    },
                    action: r.action_code,
                    condition,
                })
            })
            .collect::<Result<Vec<_>, astral_types::PolicyError>>()?;

        Ok(rules)
    }

    /// Raw delegation reader retained exclusively for realtime/consistency
    /// checks. Formal PolicyEngine evaluation uses the projected method below.
    async fn load_delegated_rules(
        &self,
        delegate_id: i64,
        resource: &str,
        action: &str,
    ) -> Result<Vec<PermissionRule>, astral_types::PolicyError> {
        let gate = self.get_projection_gate(delegate_id).await?;
        if !projection_is_readable(gate.as_ref()) {
            return Ok(vec![]);
        }

        let rows = sqlx::query_as::<_, PermissionRuleRow>(
            "SELECT d.delegation_id as rule_id, 'ALLOW' as effect, d.resource_type, NULL as resource_id, d.action_code, NULL as condition_json              FROM permission_delegation d              WHERE d.delegate_card_id = ?                AND d.status = 'ACTIVE'                AND (d.effective_from IS NULL OR d.effective_from <= UTC_TIMESTAMP())                AND (d.effective_until IS NULL OR d.effective_until > UTC_TIMESTAMP())                AND (d.resource_type = ? OR d.resource_type = '*' OR d.resource_type LIKE CONCAT(?, ':%'))                AND (d.action_code = ? OR d.action_code = '*')              ORDER BY d.delegation_id",
        )
        .bind(delegate_id)
        .bind(resource)
        .bind(resource)
        .bind(action)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| astral_types::PolicyError::Repository(e.to_string()))?;

        rows.into_iter()
            .map(|r| {
                let condition = parse_condition_json(r.condition_json)?;
                Ok(PermissionRule {
                    id: r.rule_id,
                    effect: match r.effect.as_str() {
                        "ALLOW" => astral_types::Effect::Allow,
                        "DENY" => astral_types::Effect::Deny,
                        _ => astral_types::Effect::NotMatch,
                    },
                    resource: r.resource_type,
                    action: r.action_code,
                    condition,
                })
            })
            .collect()
    }

    /// L2.5 formal authorization reader.
    ///
    /// The current CARD snapshot does not retain enough source provenance to
    /// distinguish a delegation row from a manual CARD_ONLY row without joining
    /// `permission_rule`. Formal authorization must not perform that raw-source
    /// join. L2 already consumes the generation-gated CARD snapshot, so the
    /// safe interim behavior is an explicit fail-closed result here; a future
    /// delegation-owned projection can replace this without widening access.
    async fn load_projected_delegated_rules(
        &self,
        _delegate_id: i64,
        _resource: &str,
        _action: &str,
    ) -> Result<Vec<PermissionRule>, astral_types::PolicyError> {
        Err(astral_types::PolicyError::Repository(
            "delegation projection provenance is unavailable; formal delegation read denied".into(),
        ))
    }

    /// 投影门禁（对齐 Java AuthorizationReadPort.getCardProjectionStatus）。
    ///
    /// 总是返回显式状态；缺失 head 表示 `ready=false`，由引擎返回 AUTHORIZATION_PENDING。
    async fn get_projection_gate(
        &self,
        card_id: i64,
    ) -> Result<Option<ProjectionGate>, astral_types::PolicyError> {
        load_projection_gate(&self.pool, card_id).await
    }

    /// Published-card read port — a formal authorization input, not a shadow
    /// read: strict Rust-owned published-card evidence reader
    /// ([`crate::authorization_projection_repository::load_published_card_grant_evidence`])
    /// exposed through one short transaction that commits explicitly before
    /// returning (locks never outlive the call).
    ///
    /// - Scope (tenant/card/user_filter/domain lens) is passed through
    ///   unchanged; no hash/UUID/manifest verification is duplicated here and
    ///   no legacy snapshot / raw source / cache fallback exists on this path.
    /// - Every `AuthorizationEvidenceError` maps to an explicit `PolicyError`
    ///   — never to an empty grant collection and never swallowed into
    ///   success.
    /// - On success this production implementation always returns
    ///   `Some(evidence)` with a Ready gate; `Ok(None)` stays reserved for the
    ///   legacy/test default on the trait.
    ///
    /// `PolicyEngine.evaluate()` consumes this port formally whenever
    /// [`RuleRepository::requires_published_card_evidence`] is true (this
    /// repository reports true, so strict-gate evaluations read this port and
    /// skip the L1/L2/L2.5 readers); real MySQL integration testing remains a
    /// later gate.
    async fn load_published_card_authorization(
        &self,
        scope: &PublishedCardEvidenceScope,
    ) -> Result<Option<PublishedCardAuthorization>, astral_types::PolicyError> {
        crate::authorization_projection_repository::load_published_card_grant_evidence(
            &self.pool, scope,
        )
        .await
        .map(Some)
        .map_err(published_card_evidence_error_to_policy_error)
    }
}

// ===== 模块级公共函数（非 trait 方法，供各业务模块直接调用） =====

/// Canonical token family row. `family_id` is the BIGINT storage PK and
/// `family_key` is the unique opaque key supplied by the caller.
#[derive(Debug, sqlx::FromRow)]
pub struct TokenFamilyRow {
    pub family_id: i64,
    pub user_id: i64,
    pub family_key: String,
    pub status: String,
    pub issued_at: time::PrimitiveDateTime,
    pub expires_at: Option<time::PrimitiveDateTime>,
    pub revoked_at: Option<time::PrimitiveDateTime>,
    pub revoked_reason: Option<String>,
    pub metadata_json: Option<String>,
}

/// 查询用户所有 ACTIVE 卡片 ID
pub async fn find_active_cards_by_user(
    pool: &MySqlPool,
    user_id: i64,
) -> Result<Vec<i64>, DbError> {
    let rows = sqlx::query_as::<_, (i64,)>(
        "SELECT card_id FROM user_card WHERE user_id = ? AND card_status = 'ACTIVE'          AND (valid_from IS NULL OR valid_from <= NOW())          AND (valid_until IS NULL OR valid_until >= NOW())"
    ).bind(user_id).fetch_all(pool).await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

/// 查询 token family（按 BIGINT family_id 主键查询）。
pub async fn find_token_family(
    pool: &MySqlPool,
    family_id: i64,
) -> Result<Option<TokenFamilyRow>, DbError> {
    Ok(sqlx::query_as::<_, TokenFamilyRow>(
        "SELECT family_id, user_id, family_key, status, issued_at, expires_at, revoked_at, revoked_reason, metadata_json \
         FROM auth_token_family WHERE family_id = ?",
    )
    .bind(family_id)
    .fetch_optional(pool)
    .await?)
}

/// 创建 token family；插入 family_key 并返回 BIGINT LAST_INSERT_ID。
pub async fn create_token_family(
    pool: &MySqlPool,
    family_key: &str,
    user_id: i64,
) -> Result<i64, DbError> {
    let now = OffsetDateTime::now_utc();
    let expires_at = PrimitiveDateTime::new(
        (now + Duration::days(30)).date(),
        (now + Duration::days(30)).time(),
    );
    let result = sqlx::query(
        "INSERT INTO auth_token_family \
         (user_id, family_key, status, issued_at, expires_at) \
         VALUES (?, ?, 'ACTIVE', UTC_TIMESTAMP(), ?)",
    )
    .bind(user_id)
    .bind(family_key)
    .bind(expires_at)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 || result.last_insert_id() == 0 {
        return Err(DbError::Mapping(
            "token family was not durably created".into(),
        ));
    }
    Ok(result.last_insert_id() as i64)
}

/// 撤销整个 token family（按 BIGINT family_id 主键定位）。
pub async fn revoke_token_family(
    pool: &MySqlPool,
    family_id: i64,
    reason: &str,
) -> Result<(), DbError> {
    sqlx::query("UPDATE auth_token_family SET status = 'REVOKED', revoked_at = CURRENT_TIMESTAMP, revoked_reason = ? WHERE family_id = ? AND status = 'ACTIVE'")
        .bind(reason).bind(family_id).execute(pool).await?;
    Ok(())
}

// 插入审计日志到 DB
pub async fn insert_audit_log(
    pool: &MySqlPool,
    entry: &astral_common::audit::AuditEntry,
) -> Result<(), DbError> {
    let event_type_str = serde_json::to_value(&entry.event_type)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default();

    sqlx::query(
        "INSERT INTO audit_log (user_id, card_id, action, resource, decision, reason, event_type, source_ip, request_id, domain_id, tenant_id, detail) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
        .bind(entry.user_id)
        .bind(entry.card_id)
        .bind(&entry.action)
        .bind(&entry.resource)
        .bind(&entry.decision)
        .bind(&entry.reason)
        .bind(&event_type_str)
        .bind(&entry.source_ip)
        .bind(&entry.request_id)
        .bind(entry.domain_id)
        .bind(entry.tenant_id)
        .bind(&entry.detail)
        .execute(pool)
        .await?;
    Ok(())
}

/// 权限决策审计（fire-and-forget，对齐 Java `AuditService.record(PolicyContext, PolicyDecision)`）
///
/// 各服务权限中间件在每个判定（ALLOW/DENY）后调用；DB 写入失败仅记 warning 不阻塞
/// 主请求（审计非关键路径，决策本身已 fail-closed）。
#[allow(clippy::too_many_arguments)]
pub async fn record_permission_audit(
    pool: &MySqlPool,
    user_id: Option<i64>,
    card_id: Option<i64>,
    domain_id: Option<i64>,
    resource: &str,
    action: &str,
    allowed: bool,
    reason: &str,
    path: &str,
) {
    let entry = astral_common::audit::AuditEntry {
        user_id,
        card_id,
        action: action.to_string(),
        resource: resource.to_string(),
        decision: if allowed {
            "ALLOW".into()
        } else {
            "DENY".into()
        },
        reason: Some(reason.to_string()),
        event_type: astral_common::audit::AuditEventType::PermissionCheck,
        category: Some(astral_common::audit::AuditCategory::Permission),
        source_ip: None,
        request_id: None,
        domain_id,
        tenant_id: None,
        detail: Some(path.to_string()),
    };
    if let Err(e) = insert_audit_log(pool, &entry).await {
        tracing::warn!(error = %e, "permission audit insert failed");
    }
}

/// ALLOW 命中统计落库（fire-and-forget，对齐 Java：ALLOW 命中异步写入 permission_hit_stat）。
/// `rule_source` 使用 canonical 来源值：RULE_SET / PERMISSION_RULE / DELEGATION / TEMPLATE；DB 不可用仅记 debug。
pub async fn record_permission_hit(
    pool: &MySqlPool,
    card_id: i64,
    resource_type: &str,
    action_code: &str,
    rule_source: Option<&str>,
) {
    if let Err(e) =
        upsert_permission_hit_stat(pool, card_id, resource_type, action_code, rule_source).await
    {
        tracing::debug!(card_id, resource = resource_type, action = action_code, error = %e, "hit stat upsert failed");
    }
}

/// 查询会话成员 ID 列表（对齐 platform_v4：chat_conversation_member）
pub async fn find_session_member_ids(
    pool: &MySqlPool,
    conversation_id: i64,
) -> Result<Vec<i64>, DbError> {
    let rows = sqlx::query_as::<_, (i64,)>(
        "SELECT user_id FROM chat_conversation_member WHERE conversation_id = ?",
    )
    .bind(conversation_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

/// 更新会话最后消息（对齐 platform_v4：chat_conversation，last_message_time）
pub async fn update_session_last_message(
    pool: &MySqlPool,
    conversation_id: i64,
    message_id: i64,
) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE chat_conversation SET last_message_id = ?, last_message_time = NOW() WHERE id = ?",
    )
    .bind(message_id)
    .bind(conversation_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// 用户 MFA 配置行
#[derive(Debug, sqlx::FromRow)]
pub struct UserMfaRow {
    pub id: Option<i64>,
    pub user_id: i64,
    pub mfa_type: String,
    pub secret_enc: Option<Vec<u8>>,
    pub phone: Option<String>,
    pub email: Option<String>,
    pub is_enabled: i32,
    pub is_primary: i32,
    pub backup_codes_hash: Option<String>,
    pub backup_codes_used: i32,
    pub verified_at: Option<time::PrimitiveDateTime>,
    pub last_used_at: Option<time::PrimitiveDateTime>,
    pub last_totp_counter: Option<i64>,
}

/// 查询用户 MFA 配置
pub async fn find_user_mfa(
    pool: &MySqlPool,
    user_id: i64,
    mfa_type: &str,
) -> Result<Option<UserMfaRow>, DbError> {
    let row = sqlx::query_as::<_, UserMfaRow>(
        "SELECT id, user_id, mfa_type, secret_enc, phone, email, is_enabled, is_primary, \
         backup_codes_hash, backup_codes_used, verified_at, last_used_at, last_totp_counter \
         FROM user_mfa WHERE user_id = ? AND mfa_type = ?",
    )
    .bind(user_id)
    .bind(mfa_type)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// 查询用户所有已启用的 MFA 配置
pub async fn find_enabled_mfa_for_user(
    pool: &MySqlPool,
    user_id: i64,
) -> Result<Vec<UserMfaRow>, DbError> {
    let rows = sqlx::query_as::<_, UserMfaRow>(
        "SELECT id, user_id, mfa_type, secret_enc, phone, email, is_enabled, is_primary, \
         backup_codes_hash, backup_codes_used, verified_at, last_used_at, last_totp_counter \
         FROM user_mfa WHERE user_id = ? AND is_enabled = 1",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// 创建或更新用户 MFA 配置
pub async fn upsert_user_mfa(
    pool: &MySqlPool,
    user_id: i64,
    mfa_type: &str,
    secret_enc: Option<&[u8]>,
    backup_codes_hash: Option<&str>,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO user_mfa (user_id, mfa_type, secret_enc, backup_codes_hash, is_enabled, is_primary) \
         VALUES (?, ?, ?, ?, 1, 1) \
         ON DUPLICATE KEY UPDATE secret_enc = VALUES(secret_enc), backup_codes_hash = VALUES(backup_codes_hash), \
         is_enabled = 1, backup_codes_used = 0, updated_at = CURRENT_TIMESTAMP"
    )
        .bind(user_id)
        .bind(mfa_type)
        .bind(secret_enc)
        .bind(backup_codes_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Stage a factor disabled; possession must be proven through the authenticated
/// verification route before it becomes an MFA login requirement.
pub async fn stage_user_mfa(
    pool: &MySqlPool,
    user_id: i64,
    mfa_type: &str,
    secret_enc: Option<&[u8]>,
    backup_codes_hash: Option<&str>,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO user_mfa (user_id, mfa_type, secret_enc, backup_codes_hash, is_enabled, is_primary, backup_codes_used, last_totp_counter) \
         VALUES (?, ?, ?, ?, 0, 0, 0, NULL) \
         ON DUPLICATE KEY UPDATE secret_enc = VALUES(secret_enc), \
         backup_codes_hash = VALUES(backup_codes_hash), is_enabled = 0, \
         backup_codes_used = 0, verified_at = NULL, last_totp_counter = NULL, \
         updated_at = CURRENT_TIMESTAMP",
    )
    .bind(user_id)
    .bind(mfa_type)
    .bind(secret_enc)
    .bind(backup_codes_hash)
    .execute(pool)
    .await?;
    Ok(())
}

/// Activate a staged TOTP factor only after its first, unused counter is proven.
pub async fn activate_pending_totp(
    pool: &MySqlPool,
    user_id: i64,
    counter: i64,
) -> Result<bool, DbError> {
    let result = sqlx::query(
        "UPDATE user_mfa SET is_enabled = 1, is_primary = 1, verified_at = CURRENT_TIMESTAMP, \
         last_totp_counter = ?, last_used_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP \
         WHERE user_id = ? AND mfa_type = 'TOTP' AND is_enabled = 0 \
           AND secret_enc IS NOT NULL AND (last_totp_counter IS NULL OR last_totp_counter < ?)",
    )
    .bind(counter)
    .bind(user_id)
    .bind(counter)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Disable user MFA
pub async fn disable_user_mfa(
    pool: &MySqlPool,
    user_id: i64,
    mfa_type: &str,
) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE user_mfa SET is_enabled = 0, secret_enc = NULL, backup_codes_hash = NULL, \
         updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND mfa_type = ?",
    )
    .bind(user_id)
    .bind(mfa_type)
    .execute(pool)
    .await?;
    Ok(())
}

/// 递增备份码使用计数并更新最后使用时间
pub async fn mark_mfa_used(pool: &MySqlPool, user_id: i64, mfa_type: &str) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE user_mfa SET backup_codes_used = backup_codes_used + 1, last_used_at = CURRENT_TIMESTAMP \
         WHERE user_id = ? AND mfa_type = ?"
    )
        .bind(user_id)
        .bind(mfa_type)
        .execute(pool)
        .await?;
    Ok(())
}

/// 插入 MFA 尝试日志
pub async fn insert_mfa_attempt(
    pool: &MySqlPool,
    user_id: i64,
    mfa_type: &str,
    success: bool,
    ip: Option<&str>,
    failure_reason: Option<&str>,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO mfa_attempt_log (user_id, mfa_type, success, ip, failure_reason) VALUES (?, ?, ?, ?, ?)"
    )
        .bind(user_id)
        .bind(mfa_type)
        .bind(success as i32)
        .bind(ip)
        .bind(failure_reason)
        .execute(pool)
        .await?;
    Ok(())
}

/// 统计最近 N 分钟内的 MFA 失败次数
pub async fn count_recent_mfa_failures(
    pool: &MySqlPool,
    user_id: i64,
    window_minutes: i32,
) -> Result<i32, DbError> {
    let row: (i32,) = sqlx::query_as(
        "SELECT COUNT(*) FROM mfa_attempt_log \
         WHERE user_id = ? AND success = 0 AND status IN ('FAILED', 'PENDING') \
           AND attempted_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? MINUTE)",
    )
    .bind(user_id)
    .bind(window_minutes)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

// ===== 内部行类型映射 =====

#[derive(Debug, sqlx::FromRow)]
struct PermissionRuleRow {
    rule_id: i64,
    effect: String,
    resource_type: String,
    resource_id: Option<i64>,
    action_code: String,
    condition_json: Option<String>,
}

// ===== I-4: 规则集/SoD/命中统计 Repository 函数（对齐 Java Mapper 层）=====
//
// Java 基线对照:
// - RuleSetMapper: AstralGeneral/.../mapper/RuleSetMapper.java
// - SodPolicyMapper: AstralGeneral/.../mapper/SodPolicyMapper.java
// - PermissionDelegationMapper: AstralGeneral/.../mapper/PermissionDelegationMapper.java

use astral_types::{PermissionHitStat, RuleSet as DbRuleSet, RuleSetEntry as DbRuleSetEntry};

/// 查询所有活跃规则集
/// Java 对照: RuleSetMapper.selectAll()
pub async fn find_rule_sets(pool: &MySqlPool) -> Result<Vec<DbRuleSet>, DbError> {
    let rows = sqlx::query_as::<_, RuleSetRow>(
        "SELECT rule_set_id, name, description, source_type, enabled, \
         UNIX_TIMESTAMP(created_at) as created_at, UNIX_TIMESTAMP(updated_at) as updated_at \
         FROM rule_set WHERE enabled = 1 ORDER BY rule_set_id",
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| DbRuleSet {
            id: Some(r.rule_set_id),
            name: r.name,
            ref_type: r.source_type,
            description: r.description,
            is_active: r.enabled != 0,
            version: 0,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
        .collect())
}

/// 查询规则集的所有条目
/// Java 对照: RuleSetEntryMapper.selectByRuleSetId()
pub async fn find_rule_set_entries(
    pool: &MySqlPool,
    rule_set_id: i64,
) -> Result<Vec<DbRuleSetEntry>, DbError> {
    let rows = sqlx::query_as::<_, RuleSetEntryRow>(
        "SELECT entry_id, rule_set_id, effect, resource_type, resource_id, action_code, condition_json, priority, \
         UNIX_TIMESTAMP(created_at) as created_at \
         FROM rule_set_entry WHERE rule_set_id = ? ORDER BY priority DESC"
    )
        .bind(rule_set_id)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .into_iter()
        .map(|r| DbRuleSetEntry {
            id: Some(r.entry_id),
            rule_set_id: r.rule_set_id,
            effect: r.effect,
            resource: r
                .resource_type
                .as_ref()
                .map(|resource| match r.resource_id {
                    Some(id) => format!("{resource}:{id}"),
                    None => format!("{resource}:*"),
                }),
            action: r.action_code,
            condition_json: r.condition_json,
            priority: r.priority,
            created_at: r.created_at,
        })
        .collect())
}

/// 记录权限命中统计（upsert）
/// Java 对照: PermissionHitStatMapper.upsert()
pub async fn upsert_permission_hit_stat(
    pool: &MySqlPool,
    card_id: i64,
    resource_type: &str,
    action_code: &str,
    rule_source: Option<&str>,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO permission_hit_stat (card_id, resource_type, action_code, hit_count, last_hit_at, rule_source) \
         VALUES (?, ?, ?, 1, NOW(), ?) \
         ON DUPLICATE KEY UPDATE hit_count = hit_count + 1, last_hit_at = NOW(), rule_source = VALUES(rule_source)"
    )
        .bind(card_id)
        .bind(resource_type)
        .bind(action_code)
        .bind(rule_source)
        .execute(pool)
        .await?;
    Ok(())
}

/// 查询权限命中统计（Top N）
/// Java 对照: PermissionHitStatMapper.selectTop()
pub async fn find_top_permission_hit_stats(
    pool: &MySqlPool,
    limit: i32,
) -> Result<Vec<PermissionHitStat>, DbError> {
    let rows = sqlx::query_as::<_, PermissionHitStatRow>(
        "SELECT card_id, resource_type, action_code, \
         CAST(hit_count AS SIGNED) as hit_count, \
         UNIX_TIMESTAMP(last_hit_at) as last_hit_at, rule_source \
         FROM permission_hit_stat ORDER BY hit_count DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| PermissionHitStat {
            id: None,
            card_id: r.card_id,
            resource_type: r.resource_type,
            action_code: r.action_code,
            hit_count: r.hit_count,
            last_hit_at: r.last_hit_at,
            rule_source: r.rule_source,
        })
        .collect())
}

// ===== 内部行类型（I-4 补充）=====

#[derive(Debug, sqlx::FromRow)]
struct RuleSetRow {
    rule_set_id: i64,
    name: String,
    description: Option<String>,
    source_type: String,
    enabled: i8,
    created_at: Option<i64>,
    updated_at: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct RuleSetEntryRow {
    entry_id: i64,
    rule_set_id: i64,
    effect: String,
    resource_type: Option<String>,
    resource_id: Option<i64>,
    action_code: Option<String>,
    condition_json: Option<String>,
    priority: i32,
    created_at: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct PermissionHitStatRow {
    card_id: i64,
    resource_type: String,
    action_code: String,
    hit_count: i64,
    last_hit_at: Option<i64>,
    rule_source: Option<String>,
}

/// 密码重置令牌行
#[derive(Debug, sqlx::FromRow)]
pub struct PasswordResetTokenRow {
    pub id: i64,
    pub user_id: i64,
    pub card_number: String,
    pub token: String,
    pub expires_at: time::PrimitiveDateTime,
    pub used_at: Option<time::PrimitiveDateTime>,
    pub created_at: Option<time::PrimitiveDateTime>,
}

/// 插入密码重置令牌
pub async fn insert_password_reset_token(
    pool: &MySqlPool,
    user_id: i64,
    card_number: &str,
    token_hash: &str,
    expires_at: &time::PrimitiveDateTime,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO password_reset_token (user_id, card_number, token, expires_at) VALUES (?, ?, ?, ?)"
    )
        .bind(user_id)
        .bind(card_number)
        .bind(token_hash)
        .bind(expires_at)
        .execute(pool)
        .await?;
    Ok(())
}

/// 查找未使用的密码重置令牌（按 token hash）
pub async fn find_valid_password_reset_token(
    pool: &MySqlPool,
    token_hash: &str,
) -> Result<Option<PasswordResetTokenRow>, DbError> {
    let row = sqlx::query_as::<_, PasswordResetTokenRow>(
        "SELECT id, user_id, card_number, token, expires_at, used_at, created_at \
         FROM password_reset_token \
         WHERE token = ? AND used_at IS NULL AND expires_at > NOW() \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// 原子消费密码重置令牌。返回 1 表示本次消费成功，0 表示令牌已被其他请求消费。
pub async fn mark_password_reset_token_used(pool: &MySqlPool, id: i64) -> Result<bool, DbError> {
    let result = sqlx::query(
        "UPDATE password_reset_token SET used_at = NOW() WHERE id = ? AND used_at IS NULL AND expires_at > NOW()",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// 事务内原子消费密码重置令牌（与密码哈希更新同一事务）。
/// `used_at IS NULL` 条件即 replay 边界：并发请求中仅一个能成功消费。
pub async fn mark_password_reset_token_used_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
    id: i64,
) -> Result<bool, DbError> {
    let result = sqlx::query(
        "UPDATE password_reset_token SET used_at = NOW() WHERE id = ? AND used_at IS NULL AND expires_at > NOW()",
    )
    .bind(id)
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// 作废用户所有未使用的重置令牌
pub async fn invalidate_user_password_reset_tokens(
    pool: &MySqlPool,
    user_id: i64,
) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE password_reset_token SET used_at = NOW() WHERE user_id = ? AND used_at IS NULL",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

// ===== Phase 2a: Identity — 验证码 =====

/// 验证码行
#[derive(Debug, sqlx::FromRow)]
pub struct VerificationCodeRow {
    pub id: i64,
    pub target: String,
    pub purpose: String,
    pub code: String,
    pub expires_at: time::PrimitiveDateTime,
    pub verified_at: Option<time::PrimitiveDateTime>,
    pub created_at: Option<time::PrimitiveDateTime>,
}

/// 插入验证码
pub async fn insert_verification_code(
    pool: &MySqlPool,
    target: &str,
    purpose: &str,
    code: &str,
    expires_at: &time::PrimitiveDateTime,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO verification_code (target, purpose, code, expires_at) VALUES (?, ?, ?, ?)",
    )
    .bind(target)
    .bind(purpose)
    .bind(code)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// 查找指定 target + purpose 未使用、未过期的验证码（按创建时间倒序取最新）
pub async fn find_valid_verification_code(
    pool: &MySqlPool,
    target: &str,
    purpose: &str,
) -> Result<Option<VerificationCodeRow>, DbError> {
    let row = sqlx::query_as::<_, VerificationCodeRow>(
        "SELECT id, target, purpose, code, expires_at, verified_at, created_at \
         FROM verification_code \
         WHERE target = ? AND purpose = ? AND verified_at IS NULL AND expires_at > NOW() \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(target)
    .bind(purpose)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// 原子消费验证码：verified_at 仍为 NULL、未过期且身份字段完全匹配时只有一个并发校验成功。
pub async fn mark_verification_code_verified(
    pool: &MySqlPool,
    id: i64,
    target: &str,
    purpose: &str,
    code: &str,
) -> Result<bool, DbError> {
    let result = sqlx::query(
        "UPDATE verification_code SET verified_at = NOW() \
         WHERE id = ? AND target = ? AND purpose = ? AND code = ? \
           AND verified_at IS NULL AND expires_at > NOW()",
    )
    .bind(id)
    .bind(target)
    .bind(purpose)
    .bind(code)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Consume a verified MFA recovery code from the locked method row.
/// Hash array parsing and exact member removal happen inside the same short transaction.
pub async fn consume_mfa_recovery_code(
    pool: &MySqlPool,
    user_id: i64,
    code_hash: &str,
) -> Result<bool, DbError> {
    let mut tx = pool.begin().await?;
    let row: Option<(String, i32)> = sqlx::query_as(
        "SELECT backup_codes_hash, backup_codes_used FROM user_mfa \
         WHERE user_id = ? AND mfa_type = 'RECOVERY_CODES' AND is_enabled = 1 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((serialized, used)) = row else {
        tx.rollback().await?;
        return Ok(false);
    };
    if used < 0 || used as usize >= 10 {
        tx.rollback().await?;
        return Ok(false);
    }
    let mut hashes: Vec<String> = serde_json::from_str(&serialized)
        .map_err(|error| DbError::Mapping(format!("MFA recovery hash list is invalid: {error}")))?;
    let Some(index) = hashes.iter().position(|hash| hash == code_hash) else {
        tx.rollback().await?;
        return Ok(false);
    };
    hashes.remove(index);
    let updated = sqlx::query(
        "UPDATE user_mfa SET backup_codes_hash = ?, backup_codes_used = backup_codes_used + 1, \
         last_used_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP \
         WHERE user_id = ? AND mfa_type = 'RECOVERY_CODES' AND is_enabled = 1 \
           AND backup_codes_used = ? AND backup_codes_hash = ?",
    )
    .bind(serde_json::to_string(&hashes).map_err(|error| {
        DbError::Mapping(format!("Serialize MFA recovery hashes failed: {error}"))
    })?)
    .bind(user_id)
    .bind(used)
    .bind(&serialized)
    .execute(&mut *tx)
    .await?;
    if updated.rows_affected() != 1 {
        tx.rollback().await?;
        return Ok(false);
    }
    tx.commit().await?;
    Ok(true)
}

/// Confirm a staged recovery factor by consuming the presented code in the same transaction that enables it.
pub async fn activate_pending_recovery_code(
    pool: &MySqlPool,
    user_id: i64,
    code_hash: &str,
) -> Result<bool, DbError> {
    let mut tx = pool.begin().await?;
    let row: Option<(String, i32)> = sqlx::query_as(
        "SELECT backup_codes_hash, backup_codes_used FROM user_mfa \
         WHERE user_id = ? AND mfa_type = 'RECOVERY_CODES' AND is_enabled = 0 FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((serialized, used)) = row else {
        tx.rollback().await?;
        return Ok(false);
    };
    let mut hashes: Vec<String> = serde_json::from_str(&serialized)
        .map_err(|error| DbError::Mapping(format!("MFA recovery hash list is invalid: {error}")))?;
    let Some(index) = hashes.iter().position(|hash| hash == code_hash) else {
        tx.rollback().await?;
        return Ok(false);
    };
    hashes.remove(index);
    let changed = sqlx::query(
        "UPDATE user_mfa SET backup_codes_hash = ?, backup_codes_used = ?, is_enabled = 1, \
         is_primary = 1, verified_at = CURRENT_TIMESTAMP, last_used_at = CURRENT_TIMESTAMP, \
         updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND mfa_type = 'RECOVERY_CODES' \
           AND is_enabled = 0 AND backup_codes_used = ? AND backup_codes_hash = ?",
    )
    .bind(serde_json::to_string(&hashes).map_err(|error| DbError::Mapping(error.to_string()))?)
    .bind(used + 1)
    .bind(user_id)
    .bind(used)
    .bind(&serialized)
    .execute(&mut *tx)
    .await?;
    if changed.rows_affected() != 1 {
        tx.rollback().await?;
        return Ok(false);
    }
    tx.commit().await?;
    Ok(true)
}

/// Atomically record a TOTP step as consumed. Concurrent requests using the same
/// time-step cannot both mint a grant or verify a code.
pub async fn consume_mfa_totp_counter(
    pool: &MySqlPool,
    user_id: i64,
    counter: i64,
) -> Result<bool, DbError> {
    let result = sqlx::query(
        "UPDATE user_mfa SET last_totp_counter = ?, last_used_at = CURRENT_TIMESTAMP, \
         updated_at = CURRENT_TIMESTAMP \
         WHERE user_id = ? AND mfa_type = 'TOTP' AND is_enabled = 1 \
           AND (last_totp_counter IS NULL OR last_totp_counter < ?)",
    )
    .bind(counter)
    .bind(user_id)
    .bind(counter)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

/// Durable attempt reservation. PENDING rows count as failures until resolved;
/// abandoning a request can never reopen the brute-force budget.
pub async fn reserve_mfa_attempt(
    pool: &MySqlPool,
    user_id: i64,
    attempt_code: &str,
    mfa_type: &str,
    ip: Option<&str>,
    user_agent: Option<&str>,
) -> Result<(), DbError> {
    let mut tx = pool.begin().await?;
    // Serialize attempts on the account credential row so concurrent nodes cannot
    // all observe spare budget and reserve more than the configured maximum.
    let credential: Option<(i64,)> = sqlx::query_as(
        "SELECT credential_id FROM user_local_credential WHERE user_id = ? AND status = 'ACTIVE' FOR UPDATE",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?;
    if credential.is_none() {
        tx.rollback().await?;
        return Err(DbError::Mapping(
            "MFA attempt actor has no active local credential".into(),
        ));
    }
    let failures: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM mfa_attempt_log WHERE user_id = ? AND success = 0 \
         AND status IN ('FAILED', 'PENDING') AND attempted_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 15 MINUTE)",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    if failures.0 >= 5 {
        tx.rollback().await?;
        return Err(DbError::Mapping("MFA attempt limit exceeded".into()));
    }
    sqlx::query(
        "INSERT INTO mfa_attempt_log \
         (user_id, mfa_type, attempt_code, status, success, ip, user_agent, failure_reason) \
         VALUES (?, ?, ?, 'PENDING', 0, ?, ?, 'verification in progress')",
    )
    .bind(user_id)
    .bind(mfa_type)
    .bind(attempt_code)
    .bind(ip)
    .bind(user_agent)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Resolve an attempt reservation. DB failure is returned to the caller (fail-closed).
pub async fn resolve_mfa_attempt(
    pool: &MySqlPool,
    attempt_code: &str,
    success: bool,
    failure_reason: Option<&str>,
) -> Result<(), DbError> {
    let result = sqlx::query(
        "UPDATE mfa_attempt_log SET success = ?, status = ?, failure_reason = ?, \
         attempted_at = CURRENT_TIMESTAMP \
         WHERE attempt_code = ? AND status = 'PENDING' AND success = 0",
    )
    .bind(success as i32)
    .bind(if success { "SUCCEEDED" } else { "FAILED" })
    .bind(failure_reason)
    .bind(attempt_code)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(DbError::Mapping(
            "MFA attempt reservation could not be resolved exactly once".into(),
        ));
    }
    Ok(())
}

/// Resolve a management verification attempt only for the reserved actor and factor method.
pub async fn resolve_mfa_attempt_for_actor(
    pool: &MySqlPool,
    attempt_code: &str,
    user_id: i64,
    mfa_type: &str,
    success: bool,
    failure_reason: Option<&str>,
) -> Result<(), DbError> {
    let result = sqlx::query(
        "UPDATE mfa_attempt_log SET success = ?, status = ?, failure_reason = ?, \
         attempted_at = CURRENT_TIMESTAMP \
         WHERE attempt_code = ? AND user_id = ? AND mfa_type = ? \
           AND status = 'PENDING' AND success = 0",
    )
    .bind(success as i32)
    .bind(if success { "SUCCEEDED" } else { "FAILED" })
    .bind(failure_reason)
    .bind(attempt_code)
    .bind(user_id)
    .bind(mfa_type)
    .execute(pool)
    .await?;
    if result.rows_affected() != 1 {
        return Err(DbError::Mapping(
            "MFA attempt actor/method reservation was not pending".into(),
        ));
    }
    Ok(())
}

// ===== Phase 2a: Identity — 管理员统计 =====

/// 系统统计结果
#[derive(Debug, Clone)]
pub struct SystemStatsResult {
    pub total_users: i64,
    pub total_cards: i64,
    pub active_sessions: i64,
    pub requests_today: i64,
}

/// 查询系统统计
pub async fn query_system_stats(pool: &MySqlPool) -> Result<SystemStatsResult, DbError> {
    // 真实表结构：identity_card 无 deleted_at 列；platform_user 才有 deleted_at
    // total_users 统计平台用户数（未删除）
    let total_users: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM platform_user WHERE deleted_at IS NULL")
            .fetch_one(pool)
            .await?;

    // total_cards 统计活跃用户卡（真实列名 card_status）
    let total_cards: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM user_card WHERE card_status = 'ACTIVE'")
            .fetch_one(pool)
            .await?;

    let active_sessions: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM auth_device_session WHERE status = 'ACTIVE'")
            .fetch_one(pool)
            .await?;

    let requests_today_sql = format!(
        "SELECT COUNT(*) {} AND created_at >= CURDATE()",
        user_visible_audit_from_clause()
    );
    let requests_today: (i64,) = sqlx::query_as(&requests_today_sql).fetch_one(pool).await?;

    Ok(SystemStatsResult {
        total_users: total_users.0,
        total_cards: total_cards.0,
        active_sessions: active_sessions.0,
        requests_today: requests_today.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_visible_audit_queries_exclude_internal_scheduler_rows() {
        assert_eq!(USER_VISIBLE_AUDIT_PREDICATE, "decision <> 'INTERNAL'");
        let from_clause = user_visible_audit_from_clause();
        assert_eq!(from_clause, "FROM audit_log WHERE decision <> 'INTERNAL'");
        let requests_today_sql = format!(
            "SELECT COUNT(*) {} AND created_at >= CURDATE()",
            user_visible_audit_from_clause()
        );
        assert!(requests_today_sql.contains("decision <> 'INTERNAL'"));
        assert!(requests_today_sql.contains("created_at >= CURDATE()"));

        let source = include_str!("repository.rs");
        for function_name in [
            "pub async fn query_system_stats",
            "pub async fn query_audit_logs",
            "pub async fn count_audit_logs",
        ] {
            let body = source
                .split(function_name)
                .nth(1)
                .expect("user-visible audit reader must exist");
            assert!(
                body.contains("user_visible_audit_from_clause()"),
                "{function_name} must exclude INTERNAL audit rows"
            );
        }
    }

    #[test]
    fn projection_gate_maps_missing_and_empty_head_to_deny() {
        let missing = projection_gate_from_row(None);
        assert!(!missing.ready);
        assert_eq!(missing.source_generation, 0);

        // 事件尚未落任何一代（source_generation=0）：投影通道未建立。
        let unproven_zero_generation = projection_gate_from_row(Some((0, 0)));
        assert!(!unproven_zero_generation.ready);

        // 旧链状态列退役后，ready 只要求 head 存在且至少一代事件。
        let live = projection_gate_from_row(Some((2, 0)));
        assert!(live.ready);
    }

    #[test]
    fn permission_projection_readability_requires_nonempty_head() {
        assert!(!projection_is_readable(None));
        assert!(!projection_is_readable(Some(&ProjectionGate {
            ready: false,
            source_generation: 0,
            revoke_fence: 0,
        })));
        assert!(projection_is_readable(Some(&ProjectionGate {
            ready: true,
            source_generation: 2,
            revoke_fence: 0,
        })));
    }

    #[test]
    fn missing_projection_head_is_non_readable() {
        assert!(!projection_is_readable(Some(&projection_gate_from_row(
            None
        ))));
    }

    #[tokio::test]
    async fn formal_delegation_reader_fails_closed_without_projected_provenance() {
        let pool = MySqlPool::connect_lazy("mysql://localhost:1/astral_test").unwrap();
        let repo = SqlxRuleRepository::new(pool);

        let error = repo
            .load_projected_delegated_rules(7, "learn_course", "read")
            .await
            .expect_err("formal delegation reads must remain unavailable without provenance");

        assert!(error
            .to_string()
            .contains("delegation projection provenance is unavailable"));
    }

    // ===== Published-card formal read port（严格 reader 桥接；Sqlx 能力声明为 true 时由 PolicyEngine.evaluate 正式消费）=====

    #[test]
    fn published_card_evidence_errors_map_to_explicit_policy_errors() {
        use crate::authorization_projection_repository::AuthorizationEvidenceError;

        let not_ready =
            published_card_evidence_error_to_policy_error(AuthorizationEvidenceError::NotReady(
                "code=published_card_evidence.current_pointer_missing;tenant=7;card=17".into(),
            ));
        match not_ready {
            astral_types::PolicyError::Repository(message) => {
                assert!(message.starts_with("published_card_evidence_not_ready;"));
                assert!(message.contains("code=published_card_evidence.current_pointer_missing"));
            }
            other => panic!("NotReady must map onto Repository, got {other:?}"),
        }

        let corrupt =
            published_card_evidence_error_to_policy_error(AuthorizationEvidenceError::Corrupt(
                "code=published_card_evidence.pointer_moved_under_read".into(),
            ));
        match corrupt {
            astral_types::PolicyError::Repository(message) => {
                assert!(message.starts_with("published_card_evidence_corrupt;"));
                assert!(message.contains("pointer_moved_under_read"));
            }
            other => panic!("Corrupt must map onto Repository, got {other:?}"),
        }

        let invalid_request = published_card_evidence_error_to_policy_error(
            AuthorizationEvidenceError::InvalidRequest(
                "code=published_card_evidence.invalid_scope;detail=x".into(),
            ),
        );
        match invalid_request {
            astral_types::PolicyError::InvalidContext(message) => {
                assert!(message.starts_with("published_card_evidence_invalid_request;"));
                assert!(message.contains("invalid_scope"));
            }
            other => panic!("InvalidRequest must map onto InvalidContext, got {other:?}"),
        }

        let query = published_card_evidence_error_to_policy_error(
            AuthorizationEvidenceError::Query(sqlx::Error::RowNotFound),
        );
        match query {
            astral_types::PolicyError::Repository(message) => {
                assert!(message.starts_with("published_card_evidence_query_failed;"));
            }
            other => panic!("Query failure must map onto Repository, got {other:?}"),
        }
    }

    /// Shape guard: the SqlxRuleRepository published-card port must delegate to
    /// the strict pool reader with the scope forwarded unchanged and every
    /// error mapped explicitly — no legacy snapshot/raw-source/cache fallback
    /// may exist on this path, and successes cannot become an empty collection.
    #[test]
    fn sqlx_published_card_port_delegates_to_strict_reader_without_legacy_fallback() {
        let source = include_str!("repository.rs");
        let body = source
            .split("async fn load_published_card_authorization")
            .nth(1)
            .and_then(|body| body.split("// ===== 模块级公共函数").next())
            .expect("published-card port override must exist inside the trait impl");

        for required in [
            "crate::authorization_projection_repository::load_published_card_grant_evidence(",
            "&self.pool",
            "scope",
            ".map(Some)",
            ".map_err(published_card_evidence_error_to_policy_error)",
        ] {
            assert!(
                body.contains(required),
                "published-card port must contain `{required}`"
            );
        }
        for forbidden in [
            "permission_rule_snapshot",
            "rule_set_snapshot",
            "redis_conn",
            "UTC_TIMESTAMP",
        ] {
            assert!(
                !body.contains(forbidden),
                "published-card port must not fall back to legacy cache/snapshot paths ({forbidden})"
            );
        }
    }

    /// The strict pool wrapper owns ONE short transaction with an explicit
    /// commit before returning; the typed result is a whole evidence object,
    /// so an absent current pointer surfaces as an error rather than an empty
    /// authorization set.
    #[test]
    fn strict_pool_reader_commits_explicitly_and_never_returns_empty_success() {
        let source = include_str!("authorization_projection_repository.rs").replace("\r\n", "\n");
        let body = source
            .split("pub async fn load_published_card_grant_evidence(\n    pool")
            .nth(1)
            .and_then(|body| body.split("Bridge from the pure compiler kernel").next())
            .expect("pool-level strict reader must exist");

        // The typed result carries the evidence-error vocabulary directly;
        // transport failures use the declared From<sqlx::Error> conversion.
        assert!(body.contains("-> Result<PublishedCardAuthorization, AuthorizationEvidenceError>"));
        assert!(body.contains("let mut tx = pool.begin().await?;"));
        let begin = body.find("pool.begin()").expect("transaction begin");
        let read = body
            .find("load_published_card_grant_evidence_in_tx(&mut tx, scope)")
            .expect("transaction-scoped reader call");
        let commit = body.find("tx.commit().await?").expect("explicit commit");
        assert!(
            begin < read && read < commit,
            "read must run inside begin..commit"
        );
        // The returned contract is one verified evidence object per scope,
        // not a collection that could degenerate into an empty ALLOW.
        assert!(!body.contains("Ok(vec![") && !body.contains("Ok(Vec::new())"));
    }
}

/// 审计日志条目查询结果（对齐 admin.rs AuditLogEntry）
#[derive(Debug, sqlx::FromRow)]
pub struct AuditLogQueryRow {
    pub id: i64,
    pub user_id: i64,
    pub action: String,
    pub resource: String,
    pub detail: Option<String>,
    pub created_at: Option<time::PrimitiveDateTime>,
}

/// 查询审计日志（分页）
pub async fn query_audit_logs(
    pool: &MySqlPool,
    user_id: Option<i64>,
    action: Option<&str>,
    page: i64,
    size: i64,
) -> Result<Vec<AuditLogQueryRow>, DbError> {
    let offset = (page - 1).max(0) * size;

    let mut sql = format!(
        "SELECT id, user_id, action, resource, COALESCE(detail, '') as detail, created_at {}",
        user_visible_audit_from_clause()
    );
    let mut _has_user_filter = false;
    let mut _has_action_filter = false;

    if user_id.is_some() {
        sql.push_str(" AND user_id = ?");
        _has_user_filter = true;
    }
    if let Some(a) = action {
        if !a.is_empty() {
            sql.push_str(" AND action = ?");
            _has_action_filter = true;
        }
    }

    sql.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

    let mut query = sqlx::query_as::<_, AuditLogQueryRow>(&sql);
    if let Some(uid) = user_id {
        query = query.bind(uid);
    }
    if let Some(a) = action {
        if !a.is_empty() {
            query = query.bind(a);
        }
    }
    query = query.bind(size).bind(offset);

    let rows = query.fetch_all(pool).await?;
    Ok(rows)
}

/// 审计日志总数（与 query_audit_logs 同过滤条件；admin 分页用）。
pub async fn count_audit_logs(
    pool: &MySqlPool,
    user_id: Option<i64>,
    action: Option<&str>,
) -> Result<i64, DbError> {
    let mut sql = format!("SELECT COUNT(*) {}", user_visible_audit_from_clause());
    let mut _has_user_filter = false;
    let mut _has_action_filter = false;

    if user_id.is_some() {
        sql.push_str(" AND user_id = ?");
        _has_user_filter = true;
    }
    if let Some(a) = action {
        if !a.is_empty() {
            sql.push_str(" AND action = ?");
            _has_action_filter = true;
        }
    }

    let mut query = sqlx::query_scalar::<_, i64>(&sql);
    if let Some(uid) = user_id {
        query = query.bind(uid);
    }
    if let Some(a) = action {
        if !a.is_empty() {
            query = query.bind(a);
        }
    }
    query.fetch_one(pool).await.map_err(DbError::from)
}

// ===== 安全与教育域公共函数 =====

/// 查询默认密码策略
pub async fn find_default_password_policy(
    pool: &MySqlPool,
) -> Result<Option<astral_types::PasswordPolicy>, DbError> {
    #[derive(Debug, sqlx::FromRow)]
    struct Row {
        id: Option<i64>,
        name: String,
        min_length: i32,
        max_length: Option<i32>,
        require_uppercase: bool,
        require_lowercase: bool,
        require_digit: bool,
        require_special: bool,
        special_chars: Option<String>,
        max_retries: i32,
        lockout_minutes: i32,
        password_expiry_days: Option<i32>,
        history_count: i32,
        is_default: bool,
        status: String,
    }
    let row = sqlx::query_as::<_, Row>(
        "SELECT * FROM password_policy WHERE is_default = 1 AND status = 'ACTIVE' LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| astral_types::PasswordPolicy {
        id: r.id,
        name: r.name,
        min_length: r.min_length,
        max_length: r.max_length,
        require_uppercase: r.require_uppercase,
        require_lowercase: r.require_lowercase,
        require_digit: r.require_digit,
        require_special: r.require_special,
        special_chars: r.special_chars,
        max_retries: r.max_retries,
        lockout_minutes: r.lockout_minutes,
        password_expiry_days: r.password_expiry_days,
        history_count: r.history_count,
        is_default: r.is_default,
        status: r.status,
    }))
}

/// 插入安全事件
pub async fn insert_security_event(
    pool: &MySqlPool,
    user_id: Option<i64>,
    event_type: &str,
    severity: &str,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    detail: Option<&str>,
) -> Result<i64, DbError> {
    let result = sqlx::query(
        "INSERT INTO security_event (user_id, event_type, severity, ip_address, user_agent, detail) VALUES (?, ?, ?, ?, ?, ?)"
    )
    .bind(user_id).bind(event_type).bind(severity).bind(ip_address).bind(user_agent).bind(detail)
    .execute(pool).await?;
    Ok(result.last_insert_id() as i64)
}

/// 查询启用的 OAuth 提供商
pub async fn find_enabled_oauth_providers(
    pool: &MySqlPool,
) -> Result<Vec<astral_types::OauthProvider>, DbError> {
    #[derive(Debug, sqlx::FromRow)]
    struct Row {
        id: Option<i64>,
        provider_name: String,
        client_id: String,
        client_secret_encrypted: Option<String>,
        authorize_url: Option<String>,
        token_url: Option<String>,
        userinfo_url: Option<String>,
        scope: Option<String>,
        enabled: bool,
        created_at: Option<i64>,
    }
    let rows =
        sqlx::query_as::<_, Row>("SELECT * FROM oauth_provider WHERE enabled = 1 ORDER BY id")
            .fetch_all(pool)
            .await?;
    Ok(rows
        .into_iter()
        .map(|r| astral_types::OauthProvider {
            id: r.id,
            provider_name: r.provider_name,
            client_id: r.client_id,
            client_secret_encrypted: r.client_secret_encrypted,
            authorize_url: r.authorize_url,
            token_url: r.token_url,
            userinfo_url: r.userinfo_url,
            scope: r.scope,
            enabled: r.enabled,
            created_at: r.created_at,
        })
        .collect())
}

/// 按 code 查询学校
pub async fn find_school_by_code(
    pool: &MySqlPool,
    code: &str,
) -> Result<Option<astral_types::School>, DbError> {
    #[derive(Debug, sqlx::FromRow)]
    struct Row {
        id: Option<i64>,
        name: String,
        code: Option<String>,
        province: Option<String>,
        city: Option<String>,
        district: Option<String>,
        address: Option<String>,
        school_type: Option<String>,
        logo_url: Option<String>,
        contact_phone: Option<String>,
        contact_email: Option<String>,
        status: String,
        created_at: Option<i64>,
    }
    let row = sqlx::query_as::<_, Row>("SELECT * FROM school WHERE code = ? AND status = 'ACTIVE'")
        .bind(code)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| astral_types::School {
        id: r.id,
        name: r.name,
        code: r.code,
        province: r.province,
        city: r.city,
        district: r.district,
        address: r.address,
        school_type: r.school_type,
        logo_url: r.logo_url,
        contact_phone: r.contact_phone,
        contact_email: r.contact_email,
        status: r.status,
        created_at: r.created_at,
    }))
}
