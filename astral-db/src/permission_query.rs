//! 共享权限读查询（登录权限链：一律读已发布 published card evidence）
//!
//! 对齐 Java `PermissionSnapshotService.findSnapshot` + `refreshUserPermissions` 语义：
//! 权限视图读**已发布的授权证据**（`authorization_projection_current` 当前指针
//! 锁定的 COMMITTED manifest 链），不触碰 `permission_rule` / `rule_set_entry`
//! 源表，也不再读取 legacy `permission_rule_snapshot` / `rule_set_snapshot`
//! MAX(version_no) 读链。
//!
//! 查询策略（登录有效权限与卡摘要同源）：
//! 1. 有效权限 / 卡摘要：一律派生自 Rust-owned published card evidence ——
//!    严格 reader [`crate::authorization_projection_repository::
//!    load_published_card_grant_evidence`] 在单个短事务内按当前指针锁定并整链
//!    校验卡作用域全部已发布聚合，只有 accepted（已进入有效授权集合）的
//!    verified 记录参与派生；`NotReady`/`Corrupt` 一律 fail-closed。
//!
//! 进程内 evidence 缓存：本模块两处卡级 evidence 读取统一经
//! [`crate::evidence_cache::cached_load_published_card_grant_evidence`] ——命中前
//! 逐项复读当前指针版本组、pending delta 位及严格读栅栏；miss/漂移回源唯一的
//! 来源是严格 published-evidence reader。正确性论证与失效语义见
//! `crate::evidence_cache` 模块文档。
//! 2. 读侧纵深防御：RULE_SET 来源的 grant 在读取时按 `rule_set.enabled = 1` 和
//!    租户戳过滤；缺失、禁用或租户戳不匹配的 rule set 不参与权限派生。
//!
//! 【上线灰度观察项】登录权限列表可能变宽：evidence 的生效集合包含
//! APPROVAL / DELEGATION / SYSTEM 来源（旧读链只看卡规则快照 + 规则集快照，
//! 看不到这些来源）。切换后属于授权面语义修复而非回归，但需关注登录权限
//! 列表新增项的告警/客诉（对齐 SoD 读链切换先例的观察方式）。

use std::collections::{BTreeSet, HashMap};

use astral_types::{
    BindingLayer, DomainScopeRequirement, GrantSourceKind, PublishedCardAuthorization,
    PublishedCardEvidenceScope,
};
use sqlx::{MySqlPool, QueryBuilder};

use crate::authorization_projection_repository::AuthorizationEvidenceError;
use crate::evidence_cache::cached_load_published_card_grant_evidence;
use crate::DbError;

mod fence;
pub(crate) use fence::evidence_fence_baseline;
use fence::{decode_pointer_fence_rows, PointerFenceSqlRow, POINTER_FENCE_VERSIONS_SQL};
pub use fence::{CardScopeFenceSnapshot, PermissionCacheManifestVersion};

/// 权限授予记录（resource_type 由 resource_key 拆分，对齐 Java `parseResourceKey`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionGrantRow {
    pub resource_type: String,
    pub action_code: String,
    /// Validity window copied from the projected row, expressed as UTC UNIX seconds.
    pub valid_from_ts: Option<i64>,
    pub valid_to_ts: Option<i64>,
}

/// 卡片权限摘要（对齐现有 identity 卡片列表的 CSV 摘要输出）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CardPermissionSummary {
    pub action_codes: Option<String>,
    pub base_rule_set_ids: Option<String>,
    pub overlay_rule_set_ids: Option<String>,
}

/// 解析 resource_key 为 resource_type：`type:*` 与 `type:id` 均返回 `type`。
fn parse_resource_type(resource_key: &str) -> String {
    match resource_key.rfind(':') {
        Some(idx) => resource_key[..idx].to_string(),
        None => resource_key.to_string(),
    }
}

/// 有效权限的核心读取：卡级 published evidence → 生效 grant 映射。
///
/// fail-closed 语义（对齐 [`load_card_permission_summaries`] 先例）：
/// - `user_card.tenant_id` 缺失或非正的卡无法构造 evidence scope → 空结果；
/// - evidence `NotReady`（指针缺失/非 COMMITTED/超扇出）→ 空结果（与旧读链
///   head gate fail-closed 同向）；
/// - evidence `Corrupt` 或 Ready 证据合同校验失败 → warn + 空结果（对账）；
/// - RULE_SET 来源 grant 缺少 RULE_SET 聚合 provenance（形状矛盾）→ 空结果；
/// - DB 传输错误原样上抛为 [`DbError`]，绝不吞错降级为"无权限继续"。
async fn find_effective_permissions_for_tenant(
    pool: &MySqlPool,
    tenant_id: i64,
    card_id: i64,
) -> Result<Vec<PermissionGrantRow>, DbError> {
    // 卡级 lens：不按 user 收窄、不限 domain（对齐 legacy 卡级列表语义）。
    let scope = PublishedCardEvidenceScope {
        tenant_id,
        card_id,
        user_filter: None,
        domain: DomainScopeRequirement::Unconstrained,
    };
    // 进程内 evidence 缓存读取：命中由指针对牌保证，miss/漂移回源严格 reader
    // （错误族与严格 reader 完全一致，fail-closed 语义不变）。
    let evidence = match cached_load_published_card_grant_evidence(pool, &scope).await {
        Ok(evidence) => evidence,
        Err(AuthorizationEvidenceError::NotReady(detail)) => {
            tracing::debug!(
                card_id,
                detail = detail.as_str(),
                "published card evidence not ready, returning safe permission miss"
            );
            return Ok(Vec::new());
        }
        Err(AuthorizationEvidenceError::Corrupt(detail)) => {
            tracing::warn!(
                card_id,
                detail = detail.as_str(),
                "published card evidence corrupt, returning safe permission miss (reconciliation required)"
            );
            return Ok(Vec::new());
        }
        // DB 传输失败响亮上抛；scope 由本函数构造，InvalidRequest 只可能是
        // 编程错误，同样不允许静默降级为空授权视图。
        Err(error) => {
            return Err(match error {
                AuthorizationEvidenceError::Query(query) => query.into(),
                other => DbError::Mapping(format!(
                    "published card evidence reader rejected the permission scope: {other}"
                )),
            });
        }
    };
    // 纵深防御：reader 产物再过一次合同校验；形状矛盾的证据绝不参与授权派生。
    if let Err(contract_error) = evidence.validate() {
        tracing::warn!(
            card_id,
            error = ?contract_error,
            "published card evidence failed contract validation, returning safe permission miss"
        );
        return Ok(Vec::new());
    }

    // 读侧纵深防御（对齐旧读链 SQL 的 `rs.enabled = 1` + 租户戳防线）：
    // RULE_SET 来源 grant 按 rule_set.enabled=1 + 租户戳过滤。发布/入账侧只
    // 在绑定与物化时刻检查 enabled，不提供运行时防线；入账后 rule_set 被外部
    // 禁用时 evidence 仍会携带其 grant，只能在这里排除（见模块文档后续项）。
    let mut contributing_rule_set_ids = std::collections::BTreeSet::new();
    for record in &evidence.records {
        if record.accepted_into_effective_set
            && record.grant.source_kind == GrantSourceKind::RuleSet
        {
            contributing_rule_set_ids.insert(record.aggregate_id);
        }
    }
    let enabled_rule_set_ids = if contributing_rule_set_ids.is_empty() {
        std::collections::HashSet::new()
    } else {
        load_enabled_rule_set_ids(pool, &contributing_rule_set_ids, tenant_id).await?
    };

    let grants = match permission_grant_rows_from_evidence(&evidence, &enabled_rule_set_ids) {
        Ok(grants) => grants,
        Err(shape_error) => {
            tracing::warn!(
                card_id,
                error = ?shape_error,
                "published card evidence shape cannot produce permission rows, returning safe permission miss"
            );
            return Ok(Vec::new());
        }
    };
    Ok(grants)
}

/// Ready 证据内部使其授权行不可安全派生的形状矛盾（Corrupt 族，整卡不产出）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum PublishedGrantShapeError {
    /// `RULE_SET` 来源 grant 的来源聚合不是 `RULE_SET`：不存在可信的
    /// rule_set_id，enabled 过滤无法作用，授权行不得从其派生。
    RuleSetProvenanceMissing { grant_id: String },
}

/// 从严格 published card evidence 纯派生有效授权行（无 I/O）。
///
/// 只消费 `records` 中 `accepted_into_effective_set` 的子集（选择 `records`
/// 而非 `effective_grants` 是因为 rule_set_id 存在于记录的来源聚合
/// provenance 上，裸 `CanonicalGrant` 会丢弃它，与卡摘要派生同一取舍）。
/// RULE_SET 来源按 `enabled_rule_set_ids` 再过滤（缺行 = 未通过 = 排除），
/// 非 RULE_SET 来源（DIRECT/APPROVAL/DELEGATION/SYSTEM）全部放行——
/// 【上线灰度观察项】这是登录权限列表变宽的来源，见模块文档。
///
/// 去重语义：`(resource_type, action_code)` 相同的多来源 grant 合并为一行，
/// 保留确定性 evidence 顺序中的首个窗口；输出按该键升序（对齐旧读链
/// UNION 去重 + 排序布局）。
fn permission_grant_rows_from_evidence(
    evidence: &PublishedCardAuthorization,
    enabled_rule_set_ids: &std::collections::HashSet<i64>,
) -> Result<Vec<PermissionGrantRow>, PublishedGrantShapeError> {
    let mut merged: std::collections::BTreeMap<(String, String), (Option<i64>, Option<i64>)> =
        std::collections::BTreeMap::new();
    for record in &evidence.records {
        if !record.accepted_into_effective_set {
            continue;
        }
        let grant = &record.grant;
        if grant.source_kind == GrantSourceKind::RuleSet {
            if record.aggregate_type != "RULE_SET" {
                return Err(PublishedGrantShapeError::RuleSetProvenanceMissing {
                    grant_id: grant.grant_id.to_string(),
                });
            }
            if !enabled_rule_set_ids.contains(&record.aggregate_id) {
                continue;
            }
        }
        // resource 是 scoped key（`type:*` / `type:id`），对齐 Java parseResourceKey。
        let resource_type = parse_resource_type(&grant.resource);
        // validity → 旧链 valid_from/valid_to 的 UNIX 秒窗口。
        merged
            .entry((resource_type, grant.action.clone()))
            .or_insert((grant.validity.not_before, grant.validity.expires_at));
    }
    Ok(merged
        .into_iter()
        .map(
            |((resource_type, action_code), (valid_from_ts, valid_to_ts))| PermissionGrantRow {
                resource_type,
                action_code,
                valid_from_ts,
                valid_to_ts,
            },
        )
        .collect())
}

/// 批量解析贡献方 rule set 的 enabled + 租户戳，返回可信任其 grant 的
/// rule_set_id 集合。`enabled = 1` 且 `tenant_id` 与卡租户 NULL 安全相等
/// （对齐旧读链 `rs.enabled = 1 AND rs.tenant_id <=> crsrf.tenant_id`）才
/// 通过；rule_set 行缺失视为不通过（旧 INNER JOIN 同语义，fail-closed）。
async fn load_enabled_rule_set_ids(
    pool: &MySqlPool,
    rule_set_ids: &std::collections::BTreeSet<i64>,
    card_tenant_id: i64,
) -> Result<std::collections::HashSet<i64>, DbError> {
    if rule_set_ids.is_empty() {
        return Ok(std::collections::HashSet::new());
    }
    let mut builder = QueryBuilder::<sqlx::MySql>::new(
        "SELECT rule_set_id, enabled, tenant_id FROM rule_set WHERE rule_set_id IN (",
    );
    let mut separator = "";
    for rule_set_id in rule_set_ids {
        builder.push(separator).push_bind(*rule_set_id);
        separator = ", ";
    }
    builder.push(")");

    let rows: Vec<(i64, i8, Option<i64>)> = builder.build_query_as().fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .filter(|(_, enabled, rule_set_tenant_id)| {
            enabled_rule_set_row_is_allowed(*enabled, *rule_set_tenant_id, card_tenant_id)
        })
        .map(|(rule_set_id, _, _)| rule_set_id)
        .collect())
}

/// rule_set 行能否信任其 RULE_SET 来源 grant（纯逻辑）：`enabled = 1` 且
/// `tenant_id` 与卡租户 NULL 安全相等。
fn enabled_rule_set_row_is_allowed(
    enabled: i8,
    rule_set_tenant_id: Option<i64>,
    card_tenant_id: i64,
) -> bool {
    enabled == 1 && tenant_stamp_matches(rule_set_tenant_id, Some(card_tenant_id))
}

/// MySQL NULL 安全等值（`<=>`）的 Rust 语义：`None` 只与 `None` 相等。
fn tenant_stamp_matches(left: Option<i64>, right: Option<i64>) -> bool {
    left == right
}

/// 单卡租户定位（evidence scope 必需输入；不是授权事实）。
///
/// 复用批量 [`load_card_tenants`] 的读取与语义：`user_card` 行缺失或
/// `tenant_id` 空/非正返回 `None`，调用方必须 fail-closed。
async fn load_single_card_tenant(pool: &MySqlPool, card_id: i64) -> Result<Option<i64>, DbError> {
    let tenants = load_card_tenants(pool, &[card_id]).await?;
    Ok(tenants
        .get(&card_id)
        .copied()
        .flatten()
        .filter(|tenant_id| *tenant_id > 0))
}

/// 批量加载卡片权限摘要（卡级 action_codes + BASE/OVERLAY 规则集 id）。
///
/// 正式摘要一律派生自 Rust-owned published card evidence：严格 reader
/// [`crate::authorization_projection_repository::load_published_card_grant_evidence`] 在单个短事务内按
/// `authorization_projection_current` 当前指针（FOR UPDATE）读取并整链校验
/// 每张卡作用域的全部已发布聚合。legacy `permission_rule_snapshot` /
/// `rule_set_snapshot` 的 MAX(version_no) 读取已从本路径移除，不存在任何
/// legacy 快照 / raw source / cache 回退。
///
/// fail-closed 语义（缺行 = `None`，绝不伪造空 CSV 授权视图）：
/// - 当前指针缺失 / 非 COMMITTED / 超出扇出上限（`NotReady`）、链校验失败
///   或合同校验不过（`Corrupt` 族）的卡一律不产生摘要；
/// - `user_card.tenant_id` 缺失或非正数的卡无法构造 evidence scope，同样
///   不产生摘要（tenant 只用于定位租户键控的指针行；reader 会再次校验全部
///   tenant 戳，陈旧租户只会 fail closed 而不会放行）；
/// - DB 传输错误原样向上传播为 [`DbError`]，绝不吞错降级为“缺摘要继续”。
///
/// 派生映射（只消费 accepted=已进入有效授权集合的 verified 记录，见
/// `card_permission_summary_from_evidence`）：
/// - 非 `RULE_SET` 来源（DIRECT/APPROVAL/DELEGATION/SYSTEM）→ 去重升序
///   action codes（对齐 legacy 卡规则摘要 CSV 输出）；
/// - `RULE_SET` 来源 → 按 `binding_layer` 分组到 BASE / OVERLAY 规则集 id
///   CSV（记录的 `aggregate_id` 即 rule_set_id）。
///
/// 并发/一致性：reader 在各自短事务内重校验指针未漂移
/// （`pointer_moved_under_read`），因此不需要本文件 legacy 版本的批量
/// head-recheck；卡按去重升序处理保证读取顺序确定。每卡一次短事务是严格
/// reader 的既定合同 —— 刻意不引入跨卡大事务，避免批量读长时间持有大量
/// 指针行锁阻塞 publisher（正确性优先于批量优化）。
pub async fn load_card_permission_summaries(
    pool: &MySqlPool,
    card_ids: &[i64],
) -> Result<std::collections::HashMap<i64, CardPermissionSummary>, DbError> {
    let mut summaries: std::collections::HashMap<i64, CardPermissionSummary> =
        std::collections::HashMap::new();
    if card_ids.is_empty() {
        return Ok(summaries);
    }

    // 去重升序处理：同一输入产生确定一致的 evidence 读取顺序。
    let mut ordered_card_ids = card_ids.to_vec();
    ordered_card_ids.sort_unstable();
    ordered_card_ids.dedup();
    // 非正数 card id 永远无法通过 evidence scope 合同（也从未能匹配任何
    // legacy 行）：直接不产生摘要。
    ordered_card_ids.retain(|card_id| *card_id > 0);
    if ordered_card_ids.is_empty() {
        return Ok(summaries);
    }

    // 仅作 scope 定位输入的批量租户读取（一次 IN 查询，非授权事实）。
    let card_tenants = load_card_tenants(pool, &ordered_card_ids).await?;

    for card_id in &ordered_card_ids {
        let Some(tenant_id) = card_tenants
            .get(card_id)
            .copied()
            .flatten()
            .filter(|tenant_id| *tenant_id > 0)
        else {
            tracing::debug!(
                card_id,
                "card tenant missing or non-positive, omitting permission summary"
            );
            continue;
        };

        // 卡级摘要视角：不按 user 收窄、不限 domain（对齐 legacy 卡摘要语义）。
        let scope = PublishedCardEvidenceScope {
            tenant_id,
            card_id: *card_id,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        };
        match cached_load_published_card_grant_evidence(pool, &scope).await {
            Ok(evidence) => {
                if evidence.validate().is_err() {
                    tracing::warn!(
                        card_id,
                        "published card evidence failed contract validation, omitting permission summary"
                    );
                    continue;
                }
                match card_permission_summary_from_evidence(&evidence) {
                    Ok(Some(summary)) => {
                        summaries.insert(*card_id, summary);
                    }
                    Ok(None) => {
                        // Ready 证据证明空有效授权面：不产生摘要条目，
                        // 绝不转换成空 CSV 授权视图。
                    }
                    Err(shape_error) => {
                        tracing::warn!(
                            card_id,
                            error = ?shape_error,
                            "published card evidence shape cannot produce a summary, omitting"
                        );
                    }
                }
            }
            Err(AuthorizationEvidenceError::NotReady(detail)) => {
                tracing::debug!(
                    card_id,
                    detail = detail.as_str(),
                    "published card evidence not ready, omitting permission summary"
                );
            }
            Err(AuthorizationEvidenceError::Corrupt(detail)) => {
                tracing::warn!(
                    card_id,
                    detail = detail.as_str(),
                    "published card evidence corrupt, omitting permission summary (reconciliation required)"
                );
            }
            // DB 传输失败与 reader 合同拒绝不得静默降级为“缺摘要”：响亮上抛。
            Err(error) => {
                return Err(match error {
                    AuthorizationEvidenceError::Query(query) => query.into(),
                    other => DbError::Mapping(format!(
                        "published card evidence reader rejected the summary scope: {other}"
                    )),
                });
            }
        }
    }

    Ok(summaries)
}

/// 批量读取卡片租户（evidence scope 的定位输入；不是授权事实）。
///
/// `authorization_projection_current` 指针行按租户键控，构造严格 reader 的
/// scope 必须携带租户。reader 内部会校验指针租户戳与 scope 一致，因此这里
/// 读到的陈旧 `user_card.tenant_id` 只会导致 fail closed（Corrupt），不可能
/// 错误放行其它租户的数据。
async fn load_card_tenants(
    pool: &MySqlPool,
    card_ids: &[i64],
) -> Result<HashMap<i64, Option<i64>>, DbError> {
    if card_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let mut builder = QueryBuilder::<sqlx::MySql>::new(
        "SELECT card_id, tenant_id FROM user_card WHERE card_id IN (",
    );
    let mut separator = "";
    for card_id in card_ids {
        builder.push(separator).push_bind(*card_id);
        separator = ", ";
    }
    builder.push(")");

    let rows: Vec<(i64, Option<i64>)> = builder.build_query_as().fetch_all(pool).await?;
    Ok(rows.into_iter().collect())
}

/// Ready 证据内部使其摘要不可安全产出的形状矛盾（Corrupt 族，整卡不产出）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum PublishedSummaryShapeError {
    /// `RULE_SET` 来源 grant 的来源聚合不是 `RULE_SET`：不存在可信的
    /// rule_set_id，摘要不得从其派生。
    RuleSetProvenanceMissing { grant_id: String },
    /// `RULE_SET` 来源 grant 缺少 BASE/OVERLAY 绑定层：无法归类（合同对齐
    /// 本应禁止该形状；此处为纵深防御）。
    RuleSetLayerMissing { grant_id: String },
}

/// 从严格 published card evidence 纯派生卡摘要（无 I/O）。
///
/// 只消费 `records` 中 `accepted_into_effective_set` 的子集：被安全排除的
/// 记录（过期/未生效/非 ACTIVE/lens 收窄）从未进入有效授权集合，绝不参与
/// 摘要。选择 `records` 而非 `effective_grants` 是因为 rule_set_id 存在于
/// 记录的来源聚合 provenance 上，裸 `CanonicalGrant` 会丢弃它。
///
/// 返回 `Ok(None)` 表示 Ready 证据证明空有效授权面（对齐 legacy 行为：无
/// GROUP_CONCAT 行 → 无摘要条目），绝不返回空 CSV 的 `Some`。
fn card_permission_summary_from_evidence(
    evidence: &PublishedCardAuthorization,
) -> Result<Option<CardPermissionSummary>, PublishedSummaryShapeError> {
    // BTree = 确定升序 CSV 输出（对齐 legacy GROUP_CONCAT(... ORDER BY ...)
    // 布局；action code 为规范化标识符，字节序即词法序）。
    let mut action_codes: BTreeSet<String> = BTreeSet::new();
    let mut base_rule_set_ids: BTreeSet<i64> = BTreeSet::new();
    let mut overlay_rule_set_ids: BTreeSet<i64> = BTreeSet::new();

    for record in &evidence.records {
        if !record.accepted_into_effective_set {
            continue;
        }
        let grant = &record.grant;
        if grant.source_kind == GrantSourceKind::RuleSet {
            if record.aggregate_type != "RULE_SET" {
                return Err(PublishedSummaryShapeError::RuleSetProvenanceMissing {
                    grant_id: grant.grant_id.to_string(),
                });
            }
            match grant.binding_layer {
                BindingLayer::Base => {
                    base_rule_set_ids.insert(record.aggregate_id);
                }
                BindingLayer::Overlay => {
                    overlay_rule_set_ids.insert(record.aggregate_id);
                }
                BindingLayer::None => {
                    return Err(PublishedSummaryShapeError::RuleSetLayerMissing {
                        grant_id: grant.grant_id.to_string(),
                    });
                }
            }
        } else {
            // 卡级贡献（DIRECT/APPROVAL/DELEGATION/SYSTEM）→ action 摘要。
            action_codes.insert(grant.action.clone());
        }
    }

    if action_codes.is_empty() && base_rule_set_ids.is_empty() && overlay_rule_set_ids.is_empty() {
        return Ok(None);
    }
    Ok(Some(CardPermissionSummary {
        action_codes: sorted_csv(action_codes.iter().map(String::as_str)),
        base_rule_set_ids: sorted_csv(base_rule_set_ids.iter().map(i64::to_string)),
        overlay_rule_set_ids: sorted_csv(overlay_rule_set_ids.iter().map(i64::to_string)),
    }))
}

/// 把预排序值连接为 legacy `GROUP_CONCAT(... SEPARATOR ',')` 的 CSV 布局；
/// 空组件保持 `None`（绝不产出空字符串授权视图）。
fn sorted_csv<I>(values: I) -> Option<String>
where
    I: IntoIterator,
    I::Item: ToString,
{
    let joined = values
        .into_iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",");
    (!joined.is_empty()).then_some(joined)
}

/// 卡作用域（含 aggregate-wide `NULL` card delta）撤权类未发布 delta 轻探针
/// （无锁、单条 SQL；缓存命中校验的 pending 位输入）。与严格 reader 的
/// freshness 门同谓词：存在撤权类（REMOVE/REVOKE 或行级
/// `invalidates_published_evidence <> 0` 或 fence 超前已发布水位）
/// 未发布 delta ⟺ 旧代证据对移除/吊销即越权。收窄型 UPDATE 的 stale-ALLOW
/// 窗口由写侧闭合：authorization-content 变化的 UPDATE 在该行记录
/// invalidates_published_evidence=1；纯 provenance-only/no-op UPDATE 不置位（缺新授权只
/// 是 deny-biased EC 的 ms 级窗口——写突发下全量阻塞会造成权限检查自饥饿，
/// P3 风暴实测教训）。作用域为 `(card_id = ? OR card_id IS NULL)`，aggregate-wide
/// 的撤权类 delta 同样置位；已发布水位子查询用 NULL-safe `<=>` 关联（普通
/// `=` 会把 NULL card 水位折叠成 0，使已被已发布水位覆盖的 aggregate-wide
/// delta 误报 pending）。此处的无锁读不是授权事实——池级 autocommit 语句读
/// 最新已提交状态，配合命中协议的读前/读后双读纪律；权威判定由严格 reader
/// 的 freshness 门承担。
const PENDING_DELTA_PROBE_SQL: &str = "SELECT EXISTS(SELECT 1 FROM authorization_delta_event \
     WHERE tenant_id = ? AND (card_id = ? OR card_id IS NULL) AND status <> 'SUCCEEDED' \
       AND (invalidates_published_evidence <> 0 \
            OR event_type IN ('REMOVE', 'REVOKE') \
            OR revoke_fence > COALESCE((SELECT MAX(p.revoke_fence) FROM authorization_delta_event p \
                                        WHERE p.tenant_id = authorization_delta_event.tenant_id \
                                          AND p.card_id <=> authorization_delta_event.card_id \
                                          AND p.status = 'SUCCEEDED'), 0)))";

#[cfg(feature = "e1-observability")]
fn log_e1_fence_observation(
    event: &'static str,
    observation: &'static str,
    tenant_id: i64,
    card_id: i64,
    outcome: &'static str,
    pending: Option<bool>,
) {
    let stamp = policy_engine::e1_observation::stamp();
    tracing::info!(
        target: "authz_e1",
        event,
        observation,
        request_id = stamp.request_id.as_deref().unwrap_or(""),
        process_observation_id = %stamp.process_observation_id,
        event_sequence = stamp.event_sequence,
        wall_unix_ns = %stamp.wall_unix_ns,
        tenant_id,
        card_id,
        outcome,
        pending = ?pending,
        "e1 authorization observation"
    );
}

/// 轻读卡作用域缓存栅栏快照（缓存命中校验的栅栏输入；无锁）。
///
/// 该读不是授权事实：进程内 evidence 缓存（`crate::evidence_cache`）的命中校验
/// 以它为对牌基准——快照逐字段相等（版本组含集合形状与 pending 位）才允许
/// 命中，且命中前还会复核一次栅栏未漂移；miss 时一律
/// 回到严格 evidence reader（锁定 + 整链校验 + source-freshness 门）取数。
pub async fn load_card_scope_fence_snapshot(
    pool: &MySqlPool,
    tenant_id: i64,
    card_id: i64,
) -> Result<CardScopeFenceSnapshot, DbError> {
    #[cfg(feature = "e1-observability")]
    log_e1_fence_observation(
        "authoritative_read_start",
        "cache_manifest",
        tenant_id,
        card_id,
        "started",
        None,
    );
    let rows_result = sqlx::query_as::<_, PointerFenceSqlRow>(POINTER_FENCE_VERSIONS_SQL)
        .bind(tenant_id)
        .bind(card_id)
        .fetch_all(pool)
        .await;
    #[cfg(feature = "e1-observability")]
    log_e1_fence_observation(
        "authoritative_read_end",
        "cache_manifest",
        tenant_id,
        card_id,
        if rows_result.is_ok() { "ok" } else { "error" },
        None,
    );
    let rows = rows_result?;
    let manifest_versions = decode_pointer_fence_rows(rows)?;
    #[cfg(feature = "e1-observability")]
    log_e1_fence_observation(
        "authoritative_read_start",
        "cache_pending_probe",
        tenant_id,
        card_id,
        "started",
        None,
    );
    let pending_result: Result<(i64,), sqlx::Error> = sqlx::query_as(PENDING_DELTA_PROBE_SQL)
        .bind(tenant_id)
        .bind(card_id)
        .fetch_one(pool)
        .await;
    #[cfg(feature = "e1-observability")]
    log_e1_fence_observation(
        "authoritative_read_end",
        "cache_pending_probe",
        tenant_id,
        card_id,
        if pending_result.is_ok() {
            "ok"
        } else {
            "error"
        },
        pending_result.as_ref().ok().map(|row| row.0 != 0),
    );
    let (pending,) = pending_result?;
    Ok(CardScopeFenceSnapshot {
        manifest_versions,
        card_source_pending: pending != 0,
    })
}

/// Read effective permissions exclusively from CURRENT V6 published evidence.
///
/// The process-local evidence L1 is fenced by current pointer versions, pending
/// source deltas, read-before/read-after checks, and evidence validity windows.
/// A miss or fence drift falls back only to the strict published-evidence reader.
pub async fn find_effective_permissions_cached(
    pool: &MySqlPool,
    card_id: i64,
) -> Result<Vec<PermissionGrantRow>, DbError> {
    let Some(tenant_id) = load_single_card_tenant(pool, card_id).await? else {
        tracing::debug!(
            card_id,
            "card tenant missing or non-positive, returning safe permission miss"
        );
        return Ok(Vec::new());
    };
    find_effective_permissions_for_tenant(pool, tenant_id, card_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    use astral_types::{
        CanonicalGrant, GrantEffect, GrantId, GrantProvenance, GrantRevision, GrantState,
        PublicationSeal, PublishedAggregateManifestSummary, PublishedCardAuthorizationGate,
        PublishedEvidenceGateStatus, TenantScope, UnacceptedGrantReason, ValidityWindow,
        VerifiedPublishedGrantRecord,
    };

    // ===== 卡摘要：published card evidence 纯派生测试（无 I/O）=====

    fn fixed_grant_id(seed: u32) -> String {
        format!("00000000-0000-4000-8000-{seed:012}")
    }

    fn published_grant(
        grant_id: &str,
        source_kind: GrantSourceKind,
        binding_layer: BindingLayer,
        action: &str,
    ) -> CanonicalGrant {
        CanonicalGrant {
            grant_id: GrantId::parse(grant_id).expect("valid grant id"),
            revision: GrantRevision::new(1).expect("valid revision"),
            state: GrantState::Active,
            source_kind,
            binding_layer,
            tenant: TenantScope::new(7, Some(11)).expect("valid tenant scope"),
            card_id: 1,
            user_id: 1,
            resource: "learn_subject:*".to_string(),
            action: action.to_string(),
            effect: GrantEffect::Allow,
            validity: ValidityWindow::perpetual(),
            provenance: GrantProvenance {
                source_id: "source-1".to_string(),
                source_entry: Some("entry-1".to_string()),
                binding_id: (source_kind == GrantSourceKind::RuleSet)
                    .then(|| "binding-1".to_string()),
                delegation_id: (source_kind == GrantSourceKind::Delegation)
                    .then(|| "delegation-1".to_string()),
                operation_id: "op-1".to_string(),
                event_id: Some("event-1".to_string()),
                actor_user_id: None,
            },
        }
    }

    fn published_record(
        aggregate_type: &str,
        aggregate_id: i64,
        grant: CanonicalGrant,
        accepted: bool,
    ) -> VerifiedPublishedGrantRecord {
        VerifiedPublishedGrantRecord {
            aggregate_type: aggregate_type.to_string(),
            aggregate_id,
            publication_generation: 1,
            revoke_fence: 0,
            manifest_id: 1,
            event_id: "event-1".to_string(),
            operation_id: "op-1".to_string(),
            semantic_hash_hex: "a".repeat(64),
            dependency_hash_hex: "b".repeat(64),
            compiler_version: astral_types::AUTHORIZATION_COMPILER_VERSION.to_owned(),
            segment_ordinal: 0,
            position_in_segment: 0,
            grant,
            accepted_into_effective_set: accepted,
            unaccepted_reason: (!accepted).then_some(UnacceptedGrantReason::Expired),
        }
    }

    /// 手工 Ready 证据 fixture（仅测试用；真实构造者是严格 DB reader）。
    /// 每个 distinct 来源聚合补一个 manifest，使 fixture 始终满足合同校验。
    fn published_evidence(
        records: Vec<VerifiedPublishedGrantRecord>,
    ) -> PublishedCardAuthorization {
        let mut manifests: Vec<PublishedAggregateManifestSummary> = Vec::new();
        for record in &records {
            let origin_present = manifests.iter().any(|manifest| {
                manifest.aggregate_type == record.aggregate_type
                    && manifest.aggregate_id == record.aggregate_id
            });
            if !origin_present {
                manifests.push(PublishedAggregateManifestSummary {
                    seal: PublicationSeal::from_unix_seconds(1_700_000_000).unwrap(),
                    tenant_id: 7,
                    card_id: 1,
                    aggregate_type: record.aggregate_type.clone(),
                    aggregate_id: record.aggregate_id,
                    manifest_id: manifests.len() as i64 + 1,
                    generation: 1,
                    source_generation: 1,
                    projected_generation: 1,
                    revoke_fence: 0,
                    cas_version: 1,
                    semantic_hash_hex: "a".repeat(64),
                    dependency_hash_hex: "b".repeat(64),
                    manifest_digest_hex: "c".repeat(64),
                    compiler_version: astral_types::AUTHORIZATION_COMPILER_VERSION.to_owned(),
                    event_id: "event-1".to_string(),
                    operation_id: "op-1".to_string(),
                    parent_manifest_id: None,
                    segment_count: 1,
                    declared_grant_row_count: records.len() as u64,
                });
            }
        }
        let effective_grants: Vec<CanonicalGrant> = records
            .iter()
            .filter(|record| record.accepted_into_effective_set)
            .map(|record| record.grant.clone())
            .collect();
        let verified_record_count = records.len();
        let effective_grant_count = effective_grants.len();
        PublishedCardAuthorization {
            tenant_id: 7,
            card_id: 1,
            read_unix_seconds: 1_700_000_000,
            gate: PublishedCardAuthorizationGate {
                status: PublishedEvidenceGateStatus::Ready,
                aggregate_manifest_count: manifests.len(),
                verified_record_count,
                effective_grant_count,
                not_in_effective_count: verified_record_count - effective_grant_count,
                equivalent_duplicate_collapsed_count: 0,
            },
            manifests,
            records,
            effective_grants,
        }
    }

    #[test]
    fn summary_derives_actions_and_rule_set_layers_from_accepted_records() {
        let evidence = published_evidence(vec![
            published_record(
                "USER_CARD",
                1,
                published_grant(
                    &fixed_grant_id(1),
                    GrantSourceKind::Direct,
                    BindingLayer::None,
                    "read",
                ),
                true,
            ),
            // 同 action 的第二条 accepted 卡级贡献 → 去重
            published_record(
                "USER_CARD",
                1,
                published_grant(
                    &fixed_grant_id(2),
                    GrantSourceKind::Approval,
                    BindingLayer::None,
                    "read",
                ),
                true,
            ),
            published_record(
                "USER_CARD",
                1,
                published_grant(
                    &fixed_grant_id(3),
                    GrantSourceKind::Delegation,
                    BindingLayer::None,
                    "write",
                ),
                true,
            ),
            // 规则集贡献的 action 不进 action_codes，只归入规则集 id 分组
            published_record(
                "RULE_SET",
                10,
                published_grant(
                    &fixed_grant_id(4),
                    GrantSourceKind::RuleSet,
                    BindingLayer::Base,
                    "read",
                ),
                true,
            ),
            published_record(
                "RULE_SET",
                3,
                published_grant(
                    &fixed_grant_id(5),
                    GrantSourceKind::RuleSet,
                    BindingLayer::Base,
                    "delete",
                ),
                true,
            ),
            published_record(
                "RULE_SET",
                7,
                published_grant(
                    &fixed_grant_id(6),
                    GrantSourceKind::RuleSet,
                    BindingLayer::Base,
                    "export",
                ),
                true,
            ),
            published_record(
                "RULE_SET",
                7,
                published_grant(
                    &fixed_grant_id(7),
                    GrantSourceKind::RuleSet,
                    BindingLayer::Overlay,
                    "admin",
                ),
                true,
            ),
            // 被安全排除（过期）的记录绝不参与摘要
            published_record(
                "USER_CARD",
                1,
                published_grant(
                    &fixed_grant_id(8),
                    GrantSourceKind::Direct,
                    BindingLayer::None,
                    "secret",
                ),
                false,
            ),
            published_record(
                "RULE_SET",
                9,
                published_grant(
                    &fixed_grant_id(9),
                    GrantSourceKind::RuleSet,
                    BindingLayer::Overlay,
                    "hidden",
                ),
                false,
            ),
        ]);
        // fixture 自身必须始终满足 evidence 合同，防止测试随合同漂移。
        let contract = evidence.validate();
        assert!(contract.is_ok(), "fixture invalid: {contract:?}");

        let summary = card_permission_summary_from_evidence(&evidence)
            .expect("evidence shape must allow a summary")
            .expect("accepted records must produce a summary");
        assert_eq!(summary.action_codes.as_deref(), Some("read,write"));
        // 规则集 id 按数值升序（legacy GROUP_CONCAT ORDER BY rule_set_id 布局）
        assert_eq!(summary.base_rule_set_ids.as_deref(), Some("3,7,10"));
        assert_eq!(summary.overlay_rule_set_ids.as_deref(), Some("7"));
    }

    #[test]
    fn proven_empty_effective_surface_yields_no_summary() {
        // 零记录：Ready 空证据
        let empty = published_evidence(Vec::new());
        assert_eq!(
            card_permission_summary_from_evidence(&empty).expect("shape ok"),
            None
        );

        // 全部记录被安全排除：同样不产出（绝不伪造空 CSV 授权视图）
        let all_excluded = published_evidence(vec![published_record(
            "USER_CARD",
            1,
            published_grant(
                &fixed_grant_id(1),
                GrantSourceKind::Direct,
                BindingLayer::None,
                "read",
            ),
            false,
        )]);
        assert_eq!(
            card_permission_summary_from_evidence(&all_excluded).expect("shape ok"),
            None
        );
    }

    #[test]
    fn ruleset_grant_without_ruleset_aggregate_provenance_fails_the_summary() {
        let evidence = published_evidence(vec![published_record(
            "USER_CARD",
            1,
            published_grant(
                &fixed_grant_id(1),
                GrantSourceKind::RuleSet,
                BindingLayer::Base,
                "read",
            ),
            true,
        )]);
        assert_eq!(
            card_permission_summary_from_evidence(&evidence),
            Err(PublishedSummaryShapeError::RuleSetProvenanceMissing {
                grant_id: GrantId::parse(&fixed_grant_id(1))
                    .expect("valid grant id")
                    .to_string(),
            })
        );
    }

    #[test]
    fn ruleset_grant_without_binding_layer_fails_the_summary() {
        // 合同对齐本应禁止 RuleSet/None；此处验证派生层的纵深防御分支。
        let evidence = published_evidence(vec![published_record(
            "RULE_SET",
            7,
            published_grant(
                &fixed_grant_id(1),
                GrantSourceKind::RuleSet,
                BindingLayer::None,
                "read",
            ),
            true,
        )]);
        assert_eq!(
            card_permission_summary_from_evidence(&evidence),
            Err(PublishedSummaryShapeError::RuleSetLayerMissing {
                grant_id: GrantId::parse(&fixed_grant_id(1))
                    .expect("valid grant id")
                    .to_string(),
            })
        );
    }

    #[test]
    fn sorted_csv_is_deterministic_and_never_empty_string() {
        // 调用方以 BTreeSet 预排序去重；sorted_csv 只负责连接。
        assert_eq!(
            sorted_csv(["b", "a", "b"].into_iter().collect::<BTreeSet<_>>().iter()),
            Some("a,b".to_string())
        );
        // 数值序来自调用方的 BTreeSet<i64>：词法序会把 10 排在 2 前，数值序不会。
        assert_eq!(
            sorted_csv([10_i64, 9_i64, 2_i64].into_iter().collect::<BTreeSet<_>>()),
            Some("2,9,10".to_string())
        );
        assert_eq!(sorted_csv(Vec::<&str>::new()), None);
    }

    // ===== Published-evidence permission derivation tests =====

    #[test]
    fn enabled_rule_set_filter_is_tenant_scoped_and_fail_closed() {
        assert!(tenant_stamp_matches(None, None));
        assert!(tenant_stamp_matches(Some(7), Some(7)));
        assert!(!tenant_stamp_matches(None, Some(7)));
        assert!(!tenant_stamp_matches(Some(7), None));
        assert!(!tenant_stamp_matches(Some(7), Some(8)));
        assert!(enabled_rule_set_row_is_allowed(1, Some(7), 7));
        assert!(!enabled_rule_set_row_is_allowed(0, Some(7), 7));
        assert!(!enabled_rule_set_row_is_allowed(1, Some(8), 7));
        assert!(!enabled_rule_set_row_is_allowed(1, None, 7));
        assert!(!enabled_rule_set_row_is_allowed(1, Some(7), 8));
    }

    #[test]
    fn malformed_or_duplicate_manifest_cannot_produce_a_cache_baseline() {
        let valid = published_evidence(vec![published_record(
            "USER_CARD",
            1,
            published_grant(
                &fixed_grant_id(1),
                GrantSourceKind::Direct,
                BindingLayer::None,
                "read",
            ),
            true,
        )]);
        assert!(evidence_fence_baseline(&valid).is_ok());
        let mut invalid = valid.clone();
        invalid.manifests[0].manifest_digest_hex = "invalid".to_owned();
        assert!(evidence_fence_baseline(&invalid).is_err());
        invalid = valid.clone();
        invalid.manifests[0].generation = 0;
        assert!(evidence_fence_baseline(&invalid).is_err());
        invalid = valid;
        invalid.manifests.push(invalid.manifests[0].clone());
        assert!(evidence_fence_baseline(&invalid).is_err());
    }

    /// 源码形状守卫：pending 位轻探针必须与严格 reader 的 source-freshness 门
    /// 同谓词形状——撤权类（REMOVE/REVOKE 或 fence 超前已发布水位）、覆盖
    /// 卡作用域与 aggregate-wide（NULL card）、NULL-safe 水位关联，且保持
    /// 非锁定（轻探针在缓存命中协议的读前/读后双读中执行，锁定读会拖垮
    /// 命中路径）。
    #[test]
    fn pending_delta_probe_shape_matches_the_strict_freshness_gate() {
        for required in [
            "status <> 'SUCCEEDED'",
            "invalidates_published_evidence <> 0",
            "event_type IN ('REMOVE', 'REVOKE')",
            "revoke_fence > COALESCE",
            "(card_id = ? OR card_id IS NULL)",
            "p.card_id <=> authorization_delta_event.card_id",
        ] {
            assert!(
                PENDING_DELTA_PROBE_SQL.contains(required),
                "pending probe is missing freshness fragment: {required}"
            );
            assert!(
                crate::authorization_projection_repository::FRESHNESS_GATE_PROBE_SQL
                    .contains(required),
                "strict reader probe is missing freshness fragment: {required}"
            );
        }
        assert!(PENDING_DELTA_PROBE_SQL.contains("status <> 'SUCCEEDED'"));
        assert!(PENDING_DELTA_PROBE_SQL.contains("event_type IN ('REMOVE', 'REVOKE')"));
        assert!(PENDING_DELTA_PROBE_SQL.contains("revoke_fence > COALESCE"));
        // 2026-09-04 修订：必须同时覆盖卡作用域与 aggregate-wide（NULL card）。
        assert!(PENDING_DELTA_PROBE_SQL.contains("(card_id = ? OR card_id IS NULL)"));
        // 水位关联 NULL-safe（<=>）：NULL card 行对 NULL card 已发布水位比较。
        assert!(PENDING_DELTA_PROBE_SQL.contains("p.card_id <=> authorization_delta_event.card_id"));
        assert!(!PENDING_DELTA_PROBE_SQL.contains("p.card_id = authorization_delta_event"));
        // 轻探针必须非锁定（严格 reader 的锁定纪律不适用于缓存命中路径）。
        assert!(!PENDING_DELTA_PROBE_SQL.contains("FOR UPDATE"));
    }
}
