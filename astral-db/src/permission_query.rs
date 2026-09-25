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
//! [`crate::evidence_cache::cached_load_published_card_grant_evidence`] ——
//! 命中前提是"指针对牌"（当前指针版本组 + 共享缓存时代与填充时刻逐项相等，
//! 命中前复读一次栅栏未漂移）；miss/漂移回源严格 reader 取数。正确性论证
//! 与失效语义见 `crate::evidence_cache` 模块文档。
//! 2. 读侧纵深防御（对齐旧读链 SQL 的 `rs.enabled = 1` 防线）：RULE_SET 来源
//!    的生效 grant 在读取时再按 `rule_set.enabled = 1` + 租户戳过滤；绑定引用
//!    中存在缺失/禁用/租户戳不匹配的 rule set 时拒绝信任缓存。发布侧对
//!    "入账后 rule_set 被禁用"目前没有运行时防线（仓内不存在 enabled 置 0 的
//!    写路径，该形状只能来自 legacy/外部写入），此过滤是唯一的防线；
//!    【后续项】发布侧应在 rule_set 禁用流转时对已入账贡献做 REMOVE/REVOKE
//!    物化，读侧过滤届时退化为纯纵深防御。
//!
//! Cache-Aside（`find_effective_permissions_cached`）：对齐 Java `findSnapshot`
//! 缓存语义 —— Redis `perm:card:[tenantId:]cardId` Hash，field
//! `snapshot:{resourceType}:{actionCode}`；缓存 envelope（schema_version=5）
//! 携带 evidence 各已发布聚合的版本组（generation + revoke_fence）、卡作用域
//! 未发布 delta 位（`card_source_pending`，撤销类变更的越权窗口内全部 miss）
//! 作栅栏，任一聚合发布推进即自动 miss；同时携带共享缓存时代
//! （`crate::cache_epoch`，整库恢复/重建后运维换时代 → 携带旧时代的条目全部
//! miss）；空授权仍写 metadata-only 合法命中；evidence `NotReady`/`Corrupt`
//! 一律空结果 fail-closed，绝不写缓存。
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
use redis::AsyncCommands;
use sqlx::{MySqlPool, QueryBuilder};
use time::OffsetDateTime;

use crate::authorization_projection_repository::AuthorizationEvidenceError;
use crate::evidence_cache::cached_load_published_card_grant_evidence;
use crate::DbError;

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

fn snapshot_window_is_active(
    valid_from_ts: Option<i64>,
    valid_to_ts: Option<i64>,
    now_secs: i64,
) -> bool {
    valid_from_ts.is_none_or(|valid_from| now_secs >= valid_from)
        && valid_to_ts.is_none_or(|valid_to| now_secs <= valid_to)
}

/// 查询卡的有效权限（evidence 派生；Redis 不可用时的权威回退路径）。
///
/// 语义与 [`find_effective_permissions_cached`] 的回源路径完全一致：不读
/// legacy 快照表，不受 head gate 约束，只信严格 reader 产出的已发布证据。
pub async fn find_effective_permissions_from_snapshot(
    pool: &MySqlPool,
    card_id: i64,
) -> Result<Vec<PermissionGrantRow>, DbError> {
    let Some(tenant_id) = load_single_card_tenant(pool, card_id).await? else {
        return Ok(Vec::new());
    };
    Ok(
        find_effective_permissions_for_tenant(pool, tenant_id, card_id)
            .await?
            .grants,
    )
}

/// 一次有效权限读取的产物：授权行 + 证据版本组（缓存栅栏输入）。
///
/// `manifest_versions` 为空当且仅当本次读取未成功消费 Ready 证据
/// （fail-closed 路径），调用方据此跳过缓存写回。
#[derive(Debug, Clone, PartialEq, Eq)]
struct EffectivePermissionRead {
    grants: Vec<PermissionGrantRow>,
    manifest_versions: Vec<PermissionCacheManifestVersion>,
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
) -> Result<EffectivePermissionRead, DbError> {
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
            return Ok(EffectivePermissionRead {
                grants: Vec::new(),
                manifest_versions: Vec::new(),
            });
        }
        Err(AuthorizationEvidenceError::Corrupt(detail)) => {
            tracing::warn!(
                card_id,
                detail = detail.as_str(),
                "published card evidence corrupt, returning safe permission miss (reconciliation required)"
            );
            return Ok(EffectivePermissionRead {
                grants: Vec::new(),
                manifest_versions: Vec::new(),
            });
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
        return Ok(EffectivePermissionRead {
            grants: Vec::new(),
            manifest_versions: Vec::new(),
        });
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
            return Ok(EffectivePermissionRead {
                grants: Vec::new(),
                manifest_versions: Vec::new(),
            });
        }
    };
    let manifest_versions = evidence_manifest_versions(&evidence);
    Ok(EffectivePermissionRead {
        grants,
        manifest_versions,
    })
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

/// 绑定引用行：`(rule_set_id, ref_tenant_id, rule_set_enabled, rule_set_tenant_id)`。
type RuleSetBindingRow = (i64, Option<i64>, Option<i8>, Option<i64>);

/// 缓存信任门禁：绑定引用中不可信 rule set 的 id 清单（升序去重）。
///
/// 引用对应的 rule set 缺失、`enabled != 1`、rule set 租户戳与引用租户戳
/// 不匹配、或引用租户戳与卡租户不匹配时该引用不可信。缓存载荷不携带
/// per-grant 的 rule set 来源，存在任何不可信引用时必须整体拒绝缓存
/// （对齐旧链 `rule_set_active` 缓存守卫），回退 evidence 读侧过滤。
async fn load_unsafe_rule_set_binding_ids(
    pool: &MySqlPool,
    card_id: i64,
    card_tenant_id: i64,
) -> Result<Vec<i64>, DbError> {
    let rows: Vec<RuleSetBindingRow> = sqlx::query_as(
        "SELECT crsrf.rule_set_id, crsrf.tenant_id, rs.enabled, rs.tenant_id \
         FROM card_rule_set_ref crsrf \
         LEFT JOIN rule_set rs ON rs.rule_set_id = crsrf.rule_set_id \
         WHERE crsrf.card_id = ?",
    )
    .bind(card_id)
    .fetch_all(pool)
    .await?;

    let mut unsafe_ids: Vec<i64> = rows
        .into_iter()
        .filter(|(_, ref_tenant_id, rule_set_enabled, rule_set_tenant_id)| {
            rule_set_binding_is_unsafe(
                *ref_tenant_id,
                *rule_set_enabled,
                *rule_set_tenant_id,
                card_tenant_id,
            )
        })
        .map(|(rule_set_id, _, _, _)| rule_set_id)
        .collect();
    unsafe_ids.sort_unstable();
    unsafe_ids.dedup();
    Ok(unsafe_ids)
}

/// 单条绑定引用是否不可信（纯逻辑）：rule set 缺失（enabled 为 NULL）、
/// `enabled != 1`、引用租户戳与卡租户不匹配、或 rule set 租户戳与引用租户戳
/// 不匹配，均视为不可信（对齐旧读链 SQL 的 `rs.enabled = 1` 与两级
/// `tenant_id <=>` 纵深防御）。
fn rule_set_binding_is_unsafe(
    ref_tenant_id: Option<i64>,
    rule_set_enabled: Option<i8>,
    rule_set_tenant_id: Option<i64>,
    card_tenant_id: i64,
) -> bool {
    rule_set_enabled != Some(1)
        || !tenant_stamp_matches(ref_tenant_id, Some(card_tenant_id))
        || !tenant_stamp_matches(rule_set_tenant_id, ref_tenant_id)
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
/// [`load_published_card_grant_evidence`] 在单个短事务内按
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
/// [`card_permission_summary_from_evidence`]）：
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

// ===== 读侧投影缓存（对齐 Java PermissionSnapshotService.findSnapshot Cache-Aside）=====

// 旧 head/snapshot 读链的 `ProjectionStatus`（head READY + source==projected 门禁）
// 随本批次读链切换移除：evidence 读链的发布事实以 `authorization_projection_current`
// 指针版本组 + 卡作用域未发布 delta 位为准（见下方 envelope v5），不再读取
// `authorization_projection_head`。

/// 读侧投影缓存 key（对齐 Java PermissionCacheService：`perm:card:[tenantId:]cardId`）。
pub fn permission_cache_key(card_id: i64, tenant_id: Option<i64>) -> String {
    match tenant_id {
        Some(tid) => format!("perm:card:{tid}:{card_id}"),
        None => format!("perm:card:{card_id}"),
    }
}

// 旧 v2 兼容函数 `is_cache_version_compatible`（head 三版本逐项匹配）随旧
// 读链一并退役：envelope 兼容判定见 [`cache_envelope_is_compatible`]。

/// 缓存 envelope 版本 5：栅栏 = 共享缓存时代 + evidence 各已发布聚合的版本组
/// + **卡作用域未发布 delta 位**（`card_source_pending`）。
///
/// 相对 v4 新增 `card_source_pending`：source mutation 已提交而发布未完成/
/// 未成功时（存在非 `SUCCEEDED` 的本卡 delta），旧代证据对撤销类变更即越权，
/// 该位使全部 L1/L2 条目在 source 提交瞬间失配 miss → 回源严格 reader 撞
/// source-freshness 门（PENDING）。旧 v4 载荷反序列化时缺该必填字段直接
/// 失败 → 自动 miss 并被重写覆盖（一次性自愈，无需人工清缓存）。
///
/// 更早的 v2（head 三版本 + rule_set_versions）与 v3（无 cache_epoch）随历史
/// 读链一并退役。
const EFFECTIVE_PERMISSION_CACHE_SCHEMA: i64 = 5;
const CACHE_METADATA_FIELD: &str = "__metadata";

/// 卡作用域缓存栅栏快照：逐聚合指针版本组 + 卡级"存在撤权类未发布 delta"位。
///
/// 进程内 evidence 缓存（`crate::evidence_cache`）与 Redis envelope 的命中
/// 校验都以本快照为对牌基准——**逐字段相等**（含集合形状与 pending 位）才
/// 允许命中，且命中后还会复读复核一次；miss 一律回到严格 evidence reader
/// （锁定 + 整链校验 + source-freshness 门）取数。
///
/// `card_source_pending` 的填充侧基准恒为 `false`：严格 reader 门禁通过 ⟺
/// 此刻不存在撤权类（REMOVE/REVOKE 或 fence 超前）未发布 delta；此后此类
/// delta 落库使现场读变 `true` → 与基线失配 → 全部缓存条目立即 miss。
/// 纯 ADD/UPDATE 类未发布 delta 不置位（deny-biased EC：缺新授权/收窄窗口
/// 由发布收敛，写突发不得自饥饿——P3 风暴实测教训）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardScopeFenceSnapshot {
    /// 按 `(aggregate_type, aggregate_id)` 升序的指针版本组。
    pub manifest_versions: Vec<PermissionCacheManifestVersion>,
    /// 本卡作用域存在未发布（非 `SUCCEEDED`）授权 delta（现场读）；填充侧
    /// 基准恒为 `false`（严格 reader 门禁通过后的证据才允许入缓存）。
    pub card_source_pending: bool,
}

/// 单个已发布聚合的缓存栅栏版本（对应 evidence manifest 摘要与
/// `authorization_projection_current` 指针行的同名字段）。
///
/// `manifest_id` 来自指针行同名列 / evidence manifest 摘要：同一 generation 下
/// 指针被重写到另一条 COMMITTED manifest（病态重写）或发布推进到新 manifest
/// 都会改变该值，对牌随之失败。该字段加入后，Redis v4 载荷中未携带
/// `manifest_id` 的旧 `manifest_versions` 条目在读取侧反序列化失败 → 自动
/// miss 并被重写覆盖（一次性自愈，无需人工清缓存；schema_version 保持 4）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PermissionCacheManifestVersion {
    pub aggregate_type: String,
    pub aggregate_id: i64,
    pub manifest_id: i64,
    pub generation: u64,
    pub revoke_fence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct PermissionCacheEnvelope {
    schema_version: i64,
    /// 按 `(aggregate_type, aggregate_id)` 升序的版本组；任一聚合发布推进
    /// （generation 或 revoke_fence 变化）即令旧缓存失效。
    manifest_versions: Vec<PermissionCacheManifestVersion>,
    /// 本卡作用域存在未发布授权 delta（PENDING/LEASED/QUARANTINED）→ 旧代
    /// 证据不可信（撤销类变更越权窗口）。v5 新增必填字段：旧 v4 载荷缺字段
    /// 反序列化失败 → 自动 miss 重写。
    card_source_pending: bool,
    /// 写入时刻的共享缓存时代（`crate::cache_epoch`；键格式不变，Java 契约
    /// 键不受影响）。整库恢复/重建后运维 `DEL astral:auth:cache_epoch` 换
    /// 时代，携带旧时代的条目在读取侧 epoch 不等 → miss 重写。
    cache_epoch: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PermissionCacheEntry {
    #[serde(flatten)]
    envelope: PermissionCacheEnvelope,
    effect: String,
    valid_from_ts: Option<i64>,
    valid_to_ts: Option<i64>,
}

/// 从 Ready 证据提取缓存栅栏版本组（manifests 已按聚合身份升序，这里防御性
/// 重排一次，保证写侧与读侧比较形状逐字节一致）。
///
/// 供 Redis envelope 与进程内 evidence 缓存（`crate::evidence_cache`）共用：
/// 两条读侧栅栏的比较基准必须同源同形，避免出现两套漂移的版本组定义。
pub(crate) fn evidence_manifest_versions(
    evidence: &PublishedCardAuthorization,
) -> Vec<PermissionCacheManifestVersion> {
    let mut versions: Vec<PermissionCacheManifestVersion> = evidence
        .manifests
        .iter()
        .map(|manifest| PermissionCacheManifestVersion {
            aggregate_type: manifest.aggregate_type.clone(),
            aggregate_id: manifest.aggregate_id,
            manifest_id: manifest.manifest_id,
            generation: manifest.generation,
            revoke_fence: manifest.revoke_fence,
        })
        .collect();
    versions.sort_by(|left, right| {
        left.aggregate_type
            .cmp(&right.aggregate_type)
            .then(left.aggregate_id.cmp(&right.aggregate_id))
    });
    versions
}

/// 从 Ready 证据提取完整缓存栅栏快照（版本组 + pending 位基准）。
///
/// 填充侧 `card_source_pending` 恒为 `false`：该证据只能来自通过
/// source-freshness 门禁的严格 reader（存在未发布 delta 时 reader 返回
/// `NotReady`，根本没有证据可填），因此基线永远声明"无未发布 delta"；此后
/// 现场读翻为 `true` 即与基线失配 → 缓存整体 miss → 回源撞门。
pub(crate) fn evidence_fence_baseline(
    evidence: &PublishedCardAuthorization,
) -> CardScopeFenceSnapshot {
    CardScopeFenceSnapshot {
        manifest_versions: evidence_manifest_versions(evidence),
        card_source_pending: false,
    }
}

/// 从当前指针行（轻读、无锁）提取缓存命中校验用的版本组；与
/// [`evidence_manifest_versions`] 同形状。generation/fence 为负数只可能是
/// 损坏状态，折叠为 `u64::MAX` 哨兵——永远无法与真实 envelope 匹配，从而
/// miss 进入严格 evidence 读链 fail-closed。`manifest_id` 为 i64 直通（两侧
/// 同为 i64，无需折叠）：损坏的负值只会与合法 evidence 的正 manifest_id
/// 失配 → miss 回源 → 严格 reader 以 Corrupt fail-closed。
fn pointer_fence_version(
    aggregate_type: String,
    aggregate_id: i64,
    manifest_id: i64,
    current_generation: i64,
    revoke_fence: i64,
) -> PermissionCacheManifestVersion {
    PermissionCacheManifestVersion {
        aggregate_type,
        aggregate_id,
        manifest_id,
        generation: u64::try_from(current_generation).unwrap_or(u64::MAX),
        revoke_fence: u64::try_from(revoke_fence).unwrap_or(u64::MAX),
    }
}

/// 卡作用域指针版本组轻读（无锁、单条 SQL；`load_pointer_fence_versions`
/// 时代的既有查询原样保留，现作为栅栏快照的版本组分量）。
const POINTER_FENCE_VERSIONS_SQL: &str = "SELECT aggregate_type, aggregate_id, manifest_id, \
     current_generation, revoke_fence \
     FROM authorization_projection_current \
     WHERE tenant_id = ? AND card_id = ? \
     ORDER BY aggregate_type ASC, aggregate_id ASC";

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
/// 该读不是授权事实：进程内 evidence 缓存（`crate::evidence_cache`）与 Redis
/// envelope 的命中校验都以它为对牌基准——快照逐字段相等（版本组含集合形状
/// 与 pending 位）才允许命中，且命中前还会复核一次栅栏未漂移；miss 时一律
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
    let rows_result = sqlx::query_as(POINTER_FENCE_VERSIONS_SQL)
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
    let manifest_versions = rows
        .into_iter()
        .map(
            |(aggregate_type, aggregate_id, manifest_id, current_generation, revoke_fence)| {
                pointer_fence_version(
                    aggregate_type,
                    aggregate_id,
                    manifest_id,
                    current_generation,
                    revoke_fence,
                )
            },
        )
        .collect();
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

/// 缓存版本兼容性：schema 一致、版本组与当前指针逐项完全匹配、卡作用域无
/// 未发布 delta（pending 位一致）、且共享缓存时代一致（当前时代未知 = Redis
/// 降级 → 跳过 epoch 子校验，其余栅栏照常）。
fn cache_envelope_is_compatible(
    envelope: &PermissionCacheEnvelope,
    snapshot: &CardScopeFenceSnapshot,
    current_epoch: Option<&str>,
) -> bool {
    envelope.schema_version == EFFECTIVE_PERMISSION_CACHE_SCHEMA
        && envelope.manifest_versions == snapshot.manifest_versions
        && envelope.card_source_pending == snapshot.card_source_pending
        && crate::cache_epoch::cache_epoch_matches(current_epoch, envelope.cache_epoch.as_deref())
}

fn permission_cache_entry_is_readable(
    entry: &PermissionCacheEntry,
    metadata: &PermissionCacheEnvelope,
    now_secs: i64,
) -> bool {
    entry.effect == "ALLOW"
        && entry.envelope == *metadata
        && snapshot_window_is_active(entry.valid_from_ts, entry.valid_to_ts, now_secs)
}

/// 读卡有效权限（Cache-Aside，对齐 Java `PermissionSnapshotService.findSnapshot`）。
///
/// 读链语义（本批次起为 evidence 读链，替代旧 head/snapshot 读链）：
/// - 租户缺失/非正 → 空 vec fail-closed（无法构造 evidence scope）；
/// - 缓存信任门禁：绑定引用存在缺失/禁用/租户戳不匹配的 rule set 时拒绝
///   信任缓存（载荷无 per-grant rule set 来源），直接走 evidence 读侧过滤；
/// - 缓存栅栏 = 当前指针版本组 + 卡作用域未发布 delta 位 + 共享缓存时代
///   （envelope v5）；任一聚合发布推进、source 提交未发布（撤销类越权窗口）
///   或运维换时代即 miss；
/// - evidence `NotReady`/`Corrupt` → 空 vec fail-closed 且不写缓存；
/// - Redis 不可用时回退 [`find_effective_permissions_from_snapshot`]（同源
///   evidence 派生，语义对齐）。
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

    let redis_url = std::env::var("REDIS_URL")
        .or_else(|_| std::env::var("ASTRAL_REDIS_URL"))
        .unwrap_or_else(|_| "redis://localhost:6379".into());
    let Ok(client) = redis::Client::open(redis_url.as_str()) else {
        return Ok(
            find_effective_permissions_for_tenant(pool, tenant_id, card_id)
                .await?
                .grants,
        );
    };
    let Ok(mut conn) = client.get_connection_manager().await else {
        return Ok(
            find_effective_permissions_for_tenant(pool, tenant_id, card_id)
                .await?
                .grants,
        );
    };

    // 缓存信任门禁（对齐旧链 rule_set_active 守卫）：不可信引用在场时缓存
    // 载荷无法按来源过滤，整体旁路，回退 evidence 读侧过滤路径。
    let unsafe_binding_ids = load_unsafe_rule_set_binding_ids(pool, card_id, tenant_id).await?;
    if !unsafe_binding_ids.is_empty() {
        tracing::debug!(
            card_id,
            unsafe_rule_set_ids = ?unsafe_binding_ids,
            "unsafe rule set bindings present, bypassing permission cache"
        );
        return Ok(
            find_effective_permissions_for_tenant(pool, tenant_id, card_id)
                .await?
                .grants,
        );
    }

    let key = permission_cache_key(card_id, Some(tenant_id));
    let fence = load_card_scope_fence_snapshot(pool, tenant_id, card_id).await?;
    if let Some(grants) = read_permission_cache(&mut conn, &key, &fence).await {
        // 发布可能在两次栅栏读之间推进。命中后复核栅栏未漂移再返回，避免
        // 命中瞬间掠过的发布被旧缓存掩盖（对齐旧链 gate recheck 语义）。
        let rechecked_fence = load_card_scope_fence_snapshot(pool, tenant_id, card_id).await?;
        if rechecked_fence == fence {
            return Ok(grants);
        }
    }

    let read = find_effective_permissions_for_tenant(pool, tenant_id, card_id).await?;
    // manifest_versions 为空 ⟺ 未成功消费 Ready 证据（fail-closed），绝不写缓存。
    // 非空 ⟺ 严格 reader 的 source-freshness 门已通过（无未发布 delta），
    // 因此写入侧 pending 基线恒为 false。
    if !read.manifest_versions.is_empty() {
        write_permission_cache(
            &mut conn,
            &key,
            &CardScopeFenceSnapshot {
                manifest_versions: read.manifest_versions.clone(),
                card_source_pending: false,
            },
            &read.grants,
        )
        .await;
    }
    Ok(read.grants)
}

/// 读取权限缓存（key 不存在或版本组/pending 位/时代不匹配 → None；空授权是
/// 合法命中）。
async fn read_permission_cache(
    conn: &mut redis::aio::ConnectionManager,
    key: &str,
    snapshot: &CardScopeFenceSnapshot,
) -> Option<Vec<PermissionGrantRow>> {
    let exists: i64 = conn.exists(key).await.ok()?;
    if exists == 0 {
        return None;
    }
    let entries: HashMap<String, String> = conn.hgetall(key).await.ok()?;
    let metadata: PermissionCacheEnvelope =
        serde_json::from_str(entries.get(CACHE_METADATA_FIELD)?).ok()?;
    let current_epoch = crate::cache_epoch::current_cache_epoch().await;
    if !cache_envelope_is_compatible(&metadata, snapshot, current_epoch.as_deref()) {
        return None;
    }

    let mut grants = Vec::new();
    for (field, value) in &entries {
        let Some(suffix) = field.strip_prefix("snapshot:") else {
            continue;
        };
        let mut parts = suffix.splitn(2, ':');
        let (Some(resource_type), Some(action_code)) = (parts.next(), parts.next()) else {
            return None;
        };
        let entry: PermissionCacheEntry = serde_json::from_str(value).ok()?;
        let now_secs = OffsetDateTime::now_utc().unix_timestamp();
        if !permission_cache_entry_is_readable(&entry, &metadata, now_secs) {
            return None;
        }
        grants.push(PermissionGrantRow {
            resource_type: resource_type.to_string(),
            action_code: action_code.to_string(),
            valid_from_ts: entry.valid_from_ts,
            valid_to_ts: entry.valid_to_ts,
        });
    }

    // A metadata-only hash is the durable representation of an empty
    // projected permission set; it must remain a valid fenced cache hit.
    grants.sort_by(|a, b| {
        a.resource_type
            .cmp(&b.resource_type)
            .then(a.action_code.cmp(&b.action_code))
    });
    grants.dedup();
    Some(grants)
}

/// Write back a fenced cache payload (Hash + TTL 3600 + jitter 60s).
/// Empty grants still write the metadata field so an empty authorization
/// surface cannot be confused with a missing cache entry or bypass the fence.
/// The envelope carries the current shared cache epoch so a post-restore
/// epoch rotation invalidates every payload written before it.
async fn write_permission_cache(
    conn: &mut redis::aio::ConnectionManager,
    key: &str,
    snapshot: &CardScopeFenceSnapshot,
    grants: &[PermissionGrantRow],
) {
    let cache_epoch = crate::cache_epoch::current_cache_epoch().await;
    let envelope = PermissionCacheEnvelope {
        schema_version: EFFECTIVE_PERMISSION_CACHE_SCHEMA,
        manifest_versions: snapshot.manifest_versions.clone(),
        card_source_pending: snapshot.card_source_pending,
        cache_epoch,
    };
    let metadata = serde_json::to_string(&envelope).unwrap_or_default();
    if metadata.is_empty() {
        return;
    }
    let mut fields = vec![(CACHE_METADATA_FIELD.to_string(), metadata)];
    fields.extend(grants.iter().map(|g| {
        let field = format!("snapshot:{}:{}", g.resource_type, g.action_code);
        let value = serde_json::json!({
            "effect": "ALLOW",
            "valid_from_ts": g.valid_from_ts,
            "valid_to_ts": g.valid_to_ts,
            "schema_version": envelope.schema_version,
            "manifest_versions": envelope.manifest_versions.clone(),
            "card_source_pending": envelope.card_source_pending,
            "cache_epoch": envelope.cache_epoch.clone(),
        });
        (field, value.to_string())
    }));
    let ttl = 3600 + jitter_secs();
    let mut pipeline = redis::pipe();
    pipeline
        .atomic()
        .cmd("DEL")
        .arg(key)
        .ignore()
        .cmd("HSET")
        .arg(key);
    for (field, value) in &fields {
        pipeline.arg(field).arg(value);
    }
    pipeline
        .ignore()
        .cmd("EXPIRE")
        .arg(key)
        .arg(ttl as i64)
        .ignore();
    let _: Result<(), _> = pipeline.query_async(conn).await;
}

/// TTL jitter（0-59s，避免整点雪崩；不引入 rand 依赖）
fn jitter_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64
        % 60
}

#[cfg(test)]
mod tests {
    use super::*;

    use astral_types::{
        CanonicalGrant, GrantEffect, GrantId, GrantProvenance, GrantRevision, GrantState,
        PublishedAggregateManifestSummary, PublishedCardAuthorizationGate,
        PublishedEvidenceGateStatus, TenantScope, UnacceptedGrantReason, ValidityWindow,
        VerifiedPublishedGrantRecord,
    };

    #[test]
    fn cache_key_matches_java_layout() {
        assert_eq!(permission_cache_key(7, None), "perm:card:7");
        assert_eq!(permission_cache_key(7, Some(3)), "perm:card:3:7");
    }

    #[test]
    fn snapshot_window_boundaries_are_inclusive_and_expiry_is_fail_closed() {
        let now = 1_000;
        assert!(snapshot_window_is_active(None, None, now));
        assert!(snapshot_window_is_active(Some(now), Some(now), now));
        assert!(!snapshot_window_is_active(Some(now + 1), None, now));
        assert!(!snapshot_window_is_active(None, Some(now - 1), now));
    }

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
            compiler_version: "test".to_string(),
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
                    compiler_version: "test".to_string(),
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

    // ===== 有效权限映射与缓存 envelope v4 纯测试（无 I/O）=====

    /// 测试夹具共享时代（读写两侧一致即为"当前时代"）。
    const CACHE_EPOCH_FIXTURE: &str = "epoch-fixture-1";

    fn published_grant_with_validity(
        base: &CanonicalGrant,
        validity: ValidityWindow,
    ) -> CanonicalGrant {
        let mut grant = base.clone();
        grant.validity = validity;
        grant
    }

    #[test]
    fn permission_rows_map_from_accepted_records_and_filter_disabled_rule_sets() {
        let direct = published_record(
            "USER_CARD",
            1,
            published_grant(
                &fixed_grant_id(1),
                GrantSourceKind::Direct,
                BindingLayer::None,
                "read",
            ),
            true,
        );
        // 同 (type, action) 的第二来源（APPROVAL）→ 去重保留确定性顺序首行窗口
        let approval = published_record(
            "USER_CARD",
            1,
            published_grant_with_validity(
                &published_grant(
                    &fixed_grant_id(2),
                    GrantSourceKind::Approval,
                    BindingLayer::None,
                    "read",
                ),
                ValidityWindow::between(100, 200),
            ),
            true,
        );
        // enabled 规则集来源 → 参与授权行
        let ruleset_enabled = published_record(
            "RULE_SET",
            10,
            published_grant(
                &fixed_grant_id(3),
                GrantSourceKind::RuleSet,
                BindingLayer::Base,
                "export",
            ),
            true,
        );
        // disabled（未通过 enabled 集合）规则集来源 → 读侧排除
        let ruleset_disabled = published_record(
            "RULE_SET",
            11,
            published_grant(
                &fixed_grant_id(4),
                GrantSourceKind::RuleSet,
                BindingLayer::Base,
                "secret",
            ),
            true,
        );
        // 被安全排除（过期）的记录绝不参与授权行
        let excluded = published_record(
            "USER_CARD",
            1,
            published_grant(
                &fixed_grant_id(5),
                GrantSourceKind::Direct,
                BindingLayer::None,
                "hidden",
            ),
            false,
        );
        let evidence = published_evidence(vec![
            direct,
            approval,
            ruleset_enabled,
            ruleset_disabled,
            excluded,
        ]);
        let contract = evidence.validate();
        assert!(contract.is_ok(), "fixture invalid: {contract:?}");

        let allowed = std::collections::HashSet::from([10_i64]);
        let rows = permission_grant_rows_from_evidence(&evidence, &allowed).expect("shape ok");
        // 输出按 (resource_type, action_code) 升序；"read" 去重后保留首行
        // （DIRECT, perpetual）窗口；disabled 来源与被排除记录不出现。
        assert_eq!(
            rows,
            vec![
                PermissionGrantRow {
                    resource_type: "learn_subject".to_string(),
                    action_code: "export".to_string(),
                    valid_from_ts: None,
                    valid_to_ts: None,
                },
                PermissionGrantRow {
                    resource_type: "learn_subject".to_string(),
                    action_code: "read".to_string(),
                    valid_from_ts: None,
                    valid_to_ts: None,
                },
            ]
        );
    }

    #[test]
    fn ruleset_grant_without_ruleset_aggregate_provenance_fails_rows() {
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
            permission_grant_rows_from_evidence(&evidence, &std::collections::HashSet::new()),
            Err(PublishedGrantShapeError::RuleSetProvenanceMissing {
                grant_id: GrantId::parse(&fixed_grant_id(1))
                    .expect("valid grant id")
                    .to_string(),
            })
        );
    }

    #[test]
    fn cache_envelope_v5_fences_on_any_aggregate_version_or_pending_change() {
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
            published_record(
                "RULE_SET",
                10,
                published_grant(
                    &fixed_grant_id(2),
                    GrantSourceKind::RuleSet,
                    BindingLayer::Base,
                    "export",
                ),
                true,
            ),
        ]);
        // 填充侧基准：pending 恒为 false（严格 reader 门禁通过后才可能有证据）。
        let baseline = evidence_fence_baseline(&evidence);
        assert!(!baseline.card_source_pending);
        let versions = &baseline.manifest_versions;
        assert_eq!(versions.len(), 2);
        // 防御性重排：按 (aggregate_type, aggregate_id) 升序
        assert_eq!(versions[0].aggregate_type, "RULE_SET");
        assert_eq!(versions[0].aggregate_id, 10);
        assert_eq!(versions[1].aggregate_type, "USER_CARD");

        let envelope = PermissionCacheEnvelope {
            schema_version: EFFECTIVE_PERMISSION_CACHE_SCHEMA,
            manifest_versions: versions.clone(),
            card_source_pending: false,
            cache_epoch: Some(CACHE_EPOCH_FIXTURE.to_string()),
        };
        assert!(cache_envelope_is_compatible(
            &envelope,
            &baseline,
            Some(CACHE_EPOCH_FIXTURE)
        ));

        // 任一聚合 generation 推进 → 失效
        let mut advanced = baseline.clone();
        advanced.manifest_versions[0].generation += 1;
        assert!(!cache_envelope_is_compatible(
            &envelope,
            &advanced,
            Some(CACHE_EPOCH_FIXTURE)
        ));

        // 任一聚合 revoke_fence 变化 → 失效
        let mut revoked = baseline.clone();
        revoked.manifest_versions[1].revoke_fence += 1;
        assert!(!cache_envelope_is_compatible(
            &envelope,
            &revoked,
            Some(CACHE_EPOCH_FIXTURE)
        ));

        // 新聚合发布（版本组形状变化）→ 失效
        let mut added = baseline.clone();
        added
            .manifest_versions
            .push(PermissionCacheManifestVersion {
                aggregate_type: "APPROVAL".to_string(),
                aggregate_id: 3,
                manifest_id: 1,
                generation: 1,
                revoke_fence: 0,
            });
        assert!(!cache_envelope_is_compatible(
            &envelope,
            &added,
            Some(CACHE_EPOCH_FIXTURE)
        ));

        // source 提交未发布（pending 位翻转）→ 失效：撤销类变更的越权窗口内
        // 全部缓存条目立即 miss，回源撞 source-freshness 门。
        let mut pending = baseline.clone();
        pending.card_source_pending = true;
        assert!(!cache_envelope_is_compatible(
            &envelope,
            &pending,
            Some(CACHE_EPOCH_FIXTURE)
        ));

        // v2 / v3 旧载荷（schema_version=2/3）自动 miss
        for legacy_schema in [2, 3] {
            let mut legacy = envelope.clone();
            legacy.schema_version = legacy_schema;
            assert!(
                !cache_envelope_is_compatible(&legacy, &baseline, Some(CACHE_EPOCH_FIXTURE)),
                "legacy schema {legacy_schema} must miss"
            );
        }
    }

    #[test]
    fn cache_envelope_epoch_rotation_fences_known_epochs_only() {
        let baseline = CardScopeFenceSnapshot {
            manifest_versions: Vec::new(),
            card_source_pending: false,
        };
        let envelope = PermissionCacheEnvelope {
            schema_version: EFFECTIVE_PERMISSION_CACHE_SCHEMA,
            manifest_versions: baseline.manifest_versions.clone(),
            card_source_pending: baseline.card_source_pending,
            cache_epoch: Some(CACHE_EPOCH_FIXTURE.to_string()),
        };

        // 整库恢复/重建后运维换时代：携带旧时代的条目 → miss
        assert!(!cache_envelope_is_compatible(
            &envelope,
            &baseline,
            Some("rotated-epoch")
        ));
        // 当前时代未知（Redis 降级）→ 跳过 epoch 子校验，其余栅栏照常
        assert!(cache_envelope_is_compatible(&envelope, &baseline, None));

        // 条目未携带时代（写侧降级窗口）：两侧语义均放行（版本组栅栏兜底）
        let mut no_epoch = envelope.clone();
        no_epoch.cache_epoch = None;
        assert!(cache_envelope_is_compatible(
            &no_epoch,
            &baseline,
            Some(CACHE_EPOCH_FIXTURE)
        ));
        assert!(cache_envelope_is_compatible(&no_epoch, &baseline, None));
    }

    #[test]
    fn legacy_v3_v4_envelopes_miss_v5_read_side() {
        // v3 旧载荷（无 cache_epoch、无 card_source_pending）：v5 反序列化时
        // 缺必填字段直接失败 → 自动 miss 并被重写覆盖（根本进不了兼容判定）。
        let legacy_v3_json = r#"{"schema_version":3,"manifest_versions":[]}"#;
        assert!(
            serde_json::from_str::<PermissionCacheEnvelope>(legacy_v3_json).is_err(),
            "v3 payload must fail v5 deserialization (missing card_source_pending)"
        );

        // v4 载荷（schema + epoch + 版本组，无 card_source_pending）：同样缺
        // v5 必填字段 → 反序列化失败 → miss（一次性自愈，无需人工清缓存）。
        let legacy_v4_json = format!(
            r#"{{"schema_version":4,"manifest_versions":[],"cache_epoch":"{CACHE_EPOCH_FIXTURE}"}}"#
        );
        assert!(
            serde_json::from_str::<PermissionCacheEnvelope>(&legacy_v4_json).is_err(),
            "v4 payload must fail v5 deserialization (missing card_source_pending)"
        );

        // v5 完整载荷在相同输入下是合法命中。
        let v5_json = format!(
            r#"{{"schema_version":5,"manifest_versions":[],"card_source_pending":false,"cache_epoch":"{CACHE_EPOCH_FIXTURE}"}}"#
        );
        let decoded_v5: PermissionCacheEnvelope = serde_json::from_str(&v5_json).unwrap();
        let baseline = CardScopeFenceSnapshot {
            manifest_versions: Vec::new(),
            card_source_pending: false,
        };
        assert!(cache_envelope_is_compatible(
            &decoded_v5,
            &baseline,
            Some(CACHE_EPOCH_FIXTURE)
        ));
        // 现场翻 pending → miss。
        let mut pending = baseline.clone();
        pending.card_source_pending = true;
        assert!(!cache_envelope_is_compatible(
            &decoded_v5,
            &pending,
            Some(CACHE_EPOCH_FIXTURE)
        ));
    }

    #[test]
    fn cache_entry_validity_is_fail_closed_and_boundary_inclusive() {
        let metadata = PermissionCacheEnvelope {
            schema_version: EFFECTIVE_PERMISSION_CACHE_SCHEMA,
            manifest_versions: vec![PermissionCacheManifestVersion {
                aggregate_type: "USER_CARD".to_string(),
                aggregate_id: 1,
                manifest_id: 9,
                generation: 4,
                revoke_fence: 2,
            }],
            card_source_pending: false,
            cache_epoch: Some(CACHE_EPOCH_FIXTURE.to_string()),
        };
        let entry = PermissionCacheEntry {
            envelope: metadata.clone(),
            effect: "ALLOW".to_string(),
            valid_from_ts: Some(1_000),
            valid_to_ts: Some(1_000),
        };
        assert!(permission_cache_entry_is_readable(&entry, &metadata, 1_000));
        assert!(!permission_cache_entry_is_readable(
            &entry, &metadata, 1_001
        ));
        assert!(!permission_cache_entry_is_readable(&entry, &metadata, 999));

        let mut denied = entry.clone();
        denied.effect = "DENY".to_string();
        assert!(!permission_cache_entry_is_readable(
            &denied, &metadata, 1_000
        ));

        // entry 内嵌 envelope 与 metadata 漂移（例如部分写入）→ 不可读
        let mut drifted = entry.clone();
        drifted.envelope.manifest_versions[0].generation = 5;
        assert!(!permission_cache_entry_is_readable(
            &drifted, &metadata, 1_000
        ));
    }

    #[test]
    fn rule_set_binding_safety_is_null_safe_and_fail_closed() {
        // MySQL NULL 安全等值（<=>）的 Rust 语义
        assert!(tenant_stamp_matches(None, None));
        assert!(tenant_stamp_matches(Some(7), Some(7)));
        assert!(!tenant_stamp_matches(None, Some(7)));
        assert!(!tenant_stamp_matches(Some(7), None));
        assert!(!tenant_stamp_matches(Some(7), Some(8)));

        // enabled 行过滤：禁用 / 租户戳不匹配 / 平台规则集对租户卡 一律不通过
        assert!(enabled_rule_set_row_is_allowed(1, Some(7), 7));
        assert!(!enabled_rule_set_row_is_allowed(0, Some(7), 7));
        assert!(!enabled_rule_set_row_is_allowed(1, Some(8), 7));
        assert!(!enabled_rule_set_row_is_allowed(1, None, 7));
        assert!(!enabled_rule_set_row_is_allowed(1, Some(7), 8));

        // 缓存信任门禁：缺失/禁用/租户戳不匹配的绑定引用均不可信
        assert!(rule_set_binding_is_unsafe(None, None, None, 7));
        assert!(rule_set_binding_is_unsafe(Some(7), Some(0), Some(7), 7));
        assert!(rule_set_binding_is_unsafe(Some(8), Some(1), Some(8), 7));
        assert!(rule_set_binding_is_unsafe(Some(7), Some(1), Some(8), 7));
        assert!(!rule_set_binding_is_unsafe(Some(7), Some(1), Some(7), 7));
    }

    #[test]
    fn pointer_fence_version_folds_negative_into_unmatchable_sentinel() {
        let version = pointer_fence_version("USER_CARD".to_string(), 1, 9, 4, 2);
        assert_eq!(version.generation, 4);
        assert_eq!(version.revoke_fence, 2);
        assert_eq!(version.manifest_id, 9);

        // 负数代数/栅栏只可能是损坏状态：折叠为永不匹配的哨兵 → 缓存 miss
        let corrupt = pointer_fence_version("USER_CARD".to_string(), 1, 9, -1, -5);
        assert_eq!(corrupt.generation, u64::MAX);
        assert_eq!(corrupt.revoke_fence, u64::MAX);
        // manifest_id 为 i64 直通（无 u64 折叠）：负值只会与合法 evidence 失配
        assert_eq!(corrupt.manifest_id, 9);
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
