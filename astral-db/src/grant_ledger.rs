//! 授权账本公共组装层 — grant_ledger
//!
//! 这里是 astral-trustgraph `repository/grant_ledger_adapter.rs` 中规则集
//! （RULE_SET 来源）授权账本**纯组装层**与全部来源家族共用的低层组装 helper
//! 的单一事实源。identity 与 trustgraph 是两个独立服务二进制（服务互依禁止），
//! 但两者都会在各自的 source transaction 内物化模板 RuleSet 绑定的 ALLOW
//! 账本贡献；把"GrantIdentityKey → CanonicalGrant → GrantDelta + GrantEvidence"
//! 的组装与"贡献事件号派生"收敛到本模块，保证同一张卡的同一条目绑定在两个
//! 服务里得到逐字节一致的 grant_id / contribution event id / canonical payload，
//! 不会制造重复或冲突的账本身份。
//!
//! 本模块只做**无网络的纯 DTO 组装与错误映射**，不发起任何 SQL（仅
//! [`append_ruleset_grant_delta_in_tx`] 在调用方已持有的事务内追加 revision 与
//! delta event 两个写入）。业务身份（operation_id / event_id / grant_id /
//! aggregate identity）全部由调用链传入或由稳定 durable 事实确定性派生；这里
//! 绝不生成随机业务 identity。随机值只允许出现在更深层各自 owner 的职责里
//! （projection outbox event、worker lease token），它们以 durable 身份回传后
//! 仍通过本模块显式绑定。
//!
//! 无法证明的租户/用户/卡片/有效期/projection 身份一律 fail-closed
//! （`AstralError::Validation` / `AstralError::Internal`），不填假值、不回退
//! raw source。

use sqlx::MySql;

use astral_types::registry::build_resource_key;
use astral_types::{
    AstralError, BindingLayer, CanonicalGrant, DeltaEventIdentity, DependencyVector,
    DependencyVersion, GrantContractError, GrantDelta, GrantEffect, GrantEvidence, GrantId,
    GrantIdentityKey, GrantProvenance, GrantRevision, GrantSourceKind, GrantState, TenantScope,
    ValidityWindow,
};
use policy_engine::COMPILER_VERSION;
use sha2::{Digest, Sha256};
use time::{Date, Month, PrimitiveDateTime, Time};

/// 授权账本中规则集来源的聚合类型（受 `validated_aggregate_type` 字符集约束）。
pub const RULE_SET_AGGREGATE_TYPE: &str = "RULE_SET";

/// 依赖向量中 CARD 源流（source_generation/revoke_fence 绑定目标）的标识前缀。
const CARD_DEPENDENCY_PREFIX: &str = "card:";
/// 卡片承载作用域（binding_key）的稳定前缀。
const USER_CARD_BINDING_PREFIX: &str = "user-card:";
/// HTTP request-id 复用为 durable operation_id 时允许的最大长度（canonical 上限 64）。
///
/// 这是全仓操作身份宽度的单一事实源：外部显式 header、内部确定性派生 id 与
/// Java-owned `audit_log.request_id VARCHAR(64)` 共享同一 canonical 上限 —— 超过
/// 64 字节的 header 直接 Validation fail-closed（绝不截断/静默归一化），所有内部
/// 派生 id 格式必须保持 <64 字节（见各 derive_* 契约注释）。审计侧统一入口校验
/// （trustgraph audit_log_repository）与这里保持同一上限，两侧不得漂移。
pub const MAX_HEADER_OPERATION_ID_LENGTH: usize = 64;

// ─────────────────────────────────────────────────────────────────────────────
// 错误映射：GrantRepositoryError -> AstralError（全部 fail-closed）
// ─────────────────────────────────────────────────────────────────────────────

pub fn map_grant_repository_error(error: crate::GrantRepositoryError) -> AstralError {
    use crate::GrantRepositoryError;
    match error {
        // 共享合同拒绝：入参/组装结果本身不满足 canonical 合同。
        GrantRepositoryError::Contract(contract) => map_contract_error(contract),
        // 请求字段互相矛盾：账本写入被拒绝，本片内的这类错误属于编排缺陷而非可恢复状态。
        GrantRepositoryError::ScopeViolation(message) | GrantRepositoryError::Mapping(message) => {
            AstralError::Internal(format!(
                "authorization ledger refused approval append: {message}"
            ))
        }
        // 账本头被并发/重复 mutation 占用：显式失败并整体回滚，绝不把重复当成功。
        GrantRepositoryError::RevisionConflict(conflict) => {
            AstralError::Validation(format!("approval grant revision conflict: {conflict}"))
        }
        GrantRepositoryError::DuplicateDeltaEvent(message) => {
            AstralError::Validation(format!("duplicate approval delta event: {message}"))
        }
        // 驱动层失败原样保留为 Database 错误语义。
        GrantRepositoryError::Query(driver) => {
            AstralError::Database(format!("authorization ledger query failed: {driver}"))
        }
        GrantRepositoryError::LeaseCasFailed(message) => AstralError::Internal(format!(
            "delta lease CAS failed during approval append: {message}"
        )),
        GrantRepositoryError::ClaimRace => {
            AstralError::Internal("claim race while holding the grant ledger row lock".to_owned())
        }
    }
}

pub fn map_contract_error(error: GrantContractError) -> AstralError {
    AstralError::Validation(format!("approval grant contract rejected payload: {error}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// 请求级 operation identity 的统一入口校验（纯逻辑、单一契约）
// ─────────────────────────────────────────────────────────────────────────────

fn request_operation_id_byte_is_safe(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
}

/// 请求级 operation identity 的统一入口校验（纯逻辑、单一契约）：
/// - 缺失或纯空白 → `Ok(None)`：调用方按各自语义处理（HTTP 用户上下文走
///   事务内确定性派生，但永不随机 fallback 进账本；系统路径传固定稳定串）；
/// - 携带但超长/含非 ASCII 安全集字符/控制字符 → `Err(Validation)` fail-closed，
///   绝不静默替换或截断 —— 与审批/direct 规则路径的既有头部校验同一条门禁。
pub fn validated_request_operation_id(
    operation_id: Option<&str>,
) -> Result<Option<String>, AstralError> {
    let Some(header) = operation_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let usable = header.len() <= MAX_HEADER_OPERATION_ID_LENGTH
        && header.bytes().all(request_operation_id_byte_is_safe);
    if !usable {
        return Err(AstralError::Validation(format!(
            "request id header is not reusable as a durable operation id: {header:?}"
        )));
    }
    Ok(Some(header.to_owned()))
}

/// 纯校验：正数 id 门禁（canonical 合同拒绝非正 id）。
pub fn require_positive(value: i64, description: &str) -> Result<(), AstralError> {
    if value <= 0 {
        return Err(AstralError::Validation(format!(
            "approval canonical grant requires a positive {description}, got {value}"
        )));
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// i64 -> u64 边界（checked conversions）
// ─────────────────────────────────────────────────────────────────────────────

/// 将投影代次/围栏跨过有符号 SQL 列到无符号合同域。负值为持久层不变式破坏，
/// 归类 Internal；非正代次由调用方给出明确 Validation 语义。
fn cross_unsigned(value: i64, field: &'static str) -> Result<u64, AstralError> {
    u64::try_from(value).map_err(|_| {
        AstralError::Internal(format!(
            "projection {field} {value} cannot cross the unsigned contract boundary"
        ))
    })
}

/// 校验任意 contribution event id 的持久化形状（与 projection 身份同一条门禁）：
/// 非空、≤ `crate::MAX_EVENT_ID_LENGTH`、无空白/控制字符。形状不合法一律
/// Validation fail-closed，绝不静默替换或截断。
pub fn validated_contribution_event_id(event_id: &str) -> Result<String, AstralError> {
    let trimmed = event_id.trim();
    if trimmed.is_empty()
        || trimmed.len() > crate::MAX_EVENT_ID_LENGTH
        || trimmed.chars().any(char::is_whitespace)
        || trimmed.chars().any(char::is_control)
    {
        return Err(AstralError::Validation(format!(
            "contribution delta event id is not usable for the authorization ledger: {trimmed:?}"
        )));
    }
    Ok(trimmed.to_owned())
}

/// 校验并转换 projection 事件身份（fail-closed）。
pub struct ValidatedProjectionIdentity {
    pub event_id: String,
    pub generation: u64,
    pub fence: u64,
}

pub fn validated_projection_identity(
    projection: &crate::ProjectionEventIdentity,
) -> Result<ValidatedProjectionIdentity, AstralError> {
    let event_id = projection.event_id.trim();
    if event_id.is_empty()
        || event_id.len() > crate::MAX_EVENT_ID_LENGTH
        || event_id.chars().any(char::is_whitespace)
        || event_id.chars().any(char::is_control)
    {
        return Err(AstralError::Validation(format!(
            "projection identity carries an unusable event id for the authorization ledger: {event_id:?}"
        )));
    }
    if projection.source_generation <= 0 {
        return Err(AstralError::Validation(format!(
            "projection identity lacks a positive CARD source_generation: {}",
            projection.source_generation
        )));
    }
    Ok(ValidatedProjectionIdentity {
        event_id: event_id.to_owned(),
        generation: cross_unsigned(projection.source_generation, "source_generation")?,
        fence: cross_unsigned(projection.revoke_fence, "revoke_fence")?,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// 有效期解析（UTC Unix 秒；无法证明的格式一律 fail-closed）
// ─────────────────────────────────────────────────────────────────────────────

const VALIDITY_FORMAT_HINT: &str = "must be UTC 'YYYY-MM-DD' or 'YYYY-MM-DD[ T]HH:MM:SS'";

fn parse_utc_unix_seconds(field: &'static str, raw: &str) -> Result<i64, AstralError> {
    let bytes = raw.as_bytes();
    let invalid = || {
        AstralError::Validation(format!(
            "approval validity field '{field}' value {raw:?} {VALIDITY_FORMAT_HINT}"
        ))
    };
    if bytes.len() != 10 && bytes.len() != 19 {
        return Err(invalid());
    }
    let digit = |index: usize| -> Result<u32, AstralError> {
        bytes[index]
            .checked_sub(b'0')
            .filter(|d| *d <= 9)
            .map(u32::from)
            .ok_or_else(invalid)
    };
    let number = |from: usize, to: usize| -> Result<u32, AstralError> {
        (from..=to).try_fold(0u32, |acc, index| digit(index).map(|d| acc * 10 + d))
    };
    // 固定分隔符位置：[4]='-' [7]='-'，datetime 时 [10]=' '/'T'、[13]/[16]=':'。
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return Err(invalid());
    }
    let year = number(0, 3)?;
    let month = number(5, 6)?;
    let day = number(8, 9)?;
    let (hour, minute, second) = if bytes.len() == 10 {
        (0, 0, 0)
    } else {
        if bytes[10] != b' ' && bytes[10] != b'T' {
            return Err(invalid());
        }
        if bytes[13] != b':' || bytes[16] != b':' {
            return Err(invalid());
        }
        (number(11, 12)?, number(14, 15)?, number(17, 18)?)
    };
    if !(2000..=9999).contains(&year) {
        return Err(invalid());
    }
    let month_value = Month::try_from(month as u8).map_err(|_| invalid())?;
    let date =
        Date::from_calendar_date(year as i32, month_value, day as u8).map_err(|_| invalid())?;
    let clock = Time::from_hms(hour as u8, minute as u8, second as u8).map_err(|_| invalid())?;
    Ok(PrimitiveDateTime::new(date, clock)
        .assume_utc()
        .unix_timestamp())
}

pub fn parse_validity_window(
    valid_from: Option<&str>,
    valid_to: Option<&str>,
) -> Result<ValidityWindow, AstralError> {
    let not_before = match valid_from.map(str::trim).filter(|value| !value.is_empty()) {
        Some(raw) => Some(parse_utc_unix_seconds("validFrom", raw)?),
        None => None,
    };
    let expires_at = match valid_to.map(str::trim).filter(|value| !value.is_empty()) {
        Some(raw) => Some(parse_utc_unix_seconds("validTo", raw)?),
        None => None,
    };
    // 两端皆空即合同默认 perpetual 显式形态；带值组合由 ValidityWindow::validate 门禁。
    let window = ValidityWindow {
        not_before,
        expires_at,
    };
    window.validate().map_err(map_contract_error)?;
    Ok(window)
}

// ─────────────────────────────────────────────────────────────────────────────
// 纯组装共用小件：资源键 / 条件门禁 / hash / 稳定文本形式
// ─────────────────────────────────────────────────────────────────────────────

/// 用户卡承载作用域（identity key 的 binding_key）的稳定文本形式。
pub fn binding_key_for(card_id: i64) -> String {
    format!("{USER_CARD_BINDING_PREFIX}{card_id}")
}

/// 依赖向量中 CARD 代次绑定（按租户行内自洽的卡标识）的稳定文本形式。
pub fn card_dependency_id(card_id: i64) -> String {
    format!("{CARD_DEPENDENCY_PREFIX}{card_id}")
}

/// canonical grant 的资源表达（object-scope preserving，与读侧
/// `astral_types::registry::build_resource_key` 共享同一形态）：
/// - source 行携带 resource_id → `type:id`（对象级授权，绝不放宽成裸类型）；
/// - source 行无 resource_id → `type:*`（类型级通配的显式形态）。
///
/// 类型段不可为空且不得携带 `:`：携带分隔符的类型无法安全拼出无歧义的
/// scoped key，按 fail-closed 拒绝而不是猜测切分。`*` 通配语义交由
/// compiler 的 WildcardImpact 全量重建路径兜底，这里不额外拦截。
pub fn canonical_resource_key(
    resource_type: &str,
    resource_id: Option<i64>,
) -> Result<String, AstralError> {
    let trimmed = resource_type.trim();
    if trimmed.is_empty() {
        return Err(AstralError::Validation(
            "canonical grant requires a non-empty resource type; refusing to materialize an unscoped grant"
                .into(),
        ));
    }
    if trimmed.contains(':') {
        return Err(AstralError::Validation(format!(
            "canonical grant resource type {trimmed:?} must not carry the ':' scope separator; refusing to compose an ambiguous resource key"
        )));
    }
    Ok(build_resource_key(trimmed, resource_id))
}

/// canonical 合同没有 condition 槽位：带条件的 source 授权无法被无条件
/// canonical ALLOW 忠实表达，静默丢弃条件会放宽授权面。任何非空
/// condition_json 在组装 canonical ADD/UPDATE 前必须显式拒绝（fail-closed）；
/// 空/空白值视为无条件放行。REMOVE/REVOKE tombstone 不携带授权语义，不走本门禁。
pub fn reject_unrepresentable_condition(
    condition_json: Option<&str>,
    source_path: &'static str,
) -> Result<(), AstralError> {
    let has_condition = condition_json
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some();
    if has_condition {
        return Err(AstralError::Validation(format!(
            "{source_path} carries a non-empty condition_json; the canonical grant contract has no condition slot, so the ADD/UPDATE is refused fail-closed instead of silently dropping the condition"
        )));
    }
    Ok(())
}

pub fn sha256_hex_of(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn payload_id_mismatch(stored: Option<&str>, expected: &str) -> bool {
    stored.map(str::trim).unwrap_or_default() != expected.trim()
}

/// UPDATE 是否可能移除旧授权（authorization-content 变化判定，三条 UPDATE 链
/// —— direct rule / rule-set entry / delegation —— 共用的单一事实源）。
///
/// 仅比较决定"放行什么"的 canonical 字段：`resource`、`action`、`effect`、
/// `validity`。provenance（operation/event/actor）、revision/state 属于
/// provenance-only 或簿记维度，不参与：纯 provenance-only/no-op UPDATE 保持
/// 原有非 REVOKE 投影语义，不得把无关写打成 PENDING（P3 写风暴自饥饿教训）。
///
/// 保守策略（2026-09-04）：`effect` 统一按 `GrantEffect::Allow` 对比——三条
/// UPDATE builder 都显式钉死 ALLOW-only，若 before-image 携带其他 effect 语义
/// 即内容变化。delta 层无法可靠区分"纯扩权"与"移动/收窄"（如 `type:1` →
/// `type:2` 同时移除旧对象授权并新增新对象授权），因此**任何**
/// authorization-content 变化都按 revoke-class 处理：写侧让 CARD 父投影事件
/// 改用 REVOKE 语义抬 fence，使 delta 未发布期间严格 reader 的
/// source-freshness 门命中（PENDING），闭合收窄型 UPDATE 的 stale-ALLOW 窗口；
/// 代价只是扩权类 UPDATE 也经历一次 ms 级发布延迟的 PENDING（deny-biased
/// 方向，安全侧）。
pub fn update_authorization_content_changed(
    before: &CanonicalGrant,
    after_resource: &str,
    after_action: &str,
    after_validity: &ValidityWindow,
) -> bool {
    before.resource != after_resource
        || before.action != after_action
        || before.effect != GrantEffect::Allow
        || before.validity != *after_validity
}

/// direct rule UPDATE 的 before-image（head.payload）与新 grant 的
/// authorization-content 比较。字段解析与 [`build_direct_update_draft`] 完全
/// 同源（`canonical_resource_key` / `parse_validity_window`），保证判定与落库
/// 零漂移；调用方必须在追加 CARD 父投影事件**之前**调用本函数，以便按结果
/// 选择 REVOKE（抬 fence）或原 UPDATE 事件语义。
pub fn direct_update_authorization_content_changed(
    facts: &DirectRuleLedgerFacts<'_>,
    head: &crate::GrantHeadSnapshot,
) -> Result<bool, AstralError> {
    let after_resource = canonical_resource_key(facts.resource, facts.resource_id)?;
    let after_validity = parse_validity_window(facts.valid_from, facts.valid_to)?;
    Ok(update_authorization_content_changed(
        &head.payload,
        &after_resource,
        facts.action,
        &after_validity,
    ))
}

/// rule-set entry UPDATE 的 before-image（head.payload）与新 grant 的
/// authorization-content 比较。字段解析与 [`build_ruleset_update_draft`] 完全
/// 同源；调用方必须在追加 CARD 父投影事件**之前**调用（fanout 按卡判定任一
/// 条目内容变化即对该卡使用 REVOKE 语义抬 fence）。
pub fn ruleset_update_authorization_content_changed(
    facts: &RuleSetEntryLedgerFacts<'_>,
    head: &crate::GrantHeadSnapshot,
) -> Result<bool, AstralError> {
    let after_resource = canonical_resource_key(facts.resource, facts.resource_id)?;
    let after_validity = parse_validity_window(facts.valid_from, facts.valid_to)?;
    Ok(update_authorization_content_changed(
        &head.payload,
        &after_resource,
        facts.action,
        &after_validity,
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// RULE_SET 来源（rule_set_entry × card_rule_set_ref × user_card 承载卡）
// — 稳定身份派生与 delta 组装
// ─────────────────────────────────────────────────────────────────────────────

/// 规则集贡献操作语义 token（DeltaEventIdentity.mutation_kind，与 direct 同族但
/// 由本模块独立使用；同一 (operation, tenant, aggregate, source_entry) 下不同
/// kind 必然得到不同事件号）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSetMutationKind {
    Add,
    Update,
    Remove,
}

impl RuleSetMutationKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Update => "update",
            Self::Remove => "remove",
        }
    }
}

/// 组装规则集授权账本条目所需的全部事实输入。每个字段都必须来自调用方已锁定
/// （FOR UPDATE）的 source 行（rule_set_entry / card_rule_set_ref / user_card）；
/// 无法证明的值不允许组装期回填。有效期来自 rule_set_entry 的 DATETIME 列，
/// 由调用方以 `DATE_FORMAT(...,'%Y-%m-%dT%H:%i:%s')` 读回 UTC 文本。
#[derive(Debug, Clone)]
pub struct RuleSetEntryLedgerFacts<'a> {
    /// 锁定中的 user_card.tenant_id；租户缺失不允许规则集贡献物化。
    pub tenant_id: i64,
    /// 锁定中的 user_card.domain_id；允许 None（TenantScope 合同允许）。
    pub domain_id: Option<i64>,
    pub card_id: i64,
    pub user_id: i64,
    pub rule_set_id: i64,
    /// 稳定的规则集条目主键：本贡献在 aggregate 内的 source_entry。
    pub entry_id: i64,
    /// 承载绑定的稳定主键（card_rule_set_ref.id）：binding 身份的一等来源。
    pub ref_id: i64,
    /// 绑定层级标签（BASE/OVERLAY），锁定行真实读取。
    pub ref_type: &'a str,
    /// 条目的 canonical 授权语义（resource/action 必须非空且可归一化）。
    pub resource: &'a str,
    /// 锁定行的对象作用域主键；Some(id) → canonical resource `type:id`，
    /// None → `type:*`。绝不把对象授权放宽成裸类型。
    pub resource_id: Option<i64>,
    pub action: &'a str,
    /// source 行真实条件文本（原样传入，不解析）；非空值在 ADD/UPDATE 组装期
    /// fail-closed（canonical 合同无 condition 槽位）。REMOVE 路径不消费本字段。
    pub condition_json: Option<&'a str>,
    /// source 行真实有效期文本（UTC）；None 即 perpetual。
    pub valid_from: Option<&'a str>,
    pub valid_to: Option<&'a str>,
}

fn require_ruleset_positive_ids(facts: &RuleSetEntryLedgerFacts<'_>) -> Result<(), AstralError> {
    require_positive(facts.tenant_id, "tenant id")?;
    require_positive(facts.card_id, "card id")?;
    require_positive(facts.user_id, "card owner user id")?;
    require_positive(facts.rule_set_id, "rule set id")?;
    require_positive(facts.entry_id, "rule set entry id")?;
    require_positive(facts.ref_id, "card_rule_set_ref id")?;
    Ok(())
}

/// 把绑定行的 ref_type 归一为合同层标（BASE/OVERLAY）。RuleSet 贡献只接受这两个
/// 层标；其他值（含 NONE/lowercase drift）一律 Validation fail-closed，绝不猜测。
pub fn ruleset_binding_layer(ref_type: &str) -> Result<BindingLayer, AstralError> {
    match ref_type.trim() {
        "BASE" => Ok(BindingLayer::Base),
        "OVERLAY" => Ok(BindingLayer::Overlay),
        other => Err(AstralError::Validation(format!(
            "rule set binding ref_type must be BASE or OVERLAY for the authorization ledger, got {other:?}"
        ))),
    }
}

/// GrantIdentityKey 的 binding_key：至少携带 card/rule_set/binding 主键与层标，
/// 使同一 entry 在不同卡、不同绑定行或不同层上派生互异的稳定 GrantId。
fn ruleset_binding_key(card_id: i64, rule_set_id: i64, ref_id: i64, ref_type: &str) -> String {
    format!(
        "{USER_CARD_BINDING_PREFIX}{card_id}:rule-set:{rule_set_id}:binding:{ref_id}:{ref_type}"
    )
}

/// 由单个 builder 共用的规则集身份解析结果。
struct RuleSetIdentityContext {
    tenant_scope: TenantScope,
    grant_id: GrantId,
}

/// 解析租户作用域并确定性派生规则集贡献身份
/// （aggregate=`RULE_SET`、source_entry=entry、binding_key=卡片×绑定行×层标）。
///
/// 资源/action/priority/validity 不进入身份：更新这些可变属性复用同一 grant；
/// entry/ref/card/tenant/layer 任一漂移必然得到不同的 GrantId 或显式失败。
fn resolve_ruleset_identity(
    facts: &RuleSetEntryLedgerFacts<'_>,
) -> Result<RuleSetIdentityContext, AstralError> {
    require_ruleset_positive_ids(facts)?;
    let binding_layer = ruleset_binding_layer(facts.ref_type)?;
    let tenant_scope =
        TenantScope::new(facts.tenant_id, facts.domain_id).map_err(map_contract_error)?;
    let identity_key = GrantIdentityKey::rule_set(
        tenant_scope.clone(),
        binding_layer,
        &facts.rule_set_id.to_string(),
        &facts.entry_id.to_string(),
        &ruleset_binding_key(
            facts.card_id,
            facts.rule_set_id,
            facts.ref_id,
            binding_layer.as_str(),
        ),
    )
    .map_err(map_contract_error)?;
    let grant_id = identity_key.derive_grant_id().map_err(map_contract_error)?;
    Ok(RuleSetIdentityContext {
        tenant_scope,
        grant_id,
    })
}

/// 校验 head 快照与本条规则集 mutation 声明的身份一致：grant id / source kind /
/// binding layer / provenance.source_entry(=entry) / provenance.binding_id(=ref) /
/// 租户域 / 卡与用户归属任一漂移都 fail-closed，禁止把 delta 打到另一份账本记录上。
#[allow(clippy::too_many_arguments)]
fn assert_ruleset_head_alignment(
    head: &crate::GrantHeadSnapshot,
    expected_grant_id: GrantId,
    tenant_scope: &TenantScope,
    layer: BindingLayer,
    card_id: i64,
    user_id: i64,
    entry_id: i64,
    ref_id: i64,
) -> Result<(), AstralError> {
    if head.grant_id != expected_grant_id || head.payload.grant_id != expected_grant_id {
        return Err(AstralError::Internal(format!(
            "grant ledger head {0} does not match the derived rule set identity",
            head.grant_id.as_str()
        )));
    }
    if head.payload.source_kind != GrantSourceKind::RuleSet {
        return Err(AstralError::Validation(
            "grant ledger head is not a RULE_SET grant; refusing to mutate it from the rule set path"
                .into(),
        ));
    }
    if head.payload.binding_layer != layer {
        return Err(AstralError::Validation(format!(
            "grant ledger head binding layer {} drifts from the locked binding {}",
            head.payload.binding_layer.as_str(),
            layer.as_str()
        )));
    }
    if payload_id_mismatch(
        head.payload.provenance.source_entry.as_deref(),
        &entry_id.to_string(),
    ) {
        return Err(AstralError::Internal(
            "grant ledger head provenance source_entry does not match the locked rule set entry id"
                .into(),
        ));
    }
    if payload_id_mismatch(
        head.payload.provenance.binding_id.as_deref(),
        &ref_id.to_string(),
    ) {
        return Err(AstralError::Internal(
            "grant ledger head provenance binding_id does not match the locked card_rule_set_ref id"
                .into(),
        ));
    }
    if head.payload.tenant != *tenant_scope {
        return Err(AstralError::Validation(
            "grant ledger head tenant/domain drifts from the locked user_card row".into(),
        ));
    }
    if head.payload.card_id != card_id || head.payload.user_id != user_id {
        return Err(AstralError::Validation(
            "grant ledger head card/user context drifts from the locked user_card row".into(),
        ));
    }
    Ok(())
}

/// ADD/UPDATE 与 REMOVE 共用的组装完成的规则集贡献草稿。revision 与 delta event
/// 请求共享同一份数据；before-image/digest 成对出现或同时缺席（ADD 双空）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSetGrantDeltaDraft {
    pub tenant_id: i64,
    pub card_id: i64,
    pub rule_set_id: i64,
    pub event_id: String,
    pub operation_id: String,
    pub grant_id: GrantId,
    pub delta: GrantDelta,
    pub semantic_hash_hex: String,
    pub dependency_hash_hex: String,
    pub before_image_json: Option<String>,
    pub before_digest_hex: Option<String>,
    /// 带 metadata 的 CARD 投影事件身份（构造期绑定，防止 request 双写漂移）。
    pub source_generation: u64,
    pub revoke_fence: u64,
    /// This delta may leave published evidence authorizing pre-update access.
    pub invalidates_published_evidence: bool,
}

impl RuleSetGrantDeltaDraft {
    pub fn revision_request(&self) -> crate::GrantRevisionAppendRequest {
        crate::GrantRevisionAppendRequest {
            tenant_id: self.tenant_id,
            card_id_scope: Some(self.card_id),
            aggregate_type: RULE_SET_AGGREGATE_TYPE.to_owned(),
            aggregate_id: self.rule_set_id,
            delta: self.delta.clone(),
            event_id: self.event_id.clone(),
            operation_id: self.operation_id.clone(),
            semantic_hash_hex: self.semantic_hash_hex.clone(),
            dependency_hash_hex: self.dependency_hash_hex.clone(),
            compiler_version: COMPILER_VERSION.to_owned(),
        }
    }

    pub fn event_type(&self) -> crate::DeltaEventType {
        match self.delta.operation_name() {
            "ADD" => crate::DeltaEventType::Add,
            "UPDATE" => crate::DeltaEventType::Update,
            "REMOVE" => crate::DeltaEventType::Remove,
            _ => crate::DeltaEventType::Revoke,
        }
    }

    pub fn delta_event_request(
        &self,
        base_version: i64,
        target_version: i64,
    ) -> Result<crate::DeltaEventAppendRequest, AstralError> {
        let delta_json = serde_json::to_string(&self.delta).map_err(|error| {
            AstralError::Internal(format!("delta serialization failed: {error}"))
        })?;
        Ok(crate::DeltaEventAppendRequest {
            tenant_id: self.tenant_id,
            card_id: Some(self.card_id),
            aggregate_type: RULE_SET_AGGREGATE_TYPE.to_owned(),
            aggregate_id: self.rule_set_id,
            grant_id: self.grant_id,
            event_id: self.event_id.clone(),
            operation_id: self.operation_id.clone(),
            event_type: self.event_type(),
            base_version,
            target_version,
            // CARD 流依赖向量：与构造期校验的 generation/fence 完全一致。
            source_generation: self.source_generation,
            revoke_fence: self.revoke_fence,
            invalidates_published_evidence: self.invalidates_published_evidence,
            before_image_json: self.before_image_json.clone(),
            before_digest_hex: self.before_digest_hex.clone(),
            delta_json,
            semantic_hash_hex: self.semantic_hash_hex.clone(),
            dependency_hash_hex: self.dependency_hash_hex.clone(),
            compiler_version: COMPILER_VERSION.to_owned(),
            next_attempt_at: None,
        })
    }
}

/// 在调用方事务内追加一个规则集贡献：revision（immutable）+ delta event，
/// 两者共享草稿身份；任一错误向上传播触发整体回滚。本函数不 commit、
/// 不访问 Redis/MQ、不吞错、不降级。
pub async fn append_ruleset_grant_delta_in_tx(
    tx: &mut sqlx::Transaction<'_, MySql>,
    draft: &RuleSetGrantDeltaDraft,
    base_version: i64,
    target_version: i64,
) -> Result<(), AstralError> {
    if target_version <= base_version || base_version < 0 {
        return Err(AstralError::Validation(
            "rule set delta version must strictly advance from a non-negative base".into(),
        ));
    }
    crate::append_grant_revision_in_tx(&mut *tx, &draft.revision_request())
        .await
        .map_err(map_grant_repository_error)?;
    crate::append_delta_event(
        &mut **tx,
        &draft.delta_event_request(base_version, target_version)?,
    )
    .await
    .map_err(map_grant_repository_error)?;
    Ok(())
}

/// 从批次共享的稳定 operation id + 单条规则集贡献的完整稳定维度
/// （租户/RULE_SET 聚合/entry×卡×绑定行/kind）派生该贡献独立且可重放的
/// delta event id。
///
/// - 同一 operation 内两条不同贡献（不同 entry、不同绑定卡或不同绑定行）
///   必然得到不同 event id，满足 `authorization_delta_event.uk_ade_event`
///   全局唯一，不再把共享 parent 投影事件号重复用作多个 delta 的事件号；
/// - 相同输入重放得到相同 id，唯一冲突只可能来自真实重复提交并 fail-closed；
/// - 派生经 astral-types 固定 namespace helper 完成，域分离于 grant identity。
pub fn derive_ruleset_contribution_event_id(
    operation_id: &str,
    facts: &RuleSetEntryLedgerFacts<'_>,
    kind: RuleSetMutationKind,
) -> Result<String, AstralError> {
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "rule set contribution identity requires the shared durable operation id".into(),
        ));
    }
    require_ruleset_positive_ids(facts)?;
    let scoped_entry = format!(
        "{}:card:{}:ref:{}",
        facts.entry_id, facts.card_id, facts.ref_id
    );
    let identity = DeltaEventIdentity {
        operation_id,
        tenant_id: facts.tenant_id,
        aggregate_type: RULE_SET_AGGREGATE_TYPE,
        aggregate_id: facts.rule_set_id,
        source_entry: &scoped_entry,
        mutation_kind: kind.as_str(),
    };
    let event_id = identity
        .derive_event_id()
        .map_err(map_contract_error)?
        .to_string();
    validated_contribution_event_id(&event_id)?;
    Ok(event_id)
}

/// 通过与 builder 完全相同的路径派生规则集贡献的身份主键
/// （aggregate=`RULE_SET`、source_entry=entry、binding_key 含卡/绑定行/层标）。
pub fn derive_ruleset_identity(
    facts: &RuleSetEntryLedgerFacts<'_>,
) -> Result<GrantId, AstralError> {
    let context = resolve_ruleset_identity(facts)?;
    Ok(context.grant_id)
}

/// 共享的证据构造尾部：CARD 流依赖向量 + evidence 校验 + hash 对。
///
/// `evidence_event_id` 是本贡献自身的独立事件号：合同要求 provenance.event_id 与
/// evidence.event_id 一致，因此 evidence 绑定 contribution 事件（revision/delta
/// 落库使用的同一 id）；CARD 投影身份只提供 generation/fence 的 durable 绑定。
fn ruleset_evidence_hashes(
    canonical_grant: &CanonicalGrant,
    card_id: i64,
    projection_identity: &ValidatedProjectionIdentity,
    operation_id: &str,
    evidence_event_id: &str,
) -> Result<(DependencyVector, String, String), AstralError> {
    let dependency_vector = DependencyVector::new(vec![DependencyVersion::new(
        card_dependency_id(card_id),
        projection_identity.generation,
        projection_identity.fence,
    )
    .map_err(map_contract_error)?])
    .map_err(map_contract_error)?;
    let evidence = GrantEvidence {
        grant: canonical_grant.clone(),
        event_id: evidence_event_id.to_owned(),
        operation_id: operation_id.to_owned(),
        source_generation: projection_identity.generation,
        revoke_fence: projection_identity.fence,
        dependency_vector: dependency_vector.clone(),
    };
    evidence.validate().map_err(map_contract_error)?;
    let semantic_hash_hex = canonical_grant
        .canonical_hash()
        .map_err(map_contract_error)?;
    let dependency_hash_hex = evidence
        .dependency_vector
        .canonical_hash()
        .map_err(map_contract_error)?;
    Ok((dependency_vector, semantic_hash_hex, dependency_hash_hex))
}

/// 校验系统 actor 语义：用户上下文要求正数 actor；system mutation 的
/// SYSTEM_ACTOR_ID(-1) 以 None 表达（canonical 合同拒绝非正 actor）。
fn ruleset_actor_user_id(actor_user_id: Option<i64>) -> Result<Option<i64>, AstralError> {
    match actor_user_id {
        Some(actor_user_id) => {
            require_positive(actor_user_id, "actor user id")?;
            Ok(Some(actor_user_id))
        }
        None => Ok(None),
    }
}

/// 纯组装一条规则集条目创建贡献（ADD rev1，base 0 → target 1）。ADD 天然没有
/// before-image，两个字段保持成对缺席。
#[allow(clippy::too_many_arguments)]
pub fn build_ruleset_add_draft(
    facts: &RuleSetEntryLedgerFacts<'_>,
    operation_id: &str,
    actor_user_id: Option<i64>,
    projection: &crate::ProjectionEventIdentity,
    contribution_event_id: &str,
) -> Result<RuleSetGrantDeltaDraft, AstralError> {
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "rule set operation id must not be empty".into(),
        ));
    }
    let identity_context = resolve_ruleset_identity(facts)?;
    // CARD 投影事件提供 durable generation/fence 绑定；本贡献自身的独立事件号
    // 用于 revision/delta/provenance/evidence 的 event 维度。
    let projection_identity = validated_projection_identity(projection)?;
    let contribution = validated_contribution_event_id(contribution_event_id)?;
    let validity = parse_validity_window(facts.valid_from, facts.valid_to)?;
    let actor_user_id = ruleset_actor_user_id(actor_user_id)?;
    require_nonempty_canonical_field(facts.action, "action")?;
    reject_unrepresentable_condition(facts.condition_json, "rule set entry add")?;
    let resource = canonical_resource_key(facts.resource, facts.resource_id)?;

    let provisional_grant = CanonicalGrant {
        grant_id: identity_context.grant_id,
        revision: GrantRevision::initial(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::RuleSet,
        binding_layer: ruleset_binding_layer(facts.ref_type)?,
        tenant: identity_context.tenant_scope.clone(),
        card_id: facts.card_id,
        user_id: facts.user_id,
        resource,
        action: facts.action.to_owned(),
        effect: GrantEffect::Allow,
        validity,
        provenance: GrantProvenance {
            source_id: facts.rule_set_id.to_string(),
            source_entry: Some(facts.entry_id.to_string()),
            // 合同强制 RULE_SET 贡献携带承载绑定的稳定主键。
            binding_id: Some(facts.ref_id.to_string()),
            delegation_id: None,
            operation_id: operation_id.to_owned(),
            event_id: Some(contribution.clone()),
            actor_user_id,
        },
    };
    let canonical_grant = provisional_grant
        .canonicalized()
        .map_err(map_contract_error)?;

    let delta = GrantDelta::add(canonical_grant.clone());
    delta.validate().map_err(map_contract_error)?;
    let (_, semantic_hash_hex, dependency_hash_hex) = ruleset_evidence_hashes(
        &canonical_grant,
        facts.card_id,
        &projection_identity,
        operation_id,
        &contribution,
    )?;

    Ok(RuleSetGrantDeltaDraft {
        tenant_id: facts.tenant_id,
        card_id: facts.card_id,
        rule_set_id: facts.rule_set_id,
        event_id: contribution,
        operation_id: operation_id.to_owned(),
        grant_id: identity_context.grant_id,
        delta,
        semantic_hash_hex,
        dependency_hash_hex,
        before_image_json: None,
        before_digest_hex: None,
        source_generation: projection_identity.generation,
        revoke_fence: projection_identity.fence,
        invalidates_published_evidence: false,
    })
}

fn require_nonempty_canonical_field(value: &str, field: &'static str) -> Result<(), AstralError> {
    if value.trim().is_empty() {
        return Err(AstralError::Validation(format!(
            "rule set canonical grant requires a non-empty {field}; refusing to materialize a legacy row without it"
        )));
    }
    Ok(())
}

/// 纯组装一条规则集条目更新贡献（UPDATE rev=head+1），保留旧 canonical grant
/// JSON 作为成对 before-image + digest。head 缺失、层标/entry/binding/租户/卡
/// 漂移一律 fail-closed；CAS/stale/gap 冲突仍由 repository 的 transition 规则裁决。
///
/// 更新映射仅覆盖 canonical 合同内的可变属性（resource/action/effect/validity）：
/// resource 以 scoped key（`type:id`/`type:*`）表达对象作用域；非空
/// condition_json 无法被 canonical 合同表达，UPDATE 前显式 fail-closed 拒绝；
/// priority 保留在 source 行与 legacy 审计 JSON 中。identity 不变
/// （source_entry 恒为 entry_id）。
#[allow(clippy::too_many_arguments)]
pub fn build_ruleset_update_draft(
    facts: &RuleSetEntryLedgerFacts<'_>,
    head: &crate::GrantHeadSnapshot,
    operation_id: &str,
    actor_user_id: Option<i64>,
    projection: &crate::ProjectionEventIdentity,
    contribution_event_id: &str,
) -> Result<RuleSetGrantDeltaDraft, AstralError> {
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "rule set operation id must not be empty".into(),
        ));
    }
    let identity_context = resolve_ruleset_identity(facts)?;
    assert_ruleset_head_alignment(
        head,
        identity_context.grant_id,
        &identity_context.tenant_scope,
        ruleset_binding_layer(facts.ref_type)?,
        facts.card_id,
        facts.user_id,
        facts.entry_id,
        facts.ref_id,
    )?;
    let projection_identity = validated_projection_identity(projection)?;
    let contribution = validated_contribution_event_id(contribution_event_id)?;
    let validity = parse_validity_window(facts.valid_from, facts.valid_to)?;
    let actor_user_id = ruleset_actor_user_id(actor_user_id)?;
    require_nonempty_canonical_field(facts.action, "action")?;
    reject_unrepresentable_condition(facts.condition_json, "rule set entry update")?;
    let resource = canonical_resource_key(facts.resource, facts.resource_id)?;

    let expected_revision = head.entry.revision;
    let next_revision = expected_revision.next().map_err(map_contract_error)?;

    let mut updated = head.payload.clone();
    updated.resource = resource;
    updated.action = facts.action.to_owned();
    updated.effect = GrantEffect::Allow;
    updated.validity = validity;
    updated.revision = next_revision;
    updated.state = GrantState::Active;
    updated.provenance.operation_id = operation_id.to_owned();
    updated.provenance.event_id = Some(contribution.clone());
    updated.provenance.actor_user_id = actor_user_id;
    let before_image_json = head.payload.canonical_input().map_err(map_contract_error)?;
    let before_digest_hex = sha256_hex_of(&before_image_json);

    let delta = GrantDelta::update(updated, expected_revision);
    delta.validate().map_err(map_contract_error)?;
    let resulting_grant = match &delta {
        GrantDelta::Update { grant, .. } => grant.clone(),
        other => unreachable!("UPDATE delta built in-place got {other:?}"),
    };

    let (_, semantic_hash_hex, dependency_hash_hex) = ruleset_evidence_hashes(
        &resulting_grant,
        facts.card_id,
        &projection_identity,
        operation_id,
        &contribution,
    )?;
    let invalidates_published_evidence = ruleset_update_authorization_content_changed(facts, head)?;

    Ok(RuleSetGrantDeltaDraft {
        tenant_id: facts.tenant_id,
        card_id: facts.card_id,
        rule_set_id: facts.rule_set_id,
        event_id: contribution,
        operation_id: operation_id.to_owned(),
        grant_id: identity_context.grant_id,
        delta,
        semantic_hash_hex,
        dependency_hash_hex,
        before_image_json: Some(before_image_json),
        before_digest_hex: Some(before_digest_hex),
        source_generation: projection_identity.generation,
        revoke_fence: projection_identity.fence,
        invalidates_published_evidence,
    })
}

/// 纯组装一条规则集条目删除贡献（REMOVE rev=head+1）。tombstone kind 固定为
/// `REMOVE`（source removal 语义，revoke fence 仍由 CARD REVOKE 投影事件递增）；
/// 旧 canonical grant JSON 作为 before-image 成对落库，semantic hash 锚定被移除
/// 的旧授权内容。对普通 DENY 场景不产生任何 delta——DENY 不是 canonical ALLOW。
#[allow(clippy::too_many_arguments)]
pub fn build_ruleset_remove_draft(
    facts: &RuleSetEntryLedgerFacts<'_>,
    head: &crate::GrantHeadSnapshot,
    operation_id: &str,
    projection: &crate::ProjectionEventIdentity,
    contribution_event_id: &str,
) -> Result<RuleSetGrantDeltaDraft, AstralError> {
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "rule set operation id must not be empty".into(),
        ));
    }
    let identity_context = resolve_ruleset_identity(facts)?;
    assert_ruleset_head_alignment(
        head,
        identity_context.grant_id,
        &identity_context.tenant_scope,
        ruleset_binding_layer(facts.ref_type)?,
        facts.card_id,
        facts.user_id,
        facts.entry_id,
        facts.ref_id,
    )?;
    // CARD（parent）投影事件只提供 durable generation/fence 绑定。
    let projection_identity = validated_projection_identity(projection)?;
    // 本贡献自身的独立事件号。
    let contribution = validated_contribution_event_id(contribution_event_id)?;
    let expected_revision = head.entry.revision;

    let before_image_json = head.payload.canonical_input().map_err(map_contract_error)?;
    let before_digest_hex = sha256_hex_of(&before_image_json);
    let delta = GrantDelta::remove(identity_context.grant_id, expected_revision);
    delta.validate().map_err(map_contract_error)?;
    let semantic_hash_hex = sha256_hex_of(&before_image_json);

    // 依赖向量仅做合同级校验 + hash（Remove evidence 不存在 canonical grant 对）。
    let dependency_vector = DependencyVector::new(vec![DependencyVersion::new(
        card_dependency_id(facts.card_id),
        projection_identity.generation,
        projection_identity.fence,
    )
    .map_err(map_contract_error)?])
    .map_err(map_contract_error)?;
    let dependency_hash_hex = dependency_vector
        .canonical_hash()
        .map_err(map_contract_error)?;

    Ok(RuleSetGrantDeltaDraft {
        tenant_id: facts.tenant_id,
        card_id: facts.card_id,
        rule_set_id: facts.rule_set_id,
        event_id: contribution,
        operation_id: operation_id.to_owned(),
        grant_id: identity_context.grant_id,
        delta,
        semantic_hash_hex,
        dependency_hash_hex,
        before_image_json: Some(before_image_json),
        before_digest_hex: Some(before_digest_hex),
        source_generation: projection_identity.generation,
        revoke_fence: projection_identity.fence,
        invalidates_published_evidence: true,
    })
}

// ─── DIRECT 来源（permission_rule 卡载直授权）— v2 自 trustgraph adapter 下沉 ───

/// 授权账本中 direct 规则来源的聚合类型。`GrantIdentityKey::direct` 的合同把
/// 承载卡本身作为 source aggregate（`USER_CARD`），aggregate_id 即 card 主键，
/// source_entry 是单条 `permission_rule` 的稳定 rule_id。
pub const DIRECT_AGGREGATE_TYPE: &str = "USER_CARD";

// DIRECT delta 组装（Add / Update / Remove）与事务追加
// ─────────────────────────────────────────────────────────────────────────────

/// 组装 direct 授权账本条目所需的全部事实输入。每个字段都必须来自调用方
/// 已锁定（FOR UPDATE）的 source 行；无法证明的值不允许组装期回填。
#[derive(Debug, Clone)]
pub struct DirectRuleLedgerFacts<'a> {
    /// 锁定中的 user_card.tenant_id；NULL 会在组装期 fail-closed。
    pub tenant_id: Option<i64>,
    /// 锁定中的 user_card.domain_id；允许 None（TenantScope 合同允许）。
    pub domain_id: Option<i64>,
    pub card_id: i64,
    pub user_id: i64,
    pub rule_id: i64,
    pub resource: &'a str,
    /// 锁定行的对象作用域主键；Some(id) → canonical resource `type:id`，
    /// None → `type:*`。绝不把对象授权放宽成裸类型。
    pub resource_id: Option<i64>,
    pub action: &'a str,
    /// source 行真实条件文本（原样传入，不解析）；非空值在 ADD/UPDATE 组装期
    /// fail-closed（canonical 合同无 condition 槽位）。REMOVE 路径不消费本字段。
    pub condition_json: Option<&'a str>,
    /// source 行的真实有效期（UTC 'YYYY-MM-DD' 或 'YYYY-MM-DD[ T]HH:MM:SS'）。
    pub valid_from: Option<&'a str>,
    pub valid_to: Option<&'a str>,
}

/// 由单个 builder 共用的身份/有效期解析结果。
pub struct DirectRuleIdentityContext {
    tenant_scope: TenantScope,
    tenant_id: i64,
    grant_id: GrantId,
}

pub fn require_direct_rule_positive_ids(
    facts: &DirectRuleLedgerFacts<'_>,
) -> Result<(), AstralError> {
    require_positive(facts.card_id, "card id")?;
    require_positive(facts.user_id, "card owner user id")?;
    require_positive(facts.rule_id, "permission_rule id")?;
    Ok(())
}

/// 解析租户作用域并确定性派生 direct grant 身份（aggregate=`USER_CARD`、
/// aggregate_id=card、source_entry=rule、binding scope=卡承载作用域）。
pub fn resolve_direct_identity(
    facts: &DirectRuleLedgerFacts<'_>,
) -> Result<DirectRuleIdentityContext, AstralError> {
    let tenant_id = facts.tenant_id.ok_or_else(|| {
        AstralError::Validation(
            "locked user_card has a NULL tenant_id; a tenant-scoped direct grant cannot be assembled"
                .into(),
        )
    })?;
    let tenant_scope = TenantScope::new(tenant_id, facts.domain_id).map_err(map_contract_error)?;
    // 更新资源/action/priority/validity 复用同一 grant：这些可变属性不进入
    // identity key；source_entry=rule_id 的语义变更才是 Remove+Add。
    let identity_key = GrantIdentityKey::direct(
        tenant_scope.clone(),
        &facts.card_id.to_string(),
        &facts.rule_id.to_string(),
    )
    .map_err(map_contract_error)?;
    let grant_id = identity_key.derive_grant_id().map_err(map_contract_error)?;
    Ok(DirectRuleIdentityContext {
        tenant_scope,
        tenant_id,
        grant_id,
    })
}

/// 校验 head 快照与本次 mutation 声明的身份一致；任何 card/tenant/provenance
/// 漂移都 fail-closed，禁止把 tombstone 打到另一份账本记录上。
fn assert_direct_head_alignment(
    head: &crate::GrantHeadSnapshot,
    expected_grant_id: GrantId,
    tenant_scope: &TenantScope,
    card_id: i64,
    user_id: i64,
    rule_id: i64,
) -> Result<(), AstralError> {
    if head.grant_id != expected_grant_id || head.payload.grant_id != expected_grant_id {
        return Err(AstralError::Internal(format!(
            "grant ledger head {0} does not match the derived direct identity",
            head.grant_id.as_str()
        )));
    }
    if head.payload.source_kind != GrantSourceKind::Direct
        || head.payload.binding_layer != BindingLayer::None
    {
        return Err(AstralError::Validation(
            "grant ledger head is not a DIRECT none-layer grant; refusing to mutate it from the direct rule path".into(),
        ));
    }
    if payload_id_mismatch(
        head.payload.provenance.source_entry.as_deref(),
        &rule_id.to_string(),
    ) {
        return Err(AstralError::Internal(
            "grant ledger head provenance source_entry does not match the locked rule id".into(),
        ));
    }
    if head.payload.tenant != *tenant_scope {
        return Err(AstralError::Validation(
            "grant ledger head tenant/domain drifts from the locked user_card row".into(),
        ));
    }
    if head.payload.card_id != card_id || head.payload.user_id != user_id {
        return Err(AstralError::Validation(
            "grant ledger head card/user context drifts from the locked user_card row".into(),
        ));
    }
    Ok(())
}

/// ADD/UPDATE 与 REMOVE 共用的组装完成的直接贡献草稿。revision 与 delta event
/// 请求共享同一份数据，before-image/digest 必须成对出现或同时缺席。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectGrantDeltaDraft {
    pub tenant_id: i64,
    pub card_id: i64,
    pub event_id: String,
    pub operation_id: String,
    pub grant_id: GrantId,
    pub delta: GrantDelta,
    pub semantic_hash_hex: String,
    pub dependency_hash_hex: String,
    pub before_image_json: Option<String>,
    pub before_digest_hex: Option<String>,
    /// 带 metadata 的 CARD 投影事件身份（构造期绑定，防止 request 双写漂移）。
    pub source_generation: u64,
    pub revoke_fence: u64,
    /// This delta may leave published evidence authorizing pre-update access.
    pub invalidates_published_evidence: bool,
}

impl DirectGrantDeltaDraft {
    pub fn revision_request(&self) -> crate::GrantRevisionAppendRequest {
        crate::GrantRevisionAppendRequest {
            tenant_id: self.tenant_id,
            card_id_scope: Some(self.card_id),
            aggregate_type: DIRECT_AGGREGATE_TYPE.to_owned(),
            aggregate_id: self.card_id,
            delta: self.delta.clone(),
            event_id: self.event_id.clone(),
            operation_id: self.operation_id.clone(),
            semantic_hash_hex: self.semantic_hash_hex.clone(),
            dependency_hash_hex: self.dependency_hash_hex.clone(),
            compiler_version: COMPILER_VERSION.to_owned(),
        }
    }

    fn event_type(&self) -> crate::DeltaEventType {
        match self.delta.operation_name() {
            "ADD" => crate::DeltaEventType::Add,
            "UPDATE" => crate::DeltaEventType::Update,
            "REMOVE" => crate::DeltaEventType::Remove,
            _ => crate::DeltaEventType::Revoke,
        }
    }

    pub fn delta_event_request(
        &self,
        base_version: i64,
        target_version: i64,
    ) -> Result<crate::DeltaEventAppendRequest, AstralError> {
        let delta_json = serde_json::to_string(&self.delta).map_err(|error| {
            AstralError::Internal(format!("delta serialization failed: {error}"))
        })?;
        Ok(crate::DeltaEventAppendRequest {
            tenant_id: self.tenant_id,
            card_id: Some(self.card_id),
            aggregate_type: DIRECT_AGGREGATE_TYPE.to_owned(),
            aggregate_id: self.card_id,
            grant_id: self.grant_id,
            event_id: self.event_id.clone(),
            operation_id: self.operation_id.clone(),
            event_type: self.event_type(),
            base_version,
            target_version,
            // CARD 流依赖向量：与构造期校验的 generation/fence 完全一致。
            source_generation: self.source_generation,
            revoke_fence: self.revoke_fence,
            invalidates_published_evidence: self.invalidates_published_evidence,
            before_image_json: self.before_image_json.clone(),
            before_digest_hex: self.before_digest_hex.clone(),
            delta_json,
            semantic_hash_hex: self.semantic_hash_hex.clone(),
            dependency_hash_hex: self.dependency_hash_hex.clone(),
            compiler_version: COMPILER_VERSION.to_owned(),
            next_attempt_at: None,
        })
    }
}

/// 在调用方事务内追加一个 direct 贡献：revision（immutable）+ delta event，
/// 两者共享草稿身份；任一错误向上传播触发整体回滚。本函数不 commit、
/// 不访问 Redis/MQ、不吞错、不降级。
pub async fn append_direct_grant_delta_in_tx(
    tx: &mut sqlx::Transaction<'_, MySql>,
    draft: &DirectGrantDeltaDraft,
    base_version: i64,
    target_version: i64,
) -> Result<(), AstralError> {
    if target_version <= base_version || base_version < 0 {
        return Err(AstralError::Validation(
            "direct delta version must strictly advance from a non-negative base".into(),
        ));
    }
    crate::append_grant_revision_in_tx(&mut *tx, &draft.revision_request())
        .await
        .map_err(map_grant_repository_error)?;
    crate::append_delta_event(
        &mut **tx,
        &draft.delta_event_request(base_version, target_version)?,
    )
    .await
    .map_err(map_grant_repository_error)?;
    Ok(())
}

/// 纯组装一条 direct 规则创建贡献（ADD rev1）。
pub fn build_direct_add_draft(
    facts: &DirectRuleLedgerFacts<'_>,
    operation_id: &str,
    actor_user_id: i64,
    projection: &crate::ProjectionEventIdentity,
) -> Result<DirectGrantDeltaDraft, AstralError> {
    require_direct_rule_positive_ids(facts)?;
    require_positive(actor_user_id, "actor user id")?;
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "direct rule operation id must not be empty".into(),
        ));
    }
    let identity_context = resolve_direct_identity(facts)?;
    let projection_identity = validated_projection_identity(projection)?;
    let validity = parse_validity_window(facts.valid_from, facts.valid_to)?;
    reject_unrepresentable_condition(facts.condition_json, "direct rule create")?;
    let resource = canonical_resource_key(facts.resource, facts.resource_id)?;

    let provisional_grant = CanonicalGrant {
        grant_id: identity_context.grant_id,
        revision: GrantRevision::initial(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::Direct,
        binding_layer: BindingLayer::None,
        tenant: identity_context.tenant_scope.clone(),
        card_id: facts.card_id,
        user_id: facts.user_id,
        resource,
        action: facts.action.to_owned(),
        effect: GrantEffect::Allow,
        validity,
        provenance: GrantProvenance {
            source_id: facts.card_id.to_string(),
            source_entry: Some(facts.rule_id.to_string()),
            binding_id: None,
            delegation_id: None,
            operation_id: operation_id.to_owned(),
            event_id: Some(projection_identity.event_id.clone()),
            actor_user_id: Some(actor_user_id),
        },
    };
    let canonical_grant = provisional_grant
        .canonicalized()
        .map_err(map_contract_error)?;

    let delta = GrantDelta::add(canonical_grant.clone());
    delta.validate().map_err(map_contract_error)?;
    let dependency_vector = DependencyVector::new(vec![DependencyVersion::new(
        card_dependency_id(facts.card_id),
        projection_identity.generation,
        projection_identity.fence,
    )
    .map_err(map_contract_error)?])
    .map_err(map_contract_error)?;
    let evidence = GrantEvidence {
        grant: canonical_grant.clone(),
        event_id: projection_identity.event_id.clone(),
        operation_id: operation_id.to_owned(),
        source_generation: projection_identity.generation,
        revoke_fence: projection_identity.fence,
        dependency_vector,
    };
    evidence.validate().map_err(map_contract_error)?;

    Ok(DirectGrantDeltaDraft {
        tenant_id: identity_context.tenant_id,
        card_id: facts.card_id,
        event_id: projection_identity.event_id,
        operation_id: operation_id.to_owned(),
        grant_id: identity_context.grant_id,
        delta,
        semantic_hash_hex: canonical_grant
            .canonical_hash()
            .map_err(map_contract_error)?,
        dependency_hash_hex: evidence
            .dependency_vector
            .canonical_hash()
            .map_err(map_contract_error)?,
        before_image_json: None,
        before_digest_hex: None,
        source_generation: projection_identity.generation,
        revoke_fence: projection_identity.fence,
        invalidates_published_evidence: false,
    })
}

/// 纯组装一条 direct 规则更新贡献（UPDATE rev=head+1），保留旧 canonical grant
/// 作为 before-image 并计算成对 digest。head 缺失、CAS/stale/gap、card/tenant/
/// provenance 不一致一律 fail-closed（进 ledger 冲突分类仍由 repository 决定）。
///
/// effect 不从 head.payload 继承，而是显式钉为 `GrantEffect::Allow`（与
/// `build_ruleset_update_draft` 同一 ALLOW-only 纵深防御）：即使未来 head 形状
/// 演化携带其他 effect 语义，direct UPDATE 也绝不把非 ALLOW 放行写入账本。
pub fn build_direct_update_draft(
    facts: &DirectRuleLedgerFacts<'_>,
    head: &crate::GrantHeadSnapshot,
    operation_id: &str,
    actor_user_id: i64,
    projection: &crate::ProjectionEventIdentity,
) -> Result<DirectGrantDeltaDraft, AstralError> {
    require_direct_rule_positive_ids(facts)?;
    require_positive(actor_user_id, "actor user id")?;
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "direct rule operation id must not be empty".into(),
        ));
    }
    let identity_context = resolve_direct_identity(facts)?;
    assert_direct_head_alignment(
        head,
        identity_context.grant_id,
        &identity_context.tenant_scope,
        facts.card_id,
        facts.user_id,
        facts.rule_id,
    )?;
    let projection_identity = validated_projection_identity(projection)?;
    let validity = parse_validity_window(facts.valid_from, facts.valid_to)?;
    let expected_revision = head.entry.revision;
    let next_revision = expected_revision.next().map_err(map_contract_error)?;
    reject_unrepresentable_condition(facts.condition_json, "direct rule update")?;
    let resource = canonical_resource_key(facts.resource, facts.resource_id)?;

    let mut updated = head.payload.clone();
    updated.resource = resource;
    updated.action = facts.action.to_owned();
    // ALLOW-only 纵深防御：effect 显式钉为 ALLOW，绝不继承 head.payload.effect
    //（对齐 build_ruleset_update_draft；head 形状演化时 UPDATE 仍只能产出放行语义）。
    updated.effect = GrantEffect::Allow;
    updated.validity = validity;
    updated.revision = next_revision;
    updated.state = GrantState::Active;
    updated.provenance.operation_id = operation_id.to_owned();
    updated.provenance.event_id = Some(projection_identity.event_id.clone());
    updated.provenance.actor_user_id = Some(actor_user_id);
    let before_image_json = head.payload.canonical_input().map_err(map_contract_error)?;
    let before_digest_hex = sha256_hex_of(&before_image_json);

    let delta = GrantDelta::update(updated, expected_revision);
    delta.validate().map_err(map_contract_error)?;
    let resulting_grant = match &delta {
        GrantDelta::Update { grant, .. } => grant.clone(),
        other => unreachable!("UPDATE delta built in-place got {other:?}"),
    };

    let dependency_vector = DependencyVector::new(vec![DependencyVersion::new(
        card_dependency_id(facts.card_id),
        projection_identity.generation,
        projection_identity.fence,
    )
    .map_err(map_contract_error)?])
    .map_err(map_contract_error)?;
    let evidence = GrantEvidence {
        grant: resulting_grant.clone(),
        event_id: projection_identity.event_id.clone(),
        operation_id: operation_id.to_owned(),
        source_generation: projection_identity.generation,
        revoke_fence: projection_identity.fence,
        dependency_vector,
    };
    evidence.validate().map_err(map_contract_error)?;
    let invalidates_published_evidence = direct_update_authorization_content_changed(facts, head)?;

    Ok(DirectGrantDeltaDraft {
        tenant_id: identity_context.tenant_id,
        card_id: facts.card_id,
        event_id: projection_identity.event_id,
        operation_id: operation_id.to_owned(),
        grant_id: identity_context.grant_id,
        delta,
        semantic_hash_hex: resulting_grant
            .canonical_hash()
            .map_err(map_contract_error)?,
        dependency_hash_hex: evidence
            .dependency_vector
            .canonical_hash()
            .map_err(map_contract_error)?,
        before_image_json: Some(before_image_json),
        before_digest_hex: Some(before_digest_hex),
        source_generation: projection_identity.generation,
        revoke_fence: projection_identity.fence,
        invalidates_published_evidence,
    })
}

/// 纯组装一条 direct 规则删除贡献（REMOVE rev=head+1）。tombstone kind 固定为
/// `REMOVE`（source removal 语义）；旧 canonical grant 作为 before-image 成对落库。
///
/// 事件身份参数显式分离：
/// - `projection`：本批次共享的 CARD head/outbox source 事件身份（parent），
///   只用于 generation/fence 绑定与形状校验；
/// - `contribution_event_id`：该贡献自身落库使用的 delta/revision event id
///   （revision_request 与 delta_event_request 均绑定此值）。单条删除路径
///   （1 rule : 1 投影事件）沿用投影事件号本身；批量路径必须由调用方为每条
///   规则传入经 `derive_direct_contribution_event_id` 派生的独立 id，否则同一
///   parent 下第二个 REMOVE 必然撞上 `uk_ade_event` 全局唯一键。任意形态
///   不合法（空/超长/空白/控制字符）一律 fail-closed。
pub fn build_direct_remove_draft(
    facts: &DirectRuleLedgerFacts<'_>,
    head: &crate::GrantHeadSnapshot,
    operation_id: &str,
    projection: &crate::ProjectionEventIdentity,
    contribution_event_id: &str,
) -> Result<DirectGrantDeltaDraft, AstralError> {
    require_direct_rule_positive_ids(facts)?;
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "direct rule operation id must not be empty".into(),
        ));
    }
    let identity_context = resolve_direct_identity(facts)?;
    assert_direct_head_alignment(
        head,
        identity_context.grant_id,
        &identity_context.tenant_scope,
        facts.card_id,
        facts.user_id,
        facts.rule_id,
    )?;
    // source（parent）投影事件只提供 durable generation/fence 绑定。
    let projection_identity = validated_projection_identity(projection)?;
    // 本贡献自身的独立事件号。
    let contribution = validated_contribution_event_id(contribution_event_id)?;
    let expected_revision = head.entry.revision;

    let before_image_json = head.payload.canonical_input().map_err(map_contract_error)?;
    let before_digest_hex = sha256_hex_of(&before_image_json);
    let delta = GrantDelta::remove(identity_context.grant_id, expected_revision);
    delta.validate().map_err(map_contract_error)?;
    // REMOVE 无 canonical grant payload；semantic hash 锚定被移除的旧授权内容。
    let semantic_hash_hex = sha256_hex_of(&before_image_json);

    // 依赖向量仅做合同级校验 + hash（Remove evidence 不存在 canonical grant 对）。
    let dependency_vector = DependencyVector::new(vec![DependencyVersion::new(
        card_dependency_id(facts.card_id),
        projection_identity.generation,
        projection_identity.fence,
    )
    .map_err(map_contract_error)?])
    .map_err(map_contract_error)?;

    Ok(DirectGrantDeltaDraft {
        tenant_id: identity_context.tenant_id,
        card_id: facts.card_id,
        event_id: contribution,
        operation_id: operation_id.to_owned(),
        grant_id: identity_context.grant_id,
        delta,
        semantic_hash_hex,
        dependency_hash_hex: dependency_vector
            .canonical_hash()
            .map_err(map_contract_error)?,
        before_image_json: Some(before_image_json),
        before_digest_hex: Some(before_digest_hex),
        source_generation: projection_identity.generation,
        revoke_fence: projection_identity.fence,
        invalidates_published_evidence: true,
    })
}

/// 解析直接规则的稳定租户边界（fail-closed：NULL/非正租户拒绝，不回填假值）。
pub fn derive_direct_tenant(facts: &DirectRuleLedgerFacts<'_>) -> Result<i64, AstralError> {
    let tenant_id = facts.tenant_id.ok_or_else(|| {
        AstralError::Validation(
            "locked user_card has a NULL tenant_id; a tenant-scoped direct grant identity cannot be derived"
                .into(),
        )
    })?;
    require_positive(tenant_id, "tenant id")?;
    Ok(tenant_id)
}

/// 通过与 builder 完全相同的路径派生 direct grant 身份主键
/// （aggregate=`USER_CARD`、aggregate_id=card、source_entry=rule）。
pub fn derive_direct_identity(facts: &DirectRuleLedgerFacts<'_>) -> Result<GrantId, AstralError> {
    require_direct_rule_positive_ids(facts)?;
    let context = resolve_direct_identity(facts)?;
    Ok(context.grant_id)
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CurrentLedgerEntry, GrantHeadSnapshot};

    const TENANT_ID: i64 = 7;
    const DOMAIN_ID: i64 = 11;
    const CARD_ID: i64 = 21;
    const USER_ID: i64 = 42;
    const RULE_ID: i64 = 5077;
    const RULE_SET_ID: i64 = 91;
    const ENTRY_ID: i64 = 5;
    const REF_ID: i64 = 3;

    fn test_grant(resource: &str, action: &str, validity: ValidityWindow) -> CanonicalGrant {
        CanonicalGrant {
            grant_id: GrantId::parse("550e8400-e29b-41d4-a716-446655440001")
                .expect("test grant id must be a valid UUID"),
            revision: GrantRevision::initial(),
            state: GrantState::Active,
            source_kind: GrantSourceKind::Direct,
            binding_layer: BindingLayer::None,
            tenant: TenantScope::new(TENANT_ID, Some(DOMAIN_ID)).expect("tenant scope is valid"),
            card_id: CARD_ID,
            user_id: USER_ID,
            resource: resource.to_owned(),
            action: action.to_owned(),
            effect: GrantEffect::Allow,
            validity,
            provenance: GrantProvenance {
                source_id: CARD_ID.to_string(),
                source_entry: Some(RULE_ID.to_string()),
                binding_id: None,
                delegation_id: None,
                operation_id: "op-1".to_owned(),
                event_id: Some("event-1".to_owned()),
                actor_user_id: Some(USER_ID),
            },
        }
    }

    fn head_for(payload: CanonicalGrant) -> GrantHeadSnapshot {
        GrantHeadSnapshot {
            grant_id: payload.grant_id,
            entry: CurrentLedgerEntry {
                revision: payload.revision,
                state: payload.state,
                status_active: true,
            },
            payload,
        }
    }

    fn direct_facts<'a>(
        resource: &'a str,
        resource_id: Option<i64>,
        action: &'a str,
        valid_from: Option<&'a str>,
        valid_to: Option<&'a str>,
    ) -> DirectRuleLedgerFacts<'a> {
        DirectRuleLedgerFacts {
            tenant_id: Some(TENANT_ID),
            domain_id: Some(DOMAIN_ID),
            card_id: CARD_ID,
            user_id: USER_ID,
            rule_id: RULE_ID,
            resource,
            resource_id,
            action,
            condition_json: None,
            valid_from,
            valid_to,
        }
    }

    fn ruleset_facts<'a>(
        resource: &'a str,
        resource_id: Option<i64>,
        action: &'a str,
        valid_from: Option<&'a str>,
        valid_to: Option<&'a str>,
    ) -> RuleSetEntryLedgerFacts<'a> {
        RuleSetEntryLedgerFacts {
            tenant_id: TENANT_ID,
            domain_id: Some(DOMAIN_ID),
            card_id: CARD_ID,
            user_id: USER_ID,
            rule_set_id: RULE_SET_ID,
            entry_id: ENTRY_ID,
            ref_id: REF_ID,
            ref_type: "BASE",
            resource,
            resource_id,
            action,
            condition_json: None,
            valid_from,
            valid_to,
        }
    }

    /// 核心判定：no-op（四元组逐项相等）与 provenance-only（operation/event/
    /// actor 不同、授权内容全等）一律 false —— 纯 provenance-only/no-op UPDATE
    /// 必须保持原事件语义，不得把无关写打成 PENDING。
    #[test]
    fn core_gate_admits_noop_and_provenance_only_updates() {
        let before = test_grant("learn_course:*", "read", ValidityWindow::perpetual());
        // no-op：四元组逐项相等。
        assert!(!update_authorization_content_changed(
            &before,
            &before.resource,
            &before.action,
            &before.validity,
        ));
        // provenance-only：operation/event/actor 全部漂移，content 全等。
        let mut provenance_only = before.clone();
        provenance_only.provenance.operation_id = "op-2".to_owned();
        provenance_only.provenance.event_id = Some("event-2".to_owned());
        provenance_only.provenance.actor_user_id = Some(999);
        provenance_only.revision = before
            .revision
            .next()
            .expect("revision successor must exist");
        assert!(!update_authorization_content_changed(
            &provenance_only,
            &provenance_only.resource,
            &provenance_only.action,
            &provenance_only.validity,
        ));
        // 判定只消费 content 四字段：把 before 与 provenance-only 的 content
        // 交叉比较仍为 false（provenance 漂移不进入判定）。
        assert!(!update_authorization_content_changed(
            &before,
            &provenance_only.resource,
            &provenance_only.action,
            &provenance_only.validity,
        ));
    }

    /// 核心判定：resource/action/validity 任一变化都 flag（保守 revoke-class，
    /// delta 层无法可靠区分纯扩权与移动/收窄）。effect 维度由
    /// `before.effect != GrantEffect::Allow` 分支覆盖（GrantEffect 单变体
    /// ALLOW-only，运行时无法构造非 ALLOW before-image，结构性钉死）。
    #[test]
    fn core_gate_flags_every_authorization_content_change() {
        let before = test_grant("learn_course:*", "read", ValidityWindow::perpetual());
        // resource 类型移动。
        assert!(update_authorization_content_changed(
            &before,
            "learn_quiz:*",
            &before.action,
            &before.validity,
        ));
        // resource 对象作用域移动（type:1 → type:2 同形：旧对象授权被移除）。
        let object_before = test_grant("learn_course:1", "read", ValidityWindow::perpetual());
        assert!(update_authorization_content_changed(
            &object_before,
            "learn_course:2",
            &object_before.action,
            &object_before.validity,
        ));
        // action 变化。
        assert!(update_authorization_content_changed(
            &before,
            &before.resource,
            "write",
            &before.validity,
        ));
        // 有效期上界收窄/延长（两侧都是内容变化：窗口定义了放行时间面）。
        assert!(update_authorization_content_changed(
            &before,
            &before.resource,
            &before.action,
            &ValidityWindow {
                not_before: None,
                expires_at: Some(1_800_000_000),
            },
        ));
        assert!(update_authorization_content_changed(
            &test_grant(
                "learn_course:*",
                "read",
                ValidityWindow {
                    not_before: None,
                    expires_at: Some(1_800_000_000),
                },
            ),
            "learn_course:*",
            "read",
            &ValidityWindow {
                not_before: None,
                expires_at: Some(1_900_000_000),
            },
        ));
        // 有效期下界移动。
        assert!(update_authorization_content_changed(
            &before,
            &before.resource,
            &before.action,
            &ValidityWindow {
                not_before: Some(1),
                expires_at: None,
            },
        ));
        // effect 分支语义说明：非 ALLOW before-image 即内容变化（保守方向）；
        // 构造性运行时覆盖不可行（单变体枚举），由 builder 的
        // `updated.effect = GrantEffect::Allow` 钉死（各自模块守卫测试）。
    }

    /// direct helper：no-op → false；resource 作用域/action/有效期变化 → true；
    /// 非法 resource type（canonical_resource_key 门禁）原样 fail-closed。
    #[test]
    fn direct_helper_matches_before_image_content_diff() {
        let head = head_for(test_grant(
            "learn_course:*",
            "read",
            ValidityWindow::perpetual(),
        ));
        // no-op：与 before-image 逐项相等。helper 形参只有 content 四字段，
        // 结构上不消费 operation/event/actor —— provenance-only 漂移不可能
        // 进入判定（对齐核心判定的交叉比较证明）。
        assert!(!direct_update_authorization_content_changed(
            &direct_facts("learn_course", None, "read", None, None),
            &head,
        )
        .unwrap());
        // 对象作用域变化（type:* → type:9）。
        assert!(direct_update_authorization_content_changed(
            &direct_facts("learn_course", Some(9), "read", None, None),
            &head,
        )
        .unwrap());
        // action 变化。
        assert!(direct_update_authorization_content_changed(
            &direct_facts("learn_course", None, "write", None, None),
            &head,
        )
        .unwrap());
        // 有效期变化。
        assert!(direct_update_authorization_content_changed(
            &direct_facts(
                "learn_course",
                None,
                "read",
                Some("2026-01-01"),
                Some("2026-12-31")
            ),
            &head,
        )
        .unwrap());
        // 非法 resource type：与 builder 同一 fail-closed 门禁。
        assert!(direct_update_authorization_content_changed(
            &direct_facts("learn:course", None, "read", None, None),
            &head,
        )
        .is_err());
        assert!(direct_update_authorization_content_changed(
            &direct_facts("   ", None, "read", None, None),
            &head,
        )
        .is_err());
    }

    /// ruleset helper：no-op → false；resource/action/有效期变化 → true；
    /// 非法 resource type fail-closed。判定与 `build_ruleset_update_draft`
    /// 同源（canonical_resource_key / parse_validity_window）。
    #[test]
    fn ruleset_helper_matches_before_image_content_diff() {
        let mut payload = test_grant("learn_course:*", "read", ValidityWindow::perpetual());
        payload.source_kind = GrantSourceKind::RuleSet;
        payload.binding_layer = BindingLayer::Base;
        payload.provenance.source_id = RULE_SET_ID.to_string();
        payload.provenance.source_entry = Some(ENTRY_ID.to_string());
        payload.provenance.binding_id = Some(REF_ID.to_string());
        let head = head_for(payload);
        // no-op。
        assert!(!ruleset_update_authorization_content_changed(
            &ruleset_facts("learn_course", None, "read", None, None),
            &head,
        )
        .unwrap());
        // resource 移动。
        assert!(ruleset_update_authorization_content_changed(
            &ruleset_facts("learn_quiz", None, "read", None, None),
            &head,
        )
        .unwrap());
        // 对象作用域移动。
        assert!(ruleset_update_authorization_content_changed(
            &ruleset_facts("learn_course", Some(3), "read", None, None),
            &head,
        )
        .unwrap());
        // action 变化。
        assert!(ruleset_update_authorization_content_changed(
            &ruleset_facts("learn_course", None, "write", None, None),
            &head,
        )
        .unwrap());
        // 有效期变化。
        assert!(ruleset_update_authorization_content_changed(
            &ruleset_facts("learn_course", None, "read", Some("2026-01-01"), None),
            &head,
        )
        .unwrap());
        // 非法 resource type fail-closed。
        assert!(ruleset_update_authorization_content_changed(
            &ruleset_facts("   ", None, "read", None, None),
            &head,
        )
        .is_err());
    }
}
