//! 组织范围（ORG_SCOPE）共享类型合同 — Phase 2 default-off。
//!
//! 本模块是多租户行政祖先树/共享单元授权的**唯一共享类型事实源**（types owner 维护，
//! 实现合同见 `Docs/架构/Rust架构设计/Rust多租户聚合分区与组织层级设计_V0.1.md`）：
//!
//! - 行政边/授权 grant/本地剪裁/成员资格均为独立 typed 事实，全部带稳定 UUID、
//!   显式 revision/generation/fence 与批准 operation 证明；绝不从身份或目录字段推导授权。
//! - serde：全部**结构体** `deny_unknown_fields`（未知字段一律拒绝）；授权关键
//!   布尔（active/delegable）为必填字段，缺失即反序列化失败；`Option` 语义字段
//!   （domain/subject/parent）带**哨兵 default**——JSON 缺键时填入非法哨兵值，
//!   由 `validate()` fail-closed 拒绝，因此"缺字段"不可能被解释成更宽的默认授权
//!   （None 必须显式写 `null`）。tagged enum 的例外见各类型注释。
//! - 本模块零 I/O、零 panic：对外部数据只返回 typed [`OrgError`]。
//! - 资源/动作语义与既有引擎匹配器对齐（`crate::registry::parse_resource_key`
//!   同形态语义 / `get_alias_sources` 别名直接复用）：对象/类型/全局三级 +
//!   write 别名，保守可证明才匹配。
//!
//! 聚合身份仍为 `(tenant_id, 'ORG_SCOPE', aggregate_id)`；首版每租户一个单元，
//! `aggregate_id = tenant_id`（由 DB owner 落库，不在本模块重复校验）。

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::registry::get_alias_sources;
use crate::ValidityWindow;

// ─────────────────────────────────────────────────────────────────────────────
// 常量与边界
// ─────────────────────────────────────────────────────────────────────────────

/// ORG_SCOPE 聚合在投影/发布存储中的 `aggregate_type` 常量
/// （对齐 `grant_ledger::RULE_SET_AGGREGATE_TYPE` 的字符串常量模式；
/// `ProjectionAggregate` 枚举保持只覆盖源 mutation 通道，不因 ORG_SCOPE 扩张）。
pub const ORG_SCOPE_AGGREGATE_TYPE: &str = "ORG_SCOPE";

/// 资源/动作键长度上限（对齐 astral-db `MAX_PROJECTION_KEY_LENGTH`）。
pub const MAX_ORG_KEY_LEN: usize = 191;
/// 操作 ID/编译器戳长度上限（对齐 `grant_ledger::MAX_HEADER_OPERATION_ID_LENGTH`）。
pub const MAX_ORG_ID_TEXT_LEN: usize = 64;
/// 单元编译输入的 grant 数上限（防御性；超限 fail-closed 走显式全量路径）。
pub const MAX_ORG_GRANTS_PER_INPUT: usize = 10_000;
/// 单元编译输入的 mask 数上限。
pub const MAX_ORG_MASKS_PER_INPUT: usize = 1_000;
/// 编译输入/publication 可钉住的祖先依赖数上限。
///
/// `dependencies` 是**传递完备的扁平祖先向量**（直接父 + 全部更远祖先，每个行政
/// 祖先层级恰一项；根单元为空），见 `OrgPublication` 与 `OrgCompileInput` 合同。
/// 行政树深度上界即 [`MAX_ORG_PROVENANCE_CHAIN`]，深度 D 的单元恰有 D 项祖先依赖，
/// 因此本界必须与 provenance 深度上界相等：两者脱钩会使许可拓扑内的深树单元被
/// 错误 fail-closed（永远无法发布/编译）。
pub const MAX_ORG_DEPENDENCIES: usize = MAX_ORG_PROVENANCE_CHAIN;
/// 编译输入可携带的直接父 publication 数上限。
///
/// 合同强约束 root=0 / child=1（`OrgCompileInput::validate` 的形状匹配拒绝其余
/// 形态；DB loader 亦只装载 0 或 1 项）；本常量把同一事实表达为公开边界，仅用于
/// 对超量输入提前 fail-closed，不放宽也不收紧任何已被形状匹配拒绝的输入。
pub const MAX_ORG_PARENT_PUBLICATIONS: usize = 1;
/// provenance 链最大深度（行政树深度上界）。
pub const MAX_ORG_PROVENANCE_CHAIN: usize = 64;
/// 单个 publication 的段数上限（对齐 `MAX_SEGMENTS_PER_MANIFEST`）。
pub const MAX_ORG_SEGMENTS_PER_PUBLICATION: usize = 100_000;
/// 单段贡献数上限（对齐 `MAX_SEGMENT_PAYLOAD_BYTES` 的行数侧保守界）。
pub const MAX_ORG_CONTRIBUTIONS_PER_SEGMENT: usize = 4_096;
/// RootInit 初始 grant 数上限。
pub const MAX_ORG_ROOT_INIT_GRANTS: usize = 1_000;
/// 单个主体可同时持有的 active ORG_SCOPE membership 数上限。
///
/// 上限按 `user_id` 全局计数，不按行政根或租户拆分；有效期已经结束但尚未撤销的
/// active 行仍占用名额，避免把过期状态当作静默扩权或跨单元并行任职的旁路。
pub const MAX_ORG_ACTIVE_MEMBERSHIPS_PER_USER: usize = 8;

// ─────────────────────────────────────────────────────────────────────────────
// 错误合同
// ─────────────────────────────────────────────────────────────────────────────

/// ORG_SCOPE 合同错误的稳定机器码全集。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrgErrorCode {
    InvalidField,
    IdentifierTooLong,
    NilUuid,
    NonCanonicalUuid,
    DigestMismatch,
    Deserialization,
    Serialization,
    TenantMismatch,
    RootMismatch,
    OriginMismatch,
    ParentNotDelegable,
    SelfReference,
    MaskTargetSelf,
    DuplicateGrant,
    DuplicateMask,
    DuplicateProvenance,
    DependencyCountMismatch,
    DependencyMismatch,
    ParentRequiredForChild,
    ParentForbiddenForRoot,
    MasksForbiddenForRoot,
    ImmutableFieldChanged,
    RevisionNotAdvanced,
    InvalidScopeRelation,
    SegmentOrderInvalid,
    SegmentIndexInvalid,
    BoundsExceeded,
    MembershipInactive,
    MembershipExpired,
    NotAdmissionReady,
    InvalidRequest,
}

impl OrgErrorCode {
    /// 稳定机器码（日志/审计/DB 落库用，绝不漂移）。
    pub const fn as_str(self) -> &'static str {
        match self {
            OrgErrorCode::InvalidField => "org_scope.invalid_field",
            OrgErrorCode::IdentifierTooLong => "org_scope.identifier_too_long",
            OrgErrorCode::NilUuid => "org_scope.nil_uuid",
            OrgErrorCode::NonCanonicalUuid => "org_scope.non_canonical_uuid",
            OrgErrorCode::DigestMismatch => "org_scope.digest_mismatch",
            OrgErrorCode::Deserialization => "org_scope.deserialization",
            OrgErrorCode::Serialization => "org_scope.serialization",
            OrgErrorCode::TenantMismatch => "org_scope.tenant_mismatch",
            OrgErrorCode::RootMismatch => "org_scope.root_mismatch",
            OrgErrorCode::OriginMismatch => "org_scope.origin_mismatch",
            OrgErrorCode::ParentNotDelegable => "org_scope.parent_not_delegable",
            OrgErrorCode::SelfReference => "org_scope.self_reference",
            OrgErrorCode::MaskTargetSelf => "org_scope.mask_target_self",
            OrgErrorCode::DuplicateGrant => "org_scope.duplicate_grant",
            OrgErrorCode::DuplicateMask => "org_scope.duplicate_mask",
            OrgErrorCode::DuplicateProvenance => "org_scope.duplicate_provenance",
            OrgErrorCode::DependencyCountMismatch => "org_scope.dependency_count_mismatch",
            OrgErrorCode::DependencyMismatch => "org_scope.dependency_mismatch",
            OrgErrorCode::ParentRequiredForChild => "org_scope.parent_required_for_child",
            OrgErrorCode::ParentForbiddenForRoot => "org_scope.parent_forbidden_for_root",
            OrgErrorCode::MasksForbiddenForRoot => "org_scope.masks_forbidden_for_root",
            OrgErrorCode::ImmutableFieldChanged => "org_scope.immutable_field_changed",
            OrgErrorCode::RevisionNotAdvanced => "org_scope.revision_not_advanced",
            OrgErrorCode::InvalidScopeRelation => "org_scope.invalid_scope_relation",
            OrgErrorCode::SegmentOrderInvalid => "org_scope.segment_order_invalid",
            OrgErrorCode::SegmentIndexInvalid => "org_scope.segment_index_invalid",
            OrgErrorCode::BoundsExceeded => "org_scope.bounds_exceeded",
            OrgErrorCode::MembershipInactive => "org_scope.membership_inactive",
            OrgErrorCode::MembershipExpired => "org_scope.membership_expired",
            OrgErrorCode::NotAdmissionReady => "org_scope.not_admission_ready",
            OrgErrorCode::InvalidRequest => "org_scope.invalid_request",
        }
    }
}

/// ORG_SCOPE typed 合同错误：稳定机器码 + 人类可读 detail。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgError {
    pub code: OrgErrorCode,
    pub message: String,
}

impl OrgError {
    pub fn new(code: OrgErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for OrgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "org_scope error code={} detail={}",
            self.code.as_str(),
            self.message
        )
    }
}

impl std::error::Error for OrgError {}

type OrgResult<T> = Result<T, OrgError>;

// ─────────────────────────────────────────────────────────────────────────────
// 纯校验 helpers（本模块私有）
// ─────────────────────────────────────────────────────────────────────────────

fn org_validate_identifier(value: &str, field: &'static str, max_len: usize) -> OrgResult<()> {
    if value.is_empty() {
        return Err(OrgError::new(
            OrgErrorCode::InvalidField,
            format!("{field} must not be empty"),
        ));
    }
    if value.len() > max_len {
        return Err(OrgError::new(
            OrgErrorCode::IdentifierTooLong,
            format!("{field} exceeds {max_len} bytes"),
        ));
    }
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(OrgError::new(
            OrgErrorCode::InvalidField,
            format!("{field} contains whitespace or control characters"),
        ));
    }
    Ok(())
}

fn org_validate_positive_i64(value: i64, field: &'static str) -> OrgResult<()> {
    if value <= 0 {
        return Err(OrgError::new(
            OrgErrorCode::InvalidField,
            format!("{field} must be positive, got {value}"),
        ));
    }
    Ok(())
}

fn org_validate_u64_nonzero(value: u64, field: &'static str) -> OrgResult<()> {
    if value == 0 {
        return Err(OrgError::new(
            OrgErrorCode::InvalidField,
            format!("{field} must be greater than zero"),
        ));
    }
    Ok(())
}

/// 稳定 ID 必须是规范小写连字符 UUID（拒绝 nil / 大写 / 大括号等非规范形态）。
fn org_validate_stable_uuid(value: &str, field: &'static str) -> OrgResult<()> {
    org_validate_identifier(value, field, 36)?;
    let parsed = Uuid::parse_str(value).map_err(|error| {
        OrgError::new(
            OrgErrorCode::InvalidField,
            format!("{field} is not a valid UUID: {error}"),
        )
    })?;
    if parsed.is_nil() {
        return Err(OrgError::new(
            OrgErrorCode::NilUuid,
            format!("{field} must not be the nil UUID"),
        ));
    }
    if parsed.to_string() != value {
        return Err(OrgError::new(
            OrgErrorCode::NonCanonicalUuid,
            format!("{field} must be the canonical lowercase hyphenated UUID form"),
        ));
    }
    Ok(())
}

fn org_validate_operation_id(value: &str, field: &'static str) -> OrgResult<()> {
    org_validate_identifier(value, field, MAX_ORG_ID_TEXT_LEN)
}

fn org_window_valid(validity: &ValidityWindow) -> OrgResult<()> {
    validity
        .validate()
        .map_err(|error| OrgError::new(OrgErrorCode::InvalidField, format!("validity: {error}")))
}

fn org_sha256_hex(input: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

// ─────────────────────────────────────────────────────────────────────────────
// 资源/动作形态与匹配语义（与既有引擎匹配器对齐）
// ─────────────────────────────────────────────────────────────────────────────

/// 资源键的规范化形态：`*` 全局 / `type`|`type:*` 类型级 / `type:id` 对象级。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrgResourceForm {
    Global,
    TypeLevel {
        type_name: String,
    },
    Object {
        type_name: String,
        object_id: String,
    },
}

/// 解析并校验资源键形态（`registry::parse_resource_key` 同语义 + fail-closed 形态校验）。
pub fn org_parse_resource_form(key: &str) -> OrgResult<OrgResourceForm> {
    org_validate_identifier(key, "resource", MAX_ORG_KEY_LEN)?;
    if key == "*" {
        return Ok(OrgResourceForm::Global);
    }
    match key.rfind(':') {
        Some(index) => {
            let type_name = &key[..index];
            let id_part = &key[index + 1..];
            if type_name.is_empty() || type_name.contains('*') {
                return Err(OrgError::new(
                    OrgErrorCode::InvalidField,
                    format!("resource type segment is invalid: {key}"),
                ));
            }
            if id_part == "*" {
                Ok(OrgResourceForm::TypeLevel {
                    type_name: type_name.to_owned(),
                })
            } else if id_part.is_empty() || id_part.contains('*') {
                Err(OrgError::new(
                    OrgErrorCode::InvalidField,
                    format!("resource object segment is invalid: {key}"),
                ))
            } else {
                Ok(OrgResourceForm::Object {
                    type_name: type_name.to_owned(),
                    object_id: id_part.to_owned(),
                })
            }
        }
        None => {
            if key.contains('*') {
                return Err(OrgError::new(
                    OrgErrorCode::InvalidField,
                    format!("resource type segment is invalid: {key}"),
                ));
            }
            Ok(OrgResourceForm::TypeLevel {
                type_name: key.to_owned(),
            })
        }
    }
}

/// 包含关系：祖先形态是否覆盖后代形态（Global ⊇ Type ⊇ Object，同类型内）。
pub fn org_resource_form_covers(ancestor: &OrgResourceForm, descendant: &OrgResourceForm) -> bool {
    match (ancestor, descendant) {
        (OrgResourceForm::Global, _) => true,
        (
            OrgResourceForm::TypeLevel {
                type_name: ancestor_type,
            },
            OrgResourceForm::TypeLevel {
                type_name: descendant_type,
            },
        ) => ancestor_type == descendant_type,
        (
            OrgResourceForm::TypeLevel {
                type_name: ancestor_type,
            },
            OrgResourceForm::Object {
                type_name: descendant_type,
                ..
            },
        ) => ancestor_type == descendant_type,
        (
            OrgResourceForm::Object {
                type_name: ancestor_type,
                object_id: ancestor_object,
            },
            OrgResourceForm::Object {
                type_name: descendant_type,
                object_id: descendant_object,
            },
        ) => ancestor_type == descendant_type && ancestor_object == descendant_object,
        (OrgResourceForm::TypeLevel { .. }, OrgResourceForm::Global) => false,
        (OrgResourceForm::Object { .. }, _) => false,
    }
}

/// 请求侧匹配：contribution 的资源形态是否覆盖请求形态（fail-closed：形态非法即不匹配）。
pub fn org_resource_matches(request_resource: &str, contribution_resource: &str) -> bool {
    match (
        org_parse_resource_form(request_resource),
        org_parse_resource_form(contribution_resource),
    ) {
        (Ok(request), Ok(contribution)) => org_resource_form_covers(&contribution, &request),
        _ => false,
    }
}

/// 动作覆盖：`*` ⊇ 一切；`write` ⊇ {write, create, update, delete}（复用 registry 别名映射）。
pub fn org_action_covers(ancestor: &str, descendant: &str) -> bool {
    if ancestor == "*" {
        return true;
    }
    if descendant == "*" {
        return false;
    }
    if ancestor == descendant {
        return true;
    }
    ancestor == "write" && get_alias_sources(descendant).contains(&"write")
}

/// 请求侧动作匹配（与引擎 `get_alias_sources` 语义一致：请求 create/update/delete
/// 可命中 write 来源 grant；`*` 命中一切）。
pub fn org_action_matches(request_action: &str, contribution_action: &str) -> bool {
    contribution_action == "*"
        || contribution_action == request_action
        || (contribution_action == "write" && get_alias_sources(request_action).contains(&"write"))
}

fn org_validate_action(value: &str) -> OrgResult<()> {
    org_validate_identifier(value, "action", MAX_ORG_KEY_LEN)?;
    if value != "*" && value.contains('*') {
        return Err(OrgError::new(
            OrgErrorCode::InvalidField,
            "action must be an exact identifier or the single '*' wildcard",
        ));
    }
    Ok(())
}

/// 有效期包含：祖先窗口必须覆盖后代窗口（None = 无界）。
pub fn org_window_covers(ancestor: &ValidityWindow, descendant: &ValidityWindow) -> bool {
    let ancestor_start = ancestor.not_before.unwrap_or(i64::MIN);
    let ancestor_end = ancestor.expires_at.unwrap_or(i64::MAX);
    let descendant_start = descendant.not_before.unwrap_or(i64::MIN);
    let descendant_end = descendant.expires_at.unwrap_or(i64::MAX);
    ancestor_start <= descendant_start && descendant_end <= ancestor_end
}

// ─────────────────────────────────────────────────────────────────────────────
// 核心事实类型
// ─────────────────────────────────────────────────────────────────────────────

/// 段/桶的精确键：单元内按 `(resource, action)` 精确分桶（多合法来源保留在桶内有序列表）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgScopeKey {
    pub resource: String,
    pub action: String,
}

impl OrgScopeKey {
    pub fn validate(&self) -> OrgResult<()> {
        org_parse_resource_form(&self.resource).map(|_| ())?;
        org_validate_action(&self.action)
    }
}

/// 授权作用域：资源租户 V1 恒等（跨租户资源访问必须显式批准另行建模）、
/// domain 可约束、有效期复用 [`ValidityWindow`]。
///
/// serde：`domainId` 缺键时填哨兵 `Some(-1)` 并由 `validate()` 拒绝——
/// "无 domain 约束"必须显式写 `null`，不得靠省略字段静默放宽。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgScope {
    pub resource_tenant_id: i64,
    #[serde(default = "org_sentinel_domain")]
    pub domain_id: Option<i64>,
    pub resource: String,
    pub action: String,
    pub validity: ValidityWindow,
}

fn org_sentinel_domain() -> Option<i64> {
    Some(-1)
}

impl OrgScope {
    pub fn validate(&self) -> OrgResult<()> {
        org_validate_positive_i64(self.resource_tenant_id, "scope.resource_tenant_id")?;
        if let Some(domain_id) = self.domain_id {
            org_validate_positive_i64(domain_id, "scope.domain_id")?;
        }
        org_parse_resource_form(&self.resource).map(|_| ())?;
        org_validate_action(&self.action)?;
        org_window_valid(&self.validity)
    }

    /// 祖先作用域是否可证明覆盖后代作用域（资源/动作/租户/domain/有效期全维）。
    pub fn covers(&self, descendant: &OrgScope) -> OrgResult<()> {
        org_scope_covers(self, descendant)
    }
}

/// 作用域包含的纯函数形态（供 compiler 与测试复用）。
pub fn org_scope_covers(ancestor: &OrgScope, descendant: &OrgScope) -> OrgResult<()> {
    if ancestor.resource_tenant_id != descendant.resource_tenant_id {
        return Err(OrgError::new(
            OrgErrorCode::InvalidScopeRelation,
            "resource tenant must remain exact in v1 (no implicit cross-tenant resource scope)",
        ));
    }
    match ancestor.domain_id {
        None => {}
        Some(ancestor_domain) => match descendant.domain_id {
            Some(descendant_domain) if descendant_domain == ancestor_domain => {}
            _ => {
                return Err(OrgError::new(
                    OrgErrorCode::InvalidScopeRelation,
                    "domain narrowing is not provable: descendant must carry the same explicit domain",
                ));
            }
        },
    }
    let ancestor_form = org_parse_resource_form(&ancestor.resource)?;
    let descendant_form = org_parse_resource_form(&descendant.resource)?;
    if !org_resource_form_covers(&ancestor_form, &descendant_form) {
        return Err(OrgError::new(
            OrgErrorCode::InvalidScopeRelation,
            format!(
                "resource coverage is not provable: {} does not cover {}",
                ancestor.resource, descendant.resource
            ),
        ));
    }
    if !org_action_covers(&ancestor.action, &descendant.action) {
        return Err(OrgError::new(
            OrgErrorCode::InvalidScopeRelation,
            format!(
                "action coverage is not provable: {} does not cover {}",
                ancestor.action, descendant.action
            ),
        ));
    }
    if !org_window_covers(&ancestor.validity, &descendant.validity) {
        return Err(OrgError::new(
            OrgErrorCode::InvalidScopeRelation,
            "validity window is not contained in the ancestor window",
        ));
    }
    Ok(())
}

/// 主体：`None` = 单元共享贡献；`Some` = 绑定 (user, card) 的个人分支。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgSubject {
    pub user_id: i64,
    pub card_id: i64,
}

impl OrgSubject {
    pub fn validate(&self) -> OrgResult<()> {
        org_validate_positive_i64(self.user_id, "subject.user_id")?;
        org_validate_positive_i64(self.card_id, "subject.card_id")
    }
}

/// 匹配索引的主体过滤（readonly 索引的查询参数）。
///
/// 只有两种 fail-closed 过滤：单元共享贡献（[`OrgSubjectFilter::SharedOnly`]）或
/// 精确 (user, card) 绑定的个人贡献（[`OrgSubjectFilter::PersonalOf`]）。
/// **刻意不提供 `All` 通配主体过滤**：通配会让调用方意外匹配到其他用户的
/// Personal 贡献。需要"共享 + 本人个人"组合时，由调用方按贡献自身的
/// `subject` 分支分别构造两种过滤（见 `sod_check` 与 `org_admission` 的用法），
/// 而不是放宽本枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrgSubjectFilter {
    SharedOnly,
    PersonalOf { user_id: i64, card_id: i64 },
}

/// 请求级匹配判定（fail-closed）：主体过滤 + 资源租户恒等 + domain 严格相等 +
/// 有效期统一时钟。资源/动作形态匹配由调用方在桶级完成（readonly 索引）。
pub fn org_contribution_matches_request(
    contribution: &OrgContribution,
    request: &OrgReadRequest,
    filter: OrgSubjectFilter,
) -> bool {
    match filter {
        OrgSubjectFilter::SharedOnly => {
            if contribution.subject.is_some() {
                return false;
            }
        }
        OrgSubjectFilter::PersonalOf { user_id, card_id } => match contribution.subject.as_ref() {
            Some(subject) if subject.user_id == user_id && subject.card_id == card_id => {}
            _ => return false,
        },
    }
    if contribution.scope.resource_tenant_id != request.resource_tenant_id {
        return false;
    }
    if let Some(domain_id) = contribution.scope.domain_id {
        if request.domain_id != Some(domain_id) {
            return false;
        }
    }
    contribution
        .scope
        .validity
        .is_valid_at(request.now_unix_seconds)
}

/// 精确祖先贡献引用：tenant + grant_id + revision（revision 漂移即未对账，绝不静默匹配）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgGrantRef {
    pub tenant_id: i64,
    pub grant_id: String,
    pub revision: u64,
}

impl OrgGrantRef {
    pub fn validate(&self) -> OrgResult<()> {
        org_validate_positive_i64(self.tenant_id, "grant_ref.tenant_id")?;
        org_validate_stable_uuid(&self.grant_id, "grant_ref.grant_id")?;
        org_validate_u64_nonzero(self.revision, "grant_ref.revision")
    }
}

/// 组织授权 grant（单元账本事实）。
///
/// 不变量（`validate` 强制 + `org_grant_revision_compatible` 跨 revision 强制）：
/// - `parent Some(ref)`：ref.tenant 必须 == origin（origin = 直接行政上级，唯一授权来源）；
/// - `parent None`：仅行政根的自源初始授权可用（origin == receiving）；
/// - 跨 revision：receiving/origin/root/delegable/parent/subject 不可变；
///   scope/active/operation 可变（scope 变更会使后代依赖进入未对账状态）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgGrant {
    pub grant_id: String,
    pub revision: u64,
    pub receiving_tenant_id: i64,
    pub origin_tenant_id: i64,
    pub root_tenant_id: i64,
    pub scope: OrgScope,
    pub delegable: bool,
    #[serde(default = "org_sentinel_parent_ref")]
    pub parent: Option<OrgGrantRef>,
    #[serde(default = "org_sentinel_subject")]
    pub subject: Option<OrgSubject>,
    pub active: bool,
    pub operation_id: String,
}

fn org_sentinel_parent_ref() -> Option<OrgGrantRef> {
    Some(OrgGrantRef {
        tenant_id: -1,
        grant_id: "00000000-0000-0000-0000-000000000000".to_owned(),
        revision: 0,
    })
}

fn org_sentinel_subject() -> Option<OrgSubject> {
    Some(OrgSubject {
        user_id: -1,
        card_id: -1,
    })
}

impl OrgGrant {
    pub fn validate(&self) -> OrgResult<()> {
        org_validate_stable_uuid(&self.grant_id, "grant.grant_id")?;
        org_validate_u64_nonzero(self.revision, "grant.revision")?;
        org_validate_positive_i64(self.receiving_tenant_id, "grant.receiving_tenant_id")?;
        org_validate_positive_i64(self.origin_tenant_id, "grant.origin_tenant_id")?;
        org_validate_positive_i64(self.root_tenant_id, "grant.root_tenant_id")?;
        self.scope.validate()?;
        org_validate_operation_id(&self.operation_id, "grant.operation_id")?;
        if let Some(subject) = &self.subject {
            subject.validate()?;
        }
        match &self.parent {
            Some(parent) => {
                parent.validate()?;
                if parent.tenant_id != self.origin_tenant_id {
                    return Err(OrgError::new(
                        OrgErrorCode::OriginMismatch,
                        "grant parent tenant must equal grant origin tenant",
                    ));
                }
            }
            None => {
                if self.origin_tenant_id != self.receiving_tenant_id {
                    return Err(OrgError::new(
                        OrgErrorCode::OriginMismatch,
                        "parentless grants must be self-originated (authority-root genesis only)",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// 跨 revision 不变式：origins 与 parent provenance 不可变；revision 必须严格前进。
pub fn org_grant_revision_compatible(previous: &OrgGrant, next: &OrgGrant) -> OrgResult<()> {
    if previous.grant_id != next.grant_id {
        return Err(OrgError::new(
            OrgErrorCode::InvalidRequest,
            "revision compatibility requires the same grant_id",
        ));
    }
    org_validate_u64_nonzero(next.revision, "grant.revision")?;
    if next.revision <= previous.revision {
        return Err(OrgError::new(
            OrgErrorCode::RevisionNotAdvanced,
            format!(
                "grant {} revision must advance: {} -> {}",
                previous.grant_id, previous.revision, next.revision
            ),
        ));
    }
    let immutable_checks: [(&'static str, bool); 6] = [
        (
            "receiving_tenant_id",
            previous.receiving_tenant_id == next.receiving_tenant_id,
        ),
        (
            "origin_tenant_id",
            previous.origin_tenant_id == next.origin_tenant_id,
        ),
        (
            "root_tenant_id",
            previous.root_tenant_id == next.root_tenant_id,
        ),
        ("delegable", previous.delegable == next.delegable),
        ("parent", previous.parent == next.parent),
        ("subject", previous.subject == next.subject),
    ];
    for (field, equal) in immutable_checks {
        if !equal {
            return Err(OrgError::new(
                OrgErrorCode::ImmutableFieldChanged,
                format!(
                    "grant {} field {field} is immutable across revisions",
                    previous.grant_id
                ),
            ));
        }
    }
    Ok(())
}

/// 本级精确来源剪裁（mask）：屏蔽指向祖先贡献的 exact identity/revision。
/// 同源 grant 换 revision 重发不得"洗白"mask——revision 漂移进入未对账 PENDING。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgMask {
    pub mask_id: String,
    pub tenant_id: i64,
    pub target: OrgGrantRef,
    pub active: bool,
    pub revision: u64,
    pub operation_id: String,
}

impl OrgMask {
    pub fn validate(&self) -> OrgResult<()> {
        org_validate_stable_uuid(&self.mask_id, "mask.mask_id")?;
        org_validate_positive_i64(self.tenant_id, "mask.tenant_id")?;
        self.target.validate()?;
        org_validate_u64_nonzero(self.revision, "mask.revision")?;
        org_validate_operation_id(&self.operation_id, "mask.operation_id")?;
        if self.target.tenant_id == self.tenant_id {
            return Err(OrgError::new(
                OrgErrorCode::MaskTargetSelf,
                "mask targets ancestor contributions only; revoke own grants via the grant ledger",
            ));
        }
        Ok(())
    }
}

/// 成员资格：独立版本化事实，与单元内容分离；card pair/租户匹配由 DB/运行期校验，
/// 本类型只承载结构与时间窗。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgMembership {
    pub membership_id: String,
    pub tenant_id: i64,
    pub root_tenant_id: i64,
    pub user_id: i64,
    pub identity_card_id: i64,
    pub card_id: i64,
    pub revision: u64,
    pub active: bool,
    pub validity: ValidityWindow,
    pub operation_id: String,
}

impl OrgMembership {
    pub fn validate(&self) -> OrgResult<()> {
        org_validate_stable_uuid(&self.membership_id, "membership.membership_id")?;
        org_validate_positive_i64(self.tenant_id, "membership.tenant_id")?;
        org_validate_positive_i64(self.root_tenant_id, "membership.root_tenant_id")?;
        org_validate_positive_i64(self.user_id, "membership.user_id")?;
        org_validate_positive_i64(self.identity_card_id, "membership.identity_card_id")?;
        org_validate_positive_i64(self.card_id, "membership.card_id")?;
        org_validate_u64_nonzero(self.revision, "membership.revision")?;
        org_window_valid(&self.validity)?;
        org_validate_operation_id(&self.operation_id, "membership.operation_id")
    }

    pub fn is_valid_at(&self, unix_seconds: i64) -> bool {
        self.validity.is_valid_at(unix_seconds)
    }
}

/// 已编译单元钉住的祖先头栅栏。
///
/// **传递完备向量**：`OrgPublication.dependencies` 必须覆盖本单元的**全部祖先**
/// （直接行政父 + 所有更远的祖先，直至行政根），按 `tenant_id` 严格排序——
/// 不是只有直接父。这样 reader 只需按本单元 publication 内的有界 head ID
/// 逐项 fresh-check 全部祖先源头即可即时感知任意层级撤销/移动（例如祖父撤销
/// 而父尚未重发布时，子单元钉住的祖父栅栏即失配 → 立即 PENDING），
/// 绝不在运行时遍历图发现祖先。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgDependency {
    pub tenant_id: i64,
    pub generation: u64,
    pub revoke_fence: u64,
    pub relationship_revision: u64,
}

impl OrgDependency {
    pub fn validate(&self) -> OrgResult<()> {
        org_validate_positive_i64(self.tenant_id, "dependency.tenant_id")?;
        org_validate_u64_nonzero(self.generation, "dependency.generation")?;
        if self.revoke_fence > self.generation {
            return Err(OrgError::new(
                OrgErrorCode::InvalidField,
                format!(
                    "dependency revoke_fence {} cannot exceed generation {}",
                    self.revoke_fence, self.generation
                ),
            ));
        }
        org_validate_u64_nonzero(
            self.relationship_revision,
            "dependency.relationship_revision",
        )
    }
}

/// 依赖栅栏必须与祖先 publication 的发布身份逐项一致。
pub fn org_dependency_matches_publication(
    dependency: &OrgDependency,
    publication: &OrgPublication,
) -> bool {
    dependency.tenant_id == publication.tenant_id
        && dependency.generation == publication.generation
        && dependency.revoke_fence == publication.revoke_fence
        && dependency.relationship_revision == publication.relationship_revision
}

#[derive(Serialize)]
struct OrgDependencyDigestInput<'a> {
    domain: &'static str,
    dependencies: Vec<&'a OrgDependency>,
}

const ORG_DEPENDENCY_DIGEST_DOMAIN: &str = "astral-org-dependencies-v1";

/// 依赖向量摘要：排序后的依赖栅栏列表的 sha256（确定性，与输入顺序无关）。
pub fn org_dependency_digest_hex(dependencies: &[OrgDependency]) -> OrgResult<String> {
    let mut sorted: Vec<&OrgDependency> = dependencies.iter().collect();
    sorted.sort();
    let input = OrgDependencyDigestInput {
        domain: ORG_DEPENDENCY_DIGEST_DOMAIN,
        dependencies: sorted,
    };
    let encoded = serde_json::to_string(&input).map_err(|error| {
        OrgError::new(
            OrgErrorCode::Serialization,
            format!("dependency digest input: {error}"),
        )
    })?;
    Ok(org_sha256_hex(encoded.as_bytes()))
}

/// 行政根的显式激活证明（根 genesis 绝不自动创建）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgRootActivation {
    pub operator_user_id: i64,
    pub approval_operation_id: String,
}

impl OrgRootActivation {
    pub fn validate(&self) -> OrgResult<()> {
        org_validate_positive_i64(self.operator_user_id, "root_activation.operator_user_id")?;
        org_validate_operation_id(
            &self.approval_operation_id,
            "root_activation.approval_operation_id",
        )
    }
}

/// 行政节点：`parent_tenant_id: None` ⟺ 行政根（必须有显式 `root_activation`）。
/// 目录/资金关系不入本类型；relationship 变更走 relationship_revision 前进。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgNode {
    pub tenant_id: i64,
    pub root_tenant_id: i64,
    #[serde(default = "org_sentinel_parent_tenant")]
    pub parent_tenant_id: Option<i64>,
    pub generation: u64,
    pub revoke_fence: u64,
    pub relationship_revision: u64,
    pub active: bool,
    pub operation_id: String,
    #[serde(default)]
    pub root_activation: Option<OrgRootActivation>,
}

fn org_sentinel_parent_tenant() -> Option<i64> {
    Some(-1)
}

impl OrgNode {
    pub fn is_root(&self) -> bool {
        self.parent_tenant_id.is_none()
    }

    pub fn validate(&self) -> OrgResult<()> {
        org_validate_positive_i64(self.tenant_id, "node.tenant_id")?;
        org_validate_positive_i64(self.root_tenant_id, "node.root_tenant_id")?;
        org_validate_u64_nonzero(self.generation, "node.generation")?;
        if self.revoke_fence > self.generation {
            return Err(OrgError::new(
                OrgErrorCode::InvalidField,
                format!(
                    "node revoke_fence {} cannot exceed generation {}",
                    self.revoke_fence, self.generation
                ),
            ));
        }
        org_validate_u64_nonzero(self.relationship_revision, "node.relationship_revision")?;
        org_validate_operation_id(&self.operation_id, "node.operation_id")?;
        match self.parent_tenant_id {
            None => {
                if self.root_tenant_id != self.tenant_id {
                    return Err(OrgError::new(
                        OrgErrorCode::RootMismatch,
                        "administrative root must be its own root tenant",
                    ));
                }
                let activation = self.root_activation.as_ref().ok_or_else(|| {
                    OrgError::new(
                        OrgErrorCode::InvalidField,
                        "administrative root requires an explicit root_activation proof",
                    )
                })?;
                activation.validate()?;
            }
            Some(parent_tenant_id) => {
                org_validate_positive_i64(parent_tenant_id, "node.parent_tenant_id")?;
                if parent_tenant_id == self.tenant_id {
                    return Err(OrgError::new(
                        OrgErrorCode::SelfReference,
                        "node cannot be its own administrative parent",
                    ));
                }
                if self.root_tenant_id == self.tenant_id {
                    return Err(OrgError::new(
                        OrgErrorCode::RootMismatch,
                        "non-root node cannot claim itself as authority root",
                    ));
                }
                if self.root_activation.is_some() {
                    return Err(OrgError::new(
                        OrgErrorCode::InvalidField,
                        "root_activation is reserved for administrative roots",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// 贡献 provenance：origin = 链最根端的来源租户；链自根端向直接父排列（精确 revision）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgProvenance {
    pub origin_tenant_id: i64,
    pub parent_chain: Vec<OrgGrantRef>,
    pub operation_id: String,
}

impl OrgProvenance {
    pub fn validate(&self) -> OrgResult<()> {
        org_validate_positive_i64(self.origin_tenant_id, "provenance.origin_tenant_id")?;
        if self.parent_chain.len() > MAX_ORG_PROVENANCE_CHAIN {
            return Err(OrgError::new(
                OrgErrorCode::BoundsExceeded,
                format!("provenance chain exceeds {MAX_ORG_PROVENANCE_CHAIN} entries"),
            ));
        }
        org_validate_operation_id(&self.operation_id, "provenance.operation_id")?;
        for (index, reference) in self.parent_chain.iter().enumerate() {
            reference.validate().map_err(|error| {
                OrgError::new(
                    error.code,
                    format!("provenance.parent_chain[{index}]: {}", error.message),
                )
            })?;
        }
        for left in 0..self.parent_chain.len() {
            for right in (left + 1)..self.parent_chain.len() {
                if self.parent_chain[left] == self.parent_chain[right] {
                    return Err(OrgError::new(
                        OrgErrorCode::DuplicateProvenance,
                        format!(
                            "provenance chain repeats grant {}",
                            self.parent_chain[left].grant_id
                        ),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// 单元账本中一条生效贡献（publication 的段成员）：保留多合法来源，不压缩成单一 ALLOW。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgContribution {
    /// 本单元自己的 grant（tenant == publication.tenant_id）。
    pub grant_ref: OrgGrantRef,
    pub scope: OrgScope,
    pub delegable: bool,
    pub subject: Option<OrgSubject>,
    pub provenance: OrgProvenance,
}

impl OrgContribution {
    pub fn validate(&self) -> OrgResult<()> {
        self.grant_ref.validate()?;
        self.scope.validate()?;
        if let Some(subject) = &self.subject {
            subject.validate()?;
        }
        self.provenance.validate()
    }
}

/// 段的 typed 内容（`OrgSegment.content` 的 Value 形态经此类型双向转换并强校验）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgSegmentContent {
    pub key: OrgScopeKey,
    pub contributions: Vec<OrgContribution>,
}

impl OrgSegmentContent {
    pub fn validate(&self) -> OrgResult<()> {
        self.key.validate()?;
        if self.contributions.is_empty() {
            return Err(OrgError::new(
                OrgErrorCode::InvalidField,
                "segment must contain at least one contribution",
            ));
        }
        if self.contributions.len() > MAX_ORG_CONTRIBUTIONS_PER_SEGMENT {
            return Err(OrgError::new(
                OrgErrorCode::BoundsExceeded,
                format!("segment exceeds {MAX_ORG_CONTRIBUTIONS_PER_SEGMENT} contributions"),
            ));
        }
        for contribution in &self.contributions {
            contribution.validate()?;
            if contribution.scope.resource != self.key.resource
                || contribution.scope.action != self.key.action
            {
                return Err(OrgError::new(
                    OrgErrorCode::SegmentOrderInvalid,
                    "segment key must exactly bind every contribution resource and action",
                ));
            }
        }
        for pair in self.contributions.windows(2) {
            let order = pair[0]
                .grant_ref
                .grant_id
                .cmp(&pair[1].grant_ref.grant_id)
                .then(pair[0].grant_ref.revision.cmp(&pair[1].grant_ref.revision));
            if order == std::cmp::Ordering::Equal {
                return Err(OrgError::new(
                    OrgErrorCode::SegmentOrderInvalid,
                    format!(
                        "segment {} has duplicate grant {}",
                        self.key.resource, pair[0].grant_ref.grant_id
                    ),
                ));
            }
            if order == std::cmp::Ordering::Greater {
                return Err(OrgError::new(
                    OrgErrorCode::SegmentOrderInvalid,
                    format!(
                        "segment {} contributions are not in deterministic (grant_id, revision) order",
                        self.key.resource
                    ),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct OrgSegmentDigestInput<'a> {
    domain: &'static str,
    key: &'a OrgScopeKey,
    contributions: &'a [OrgContribution],
}

const ORG_SEGMENT_DIGEST_DOMAIN: &str = "astral-org-segment-v1";

/// 段内容摘要：typed 规范 JSON 的 sha256（对 Value 形态不直接摘要——必须经 typed 解码）。
pub fn org_segment_digest_hex(content: &OrgSegmentContent) -> OrgResult<String> {
    content.validate()?;
    let input = OrgSegmentDigestInput {
        domain: ORG_SEGMENT_DIGEST_DOMAIN,
        key: &content.key,
        contributions: &content.contributions,
    };
    let encoded = serde_json::to_string(&input).map_err(|error| {
        OrgError::new(
            OrgErrorCode::Serialization,
            format!("segment digest input: {error}"),
        )
    })?;
    Ok(org_sha256_hex(encoded.as_bytes()))
}

/// 段身份 = 规范键文本的 sha256（内容无关、代次无关，跨代可对牌）。
pub fn org_segment_identity_hex(key: &OrgScopeKey) -> String {
    org_sha256_hex(
        format!(
            "{ORG_SEGMENT_DIGEST_DOMAIN}/segment-identity/{}:{}",
            key.resource, key.action
        )
        .as_bytes(),
    )
}

/// DB 冻结的段 wire 形态：`index` 为 publication 内序号，`content` 为 typed 内容 JSON。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgSegment {
    pub index: u32,
    pub digest_hex: String,
    pub content: serde_json::Value,
}

/// typed 内容 → wire 段（编译器唯一构造入口）。
pub fn org_build_segment(index: u32, content: OrgSegmentContent) -> OrgResult<OrgSegment> {
    let digest_hex = org_segment_digest_hex(&content)?;
    let content_value = serde_json::to_value(&content).map_err(|error| {
        OrgError::new(
            OrgErrorCode::Serialization,
            format!("segment content: {error}"),
        )
    })?;
    Ok(OrgSegment {
        index,
        digest_hex,
        content: content_value,
    })
}

/// wire 段 → typed 内容（sha256 + 合同强校验；DB reader 验证入口）。
pub fn org_decode_segment_content(segment: &OrgSegment) -> OrgResult<OrgSegmentContent> {
    let content: OrgSegmentContent =
        serde_json::from_value(segment.content.clone()).map_err(|error| {
            OrgError::new(
                OrgErrorCode::Deserialization,
                format!("segment content: {error}"),
            )
        })?;
    content.validate()?;
    let expected = org_segment_digest_hex(&content)?;
    if expected != segment.digest_hex {
        return Err(OrgError::new(
            OrgErrorCode::DigestMismatch,
            format!("segment {} digest does not bind its content", segment.index),
        ));
    }
    Ok(content)
}

#[derive(Serialize)]
struct OrgManifestSegmentRef<'a> {
    index: u32,
    digest_hex: &'a str,
}

#[derive(Serialize)]
struct OrgManifestDigestInput<'a> {
    domain: &'static str,
    tenant_id: i64,
    root_tenant_id: i64,
    generation: u64,
    relationship_revision: u64,
    revoke_fence: u64,
    dependencies: &'a [OrgDependency],
    segments: Vec<OrgManifestSegmentRef<'a>>,
    compiler_version: &'a str,
    operation_id: &'a str,
}

const ORG_MANIFEST_DIGEST_DOMAIN: &str = "astral-org-publication-v1";

/// manifest 摘要材料（依赖/段引用必须已经按合同排序）。
pub struct OrgManifestDigestMaterial<'a> {
    pub tenant_id: i64,
    pub root_tenant_id: i64,
    pub generation: u64,
    pub relationship_revision: u64,
    pub revoke_fence: u64,
    pub dependencies: &'a [OrgDependency],
    pub segments: &'a [OrgSegment],
    pub compiler_version: &'a str,
    pub operation_id: &'a str,
}

/// manifest 摘要：绑定 tenant/root/generation/围栏/排序依赖/段序 + 段 digest。
pub fn org_manifest_digest_hex(material: &OrgManifestDigestMaterial<'_>) -> OrgResult<String> {
    if material.segments.len() > MAX_ORG_SEGMENTS_PER_PUBLICATION {
        return Err(OrgError::new(
            OrgErrorCode::BoundsExceeded,
            format!("publication exceeds {MAX_ORG_SEGMENTS_PER_PUBLICATION} segments"),
        ));
    }
    let segment_refs = material
        .segments
        .iter()
        .map(|segment| OrgManifestSegmentRef {
            index: segment.index,
            digest_hex: segment.digest_hex.as_str(),
        })
        .collect();
    let input = OrgManifestDigestInput {
        domain: ORG_MANIFEST_DIGEST_DOMAIN,
        tenant_id: material.tenant_id,
        root_tenant_id: material.root_tenant_id,
        generation: material.generation,
        relationship_revision: material.relationship_revision,
        revoke_fence: material.revoke_fence,
        dependencies: material.dependencies,
        segments: segment_refs,
        compiler_version: material.compiler_version,
        operation_id: material.operation_id,
    };
    let encoded = serde_json::to_string(&input).map_err(|error| {
        OrgError::new(
            OrgErrorCode::Serialization,
            format!("manifest digest input: {error}"),
        )
    })?;
    Ok(org_sha256_hex(encoded.as_bytes()))
}

/// 单元 publication（序列化合同；DB 存 immutable publication/segment/current pointer）。
///
/// - `generation`/`revoke_fence`/`relationship_revision` 即本单元 node 头栅栏；
/// - `dependencies` = **全部祖先**的扁平有界版本向量（直接父 + 所有更远祖先，
///   按 tenant 排序；根单元为空）——reader 对每个 bound head ID fresh-check，
///   任意祖先的源 generation/fence 前进都会使本 publication 的对应钉栅失配 → PENDING；
/// - 父贡献引用（provenance 链）仍钉精确批准 revision。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgPublication {
    pub tenant_id: i64,
    pub root_tenant_id: i64,
    pub generation: u64,
    pub relationship_revision: u64,
    pub revoke_fence: u64,
    pub dependencies: Vec<OrgDependency>,
    pub manifest_digest_hex: String,
    pub compiler_version: String,
    pub segments: Vec<OrgSegment>,
    pub operation_id: String,
}

impl OrgPublication {
    pub fn validate(&self) -> OrgResult<()> {
        org_validate_positive_i64(self.tenant_id, "publication.tenant_id")?;
        org_validate_positive_i64(self.root_tenant_id, "publication.root_tenant_id")?;
        org_validate_u64_nonzero(self.generation, "publication.generation")?;
        if self.revoke_fence > self.generation {
            return Err(OrgError::new(
                OrgErrorCode::InvalidField,
                format!(
                    "publication revoke_fence {} cannot exceed generation {}",
                    self.revoke_fence, self.generation
                ),
            ));
        }
        org_validate_u64_nonzero(
            self.relationship_revision,
            "publication.relationship_revision",
        )?;
        org_validate_identifier(
            &self.compiler_version,
            "publication.compiler_version",
            MAX_ORG_ID_TEXT_LEN,
        )?;
        org_validate_operation_id(&self.operation_id, "publication.operation_id")?;
        if self.dependencies.len() > MAX_ORG_DEPENDENCIES {
            return Err(OrgError::new(
                OrgErrorCode::BoundsExceeded,
                format!("publication dependencies exceed {MAX_ORG_DEPENDENCIES}"),
            ));
        }
        for pair in self.dependencies.windows(2) {
            if pair[0].tenant_id >= pair[1].tenant_id {
                return Err(OrgError::new(
                    OrgErrorCode::SegmentOrderInvalid,
                    "publication dependencies must be strictly sorted by tenant_id",
                ));
            }
        }
        for dependency in &self.dependencies {
            dependency.validate()?;
            if dependency.tenant_id == self.tenant_id {
                return Err(OrgError::new(
                    OrgErrorCode::SelfReference,
                    "publication cannot depend on its own tenant",
                ));
            }
        }
        if self.segments.len() > MAX_ORG_SEGMENTS_PER_PUBLICATION {
            return Err(OrgError::new(
                OrgErrorCode::BoundsExceeded,
                format!("publication exceeds {MAX_ORG_SEGMENTS_PER_PUBLICATION} segments"),
            ));
        }
        for (expected_index, segment) in self.segments.iter().enumerate() {
            if segment.index != expected_index as u32 {
                return Err(OrgError::new(
                    OrgErrorCode::SegmentIndexInvalid,
                    format!(
                        "segment index {} is invalid; expected {expected_index}",
                        segment.index
                    ),
                ));
            }
        }
        let mut previous_key: Option<OrgScopeKey> = None;
        for segment in &self.segments {
            let content = org_decode_segment_content(segment)?;
            if let Some(previous) = &previous_key {
                if previous >= &content.key {
                    return Err(OrgError::new(
                        OrgErrorCode::SegmentOrderInvalid,
                        "publication segments must be strictly sorted by unique (resource, action) key",
                    ));
                }
            }
            for contribution in &content.contributions {
                if contribution.grant_ref.tenant_id != self.tenant_id {
                    return Err(OrgError::new(
                        OrgErrorCode::TenantMismatch,
                        "publication contributions must belong to the publishing tenant",
                    ));
                }
            }
            previous_key = Some(content.key);
        }
        let expected_digest = org_manifest_digest_hex(&OrgManifestDigestMaterial {
            tenant_id: self.tenant_id,
            root_tenant_id: self.root_tenant_id,
            generation: self.generation,
            relationship_revision: self.relationship_revision,
            revoke_fence: self.revoke_fence,
            dependencies: &self.dependencies,
            segments: &self.segments,
            compiler_version: &self.compiler_version,
            operation_id: &self.operation_id,
        })?;
        if expected_digest != self.manifest_digest_hex {
            return Err(OrgError::new(
                OrgErrorCode::DigestMismatch,
                "publication manifest digest does not bind its segments",
            ));
        }
        Ok(())
    }

    /// 获胜贡献是否仍在本 publication 的生效集合中（整体恒等：ref+scope+subject+provenance）。
    pub fn contains_contribution(&self, winner: &OrgContribution) -> bool {
        self.segments
            .iter()
            .filter_map(|segment| org_decode_segment_content(segment).ok())
            .any(|content| content.contributions.iter().any(|c| c == winner))
    }

    /// 获胜 grant ref 是否仍在本 publication 的生效集合中（按 ref 定位）。
    pub fn contains_grant(&self, grant_ref: &OrgGrantRef) -> bool {
        self.segments
            .iter()
            .filter_map(|segment| org_decode_segment_content(segment).ok())
            .any(|content| {
                content
                    .contributions
                    .iter()
                    .any(|contribution| &contribution.grant_ref == grant_ref)
            })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pending / 准入证据 / 分支 provenance
// ─────────────────────────────────────────────────────────────────────────────

/// PENDING 稳定机码：DB reader 侧（冻结 12 项）+ 编译器侧（后 4 项）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OrgPendingCode {
    PublicationMissing,
    CurrentPointerMissing,
    NodeMissing,
    NodeInactive,
    SourceGenerationAdvanced,
    RootMismatch,
    DependencyStale,
    MembershipMissing,
    MembershipInactive,
    MembershipExpired,
    MembershipCardMismatch,
    SchemaUnmanaged,
    // 编译器侧补充（types owner 冻结，DB/API 消费方按机码透传）：
    ParentMissing,
    ParentRevisionAdvanced,
    ScopeNotCovered,
    MaskTargetRevisionAdvanced,
}

impl OrgPendingCode {
    pub const fn as_machine_code(self) -> &'static str {
        match self {
            OrgPendingCode::PublicationMissing => "org_scope.pending.publication_missing",
            OrgPendingCode::CurrentPointerMissing => "org_scope.pending.current_pointer_missing",
            OrgPendingCode::NodeMissing => "org_scope.pending.node_missing",
            OrgPendingCode::NodeInactive => "org_scope.pending.node_inactive",
            OrgPendingCode::SourceGenerationAdvanced => {
                "org_scope.pending.source_generation_advanced"
            }
            OrgPendingCode::RootMismatch => "org_scope.pending.root_mismatch",
            OrgPendingCode::DependencyStale => "org_scope.pending.dependency_stale",
            OrgPendingCode::MembershipMissing => "org_scope.pending.membership_missing",
            OrgPendingCode::MembershipInactive => "org_scope.pending.membership_inactive",
            OrgPendingCode::MembershipExpired => "org_scope.pending.membership_expired",
            OrgPendingCode::MembershipCardMismatch => "org_scope.pending.membership_card_mismatch",
            OrgPendingCode::SchemaUnmanaged => "org_scope.pending.schema_unmanaged",
            OrgPendingCode::ParentMissing => "org_scope.pending.parent_missing",
            OrgPendingCode::ParentRevisionAdvanced => "org_scope.pending.parent_revision_advanced",
            OrgPendingCode::ScopeNotCovered => "org_scope.pending.scope_not_covered",
            OrgPendingCode::MaskTargetRevisionAdvanced => {
                "org_scope.pending.mask_target_revision_advanced"
            }
        }
    }
}

/// 编译器产生的显式 PENDING 项（未对账 mask / 缺失或漂移的父授权 / 不可证明范围）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgPendingItem {
    pub code: OrgPendingCode,
    pub detail: String,
    #[serde(default)]
    pub grant_id: Option<String>,
    #[serde(default)]
    pub mask_id: Option<String>,
}

/// 编译 PENDING 报告（可落库；出现任何 item 时该编译结果不得进入准入）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgPendingReport {
    pub tenant_id: i64,
    /// 本次编译目标代次（= 节点 generation）。
    pub generation: u64,
    pub items: Vec<OrgPendingItem>,
}

/// 分支身份：单元共享卡分支 / 个人卡分支。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OrgBranchKind {
    Shared,
    Personal,
}

impl OrgBranchKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            OrgBranchKind::Shared => "SHARED",
            OrgBranchKind::Personal => "PERSONAL",
        }
    }
}

/// 获胜分支的 typed provenance（主 Agent 将其挂到 PolicyDecision.org_provenance）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgBranchProvenance {
    pub receiving_tenant_id: i64,
    pub source_tenant_id: i64,
    pub resource_tenant_id: i64,
    pub root_tenant_id: i64,
    pub membership_id: String,
    pub membership_revision: u64,
    pub branch_kind: OrgBranchKind,
    pub grant_ref: OrgGrantRef,
    pub publication_generation: u64,
    pub manifest_digest_hex: String,
    pub approval_operation_id: String,
}

impl OrgBranchProvenance {
    pub fn validate(&self) -> OrgResult<()> {
        org_validate_positive_i64(self.receiving_tenant_id, "provenance.receiving_tenant_id")?;
        org_validate_positive_i64(self.source_tenant_id, "provenance.source_tenant_id")?;
        org_validate_positive_i64(self.resource_tenant_id, "provenance.resource_tenant_id")?;
        org_validate_positive_i64(self.root_tenant_id, "provenance.root_tenant_id")?;
        org_validate_stable_uuid(&self.membership_id, "provenance.membership_id")?;
        org_validate_u64_nonzero(self.membership_revision, "provenance.membership_revision")?;
        self.grant_ref.validate()?;
        org_validate_u64_nonzero(
            self.publication_generation,
            "provenance.publication_generation",
        )?;
        org_validate_identifier(
            &self.manifest_digest_hex,
            "provenance.manifest_digest_hex",
            64,
        )?;
        org_validate_operation_id(
            &self.approval_operation_id,
            "provenance.approval_operation_id",
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 治理请求载荷（API owner 的 source mutation 输入；DB owner 落 request/audit/outbox）
// ─────────────────────────────────────────────────────────────────────────────

/// 根初始授权/根追加授权的种子（无 parent、无 subject —— 根自源共享贡献）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgGrantSeed {
    pub scope: OrgScope,
    pub delegable: bool,
}

impl OrgGrantSeed {
    pub fn validate(&self) -> OrgResult<()> {
        self.scope.validate()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OrgRequestKind {
    RootInit,
    RootGrant,
    Attach,
    Move,
    Detach,
    Grant,
}

impl OrgRequestKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            OrgRequestKind::RootInit => "ROOT_INIT",
            OrgRequestKind::RootGrant => "ROOT_GRANT",
            OrgRequestKind::Attach => "ATTACH",
            OrgRequestKind::Move => "MOVE",
            OrgRequestKind::Detach => "DETACH",
            OrgRequestKind::Grant => "GRANT",
        }
    }
}

/// 六类治理 source mutation 请求载荷（adjacently tagged：kind + payload）。
///
/// 注：tagged enum 不施加容器级 `deny_unknown_fields`（serde 对 tagged enum 的
/// 已知限制）；未知 `kind` 值天然反序列化失败，变体必填字段缺失同样失败，
/// 语义完整性由强制 `validate()` 兜底。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OrgRequestPayload {
    RootInit {
        root_tenant_id: i64,
        initial_grants: Vec<OrgGrantSeed>,
    },
    RootGrant {
        root_tenant_id: i64,
        scope: OrgScope,
        delegable: bool,
    },
    Attach {
        child_tenant_id: i64,
        parent_tenant_id: i64,
    },
    Move {
        child_tenant_id: i64,
        new_parent_tenant_id: i64,
    },
    Detach {
        child_tenant_id: i64,
    },
    Grant {
        receiving_tenant_id: i64,
        parent_grant: OrgGrantRef,
        scope: OrgScope,
        delegable: bool,
        #[serde(default = "org_sentinel_subject")]
        subject: Option<OrgSubject>,
    },
}

impl OrgRequestPayload {
    pub const fn kind(&self) -> OrgRequestKind {
        match self {
            OrgRequestPayload::RootInit { .. } => OrgRequestKind::RootInit,
            OrgRequestPayload::RootGrant { .. } => OrgRequestKind::RootGrant,
            OrgRequestPayload::Attach { .. } => OrgRequestKind::Attach,
            OrgRequestPayload::Move { .. } => OrgRequestKind::Move,
            OrgRequestPayload::Detach { .. } => OrgRequestKind::Detach,
            OrgRequestPayload::Grant { .. } => OrgRequestKind::Grant,
        }
    }

    pub fn validate(&self) -> OrgResult<()> {
        match self {
            OrgRequestPayload::RootInit {
                root_tenant_id,
                initial_grants,
            } => {
                org_validate_positive_i64(*root_tenant_id, "root_init.root_tenant_id")?;
                if initial_grants.len() > MAX_ORG_ROOT_INIT_GRANTS {
                    return Err(OrgError::new(
                        OrgErrorCode::BoundsExceeded,
                        format!("root_init exceeds {MAX_ORG_ROOT_INIT_GRANTS} initial grants"),
                    ));
                }
                for seed in initial_grants {
                    seed.validate()?;
                }
            }
            OrgRequestPayload::RootGrant {
                root_tenant_id,
                scope,
                ..
            } => {
                org_validate_positive_i64(*root_tenant_id, "root_grant.root_tenant_id")?;
                scope.validate()?;
            }
            OrgRequestPayload::Attach {
                child_tenant_id,
                parent_tenant_id,
            } => {
                org_validate_positive_i64(*child_tenant_id, "attach.child_tenant_id")?;
                org_validate_positive_i64(*parent_tenant_id, "attach.parent_tenant_id")?;
                if child_tenant_id == parent_tenant_id {
                    return Err(OrgError::new(
                        OrgErrorCode::SelfReference,
                        "tenant cannot attach to itself",
                    ));
                }
            }
            OrgRequestPayload::Move {
                child_tenant_id,
                new_parent_tenant_id,
            } => {
                org_validate_positive_i64(*child_tenant_id, "move.child_tenant_id")?;
                org_validate_positive_i64(*new_parent_tenant_id, "move.new_parent_tenant_id")?;
                if child_tenant_id == new_parent_tenant_id {
                    return Err(OrgError::new(
                        OrgErrorCode::SelfReference,
                        "tenant cannot move under itself",
                    ));
                }
            }
            OrgRequestPayload::Detach { child_tenant_id } => {
                org_validate_positive_i64(*child_tenant_id, "detach.child_tenant_id")?;
            }
            OrgRequestPayload::Grant {
                receiving_tenant_id,
                parent_grant,
                scope,
                subject,
                ..
            } => {
                org_validate_positive_i64(*receiving_tenant_id, "grant.receiving_tenant_id")?;
                parent_grant.validate()?;
                scope.validate()?;
                if let Some(subject) = subject {
                    subject.validate()?;
                }
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// worker 派发载荷（传播 intents；非审批请求载荷）
// ─────────────────────────────────────────────────────────────────────────────

/// `SUBTREE_PROPAGATE` outbox 事件的 typed 派发载荷（worker 读取后按批推进
/// 后代 root）。
///
/// - 这是 **DB-internal worker 派发合同**，不是审批请求载荷
///   （[`OrgRequestPayload`] 不受影响；审批请求仍按各自合同校验）。
/// - wire 兼容：字段与历史 ad hoc JSON producer 完全同名
///   （`child_tenant_id` / `new_root_tenant_id` / `relationship_revision`），
///   既有已入队行保持可解析；`deny_unknown_fields` 只收紧读取侧。
/// - `relationship_revision` = 锚点（child_tenant_id）在该拓扑 source 变更
///   **提交后**的 relationship_revision；worker 在同一事务内用它做意图栅栏
///   （锚点当前 revision 与载荷不一致 ⇒ 意图已被更新的拓扑变更取代或损坏）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct OrgSubtreePropagatePayload {
    pub child_tenant_id: i64,
    pub new_root_tenant_id: i64,
    pub relationship_revision: u64,
}

impl OrgSubtreePropagatePayload {
    /// 结构校验：id 必须为正、revision 必须非零（fail-closed，无 I/O）。
    pub fn validate(&self) -> OrgResult<()> {
        org_validate_positive_i64(self.child_tenant_id, "subtree_propagate.child_tenant_id")?;
        org_validate_positive_i64(
            self.new_root_tenant_id,
            "subtree_propagate.new_root_tenant_id",
        )?;
        if self.relationship_revision == 0 {
            return Err(OrgError::new(
                OrgErrorCode::InvalidField,
                "subtree_propagate.relationship_revision must be nonzero",
            ));
        }
        Ok(())
    }
}

/// `DEPENDENCY_PROPAGATE` outbox payload, fenced to the post-mutation anchor head.
/// The stable operation identity is bound by the outbox row, not duplicated here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct OrgDependencyPropagatePayload {
    pub anchor_tenant_id: i64,
    pub root_tenant_id: i64,
    pub generation: u64,
    pub revoke_fence: u64,
    pub relationship_revision: u64,
}

impl OrgDependencyPropagatePayload {
    pub fn validate(&self) -> OrgResult<()> {
        org_validate_positive_i64(
            self.anchor_tenant_id,
            "dependency_propagate.anchor_tenant_id",
        )?;
        org_validate_positive_i64(self.root_tenant_id, "dependency_propagate.root_tenant_id")?;
        org_validate_u64_nonzero(self.generation, "dependency_propagate.generation")?;
        if self.revoke_fence > self.generation {
            return Err(OrgError::new(
                OrgErrorCode::InvalidRequest,
                format!(
                    "dependency revoke_fence {} cannot exceed generation {}",
                    self.revoke_fence, self.generation
                ),
            ));
        }
        org_validate_u64_nonzero(
            self.relationship_revision,
            "dependency_propagate.relationship_revision",
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 编译输入 / 准入证据
// ─────────────────────────────────────────────────────────────────────────────

/// 编译输入：仅 DB 已证明的批准事实快照（最新 revision per grant/mask；无 I/O）。
///
/// - `dependencies` = **全部祖先**的扁平有界依赖向量（直接父 + 所有更远祖先，
///   按 tenant 排序；根单元为空）；`parent_publications` 恰好 1 项（直接父）。
///   编译器验证：直接父 head 对牌 + 父 publication 的传递依赖逐项包含于本向量。
/// - `operation_id` = 驱动本次编译发布的 durable 操作（写入 publication）。
/// - 编译代次 = `node.generation`（node 每次相关 mutation 前进；publication 与
///   node 头栅栏逐项相等）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgCompileInput {
    pub node: OrgNode,
    pub dependencies: Vec<OrgDependency>,
    pub parent_publications: Vec<OrgPublication>,
    pub grants: Vec<OrgGrant>,
    pub masks: Vec<OrgMask>,
    pub operation_id: String,
}

impl OrgCompileInput {
    /// 结构性校验（fail-closed → [`OrgError`]）；父授权解析/PENDING 分类在编译器完成。
    pub fn validate(&self) -> OrgResult<()> {
        self.node.validate()?;
        org_validate_operation_id(&self.operation_id, "compile_input.operation_id")?;
        if self.grants.len() > MAX_ORG_GRANTS_PER_INPUT {
            return Err(OrgError::new(
                OrgErrorCode::BoundsExceeded,
                format!("compile input exceeds {MAX_ORG_GRANTS_PER_INPUT} grants"),
            ));
        }
        if self.masks.len() > MAX_ORG_MASKS_PER_INPUT {
            return Err(OrgError::new(
                OrgErrorCode::BoundsExceeded,
                format!("compile input exceeds {MAX_ORG_MASKS_PER_INPUT} masks"),
            ));
        }
        if self.dependencies.len() > MAX_ORG_DEPENDENCIES
            || self.parent_publications.len() > MAX_ORG_PARENT_PUBLICATIONS
        {
            return Err(OrgError::new(
                OrgErrorCode::BoundsExceeded,
                "compile input exceeds dependency bounds",
            ));
        }
        let is_root = self.node.is_root();
        let parent_tenant_id = self.node.parent_tenant_id;
        match (is_root, self.parent_publications.len()) {
            (true, 0) => {}
            (false, 1) => {}
            _ => {
                return Err(OrgError::new(
                    OrgErrorCode::DependencyCountMismatch,
                    "root units carry zero parent publications; child units carry exactly one",
                ));
            }
        }
        if is_root {
            if !self.dependencies.is_empty() {
                return Err(OrgError::new(
                    OrgErrorCode::DependencyCountMismatch,
                    "administrative roots have no ancestor dependency vector",
                ));
            }
            if !self.masks.is_empty() {
                return Err(OrgError::new(
                    OrgErrorCode::MasksForbiddenForRoot,
                    "administrative roots have no ancestor contributions to mask",
                ));
            }
        } else {
            let parent_tenant_id = parent_tenant_id.ok_or_else(|| {
                OrgError::new(
                    OrgErrorCode::ParentRequiredForChild,
                    "child compile input requires an immediate administrative parent",
                )
            })?;
            if self.dependencies.is_empty() {
                return Err(OrgError::new(
                    OrgErrorCode::DependencyCountMismatch,
                    "child units must pin the full flattened ancestor dependency vector",
                ));
            }
            for pair in self.dependencies.windows(2) {
                if pair[0].tenant_id >= pair[1].tenant_id {
                    return Err(OrgError::new(
                        OrgErrorCode::DependencyMismatch,
                        "dependency vector must be strictly sorted by unique tenant_id",
                    ));
                }
            }
            for dependency in &self.dependencies {
                dependency.validate()?;
                if dependency.tenant_id == self.node.tenant_id {
                    return Err(OrgError::new(
                        OrgErrorCode::SelfReference,
                        "unit cannot pin itself as an ancestor dependency",
                    ));
                }
            }
            let parent_publication = &self.parent_publications[0];
            parent_publication.validate()?;
            if parent_publication.tenant_id != parent_tenant_id {
                return Err(OrgError::new(
                    OrgErrorCode::TenantMismatch,
                    "parent publication tenant must equal the immediate administrative parent",
                ));
            }
            if parent_publication.root_tenant_id != self.node.root_tenant_id {
                return Err(OrgError::new(
                    OrgErrorCode::RootMismatch,
                    "parent publication root must equal the node authority root",
                ));
            }
            // 直接父 head 必须在依赖向量内且与父 publication 逐项对牌。
            let direct = self
                .dependencies
                .iter()
                .find(|dependency| dependency.tenant_id == parent_tenant_id)
                .ok_or_else(|| {
                    OrgError::new(
                        OrgErrorCode::DependencyMismatch,
                        "dependency vector must pin the direct administrative parent",
                    )
                })?;
            if !org_dependency_matches_publication(direct, parent_publication) {
                return Err(OrgError::new(
                    OrgErrorCode::DependencyMismatch,
                    "direct parent dependency fences do not match the parent publication",
                ));
            }
            // 传递完备性：父 publication 钉的全部祖先必须逐项包含于本单元依赖向量，
            // 使任意层级祖先撤销/移动在 reader fresh-check 时立即可感知（不等父重发布）。
            if self.dependencies.len() != parent_publication.dependencies.len() + 1 {
                return Err(OrgError::new(
                    OrgErrorCode::DependencyCountMismatch,
                    "dependency vector must be the flattened transitive set: direct parent + all ancestor heads",
                ));
            }
            for ancestor_dependency in &parent_publication.dependencies {
                let pinned = self
                    .dependencies
                    .iter()
                    .find(|dependency| dependency.tenant_id == ancestor_dependency.tenant_id)
                    .ok_or_else(|| {
                        OrgError::new(
                            OrgErrorCode::DependencyMismatch,
                            format!(
                                "transitive ancestor {} is missing from the dependency vector",
                                ancestor_dependency.tenant_id
                            ),
                        )
                    })?;
                if pinned != ancestor_dependency {
                    return Err(OrgError::new(
                        OrgErrorCode::DependencyMismatch,
                        format!(
                            "transitive ancestor {} fences drift from the parent publication pins",
                            ancestor_dependency.tenant_id
                        ),
                    ));
                }
            }
        }
        let mut seen_grants: Vec<&str> = Vec::with_capacity(self.grants.len());
        for grant in &self.grants {
            grant.validate()?;
            if grant.receiving_tenant_id != self.node.tenant_id {
                return Err(OrgError::new(
                    OrgErrorCode::TenantMismatch,
                    "compile input grants must belong to the node tenant",
                ));
            }
            if grant.root_tenant_id != self.node.root_tenant_id {
                return Err(OrgError::new(
                    OrgErrorCode::RootMismatch,
                    "compile input grants must carry the node authority root",
                ));
            }
            match (&grant.parent, is_root) {
                (None, true) => {
                    if grant.origin_tenant_id != grant.receiving_tenant_id {
                        return Err(OrgError::new(
                            OrgErrorCode::OriginMismatch,
                            "root-unit grants must be self-originated",
                        ));
                    }
                    // 防御纵深：根单元无父 provenance 可证明外部资源属主，V1 资源
                    // 租户恒等。DB 写入侧已禁止该形态（root_source_resource_tenant_
                    // mismatch）；编译输入是信任边界，对畸形 durable 数据独立
                    // fail-closed，不得依赖写入侧防线。
                    if grant.scope.resource_tenant_id != self.node.root_tenant_id {
                        return Err(OrgError::new(
                            OrgErrorCode::TenantMismatch,
                            format!(
                                "root-unit grant {} claims resource tenant {} outside the authority root {}",
                                grant.grant_id, grant.scope.resource_tenant_id, self.node.root_tenant_id
                            ),
                        ));
                    }
                }
                (Some(parent), false) => {
                    if Some(grant.origin_tenant_id) != parent_tenant_id {
                        return Err(OrgError::new(
                            OrgErrorCode::OriginMismatch,
                            "child-unit grants must originate from the immediate administrative parent",
                        ));
                    }
                    if parent.tenant_id != grant.origin_tenant_id {
                        return Err(OrgError::new(
                            OrgErrorCode::OriginMismatch,
                            "grant parent tenant must equal grant origin tenant",
                        ));
                    }
                }
                (None, false) => {
                    return Err(OrgError::new(
                        OrgErrorCode::ParentRequiredForChild,
                        format!(
                            "child-unit grant {} requires a parent contribution reference",
                            grant.grant_id
                        ),
                    ));
                }
                (Some(_), true) => {
                    return Err(OrgError::new(
                        OrgErrorCode::ParentForbiddenForRoot,
                        format!(
                            "root-unit grant {} must not reference a parent",
                            grant.grant_id
                        ),
                    ));
                }
            }
            if seen_grants.contains(&grant.grant_id.as_str()) {
                return Err(OrgError::new(
                    OrgErrorCode::DuplicateGrant,
                    format!("compile input repeats grant {}", grant.grant_id),
                ));
            }
            seen_grants.push(grant.grant_id.as_str());
        }
        let mut seen_masks: Vec<&str> = Vec::with_capacity(self.masks.len());
        for mask in &self.masks {
            mask.validate()?;
            if mask.tenant_id != self.node.tenant_id {
                return Err(OrgError::new(
                    OrgErrorCode::TenantMismatch,
                    "compile input masks must belong to the node tenant",
                ));
            }
            if seen_masks.contains(&mask.mask_id.as_str()) {
                return Err(OrgError::new(
                    OrgErrorCode::DuplicateMask,
                    format!("compile input repeats mask {}", mask.mask_id),
                ));
            }
            seen_masks.push(mask.mask_id.as_str());
        }
        Ok(())
    }
}

/// 一次请求的读取上下文（readonly 匹配索引的查询参数）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgReadRequest {
    pub resource: String,
    pub action: String,
    pub resource_tenant_id: i64,
    #[serde(default)]
    pub domain_id: Option<i64>,
    pub now_unix_seconds: i64,
}

impl OrgReadRequest {
    pub fn validate(&self) -> OrgResult<()> {
        org_parse_resource_form(&self.resource).map(|_| ())?;
        org_validate_action(&self.action)?;
        org_validate_positive_i64(self.resource_tenant_id, "request.resource_tenant_id")?;
        if let Some(domain_id) = self.domain_id {
            org_validate_positive_i64(domain_id, "request.domain_id")?;
        }
        Ok(())
    }
}

/// 准入证据：publication + 已证明 membership + 节点状态 + 统一读取时钟。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OrgAdmissionEvidence {
    pub publication: OrgPublication,
    pub node: OrgNode,
    pub membership: OrgMembership,
    pub checked_at_unix: i64,
}

impl OrgAdmissionEvidence {
    pub fn validate(&self) -> OrgResult<()> {
        self.publication.validate()?;
        self.node.validate()?;
        self.membership.validate()?;
        if self.node.tenant_id != self.publication.tenant_id
            || self.node.root_tenant_id != self.publication.root_tenant_id
        {
            return Err(OrgError::new(
                OrgErrorCode::TenantMismatch,
                "evidence node must belong to the publication unit",
            ));
        }
        if !self.node.active {
            return Err(OrgError::new(
                OrgErrorCode::MembershipInactive,
                "evidence node is inactive",
            ));
        }
        // 节点头栅栏必须与 publication 逐项相等（generation/fence/relationship）。
        if self.node.generation != self.publication.generation
            || self.node.revoke_fence != self.publication.revoke_fence
            || self.node.relationship_revision != self.publication.relationship_revision
        {
            return Err(OrgError::new(
                OrgErrorCode::DependencyMismatch,
                "evidence node head fences do not match the publication",
            ));
        }
        match self.node.parent_tenant_id {
            None if !self.publication.dependencies.is_empty() => {
                return Err(OrgError::new(
                    OrgErrorCode::DependencyMismatch,
                    "administrative-root evidence must not carry ancestor dependencies",
                ));
            }
            Some(parent_tenant_id)
                if !self
                    .publication
                    .dependencies
                    .iter()
                    .any(|dependency| dependency.tenant_id == parent_tenant_id) =>
            {
                return Err(OrgError::new(
                    OrgErrorCode::DependencyMismatch,
                    "child evidence must pin its immediate administrative parent",
                ));
            }
            _ => {}
        }
        if self.membership.tenant_id != self.publication.tenant_id
            || self.membership.root_tenant_id != self.publication.root_tenant_id
        {
            return Err(OrgError::new(
                OrgErrorCode::TenantMismatch,
                "evidence membership must belong to the publication unit",
            ));
        }
        if !self.membership.active {
            return Err(OrgError::new(
                OrgErrorCode::MembershipInactive,
                "evidence membership is inactive",
            ));
        }
        if !self.membership.is_valid_at(self.checked_at_unix) {
            return Err(OrgError::new(
                OrgErrorCode::MembershipExpired,
                "evidence membership is outside its validity window at the read clock",
            ));
        }
        Ok(())
    }
}

/// 准入三态中的二态（NotManaged 等由 repository 端口表达；tagged enum 不施加
/// 容器级 deny_unknown_fields，理由同 `OrgRequestPayload`）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", content = "value", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OrgAdmissionResult {
    /// Heap-indirected only for Rust enum layout; serde preserves the existing
    /// tagged `EVIDENCE` payload shape without an additional JSON wrapper.
    Evidence(Box<OrgAdmissionEvidence>),
    Pending {
        code: OrgPendingCode,
        detail: String,
    },
}

/// read-final-recheck：最终复读证据必须与候选证据在 publication/node/membership 上
/// 恒等，获胜贡献仍在新 publication 生效集合中（整体恒等），且**获胜贡献的有效期
/// 必须在新读取时钟下重新验证**（防止 grant 在两读之间过期仍被旧候选放行）；
/// 任何漂移/过期 → PENDING。
pub fn org_admission_recheck_stable(
    baseline: &OrgAdmissionEvidence,
    next: &OrgAdmissionEvidence,
    winner: &OrgContribution,
) -> bool {
    next.validate().is_ok()
        && next.publication == baseline.publication
        && next.node == baseline.node
        && next.membership == baseline.membership
        && next.checked_at_unix >= baseline.checked_at_unix
        && next.publication.contains_contribution(winner)
        && winner.scope.validity.is_valid_at(next.checked_at_unix)
}

// ─────────────────────────────────────────────────────────────────────────────
// 测试
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_TENANT: i64 = 100;
    const CHILD_TENANT: i64 = 200;

    fn uuid(seed: u8) -> String {
        Uuid::from_u128(0xA57A_0000_0000_0000_0000_0000_0000_0000u128 | seed as u128).to_string()
    }

    fn window(start: i64, end: i64) -> ValidityWindow {
        ValidityWindow::between(start, end)
    }

    fn scope(resource: &str, action: &str) -> OrgScope {
        OrgScope {
            resource_tenant_id: CHILD_TENANT,
            domain_id: None,
            resource: resource.to_owned(),
            action: action.to_owned(),
            validity: window(1_000, 2_000),
        }
    }

    fn root_node() -> OrgNode {
        OrgNode {
            tenant_id: ROOT_TENANT,
            root_tenant_id: ROOT_TENANT,
            parent_tenant_id: None,
            generation: 3,
            revoke_fence: 1,
            relationship_revision: 2,
            active: true,
            operation_id: "op-root".to_owned(),
            root_activation: Some(OrgRootActivation {
                operator_user_id: 7,
                approval_operation_id: "op-approve-root".to_owned(),
            }),
        }
    }

    fn child_node() -> OrgNode {
        OrgNode {
            tenant_id: CHILD_TENANT,
            root_tenant_id: ROOT_TENANT,
            parent_tenant_id: Some(ROOT_TENANT),
            generation: 5,
            revoke_fence: 0,
            relationship_revision: 4,
            active: true,
            operation_id: "op-child".to_owned(),
            root_activation: None,
        }
    }

    fn dependency() -> OrgDependency {
        OrgDependency {
            tenant_id: ROOT_TENANT,
            generation: 9,
            revoke_fence: 2,
            relationship_revision: 3,
        }
    }

    fn root_genesis_grant() -> OrgGrant {
        OrgGrant {
            grant_id: uuid(1),
            revision: 1,
            receiving_tenant_id: ROOT_TENANT,
            origin_tenant_id: ROOT_TENANT,
            root_tenant_id: ROOT_TENANT,
            scope: OrgScope {
                resource_tenant_id: ROOT_TENANT,
                ..scope("doc:42", "read")
            },
            delegable: true,
            parent: None,
            subject: None,
            active: true,
            operation_id: "op-grant-1".to_owned(),
        }
    }

    /// membership fixture：tenant 由调用方给定（准入证据要求 membership 与
    /// publication 单元同租户；root 单元证据必须使用 root 租户 membership）。
    fn membership(tenant_id: i64) -> OrgMembership {
        OrgMembership {
            membership_id: uuid(9),
            tenant_id,
            root_tenant_id: ROOT_TENANT,
            user_id: 11,
            identity_card_id: 111,
            card_id: 222,
            revision: 1,
            active: true,
            validity: window(0, 9_999),
            operation_id: "op-member-1".to_owned(),
        }
    }

    // ── 节点 ──

    #[test]
    fn root_node_requires_explicit_activation() {
        let mut node = root_node();
        node.root_activation = None;
        assert_eq!(
            node.validate().unwrap_err().code,
            OrgErrorCode::InvalidField
        );
    }

    #[test]
    fn child_node_rejects_self_parent_and_self_root() {
        let mut node = child_node();
        node.parent_tenant_id = Some(CHILD_TENANT);
        assert_eq!(
            node.validate().unwrap_err().code,
            OrgErrorCode::SelfReference
        );

        let mut node = child_node();
        node.root_tenant_id = CHILD_TENANT;
        assert_eq!(
            node.validate().unwrap_err().code,
            OrgErrorCode::RootMismatch
        );
    }

    #[test]
    fn node_rejects_fence_above_generation_and_sentinel_parent() {
        let mut node = root_node();
        node.revoke_fence = node.generation + 1;
        assert_eq!(
            node.validate().unwrap_err().code,
            OrgErrorCode::InvalidField
        );

        // serde 缺省 parentId → 哨兵 -1 → validate 拒绝（不得静默当根）。
        let json = r#"{"tenantId":300,"rootTenantId":100,"generation":1,"revokeFence":0,"relationshipRevision":1,"active":true,"operationId":"op"}"#;
        let parsed: OrgNode = serde_json::from_str(json).unwrap();
        assert_eq!(
            parsed.validate().unwrap_err().code,
            OrgErrorCode::InvalidField
        );
    }

    // ── 作用域包含 ──

    #[test]
    fn scope_inclusion_object_type_and_global_resources() {
        let parent = scope("doc:*", "read");
        assert!(parent.covers(&scope("doc:42", "read")).is_ok());
        assert!(parent.covers(&scope("doc:*", "read")).is_ok());
        assert!(parent.covers(&scope("doc", "read")).is_ok());
        assert!(parent.covers(&scope("docx:42", "read")).is_err());

        let object_parent = scope("doc:42", "read");
        assert!(object_parent.covers(&scope("doc:*", "read")).is_err());
        assert!(object_parent.covers(&scope("doc:43", "read")).is_err());
        assert!(parent.covers(&scope("*", "read")).is_err());

        let global_parent = scope("*", "read");
        assert!(global_parent.covers(&scope("doc:42", "read")).is_ok());
    }

    #[test]
    fn scope_inclusion_write_alias_and_wildcards() {
        let write_parent = scope("doc:*", "write");
        assert!(write_parent.covers(&scope("doc:1", "create")).is_ok());
        assert!(write_parent.covers(&scope("doc:1", "update")).is_ok());
        assert!(write_parent.covers(&scope("doc:1", "write")).is_ok());
        assert!(write_parent.covers(&scope("doc:1", "read")).is_err());

        let create_parent = scope("doc:*", "create");
        assert!(create_parent.covers(&scope("doc:1", "write")).is_err());

        let create_child_of_wild = scope("doc:*", "*");
        assert!(write_parent.covers(&create_child_of_wild).is_err());
        assert!(scope("doc:*", "*").covers(&write_parent).is_ok());
    }

    #[test]
    fn scope_inclusion_tenant_domain_and_validity() {
        let parent = scope("doc:*", "read");
        let mut child = scope("doc:1", "read");
        child.resource_tenant_id = CHILD_TENANT + 1;
        assert_eq!(
            parent.covers(&child).unwrap_err().code,
            OrgErrorCode::InvalidScopeRelation
        );

        let mut scoped_parent = scope("doc:*", "read");
        scoped_parent.domain_id = Some(5);
        let mut child_same = scope("doc:1", "read");
        child_same.domain_id = Some(5);
        assert!(scoped_parent.covers(&child_same).is_ok());
        assert!(scoped_parent.covers(&scope("doc:1", "read")).is_err());

        let mut wide_parent = scope("doc:*", "read");
        wide_parent.validity = window(500, 3_000);
        assert!(wide_parent.covers(&scope("doc:1", "read")).is_ok());
        let mut late_child = scope("doc:1", "read");
        late_child.validity = window(600, 9_000);
        assert_eq!(
            wide_parent.covers(&late_child).unwrap_err().code,
            OrgErrorCode::InvalidScopeRelation
        );
    }

    #[test]
    fn scope_rejects_malformed_forms() {
        assert!(org_parse_resource_form("").is_err());
        assert!(org_parse_resource_form(":42").is_err());
        assert!(org_parse_resource_form("doc:").is_err());
        assert!(org_parse_resource_form("do*c:1").is_err());
        assert!(org_parse_resource_form("doc:4*2").is_err());
        assert!(org_parse_resource_form("doc:*").is_ok());
        assert!(org_parse_resource_form("doc").is_ok());
        assert!(org_parse_resource_form("*").is_ok());
    }

    // ── grant ──

    #[test]
    fn grant_rejects_non_canonical_and_nil_uuid() {
        let mut grant = root_genesis_grant();
        grant.grant_id = grant.grant_id.to_uppercase();
        assert_eq!(
            grant.validate().unwrap_err().code,
            OrgErrorCode::NonCanonicalUuid
        );
        grant.grant_id = "00000000-0000-0000-0000-000000000000".to_owned();
        assert_eq!(grant.validate().unwrap_err().code, OrgErrorCode::NilUuid);
    }

    #[test]
    fn grant_parent_tenant_must_equal_origin() {
        let grant = OrgGrant {
            grant_id: uuid(2),
            revision: 1,
            receiving_tenant_id: CHILD_TENANT,
            origin_tenant_id: ROOT_TENANT,
            root_tenant_id: ROOT_TENANT,
            scope: scope("doc:42", "read"),
            delegable: true,
            parent: Some(OrgGrantRef {
                tenant_id: ROOT_TENANT,
                grant_id: uuid(1),
                revision: 1,
            }),
            subject: None,
            active: true,
            operation_id: "op-grant-2".to_owned(),
        };
        assert!(grant.validate().is_ok());

        let mut mismatched = grant.clone();
        mismatched.parent.as_mut().unwrap().tenant_id = 999;
        assert_eq!(
            mismatched.validate().unwrap_err().code,
            OrgErrorCode::OriginMismatch
        );
    }

    #[test]
    fn grant_serde_missing_fields_fail_closed() {
        // subject 缺键 → 哨兵 → validate 拒绝（不得静默变共享）。
        let json = format!(
            r#"{{"grantId":"{}","revision":1,"receivingTenantId":100,"originTenantId":100,"rootTenantId":100,
                "scope":{{"resourceTenantId":100,"resource":"doc:*","action":"read","validity":{{"notBefore":1,"expiresAt":2}}}},
                "delegable":true,"active":true,"operationId":"op"}}"#,
            uuid(3)
        );
        let parsed: OrgGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.validate().unwrap_err().code,
            OrgErrorCode::InvalidField
        );

        // 显式 null subject/parent 合法。
        let json_explicit = format!(
            r#"{{"grantId":"{}","revision":1,"receivingTenantId":100,"originTenantId":100,"rootTenantId":100,
                "scope":{{"resourceTenantId":100,"domainId":null,"resource":"doc:*","action":"read","validity":{{"notBefore":1,"expiresAt":2}}}},
                "delegable":true,"parent":null,"subject":null,"active":true,"operationId":"op"}}"#,
            uuid(3)
        );
        let parsed: OrgGrant = serde_json::from_str(&json_explicit).unwrap();
        assert!(parsed.validate().is_ok());

        // 未知字段拒绝。
        let json_unknown = format!(
            r#"{{"grantId":"{}","revision":1,"receivingTenantId":100,"originTenantId":100,"rootTenantId":100,
                "scope":{{"resourceTenantId":100,"domainId":null,"resource":"doc:*","action":"read","validity":{{}},"extra":1}},
                "delegable":true,"parent":null,"subject":null,"active":true,"operationId":"op"}}"#,
            uuid(3)
        );
        assert!(serde_json::from_str::<OrgGrant>(&json_unknown).is_err());
    }

    #[test]
    fn grant_revision_compatibility_enforces_immutability() {
        let old = root_genesis_grant();
        let mut next = old.clone();
        next.revision = 2;
        next.scope = scope("doc:*", "read");
        assert!(org_grant_revision_compatible(&old, &next).is_ok());

        let mut origin_drift = next.clone();
        origin_drift.origin_tenant_id = 777;
        assert_eq!(
            org_grant_revision_compatible(&old, &origin_drift)
                .unwrap_err()
                .code,
            OrgErrorCode::ImmutableFieldChanged
        );

        let mut stale = old.clone();
        assert_eq!(
            org_grant_revision_compatible(&old, &stale)
                .unwrap_err()
                .code,
            OrgErrorCode::RevisionNotAdvanced
        );
        stale.revision = 1;
        assert_eq!(
            org_grant_revision_compatible(&old, &stale)
                .unwrap_err()
                .code,
            OrgErrorCode::RevisionNotAdvanced
        );
    }

    #[test]
    fn personal_subject_is_immutable_across_grant_revisions() {
        let previous = root_genesis_grant();
        let mut next = previous.clone();
        next.revision = 2;
        next.subject = Some(OrgSubject {
            user_id: 11,
            card_id: 222,
        });
        assert_eq!(
            org_grant_revision_compatible(&previous, &next)
                .unwrap_err()
                .code,
            OrgErrorCode::ImmutableFieldChanged
        );
    }

    // ── mask / membership / dependency ──

    #[test]
    fn mask_cannot_target_own_tenant() {
        let mask = OrgMask {
            mask_id: uuid(4),
            tenant_id: CHILD_TENANT,
            target: OrgGrantRef {
                tenant_id: CHILD_TENANT,
                grant_id: uuid(2),
                revision: 1,
            },
            active: true,
            revision: 1,
            operation_id: "op-mask-1".to_owned(),
        };
        assert_eq!(
            mask.validate().unwrap_err().code,
            OrgErrorCode::MaskTargetSelf
        );
    }

    #[test]
    fn membership_validation_and_time_window() {
        assert!(membership(CHILD_TENANT).validate().is_ok());
        let mut expired = membership(CHILD_TENANT);
        expired.validity = window(1, 2);
        assert!(!expired.is_valid_at(5));
    }

    #[test]
    fn dependency_fence_bound_and_publication_match() {
        assert!(dependency().validate().is_ok());
        let mut bad = dependency();
        bad.revoke_fence = bad.generation + 1;
        assert_eq!(bad.validate().unwrap_err().code, OrgErrorCode::InvalidField);
    }

    // ── publication / digest ──

    fn contribution(grant: &OrgGrant, chain: Vec<OrgGrantRef>) -> OrgContribution {
        OrgContribution {
            grant_ref: OrgGrantRef {
                tenant_id: grant.receiving_tenant_id,
                grant_id: grant.grant_id.clone(),
                revision: grant.revision,
            },
            scope: grant.scope.clone(),
            delegable: grant.delegable,
            subject: grant.subject,
            provenance: OrgProvenance {
                origin_tenant_id: grant.origin_tenant_id,
                parent_chain: chain,
                operation_id: grant.operation_id.clone(),
            },
        }
    }

    /// 通用 sealed publication 构造（contents 必须已按 key 升序给出）。
    #[allow(clippy::too_many_arguments)]
    fn sealed_publication(
        tenant_id: i64,
        root_tenant_id: i64,
        generation: u64,
        revoke_fence: u64,
        relationship_revision: u64,
        dependencies: Vec<OrgDependency>,
        contents: Vec<OrgSegmentContent>,
        operation_id: &str,
    ) -> OrgPublication {
        let segments: Vec<OrgSegment> = contents
            .into_iter()
            .enumerate()
            .map(|(index, content)| org_build_segment(index as u32, content).unwrap())
            .collect();
        let publication = OrgPublication {
            tenant_id,
            root_tenant_id,
            generation,
            relationship_revision,
            revoke_fence,
            dependencies,
            manifest_digest_hex: String::new(),
            compiler_version: "org-compiler-v1".to_owned(),
            segments,
            operation_id: operation_id.to_owned(),
        };
        let manifest_digest_hex = org_manifest_digest_hex(&OrgManifestDigestMaterial {
            tenant_id: publication.tenant_id,
            root_tenant_id: publication.root_tenant_id,
            generation: publication.generation,
            relationship_revision: publication.relationship_revision,
            revoke_fence: publication.revoke_fence,
            dependencies: &publication.dependencies,
            segments: &publication.segments,
            compiler_version: &publication.compiler_version,
            operation_id: &publication.operation_id,
        })
        .unwrap();
        OrgPublication {
            manifest_digest_hex,
            ..publication
        }
    }

    fn single_segment_publication() -> OrgPublication {
        let grant = root_genesis_grant();
        let content = OrgSegmentContent {
            key: OrgScopeKey {
                resource: "doc:42".to_owned(),
                action: "read".to_owned(),
            },
            contributions: vec![contribution(&grant, Vec::new())],
        };
        let segment = org_build_segment(0, content).unwrap();
        let publication = OrgPublication {
            tenant_id: ROOT_TENANT,
            root_tenant_id: ROOT_TENANT,
            generation: 3,
            relationship_revision: 2,
            revoke_fence: 1,
            dependencies: Vec::new(),
            manifest_digest_hex: String::new(),
            compiler_version: "org-compiler-v1".to_owned(),
            segments: vec![segment],
            operation_id: "op-publish-1".to_owned(),
        };
        let digest = org_manifest_digest_hex(&OrgManifestDigestMaterial {
            tenant_id: publication.tenant_id,
            root_tenant_id: publication.root_tenant_id,
            generation: publication.generation,
            relationship_revision: publication.relationship_revision,
            revoke_fence: publication.revoke_fence,
            dependencies: &publication.dependencies,
            segments: &publication.segments,
            compiler_version: &publication.compiler_version,
            operation_id: &publication.operation_id,
        })
        .unwrap();
        OrgPublication {
            manifest_digest_hex: digest,
            ..publication
        }
    }

    #[test]
    fn publication_digest_round_trip_and_tamper_detection() {
        let publication = single_segment_publication();
        assert!(publication.validate().is_ok());

        // 篡改 wire/raw 内容但不破坏段键绑定（delegable 不参与键绑定，参与 digest），
        // 存储 digest_hex 保持原值 → 段级 digest 不再绑定其内容 → DigestMismatch。
        let mut tampered = publication.clone();
        let mut content: OrgSegmentContent =
            org_decode_segment_content(&tampered.segments[0]).unwrap();
        content.contributions[0].delegable = !content.contributions[0].delegable;
        tampered.segments[0].content = serde_json::to_value(&content).unwrap();
        assert_eq!(
            org_decode_segment_content(&tampered.segments[0])
                .unwrap_err()
                .code,
            OrgErrorCode::DigestMismatch
        );
        assert_eq!(
            tampered.validate().unwrap_err().code,
            OrgErrorCode::DigestMismatch
        );

        // 即使按篡改后内容重算段 digest（段自身自洽），publication manifest digest
        // 也不再绑定段集合 → publication 级 DigestMismatch（双层 fail-closed）。
        let mut rebuilt = publication.clone();
        let mut content: OrgSegmentContent =
            org_decode_segment_content(&rebuilt.segments[0]).unwrap();
        content.contributions[0].delegable = !content.contributions[0].delegable;
        rebuilt.segments[0] = org_build_segment(0, content).unwrap();
        assert!(org_decode_segment_content(&rebuilt.segments[0]).is_ok());
        assert_eq!(
            rebuilt.validate().unwrap_err().code,
            OrgErrorCode::DigestMismatch
        );
    }

    #[test]
    fn publication_enforces_segment_order_and_index() {
        // 每段贡献必须与段键语义一致（read 段载 read 授权、write 段载 write 授权）；
        // 两个段按 key 升序发布 → 反转后重编 index 并重算 manifest digest，
        // 仅段序校验必须失败（digest 本身不编码 key 顺序）。
        let mut write_grant = root_genesis_grant();
        write_grant.grant_id = uuid(2);
        write_grant.scope = scope("doc:42", "write");
        write_grant.operation_id = "op-grant-2".to_owned();
        let contents = vec![
            OrgSegmentContent {
                key: OrgScopeKey {
                    resource: "doc:42".to_owned(),
                    action: "read".to_owned(),
                },
                contributions: vec![contribution(&root_genesis_grant(), Vec::new())],
            },
            OrgSegmentContent {
                key: OrgScopeKey {
                    resource: "doc:42".to_owned(),
                    action: "write".to_owned(),
                },
                contributions: vec![contribution(&write_grant, Vec::new())],
            },
        ];
        let mut publication = sealed_publication(
            ROOT_TENANT,
            ROOT_TENANT,
            3,
            1,
            2,
            Vec::new(),
            contents,
            "op-publish-1",
        );
        assert!(publication.validate().is_ok());

        // index 漂移先于 digest 校验失败：未按位对齐的段序号必须被拒绝。
        let mut index_drift = publication.clone();
        index_drift.segments[1].index = 7;
        assert_eq!(
            index_drift.validate().unwrap_err().code,
            OrgErrorCode::SegmentIndexInvalid
        );

        publication.segments.reverse();
        // 重建 index 后顺序仍逆序 → 段序校验失败。
        for (index, segment) in publication.segments.iter_mut().enumerate() {
            segment.index = index as u32;
        }
        let digest = org_manifest_digest_hex(&OrgManifestDigestMaterial {
            tenant_id: publication.tenant_id,
            root_tenant_id: publication.root_tenant_id,
            generation: publication.generation,
            relationship_revision: publication.relationship_revision,
            revoke_fence: publication.revoke_fence,
            dependencies: &publication.dependencies,
            segments: &publication.segments,
            compiler_version: &publication.compiler_version,
            operation_id: &publication.operation_id,
        })
        .unwrap();
        publication.manifest_digest_hex = digest;
        assert_eq!(
            publication.validate().unwrap_err().code,
            OrgErrorCode::SegmentOrderInvalid
        );
    }

    #[test]
    fn publication_contains_grant_finds_winner() {
        let publication = single_segment_publication();
        let winner = OrgGrantRef {
            tenant_id: ROOT_TENANT,
            grant_id: uuid(1),
            revision: 1,
        };
        assert!(publication.contains_grant(&winner));
        let absent = OrgGrantRef {
            tenant_id: ROOT_TENANT,
            grant_id: uuid(8),
            revision: 1,
        };
        assert!(!publication.contains_grant(&absent));
    }

    // ── 请求载荷 ──

    #[test]
    fn request_payload_validation_and_kinds() {
        let attach = OrgRequestPayload::Attach {
            child_tenant_id: CHILD_TENANT,
            parent_tenant_id: CHILD_TENANT,
        };
        assert_eq!(
            attach.validate().unwrap_err().code,
            OrgErrorCode::SelfReference
        );

        let grant = OrgRequestPayload::Grant {
            receiving_tenant_id: CHILD_TENANT,
            parent_grant: OrgGrantRef {
                tenant_id: ROOT_TENANT,
                grant_id: uuid(1),
                revision: 1,
            },
            scope: scope("doc:1", "read"),
            delegable: false,
            subject: Some(OrgSubject {
                user_id: 11,
                card_id: 222,
            }),
        };
        assert!(grant.validate().is_ok());
        assert_eq!(grant.kind().as_str(), "GRANT");

        let round_trip: OrgRequestPayload =
            serde_json::from_str(&serde_json::to_string(&grant).unwrap()).unwrap();
        assert_eq!(round_trip, grant);
    }

    // ── 编译输入 ──

    #[test]
    fn compile_input_root_shape() {
        let input = OrgCompileInput {
            node: root_node(),
            dependencies: Vec::new(),
            parent_publications: Vec::new(),
            grants: vec![root_genesis_grant()],
            masks: Vec::new(),
            operation_id: "op-compile-1".to_owned(),
        };
        assert!(input.validate().is_ok());

        let mut with_mask = input.clone();
        with_mask.masks.push(OrgMask {
            mask_id: uuid(5),
            tenant_id: ROOT_TENANT,
            target: OrgGrantRef {
                tenant_id: ROOT_TENANT - 1,
                grant_id: uuid(1),
                revision: 1,
            },
            active: true,
            revision: 1,
            operation_id: "op-mask".to_owned(),
        });
        assert_eq!(
            with_mask.validate().unwrap_err().code,
            OrgErrorCode::MasksForbiddenForRoot
        );
    }

    #[test]
    fn compile_input_root_grant_rejects_foreign_resource_tenant() {
        // 防御纵深：根单元无父 provenance 可证明外部资源属主，畸形 durable 数据
        // （scope 资源租户 ≠ 权威根）必须在编译输入边界 fail-closed；资源租户等于
        // 权威根的既有根授权保持兼容。
        let mut input = OrgCompileInput {
            node: root_node(),
            dependencies: Vec::new(),
            parent_publications: Vec::new(),
            grants: vec![root_genesis_grant()],
            masks: Vec::new(),
            operation_id: "op-compile-1".to_owned(),
        };
        assert!(input.validate().is_ok());

        input.grants[0].scope.resource_tenant_id = ROOT_TENANT + 1;
        assert_eq!(
            input.validate().unwrap_err().code,
            OrgErrorCode::TenantMismatch
        );
    }

    #[test]
    fn compile_input_child_requires_matching_parent_publication() {
        let publication = single_segment_publication();
        let input = OrgCompileInput {
            node: child_node(),
            dependencies: vec![dependency()],
            parent_publications: vec![publication.clone()],
            grants: vec![OrgGrant {
                grant_id: uuid(2),
                revision: 1,
                receiving_tenant_id: CHILD_TENANT,
                origin_tenant_id: ROOT_TENANT,
                root_tenant_id: ROOT_TENANT,
                scope: scope("doc:42", "read"),
                delegable: false,
                parent: Some(OrgGrantRef {
                    tenant_id: ROOT_TENANT,
                    grant_id: uuid(1),
                    revision: 1,
                }),
                subject: None,
                active: true,
                operation_id: "op-grant-2".to_owned(),
            }],
            masks: Vec::new(),
            operation_id: "op-compile-2".to_owned(),
        };
        assert!(input.validate().is_err()); // 依赖栅栏与 publication 不一致 → DependencyMismatch

        let mut aligned = input;
        aligned.dependencies[0] = OrgDependency {
            tenant_id: publication.tenant_id,
            generation: publication.generation,
            revoke_fence: publication.revoke_fence,
            relationship_revision: publication.relationship_revision,
        };
        assert!(aligned.validate().is_ok());
    }

    #[test]
    fn compile_input_requires_transitive_ancestor_dependencies() {
        // 根 publication（gen 3/fence 1/rel 2，无依赖）→ 子单元发布 deps=[root head]。
        let root_publication = single_segment_publication();
        let root_dependency = OrgDependency {
            tenant_id: root_publication.tenant_id,
            generation: root_publication.generation,
            revoke_fence: root_publication.revoke_fence,
            relationship_revision: root_publication.relationship_revision,
        };
        let child_grant = OrgGrant {
            grant_id: uuid(2),
            revision: 1,
            receiving_tenant_id: CHILD_TENANT,
            origin_tenant_id: ROOT_TENANT,
            root_tenant_id: ROOT_TENANT,
            scope: scope("doc:42", "read"),
            delegable: true,
            parent: Some(OrgGrantRef {
                tenant_id: ROOT_TENANT,
                grant_id: uuid(1),
                revision: 1,
            }),
            subject: None,
            active: true,
            operation_id: "op-grant-2".to_owned(),
        };
        let child_publication = sealed_publication(
            CHILD_TENANT,
            ROOT_TENANT,
            7,
            2,
            5,
            vec![root_dependency],
            vec![OrgSegmentContent {
                key: OrgScopeKey {
                    resource: "doc:42".to_owned(),
                    action: "read".to_owned(),
                },
                contributions: vec![contribution(
                    &child_grant,
                    vec![OrgGrantRef {
                        tenant_id: ROOT_TENANT,
                        grant_id: uuid(1),
                        revision: 1,
                    }],
                )],
            }],
            "op-publish-child",
        );
        assert!(child_publication.validate().is_ok());

        // 孙单元输入：deps 必须是 [root, child] 扁平传递向量（根在前，按 tenant 排序）。
        let grandchild_node = OrgNode {
            tenant_id: 300,
            root_tenant_id: ROOT_TENANT,
            parent_tenant_id: Some(CHILD_TENANT),
            generation: 2,
            revoke_fence: 0,
            relationship_revision: 1,
            active: true,
            operation_id: "op-gc".to_owned(),
            root_activation: None,
        };
        let child_dependency = OrgDependency {
            tenant_id: CHILD_TENANT,
            generation: child_publication.generation,
            revoke_fence: child_publication.revoke_fence,
            relationship_revision: child_publication.relationship_revision,
        };
        let complete = OrgCompileInput {
            node: grandchild_node,
            dependencies: vec![root_dependency, child_dependency],
            parent_publications: vec![child_publication],
            grants: vec![],
            masks: vec![],
            operation_id: "op-gc-compile".to_owned(),
        };
        assert!(complete.validate().is_ok());

        // 缺失传递祖先（仅钉直接父）→ 拒绝：祖父撤销将无法即时感知。
        let incomplete = OrgCompileInput {
            dependencies: vec![child_dependency],
            ..complete.clone()
        };
        assert_eq!(
            incomplete.validate().unwrap_err().code,
            OrgErrorCode::DependencyCountMismatch
        );

        // 传递祖先栅栏与父 publication 钉栅漂移 → 拒绝。
        let mut drifted_root = root_dependency;
        drifted_root.generation += 1;
        let drifted = OrgCompileInput {
            dependencies: vec![drifted_root, child_dependency],
            ..complete
        };
        assert_eq!(
            drifted.validate().unwrap_err().code,
            OrgErrorCode::DependencyMismatch
        );
    }

    /// 深行政链 fixture：tenant = 1000 + depth（随深度严格递增，tenant 排序即深度序）。
    /// 每层单元发布一个可委托 grant（贡献 provenance 链自根端向直接父排列，链长 = 深度，
    /// origin = 链最根端租户），并钉住全部祖先 head 栅栏（扁平依赖向量，长度 = 深度）。
    /// 返回 (各层 publication, 各层 grant)，索引即深度。
    fn deep_chain_fixtures(max_depth: usize) -> (Vec<OrgPublication>, Vec<OrgGrant>) {
        let base_tenant = 1_000i64;
        let tenant = |depth: usize| base_tenant + depth as i64;
        let mut publications = Vec::with_capacity(max_depth + 1);
        let mut grants = Vec::with_capacity(max_depth + 1);
        for depth in 0..=max_depth {
            let grant = OrgGrant {
                grant_id: uuid(depth as u8),
                revision: 1,
                receiving_tenant_id: tenant(depth),
                origin_tenant_id: tenant(depth.saturating_sub(1)),
                root_tenant_id: tenant(0),
                scope: OrgScope {
                    resource_tenant_id: tenant(depth),
                    domain_id: None,
                    resource: "doc:42".to_owned(),
                    action: "read".to_owned(),
                    validity: window(1_000, 2_000),
                },
                delegable: true,
                parent: if depth == 0 {
                    None
                } else {
                    Some(OrgGrantRef {
                        tenant_id: tenant(depth - 1),
                        grant_id: uuid((depth - 1) as u8),
                        revision: 1,
                    })
                },
                subject: None,
                active: true,
                operation_id: format!("op-grant-d{depth}"),
            };
            // provenance：链自根端（depth 0）向直接父（depth-1）排列；origin = 链最根端租户。
            let chain: Vec<OrgGrantRef> = (0..depth)
                .map(|level| OrgGrantRef {
                    tenant_id: tenant(level),
                    grant_id: uuid(level as u8),
                    revision: 1,
                })
                .collect();
            // 扁平依赖向量：全部祖先 head 栅栏（tenant 升序 = 深度升序），长度 = 深度。
            let dependencies: Vec<OrgDependency> = (0..depth)
                .map(|level| OrgDependency {
                    tenant_id: tenant(level),
                    generation: level as u64 + 1,
                    revoke_fence: 1,
                    relationship_revision: level as u64 + 2,
                })
                .collect();
            let owner_contribution = OrgContribution {
                grant_ref: OrgGrantRef {
                    tenant_id: grant.receiving_tenant_id,
                    grant_id: grant.grant_id.clone(),
                    revision: grant.revision,
                },
                scope: grant.scope.clone(),
                delegable: grant.delegable,
                subject: grant.subject,
                provenance: OrgProvenance {
                    origin_tenant_id: tenant(0),
                    parent_chain: chain,
                    operation_id: grant.operation_id.clone(),
                },
            };
            let publication = sealed_publication(
                tenant(depth),
                tenant(0),
                depth as u64 + 1,
                1,
                depth as u64 + 2,
                dependencies,
                vec![OrgSegmentContent {
                    key: OrgScopeKey {
                        resource: "doc:42".to_owned(),
                        action: "read".to_owned(),
                    },
                    contributions: vec![owner_contribution],
                }],
                &format!("op-publish-d{depth}"),
            );
            grants.push(grant);
            publications.push(publication);
        }
        (publications, grants)
    }

    #[test]
    fn max_depth_chain_dependency_vector_is_accepted() {
        // 对齐不变式：扁平依赖向量每层恰一项，行政树深度上界 = provenance 链上界，
        // 因此依赖数上界必须覆盖最深许可拓扑（深度 64 → 恰 64 项依赖）。
        assert_eq!(MAX_ORG_DEPENDENCIES, MAX_ORG_PROVENANCE_CHAIN);
        let (publications, grants) = deep_chain_fixtures(MAX_ORG_PROVENANCE_CHAIN);
        assert_eq!(publications.len(), MAX_ORG_PROVENANCE_CHAIN + 1);
        for (depth, publication) in publications.iter().enumerate() {
            assert_eq!(publication.dependencies.len(), depth);
            assert!(
                publication.validate().is_ok(),
                "depth {depth} publication with its full flattened dependency vector must validate"
            );
        }

        // 最深单元：provenance 链与扁平依赖向量同时恰达 64 项上界。
        let deepest = publications.last().unwrap();
        let deepest_content = org_decode_segment_content(&deepest.segments[0]).unwrap();
        assert_eq!(
            deepest_content.contributions[0]
                .provenance
                .parent_chain
                .len(),
            MAX_ORG_PROVENANCE_CHAIN
        );
        assert_eq!(deepest.dependencies.len(), MAX_ORG_DEPENDENCIES);

        // 最深单元的编译输入：64 项扁平依赖 + 直接父 publication + 自有 grant → 接受。
        let deepest_grant = grants.last().unwrap();
        let parent_publication = &publications[publications.len() - 2];
        let input = OrgCompileInput {
            node: OrgNode {
                tenant_id: deepest_grant.receiving_tenant_id,
                root_tenant_id: deepest.root_tenant_id,
                parent_tenant_id: Some(parent_publication.tenant_id),
                generation: deepest.generation,
                revoke_fence: deepest.revoke_fence,
                relationship_revision: deepest.relationship_revision,
                active: true,
                operation_id: "op-compile-d64".to_owned(),
                root_activation: None,
            },
            dependencies: deepest.dependencies.clone(),
            parent_publications: vec![parent_publication.clone()],
            grants: vec![deepest_grant.clone()],
            masks: Vec::new(),
            operation_id: "op-compile-d64".to_owned(),
        };
        assert!(input.validate().is_ok());
    }

    #[test]
    fn dependency_vector_one_over_limit_is_rejected() {
        // 深度 65 的假想单元：扁平依赖向量 65 项 = 最深许可向量 + 直接父 head，
        // publication 与编译输入都必须 BoundsExceeded（依赖上界 fail-closed）。
        let (publications, _) = deep_chain_fixtures(MAX_ORG_PROVENANCE_CHAIN);
        let deepest = publications.last().unwrap();
        let mut over_deps = deepest.dependencies.clone();
        over_deps.push(OrgDependency {
            tenant_id: deepest.tenant_id,
            generation: deepest.generation,
            revoke_fence: deepest.revoke_fence,
            relationship_revision: deepest.relationship_revision,
        });
        assert_eq!(over_deps.len(), MAX_ORG_DEPENDENCIES + 1);

        // publication 侧：空段集自洽，唯一越界点即依赖向量长度。
        let over_publication = sealed_publication(
            deepest.tenant_id + 1,
            deepest.root_tenant_id,
            deepest.generation + 1,
            1,
            deepest.relationship_revision + 1,
            over_deps.clone(),
            Vec::new(),
            "op-publish-over",
        );
        assert_eq!(
            over_publication.validate().unwrap_err().code,
            OrgErrorCode::BoundsExceeded
        );

        // 编译输入侧：越界先于形状/父对牌校验，同样 BoundsExceeded。
        let over_input = OrgCompileInput {
            node: OrgNode {
                tenant_id: deepest.tenant_id + 1,
                root_tenant_id: deepest.root_tenant_id,
                parent_tenant_id: Some(deepest.tenant_id),
                generation: deepest.generation + 1,
                revoke_fence: 1,
                relationship_revision: deepest.relationship_revision + 1,
                active: true,
                operation_id: "op-compile-over".to_owned(),
                root_activation: None,
            },
            dependencies: over_deps,
            parent_publications: vec![deepest.clone()],
            grants: Vec::new(),
            masks: Vec::new(),
            operation_id: "op-compile-over".to_owned(),
        };
        assert_eq!(
            over_input.validate().unwrap_err().code,
            OrgErrorCode::BoundsExceeded
        );
    }

    // ── 准入证据与复读 ──

    #[test]
    fn admission_evidence_validation_and_recheck() {
        let publication = single_segment_publication();
        let node = root_node();
        // root 单元证据：membership 必须与 publication 同租户（root 租户）。
        let member = membership(ROOT_TENANT);
        let winner = contribution(&root_genesis_grant(), Vec::new());
        let evidence = OrgAdmissionEvidence {
            publication: publication.clone(),
            node,
            membership: member.clone(),
            checked_at_unix: 1_500,
        };
        assert!(evidence.validate().is_ok());

        // 节点头栅栏与 publication 失配 → validate 拒绝。
        let mut fence_drift = evidence.clone();
        fence_drift.node.generation += 1;
        assert_eq!(
            fence_drift.validate().unwrap_err().code,
            OrgErrorCode::DependencyMismatch
        );

        let mut expired = evidence.clone();
        expired.checked_at_unix = 9_999;
        assert_eq!(
            expired.validate().unwrap_err().code,
            OrgErrorCode::MembershipExpired
        );

        assert!(org_admission_recheck_stable(&evidence, &evidence, &winner));

        let mut drifted = evidence.clone();
        drifted.membership.revision = 2;
        assert!(!org_admission_recheck_stable(&evidence, &drifted, &winner));

        let mut absent_winner = contribution(&root_genesis_grant(), Vec::new());
        absent_winner.grant_ref.grant_id = uuid(8);
        assert!(!org_admission_recheck_stable(
            &evidence,
            &evidence,
            &absent_winner
        ));

        // 获胜贡献在两读之间过期 → 复读必须拒绝（旧候选不得放行）。
        let mut next = evidence.clone();
        next.checked_at_unix = 2_500; // 越过 validity(1000..2000) 上界
        assert!(!org_admission_recheck_stable(&evidence, &next, &winner));
    }

    #[test]
    fn pending_codes_are_stable_and_serializable() {
        assert_eq!(
            OrgPendingCode::CurrentPointerMissing.as_machine_code(),
            "org_scope.pending.current_pointer_missing"
        );
        let result = OrgAdmissionResult::Pending {
            code: OrgPendingCode::MembershipInactive,
            detail: "membership revoked".to_owned(),
        };
        let encoded = serde_json::to_string(&result).unwrap();
        let decoded: OrgAdmissionResult = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, result);
    }

    #[test]
    fn branch_provenance_validates() {
        let provenance = OrgBranchProvenance {
            receiving_tenant_id: CHILD_TENANT,
            source_tenant_id: ROOT_TENANT,
            resource_tenant_id: CHILD_TENANT,
            root_tenant_id: ROOT_TENANT,
            membership_id: uuid(9),
            membership_revision: 1,
            branch_kind: OrgBranchKind::Shared,
            grant_ref: OrgGrantRef {
                tenant_id: CHILD_TENANT,
                grant_id: uuid(2),
                revision: 1,
            },
            publication_generation: 5,
            manifest_digest_hex: org_sha256_hex(b"manifest"),
            approval_operation_id: "op-grant-2".to_owned(),
        };
        assert!(provenance.validate().is_ok());
    }

    fn subtree_payload(child: i64, root: i64, revision: u64) -> OrgSubtreePropagatePayload {
        OrgSubtreePropagatePayload {
            child_tenant_id: child,
            new_root_tenant_id: root,
            relationship_revision: revision,
        }
    }

    #[test]
    fn subtree_payload_serializes_with_the_historical_wire_keys() {
        // wire 兼容：键名与历史 ad hoc JSON producer 完全一致（snake_case），
        // 既有已入队行保持可解析。
        let encoded = serde_json::to_string(&subtree_payload(20, 30, 7)).unwrap();
        assert_eq!(
            encoded,
            r#"{"child_tenant_id":20,"new_root_tenant_id":30,"relationship_revision":7}"#
        );
        let decoded: OrgSubtreePropagatePayload = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, subtree_payload(20, 30, 7));
    }

    #[test]
    fn subtree_payload_rejects_unknown_and_missing_fields() {
        // deny_unknown_fields：未知字段一律拒绝。
        let extra =
            r#"{"child_tenant_id":20,"new_root_tenant_id":30,"relationship_revision":7,"extra":1}"#;
        assert!(serde_json::from_str::<OrgSubtreePropagatePayload>(extra).is_err());
        // 缺字段同样失败（无哨兵 default；revision/ids 全部必填）。
        let missing = r#"{"child_tenant_id":20,"new_root_tenant_id":30}"#;
        assert!(serde_json::from_str::<OrgSubtreePropagatePayload>(missing).is_err());
        // u64 revision 不接受负数。
        let negative =
            r#"{"child_tenant_id":20,"new_root_tenant_id":30,"relationship_revision":-1}"#;
        assert!(serde_json::from_str::<OrgSubtreePropagatePayload>(negative).is_err());
    }

    #[test]
    fn subtree_payload_validate_requires_positive_ids_and_nonzero_revision() {
        assert!(subtree_payload(20, 30, 7).validate().is_ok());
        assert!(subtree_payload(20, 30, 1).validate().is_ok());
        for bad in [
            subtree_payload(0, 30, 7),
            subtree_payload(-1, 30, 7),
            subtree_payload(20, 0, 7),
            subtree_payload(20, -3, 7),
            subtree_payload(20, 30, 0),
        ] {
            assert!(
                bad.validate().is_err(),
                "payload {bad:?} must fail validation"
            );
        }
    }

    fn dependency_payload(anchor: i64) -> OrgDependencyPropagatePayload {
        OrgDependencyPropagatePayload {
            anchor_tenant_id: anchor,
            root_tenant_id: 10,
            generation: 7,
            revoke_fence: 3,
            relationship_revision: 4,
        }
    }

    #[test]
    fn dependency_payload_serializes_with_stable_wire_keys() {
        let payload = dependency_payload(20);
        let encoded = serde_json::to_string(&payload).unwrap();
        assert_eq!(
            encoded,
            r#"{"anchor_tenant_id":20,"root_tenant_id":10,"generation":7,"revoke_fence":3,"relationship_revision":4}"#
        );
        assert_eq!(
            serde_json::from_str::<OrgDependencyPropagatePayload>(&encoded).unwrap(),
            payload
        );
    }

    #[test]
    fn dependency_payload_rejects_unknown_and_missing_fields() {
        let extra = r#"{"anchor_tenant_id":20,"root_tenant_id":10,"generation":7,"revoke_fence":3,"relationship_revision":4,"extra":1}"#;
        assert!(serde_json::from_str::<OrgDependencyPropagatePayload>(extra).is_err());
        let missing =
            r#"{"anchor_tenant_id":20,"root_tenant_id":10,"generation":7,"revoke_fence":3}"#;
        assert!(serde_json::from_str::<OrgDependencyPropagatePayload>(missing).is_err());
        let negative = r#"{"anchor_tenant_id":20,"root_tenant_id":10,"generation":-1,"revoke_fence":3,"relationship_revision":4}"#;
        assert!(serde_json::from_str::<OrgDependencyPropagatePayload>(negative).is_err());
    }

    #[test]
    fn dependency_payload_requires_positive_ids_and_valid_head() {
        assert!(dependency_payload(20).validate().is_ok());
        assert!(OrgDependencyPropagatePayload {
            revoke_fence: 0,
            ..dependency_payload(20)
        }
        .validate()
        .is_ok());
        for bad in [
            OrgDependencyPropagatePayload {
                anchor_tenant_id: 0,
                ..dependency_payload(20)
            },
            OrgDependencyPropagatePayload {
                root_tenant_id: 0,
                ..dependency_payload(20)
            },
            OrgDependencyPropagatePayload {
                generation: 0,
                ..dependency_payload(20)
            },
            OrgDependencyPropagatePayload {
                revoke_fence: 1,
                generation: 0,
                ..dependency_payload(20)
            },
            OrgDependencyPropagatePayload {
                relationship_revision: 0,
                ..dependency_payload(20)
            },
        ] {
            assert!(
                bad.validate().is_err(),
                "payload {bad:?} must fail validation"
            );
        }
    }
}
