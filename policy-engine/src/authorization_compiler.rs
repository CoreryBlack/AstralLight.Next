//! Phase 2 authorization hot-state compiler kernel.
//!
//! This module is intentionally Rust-native and has no I/O. It compiles a deterministic
//! canonical ALLOW grant set in memory, applies stable [`GrantId`] / [`GrantRevision`]
//! deltas, and produces an impact plan for a future projection writer. It is not wired to
//! SQL, Redis, RabbitMQ, a worker, or the production [`PolicyEngine`](crate::PolicyEngine)
//! read path yet.
//!
//! The incremental candidate is generation/version fenced: a caller must provide the
//! exact base version, semantic hash, and dependency hash it read. A mismatch is returned
//! as an explicit conflict or full-rebuild-required outcome; it is never treated as an
//! empty or successful operation. Exact projection keys are stored in persistent maps
//! rather than array indexes. Each exact key is one independently reusable segment, so
//! unchanged segment content is retained by [`Arc`] while only affected segments are
//! rebuilt.
//!
//! O(affected) 编译（v3，2026-08）：增量候选的材料化只重建 affected key 的段
//! （`materialize_incremental_candidate`），未受影响 key 直接继承 base 段的
//! `Arc`，不再全量重算 `build_segments`；semantic hash 采用段聚合语义
//! （`semantic_hash` 只绑定 Active 段内容 hash 列表），增量路径只重算 affected
//! 段 hash。Inactive/墓碑记录不产生授权，"Active 集相同"的 ledger 状态语义
//! 等价并给出相同 hash——详见 `semantic_hash` 的语义变化说明。
//!
//! O(1) 单键变更（v4，2026-08）：HotState 的 segments 迁移为持久化
//! 数据结构（`im::HashMap` HAMT）——`clone` 从 O(N) 深拷贝降为 O(1) 结构共享，
//! 单键查/增/删均为 O(1) 平均（COW 路径复制）；增量编译的 ledger clone
//! 不再随 N 线性增长。代价是 HAMT 迭代无序：凡需要稳定序的路径（段 ordinal
//! 分配、导出、段构建）一律显式按 key 排序——单键变更全程 O(1) avg + affected
//! 段重建 O(段内成员数)；O(S log S) 的显式排序只出现在发布事务与 full oracle
//! 等低频/全量路径，与单键变更无关。
//!
//! Factored 共享层（factored 布局，2026-08）：ledger 从 per-card grant 列表
//! 重构为三层事实化表示——共享层（`SharedRuleSetEntry`：同内容条目授权只存
//! 一份，内容寻址去重）+ 绑定层（card → 规则集引用计数）+ 卡私有层
//! （`private_grants`：非 RULE_SET 来源 grant）+ 记录层（`RuleSetGrantRecord`：
//! RULE_SET grant 的 per-grant 生命周期与归属，经 `Arc` 引用共享层）。
//! 编译输入输出（`GrantLedgerEntry`/`GrantDelta`）、段表示、hash 语义与
//! durable 发布契约全部不变；`COMPILER_VERSION` 不升版（无段/hash 语义变化，
//! 升版会令滚动窗口内 in-flight 事件被 producer 版本门拒绝）。设计、转换规则
//! 与等价性论证见
//! `Docs/架构/Rust架构设计/FactoredHotState设计_V1.0.md`。

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as FmtWrite;
use std::sync::Arc;

use astral_types::{
    get_alias_sources, BindingLayer, CanonicalGrant, DependencyVector, GrantContractError,
    GrantDelta, GrantEffect, GrantId, GrantProvenance, GrantRevision, GrantSourceKind, GrantState,
    ProjectionCompileMode, SegmentReference, TenantScope, ValidityWindow, ACTION_ALIASES,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Compiler semantic version. Changing wildcard, validity, ordering, or segment semantics
/// requires a full rebuild instead of reusing a candidate produced by another version.
/// v2（2026-08-29）：触发面收窄——窗口不再强制全量、base 形态不再污染增量资格；
/// 旧版本 base 遇到 v2 编译器按 CompilerVersionMismatch 全量重建一次后恢复增量。
/// v3（2026-08-28）：semantic hash 改为段聚合语义——只绑定 Active 段内容
/// （`semantic_hash` 输入从全量 ledger 记录改为按 key 排序的段内容 hash 列表）。
/// Inactive/墓碑记录不产生授权，"Active 集相同"的两个 ledger 状态自此给出相同
/// semantic hash（更粗粒度但更正确的授权语义等价）；旧版本 base 遇到 v3 编译器
/// 按 CompilerVersionMismatch 全量重建一次后恢复增量。
/// v4（2026-08-28）：HotState 结构迁移为持久化数据结构（im::HashMap HAMT，
/// clone O(1) 结构共享、单键 O(1) avg 查/增/删）且 semantic hash 重定义为版本
/// 绑定标识——`sha256(JSON{compiler_version, tenant, version, dependency_hash})`，
/// 全部 O(1) 字段（详见 `semantic_hash` 语义说明）。旧版本 base 遇到 v4 编译器
/// 按 CompilerVersionMismatch 全量重建一次后恢复增量。
pub const COMPILER_VERSION: &str = "phase2-authorization-kernel-v4";

/// Maximum number of deltas that the local incremental planner accepts.
pub const MAX_INCREMENTAL_DELTAS: usize = 100;

/// Result type used by compiler construction, canonicalization, and oracle APIs.
pub type CompilerResult<T> = Result<T, CompilerError>;

/// Errors which prevent a compiler request from being structurally evaluated.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CompilerError {
    /// A shared grant contract rejected the input.
    #[error("grant contract validation failed: {0}")]
    Contract(#[from] GrantContractError),

    /// Two records attempted to occupy one stable grant identity while constructing a base.
    #[error("duplicate grant identity in base state: {grant_id}")]
    DuplicateGrant { grant_id: GrantId },

    /// A state invariant cannot be represented by the in-memory kernel.
    #[error("invalid hot state: {0}")]
    InvalidState(String),

    /// The deterministic hash input could not be serialized.
    #[error("canonical compiler serialization failed: {0}")]
    CanonicalSerialization(String),
}

/// A base/request mismatch or delta identity conflict.
///
/// Conflicts are explicit successful outcomes of the pure compiler API. The caller can
/// record them and decide whether to retry against a fresh base or request a full rebuild;
/// the kernel does not silently discard a delta.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CompilerConflict {
    /// The request was built from a different version than the supplied base.
    #[error("base version mismatch: request={expected}, actual={actual}")]
    BaseVersionMismatch { expected: u64, actual: u64 },

    /// The request was built from a different semantic base hash.
    #[error("base semantic hash mismatch: request={expected}, actual={actual}")]
    BaseHashMismatch { expected: String, actual: String },

    /// The request carried a stale dependency hash.
    #[error("base dependency hash mismatch: request={expected}, actual={actual}")]
    BaseDependencyHashMismatch { expected: String, actual: String },

    /// A candidate must advance exactly one version at a time.
    #[error("target version mismatch: base={base}, target={target}")]
    TargetVersionMismatch { base: u64, target: u64 },

    /// The base was compiled by a different semantic compiler.
    #[error("compiler version mismatch: request={expected}, actual={actual}")]
    CompilerVersionMismatch { expected: String, actual: String },

    /// The same stable identity occurred more than once in one batch.
    #[error("duplicate delta for grant {grant_id}")]
    DuplicateDelta { grant_id: GrantId },

    /// ADD cannot overwrite a currently active contribution.
    #[error("ADD targets an existing active grant {grant_id}")]
    ExistingGrant { grant_id: GrantId },

    /// The stable identity is not present in the mutable base ledger.
    #[error("delta targets unknown grant {grant_id}")]
    UnknownGrant { grant_id: GrantId },

    /// UPDATE cannot reactivate a grant which is already tombstoned.
    #[error("UPDATE targets inactive grant {grant_id} in state {state:?}")]
    InactiveGrant {
        grant_id: GrantId,
        state: GrantState,
    },

    /// A delta revision is stale, skipped, or inconsistent with the current ledger record.
    #[error("revision conflict for grant {grant_id}: expected {expected:?}, actual {actual:?}")]
    RevisionConflict {
        grant_id: GrantId,
        expected: GrantRevision,
        actual: GrantRevision,
    },

    /// A delta grant belongs to a different physical tenant.
    #[error("grant {grant_id} does not belong to the base tenant")]
    TenantMismatch { grant_id: GrantId },

    /// An empty batch cannot claim a new target version.
    #[error("an empty delta batch cannot advance the projection version")]
    EmptyDeltaBatch,
}

/// Conservative reasons why a local candidate must be rebuilt by the full oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FullRebuildReason {
    /// More than [`MAX_INCREMENTAL_DELTAS`] were supplied.
    DeltaTooLarge,
    /// A resource/action wildcard may affect an unknown set of exact keys.
    WildcardImpact,
    /// An action alias has more than one semantic lookup expansion.
    ActionAliasImpact,
    /// A validity window requires time-aware evaluation outside this kernel.
    ///
    /// Deprecated trigger (reserved): 2026-08-29 触发面收窄后窗口不再强制全量——
    /// 窗口是 grant 自身属性且读侧按 UTC now 过滤，窗口 delta 走组合级增量
    /// （semantic/segment hash 覆盖 validity 字段保证变更可检测）。枚举值保留
    /// 以稳定序列化/匹配兼容，当前无触发点。
    #[allow(dead_code)]
    ValidityWindowImpact,
    /// A source/layer change may alter precedence semantics outside ALLOW-only storage.
    BindingImpact,
    /// The base was produced by an incompatible compiler.
    CompilerVersionMismatch,
    /// Dependency material changed; all dependent segments must be re-evaluated.
    DependencyChanged,
}

// ─────────────────────────────────────────────────────────────────────────────
// Factored ledger layers（factored 布局，2026-08）
//
// 设计与等价性论证：Docs/架构/Rust架构设计/FactoredHotState设计_V1.0.md。
// 共享层存放 RULE_SET 条目授权的内容事实（同内容只存一份，内容寻址去重）；
// 绑定层存放 card → 规则集引用计数；记录层存放 RULE_SET grant 的 per-grant
// 生命周期与归属（经 Arc 引用共享层）；卡私有层存放非 RULE_SET 来源 grant。
// 编译输入输出、段表示与 hash 语义不变。
// ─────────────────────────────────────────────────────────────────────────────

/// 共享层条目：RULE_SET 条目授权的内容事实，不含任何卡/绑定归属。
///
/// 键为 [`SharedRuleSetEntry::content_hash`]（sha256 of canonical content JSON）。
/// 收敛态（同 (source_id, source_entry) 跨卡内容一致，见设计文档 §2 的 Phase 1
/// 验证）下内容寻址与"按 (rule_set_id, entry_id) 去重"严格等价；前提暂时被打破
/// 时自动退化为少共享/不共享，绝不跨卡污染（fail-safe）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedRuleSetEntry {
    /// 内容身份（共享层 map 键）：`sha256_hex(canonical content JSON)`。
    pub content_hash: String,
    /// rule_set_id（ledger `provenance.source_id`）。
    pub source_id: String,
    /// entry_id（ledger `provenance.source_entry`）。
    pub source_entry: Option<String>,
    /// 条目授权资源（canonical）。
    pub resource: String,
    /// 条目授权动作（canonical）。
    pub action: String,
    /// 条目效果（ALLOW-only 合同下恒为 ALLOW）。
    pub effect: GrantEffect,
    /// 条目有效期（来自 entry 行，跨卡一致）。
    pub validity: ValidityWindow,
    /// 该内容首次进入共享层时的 hot-state version（可观测性字段）。
    pub first_seen_version: u64,
}

impl SharedRuleSetEntry {
    /// 纵深防御：hash 命中后逐字段核对实际内容（sha256 碰撞实际不可达）。
    fn matches_grant(&self, grant: &CanonicalGrant) -> bool {
        self.source_id == grant.provenance.source_id
            && self.source_entry == grant.provenance.source_entry
            && self.resource == grant.resource
            && self.action == grant.action
            && self.effect == grant.effect
            && self.validity == grant.validity
    }
}

/// RULE_SET 来源 grant 的 per-grant 记录：身份生命周期 + 卡归属 + 共享层引用。
///
/// 冻结的 [`GrantDelta`] 契约按 GrantId 个体携带独立 revision/state/CAS 语义
/// （同卡不同 entry 可独立墓碑、跨卡同 entry 各有 revision 链），因此绑定层
/// 之上必须保留 per-grant 记录层（设计文档 §3.3）。tenant/domain 不入记录：
/// 构造期已验证 `grant.tenant == HotState.tenant`，组装取状态租户。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSetGrantRecord {
    pub revision: GrantRevision,
    pub state: GrantState,
    pub binding_layer: BindingLayer,
    /// 授权载体卡。
    pub card_id: i64,
    /// 卡所属认证用户。
    pub user_id: i64,
    /// 承载绑定的稳定主键（`provenance.binding_id`；合同强制存在，构造期
    /// None 即 fail-closed）。
    pub binding_id: String,
    pub operation_id: String,
    pub event_id: Option<String>,
    pub actor_user_id: Option<i64>,
    /// → 共享层条目（内容事实）。
    pub entry: Arc<SharedRuleSetEntry>,
}

impl RuleSetGrantRecord {
    /// 按状态租户组装完整 canonical grant。
    ///
    /// 组装是纯函数：对同一 (record, entry, tenant, grant_id) 产出与构造输入
    /// 逐字节相等的 grant（parity 测试锚定，设计文档 §5.2 评估等价性定理）。
    fn to_grant(&self, tenant: &TenantScope, grant_id: GrantId) -> CanonicalGrant {
        CanonicalGrant {
            grant_id,
            revision: self.revision,
            state: self.state,
            source_kind: GrantSourceKind::RuleSet,
            binding_layer: self.binding_layer,
            tenant: tenant.clone(),
            card_id: self.card_id,
            user_id: self.user_id,
            resource: self.entry.resource.clone(),
            action: self.entry.action.clone(),
            effect: self.entry.effect,
            validity: self.entry.validity,
            provenance: GrantProvenance {
                source_id: self.entry.source_id.clone(),
                source_entry: self.entry.source_entry.clone(),
                binding_id: Some(self.binding_id.clone()),
                delegation_id: None,
                operation_id: self.operation_id.clone(),
                event_id: self.event_id.clone(),
                actor_user_id: self.actor_user_id,
            },
        }
    }

    /// 记录的精确投影键（无需组装完整 grant）。
    fn projection_key(&self) -> CompilerResult<ProjectionKey> {
        ProjectionKey::new(
            self.card_id,
            self.user_id,
            self.entry.resource.clone(),
            self.entry.action.clone(),
        )
    }
}

#[derive(Serialize)]
struct SharedEntryHashInput<'a> {
    /// 领域标签，防跨域 hash 复用。
    kind: &'static str,
    source_id: &'a str,
    source_entry: Option<&'a str>,
    resource: &'a str,
    action: &'a str,
    effect: GrantEffect,
    validity: &'a ValidityWindow,
}

/// 共享层内容身份：内容七元组的 canonical JSON sha256。
fn shared_entry_content_hash(grant: &CanonicalGrant) -> CompilerResult<String> {
    let input = SharedEntryHashInput {
        kind: "rule-set-entry",
        source_id: grant.provenance.source_id.as_str(),
        source_entry: grant.provenance.source_entry.as_deref(),
        resource: grant.resource.as_str(),
        action: grant.action.as_str(),
        effect: grant.effect,
        validity: &grant.validity,
    };
    let encoded = serde_json::to_string(&input)
        .map_err(|error| CompilerError::CanonicalSerialization(error.to_string()))?;
    Ok(sha256_hex(encoded.as_bytes()))
}

/// 共享层 intern：命中复用既有 `Arc`（含碰撞核对），未命中新建条目。
fn intern_shared_entry(
    shared_entries: &mut im::HashMap<String, Arc<SharedRuleSetEntry>>,
    grant: &CanonicalGrant,
    version: u64,
) -> CompilerResult<Arc<SharedRuleSetEntry>> {
    let content_hash = shared_entry_content_hash(grant)?;
    if let Some(existing) = shared_entries.get(&content_hash) {
        if existing.matches_grant(grant) {
            return Ok(existing.clone());
        }
    }
    let entry = Arc::new(SharedRuleSetEntry {
        content_hash: content_hash.clone(),
        source_id: grant.provenance.source_id.clone(),
        source_entry: grant.provenance.source_entry.clone(),
        resource: grant.resource.clone(),
        action: grant.action.clone(),
        effect: grant.effect,
        validity: grant.validity,
        first_seen_version: version,
    });
    shared_entries.insert(content_hash, entry.clone());
    Ok(entry)
}

/// 绑定层单卡计数面：card_id → (rule_set source_id → 引用记录数)。
type BindingCounts = im::OrdMap<String, u64>;

/// 绑定计数 +1（记录新增/复活落层时调用）。
fn binding_increment(
    bindings: &mut im::HashMap<i64, BindingCounts>,
    card_id: i64,
    source_id: &str,
) {
    let updated = {
        let counts = bindings.get(&card_id).cloned().unwrap_or_default();
        let next = counts
            .get(source_id)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        counts.update(source_id.to_owned(), next)
    };
    bindings.insert(card_id, updated);
}

/// 绑定计数 −1（记录跨层迁移/被替换时调用；墓碑不调用——墓碑保留 ledger
/// 记录即保留绑定事实）。计数归零移除键，空卡移除行，保持绑定层最小化。
fn binding_decrement(
    bindings: &mut im::HashMap<i64, BindingCounts>,
    card_id: i64,
    source_id: &str,
) {
    let Some(counts) = bindings.get(&card_id).cloned() else {
        return;
    };
    let Some(current) = counts.get(source_id).copied() else {
        return;
    };
    if current <= 1 {
        let mut counts = counts;
        counts.remove(source_id);
        if counts.is_empty() {
            bindings.remove(&card_id);
        } else {
            bindings.insert(card_id, counts);
        }
    } else {
        bindings.insert(card_id, counts.update(source_id.to_owned(), current - 1));
    }
}

/// Factored ledger 的可变装配视图（构造/增量 delta 共用）。
///
/// 四个字段均为 `im` 持久化结构：从 base 派生时整体 O(1) 结构共享 clone，
/// 单键变更为 COW 路径复制，旧快照不可变。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct FactoredLedger {
    shared_entries: im::HashMap<String, Arc<SharedRuleSetEntry>>,
    bindings: im::HashMap<i64, BindingCounts>,
    ruleset_records: im::HashMap<GrantId, RuleSetGrantRecord>,
    private_grants: im::HashMap<GrantId, CanonicalGrant>,
}

impl FactoredLedger {
    /// O(1) 结构共享派生（增量 delta 应用的起点）。
    fn derive_from(state: &HotState) -> Self {
        Self {
            shared_entries: state.shared_entries.clone(),
            bindings: state.bindings.clone(),
            ruleset_records: state.ruleset_records.clone(),
            private_grants: state.private_grants.clone(),
        }
    }
}

/// 跨层 grant 视图：定位既有记录后统一读侧（CAS/受影响面/导出）。
#[derive(Debug, Clone, Copy)]
enum LedgerGrantView<'a> {
    Private(&'a CanonicalGrant),
    RuleSet(&'a RuleSetGrantRecord),
}

impl LedgerGrantView<'_> {
    fn source_kind(&self) -> GrantSourceKind {
        match self {
            Self::Private(grant) => grant.source_kind,
            Self::RuleSet(_) => GrantSourceKind::RuleSet,
        }
    }

    fn binding_layer(&self) -> BindingLayer {
        match self {
            Self::Private(grant) => grant.binding_layer,
            Self::RuleSet(record) => record.binding_layer,
        }
    }

    fn state(&self) -> GrantState {
        match self {
            Self::Private(grant) => grant.state,
            Self::RuleSet(record) => record.state,
        }
    }

    fn revision(&self) -> GrantRevision {
        match self {
            Self::Private(grant) => grant.revision,
            Self::RuleSet(record) => record.revision,
        }
    }

    fn projection_key(&self) -> CompilerResult<ProjectionKey> {
        match self {
            Self::Private(grant) => ProjectionKey::from_grant(grant),
            Self::RuleSet(record) => record.projection_key(),
        }
    }

    fn wildcard_alias_reason(&self) -> Option<FullRebuildReason> {
        match self {
            Self::Private(grant) => wildcard_or_alias_reason(&grant.resource, &grant.action),
            Self::RuleSet(record) => {
                wildcard_or_alias_reason(&record.entry.resource, &record.entry.action)
            }
        }
    }
}

/// 跨层定位既有 grant 记录。
fn ledger_view<'a>(ledger: &'a FactoredLedger, grant_id: &GrantId) -> Option<LedgerGrantView<'a>> {
    if let Some(record) = ledger.ruleset_records.get(grant_id) {
        return Some(LedgerGrantView::RuleSet(record));
    }
    ledger
        .private_grants
        .get(grant_id)
        .map(LedgerGrantView::Private)
}

/// 跨层定位 HotState 上的既有 grant 记录（只读视图）。
fn state_grant_view(state: &HotState, grant_id: GrantId) -> Option<LedgerGrantView<'_>> {
    if let Some(record) = state.ruleset_records.get(&grant_id) {
        return Some(LedgerGrantView::RuleSet(record));
    }
    state
        .private_grants
        .get(&grant_id)
        .map(LedgerGrantView::Private)
}

/// 按 source_kind 落层插入一条 grant（构造与载荷替换共用）。
///
/// RULE_SET 走共享层 intern + 记录层 + 绑定层；其余进卡私有层。`GrantId`
/// 全层唯一，跨层重复即 [`CompilerError::DuplicateGrant`]。RULE_SET 缺
/// `binding_id` 或携带 `delegation_id` 均为合同违规，构造期 fail-closed。
fn ledger_insert_grant(
    ledger: &mut FactoredLedger,
    grant: CanonicalGrant,
    version: u64,
) -> CompilerResult<()> {
    if ledger.private_grants.contains_key(&grant.grant_id)
        || ledger.ruleset_records.contains_key(&grant.grant_id)
    {
        return Err(CompilerError::DuplicateGrant {
            grant_id: grant.grant_id,
        });
    }
    if grant.source_kind == GrantSourceKind::RuleSet {
        let Some(binding_id) = grant.provenance.binding_id.clone() else {
            return Err(CompilerError::InvalidState(
                "RULE_SET grant must carry provenance.binding_id".to_owned(),
            ));
        };
        if grant.provenance.delegation_id.is_some() {
            return Err(CompilerError::InvalidState(
                "RULE_SET grant must not carry provenance.delegation_id".to_owned(),
            ));
        }
        let entry = intern_shared_entry(&mut ledger.shared_entries, &grant, version)?;
        let card_id = grant.card_id;
        let source_id = grant.provenance.source_id.clone();
        ledger.ruleset_records.insert(
            grant.grant_id,
            RuleSetGrantRecord {
                revision: grant.revision,
                state: grant.state,
                binding_layer: grant.binding_layer,
                card_id,
                user_id: grant.user_id,
                binding_id,
                operation_id: grant.provenance.operation_id,
                event_id: grant.provenance.event_id,
                actor_user_id: grant.provenance.actor_user_id,
                entry,
            },
        );
        binding_increment(&mut ledger.bindings, card_id, &source_id);
    } else {
        ledger.private_grants.insert(grant.grant_id, grant);
    }
    Ok(())
}

/// 按载荷落层替换一条 grant（Add 新增 / 复活 / Update 共用）。
///
/// 先撤销旧记录的绑定贡献并移除旧层残留（跨层复活/迁移），再插入新层——
/// 任何时刻 `GrantId` 至多存在于一层。全量 oracle 路径允许载荷 kind 与既有
/// 记录不同（增量路径的 kind 漂移已被 `BindingImpact` 拦截）；租户一致性由
/// 调用方在 delta 边界校验。
fn ledger_replace_with_payload(
    ledger: &mut FactoredLedger,
    grant: CanonicalGrant,
    version: u64,
) -> CompilerResult<()> {
    if let Some(old) = ledger.ruleset_records.get(&grant.grant_id).cloned() {
        binding_decrement(&mut ledger.bindings, old.card_id, &old.entry.source_id);
        ledger.ruleset_records.remove(&grant.grant_id);
    }
    ledger.private_grants.remove(&grant.grant_id);
    ledger_insert_grant(ledger, grant, version)
}

/// One exact key in the mutable hot-state ledger.
///
/// Tenant identity is held by [`HotState`], while card and user identity remain part of
/// the key. Resource and action are already canonicalized by [`CanonicalGrant`]. Keeping
/// them in an ordered value type makes source order and hash order independent of input
/// array order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectionKey {
    /// Physical card carrying the authorization contribution.
    pub card_id: i64,
    /// Authenticated user owning the card.
    pub user_id: i64,
    /// Canonical resource or resource key.
    pub resource: String,
    /// Canonical action code.
    pub action: String,
}

/// Alias for callers that use the phrase “exact grant key”.
pub type ExactGrantKey = ProjectionKey;

/// Alias for callers that use the phrase “affected key”.
pub type AffectedKey = ProjectionKey;

impl ProjectionKey {
    /// Build the key from a validated canonical grant.
    pub fn from_grant(grant: &CanonicalGrant) -> CompilerResult<Self> {
        let canonical = grant.canonicalized()?;
        Self::new(
            canonical.card_id,
            canonical.user_id,
            canonical.resource,
            canonical.action,
        )
    }

    /// Build a key from its stable physical and semantic components.
    pub fn new(
        card_id: i64,
        user_id: i64,
        resource: impl Into<String>,
        action: impl Into<String>,
    ) -> CompilerResult<Self> {
        if card_id <= 0 {
            return Err(CompilerError::Contract(GrantContractError::NonPositiveId {
                field: "card_id",
                value: card_id,
            }));
        }
        if user_id <= 0 {
            return Err(CompilerError::Contract(GrantContractError::NonPositiveId {
                field: "user_id",
                value: user_id,
            }));
        }
        let resource = normalize_key_identifier(resource.into(), "resource")?;
        let action = normalize_key_identifier(action.into(), "action")?;
        Ok(Self {
            card_id,
            user_id,
            resource,
            action,
        })
    }

    /// Return a canonical text form used only as a hash/segment identity input.
    pub fn canonical_input(&self) -> CompilerResult<String> {
        serde_json::to_string(self)
            .map_err(|error| CompilerError::CanonicalSerialization(error.to_string()))
    }

    /// Stable human-readable key form, useful in impact-plan logs and tests.
    pub fn as_string(&self) -> String {
        format!(
            "card={};user={};resource={};action={}",
            self.card_id, self.user_id, self.resource, self.action
        )
    }
}

/// Immutable content for one exact-key segment.
///
/// `Arc<SegmentContent>` is retained by unchanged candidate segments. The segment identity
/// and content hash remain stable even though a new manifest generation receives a fresh
/// generation-bearing [`SegmentReference`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SegmentContent {
    /// Exact key covered by this segment.
    pub key: ProjectionKey,
    /// Canonically ordered active ALLOW contributions for the key.
    pub grants: Vec<CanonicalGrant>,
    /// Stable digest of compiler version, key, and ordered contribution content.
    pub content_hash: String,
    /// Stable segment identity derived from the exact key, not from content or generation.
    pub segment_id: String,
}

impl SegmentContent {
    /// Number of active contributions in the segment.
    pub fn grant_count(&self) -> u64 {
        self.grants.len() as u64
    }
}

/// A generation-independent impact entry comparing one segment before and after a candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SegmentImpact {
    /// Exact key whose segment was considered.
    pub key: ProjectionKey,
    /// Stable segment identity.
    pub segment_id: String,
    /// Previous content digest, if a segment existed in the base.
    pub before_content_hash: Option<String>,
    /// Candidate content digest, if a segment exists after compilation.
    pub after_content_hash: Option<String>,
    /// Whether the segment content actually differs.
    pub content_changed: bool,
}

/// Deterministic exact-key/segment plan produced before a candidate is exposed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImpactPlan {
    /// Sorted exact keys known to be affected by this batch.
    pub affected_keys: Vec<ProjectionKey>,
    /// Sorted segment impact details for those keys.
    pub affected_segments: Vec<SegmentImpact>,
    /// True when a local candidate is not safe and a full oracle is required.
    pub full_rebuild: bool,
    /// Explicit fallback reason, when `full_rebuild` is true.
    pub reason: Option<FullRebuildReason>,
}

impl ImpactPlan {
    /// Return stable segment identities in key order.
    pub fn affected_segment_ids(&self) -> Vec<&str> {
        self.affected_segments
            .iter()
            .map(|segment| segment.segment_id.as_str())
            .collect()
    }
}

/// Mutable, versioned in-memory hot state used as the compiler base and candidate.
///
/// The grant ledger retains the latest record, including `REVOKED`/`REMOVED` tombstone
/// state, so a later stale or duplicate delta is a conflict rather than an unknown or
/// silent no-op. Only `ACTIVE` records contribute to exact-key segments.
///
/// v4 结构（O(1) 单键变更，2026-08）：全部集合字段为持久化数据结构——
/// `clone` 是 O(1) 结构共享，单键查/增/删 O(1) 平均（HAMT）或 O(log n)
/// （OrdMap 绑定计数）。HAMT 迭代无序：需要稳定序的消费路径显式排序——
/// 导出按 `GrantId` 排序（`all_grants`/`active_grants`）、段 ordinal 分配按
/// [`ProjectionKey`] 排序（`segment_keys`/`segment_references`），保证跨进程/
/// 跨构建的确定序与 HAMT 内部实现解耦。
///
/// factored 布局（2026-08）：ledger 从 per-card grant 列表重构为共享层
/// （`shared_entries`）+ 绑定层（`bindings`）+ 记录层（`ruleset_records`）+
/// 卡私有层（`private_grants`）；规则集条目授权内容跨卡只存一份。编译输入
/// 输出、段表示与 hash 语义不变——设计见
/// `Docs/架构/Rust架构设计/FactoredHotState设计_V1.0.md`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotState {
    /// Physical tenant boundary for every ledger record.
    pub tenant: TenantScope,
    /// Durable-style projection generation represented by this pure candidate.
    pub version: u64,
    /// 共享层：RULE_SET 条目授权内容（内容寻址，跨卡只存一份）。
    ///
    /// 键 = [`SharedRuleSetEntry::content_hash`]；记录层经 `Arc` 引用条目。
    /// 派生状态中不再被记录引用的陈旧条目会残留，由下一次全量重建
    /// （ledger 重放）剪枝。
    pub shared_entries: im::HashMap<String, Arc<SharedRuleSetEntry>>,
    /// 绑定层：card_id → (rule_set source_id → 引用记录数，含墓碑)。
    ///
    /// 任务书 `HashMap<CardId, OrdSet<RuleSetId>>` 的引用计数等价结构；
    /// 冻结 per-grant delta 契约下编译受影响面不消费本层（跨卡传播不存在），
    /// 它是 rule-set 级 delta（受影响面 = 绑定该规则集的卡）的结构基础。
    pub bindings: im::HashMap<i64, BindingCounts>,
    /// 记录层：RULE_SET grant 的 per-grant 生命周期与归属（revision/state/CAS
    /// 语义所需的完整记录面），内容经 `entry` 引用共享层。
    pub ruleset_records: im::HashMap<GrantId, RuleSetGrantRecord>,
    /// 卡私有层：DIRECT/APPROVAL/DELEGATION/SYSTEM 来源 grant（完整归属）。
    pub private_grants: im::HashMap<GrantId, CanonicalGrant>,
    /// Exact-key segments keyed by [`ProjectionKey`]. Arc identity is reused for
    /// unchanged segments.
    ///
    /// HAMT：O(1) avg 单键变更 + O(1) 结构共享 clone（增量候选继承 base 段只花
    /// 一次 O(1) clone）。迭代无序——段 ordinal/发布 digest 的确定序由消费方
    /// 显式按 [`ProjectionKey`] 排序（`ProjectionKey` 实现 `Ord`），排序成本
    /// O(S log S) 只发生在发布事务/对账等低频路径。
    pub segments: im::HashMap<ProjectionKey, Arc<SegmentContent>>,
    /// Semantic digest binding compiler version, tenant, version, and dependency hash.
    pub semantic_hash: String,
    /// Digest of the canonical dependency vector.
    pub dependency_hash: String,
    /// Semantic compiler version which produced this state.
    pub compiler_version: String,
    dependency_vector: DependencyVector,
}

/// Alias for callers that prefer the fully qualified domain name.
pub type AuthorizationHotState = HotState;

impl HotState {
    /// Construct a canonical state using the Phase 2 compiler version.
    pub fn from_grants<I>(
        tenant: TenantScope,
        version: u64,
        grants: I,
        dependency_vector: DependencyVector,
    ) -> CompilerResult<Self>
    where
        I: IntoIterator<Item = CanonicalGrant>,
    {
        Self::from_grants_with_compiler(
            tenant,
            version,
            grants,
            dependency_vector,
            COMPILER_VERSION,
        )
    }

    /// Construct a canonical state with an explicit compiler version for compatibility
    /// checks and full-rebuild tests.
    pub fn from_grants_with_compiler<I>(
        tenant: TenantScope,
        version: u64,
        grants: I,
        dependency_vector: DependencyVector,
        compiler_version: impl Into<String>,
    ) -> CompilerResult<Self>
    where
        I: IntoIterator<Item = CanonicalGrant>,
    {
        tenant.validate()?;
        if version == 0 {
            return Err(CompilerError::InvalidState(
                "hot-state version must be greater than zero".to_owned(),
            ));
        }
        let mut ledger = FactoredLedger::default();
        for raw_grant in grants {
            let grant = raw_grant.canonicalized()?;
            if grant.tenant != tenant {
                return Err(CompilerError::InvalidState(
                    "grant tenant does not match hot-state tenant".to_owned(),
                ));
            }
            ledger_insert_grant(&mut ledger, grant, version)?;
        }
        let dependencies = dependency_vector.canonicalized()?;
        Self::materialize(
            tenant,
            version,
            ledger,
            dependencies,
            compiler_version.into(),
        )
    }

    /// Construct an empty versioned state.
    pub fn empty(
        tenant: TenantScope,
        version: u64,
        dependency_vector: DependencyVector,
    ) -> CompilerResult<Self> {
        Self::from_grants(tenant, version, std::iter::empty(), dependency_vector)
    }

    /// Return the canonical dependency vector used to build this state.
    pub fn dependency_vector(&self) -> &DependencyVector {
        &self.dependency_vector
    }

    /// Return the latest ledger record for a stable grant identity.
    ///
    /// factored 布局：私有层直返克隆；记录层按状态租户组装（纯函数，与构造
    /// 输入逐字节相等，见设计文档 §5.2）。
    pub fn grant(&self, grant_id: GrantId) -> Option<CanonicalGrant> {
        if let Some(record) = self.ruleset_records.get(&grant_id) {
            return Some(record.to_grant(&self.tenant, grant_id));
        }
        self.private_grants.get(&grant_id).cloned()
    }

    /// Return all ledger records in stable GrantId order, including tombstones.
    ///
    /// factored 布局：私有层与记录层合并后按 `GrantId` 排序（保持确定序契约；
    /// HAMT 迭代无序）。组装为 owned 值——记录层的 grant 按需组装，与构造输入
    /// 逐字节相等。
    pub fn all_grants(&self) -> Vec<CanonicalGrant> {
        let mut records: Vec<CanonicalGrant> = self.private_grants.values().cloned().collect();
        records.extend(
            self.ruleset_records
                .iter()
                .map(|(grant_id, record)| record.to_grant(&self.tenant, *grant_id)),
        );
        records.sort_by_key(|left| left.grant_id);
        records
    }

    /// Return active ALLOW contributions in stable GrantId order.
    pub fn active_grants(&self) -> Vec<CanonicalGrant> {
        let mut records: Vec<CanonicalGrant> = self
            .private_grants
            .values()
            .filter(|grant| grant.state == GrantState::Active)
            .cloned()
            .collect();
        records.extend(
            self.ruleset_records
                .iter()
                .filter(|(_, record)| record.state == GrantState::Active)
                .map(|(grant_id, record)| record.to_grant(&self.tenant, *grant_id)),
        );
        records.sort_by_key(|left| left.grant_id);
        records
    }

    /// 绑定层查询：该卡在 ledger 事实中引用的规则集 `source_id` 及其记录数
    /// （含墓碑；墓碑保留在 ledger 即保留绑定事实）。升序返回（OrdMap 序）。
    pub fn card_rule_set_sources(&self, card_id: i64) -> Vec<(&str, u64)> {
        self.bindings
            .get(&card_id)
            .map(|counts| {
                counts
                    .iter()
                    .map(|(source_id, count)| (source_id.as_str(), *count))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// 共享层条目数（可观测性：收敛态下 = 不同 (rule_set, entry) 内容数）。
    pub fn shared_entry_count(&self) -> usize {
        self.shared_entries.len()
    }

    /// Return an unchanged or candidate segment's immutable content handle.
    pub fn segment_content(&self, key: &ProjectionKey) -> Option<Arc<SegmentContent>> {
        self.segments.get(key).cloned()
    }

    /// Return sorted exact keys with active contributions.
    ///
    /// HAMT 迭代无序，显式按 `ProjectionKey` 排序（`ProjectionKey: Ord`）。
    pub fn segment_keys(&self) -> Vec<&ProjectionKey> {
        let mut keys: Vec<&ProjectionKey> = self.segments.keys().collect();
        keys.sort_unstable();
        keys
    }

    /// Return generation-bearing references in deterministic ordinal order.
    ///
    /// Ordinal 由显式 key 排序后的位置决定（与 HAMT 迭代序解耦），发布事务
    /// 的 stage plan / manifest digest 必须与同一确定序对齐。
    pub fn segment_references(&self) -> Vec<SegmentReference> {
        let mut entries: Vec<(&ProjectionKey, &Arc<SegmentContent>)> =
            self.segments.iter().collect();
        entries.sort_by(|left, right| left.0.cmp(right.0));
        entries
            .into_iter()
            .enumerate()
            .map(|(ordinal, (_, segment))| SegmentReference {
                segment_id: segment.segment_id.clone(),
                ordinal: ordinal as u64,
                generation: self.version,
                grant_count: segment.grant_count(),
                content_hash: segment.content_hash.clone(),
            })
            .collect()
    }

    /// Return the segment reference for one exact key, if present.
    pub fn segment_reference(&self, key: &ProjectionKey) -> Option<SegmentReference> {
        let mut entries: Vec<(&ProjectionKey, &Arc<SegmentContent>)> =
            self.segments.iter().collect();
        entries.sort_by(|left, right| left.0.cmp(right.0));
        entries
            .into_iter()
            .enumerate()
            .find_map(|(ordinal, (candidate_key, segment))| {
                (candidate_key == key).then(|| SegmentReference {
                    segment_id: segment.segment_id.clone(),
                    ordinal: ordinal as u64,
                    generation: self.version,
                    grant_count: segment.grant_count(),
                    content_hash: segment.content_hash.clone(),
                })
            })
    }

    fn materialize(
        tenant: TenantScope,
        version: u64,
        ledger: FactoredLedger,
        dependency_vector: DependencyVector,
        compiler_version: String,
    ) -> CompilerResult<Self> {
        if version == 0 {
            return Err(CompilerError::InvalidState(
                "hot-state version must be greater than zero".to_owned(),
            ));
        }
        if compiler_version.trim().is_empty() {
            return Err(CompilerError::InvalidState(
                "compiler version must not be empty".to_owned(),
            ));
        }
        let dependency_hash = dependency_vector.canonical_hash()?;
        let segments = build_segments(&tenant, &ledger, &compiler_version)?;
        let semantic_hash = semantic_hash(&tenant, version, &dependency_hash, &compiler_version)?;
        Ok(Self {
            tenant,
            version,
            shared_entries: ledger.shared_entries,
            bindings: ledger.bindings,
            ruleset_records: ledger.ruleset_records,
            private_grants: ledger.private_grants,
            segments,
            semantic_hash,
            dependency_hash,
            compiler_version,
            dependency_vector,
        })
    }
}

/// Request envelope for a version-fenced incremental compilation attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileRequest {
    /// Version the caller read before producing the deltas.
    pub base_version: u64,
    /// Semantic hash the caller read before producing the deltas.
    pub base_semantic_hash: String,
    /// Candidate version. The kernel requires `base_version + 1`.
    pub target_version: u64,
    /// Dependency vector observed with the source mutation.
    pub dependency_vector: DependencyVector,
    /// Optional explicit dependency hash read by the caller.
    pub expected_dependency_hash: Option<String>,
    /// Stable-ID deltas to apply.
    pub deltas: Vec<GrantDelta>,
}

/// Alias for callers that name the request after its incremental mode.
pub type IncrementalCompileRequest = CompileRequest;

impl CompileRequest {
    /// Construct a request from an explicit base hash.
    pub fn new(
        base_version: u64,
        base_semantic_hash: impl Into<String>,
        target_version: u64,
        dependency_vector: DependencyVector,
        deltas: Vec<GrantDelta>,
    ) -> Self {
        Self {
            base_version,
            base_semantic_hash: base_semantic_hash.into(),
            target_version,
            dependency_vector,
            expected_dependency_hash: None,
            deltas,
        }
    }

    /// Construct a request whose base version and hashes are copied from a state.
    pub fn for_base(
        base: &HotState,
        target_version: u64,
        dependency_vector: DependencyVector,
        deltas: Vec<GrantDelta>,
    ) -> Self {
        Self {
            base_version: base.version,
            base_semantic_hash: base.semantic_hash.clone(),
            target_version,
            dependency_vector,
            expected_dependency_hash: Some(base.dependency_hash.clone()),
            deltas,
        }
    }

    /// Add or replace the expected dependency hash check.
    pub fn with_expected_dependency_hash(mut self, dependency_hash: impl Into<String>) -> Self {
        self.expected_dependency_hash = Some(dependency_hash.into());
        self
    }

    /// Alias for the base semantic hash for concise call sites.
    pub fn base_hash(&self) -> &str {
        &self.base_semantic_hash
    }
}

/// Successful candidate and its exact-key impact evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledProjection {
    /// Candidate hot state. It is not durable until a future writer commits it.
    pub state: HotState,
    /// Exact keys and segments considered by the compiler.
    pub plan: ImpactPlan,
    /// Incremental or full-oracle mode which produced the candidate.
    pub mode: ProjectionCompileMode,
    /// Version read as the candidate base.
    pub base_version: u64,
    /// Version represented by `state`.
    pub target_version: u64,
    /// Number of source deltas applied to the mutable ledger.
    pub applied_delta_count: usize,
}

impl CompiledProjection {
    /// Borrow the candidate state.
    pub fn state(&self) -> &HotState {
        &self.state
    }

    /// Consume the wrapper and return the candidate state.
    pub fn into_state(self) -> HotState {
        self.state
    }
}

/// Pure compiler result with explicit candidate, conflict, and fallback branches.
///
/// `large_enum_variant`：`Applied` 携带完整候选（CompiledProjection/HotState），
/// factored 布局使其超出与 fallback 变体的尺寸差阈值。变体布局是冻结消费方
/// （projector/测试）的 match 面，Box 化属破坏性 API 变更；枚举本身只在编译
/// 结果传递路径短期存活，不构成复制热点，故显式豁免。
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileOutcome {
    /// Incremental (or explicit full-oracle) compilation produced a candidate.
    Applied(CompiledProjection),
    /// The caller must run the deterministic full oracle before exposing a candidate.
    FullRebuildRequired(FullRebuildRequired),
    /// The request was stale, duplicated, or revision-conflicting.
    Conflict(CompilerConflict),
}

/// Full-rebuild branch with no hidden mutation or implicit fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullRebuildRequired {
    /// Conservative reason for refusing local incremental compilation.
    pub reason: FullRebuildReason,
    /// Known exact-key impact evidence. Unknown wildcard impact is represented by the reason.
    pub plan: ImpactPlan,
}

impl CompileOutcome {
    /// Whether this outcome contains a candidate state.
    pub fn is_applied(&self) -> bool {
        matches!(self, Self::Applied(_))
    }

    /// Borrow an applied candidate, if one exists.
    pub fn applied(&self) -> Option<&CompiledProjection> {
        match self {
            Self::Applied(candidate) => Some(candidate),
            Self::FullRebuildRequired(_) | Self::Conflict(_) => None,
        }
    }
}

/// Configurable pure incremental compiler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCompiler {
    compiler_version: String,
    max_incremental_deltas: usize,
}

impl Default for AuthorizationCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthorizationCompiler {
    /// Construct the Phase 2 compiler with the documented threshold.
    pub fn new() -> Self {
        Self {
            compiler_version: COMPILER_VERSION.to_owned(),
            max_incremental_deltas: MAX_INCREMENTAL_DELTAS,
        }
    }

    /// Construct a compiler with an explicit semantic version for tests/rollouts.
    pub fn with_compiler_version(compiler_version: impl Into<String>) -> CompilerResult<Self> {
        let compiler_version = compiler_version.into();
        if compiler_version.trim().is_empty() {
            return Err(CompilerError::InvalidState(
                "compiler version must not be empty".to_owned(),
            ));
        }
        Ok(Self {
            compiler_version,
            max_incremental_deltas: MAX_INCREMENTAL_DELTAS,
        })
    }

    /// Set the local incremental threshold without changing semantic versioning.
    pub fn with_max_incremental_deltas(mut self, maximum: usize) -> CompilerResult<Self> {
        if maximum == 0 {
            return Err(CompilerError::InvalidState(
                "incremental delta threshold must be greater than zero".to_owned(),
            ));
        }
        self.max_incremental_deltas = maximum;
        Ok(self)
    }

    /// Return the semantic compiler version.
    pub fn compiler_version(&self) -> &str {
        &self.compiler_version
    }

    /// Compile a version-fenced incremental request without I/O or durable side effects.
    pub fn compile(
        &self,
        base: &HotState,
        request: &CompileRequest,
    ) -> CompilerResult<CompileOutcome> {
        if let Some(conflict) = request_base_conflict(base, request) {
            return Ok(CompileOutcome::Conflict(conflict));
        }
        if base.compiler_version != self.compiler_version {
            let known_keys = known_affected_keys(base, &request.deltas)?;
            return Ok(full_rebuild_outcome(
                base,
                &request.deltas,
                known_keys,
                FullRebuildReason::CompilerVersionMismatch,
            ));
        }

        let dependencies = request.dependency_vector.canonicalized()?;
        let dependency_hash = dependencies.canonical_hash()?;
        if let Some(expected) = &request.expected_dependency_hash {
            if expected != &base.dependency_hash {
                return Ok(CompileOutcome::Conflict(
                    CompilerConflict::BaseDependencyHashMismatch {
                        expected: expected.clone(),
                        actual: base.dependency_hash.clone(),
                    },
                ));
            }
        }
        if dependency_hash != base.dependency_hash {
            let known_keys = known_affected_keys(base, &request.deltas)?;
            return Ok(full_rebuild_outcome(
                base,
                &request.deltas,
                known_keys,
                FullRebuildReason::DependencyChanged,
            ));
        }
        if request.deltas.is_empty() {
            return Ok(CompileOutcome::Conflict(CompilerConflict::EmptyDeltaBatch));
        }

        let canonical_deltas = canonical_deltas(&request.deltas)?;
        if canonical_deltas.len() > self.max_incremental_deltas {
            let known_keys = known_affected_keys(base, &canonical_deltas)?;
            return Ok(full_rebuild_outcome(
                base,
                &canonical_deltas,
                known_keys,
                FullRebuildReason::DeltaTooLarge,
            ));
        }
        if let Some(conflict) = duplicate_delta_conflict(&canonical_deltas)? {
            return Ok(CompileOutcome::Conflict(conflict));
        }

        let known_keys = known_affected_keys(base, &canonical_deltas)?;
        if let Some(reason) = self.full_impact_reason(base, &canonical_deltas)? {
            return Ok(full_rebuild_outcome(
                base,
                &canonical_deltas,
                known_keys,
                reason,
            ));
        }

        let records = match apply_deltas_to_ledger(base, &canonical_deltas, request.target_version)?
        {
            Ok(records) => records,
            Err(conflict) => return Ok(CompileOutcome::Conflict(conflict)),
        };
        let candidate = materialize_incremental_candidate(
            base,
            request.target_version,
            records,
            dependencies,
            self.compiler_version.clone(),
            &canonical_deltas,
            &known_keys,
        )?;
        let plan = impact_plan(base, &candidate, known_keys, false, None);
        Ok(CompileOutcome::Applied(CompiledProjection {
            state: candidate,
            plan,
            mode: ProjectionCompileMode::Incremental,
            base_version: request.base_version,
            target_version: request.target_version,
            applied_delta_count: canonical_deltas.len(),
        }))
    }

    /// Convenience API for a generic `base_version -> base_version + 1` request.
    pub fn compile_incremental(
        &self,
        base: &HotState,
        target_version: u64,
        dependency_vector: DependencyVector,
        deltas: Vec<GrantDelta>,
    ) -> CompilerResult<CompileOutcome> {
        let request = CompileRequest::for_base(base, target_version, dependency_vector, deltas);
        self.compile(base, &request)
    }

    /// Run the deterministic full compiler oracle explicitly.
    ///
    /// This method applies the same stable-ID mutation rules but materializes every segment;
    /// it is intended for parity checks and a future worker fallback, not production wiring.
    pub fn full_rebuild(
        &self,
        base: &HotState,
        target_version: u64,
        dependency_vector: DependencyVector,
        deltas: Vec<GrantDelta>,
    ) -> CompilerResult<CompileOutcome> {
        FullCompilerOracle::with_compiler(self.compiler_version.clone()).compile(
            base,
            &CompileRequest::for_base(base, target_version, dependency_vector, deltas),
        )
    }

    fn full_impact_reason(
        &self,
        base: &HotState,
        deltas: &[GrantDelta],
    ) -> CompilerResult<Option<FullRebuildReason>> {
        // 组合独立增量（每个 (key, action) 组合为独立更新单元）：每个组合的段
        // 只由落在该 key 上的 grant 构成（build_segments 按 grant 自身 canonical
        // key 分组），因此 base 中历史授权的形态（通配/别名/窗口）不影响本批
        // delta 的增量资格——delta 只触碰 known_affected_keys 列出的自身 key 段。
        // 全量触发只由 delta 自身形态决定（见 grant_impact_reason）；读侧类型级
        // 匹配是对最新发布 evidence 的读时遍历，与编译期发布方式无关。
        // factored 布局：既有记录经跨层视图读取（记录层 wildcard/别名检查走
        // 共享条目内容，语义与 per-card 存储逐字段一致）。
        for delta in deltas {
            let reason = match delta {
                GrantDelta::Add { grant } => grant_impact_reason(grant, None),
                GrantDelta::Update { grant, .. } => {
                    let old = state_grant_view(base, grant.grant_id);
                    grant_impact_reason(grant, old)
                }
                GrantDelta::Remove { grant_id, .. } | GrantDelta::Revoke { grant_id, .. } => {
                    state_grant_view(base, *grant_id).and_then(|view| view.wildcard_alias_reason())
                }
            };
            if let Some(reason) = reason {
                return Ok(Some(reason));
            }
        }
        Ok(None)
    }
}

/// Deterministic full compiler oracle used for candidate parity validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullCompilerOracle {
    compiler_version: String,
}

impl Default for FullCompilerOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl FullCompilerOracle {
    /// Construct an oracle using [`COMPILER_VERSION`].
    pub fn new() -> Self {
        Self {
            compiler_version: COMPILER_VERSION.to_owned(),
        }
    }

    fn with_compiler(compiler_version: String) -> Self {
        Self { compiler_version }
    }

    /// Rebuild every segment after applying the stable-ID deltas.
    pub fn compile(
        &self,
        base: &HotState,
        request: &CompileRequest,
    ) -> CompilerResult<CompileOutcome> {
        if let Some(conflict) = request_base_conflict(base, request) {
            return Ok(CompileOutcome::Conflict(conflict));
        }
        if request.deltas.is_empty() {
            return Ok(CompileOutcome::Conflict(CompilerConflict::EmptyDeltaBatch));
        }
        let dependencies = request.dependency_vector.canonicalized()?;
        let canonical_deltas = canonical_deltas(&request.deltas)?;
        if let Some(conflict) = duplicate_delta_conflict(&canonical_deltas)? {
            return Ok(CompileOutcome::Conflict(conflict));
        }
        let known_keys = known_affected_keys(base, &canonical_deltas)?;
        let records = match apply_deltas_to_ledger(base, &canonical_deltas, request.target_version)?
        {
            Ok(records) => records,
            Err(conflict) => return Ok(CompileOutcome::Conflict(conflict)),
        };
        let candidate = HotState::materialize(
            base.tenant.clone(),
            request.target_version,
            records,
            dependencies,
            self.compiler_version.clone(),
        )?;
        let all_keys = candidate
            .segments
            .keys()
            .cloned()
            .chain(base.segments.keys().cloned())
            .chain(known_keys)
            .collect::<BTreeSet<_>>();
        let plan = impact_plan(base, &candidate, all_keys, true, None);
        Ok(CompileOutcome::Applied(CompiledProjection {
            state: candidate,
            plan,
            mode: ProjectionCompileMode::FullRebuild,
            base_version: request.base_version,
            target_version: request.target_version,
            applied_delta_count: canonical_deltas.len(),
        }))
    }

    /// Rebuild from an explicit canonical ledger, useful as a standalone parity oracle.
    pub fn rebuild_from_grants<I>(
        &self,
        tenant: TenantScope,
        target_version: u64,
        grants: I,
        dependency_vector: DependencyVector,
    ) -> CompilerResult<HotState>
    where
        I: IntoIterator<Item = CanonicalGrant>,
    {
        HotState::from_grants_with_compiler(
            tenant,
            target_version,
            grants,
            dependency_vector,
            self.compiler_version.clone(),
        )
    }
}

fn normalize_key_identifier(value: String, field: &'static str) -> CompilerResult<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(CompilerError::Contract(
            GrantContractError::EmptyIdentifier { field },
        ));
    }
    if normalized.len() > 512 {
        return Err(CompilerError::Contract(
            GrantContractError::IdentifierTooLong { field },
        ));
    }
    if normalized
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(CompilerError::Contract(
            GrantContractError::MalformedIdentifier { field },
        ));
    }
    Ok(normalized.to_owned())
}

fn request_base_conflict(base: &HotState, request: &CompileRequest) -> Option<CompilerConflict> {
    if request.base_version != base.version {
        return Some(CompilerConflict::BaseVersionMismatch {
            expected: request.base_version,
            actual: base.version,
        });
    }
    if request.base_semantic_hash != base.semantic_hash {
        return Some(CompilerConflict::BaseHashMismatch {
            expected: request.base_semantic_hash.clone(),
            actual: base.semantic_hash.clone(),
        });
    }
    if request.target_version != base.version.saturating_add(1) {
        return Some(CompilerConflict::TargetVersionMismatch {
            base: base.version,
            target: request.target_version,
        });
    }
    None
}

fn canonical_deltas(deltas: &[GrantDelta]) -> CompilerResult<Vec<GrantDelta>> {
    let mut canonical = deltas
        .iter()
        .map(GrantDelta::canonicalized)
        .collect::<Result<Vec<_>, _>>()?;
    canonical.sort_by(|left, right| {
        let left_id = left
            .target_grant_id()
            .expect("canonical delta identity was validated");
        let right_id = right
            .target_grant_id()
            .expect("canonical delta identity was validated");
        left_id
            .cmp(&right_id)
            .then_with(|| left.operation_name().cmp(right.operation_name()))
    });
    Ok(canonical)
}

fn duplicate_delta_conflict(deltas: &[GrantDelta]) -> CompilerResult<Option<CompilerConflict>> {
    let mut seen = BTreeSet::new();
    for delta in deltas {
        let grant_id = delta.target_grant_id()?;
        if !seen.insert(grant_id) {
            return Ok(Some(CompilerConflict::DuplicateDelta { grant_id }));
        }
    }
    Ok(None)
}

fn known_affected_keys(
    base: &HotState,
    deltas: &[GrantDelta],
) -> CompilerResult<BTreeSet<ProjectionKey>> {
    let mut keys = BTreeSet::new();
    for delta in deltas {
        match delta {
            GrantDelta::Add { grant } | GrantDelta::Update { grant, .. } => {
                keys.insert(ProjectionKey::from_grant(grant)?);
                if let GrantDelta::Update { grant, .. } = delta {
                    // 旧记录的 key 经跨层视图读取（记录层无需组装完整 grant）。
                    if let Some(old) = state_grant_view(base, grant.grant_id) {
                        keys.insert(old.projection_key()?);
                    }
                }
            }
            GrantDelta::Remove { grant_id, .. } | GrantDelta::Revoke { grant_id, .. } => {
                if let Some(old) = state_grant_view(base, *grant_id) {
                    keys.insert(old.projection_key()?);
                }
            }
        }
    }
    Ok(keys)
}

fn full_rebuild_outcome(
    base: &HotState,
    deltas: &[GrantDelta],
    keys: BTreeSet<ProjectionKey>,
    reason: FullRebuildReason,
) -> CompileOutcome {
    CompileOutcome::FullRebuildRequired(FullRebuildRequired {
        reason,
        plan: impact_plan_without_candidate(base, deltas, keys, true, Some(reason)),
    })
}

fn impact_plan_without_candidate(
    base: &HotState,
    deltas: &[GrantDelta],
    mut keys: BTreeSet<ProjectionKey>,
    full_rebuild: bool,
    reason: Option<FullRebuildReason>,
) -> ImpactPlan {
    // A fallback plan records every currently known segment as affected. For a wildcard the
    // true universe may be larger; `reason` is the explicit proof that this is not a local
    // plan. The incoming exact keys are included when their payload is locally parseable.
    // 本路径只在 FullRebuildRequired 时触发（已是 O(N) 级降级路径），全量扫描
    // base 段集不构成单键变更路径的成本。
    keys.extend(base.segments.keys().cloned());
    let mut segments = Vec::new();
    for key in &keys {
        if let Some(identity) = segment_identity(base, key) {
            segments.push(SegmentImpact {
                key: key.clone(),
                segment_id: identity.segment_id,
                before_content_hash: Some(identity.content_hash),
                after_content_hash: None,
                content_changed: true,
            });
        } else if let Ok(segment_id) = stable_segment_id(key) {
            segments.push(SegmentImpact {
                key: key.clone(),
                segment_id,
                before_content_hash: None,
                after_content_hash: None,
                content_changed: true,
            });
        }
    }
    // Keep the parameter semantically visible in this pure evidence function. The actual
    // mutation is deliberately not attempted when a fallback is selected.
    let _ = deltas;
    ImpactPlan {
        affected_keys: keys.into_iter().collect(),
        affected_segments: segments,
        full_rebuild,
        reason,
    }
}

fn impact_plan(
    base: &HotState,
    candidate: &HotState,
    keys: BTreeSet<ProjectionKey>,
    full_rebuild: bool,
    reason: Option<FullRebuildReason>,
) -> ImpactPlan {
    // v4 O(1) 单键变更：只对 affected key 做 O(1) HAMT 定向读取，不构建
    // 全量 reference map（旧实现 O(S log S) 是单键路径上最后的 N 级残留）。
    // SegmentImpact 只携带 segment_id 与 content hash，不携带 ordinal，故
    // 证据内容与旧实现逐字段一致。
    let mut segments = Vec::new();
    for key in &keys {
        let before = segment_identity(base, key);
        let after = segment_identity(candidate, key);
        let segment_id = after
            .as_ref()
            .or(before.as_ref())
            .map(|identity| identity.segment_id.clone())
            .or_else(|| stable_segment_id(key).ok())
            .unwrap_or_default();
        let before_content_hash = before.map(|identity| identity.content_hash);
        let after_content_hash = after.map(|identity| identity.content_hash);
        segments.push(SegmentImpact {
            key: key.clone(),
            segment_id,
            content_changed: before_content_hash != after_content_hash,
            before_content_hash,
            after_content_hash,
        });
    }
    ImpactPlan {
        affected_keys: keys.into_iter().collect(),
        affected_segments: segments,
        full_rebuild,
        reason,
    }
}

/// O(1) 定向段身份读取（HAMT get），供增量证据构建使用。
struct SegmentIdentity {
    segment_id: String,
    content_hash: String,
}

fn segment_identity(state: &HotState, key: &ProjectionKey) -> Option<SegmentIdentity> {
    state.segments.get(key).map(|segment| SegmentIdentity {
        segment_id: segment.segment_id.clone(),
        content_hash: segment.content_hash.clone(),
    })
}

/// Apply stable-ID deltas to the factored ledger（factored 布局）。
///
/// CAS/墓碑/复活判定与 per-card 存储形态逐分支一致；差异只在存储面——
/// RULE_SET 走记录层 + 共享层 intern + 绑定层计数，其余进卡私有层。
/// 跨层 kind 迁移（仅全量 oracle 路径可达）以"旧层移除 + 新层插入"显式表达，
/// 任何时刻 `GrantId` 至多存在于一层。
///
/// 租户一致性：构造路径已逐条校验；delta 路径在此处 fail-closed 校验
/// （`TenantMismatch`），对齐 `from_grants` 的拒绝语义。
fn apply_deltas_to_ledger(
    base: &HotState,
    deltas: &[GrantDelta],
    target_version: u64,
) -> CompilerResult<Result<FactoredLedger, CompilerConflict>> {
    // 持久化结构共享：整体派生是 O(1)，后续单键变更只做 COW 路径复制——
    // 单键变更不携带 O(N) 深拷贝。
    let mut ledger = FactoredLedger::derive_from(base);
    for delta in deltas {
        let grant_id = delta.target_grant_id()?;
        match delta {
            GrantDelta::Add { grant } => {
                if grant.tenant != base.tenant {
                    return Ok(Err(CompilerConflict::TenantMismatch { grant_id }));
                }
                if let Some(existing) = ledger_view(&ledger, &grant_id) {
                    if existing.state() == GrantState::Active {
                        return Ok(Err(CompilerConflict::ExistingGrant { grant_id }));
                    }
                    // ADD may resurrect an inactive record only by strictly advancing
                    // its revision; an equal or lower revision is a stale or duplicate
                    // replay and is rejected fail-closed.
                    if !is_next_revision(existing.revision(), grant.revision) {
                        return Ok(Err(CompilerConflict::RevisionConflict {
                            grant_id,
                            expected: next_revision_or_current(existing.revision()),
                            actual: grant.revision,
                        }));
                    }
                }
                ledger_replace_with_payload(&mut ledger, grant.clone(), target_version)?;
            }
            GrantDelta::Update {
                grant,
                expected_revision,
            } => {
                if grant.tenant != base.tenant {
                    return Ok(Err(CompilerConflict::TenantMismatch { grant_id }));
                }
                let Some(existing) = ledger_view(&ledger, &grant_id) else {
                    return Ok(Err(CompilerConflict::UnknownGrant { grant_id }));
                };
                // Strict CAS equality: stale (<) and gapped (>) expectations both conflict.
                if existing.revision() != *expected_revision {
                    return Ok(Err(CompilerConflict::RevisionConflict {
                        grant_id,
                        expected: *expected_revision,
                        actual: existing.revision(),
                    }));
                }
                if existing.state() != GrantState::Active {
                    return Ok(Err(CompilerConflict::InactiveGrant {
                        grant_id,
                        state: existing.state(),
                    }));
                }
                if !is_next_revision(existing.revision(), grant.revision) {
                    return Ok(Err(CompilerConflict::RevisionConflict {
                        grant_id,
                        expected: next_revision_or_current(existing.revision()),
                        actual: grant.revision,
                    }));
                }
                ledger_replace_with_payload(&mut ledger, grant.clone(), target_version)?;
            }
            GrantDelta::Remove {
                expected_revision, ..
            }
            | GrantDelta::Revoke {
                expected_revision, ..
            } => {
                let Some(existing) = ledger_view(&ledger, &grant_id) else {
                    return Ok(Err(CompilerConflict::UnknownGrant { grant_id }));
                };
                let same_tombstone = matches!(
                    (existing.state(), delta),
                    (GrantState::Removed, GrantDelta::Remove { .. })
                        | (GrantState::Revoked, GrantDelta::Revoke { .. })
                );
                if existing.state() != GrantState::Active {
                    if same_tombstone && existing.revision() == *expected_revision {
                        return Ok(Err(CompilerConflict::DuplicateDelta { grant_id }));
                    }
                    return Ok(Err(CompilerConflict::RevisionConflict {
                        grant_id,
                        expected: *expected_revision,
                        actual: existing.revision(),
                    }));
                }
                if existing.revision() != *expected_revision {
                    return Ok(Err(CompilerConflict::RevisionConflict {
                        grant_id,
                        expected: *expected_revision,
                        actual: existing.revision(),
                    }));
                }
                // 墓碑 = 既有记录仅推进 revision/state，内容与所在层不变
                // （绑定层计数不变：墓碑保留 ledger 记录即保留绑定事实）。
                match existing {
                    LedgerGrantView::Private(grant) => {
                        let mut tombstone = grant.clone();
                        tombstone.revision = tombstone_state_revision(*expected_revision);
                        tombstone.state = match delta {
                            GrantDelta::Remove { .. } => GrantState::Removed,
                            _ => GrantState::Revoked,
                        };
                        ledger.private_grants.insert(grant_id, tombstone);
                    }
                    LedgerGrantView::RuleSet(record) => {
                        let mut tombstone = record.clone();
                        tombstone.revision = tombstone_state_revision(*expected_revision);
                        tombstone.state = match delta {
                            GrantDelta::Remove { .. } => GrantState::Removed,
                            _ => GrantState::Revoked,
                        };
                        ledger.ruleset_records.insert(grant_id, tombstone);
                    }
                }
            }
        }
    }
    Ok(Ok(ledger))
}

fn tombstone_state_revision(expected: GrantRevision) -> GrantRevision {
    // Validated as the CAS successor by `GrantDelta::revision`; fall back to the
    // carried revision when a caller bypassed contract validation.
    expected.next().unwrap_or(expected)
}

fn is_next_revision(current: GrantRevision, actual: GrantRevision) -> bool {
    current.next().map(|next| next == actual).unwrap_or(false)
}

fn next_revision_or_current(current: GrantRevision) -> GrantRevision {
    current.next().unwrap_or(current)
}

/// 通配/别名载荷的全量降级判定（增量路径的 delta 形态触发器）。
fn wildcard_or_alias_reason(resource: &str, action: &str) -> Option<FullRebuildReason> {
    if resource.contains('*') || action.contains('*') {
        return Some(FullRebuildReason::WildcardImpact);
    }
    if ACTION_ALIASES.iter().any(|(alias, _)| *alias == action)
        || !get_alias_sources(action).is_empty()
    {
        return Some(FullRebuildReason::ActionAliasImpact);
    }
    None
}

fn grant_impact_reason(
    grant: &CanonicalGrant,
    old: Option<LedgerGrantView<'_>>,
) -> Option<FullRebuildReason> {
    if let Some(reason) = wildcard_or_alias_reason(&grant.resource, &grant.action) {
        return Some(reason);
    }
    // 窗口不触发全量（2026-08-29 触发面收窄）：validity 是 grant 自身属性，
    // 窗口 delta 的影响集 = 自身 key 段；semantic/segment hash 均覆盖 validity
    // 字段，变更可检测；时间推移的生效/失效由读侧按 UTC now 过滤，与编译期
    // 发布方式无关（增量路径支持窗口规则的组合级更新）。
    if let Some(old) = old {
        if old.source_kind() != grant.source_kind || old.binding_layer() != grant.binding_layer {
            return Some(FullRebuildReason::BindingImpact);
        }
    }
    None
}

/// Materialize the incremental candidate in O(affected) instead of O(all grants).
///
/// G1（2026-08，O(affected) 化）：只有 `affected_keys` 内的段被重建——未受影响
/// key 直接继承 base 段的 `Arc`（零构建、零 serde/SHA）；affected key 的段由
/// "base 段贡献 − 本批移除/迁走的 grant + 本批落入该 key 的新 Active grant"
/// 就地重建，本批结束后 ledger 记录仍完整保留（含墓碑）。
///
/// 正确性依赖两个不变式，均由既有构造保证：
/// 1. `affected_keys` 覆盖"新 grants 的 Active key 集"与"base 段 key 集"的
///    对称差——`known_affected_keys` 对 Add/Update 插入新 grant 的 key、对
///    Update 追加旧 grant 的 key、对 Remove/Revoke 插入旧 grant 的 key；
/// 2. `base.segments[key].grants` 恰为 base ledger 在该 key 上的 Active 贡献
///    （`HotState::materialize` → `build_segments` 的构造不变式）。
///
/// 被本批移除/更新的 grant_id 只可能出现在其旧 key 段中，而旧 key 必在
/// `affected_keys` 内，因此继承段无需过滤。
fn materialize_incremental_candidate(
    base: &HotState,
    version: u64,
    ledger: FactoredLedger,
    dependency_vector: DependencyVector,
    compiler_version: String,
    deltas: &[GrantDelta],
    affected_keys: &BTreeSet<ProjectionKey>,
) -> CompilerResult<HotState> {
    // 本批 delta 索引：只遍历 deltas（≤ MAX_INCREMENTAL_DELTAS），不遍历全量
    // ledger。`removed_ids` 是被 Update 迁走或 Remove/Revoke 清除的 grant 身份；
    // `added_by_key` 是本批新落入各 affected key 的 Active 贡献（Add 新增与
    // Update 的新版本）。
    let mut removed_ids: BTreeSet<GrantId> = BTreeSet::new();
    let mut added_by_key: BTreeMap<ProjectionKey, Vec<CanonicalGrant>> = BTreeMap::new();
    for delta in deltas {
        match delta {
            GrantDelta::Add { grant } => {
                // 段只承载 Active 贡献（与 build_segments 的 Active 过滤、全量
                // oracle 逐字节一致）：复活语义下 Add 携带非 Active 状态的
                // 载荷不得进入段，否则增量段与全量段分叉（越权面）。
                if grant.state == GrantState::Active {
                    added_by_key
                        .entry(ProjectionKey::from_grant(grant)?)
                        .or_default()
                        .push(grant.clone());
                }
            }
            GrantDelta::Update { grant, .. } => {
                removed_ids.insert(grant.grant_id);
                // Update-to-inactive（失效态携带）不进段：失效必须经由墓碑
                // delta 通道表达；此处 Active 过滤保证增量段与全量 oracle
                // 的 Active 贡献集逐字节一致。
                if grant.state == GrantState::Active {
                    added_by_key
                        .entry(ProjectionKey::from_grant(grant)?)
                        .or_default()
                        .push(grant.clone());
                }
            }
            GrantDelta::Remove { grant_id, .. } | GrantDelta::Revoke { grant_id, .. } => {
                removed_ids.insert(*grant_id);
            }
        }
    }

    // 未受影响 key：直接继承 base 段。v4：HAMT clone 是 O(1) 结构共享——
    // 整个继承动作从 O(N) 遍历重建降为一次 O(1) clone；affected key 的
    // remove/insert 为 O(1) avg 的 COW 路径复制。
    let mut segments: im::HashMap<ProjectionKey, Arc<SegmentContent>> = base.segments.clone();
    // affected key：base 段贡献 − 本批移除 + 本批新增；无剩余贡献时段消失
    // （Remove 清空 key、Update 迁移 key 后旧 key 两种形态）。BTreeSet 迭代
    // 序保证处理顺序确定（与 HAMT 内部序无关）。
    for key in affected_keys {
        let mut contributions: Vec<CanonicalGrant> = match base.segments.get(key) {
            Some(segment) => segment
                .grants
                .iter()
                .filter(|grant| !removed_ids.contains(&grant.grant_id))
                .cloned()
                .collect(),
            None => Vec::new(),
        };
        if let Some(added) = added_by_key.get(key) {
            contributions.extend(added.iter().cloned());
        }
        if contributions.is_empty() {
            segments.remove(key);
            continue;
        }
        let segment = build_single_segment(key, contributions, &compiler_version)?;
        segments.insert(key.clone(), segment);
    }

    let dependency_hash = dependency_vector.canonical_hash()?;
    // v4 版本绑定语义：semantic hash 只由 O(1) 字段构成（compiler version、
    // tenant、version、dependency hash），增量路径无需重算/聚合段 hash。
    let semantic_hash = semantic_hash(&base.tenant, version, &dependency_hash, &compiler_version)?;
    Ok(HotState {
        tenant: base.tenant.clone(),
        version,
        shared_entries: ledger.shared_entries,
        bindings: ledger.bindings,
        ruleset_records: ledger.ruleset_records,
        private_grants: ledger.private_grants,
        segments,
        semantic_hash,
        dependency_hash,
        compiler_version,
        dependency_vector,
    })
}

fn build_segments(
    tenant: &TenantScope,
    ledger: &FactoredLedger,
    compiler_version: &str,
) -> CompilerResult<im::HashMap<ProjectionKey, Arc<SegmentContent>>> {
    // 分组用 BTreeMap：构建顺序按 key 确定（与 HAMT 迭代序解耦）。段内容
    // 本身由 `build_single_segment` 的显式 sort_by 保证确定性，分组序只影响
    // 构建顺序不影响逐字节结果——此处排序是全量 oracle 路径的确定性保险。
    //
    // factored 布局：卡私有层直接贡献；记录层按需组装（纯函数，与构造输入
    // 逐字节相等）后贡献。只有 Active 记录进入段（与 per-card 形态一致）。
    let mut grouped: BTreeMap<ProjectionKey, Vec<CanonicalGrant>> = BTreeMap::new();
    for grant in ledger
        .private_grants
        .values()
        .filter(|grant| grant.state == GrantState::Active)
    {
        grouped
            .entry(ProjectionKey::from_grant(grant)?)
            .or_default()
            .push(grant.clone());
    }
    for (grant_id, record) in ledger
        .ruleset_records
        .iter()
        .filter(|(_, record)| record.state == GrantState::Active)
    {
        grouped
            .entry(record.projection_key()?)
            .or_default()
            .push(record.to_grant(tenant, *grant_id));
    }

    grouped
        .into_iter()
        .map(|(key, contributions)| {
            let segment = build_single_segment(&key, contributions, compiler_version)?;
            Ok((key, segment))
        })
        .collect()
}

/// Build one exact-key segment from its Active contributions.
///
/// Contributions are canonically ordered by (grant_id, revision, source_id)
/// inside this function, so the full-oracle path (`build_segments`) and the
/// O(affected) incremental path (`materialize_incremental_candidate`, which
/// starts from the already ordered base segment contributions) produce
/// byte-identical segment content from the same Active contribution set.
fn build_single_segment(
    key: &ProjectionKey,
    mut contributions: Vec<CanonicalGrant>,
    compiler_version: &str,
) -> CompilerResult<Arc<SegmentContent>> {
    contributions.sort_by(|left, right| {
        left.grant_id
            .cmp(&right.grant_id)
            .then_with(|| left.revision.cmp(&right.revision))
            .then_with(|| left.provenance.source_id.cmp(&right.provenance.source_id))
    });
    let segment_id = stable_segment_id(key)?;
    let content_hash = segment_content_hash(key, &contributions, compiler_version)?;
    Ok(Arc::new(SegmentContent {
        key: key.clone(),
        grants: contributions,
        content_hash,
        segment_id,
    }))
}

fn stable_segment_id(key: &ProjectionKey) -> CompilerResult<String> {
    Ok(format!(
        "segment-{}",
        sha256_hex(key.canonical_input()?.as_bytes())
    ))
}

#[derive(Serialize)]
struct SegmentHashInput<'a> {
    compiler_version: &'a str,
    key: &'a ProjectionKey,
    grants: &'a [CanonicalGrant],
}

fn segment_content_hash(
    key: &ProjectionKey,
    grants: &[CanonicalGrant],
    compiler_version: &str,
) -> CompilerResult<String> {
    let input = SegmentHashInput {
        compiler_version,
        key,
        grants,
    };
    let encoded = serde_json::to_string(&input)
        .map_err(|error| CompilerError::CanonicalSerialization(error.to_string()))?;
    Ok(sha256_hex(encoded.as_bytes()))
}

/// v4 版本绑定 semantic hash 的确定性输入。
///
/// **语义变化（v3 → v4，2026-08）**：v3 的 hash 输入绑定按 key 排序的段内容
/// hash 列表（更新 O(段数)）；v4 重定义为**版本绑定标识**——只由 O(1) 字段
/// 构成（compiler version、tenant、version、dependency_hash），hash 更新从
/// O(N) 降为 O(1)，与单键 O(1) 变更目标对齐。
///
/// 语义等价性论证（逐消费点审计结论）：semantic_hash 的全部消费点均为
/// **等值 fence 比较**（"是否同一版本"：BaseHashMismatch 对牌、evidence 对牌、
/// L1 缓存栅栏），从不解包验证内容——内容完整性由 manifest digest（绑全部
/// 段 content hash）+ 读时逐段 sha256 重算承担。"同 version 不同内容"不可达：
/// 发布 CAS 原子推进 version 且段内容 content-addressed，version 相同则内容
/// 相同。v3 的"Inactive/墓碑差异不改 hash"结论自然保持（墓碑差异本就不进入
/// hash 输入）；"Active 集变化 → hash 变化"改由 version 推进承载（编译入口
/// 强制 target = base + 1），不再由内容差异在等 version 下直接体现。
#[derive(Serialize)]
struct SemanticHashInput<'a> {
    compiler_version: &'a str,
    tenant: &'a TenantScope,
    /// 版本绑定：durable-style projection generation（publish CAS 推进）。
    version: u64,
    /// 依赖向量 canonical hash：依赖物料变化仍驱动 hash 变化（DependencyChanged
    /// 全量重建语义保持）。
    dependency_hash: &'a str,
}

fn semantic_hash(
    tenant: &TenantScope,
    version: u64,
    dependency_hash: &str,
    compiler_version: &str,
) -> CompilerResult<String> {
    let input = SemanticHashInput {
        compiler_version,
        tenant,
        version,
        dependency_hash,
    };
    let encoded = serde_json::to_string(&input)
        .map_err(|error| CompilerError::CanonicalSerialization(error.to_string()))?;
    Ok(sha256_hex(encoded.as_bytes()))
}

// A small dependency-free SHA-256 implementation keeps policy-engine's dependency surface
// unchanged. Grant and dependency canonical hashes still come from astral-types; this helper
// only combines already canonical JSON into the 32-byte semantic/segment digest required by
// the projection contract.
fn sha256_hex(input: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut padded = input.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    let bit_length = (input.len() as u64).wrapping_mul(8);
    padded.extend_from_slice(&bit_length.to_be_bytes());

    let mut state: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    for chunk in padded.as_chunks::<64>().0 {
        let mut words = [0u32; 64];
        for (index, bytes) in chunk.as_chunks::<4>().0.iter().take(16).enumerate() {
            words[index] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for index in 16..64 {
            let first = words[index - 15];
            let second = words[index - 2];
            let sigma0 = first.rotate_right(7) ^ first.rotate_right(18) ^ (first >> 3);
            let sigma1 = second.rotate_right(17) ^ second.rotate_right(19) ^ (second >> 10);
            words[index] = words[index - 16]
                .wrapping_add(sigma0)
                .wrapping_add(words[index - 7])
                .wrapping_add(sigma1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for (index, constant) in K.iter().enumerate() {
            let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temporary1 = h
                .wrapping_add(sigma1)
                .wrapping_add(choice)
                .wrapping_add(*constant)
                .wrapping_add(words[index]);
            let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary2 = sigma0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut output = String::with_capacity(64);
    for word in state {
        let _ = write!(&mut output, "{word:08x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::{
        BindingLayer, DependencyVersion, GrantEffect, GrantProvenance, GrantSourceKind,
        ValidityWindow,
    };

    const TENANT_ID: i64 = 7;
    const CARD_ID: i64 = 17;
    const USER_ID: i64 = 42;

    // Fixture-only version pair for the acceptance example below. Production code
    // never fixes hot-state versions; any legal `base -> base + 1` advance is allowed.
    const CURRENT_VERSION: u64 = 111;
    const TARGET_VERSION: u64 = 112;

    fn tenant() -> TenantScope {
        TenantScope::new(TENANT_ID, Some(11)).unwrap()
    }

    fn dependencies() -> DependencyVector {
        DependencyVector::new(vec![
            DependencyVersion::new("card", 4, 0).unwrap(),
            DependencyVersion::new("rule-set", 3, 1).unwrap(),
        ])
        .unwrap()
    }

    fn grant(
        id: &str,
        revision: u64,
        resource: &str,
        action: &str,
        source: &str,
    ) -> CanonicalGrant {
        CanonicalGrant {
            grant_id: GrantId::parse(id).unwrap(),
            revision: GrantRevision::new(revision).unwrap(),
            state: GrantState::Active,
            source_kind: GrantSourceKind::RuleSet,
            binding_layer: BindingLayer::Base,
            tenant: tenant(),
            card_id: CARD_ID,
            user_id: USER_ID,
            resource: resource.to_owned(),
            action: action.to_owned(),
            effect: GrantEffect::Allow,
            validity: ValidityWindow::perpetual(),
            provenance: GrantProvenance {
                source_id: source.to_owned(),
                source_entry: None,
                binding_id: Some(format!("binding-{source}")),
                delegation_id: None,
                operation_id: format!("operation-{source}"),
                event_id: Some(format!("event-{source}")),
                actor_user_id: Some(USER_ID),
            },
        }
    }

    fn base(grants: Vec<CanonicalGrant>) -> HotState {
        HotState::from_grants(tenant(), CURRENT_VERSION, grants, dependencies()).unwrap()
    }

    fn applied(outcome: CompileOutcome) -> CompiledProjection {
        match outcome {
            CompileOutcome::Applied(candidate) => candidate,
            other => panic!("expected applied candidate, got {other:?}"),
        }
    }

    #[test]
    fn add_111_to_112_changes_only_one_exact_segment() {
        let first = grant(
            "550e8400-e29b-41d4-a716-446655440001",
            1,
            "learn_subject:1",
            "read",
            "source-a",
        );
        let second = grant(
            "550e8400-e29b-41d4-a716-446655440002",
            1,
            "learn_exam:2",
            "read",
            "source-b",
        );
        let base = base(vec![first.clone(), second.clone()]);
        let untouched_key = ProjectionKey::from_grant(&second).unwrap();
        let untouched = base.segment_content(&untouched_key).unwrap();
        let added = grant(
            "550e8400-e29b-41d4-a716-446655440003",
            1,
            "learn_subject:1",
            "read",
            "source-c",
        );

        let candidate = applied(
            AuthorizationCompiler::new()
                .compile_incremental(
                    &base,
                    TARGET_VERSION,
                    dependencies(),
                    vec![GrantDelta::add(added)],
                )
                .unwrap(),
        );

        assert_eq!(candidate.state.version, TARGET_VERSION);
        assert_eq!(candidate.plan.affected_keys.len(), 1);
        assert_eq!(candidate.state.active_grants().len(), 3);
        assert!(Arc::ptr_eq(
            &untouched,
            &candidate.state.segment_content(&untouched_key).unwrap()
        ));
    }

    #[test]
    fn update_removes_old_contribution_and_adds_new_revision() {
        let old = grant(
            "550e8400-e29b-41d4-a716-446655440004",
            1,
            "learn_subject:1",
            "read",
            "source-update",
        );
        let base = base(vec![old.clone()]);
        let mut updated = old.clone();
        updated.revision = GrantRevision::new(2).unwrap();
        updated.action = "publish".to_owned();

        let candidate = applied(
            AuthorizationCompiler::new()
                .compile_incremental(
                    &base,
                    TARGET_VERSION,
                    dependencies(),
                    vec![GrantDelta::update(
                        updated.clone(),
                        GrantRevision::initial(),
                    )],
                )
                .unwrap(),
        );

        assert!(candidate.state.grant(old.grant_id).is_some_and(|value| {
            value.revision == GrantRevision::new(2).unwrap() && value.action == "publish"
        }));
        assert!(candidate
            .state
            .segment_keys()
            .iter()
            .all(|key| key.action == "publish"));
        assert_eq!(candidate.applied_delta_count, 1);
    }

    #[test]
    fn remove_and_revoke_preserve_other_sources_on_same_key() {
        let first = grant(
            "550e8400-e29b-41d4-a716-446655440005",
            1,
            "learn_subject:1",
            "read",
            "source-one",
        );
        let second = grant(
            "550e8400-e29b-41d4-a716-446655440006",
            1,
            "learn_subject:1",
            "read",
            "source-two",
        );
        let third = grant(
            "550e8400-e29b-41d4-a716-446655440007",
            1,
            "learn_subject:1",
            "read",
            "source-three",
        );
        let base = base(vec![first.clone(), second.clone(), third.clone()]);
        let result = AuthorizationCompiler::new()
            .compile_incremental(
                &base,
                TARGET_VERSION,
                dependencies(),
                vec![GrantDelta::remove(first.grant_id, GrantRevision::initial())],
            )
            .unwrap();
        let candidate = applied(result);
        let key = ProjectionKey::from_grant(&first).unwrap();
        let remaining = candidate.state.segment_content(&key).unwrap();
        assert_eq!(remaining.grants.len(), 2);
        assert!(remaining
            .grants
            .iter()
            .all(|value| value.grant_id != first.grant_id));

        let revoked = applied(
            AuthorizationCompiler::new()
                .compile_incremental(
                    &candidate.state,
                    113,
                    dependencies(),
                    vec![GrantDelta::revoke(
                        second.grant_id,
                        GrantRevision::initial(),
                    )],
                )
                .unwrap(),
        );
        let remaining_after_revoke = revoked.state.segment_content(&key).unwrap();
        assert_eq!(remaining_after_revoke.grants.len(), 1);
        assert_eq!(remaining_after_revoke.grants[0].grant_id, third.grant_id);
    }

    #[test]
    fn unchanged_segment_identity_and_content_are_reused() {
        let first = grant(
            "550e8400-e29b-41d4-a716-446655440008",
            1,
            "learn_subject:1",
            "read",
            "source-one",
        );
        let second = grant(
            "550e8400-e29b-41d4-a716-446655440009",
            1,
            "learn_exam:2",
            "read",
            "source-two",
        );
        let base = base(vec![first.clone(), second.clone()]);
        let key = ProjectionKey::from_grant(&second).unwrap();
        let before = base.segment_content(&key).unwrap();
        let mut updated = first.clone();
        updated.revision = GrantRevision::new(2).unwrap();
        updated.provenance.operation_id = "operation-updated".to_owned();
        updated.provenance.event_id = Some("event-updated".to_owned());

        let candidate = applied(
            AuthorizationCompiler::new()
                .compile_incremental(
                    &base,
                    TARGET_VERSION,
                    dependencies(),
                    vec![GrantDelta::update(updated, GrantRevision::initial())],
                )
                .unwrap(),
        );
        let after = candidate.state.segment_content(&key).unwrap();
        assert!(Arc::ptr_eq(&before, &after));
        assert_eq!(before.segment_id, after.segment_id);
        assert_eq!(before.content_hash, after.content_hash);
    }

    #[test]
    fn stale_base_version_and_hash_are_explicit_conflicts() {
        let value = grant(
            "550e8400-e29b-41d4-a716-44665544000a",
            1,
            "learn_subject:1",
            "read",
            "source-stale",
        );
        let base = base(vec![value.clone()]);
        let mut request = CompileRequest::for_base(
            &base,
            TARGET_VERSION,
            dependencies(),
            vec![GrantDelta::remove(value.grant_id, GrantRevision::initial())],
        );
        request.base_version = 110;
        assert!(matches!(
            AuthorizationCompiler::new()
                .compile(&base, &request)
                .unwrap(),
            CompileOutcome::Conflict(CompilerConflict::BaseVersionMismatch { .. })
        ));

        let mut request = CompileRequest::for_base(
            &base,
            TARGET_VERSION,
            dependencies(),
            vec![GrantDelta::remove(value.grant_id, GrantRevision::initial())],
        );
        request.base_semantic_hash = "0".repeat(64);
        assert!(matches!(
            AuthorizationCompiler::new()
                .compile(&base, &request)
                .unwrap(),
            CompileOutcome::Conflict(CompilerConflict::BaseHashMismatch { .. })
        ));
    }

    #[test]
    fn duplicate_unknown_and_existing_deltas_are_not_silent_noops() {
        let value = grant(
            "550e8400-e29b-41d4-a716-44665544000b",
            1,
            "learn_subject:1",
            "read",
            "source-duplicate",
        );
        let base = base(vec![value.clone()]);
        let duplicate = AuthorizationCompiler::new()
            .compile_incremental(
                &base,
                TARGET_VERSION,
                dependencies(),
                vec![
                    GrantDelta::remove(value.grant_id, GrantRevision::initial()),
                    GrantDelta::remove(value.grant_id, GrantRevision::initial()),
                ],
            )
            .unwrap();
        assert!(matches!(
            duplicate,
            CompileOutcome::Conflict(CompilerConflict::DuplicateDelta { .. })
        ));

        let unknown = GrantId::parse("550e8400-e29b-41d4-a716-44665544000c").unwrap();
        let unknown_result = AuthorizationCompiler::new()
            .compile_incremental(
                &base,
                TARGET_VERSION,
                dependencies(),
                vec![GrantDelta::remove(unknown, GrantRevision::initial())],
            )
            .unwrap();
        assert!(matches!(
            unknown_result,
            CompileOutcome::Conflict(CompilerConflict::UnknownGrant { .. })
        ));

        let existing = AuthorizationCompiler::new()
            .compile_incremental(
                &base,
                TARGET_VERSION,
                dependencies(),
                vec![GrantDelta::add(value)],
            )
            .unwrap();
        assert!(matches!(
            existing,
            CompileOutcome::Conflict(CompilerConflict::ExistingGrant { .. })
        ));
    }

    #[test]
    fn revision_conflicts_reject_stale_update_and_remove() {
        let value = grant(
            "550e8400-e29b-41d4-a716-44665544000d",
            2,
            "learn_subject:1",
            "read",
            "source-revision",
        );
        let base = base(vec![value.clone()]);
        let mut stale_update = value.clone();
        stale_update.revision = GrantRevision::new(2).unwrap();
        // Structurally valid delta (payload = expected + 1), but the CAS expectation
        // of revision 1 is stale against a ledger already at revision 2.
        let outcome = AuthorizationCompiler::new()
            .compile_incremental(
                &base,
                TARGET_VERSION,
                dependencies(),
                vec![GrantDelta::update(stale_update, GrantRevision::initial())],
            )
            .unwrap();
        assert!(matches!(
            outcome,
            CompileOutcome::Conflict(CompilerConflict::RevisionConflict { .. })
        ));

        let outcome = AuthorizationCompiler::new()
            .compile_incremental(
                &base,
                TARGET_VERSION,
                dependencies(),
                vec![GrantDelta::remove(value.grant_id, GrantRevision::initial())],
            )
            .unwrap();
        assert!(matches!(
            outcome,
            CompileOutcome::Conflict(CompilerConflict::RevisionConflict { .. })
        ));

        // A gapped expectation ahead of the ledger is equally fail-closed.
        let gapped = GrantRevision::new(5).unwrap();
        let outcome = AuthorizationCompiler::new()
            .compile_incremental(
                &base,
                TARGET_VERSION,
                dependencies(),
                vec![GrantDelta::remove(value.grant_id, gapped)],
            )
            .unwrap();
        assert!(matches!(
            outcome,
            CompileOutcome::Conflict(CompilerConflict::RevisionConflict { expected, actual, .. })
                if expected == gapped && actual == GrantRevision::new(2).unwrap()
        ));
    }

    #[test]
    fn tombstones_apply_at_the_cas_successor_revision() {
        let value = grant(
            "550e8400-e29b-41d4-a716-446655440010",
            2,
            "learn_subject:1",
            "read",
            "source-tombstone",
        );
        let base = base(vec![value.clone()]);
        let candidate = applied(
            AuthorizationCompiler::new()
                .compile_incremental(
                    &base,
                    TARGET_VERSION,
                    dependencies(),
                    vec![GrantDelta::revoke(
                        value.grant_id,
                        GrantRevision::new(2).unwrap(),
                    )],
                )
                .unwrap(),
        );
        let record = candidate.state.grant(value.grant_id).unwrap();
        assert_eq!(record.state, GrantState::Revoked);
        assert_eq!(
            record.revision,
            GrantRevision::new(3).unwrap(),
            "REMOVE/REVOKE always materialize expected_revision + 1"
        );
        assert_eq!(candidate.state.active_grants().len(), 0);
    }

    #[test]
    fn any_legal_base_version_advances_exactly_one_version() {
        for (base_version, target_version) in [(1u64, 2u64), (9_999, 10_000), (111, 112)] {
            let value = grant(
                "550e8400-e29b-41d4-a716-446655440011",
                1,
                "learn_subject:1",
                "read",
                "source-arbitrary",
            );
            let base =
                HotState::from_grants(tenant(), base_version, vec![value.clone()], dependencies())
                    .unwrap();
            let candidate = applied(
                AuthorizationCompiler::new()
                    .compile_incremental(
                        &base,
                        target_version,
                        dependencies(),
                        vec![GrantDelta::remove(value.grant_id, GrantRevision::initial())],
                    )
                    .unwrap(),
            );
            assert_eq!(candidate.state.version, target_version);
            assert_eq!(candidate.target_version, target_version);
        }

        // Skipping a version is never silently accepted.
        let value = grant(
            "550e8400-e29b-41d4-a716-446655440011",
            1,
            "learn_subject:1",
            "read",
            "source-arbitrary",
        );
        let base =
            HotState::from_grants(tenant(), CURRENT_VERSION, vec![value], dependencies()).unwrap();
        let outcome = AuthorizationCompiler::new()
            .compile_incremental(&base, TARGET_VERSION + 1, dependencies(), vec![])
            .unwrap();
        assert!(matches!(
            outcome,
            CompileOutcome::Conflict(CompilerConflict::TargetVersionMismatch { .. })
        ));
    }

    #[test]
    fn wildcard_and_alias_impacts_require_full_rebuild() {
        // 触发面收窄后仅通配与别名保持全量触发；
        // 窗口精确 delta 改走组合级增量（见下方窗口/污染测试）。
        let base = base(vec![]);
        for (index, (resource, action, validity)) in [
            ("learn_subject:*", "read", ValidityWindow::perpetual()),
            ("learn_subject:1", "write", ValidityWindow::perpetual()),
        ]
        .into_iter()
        .enumerate()
        {
            let mut value = grant(
                &format!("550e8400-e29b-41d4-a716-4466554400{:02x}", index + 14),
                1,
                resource,
                action,
                &format!("source-impact-{index}"),
            );
            value.validity = validity;
            let outcome = AuthorizationCompiler::new()
                .compile_incremental(
                    &base,
                    TARGET_VERSION,
                    dependencies(),
                    vec![GrantDelta::add(value)],
                )
                .unwrap();
            assert!(matches!(
                outcome,
                CompileOutcome::FullRebuildRequired(FullRebuildRequired { .. })
            ));
        }
    }

    /// 触发面收窄（2026-08-29）：带窗口的精确 delta 走组合级增量——
    /// validity 是 grant 自身属性，semantic/segment hash 覆盖窗口字段保证
    /// 变更可检测；时间推移的生效/失效由读侧按 UTC now 过滤。
    #[test]
    fn windowed_exact_delta_compiles_incrementally_with_oracle_parity() {
        let base = base(vec![]);
        let mut value = grant(
            "550e8400-e29b-41d4-a716-446655440014",
            1,
            "learn_subject:1",
            "read",
            "source-windowed",
        );
        value.validity = ValidityWindow::between(1, 2);
        let compiler = AuthorizationCompiler::new();
        let outcome = compiler
            .compile_incremental(
                &base,
                TARGET_VERSION,
                dependencies(),
                vec![GrantDelta::add(value.clone())],
            )
            .unwrap();
        let incremental = applied(outcome);
        let oracle = applied(
            FullCompilerOracle::new()
                .compile(
                    &base,
                    &CompileRequest::for_base(
                        &base,
                        TARGET_VERSION,
                        dependencies(),
                        vec![GrantDelta::add(value)],
                    ),
                )
                .unwrap(),
        );
        assert_eq!(incremental.state, oracle.state);
    }

    /// base 污染判定已删除：base 中的通配/窗口贡献不再剥夺后续精确 delta 的
    /// 增量资格（组合独立）；精确 delta 与 full oracle 保持逐 grant/段/hash parity。
    /// oracle 保持逐 grant/段/hash parity。
    #[test]
    fn base_broad_contributions_do_not_contaminate_exact_deltas() {
        let mut wildcard = grant(
            "550e8400-e29b-41d4-a716-446655440015",
            1,
            "learn_subject:*",
            "read",
            "source-broad-wildcard",
        );
        wildcard.validity = ValidityWindow::between(1, 2);
        let mut windowed = grant(
            "550e8400-e29b-41d4-a716-446655440016",
            1,
            "learn_exam:2",
            "read",
            "source-broad-windowed",
        );
        windowed.validity = ValidityWindow::between(3, 4);
        // base 同时含通配与窗口贡献（模拟规则集物化形态，原判定下必然全量）。
        let base = base(vec![wildcard.clone(), windowed.clone()]);

        let exact_add = grant(
            "550e8400-e29b-41d4-a716-446655440017",
            1,
            "learn_exam:3",
            "read",
            "source-exact-add",
        );
        let compiler = AuthorizationCompiler::new();
        let incremental = applied(
            compiler
                .compile_incremental(
                    &base,
                    TARGET_VERSION,
                    dependencies(),
                    vec![GrantDelta::add(exact_add.clone())],
                )
                .unwrap(),
        );
        let oracle = applied(
            FullCompilerOracle::new()
                .compile(
                    &base,
                    &CompileRequest::for_base(
                        &base,
                        TARGET_VERSION,
                        dependencies(),
                        vec![GrantDelta::add(exact_add.clone())],
                    ),
                )
                .unwrap(),
        );
        assert_eq!(incremental.state, oracle.state);
        // 增量只替换自身 key 段：base 的通配/窗口段保持原引用（未重算）。
        assert_eq!(
            incremental
                .state
                .segment_content(&ProjectionKey::from_grant(&wildcard).unwrap())
                .as_deref(),
            base.segment_content(&ProjectionKey::from_grant(&wildcard).unwrap())
                .as_deref()
        );

        // 精确 Remove（删非胜者/唯一贡献两种形态）同样保持组合独立增量。
        let outcome = compiler
            .compile_incremental(
                &base,
                TARGET_VERSION,
                dependencies(),
                vec![GrantDelta::remove(
                    GrantId::parse("550e8400-e29b-41d4-a716-446655440016").unwrap(),
                    GrantRevision::new(1).unwrap(),
                )],
            )
            .unwrap();
        let incremental_remove = applied(outcome);
        let oracle_remove = applied(
            FullCompilerOracle::new()
                .compile(
                    &base,
                    &CompileRequest::for_base(
                        &base,
                        TARGET_VERSION,
                        dependencies(),
                        vec![GrantDelta::remove(
                            GrantId::parse("550e8400-e29b-41d4-a716-446655440016").unwrap(),
                            GrantRevision::new(1).unwrap(),
                        )],
                    ),
                )
                .unwrap(),
        );
        assert_eq!(incremental_remove.state, oracle_remove.state);
    }

    #[test]
    fn hashes_and_order_are_deterministic_and_full_oracle_has_parity() {
        let first = grant(
            "550e8400-e29b-41d4-a716-446655440021",
            1,
            "learn_subject:1",
            "read",
            "source-first",
        );
        let second = grant(
            "550e8400-e29b-41d4-a716-446655440022",
            1,
            "learn_exam:2",
            "read",
            "source-second",
        );
        let base_a = base(vec![first.clone(), second.clone()]);
        let base_b = base(vec![second.clone(), first.clone()]);
        assert_eq!(base_a.semantic_hash, base_b.semantic_hash);
        assert_eq!(base_a.dependency_hash, base_b.dependency_hash);
        assert_eq!(base_a.segment_references(), base_b.segment_references());

        let added = grant(
            "550e8400-e29b-41d4-a716-446655440023",
            1,
            "learn_subject:1",
            "read",
            "source-third",
        );
        let incremental = applied(
            AuthorizationCompiler::new()
                .compile_incremental(
                    &base_a,
                    TARGET_VERSION,
                    dependencies(),
                    vec![GrantDelta::add(added)],
                )
                .unwrap(),
        );
        let oracle = applied(
            FullCompilerOracle::new()
                .compile(
                    &base_a,
                    &CompileRequest::for_base(
                        &base_a,
                        TARGET_VERSION,
                        dependencies(),
                        vec![GrantDelta::add(
                            incremental
                                .state
                                .grant(
                                    GrantId::parse("550e8400-e29b-41d4-a716-446655440023").unwrap(),
                                )
                                .unwrap()
                                .clone(),
                        )],
                    ),
                )
                .unwrap(),
        );
        assert_eq!(incremental.state.semantic_hash, oracle.state.semantic_hash);
        assert_eq!(
            incremental.state.dependency_hash,
            oracle.state.dependency_hash
        );
        assert_eq!(
            incremental.state.active_grants(),
            oracle.state.active_grants()
        );
        assert_eq!(
            incremental.state.segment_references(),
            oracle.state.segment_references()
        );
    }

    // ───────── G1：四种 delta 边界（O(affected) 段材料化） ─────────

    /// G1 边界 1——Add 新 key：新 key 段出现且只含新贡献；未受影响 key 段按
    /// Arc 继承（零重算）；候选与 full oracle 逐字段一致。
    #[test]
    fn incremental_add_new_key_rebuilds_only_affected_segment() {
        let existing = grant(
            "550e8400-e29b-41d4-a716-446655440030",
            1,
            "learn_subject:1",
            "read",
            "source-g1-add",
        );
        let base = base(vec![existing.clone()]);
        let untouched_key = ProjectionKey::from_grant(&existing).unwrap();
        let untouched_before = base.segment_content(&untouched_key).unwrap();
        let added = grant(
            "550e8400-e29b-41d4-a716-446655440031",
            1,
            "learn_exam:9",
            "read",
            "source-g1-add-new",
        );

        let compiler = AuthorizationCompiler::new();
        let incremental = applied(
            compiler
                .compile_incremental(
                    &base,
                    TARGET_VERSION,
                    dependencies(),
                    vec![GrantDelta::add(added.clone())],
                )
                .unwrap(),
        );
        let added_key = ProjectionKey::from_grant(&added).unwrap();

        let new_segment = incremental
            .state
            .segment_content(&added_key)
            .expect("Add 新 key 必须产生新段");
        assert_eq!(new_segment.grants.len(), 1);
        assert_eq!(new_segment.grants[0].grant_id, added.grant_id);
        assert!(Arc::ptr_eq(
            &untouched_before,
            &incremental.state.segment_content(&untouched_key).unwrap(),
        ));
        assert_eq!(incremental.state.segments.len(), 2);

        let oracle = applied(
            FullCompilerOracle::new()
                .compile(
                    &base,
                    &CompileRequest::for_base(
                        &base,
                        TARGET_VERSION,
                        dependencies(),
                        vec![GrantDelta::add(added)],
                    ),
                )
                .unwrap(),
        );
        assert_eq!(incremental.state, oracle.state);
    }

    /// G1 边界 2——Remove 清空 key：该 key 段整体消失；其他 key 段按 Arc
    /// 继承；墓碑保留在 ledger；候选与 full oracle 逐字段一致。
    #[test]
    fn incremental_remove_clearing_key_drops_segment() {
        let first = grant(
            "550e8400-e29b-41d4-a716-446655440032",
            1,
            "learn_subject:1",
            "read",
            "source-g1-remove",
        );
        let other = grant(
            "550e8400-e29b-41d4-a716-446655440033",
            1,
            "learn_exam:2",
            "read",
            "source-g1-remove-other",
        );
        let base = base(vec![first.clone(), other.clone()]);
        let cleared_key = ProjectionKey::from_grant(&first).unwrap();
        let other_key = ProjectionKey::from_grant(&other).unwrap();
        let other_before = base.segment_content(&other_key).unwrap();

        let compiler = AuthorizationCompiler::new();
        let incremental = applied(
            compiler
                .compile_incremental(
                    &base,
                    TARGET_VERSION,
                    dependencies(),
                    vec![GrantDelta::remove(first.grant_id, GrantRevision::initial())],
                )
                .unwrap(),
        );

        assert!(
            incremental.state.segment_content(&cleared_key).is_none(),
            "Remove 清空 key 后段必须消失"
        );
        assert_eq!(incremental.state.segments.len(), 1);
        assert!(Arc::ptr_eq(
            &other_before,
            &incremental.state.segment_content(&other_key).unwrap(),
        ));
        assert_eq!(
            incremental.state.grant(first.grant_id).unwrap().state,
            GrantState::Removed,
            "墓碑必须保留在 ledger 以维持 CAS/去重语义"
        );

        let oracle = applied(
            FullCompilerOracle::new()
                .compile(
                    &base,
                    &CompileRequest::for_base(
                        &base,
                        TARGET_VERSION,
                        dependencies(),
                        vec![GrantDelta::remove(first.grant_id, GrantRevision::initial())],
                    ),
                )
                .unwrap(),
        );
        assert_eq!(incremental.state, oracle.state);
    }

    /// G1 边界 3——Update 同 key：段原地重算（旧贡献被替换、其余保留、
    /// content hash 变化）；候选与 full oracle 逐字段一致。
    #[test]
    fn incremental_update_same_key_rebuilds_segment_in_place() {
        let first = grant(
            "550e8400-e29b-41d4-a716-446655440034",
            1,
            "learn_subject:1",
            "read",
            "source-g1-upd-a",
        );
        let second = grant(
            "550e8400-e29b-41d4-a716-446655440035",
            1,
            "learn_subject:1",
            "read",
            "source-g1-upd-b",
        );
        let other = grant(
            "550e8400-e29b-41d4-a716-446655440036",
            1,
            "learn_exam:2",
            "read",
            "source-g1-upd-other",
        );
        let base = base(vec![first.clone(), second.clone(), other.clone()]);
        let key = ProjectionKey::from_grant(&first).unwrap();
        let other_key = ProjectionKey::from_grant(&other).unwrap();
        let before = base.segment_content(&key).unwrap();
        let other_before = base.segment_content(&other_key).unwrap();

        let mut updated = first.clone();
        updated.revision = GrantRevision::new(2).unwrap();
        updated.provenance.operation_id = "operation-g1-upd-a2".to_owned();

        let compiler = AuthorizationCompiler::new();
        let incremental = applied(
            compiler
                .compile_incremental(
                    &base,
                    TARGET_VERSION,
                    dependencies(),
                    vec![GrantDelta::update(updated, GrantRevision::initial())],
                )
                .unwrap(),
        );

        let after = incremental.state.segment_content(&key).unwrap();
        assert!(!Arc::ptr_eq(&before, &after), "受影响段必须重算");
        assert_ne!(before.content_hash, after.content_hash);
        assert_eq!(after.grants.len(), 2, "同 key 其余贡献必须保留");
        assert!(after
            .grants
            .iter()
            .any(|value| value.grant_id == first.grant_id
                && value.revision == GrantRevision::new(2).unwrap()));
        assert!(Arc::ptr_eq(
            &other_before,
            &incremental.state.segment_content(&other_key).unwrap(),
        ));

        let oracle = applied(
            FullCompilerOracle::new()
                .compile(
                    &base,
                    &CompileRequest::for_base(
                        &base,
                        TARGET_VERSION,
                        dependencies(),
                        vec![GrantDelta::update(
                            incremental.state.grant(first.grant_id).unwrap().clone(),
                            GrantRevision::initial(),
                        )],
                    ),
                )
                .unwrap(),
        );
        assert_eq!(incremental.state, oracle.state);
    }

    /// G1 加固——Update/Add 携带非 Active 状态的载荷不得进入段：段只承载
    /// Active 贡献（与 build_segments 的 Active 过滤、全量 oracle 逐字节
    /// 一致），否则增量段与全量段分叉（Inactive 贡献被当作有效授权发布）。
    #[test]
    fn incremental_ignores_non_active_state_payloads_in_add_and_update() {
        let existing = grant(
            "550e8400-e29b-41d4-a716-446655440039",
            1,
            "learn_subject:1",
            "read",
            "source-ia-existing",
        );
        let other = grant(
            "550e8400-e29b-41d4-a716-446655440040",
            1,
            "learn_exam:2",
            "read",
            "source-ia-other",
        );
        let base = base(vec![existing.clone(), other.clone()]);
        let key = ProjectionKey::from_grant(&existing).unwrap();

        // Update 把 grant 更新为 REVOKED 状态（CAS 匹配、合法 delta 形状）。
        let mut revoked_update = existing.clone();
        revoked_update.revision = GrantRevision::new(2).unwrap();
        revoked_update.state = GrantState::Revoked;
        // Add 携带 REVOKED 状态（复活语义下允许入 ledger，但不得进段）。
        let mut inactive_add = grant(
            "550e8400-e29b-41d4-a716-446655440041",
            1,
            "learn_exam:3",
            "read",
            "source-ia-add",
        );
        inactive_add.state = GrantState::Revoked;

        let compiler = AuthorizationCompiler::new();
        // Add 携带非 Active 状态在 grant 合同层即被拒（grant.rs：ADD requires
        // an ACTIVE grant）——防线在 delta 合同校验层，materialize 的 Active
        // 过滤是纵深第二层。
        let add_contract = compiler
            .compile_incremental(
                &base,
                TARGET_VERSION,
                dependencies(),
                vec![GrantDelta::add(inactive_add.clone())],
            )
            .unwrap_err();
        assert!(
            matches!(
                add_contract,
                CompilerError::Contract(GrantContractError::InvalidDelta(_))
            ),
            "non-Active Add must be rejected at the grant contract layer"
        );

        // Update 携带 REVOKED 状态（CAS 匹配、合法 delta 形状）——必须由
        // materialize 的 Active 过滤兜底，增量段不得包含该载荷。
        let incremental = applied(
            compiler
                .compile_incremental(
                    &base,
                    TARGET_VERSION,
                    dependencies(),
                    vec![GrantDelta::update(
                        revoked_update.clone(),
                        GrantRevision::initial(),
                    )],
                )
                .unwrap(),
        );

        // 增量段不得包含任何非 Active 贡献：Update-to-Revoked 后该 key 的
        // Active 集为空 → 段消失（与全量 oracle 的 Active 过滤语义一致）。
        assert!(
            incremental.state.segment_content(&key).is_none(),
            "Update-to-Revoked must drop the emptied segment"
        );
        let new_key = ProjectionKey::from_grant(&grant(
            "550e8400-e29b-41d4-a716-446655440041",
            1,
            "learn_exam:3",
            "read",
            "source-ia-add",
        ))
        .unwrap();
        assert!(
            incremental.state.segment_content(&new_key).is_none(),
            "non-Active Add payload must not materialize a segment"
        );

        // 与全量 oracle 逐字段一致（分叉即失败）。oracle 场景仅含合法的
        // Update-to-Revoked delta（非 Active 的 Add 已在合同层拒绝，无法
        // 构造 oracle 场景——其排除本身即防线验证）。
        let oracle = applied(
            FullCompilerOracle::new()
                .compile(
                    &base,
                    &CompileRequest::for_base(
                        &base,
                        TARGET_VERSION,
                        dependencies(),
                        vec![GrantDelta::update(
                            revoked_update.clone(),
                            GrantRevision::initial(),
                        )],
                    ),
                )
                .unwrap(),
        );
        assert_eq!(incremental.state, oracle.state);
    }

    /// G1 边界 4——Update 迁移 key：旧 key 段消失、新 key 段出现、未受影响
    /// 段按 Arc 继承；候选与 full oracle 逐字段一致。
    #[test]
    fn incremental_update_migrating_key_swaps_segments() {
        let moving = grant(
            "550e8400-e29b-41d4-a716-446655440037",
            1,
            "learn_subject:1",
            "read",
            "source-g1-mig",
        );
        let other = grant(
            "550e8400-e29b-41d4-a716-446655440038",
            1,
            "learn_exam:2",
            "read",
            "source-g1-mig-other",
        );
        let base = base(vec![moving.clone(), other.clone()]);
        let old_key = ProjectionKey::from_grant(&moving).unwrap();
        let other_key = ProjectionKey::from_grant(&other).unwrap();
        let other_before = base.segment_content(&other_key).unwrap();

        let mut migrated = moving.clone();
        migrated.revision = GrantRevision::new(2).unwrap();
        migrated.resource = "learn_exam:9".to_owned();

        let compiler = AuthorizationCompiler::new();
        let incremental = applied(
            compiler
                .compile_incremental(
                    &base,
                    TARGET_VERSION,
                    dependencies(),
                    vec![GrantDelta::update(
                        migrated.clone(),
                        GrantRevision::initial(),
                    )],
                )
                .unwrap(),
        );
        let new_key = ProjectionKey::from_grant(&migrated).unwrap();

        assert!(
            incremental.state.segment_content(&old_key).is_none(),
            "Update 迁移 key 后旧 key 段必须消失"
        );
        let new_segment = incremental
            .state
            .segment_content(&new_key)
            .expect("迁移目标 key 必须出现新段");
        assert_eq!(new_segment.grants.len(), 1);
        assert_eq!(new_segment.grants[0].grant_id, moving.grant_id);
        assert!(Arc::ptr_eq(
            &other_before,
            &incremental.state.segment_content(&other_key).unwrap(),
        ));

        let oracle = applied(
            FullCompilerOracle::new()
                .compile(
                    &base,
                    &CompileRequest::for_base(
                        &base,
                        TARGET_VERSION,
                        dependencies(),
                        vec![GrantDelta::update(migrated, GrantRevision::initial())],
                    ),
                )
                .unwrap(),
        );
        assert_eq!(incremental.state, oracle.state);
    }

    /// G1/G2 链式增量：连续多批 delta（Add 新 key、Update 迁移 key、Remove
    /// 清空 key）后，semantic hash 与段集合必须和一次性全量构建逐字节一致，
    /// 证明跨批 Arc 继承链上的段 hash 聚合不漂移。
    #[test]
    fn chained_incremental_batches_match_single_full_build() {
        let alpha = grant(
            "550e8400-e29b-41d4-a716-446655440039",
            1,
            "learn_subject:1",
            "read",
            "source-chain-a",
        );
        let beta = grant(
            "550e8400-e29b-41d4-a716-44665544003a",
            1,
            "learn_subject:2",
            "read",
            "source-chain-b",
        );
        let gamma = grant(
            "550e8400-e29b-41d4-a716-44665544003b",
            1,
            "learn_exam:3",
            "read",
            "source-chain-c",
        );
        let base = base(vec![alpha.clone(), beta.clone(), gamma.clone()]);

        let delta_add = grant(
            "550e8400-e29b-41d4-a716-44665544003c",
            1,
            "learn_exam:4",
            "read",
            "source-chain-d",
        );
        let mut migrated_beta = beta.clone();
        migrated_beta.revision = GrantRevision::new(2).unwrap();
        migrated_beta.resource = "learn_exam:5".to_owned();

        let compiler = AuthorizationCompiler::new();
        let step1 = applied(
            compiler
                .compile_incremental(
                    &base,
                    112,
                    dependencies(),
                    vec![GrantDelta::add(delta_add.clone())],
                )
                .unwrap(),
        );
        let step2 = applied(
            compiler
                .compile_incremental(
                    &step1.state,
                    113,
                    dependencies(),
                    vec![GrantDelta::update(
                        migrated_beta.clone(),
                        GrantRevision::initial(),
                    )],
                )
                .unwrap(),
        );
        let step3 = applied(
            compiler
                .compile_incremental(
                    &step2.state,
                    114,
                    dependencies(),
                    vec![GrantDelta::remove(gamma.grant_id, GrantRevision::initial())],
                )
                .unwrap(),
        );

        // 终态 ledger：alpha active rev1、beta 迁移后 rev2、gamma 墓碑 rev2、
        // delta_add active rev1。一次性全量构建必须得到同一语义 hash 与段集。
        let mut final_gamma = gamma.clone();
        final_gamma.revision = GrantRevision::new(2).unwrap();
        final_gamma.state = GrantState::Removed;
        let expected = HotState::from_grants(
            tenant(),
            114,
            vec![alpha, migrated_beta, final_gamma, delta_add],
            dependencies(),
        )
        .unwrap();
        assert_eq!(step3.state.semantic_hash, expected.semantic_hash);
        assert_eq!(step3.state.segments, expected.segments);
        assert_eq!(step3.state.active_grants(), expected.active_grants());
    }

    // ───────── G2：semantic hash 版本绑定语义（v4） ─────────

    /// v4 语义：Inactive/墓碑 ledger 记录不产生授权，"Active 集相同"的状态
    /// 给出相同 semantic hash；同 version 下任何内容差异（含 Active 集差异）
    /// 都不改变 hash——v4 是版本绑定标识，内容完整性由 manifest digest（绑
    /// 全部段 content hash）+ 读时逐段 sha256 重算承担，"同 version 不同内容"
    /// 被发布 CAS + content-addressed 排除。失效栅栏由 version 推进承载。
    #[test]
    fn inactive_and_tombstone_records_do_not_change_semantic_hash() {
        let active = grant(
            "550e8400-e29b-41d4-a716-44665544003d",
            1,
            "learn_subject:1",
            "read",
            "source-g2-active",
        );
        let mut revoked = grant(
            "550e8400-e29b-41d4-a716-44665544003e",
            1,
            "learn_exam:2",
            "read",
            "source-g2-tombstone",
        );
        revoked.state = GrantState::Revoked;
        let mut removed = grant(
            "550e8400-e29b-41d4-a716-44665544003f",
            1,
            "learn_exam:3",
            "read",
            "source-g2-tombstone",
        );
        removed.state = GrantState::Removed;

        let state_active_only = base(vec![active.clone()]);
        let state_with_revoked = base(vec![active.clone(), revoked]);
        let state_with_removed = base(vec![active, removed]);

        assert_eq!(
            state_active_only.semantic_hash, state_with_revoked.semantic_hash,
            "REVOKED 墓碑差异不得改变 semantic hash（v3/v4 语义一致）"
        );
        assert_eq!(
            state_active_only.semantic_hash, state_with_removed.semantic_hash,
            "REMOVED 墓碑差异不得改变 semantic hash（v3/v4 语义一致）"
        );
        assert_eq!(state_active_only.segments, state_with_revoked.segments);
        assert_eq!(state_active_only.segments, state_with_removed.segments);
        assert_eq!(
            state_with_revoked.all_grants().len(),
            2,
            "墓碑保留在 ledger"
        );
        assert_eq!(
            state_with_revoked.active_grants().len(),
            1,
            "墓碑不产生授权"
        );

        // v4 反向：同 version 下 Active 集变化不再直接改变 semantic hash
        // （版本绑定标识，见测试头注释）；失效栅栏由 version 推进承载。
        let extra = grant(
            "550e8400-e29b-41d4-a716-446655440040",
            1,
            "learn_exam:4",
            "read",
            "source-g2-extra",
        );
        let state_with_extra_active = base(vec![
            grant(
                "550e8400-e29b-41d4-a716-44665544003d",
                1,
                "learn_subject:1",
                "read",
                "source-g2-active",
            ),
            extra,
        ]);
        assert_eq!(
            state_active_only.semantic_hash, state_with_extra_active.semantic_hash,
            "v4 semantic hash 在同 version 下与内容无关（版本绑定标识）"
        );

        // version 推进必须改变 hash：编译入口强制 target = base + 1，因此
        // 任何成功发布都推进 version → hash 必变（失效栅栏语义保持）。
        let advanced = HotState::from_grants(
            tenant(),
            CURRENT_VERSION + 1,
            vec![grant(
                "550e8400-e29b-41d4-a716-44665544003d",
                1,
                "learn_subject:1",
                "read",
                "source-g2-active",
            )],
            dependencies(),
        )
        .unwrap();
        assert_ne!(
            state_active_only.semantic_hash, advanced.semantic_hash,
            "version 推进必须改变 v4 semantic hash（失效栅栏由版本承载）"
        );

        // dependency_hash 变化必须改变 hash：依赖物料变化仍驱动失效
        // （DependencyChanged 全量重建语义保持）。
        let drifted_dependencies = DependencyVector::new(vec![
            DependencyVersion::new("card", 5, 0).unwrap(),
            DependencyVersion::new("rule-set", 3, 1).unwrap(),
        ])
        .unwrap();
        let dependency_drifted = HotState::from_grants(
            tenant(),
            CURRENT_VERSION,
            vec![grant(
                "550e8400-e29b-41d4-a716-44665544003d",
                1,
                "learn_subject:1",
                "read",
                "source-g2-active",
            )],
            drifted_dependencies,
        )
        .unwrap();
        assert_ne!(
            state_active_only.semantic_hash, dependency_drifted.semantic_hash,
            "dependency_hash 变化必须改变 v4 semantic hash"
        );
        assert_ne!(
            state_active_only.dependency_hash, dependency_drifted.dependency_hash,
            "依赖漂移必须改变 dependency_hash（对牌栅栏输入）"
        );

        // 同 version 同字段 → hash 稳定（重复构建等值，fence 对牌依据）。
        let rebuilt_identically = base(vec![grant(
            "550e8400-e29b-41d4-a716-44665544003d",
            1,
            "learn_subject:1",
            "read",
            "source-g2-active",
        )]);
        assert_eq!(
            state_active_only.semantic_hash, rebuilt_identically.semantic_hash,
            "同 version/tenant/依赖的重复构建必须给出相同 hash"
        );
    }

    /// v4 结构语义（O(1) 单键变更的根基）：HotState.clone 与 factored ledger
    /// 各层/segments 的持久化结构 clone 是 O(1) 结构共享——clone 后向新 map
    /// 增/删不影响旧 map，旧 HotState 的 ledger/段集保持不可变（持久化数据
    /// 结构语义锚定）。
    #[test]
    fn hot_state_maps_are_structurally_shared_and_persistent() {
        let first = grant(
            "550e8400-e29b-41d4-a716-446655440043",
            1,
            "learn_subject:1",
            "read",
            "source-v4-share-a",
        );
        let base_state = base(vec![first.clone()]);
        let original_record_count = base_state.ruleset_records.len();
        let original_shared_count = base_state.shared_entries.len();
        let original_binding_count = base_state.bindings.len();
        let original_segment_count = base_state.segments.len();

        // 记录层：clone + insert → 旧 map 不受影响；remove 亦然。
        let mut cloned_records = base_state.ruleset_records.clone();
        let added = grant(
            "550e8400-e29b-41d4-a716-446655440044",
            1,
            "learn_exam:2",
            "read",
            "source-v4-share-b",
        );
        let added_record = RuleSetGrantRecord {
            revision: added.revision,
            state: added.state,
            binding_layer: added.binding_layer,
            card_id: added.card_id,
            user_id: added.user_id,
            binding_id: added.provenance.binding_id.clone().unwrap(),
            operation_id: added.provenance.operation_id.clone(),
            event_id: added.provenance.event_id.clone(),
            actor_user_id: added.provenance.actor_user_id,
            entry: base_state
                .shared_entries
                .values()
                .next()
                .expect("shared entry exists")
                .clone(),
        };
        cloned_records.insert(added.grant_id, added_record);
        assert_eq!(cloned_records.len(), original_record_count + 1);
        assert_eq!(base_state.ruleset_records.len(), original_record_count);
        assert!(base_state.ruleset_records.get(&added.grant_id).is_none());
        let mut removed_records = base_state.ruleset_records.clone();
        removed_records.remove(&first.grant_id);
        assert!(removed_records.get(&first.grant_id).is_none());
        assert!(base_state.ruleset_records.get(&first.grant_id).is_some());

        // 共享层/绑定层：clone + 写不影响旧 map（持久化结构语义）。
        let mut cloned_shared = base_state.shared_entries.clone();
        let shared_key = base_state
            .shared_entries
            .keys()
            .next()
            .expect("shared entry exists")
            .clone();
        cloned_shared.remove(&shared_key);
        assert!(cloned_shared.get(&shared_key).is_none());
        assert_eq!(base_state.shared_entries.len(), original_shared_count);
        let mut cloned_bindings = base_state.bindings.clone();
        cloned_bindings.remove(&CARD_ID);
        assert!(cloned_bindings.get(&CARD_ID).is_none());
        assert_eq!(base_state.bindings.len(), original_binding_count);

        // segments：clone + remove → 旧 map 不受影响（Arc 内容仍被两边共享）。
        let key = ProjectionKey::from_grant(&first).unwrap();
        let mut cloned_segments = base_state.segments.clone();
        let segment_before = base_state.segment_content(&key).unwrap();
        cloned_segments.remove(&key);
        assert!(cloned_segments.get(&key).is_none());
        assert_eq!(base_state.segments.len(), original_segment_count);
        assert_eq!(
            base_state.segment_content(&key).as_ref(),
            Some(&segment_before)
        );

        // HotState::clone 整体结构共享：clone 与原状态指向同一 SegmentContent
        // Arc（O(1) clone 的结构共享证据）。
        let state_clone = base_state.clone();
        assert!(Arc::ptr_eq(
            &state_clone.segment_content(&key).unwrap(),
            &segment_before
        ));

        // clone 后按增量路径推进 clone，base 的 version/ledger/段集保持不变
        // （base 不可变语义；增量候选是新的持久化结构）。
        let candidate = applied(
            AuthorizationCompiler::new()
                .compile_incremental(
                    &state_clone,
                    TARGET_VERSION,
                    dependencies(),
                    vec![GrantDelta::add(grant(
                        "550e8400-e29b-41d4-a716-446655440045",
                        1,
                        "learn_exam:9",
                        "read",
                        "source-v4-share-c",
                    ))],
                )
                .unwrap(),
        );
        assert_eq!(base_state.version, CURRENT_VERSION);
        assert_eq!(base_state.ruleset_records.len(), original_record_count);
        assert_eq!(base_state.segments.len(), original_segment_count);
        assert_eq!(candidate.state.version, TARGET_VERSION);
    }

    /// v4 O(1) 语义回归：同 version/tenant/依赖下，N=1 与 N=2000 的 ledger
    /// 给出相同 v4 semantic hash（版本绑定标识与规模无关）；增量单键变更的
    /// 正确性由 G1 四种 delta 边界测试锚定，此处锚定"hash 更新不随段数/
    /// 记录数增长"（O(1) 字段输入）。
    #[test]
    fn semantic_hash_v4_is_version_bound_and_scale_independent() {
        let make_active = |index: u32| {
            grant(
                &format!("00000000-0000-4000-8000-{index:012x}"),
                1,
                &format!("learn_scale:{index}"),
                "read",
                "source-v4-scale",
            )
        };
        let small =
            HotState::from_grants(tenant(), 77, vec![make_active(0)], dependencies()).unwrap();
        let large_grants: Vec<CanonicalGrant> = (0..2000u32).map(make_active).collect();
        let large = HotState::from_grants(tenant(), 77, large_grants, dependencies()).unwrap();
        // 版本绑定标识与 ledger/段规模无关：同 version/tenant/依赖 → 同 hash。
        assert_eq!(small.semantic_hash, large.semantic_hash);
        assert_eq!(small.segments.len(), 1);
        assert_eq!(large.segments.len(), 2000);
    }

    /// v4 迁移语义：旧编译器版本（v3）产出的 base 遇 v4 编译器必须显式
    /// FullRebuildRequired(CompilerVersionMismatch)；全量重建一次后 base 为
    /// v4，后续精确 delta 恢复增量路径。
    #[test]
    fn compiler_version_mismatch_requires_full_rebuild_then_resumes_incremental() {
        let value = grant(
            "550e8400-e29b-41d4-a716-446655440041",
            1,
            "learn_subject:1",
            "read",
            "source-v3-mig",
        );
        let legacy_base = HotState::from_grants_with_compiler(
            tenant(),
            CURRENT_VERSION,
            vec![value.clone()],
            dependencies(),
            "phase2-authorization-kernel-v3",
        )
        .unwrap();
        let added = grant(
            "550e8400-e29b-41d4-a716-446655440042",
            1,
            "learn_exam:5",
            "read",
            "source-v3-new",
        );

        let compiler = AuthorizationCompiler::new();
        let outcome = compiler
            .compile_incremental(
                &legacy_base,
                TARGET_VERSION,
                dependencies(),
                vec![GrantDelta::add(added.clone())],
            )
            .unwrap();
        assert!(matches!(
            outcome,
            CompileOutcome::FullRebuildRequired(FullRebuildRequired {
                reason: FullRebuildReason::CompilerVersionMismatch,
                ..
            })
        ));

        let rebuilt = applied(
            compiler
                .full_rebuild(
                    &legacy_base,
                    TARGET_VERSION,
                    dependencies(),
                    vec![GrantDelta::add(added)],
                )
                .unwrap(),
        );
        assert_eq!(rebuilt.mode, ProjectionCompileMode::FullRebuild);
        assert_eq!(rebuilt.state.compiler_version, COMPILER_VERSION);

        let resumed = applied(
            compiler
                .compile_incremental(
                    &rebuilt.state,
                    113,
                    dependencies(),
                    vec![GrantDelta::remove(value.grant_id, GrantRevision::initial())],
                )
                .unwrap(),
        );
        assert_eq!(resumed.mode, ProjectionCompileMode::Incremental);
        assert!(resumed
            .state
            .segment_content(&ProjectionKey::from_grant(&value).unwrap())
            .is_none());
    }

    #[test]
    fn sha256_helper_has_standard_digest_shape() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(sha256_hex(b"abc").len(), 64);
    }

    // ───────── Factored 共享层：去重 / parity / 绑定层不变式 ─────────

    /// 多卡规则集 grant 构造器：同一 (source_id, source_entry, resource, action)
    /// 跨卡复用，仅归属字段（card/user/binding/event）不同——对齐 RULE_SET
    /// fanout 物化形态（Phase 1 验证的代码级同构）。
    fn card_rule_set_grant(
        index: u64,
        card_id: i64,
        user_id: i64,
        source_id: &str,
        entry_id: &str,
        resource: &str,
    ) -> CanonicalGrant {
        CanonicalGrant {
            grant_id: GrantId::parse(&format!("00000000-0000-4000-8000-{index:012x}")).unwrap(),
            revision: GrantRevision::initial(),
            state: GrantState::Active,
            source_kind: GrantSourceKind::RuleSet,
            binding_layer: BindingLayer::Base,
            tenant: tenant(),
            card_id,
            user_id,
            resource: resource.to_owned(),
            action: "read".to_owned(),
            effect: GrantEffect::Allow,
            validity: ValidityWindow::perpetual(),
            provenance: GrantProvenance {
                source_id: source_id.to_owned(),
                source_entry: Some(entry_id.to_owned()),
                binding_id: Some(format!("binding-{card_id}-{entry_id}")),
                delegation_id: None,
                operation_id: format!("operation-{card_id}-{entry_id}"),
                event_id: Some(format!("event-{card_id}-{entry_id}")),
                actor_user_id: Some(user_id),
            },
        }
    }

    fn direct_grant(
        id: &str,
        revision: u64,
        resource: &str,
        action: &str,
        source: &str,
    ) -> CanonicalGrant {
        CanonicalGrant {
            grant_id: GrantId::parse(id).unwrap(),
            revision: GrantRevision::new(revision).unwrap(),
            state: GrantState::Active,
            source_kind: GrantSourceKind::Direct,
            binding_layer: BindingLayer::None,
            tenant: tenant(),
            card_id: CARD_ID,
            user_id: USER_ID,
            resource: resource.to_owned(),
            action: action.to_owned(),
            effect: GrantEffect::Allow,
            validity: ValidityWindow::perpetual(),
            provenance: GrantProvenance {
                source_id: source.to_owned(),
                source_entry: None,
                binding_id: None,
                delegation_id: None,
                operation_id: format!("operation-{source}"),
                event_id: Some(format!("event-{source}")),
                actor_user_id: Some(USER_ID),
            },
        }
    }

    /// 共享性去重：N 卡 × E 条目共享同一 (source_id, source_entry) 时，共享层
    /// 恰好保存 E 份内容（Phase 1 前提 → 实际去重收益），记录层保留 N×E 条
    /// per-grant 生命周期，绑定层计数正确，且每卡段只携带本卡归属（无跨卡
    /// 泄漏）。导出 grant 与构造输入逐字节相等（组装纯函数 parity）。
    #[test]
    fn factored_shared_layers_deduplicate_multi_card_rule_sets() {
        const CARDS: [i64; 3] = [101, 102, 103];
        let grants: Vec<CanonicalGrant> = CARDS
            .iter()
            .enumerate()
            .flat_map(|(card_index, card_id)| {
                let user_id = 1000 + *card_id;
                [
                    card_rule_set_grant(
                        (card_index * 2) as u64 + 1,
                        *card_id,
                        user_id,
                        "rs-1",
                        "e1",
                        "learn_subject:1",
                    ),
                    card_rule_set_grant(
                        (card_index * 2) as u64 + 2,
                        *card_id,
                        user_id,
                        "rs-1",
                        "e2",
                        "learn_exam:2",
                    ),
                ]
            })
            .collect();

        let state = base(grants.clone());

        // 共享层：2 个 entry 内容各存一份（6 条 grant → 2 条共享条目）。
        assert_eq!(state.shared_entry_count(), 2);
        assert_eq!(state.ruleset_records.len(), 6);
        assert_eq!(state.private_grants.len(), 0);
        assert_eq!(state.all_grants().len(), 6);
        assert_eq!(state.active_grants().len(), 6);

        // 绑定层：每卡对 rs-1 的引用计数 = 其 entry 记录数。
        for card_id in CARDS {
            assert_eq!(
                state.card_rule_set_sources(card_id),
                vec![("rs-1", 2)],
                "每卡对 rs-1 恰有两个 entry 记录"
            );
        }
        assert_eq!(state.bindings.len(), 3, "三张卡各自持有绑定行");

        // 段：每卡每 entry 一个 key（6 段）；每段内 grant 的归属必须等于 key
        // 的归属（虚拟化归属正确，无跨卡泄漏）。
        assert_eq!(state.segments.len(), 6);
        for (key, segment) in state.segments.iter() {
            assert!(!segment.grants.is_empty());
            for grant in &segment.grants {
                assert_eq!(grant.card_id, key.card_id, "段内归属必须与 key 卡一致");
                assert_eq!(grant.user_id, key.user_id, "段内归属必须与 key 用户一致");
            }
        }

        // 导出 parity：组装 grant 与构造输入逐字节相等（含 provenance）。
        for grant in &grants {
            assert_eq!(
                state.grant(grant.grant_id).as_ref(),
                Some(grant),
                "记录层组装必须复现原 grant"
            );
        }
    }

    /// 退化容忍（fail-safe）：同 (source_id, source_entry) 但内容（validity）
    /// 不同时，共享层退化为两条目，各卡段携带各自内容，无编译错误、无跨卡
    /// 污染——评估等价性不依赖收敛前提（设计文档 §5.2）。
    #[test]
    fn factored_shared_content_divergence_degrades_sharing_without_leakage() {
        let card_a = card_rule_set_grant(1, 201, 2001, "rs-1", "e1", "learn_subject:1");
        let mut card_b = card_rule_set_grant(2, 202, 2002, "rs-1", "e1", "learn_subject:1");
        card_b.validity = ValidityWindow::between(1_700_000_000, 1_800_000_000);
        let state = base(vec![card_a.clone(), card_b.clone()]);

        assert_eq!(
            state.shared_entry_count(),
            2,
            "内容分歧必须退化为两条共享条目"
        );
        let key_a = ProjectionKey::from_grant(&card_a).unwrap();
        let key_b = ProjectionKey::from_grant(&card_b).unwrap();
        assert_eq!(
            state.segment_content(&key_a).unwrap().grants[0].validity,
            card_a.validity,
            "卡 A 段必须携带自身内容"
        );
        assert_eq!(
            state.segment_content(&key_b).unwrap().grants[0].validity,
            card_b.validity,
            "卡 B 段必须携带自身内容"
        );
        assert_ne!(
            state.segment_content(&key_a).unwrap().grants[0],
            state.segment_content(&key_b).unwrap().grants[0]
        );
        assert_eq!(state.grant(card_a.grant_id).as_ref(), Some(&card_a));
        assert_eq!(state.grant(card_b.grant_id).as_ref(), Some(&card_b));
    }

    /// 评估等价性 parity：factored 多卡状态与"逐卡单卡参考模型"在段内容与
    /// 导出 grant 上完全一致（factored 评估 ≡ per-card 评估的安全网）。
    #[test]
    fn factored_multi_card_state_matches_per_card_reference_model() {
        let card_a_grants = vec![
            card_rule_set_grant(1, 301, 3001, "rs-1", "e1", "learn_subject:1"),
            card_rule_set_grant(2, 301, 3001, "rs-1", "e2", "learn_exam:2"),
        ];
        let card_b_private = direct_grant(
            "00000000-0000-4000-8000-000000000003",
            1,
            "learn_direct:9",
            "write",
            "direct-b",
        );
        let card_b_grants = vec![
            card_rule_set_grant(4, 302, 3002, "rs-1", "e1", "learn_subject:1"),
            card_b_private.clone(),
        ];
        let mut all = card_a_grants.clone();
        all.extend(card_b_grants.clone());
        let factored = base(all);

        // 参考模型：每卡独立构建单卡 HotState（per-card 语义）。
        let reference_a = HotState::from_grants(
            tenant(),
            CURRENT_VERSION,
            card_a_grants.clone(),
            dependencies(),
        )
        .unwrap();
        let reference_b = HotState::from_grants(
            tenant(),
            CURRENT_VERSION,
            card_b_grants.clone(),
            dependencies(),
        )
        .unwrap();

        // 每卡的段在两个模型中逐字节一致（含 content hash 与贡献排序）。
        for (reference, grants) in [
            (&reference_a, &card_a_grants),
            (&reference_b, &card_b_grants),
        ] {
            for grant in grants {
                let key = ProjectionKey::from_grant(grant).unwrap();
                assert_eq!(
                    factored.segment_content(&key).as_deref(),
                    reference.segment_content(&key).as_deref(),
                    "卡 {} 的段必须与单卡参考模型一致",
                    key.card_id
                );
            }
        }
        // factored 状态的段 key 集 = 各卡参考模型 key 集的并集。
        let mut expected_keys: BTreeSet<ProjectionKey> = BTreeSet::new();
        for reference in [&reference_a, &reference_b] {
            expected_keys.extend(reference.segment_keys().into_iter().cloned());
        }
        let factored_keys: BTreeSet<ProjectionKey> =
            factored.segment_keys().into_iter().cloned().collect();
        assert_eq!(factored_keys, expected_keys);

        // 导出集一致（按 GrantId 排序的 owned 比较）。
        let mut reference_all = reference_a.all_grants();
        reference_all.extend(reference_b.all_grants());
        reference_all.sort_by_key(|left| left.grant_id);
        assert_eq!(factored.all_grants(), reference_all);
    }

    /// 绑定层不变式：绑定层 ≡ 记录层按 (card, source_id) 分组的派生结果；
    /// Update 迁移 source_id 时计数正确移动；墓碑保留绑定事实（记录仍在）。
    #[test]
    fn factored_binding_layer_tracks_ledger_facts() {
        let card_a_1 = card_rule_set_grant(1, 401, 4001, "rs-1", "e1", "learn_subject:1");
        let card_a_2 = card_rule_set_grant(2, 401, 4001, "rs-1", "e2", "learn_exam:2");
        let card_b_rs1 = card_rule_set_grant(3, 402, 4002, "rs-1", "e1", "learn_subject:1");
        let card_b_rs2 = card_rule_set_grant(4, 402, 4002, "rs-2", "e9", "learn_exam:9");
        let state = base(vec![
            card_a_1.clone(),
            card_a_2.clone(),
            card_b_rs1.clone(),
            card_b_rs2.clone(),
        ]);
        assert_eq!(state.card_rule_set_sources(401), vec![("rs-1", 2)]);
        assert_eq!(
            state.card_rule_set_sources(402),
            vec![("rs-1", 1), ("rs-2", 1)]
        );

        // Update 把卡 B 的 rs-2 记录迁移到 rs-3（同 grant_id，内容变化）：
        // 绑定计数 rs-2 → rs-3 移动；受影响 key 只含该记录自身 key。
        let mut migrated = card_b_rs2.clone();
        migrated.revision = GrantRevision::new(2).unwrap();
        migrated.provenance.source_id = "rs-3".to_owned();
        migrated.provenance.source_entry = Some("e3".to_owned());
        migrated.resource = "learn_exam:3".to_owned();
        let compiler = AuthorizationCompiler::new();
        let candidate = applied(
            compiler
                .compile_incremental(
                    &state,
                    TARGET_VERSION,
                    dependencies(),
                    vec![GrantDelta::update(
                        migrated.clone(),
                        GrantRevision::initial(),
                    )],
                )
                .unwrap(),
        );
        assert_eq!(
            candidate.state.card_rule_set_sources(402),
            vec![("rs-1", 1), ("rs-3", 1)]
        );
        assert_eq!(candidate.plan.affected_keys.len(), 2, "旧 key + 新 key");
        assert_eq!(
            candidate.state.shared_entry_count(),
            4,
            "rs-2 旧内容条目残留，rs-3 新增"
        );
        assert_eq!(
            candidate.state.grant(migrated.grant_id).as_ref(),
            Some(&migrated),
            "迁移后组装仍逐字节复现载荷"
        );

        // 墓碑：REVOKE 卡 A 的 e1 记录不改变绑定计数（记录保留）。
        let revoked = applied(
            compiler
                .compile_incremental(
                    &candidate.state,
                    CURRENT_VERSION + 2,
                    dependencies(),
                    vec![GrantDelta::revoke(
                        card_a_1.grant_id,
                        GrantRevision::initial(),
                    )],
                )
                .unwrap(),
        );
        assert_eq!(revoked.state.card_rule_set_sources(401), vec![("rs-1", 2)]);
        assert_eq!(
            revoked
                .state
                .ruleset_records
                .get(&card_a_1.grant_id)
                .unwrap()
                .state,
            GrantState::Revoked
        );
        assert_eq!(revoked.state.active_grants().len(), 3);
    }

    /// 多卡共享规则集的增量：单卡单记录的变更只重建该卡的段，其他卡的段按
    /// Arc 继承，共享条目按 Arc 复用（内容未变 → intern 命中），且候选与
    /// full oracle 全字段 parity（含 factored 各层）。
    #[test]
    fn factored_incremental_update_touches_only_own_card_and_matches_oracle() {
        let grants: Vec<CanonicalGrant> = [501, 502, 503]
            .iter()
            .enumerate()
            .map(|(index, card_id)| {
                card_rule_set_grant(
                    index as u64 + 1,
                    *card_id,
                    5000 + card_id,
                    "rs-1",
                    "e1",
                    "learn_subject:1",
                )
            })
            .collect();
        let base_state = base(grants.clone());
        let shared_before = base_state
            .shared_entries
            .values()
            .next()
            .expect("shared entry")
            .clone();
        let other_key = ProjectionKey::from_grant(&grants[0]).unwrap();
        let other_segment = base_state.segment_content(&other_key).unwrap();

        let mut updated = grants[1].clone();
        updated.revision = GrantRevision::new(2).unwrap();
        updated.provenance.operation_id = "operation-501-e1-rev2".to_owned();

        let compiler = AuthorizationCompiler::new();
        let incremental = applied(
            compiler
                .compile_incremental(
                    &base_state,
                    TARGET_VERSION,
                    dependencies(),
                    vec![GrantDelta::update(
                        updated.clone(),
                        GrantRevision::initial(),
                    )],
                )
                .unwrap(),
        );

        // 受影响面：只有卡 502 的 key；其他卡段 Arc 原样继承。
        assert_eq!(incremental.plan.affected_keys.len(), 1);
        assert_eq!(incremental.plan.affected_keys[0].card_id, 502);
        assert!(Arc::ptr_eq(
            &other_segment,
            &incremental.state.segment_content(&other_key).unwrap()
        ));
        // 内容未变 → 共享层 intern 命中，Arc 同一。
        let shared_after = incremental
            .state
            .shared_entries
            .values()
            .find(|entry| entry.content_hash == shared_before.content_hash)
            .expect("shared entry survives");
        assert!(Arc::ptr_eq(&shared_before, shared_after));
        assert_eq!(incremental.state.shared_entry_count(), 1);
        assert_eq!(
            incremental.state.bindings.get(&501).map(|c| c.len()),
            Some(1)
        );

        // oracle parity：全字段（含共享层/绑定层/记录层/段）逐字节一致。
        let oracle = applied(
            FullCompilerOracle::new()
                .compile(
                    &base_state,
                    &CompileRequest::for_base(
                        &base_state,
                        TARGET_VERSION,
                        dependencies(),
                        vec![GrantDelta::update(updated, GrantRevision::initial())],
                    ),
                )
                .unwrap(),
        );
        assert_eq!(incremental.state, oracle.state);
    }

    /// 卡私有层回归：DIRECT grant 的 Add/Update/Remove 全走私有层（记录层与
    /// 绑定层不受影响），CAS/墓碑语义与 per-card 形态一致。
    #[test]
    fn factored_private_layer_keeps_direct_grant_semantics() {
        let first = direct_grant(
            "00000000-0000-4000-8000-000000000011",
            1,
            "learn_direct:1",
            "read",
            "direct-one",
        );
        let base_state = base(vec![first.clone()]);
        assert_eq!(base_state.private_grants.len(), 1);
        assert_eq!(base_state.ruleset_records.len(), 0);
        assert!(base_state.bindings.is_empty());
        assert_eq!(base_state.shared_entry_count(), 0);
        let key = ProjectionKey::from_grant(&first).unwrap();
        let segment_before = base_state.segment_content(&key).unwrap();

        let mut updated = first.clone();
        updated.revision = GrantRevision::new(2).unwrap();
        // 非 alias 动作（write 是别名源，会触发 ActionAliasImpact 全量降级）。
        updated.action = "publish".to_owned();
        let compiler = AuthorizationCompiler::new();
        let candidate = applied(
            compiler
                .compile_incremental(
                    &base_state,
                    TARGET_VERSION,
                    dependencies(),
                    vec![GrantDelta::update(
                        updated.clone(),
                        GrantRevision::initial(),
                    )],
                )
                .unwrap(),
        );
        assert_eq!(candidate.state.private_grants.len(), 1);
        assert_eq!(
            candidate.state.grant(first.grant_id).as_ref(),
            Some(&updated)
        );
        assert!(
            candidate.state.segment_content(&key).is_none(),
            "旧 key 段消失"
        );
        assert_eq!(
            candidate
                .state
                .segment_content(&ProjectionKey::from_grant(&updated).unwrap())
                .unwrap()
                .grants
                .len(),
            1
        );
        assert!(Arc::ptr_eq(
            &segment_before,
            &base_state.segment_content(&key).unwrap()
        ));

        let removed = applied(
            compiler
                .compile_incremental(
                    &candidate.state,
                    CURRENT_VERSION + 2,
                    dependencies(),
                    vec![GrantDelta::remove(
                        first.grant_id,
                        GrantRevision::new(2).unwrap(),
                    )],
                )
                .unwrap(),
        );
        assert_eq!(removed.state.private_grants.len(), 1, "墓碑保留在私有层");
        assert_eq!(
            removed.state.grant(first.grant_id).unwrap().state,
            GrantState::Removed
        );
        assert_eq!(removed.state.active_grants().len(), 0);
        assert!(removed.state.segments.is_empty());
    }

    /// 跨租户 delta fail-closed：与 base 租户不一致的 Add/Update 在 delta 边界
    /// 被显式拒绝（TenantMismatch），绝不进入 ledger（与 from_grants 的拒绝
    /// 语义对齐）。
    #[test]
    fn factored_delta_tenant_mismatch_is_explicit_conflict() {
        let first = card_rule_set_grant(1, 601, 6001, "rs-1", "e1", "learn_subject:1");
        let base_state = base(vec![first]);

        let mut foreign = card_rule_set_grant(2, 602, 6002, "rs-1", "e1", "learn_subject:1");
        foreign.tenant = TenantScope::new(TENANT_ID + 1, None).unwrap();
        let outcome = AuthorizationCompiler::new()
            .compile_incremental(
                &base_state,
                TARGET_VERSION,
                dependencies(),
                vec![GrantDelta::add(foreign)],
            )
            .unwrap();
        assert!(matches!(
            outcome,
            CompileOutcome::Conflict(CompilerConflict::TenantMismatch { .. })
        ));
    }
}
