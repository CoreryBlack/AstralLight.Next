//! ORG_SCOPE 纯编译器内核（Phase 2 default-off，types/DB 合同见
//! `astral_types::org_scope` 与 implementation-contract）。
//!
//! 职责（types/compiler owner）：
//! - 从 DB 已证明的批准事实快照（[`OrgCompileInput`]）编译单元证据状态：
//!   父授权解析（精确 revision）、范围包含证明、本地 mask 剪裁、provenance 链；
//! - HAMT（`im::HashMap`）贡献/桶结构：O(1) 结构共享 clone + 未变段 `Arc` 复用，
//!   增量编译只重算受影响桶（祖先差量依赖由调用方以完整输入快照呈现，
//!   编译器按 ledger diff 求受影响 key；mask/树/依赖/直接父 publication 身份
//!   变化保守全量重算）；
//! - full oracle（全量重建）与增量路径必须逐字节等价（parity 测试锚定）；
//! - readonly 匹配索引 [`OrgQueryIndex`]：按精确/类型/全局通配 + write 别名
//!   返回有界确定性候选桶，请求级身份/有效期/主体过滤 fail-closed。
//!
//! 编译代次 = `node.generation`（node 每次相关 mutation 前进；publication 与
//! node 头栅栏逐项相等，由 [`OrgAdmissionEvidence::validate`] 强制）。
//! 编译器绝不产生授权：PENDING（未对账 mask/缺失或漂移父授权/不可证明范围）
//! 与 Conflict（结构合同破坏）都绝不静默放行。

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use astral_types::org_scope::{
    org_action_matches, org_build_segment, org_contribution_matches_request,
    org_decode_segment_content, org_dependency_digest_hex, org_grant_revision_compatible,
    org_manifest_digest_hex, org_resource_matches, org_scope_covers, org_segment_digest_hex,
    OrgCompileInput, OrgContribution, OrgDependency, OrgError, OrgErrorCode, OrgGrant, OrgGrantRef,
    OrgManifestDigestMaterial, OrgMask, OrgNode, OrgPendingCode, OrgPendingItem, OrgPendingReport,
    OrgProvenance, OrgPublication, OrgReadRequest, OrgScopeKey, OrgSegmentContent,
    OrgSubjectFilter,
};

/// ORG_SCOPE 编译器版本戳（写入 publication.compiler_version；语义变化必须升版）。
pub const ORG_COMPILER_VERSION: &str = "org-compiler-v1";

// ─────────────────────────────────────────────────────────────────────────────
// 编译器内部段单元与编译状态
// ─────────────────────────────────────────────────────────────────────────────

/// 编译器内的段单元：typed 内容 + 内容摘要（wire `index` 在渲染 publication 时分配）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgSegmentCell {
    pub key: OrgScopeKey,
    pub digest_hex: String,
    pub contributions: Vec<OrgContribution>,
}

/// 直接父 publication 身份（增量编译护栏）：父租户 + 父 manifest digest。
///
/// 依赖栅栏向量（[`OrgDependency`]）只钉祖先头栅栏
/// （tenant/generation/revoke_fence/relationship_revision），不钉父 publication 的
/// 段内容、operation_id 或 compiler_version——这些全部进入父 manifest digest。
/// 因此增量编译除依赖向量外，还必须逐项比对 `(parent tenant, manifest digest)`：
/// 直接父证据工件在头栅栏不变的前提下被替换（同代重发布/换装/错装父工件）时，
/// 禁止走未变段 `Arc` 复用快路径，必须保守全量重算。root 单元无父 ⇒ `None`
/// （由 [`OrgCompileInput::validate`] 保证：root 携带零父 publication，child 恰一个）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgParentIdentity {
    pub tenant_id: i64,
    pub manifest_digest_hex: String,
}

/// 编译后的单元状态（纯内存；`segments` 为 HAMT——clone O(1) 结构共享，
/// 未变段跨编译 `Arc` 复用）。`pending` 非空 ⇒ 不得进入准入。
#[derive(Debug, Clone, PartialEq)]
pub struct OrgCompiledState {
    pub tenant_id: i64,
    pub root_tenant_id: i64,
    /// 编译代次 = `node.generation`。
    pub version: u64,
    pub node: OrgNode,
    /// 已排序的全部祖先依赖向量（扁平传递集）。
    pub dependencies: Vec<OrgDependency>,
    pub dependency_digest: String,
    /// 直接父 publication 身份（root 为 `None`）。增量编译时必须与输入钉住的
    /// 直接父逐项相等才允许段复用快路径；不等 ⇒ 保守全量重算
    /// （依赖栅栏向量相同 ≠ 直接父证据工件相同）。
    pub parent_identity: Option<OrgParentIdentity>,
    pub compiler_version: String,
    pub operation_id: String,
    /// grant 账本（最新 revision per grant_id，含 inactive 墓碑）。
    pub grant_ledger: im::HashMap<String, OrgGrant>,
    /// mask 账本（最新 revision per mask_id，含 inactive）。
    pub mask_ledger: im::HashMap<String, OrgMask>,
    /// HAMT 段：key → 段单元（未变段 Arc 复用）。
    pub segments: im::HashMap<OrgScopeKey, Arc<OrgSegmentCell>>,
    /// 生效贡献（确定序：按 key 升序 + 桶内 (grant_id, revision) 升序）。
    pub effective: Vec<OrgContribution>,
    /// 显式 PENDING 项（非空 ⇒ [`OrgCompiledState::admission_ready`] == false）。
    pub pending: Vec<OrgPendingItem>,
}

impl OrgCompiledState {
    /// 准入就绪判定：任何未对账 mask / 未解析父授权 / 不可证明范围都不得进入准入。
    pub fn admission_ready(&self) -> bool {
        self.pending.is_empty()
    }

    /// 取一个段的 `Arc` 句柄（未变段跨编译指针相等，用于复用证明与发布计划）。
    pub fn segment_cell(&self, key: &OrgScopeKey) -> Option<Arc<OrgSegmentCell>> {
        self.segments.get(key).cloned()
    }

    /// 渲染 wire publication（段按 key 升序分配 index；digest 覆盖段序+依赖+头栅栏）。
    pub fn to_publication(&self) -> Result<OrgPublication, OrgError> {
        let mut entries: Vec<(&OrgScopeKey, &Arc<OrgSegmentCell>)> = self.segments.iter().collect();
        entries.sort_by(|left, right| left.0.cmp(right.0));
        let mut segments = Vec::with_capacity(entries.len());
        for (index, (_, cell)) in entries.iter().enumerate() {
            segments.push(org_build_segment(
                index as u32,
                OrgSegmentContent {
                    key: cell.key.clone(),
                    contributions: cell.contributions.clone(),
                },
            )?);
        }
        let publication = OrgPublication {
            tenant_id: self.tenant_id,
            root_tenant_id: self.root_tenant_id,
            generation: self.version,
            relationship_revision: self.node.relationship_revision,
            revoke_fence: self.node.revoke_fence,
            dependencies: self.dependencies.clone(),
            manifest_digest_hex: String::new(),
            compiler_version: self.compiler_version.clone(),
            segments,
            operation_id: self.operation_id.clone(),
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
        })?;
        let publication = OrgPublication {
            manifest_digest_hex,
            ..publication
        };
        publication.validate()?;
        Ok(publication)
    }
}

/// 编译结果：`Applied`（pending 为空，可发布/准入）或 `Pending`
/// （显式未对账集合；状态仅供诊断/落库，绝不进入准入）。
#[derive(Debug, Clone, PartialEq)]
pub enum OrgCompileOutcome {
    Applied(OrgCompiledState),
    Pending {
        state: OrgCompiledState,
        report: OrgPendingReport,
    },
}

/// 树身份（增量受影响面判定只看结构事实，不看 generation/fence/operation）。
fn tree_identity(node: &OrgNode) -> (i64, i64, Option<i64>, u64, bool) {
    (
        node.tenant_id,
        node.root_tenant_id,
        node.parent_tenant_id,
        node.relationship_revision,
        node.active,
    )
}

fn scope_key_of(scope: &astral_types::org_scope::OrgScope) -> OrgScopeKey {
    OrgScopeKey {
        resource: scope.resource.clone(),
        action: scope.action.clone(),
    }
}

fn build_cell(
    key: OrgScopeKey,
    contributions: Vec<OrgContribution>,
) -> Result<OrgSegmentCell, OrgError> {
    let content = OrgSegmentContent {
        key: key.clone(),
        contributions,
    };
    // org_segment_digest_hex 内部先做合同校验（顺序/上限/字段）。
    let digest_hex = org_segment_digest_hex(&content)?;
    Ok(OrgSegmentCell {
        key,
        digest_hex,
        contributions: content.contributions,
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// 解析：父授权 / provenance / mask
// ─────────────────────────────────────────────────────────────────────────────

struct ResolvedUnit {
    grouped: BTreeMap<OrgScopeKey, Vec<OrgContribution>>,
    effective: Vec<OrgContribution>,
    pending: Vec<OrgPendingItem>,
}

/// Ledger diff result used by incremental compilation. `None` means a mask
/// change requires a conservative full segment rebuild.
struct DerivedLedgers {
    grant_ledger: im::HashMap<String, OrgGrant>,
    mask_ledger: im::HashMap<String, OrgMask>,
    affected: Option<BTreeSet<OrgScopeKey>>,
}

/// 解析编译输入 → 生效贡献（fail-closed）：
/// - 父引用按精确 `(tenant, grant_id, revision)` 在钉住的父 publication 内解析；
/// - 未命中但同源存在其它 revision → `ParentRevisionAdvanced` PENDING（同源重发
///   不得洗白任何本地限制）；完全缺失 → `ParentMissing` PENDING；
/// - 父贡献不可再授予 → 结构破坏 `ParentNotDelegable`（Err）；
/// - 范围包含不可证明 → `ScopeNotCovered` PENDING（该贡献不进入生效集合）；
/// - active mask 命中 provenance 链中 exact (tenant, grant_id)：revision 相等 →
///   屏蔽；漂移 → 屏蔽 + `MaskTargetRevisionAdvanced` PENDING；目标缺席 → 无操作。
fn resolve_unit(input: &OrgCompileInput) -> Result<ResolvedUnit, OrgError> {
    // 输入结构性校验（含父 publication 完整性 + 传递依赖完备性）。
    input.validate()?;

    let mut parent_exact: BTreeMap<OrgGrantRef, OrgContribution> = BTreeMap::new();
    let mut parent_max_revision: BTreeMap<(i64, String), u64> = BTreeMap::new();
    if let Some(publication) = input.parent_publications.first() {
        for segment in &publication.segments {
            let content = org_decode_segment_content(segment)?;
            for contribution in content.contributions {
                let revision_entry = parent_max_revision
                    .entry((
                        contribution.grant_ref.tenant_id,
                        contribution.grant_ref.grant_id.clone(),
                    ))
                    .or_insert(contribution.grant_ref.revision);
                if contribution.grant_ref.revision > *revision_entry {
                    *revision_entry = contribution.grant_ref.revision;
                }
                parent_exact.insert(contribution.grant_ref.clone(), contribution);
            }
        }
    }

    let mut grants: Vec<&OrgGrant> = input.grants.iter().collect();
    grants.sort_by(|left, right| left.grant_id.cmp(&right.grant_id));
    let mut contributions: Vec<OrgContribution> = Vec::with_capacity(grants.len());
    let mut pending: Vec<OrgPendingItem> = Vec::new();
    for grant in grants {
        if !grant.active {
            continue;
        }
        if let Some(contribution) =
            resolve_grant_contribution(grant, &parent_exact, &parent_max_revision, &mut pending)?
        {
            contributions.push(contribution);
        }
    }

    let mut masks: Vec<&OrgMask> = input.masks.iter().collect();
    masks.sort_by(|left, right| left.mask_id.cmp(&right.mask_id));
    let mut blocked: BTreeSet<String> = BTreeSet::new();
    for mask in masks {
        if !mask.active {
            continue;
        }
        let mut revision_drift = false;
        for contribution in &contributions {
            let matched = contribution
                .provenance
                .parent_chain
                .iter()
                .find(|reference| {
                    reference.tenant_id == mask.target.tenant_id
                        && reference.grant_id == mask.target.grant_id
                });
            if let Some(reference) = matched {
                if reference.revision != mask.target.revision {
                    revision_drift = true;
                }
                // 保守：屏蔽 + 未对账都把该贡献排除出生效集合。
                blocked.insert(contribution.grant_ref.grant_id.clone());
            }
        }
        if revision_drift {
            pending.push(OrgPendingItem {
                code: OrgPendingCode::MaskTargetRevisionAdvanced,
                detail: format!(
                    "mask {} target revision {} no longer matches its source; explicit reconciliation required",
                    mask.mask_id, mask.target.revision
                ),
                grant_id: None,
                mask_id: Some(mask.mask_id.clone()),
            });
        }
    }

    let mut grouped: BTreeMap<OrgScopeKey, Vec<OrgContribution>> = BTreeMap::new();
    for contribution in contributions {
        if blocked.contains(&contribution.grant_ref.grant_id) {
            continue;
        }
        let key = scope_key_of(&contribution.scope);
        grouped.entry(key).or_default().push(contribution);
    }
    for bucket in grouped.values_mut() {
        bucket.sort_by(|left, right| {
            left.grant_ref
                .grant_id
                .cmp(&right.grant_ref.grant_id)
                .then(left.grant_ref.revision.cmp(&right.grant_ref.revision))
        });
    }
    let effective: Vec<OrgContribution> = grouped.values().flatten().cloned().collect();
    Ok(ResolvedUnit {
        grouped,
        effective,
        pending,
    })
}

fn resolve_grant_contribution(
    grant: &OrgGrant,
    parent_exact: &BTreeMap<OrgGrantRef, OrgContribution>,
    parent_max_revision: &BTreeMap<(i64, String), u64>,
    pending: &mut Vec<OrgPendingItem>,
) -> Result<Option<OrgContribution>, OrgError> {
    let grant_ref = OrgGrantRef {
        tenant_id: grant.receiving_tenant_id,
        grant_id: grant.grant_id.clone(),
        revision: grant.revision,
    };
    let Some(parent_ref) = &grant.parent else {
        return Ok(Some(OrgContribution {
            grant_ref,
            scope: grant.scope.clone(),
            delegable: grant.delegable,
            subject: grant.subject,
            provenance: OrgProvenance {
                origin_tenant_id: grant.origin_tenant_id,
                parent_chain: Vec::new(),
                operation_id: grant.operation_id.clone(),
            },
        }));
    };
    let Some(parent_contribution) = parent_exact.get(parent_ref) else {
        let available_revision = parent_max_revision
            .get(&(parent_ref.tenant_id, parent_ref.grant_id.clone()))
            .copied();
        match available_revision {
            Some(available_revision) => pending.push(OrgPendingItem {
                code: OrgPendingCode::ParentRevisionAdvanced,
                detail: format!(
                    "parent grant {} advanced to revision {available_revision}; reapproval required",
                    parent_ref.grant_id
                ),
                grant_id: Some(grant.grant_id.clone()),
                mask_id: None,
            }),
            None => pending.push(OrgPendingItem {
                code: OrgPendingCode::ParentMissing,
                detail: format!(
                    "parent grant {} is not present in the pinned parent publication",
                    parent_ref.grant_id
                ),
                grant_id: Some(grant.grant_id.clone()),
                mask_id: None,
            }),
        }
        return Ok(None);
    };
    if !parent_contribution.delegable {
        return Err(OrgError::new(
            OrgErrorCode::ParentNotDelegable,
            format!(
                "parent grant {} is not delegable; grant {} cannot derive from it",
                parent_ref.grant_id, grant.grant_id
            ),
        ));
    }
    if org_scope_covers(&parent_contribution.scope, &grant.scope).is_err() {
        pending.push(OrgPendingItem {
            code: OrgPendingCode::ScopeNotCovered,
            detail: format!(
                "grant {} scope is not provably covered by parent grant {}",
                grant.grant_id, parent_ref.grant_id
            ),
            grant_id: Some(grant.grant_id.clone()),
            mask_id: None,
        });
        return Ok(None);
    }
    let mut parent_chain = parent_contribution.provenance.parent_chain.clone();
    parent_chain.push(parent_contribution.grant_ref.clone());
    Ok(Some(OrgContribution {
        grant_ref,
        scope: grant.scope.clone(),
        delegable: grant.delegable,
        subject: grant.subject,
        provenance: OrgProvenance {
            origin_tenant_id: parent_contribution.provenance.origin_tenant_id,
            parent_chain,
            operation_id: grant.operation_id.clone(),
        },
    }))
}

// ─────────────────────────────────────────────────────────────────────────────
// 编译器
// ─────────────────────────────────────────────────────────────────────────────

/// ORG_SCOPE 纯编译器（无 I/O、无 durable 副作用；发布/对账由 DB owner 承担）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgCompiler {
    compiler_version: String,
}

impl Default for OrgCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl OrgCompiler {
    pub fn new() -> Self {
        Self {
            compiler_version: ORG_COMPILER_VERSION.to_owned(),
        }
    }

    pub fn with_compiler_version(version: &str) -> Result<Self, OrgError> {
        if version.is_empty()
            || version.len() > astral_types::org_scope::MAX_ORG_ID_TEXT_LEN
            || version.chars().any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(OrgError::new(
                OrgErrorCode::InvalidField,
                "compiler version must be a bounded identifier",
            ));
        }
        Ok(Self {
            compiler_version: version.to_owned(),
        })
    }

    pub fn compiler_version(&self) -> &str {
        &self.compiler_version
    }

    /// 全量 oracle：从空基态重建全部段（parity 参照与冷启动路径）。
    pub fn rebuild_oracle(&self, input: &OrgCompileInput) -> Result<OrgCompiledState, OrgError> {
        self.compile_state(input, None)
    }

    /// 全量编译并分类（Applied / Pending）。
    pub fn compile_full(&self, input: &OrgCompileInput) -> Result<OrgCompileOutcome, OrgError> {
        let state = self.rebuild_oracle(input)?;
        Ok(classify_outcome(state))
    }

    /// 增量编译：基于 base 状态做 ledger diff，只重算受影响桶；未变段 `Arc` 复用。
    /// 编译器版本/依赖向量/直接父 publication 身份/树身份任一变化 → 保守全量重算
    /// （结果仍与 oracle 等价）。
    pub fn compile_incremental(
        &self,
        base: &OrgCompiledState,
        input: &OrgCompileInput,
    ) -> Result<OrgCompileOutcome, OrgError> {
        if base.tenant_id != input.node.tenant_id
            || base.root_tenant_id != input.node.root_tenant_id
        {
            return Err(OrgError::new(
                OrgErrorCode::InvalidRequest,
                "incremental compile must target the same unit tenant/root",
            ));
        }
        if input.node.generation <= base.version {
            return Err(OrgError::new(
                OrgErrorCode::RevisionNotAdvanced,
                format!(
                    "node generation {} must exceed base version {}",
                    input.node.generation, base.version
                ),
            ));
        }
        let state = self.compile_state(input, Some(base))?;
        Ok(classify_outcome(state))
    }

    fn compile_state(
        &self,
        input: &OrgCompileInput,
        base: Option<&OrgCompiledState>,
    ) -> Result<OrgCompiledState, OrgError> {
        let resolved = resolve_unit(input)?;
        // resolve_unit 内部已完成 input.validate()：直接父 publication 的 manifest
        // digest 已被逐项复核，故此身份可信任。root ⇒ None（validate 强制零父）。
        let parent_identity =
            input
                .parent_publications
                .first()
                .map(|publication| OrgParentIdentity {
                    tenant_id: publication.tenant_id,
                    manifest_digest_hex: publication.manifest_digest_hex.clone(),
                });
        let mut sorted_dependencies = input.dependencies.clone();
        sorted_dependencies.sort();
        let dependency_digest = org_dependency_digest_hex(&sorted_dependencies)?;

        let DerivedLedgers {
            grant_ledger,
            mask_ledger,
            affected,
        } = match base {
            Some(base) => derive_ledgers(base, input)?,
            None => {
                let mut grant_ledger = im::HashMap::new();
                for grant in &input.grants {
                    grant_ledger.insert(grant.grant_id.clone(), grant.clone());
                }
                let mut mask_ledger = im::HashMap::new();
                for mask in &input.masks {
                    mask_ledger.insert(mask.mask_id.clone(), mask.clone());
                }
                DerivedLedgers {
                    grant_ledger,
                    mask_ledger,
                    affected: None,
                }
            }
        };

        let incremental_context_intact = match base {
            None => false,
            Some(base) => {
                base.compiler_version == self.compiler_version
                    && base.dependencies == sorted_dependencies
                    // 直接父证据工件身份：digest 变化（即使头栅栏向量逐项相同）
                    // 也不得走未变段 Arc 复用快路径，必须保守全量重算。
                    && base.parent_identity == parent_identity
                    && tree_identity(&base.node) == tree_identity(&input.node)
            }
        };
        let mut segments = base.map(|base| base.segments.clone()).unwrap_or_default();
        let rebuild_all = !incremental_context_intact || affected.is_none();
        if rebuild_all {
            segments.clear();
            for (key, contributions) in &resolved.grouped {
                let cell = build_cell(key.clone(), contributions.clone())?;
                segments.insert(key.clone(), Arc::new(cell));
            }
        } else if let Some(keys) = affected {
            for key in keys {
                segments.remove(&key);
                if let Some(contributions) = resolved.grouped.get(&key) {
                    let cell = build_cell(key.clone(), contributions.clone())?;
                    segments.insert(key.clone(), Arc::new(cell));
                }
            }
        }

        Ok(OrgCompiledState {
            tenant_id: input.node.tenant_id,
            root_tenant_id: input.node.root_tenant_id,
            version: input.node.generation,
            node: input.node.clone(),
            dependencies: sorted_dependencies,
            dependency_digest,
            parent_identity,
            compiler_version: self.compiler_version.clone(),
            operation_id: input.operation_id.clone(),
            grant_ledger,
            mask_ledger,
            segments,
            effective: resolved.effective,
            pending: resolved.pending,
        })
    }
}

/// `Some(keys)` = 只重算 keys；`None` = mask 集合变化，保守全量重算。
/// 无论走哪条路径，stale/duplicate 的 grant/mask 重写都会被合同拒绝（Err）。
fn derive_ledgers(
    base: &OrgCompiledState,
    input: &OrgCompileInput,
) -> Result<DerivedLedgers, OrgError> {
    let mut affected: BTreeSet<OrgScopeKey> = BTreeSet::new();
    let mut grant_ledger = base.grant_ledger.clone();
    for grant in &input.grants {
        match grant_ledger.get(&grant.grant_id) {
            Some(existing) if existing == grant => {}
            Some(existing) => {
                org_grant_revision_compatible(existing, grant)?;
                affected.insert(scope_key_of(&existing.scope));
                if grant.active {
                    affected.insert(scope_key_of(&grant.scope));
                }
                grant_ledger.insert(grant.grant_id.clone(), grant.clone());
            }
            None => {
                affected.insert(scope_key_of(&grant.scope));
                grant_ledger.insert(grant.grant_id.clone(), grant.clone());
            }
        }
    }
    let input_grant_ids: HashSet<&str> = input
        .grants
        .iter()
        .map(|grant| grant.grant_id.as_str())
        .collect();
    let removed_grants: Vec<String> = grant_ledger
        .keys()
        .filter(|id| !input_grant_ids.contains(id.as_str()))
        .cloned()
        .collect();
    for grant_id in removed_grants {
        if let Some(existing) = grant_ledger.remove(&grant_id) {
            affected.insert(scope_key_of(&existing.scope));
        }
    }

    let mut mask_ledger = base.mask_ledger.clone();
    let mut masks_changed = false;
    for mask in &input.masks {
        match mask_ledger.get(&mask.mask_id) {
            Some(existing) if existing == mask => {}
            Some(existing) => {
                if mask.revision <= existing.revision {
                    return Err(OrgError::new(
                        OrgErrorCode::RevisionNotAdvanced,
                        format!("mask {} revision must advance on change", mask.mask_id),
                    ));
                }
                masks_changed = true;
                mask_ledger.insert(mask.mask_id.clone(), mask.clone());
            }
            None => {
                masks_changed = true;
                mask_ledger.insert(mask.mask_id.clone(), mask.clone());
            }
        }
    }
    let input_mask_ids: HashSet<&str> = input
        .masks
        .iter()
        .map(|mask| mask.mask_id.as_str())
        .collect();
    let removed_masks: Vec<String> = mask_ledger
        .keys()
        .filter(|id| !input_mask_ids.contains(id.as_str()))
        .cloned()
        .collect();
    if !removed_masks.is_empty() {
        masks_changed = true;
        for mask_id in removed_masks {
            mask_ledger.remove(&mask_id);
        }
    }

    let affected = if masks_changed { None } else { Some(affected) };
    Ok(DerivedLedgers {
        grant_ledger,
        mask_ledger,
        affected,
    })
}

fn classify_outcome(state: OrgCompiledState) -> OrgCompileOutcome {
    if state.pending.is_empty() {
        OrgCompileOutcome::Applied(state)
    } else {
        let report = OrgPendingReport {
            tenant_id: state.tenant_id,
            generation: state.version,
            items: state.pending.clone(),
        };
        OrgCompileOutcome::Pending { state, report }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// readonly 匹配索引（main 的 org_admission 集成入口）
// ─────────────────────────────────────────────────────────────────────────────

/// readonly 查询索引：publication/编译状态 → 按 key 排序的有界候选桶。
/// 只读、无 I/O、确定序；请求级身份/有效期/主体判定 fail-closed。
#[derive(Debug, Clone, PartialEq)]
pub struct OrgQueryIndex {
    entries: Vec<(OrgScopeKey, Arc<OrgSegmentCell>)>,
}

impl OrgQueryIndex {
    /// 从 wire publication 构建（逐段 typed 解码 + digest 复核，fail-closed）。
    pub fn from_publication(publication: &OrgPublication) -> Result<Self, OrgError> {
        publication.validate()?;
        let mut entries = Vec::with_capacity(publication.segments.len());
        for segment in &publication.segments {
            let content = org_decode_segment_content(segment)?;
            entries.push((
                content.key.clone(),
                Arc::new(OrgSegmentCell {
                    key: content.key,
                    digest_hex: segment.digest_hex.clone(),
                    contributions: content.contributions,
                }),
            ));
        }
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        Ok(Self { entries })
    }

    /// 从编译状态构建（段已验证；HAMT 迭代无序 → 显式按 key 排序）。
    pub fn from_state(state: &OrgCompiledState) -> Self {
        let mut entries: Vec<(OrgScopeKey, Arc<OrgSegmentCell>)> = state
            .segments
            .iter()
            .map(|(key, cell)| (key.clone(), Arc::clone(cell)))
            .collect();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        Self { entries }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn segment_count(&self) -> usize {
        self.entries.len()
    }

    /// 有界确定性候选集：桶级资源/动作形态匹配（对象请求可命中对象/类型/全局桶，
    /// 类型级请求绝不命中对象桶；write 别名经 registry 映射），贡献级
    /// 主体/资源租户/domain/有效期统一时钟判定。返回克隆（调用方安全持有）。
    pub fn candidates(
        &self,
        request: &OrgReadRequest,
        filter: OrgSubjectFilter,
    ) -> Vec<OrgContribution> {
        let mut matched = Vec::new();
        for (key, cell) in &self.entries {
            if !org_resource_matches(&request.resource, &key.resource) {
                continue;
            }
            if !org_action_matches(&request.action, &key.action) {
                continue;
            }
            for contribution in &cell.contributions {
                if org_contribution_matches_request(contribution, request, filter) {
                    matched.push(contribution.clone());
                }
            }
        }
        matched
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 测试
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use astral_types::org_scope::{org_dependency_matches_publication, OrgScope, OrgSubject};
    use astral_types::ValidityWindow;

    const ROOT_TENANT: i64 = 100;
    const CHILD_TENANT: i64 = 200;

    fn uuid(seed: u64) -> String {
        // 规范小写连字符 UUID 文本（policy-engine 无 uuid 依赖；合同只要求规范形态）。
        format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            (seed as u32),
            0x1,
            0xA57A,
            0xB0B0,
            seed
        )
    }

    fn window(start: i64, end: i64) -> ValidityWindow {
        ValidityWindow::between(start, end)
    }

    fn root_scope(resource: &str, action: &str) -> OrgScope {
        OrgScope {
            resource_tenant_id: ROOT_TENANT,
            domain_id: None,
            resource: resource.to_owned(),
            action: action.to_owned(),
            validity: window(1_000, 2_000),
        }
    }

    /// 下级单元接收的贡献：资源租户保持授予方租户（V1 恒等，包含关系可证明）。
    fn child_scope(resource: &str, action: &str) -> OrgScope {
        OrgScope {
            resource_tenant_id: ROOT_TENANT,
            domain_id: None,
            resource: resource.to_owned(),
            action: action.to_owned(),
            validity: window(1_000, 2_000),
        }
    }

    fn root_node(generation: u64) -> OrgNode {
        OrgNode {
            tenant_id: ROOT_TENANT,
            root_tenant_id: ROOT_TENANT,
            parent_tenant_id: None,
            generation,
            revoke_fence: 0,
            relationship_revision: 1,
            active: true,
            operation_id: "op-root".to_owned(),
            root_activation: Some(astral_types::org_scope::OrgRootActivation {
                operator_user_id: 7,
                approval_operation_id: "op-approve-root".to_owned(),
            }),
        }
    }

    fn child_node(generation: u64) -> OrgNode {
        OrgNode {
            tenant_id: CHILD_TENANT,
            root_tenant_id: ROOT_TENANT,
            parent_tenant_id: Some(ROOT_TENANT),
            generation,
            revoke_fence: 0,
            relationship_revision: 1,
            active: true,
            operation_id: "op-child".to_owned(),
            root_activation: None,
        }
    }

    fn root_grant(seed: u64, resource: &str, action: &str, delegable: bool) -> OrgGrant {
        OrgGrant {
            grant_id: uuid(seed),
            revision: 1,
            receiving_tenant_id: ROOT_TENANT,
            origin_tenant_id: ROOT_TENANT,
            root_tenant_id: ROOT_TENANT,
            scope: root_scope(resource, action),
            delegable,
            parent: None,
            subject: None,
            active: true,
            operation_id: format!("op-grant-{seed}"),
        }
    }

    fn child_grant(seed: u64, parent: OrgGrantRef, scope: OrgScope, delegable: bool) -> OrgGrant {
        OrgGrant {
            grant_id: uuid(seed),
            revision: 1,
            receiving_tenant_id: CHILD_TENANT,
            origin_tenant_id: ROOT_TENANT,
            root_tenant_id: ROOT_TENANT,
            scope,
            delegable,
            parent: Some(parent),
            subject: None,
            active: true,
            operation_id: format!("op-grant-{seed}"),
        }
    }

    fn root_ref(grant: &OrgGrant) -> OrgGrantRef {
        OrgGrantRef {
            tenant_id: grant.receiving_tenant_id,
            grant_id: grant.grant_id.clone(),
            revision: grant.revision,
        }
    }

    fn root_input(node: OrgNode, grants: Vec<OrgGrant>) -> OrgCompileInput {
        OrgCompileInput {
            node,
            dependencies: Vec::new(),
            parent_publications: Vec::new(),
            grants,
            masks: Vec::new(),
            operation_id: "op-root-compile".to_owned(),
        }
    }

    fn applied(outcome: OrgCompileOutcome) -> OrgCompiledState {
        match outcome {
            OrgCompileOutcome::Applied(state) => state,
            OrgCompileOutcome::Pending { report, .. } => {
                panic!("expected Applied, got pending: {report:?}")
            }
        }
    }

    fn pending_codes(outcome: OrgCompileOutcome) -> Vec<OrgPendingCode> {
        match outcome {
            OrgCompileOutcome::Applied(_) => panic!("expected Pending"),
            OrgCompileOutcome::Pending { report, .. } => {
                report.items.iter().map(|item| item.code).collect()
            }
        }
    }

    #[test]
    fn full_compile_root_unit_and_publication_render() {
        let g1 = root_grant(1, "doc:42", "read", true);
        let input = root_input(root_node(1), vec![g1.clone()]);
        let state = applied(OrgCompiler::new().compile_full(&input).unwrap());
        assert!(state.admission_ready());
        assert_eq!(state.effective.len(), 1);
        assert_eq!(state.segments.len(), 1);
        assert_eq!(state.version, 1);
        assert_eq!(state.grant_ledger.len(), 1);

        let publication = state.to_publication().unwrap();
        assert!(publication.validate().is_ok());
        assert_eq!(publication.generation, 1);
        assert!(publication.dependencies.is_empty());
        assert!(publication.contains_grant(&root_ref(&g1)));
    }

    #[test]
    fn empty_root_unit_compiles_and_publishes_zero_segments() {
        let input = root_input(root_node(1), vec![]);
        let state = applied(OrgCompiler::new().compile_full(&input).unwrap());
        assert!(state.admission_ready());
        let publication = state.to_publication().unwrap();
        assert!(publication.validate().is_ok());
        assert!(publication.segments.is_empty());
    }

    #[test]
    fn two_level_inheritance_builds_provenance_chain() {
        let g1 = root_grant(1, "doc:42", "read", true);
        let root_input = root_input(root_node(1), vec![g1.clone()]);
        let root_state = applied(OrgCompiler::new().compile_full(&root_input).unwrap());
        let root_publication = root_state.to_publication().unwrap();

        let dependency = OrgDependency {
            tenant_id: root_publication.tenant_id,
            generation: root_publication.generation,
            revoke_fence: root_publication.revoke_fence,
            relationship_revision: root_publication.relationship_revision,
        };
        let c1 = child_grant(2, root_ref(&g1), child_scope("doc:42", "read"), false);
        let child_input = OrgCompileInput {
            node: child_node(1),
            dependencies: vec![dependency],
            parent_publications: vec![root_publication],
            grants: vec![c1],
            masks: Vec::new(),
            operation_id: "op-child-compile".to_owned(),
        };
        let child_state = applied(OrgCompiler::new().compile_full(&child_input).unwrap());
        assert!(child_state.admission_ready());
        assert_eq!(child_state.effective.len(), 1);
        let contribution = &child_state.effective[0];
        assert_eq!(contribution.provenance.parent_chain, vec![root_ref(&g1)]);
        assert_eq!(contribution.provenance.origin_tenant_id, ROOT_TENANT);
        assert!(!contribution.delegable);

        let child_publication = child_state.to_publication().unwrap();
        assert!(child_publication.validate().is_ok());
        // 子单元依赖向量 = 全部祖先（此处即根头）。
        assert_eq!(child_publication.dependencies.len(), 1);
        assert!(org_dependency_matches_publication(
            &child_publication.dependencies[0],
            &root_state.to_publication().unwrap()
        ));
    }

    #[test]
    fn scope_not_covered_is_pending_and_excluded() {
        let g1 = root_grant(1, "doc:42", "read", true);
        let root_input = root_input(root_node(1), vec![g1.clone()]);
        let root_state = applied(OrgCompiler::new().compile_full(&root_input).unwrap());
        let root_publication = root_state.to_publication().unwrap();
        let dependency = OrgDependency {
            tenant_id: root_publication.tenant_id,
            generation: root_publication.generation,
            revoke_fence: root_publication.revoke_fence,
            relationship_revision: root_publication.relationship_revision,
        };
        let c1 = child_grant(2, root_ref(&g1), child_scope("doc:43", "read"), false);
        let child_input = OrgCompileInput {
            node: child_node(1),
            dependencies: vec![dependency],
            parent_publications: vec![root_publication],
            grants: vec![c1],
            masks: Vec::new(),
            operation_id: "op-child-compile".to_owned(),
        };
        let outcome = OrgCompiler::new().compile_full(&child_input).unwrap();
        assert_eq!(
            pending_codes(outcome),
            vec![OrgPendingCode::ScopeNotCovered]
        );
    }

    #[test]
    fn parent_not_delegable_is_structural_conflict() {
        let g1 = root_grant(1, "doc:42", "read", false);
        let root_input = root_input(root_node(1), vec![g1.clone()]);
        let root_state = applied(OrgCompiler::new().compile_full(&root_input).unwrap());
        let root_publication = root_state.to_publication().unwrap();
        let dependency = OrgDependency {
            tenant_id: root_publication.tenant_id,
            generation: root_publication.generation,
            revoke_fence: root_publication.revoke_fence,
            relationship_revision: root_publication.relationship_revision,
        };
        let c1 = child_grant(2, root_ref(&g1), child_scope("doc:42", "read"), false);
        let child_input = OrgCompileInput {
            node: child_node(1),
            dependencies: vec![dependency],
            parent_publications: vec![root_publication],
            grants: vec![c1],
            masks: Vec::new(),
            operation_id: "op-child-compile".to_owned(),
        };
        let error = OrgCompiler::new().compile_full(&child_input).unwrap_err();
        assert_eq!(error.code, OrgErrorCode::ParentNotDelegable);
    }

    #[test]
    fn parent_missing_and_revision_advanced_are_pending() {
        let g1 = root_grant(1, "doc:42", "read", true);
        let root_input = root_input(root_node(1), vec![g1.clone()]);
        let root_state = applied(OrgCompiler::new().compile_full(&root_input).unwrap());
        let root_publication = root_state.to_publication().unwrap();
        let dependency = OrgDependency {
            tenant_id: root_publication.tenant_id,
            generation: root_publication.generation,
            revoke_fence: root_publication.revoke_fence,
            relationship_revision: root_publication.relationship_revision,
        };

        // revision 漂移（同源 rev 2 未见于父 publication）。
        let mut advanced_ref = root_ref(&g1);
        advanced_ref.revision = 2;
        let advanced = child_grant(2, advanced_ref, child_scope("doc:42", "read"), false);
        let outcome = OrgCompiler::new()
            .compile_full(&OrgCompileInput {
                node: child_node(1),
                dependencies: vec![dependency],
                parent_publications: vec![root_publication.clone()],
                grants: vec![advanced],
                masks: Vec::new(),
                operation_id: "op-child-compile".to_owned(),
            })
            .unwrap();
        assert_eq!(
            pending_codes(outcome),
            vec![OrgPendingCode::ParentRevisionAdvanced]
        );

        // 完全缺失的父 grant。
        let unknown = child_grant(
            2,
            OrgGrantRef {
                tenant_id: ROOT_TENANT,
                grant_id: uuid(9),
                revision: 1,
            },
            child_scope("doc:42", "read"),
            false,
        );
        let outcome = OrgCompiler::new()
            .compile_full(&OrgCompileInput {
                node: child_node(1),
                dependencies: vec![dependency],
                parent_publications: vec![root_publication],
                grants: vec![unknown],
                masks: Vec::new(),
                operation_id: "op-child-compile".to_owned(),
            })
            .unwrap();
        assert_eq!(pending_codes(outcome), vec![OrgPendingCode::ParentMissing]);
    }

    #[test]
    fn mask_blocks_exact_source_but_not_other_contributions() {
        let g1 = root_grant(1, "doc:42", "read", true);
        let g2 = root_grant(3, "doc:*", "write", true);
        let root_input = root_input(root_node(1), vec![g1.clone(), g2.clone()]);
        let root_state = applied(OrgCompiler::new().compile_full(&root_input).unwrap());
        let root_publication = root_state.to_publication().unwrap();
        let dependency = OrgDependency {
            tenant_id: root_publication.tenant_id,
            generation: root_publication.generation,
            revoke_fence: root_publication.revoke_fence,
            relationship_revision: root_publication.relationship_revision,
        };
        let c1 = child_grant(2, root_ref(&g1), child_scope("doc:42", "read"), false);
        let c2 = child_grant(4, root_ref(&g2), child_scope("doc:*", "write"), false);
        let mask = astral_types::org_scope::OrgMask {
            mask_id: uuid(5),
            tenant_id: CHILD_TENANT,
            target: root_ref(&g1),
            active: true,
            revision: 1,
            operation_id: "op-mask-1".to_owned(),
        };
        let child_input = OrgCompileInput {
            node: child_node(1),
            dependencies: vec![dependency],
            parent_publications: vec![root_publication],
            grants: vec![c1, c2],
            masks: vec![mask],
            operation_id: "op-child-compile".to_owned(),
        };
        let state = applied(OrgCompiler::new().compile_full(&child_input).unwrap());
        assert!(state.admission_ready());
        // c1 被精确屏蔽，c2 保留（多合法来源不互扰）。
        assert_eq!(state.effective.len(), 1);
        assert_eq!(state.effective[0].grant_ref.grant_id, uuid(4));
        assert_eq!(state.mask_ledger.len(), 1);
    }

    #[test]
    fn mask_reissue_same_source_cannot_launder() {
        // 父 grant 换 revision 重发（同源）；本地 mask 仍钉旧 revision：
        // 新派生贡献必须进入未对账 PENDING，且被保守排除（不得洗白剪裁）。
        let mut g1_v2 = root_grant(1, "doc:42", "read", true);
        g1_v2.revision = 2;
        g1_v2.operation_id = "op-grant-1-reissue".to_owned();
        let root_input = root_input(root_node(2), vec![g1_v2.clone()]);
        let root_state = applied(OrgCompiler::new().compile_full(&root_input).unwrap());
        let root_publication = root_state.to_publication().unwrap();
        let dependency = OrgDependency {
            tenant_id: root_publication.tenant_id,
            generation: root_publication.generation,
            revoke_fence: root_publication.revoke_fence,
            relationship_revision: root_publication.relationship_revision,
        };
        let c3 = child_grant(6, root_ref(&g1_v2), child_scope("doc:42", "read"), false);
        let mask = astral_types::org_scope::OrgMask {
            mask_id: uuid(5),
            tenant_id: CHILD_TENANT,
            target: OrgGrantRef {
                tenant_id: ROOT_TENANT,
                grant_id: uuid(1),
                revision: 1, // 旧 revision
            },
            active: true,
            revision: 1,
            operation_id: "op-mask-1".to_owned(),
        };
        let child_input = OrgCompileInput {
            node: child_node(1),
            dependencies: vec![dependency],
            parent_publications: vec![root_publication],
            grants: vec![c3],
            masks: vec![mask],
            operation_id: "op-child-compile".to_owned(),
        };
        let outcome = OrgCompiler::new().compile_full(&child_input).unwrap();
        assert_eq!(
            pending_codes(outcome),
            vec![OrgPendingCode::MaskTargetRevisionAdvanced]
        );
    }

    #[test]
    fn mask_target_absent_is_noop() {
        let g1 = root_grant(1, "doc:42", "read", true);
        let root_input = root_input(root_node(1), vec![g1.clone()]);
        let root_state = applied(OrgCompiler::new().compile_full(&root_input).unwrap());
        let root_publication = root_state.to_publication().unwrap();
        let dependency = OrgDependency {
            tenant_id: root_publication.tenant_id,
            generation: root_publication.generation,
            revoke_fence: root_publication.revoke_fence,
            relationship_revision: root_publication.relationship_revision,
        };
        let c1 = child_grant(2, root_ref(&g1), child_scope("doc:42", "read"), false);
        let mask = astral_types::org_scope::OrgMask {
            mask_id: uuid(5),
            tenant_id: CHILD_TENANT,
            target: OrgGrantRef {
                tenant_id: ROOT_TENANT,
                grant_id: uuid(9), // 来源已不存在
                revision: 1,
            },
            active: true,
            revision: 1,
            operation_id: "op-mask-1".to_owned(),
        };
        let state = applied(
            OrgCompiler::new()
                .compile_full(&OrgCompileInput {
                    node: child_node(1),
                    dependencies: vec![dependency],
                    parent_publications: vec![root_publication],
                    grants: vec![c1],
                    masks: vec![mask],
                    operation_id: "op-child-compile".to_owned(),
                })
                .unwrap(),
        );
        assert!(state.admission_ready());
        assert_eq!(state.effective.len(), 1);
    }

    #[test]
    fn inactive_grants_stay_in_ledger_without_contributions() {
        let mut g1 = root_grant(1, "doc:42", "read", true);
        g1.active = false;
        let input = root_input(root_node(1), vec![g1.clone()]);
        let state = applied(OrgCompiler::new().compile_full(&input).unwrap());
        assert!(state.admission_ready());
        assert!(state.effective.is_empty());
        assert!(state.segments.is_empty());
        assert_eq!(state.grant_ledger.len(), 1);
        assert!(!state.grant_ledger.get(&g1.grant_id).unwrap().active);
    }

    #[test]
    fn inactive_grant_tombstone_kept_in_incremental_ledger() {
        // DB 现状输入合同：编译器接收当前 grant 账本条目（含 inactive 墓碑态）。
        // 增量路径：active grant → revision 前进的 inactive 墓碑 ⇒
        // 贡献退出生效集合、对应段移除、账本保留墓碑，且与 full oracle 等价。
        let g1 = root_grant(1, "doc:42", "read", true);
        let parent = root_state_publication(vec![g1.clone()]);
        let c1 = child_grant(2, root_ref(&g1), child_scope("doc:42", "read"), false);
        let base = applied(
            OrgCompiler::new()
                .compile_full(&OrgCompileInput {
                    node: child_node(1),
                    dependencies: vec![parent_dependency_of(&parent)],
                    parent_publications: vec![parent.clone()],
                    grants: vec![c1.clone()],
                    masks: Vec::new(),
                    operation_id: "op-child-compile".to_owned(),
                })
                .unwrap(),
        );
        assert_eq!(base.effective.len(), 1);

        // 墓碑：同 grant_id、revision 前进、active=false（receiving/origin/root/
        // delegable/parent/subject 不可变字段保持不变）。
        let mut tombstone = c1.clone();
        tombstone.revision = 2;
        tombstone.active = false;
        tombstone.operation_id = "op-grant-2-tombstone".to_owned();
        let second = OrgCompileInput {
            node: child_node(2),
            dependencies: vec![parent_dependency_of(&parent)],
            parent_publications: vec![parent.clone()],
            grants: vec![tombstone.clone()],
            masks: Vec::new(),
            operation_id: "op-child-compile-2".to_owned(),
        };
        let incremental = state_of(
            OrgCompiler::new()
                .compile_incremental(&base, &second)
                .unwrap(),
        );
        let full = state_of(OrgCompiler::new().compile_full(&second).unwrap());
        assert_eq!(incremental, full);
        assert!(incremental.admission_ready());
        assert!(incremental.effective.is_empty());
        assert!(incremental
            .segment_cell(&scope_key_of(&child_scope("doc:42", "read")))
            .is_none());
        // 账本保留墓碑（不物理删除）：inactive + 最新 revision。
        let entry = incremental.grant_ledger.get(&tombstone.grant_id).unwrap();
        assert!(!entry.active);
        assert_eq!(entry.revision, 2);

        // 账本 revision 门禁不放宽：同 revision 翻转 active 必须被拒绝。
        let mut same_rev = c1;
        same_rev.active = false;
        let second_same_rev = OrgCompileInput {
            node: child_node(2),
            dependencies: vec![parent_dependency_of(&parent)],
            parent_publications: vec![parent],
            grants: vec![same_rev],
            masks: Vec::new(),
            operation_id: "op-child-compile-2".to_owned(),
        };
        let error = OrgCompiler::new()
            .compile_incremental(&base, &second_same_rev)
            .unwrap_err();
        assert_eq!(error.code, OrgErrorCode::RevisionNotAdvanced);
    }

    #[test]
    fn inactive_mask_tombstone_restores_blocked_contribution_incrementally() {
        // 增量路径：active mask → revision 前进的 inactive 墓碑 ⇒
        // mask 集合变化触发保守全量重算，被剪裁贡献回到生效集合，
        // 账本保留 inactive 墓碑，且与 full oracle 等价。
        let g1 = root_grant(1, "doc:42", "read", true);
        let parent = root_state_publication(vec![g1.clone()]);
        let c1 = child_grant(2, root_ref(&g1), child_scope("doc:42", "read"), false);
        let mask = astral_types::org_scope::OrgMask {
            mask_id: uuid(5),
            tenant_id: CHILD_TENANT,
            target: root_ref(&g1),
            active: true,
            revision: 1,
            operation_id: "op-mask-1".to_owned(),
        };
        let base = applied(
            OrgCompiler::new()
                .compile_full(&OrgCompileInput {
                    node: child_node(1),
                    dependencies: vec![parent_dependency_of(&parent)],
                    parent_publications: vec![parent.clone()],
                    grants: vec![c1.clone()],
                    masks: vec![mask.clone()],
                    operation_id: "op-child-compile".to_owned(),
                })
                .unwrap(),
        );
        // active mask 精确屏蔽 c1。
        assert!(base.admission_ready());
        assert!(base.effective.is_empty());

        // 账本 revision 门禁不放宽：同 revision 翻转 active 必须被拒绝。
        let mut same_rev = mask.clone();
        same_rev.active = false;
        let second_same_rev = OrgCompileInput {
            node: child_node(2),
            dependencies: vec![parent_dependency_of(&parent)],
            parent_publications: vec![parent.clone()],
            grants: vec![c1.clone()],
            masks: vec![same_rev],
            operation_id: "op-child-compile-2".to_owned(),
        };
        let error = OrgCompiler::new()
            .compile_incremental(&base, &second_same_rev)
            .unwrap_err();
        assert_eq!(error.code, OrgErrorCode::RevisionNotAdvanced);

        // 墓碑：revision 前进 + active=false ⇒ 剪裁解除。
        let mut tombstone = mask;
        tombstone.revision = 2;
        tombstone.active = false;
        tombstone.operation_id = "op-mask-1-tombstone".to_owned();
        let second = OrgCompileInput {
            node: child_node(2),
            dependencies: vec![parent_dependency_of(&parent)],
            parent_publications: vec![parent],
            grants: vec![c1],
            masks: vec![tombstone.clone()],
            operation_id: "op-child-compile-2".to_owned(),
        };
        let incremental = state_of(
            OrgCompiler::new()
                .compile_incremental(&base, &second)
                .unwrap(),
        );
        let full = state_of(OrgCompiler::new().compile_full(&second).unwrap());
        assert_eq!(incremental, full);
        assert!(incremental.admission_ready());
        assert_eq!(incremental.effective.len(), 1);
        let entry = incremental.mask_ledger.get(&tombstone.mask_id).unwrap();
        assert!(!entry.active);
        assert_eq!(entry.revision, 2);
    }

    #[test]
    fn incremental_matches_full_oracle() {
        let g1 = root_grant(1, "doc:42", "read", true);
        let g2 = root_grant(3, "doc:*", "read", true);
        let root_input = root_input(root_node(1), vec![g1.clone(), g2.clone()]);
        let root_state = applied(OrgCompiler::new().compile_full(&root_input).unwrap());
        let root_publication = root_state.to_publication().unwrap();
        let dependency = OrgDependency {
            tenant_id: root_publication.tenant_id,
            generation: root_publication.generation,
            revoke_fence: root_publication.revoke_fence,
            relationship_revision: root_publication.relationship_revision,
        };
        let c1 = child_grant(2, root_ref(&g1), child_scope("doc:42", "read"), false);
        let first = OrgCompileInput {
            node: child_node(1),
            dependencies: vec![dependency],
            parent_publications: vec![root_publication.clone()],
            grants: vec![c1.clone()],
            masks: Vec::new(),
            operation_id: "op-child-compile".to_owned(),
        };
        let base = applied(OrgCompiler::new().compile_full(&first).unwrap());

        // 新增 c3：parent 覆盖其 scope（doc:* read ⊇ doc:7 read）→ 新 key (doc:7, read)。
        let c3 = child_grant(5, root_ref(&g2), child_scope("doc:7", "read"), false);
        let second = OrgCompileInput {
            node: child_node(2), // generation 前进；树身份不变
            dependencies: vec![dependency],
            parent_publications: vec![root_publication],
            grants: vec![c1, c3],
            masks: Vec::new(),
            operation_id: "op-child-compile-2".to_owned(),
        };
        let incremental = OrgCompiler::new()
            .compile_incremental(&base, &second)
            .unwrap();
        let full = OrgCompiler::new().compile_full(&second).unwrap();
        assert_eq!(applied(incremental), applied(full));
    }

    #[test]
    fn incremental_reuses_unchanged_segment_arcs() {
        let g1 = root_grant(1, "doc:42", "read", true);
        let g3 = root_grant(6, "report:*", "write", true);
        let root_input = root_input(root_node(1), vec![g1.clone(), g3.clone()]);
        let root_state = applied(OrgCompiler::new().compile_full(&root_input).unwrap());
        let root_publication = root_state.to_publication().unwrap();
        let dependency = OrgDependency {
            tenant_id: root_publication.tenant_id,
            generation: root_publication.generation,
            revoke_fence: root_publication.revoke_fence,
            relationship_revision: root_publication.relationship_revision,
        };
        let c1 = child_grant(2, root_ref(&g1), child_scope("doc:42", "read"), false);
        let untouched = child_grant(9, root_ref(&g3), child_scope("report:5", "write"), false);
        let first = OrgCompileInput {
            node: child_node(1),
            dependencies: vec![dependency],
            parent_publications: vec![root_publication.clone()],
            grants: vec![c1.clone(), untouched.clone()],
            masks: Vec::new(),
            operation_id: "op-child-compile".to_owned(),
        };
        let base = applied(OrgCompiler::new().compile_full(&first).unwrap());
        let untouched_before = base.segment_cell(&scope_key_of(&untouched.scope)).unwrap();

        // c1 前进 revision（同 key 内容变化）；untouched 不变。
        let mut c1_v2 = c1.clone();
        c1_v2.revision = 2;
        c1_v2.operation_id = "op-grant-2-r2".to_owned();
        let second = OrgCompileInput {
            node: child_node(2),
            dependencies: vec![dependency],
            parent_publications: vec![root_publication],
            grants: vec![c1_v2, untouched],
            masks: Vec::new(),
            operation_id: "op-child-compile-2".to_owned(),
        };
        let next = applied(
            OrgCompiler::new()
                .compile_incremental(&base, &second)
                .unwrap(),
        );
        let untouched_after = next.segment_cell(&scope_key_of(&child_scope("report:5", "write")));
        // 未变段 Arc 复用：指针相等。
        assert!(Arc::ptr_eq(&untouched_before, &untouched_after.unwrap()));
        // 变化段：内容相同则哈希相同，但本次被重算（新 Arc）。
        let changed = next.segment_cell(&scope_key_of(&child_scope("doc:42", "read")));
        assert!(changed.is_some());
    }

    #[test]
    fn stale_generation_rejected_on_incremental() {
        let input = root_input(root_node(1), vec![]);
        let base = applied(OrgCompiler::new().compile_full(&input).unwrap());
        let same = root_input(root_node(1), vec![]);
        let error = OrgCompiler::new()
            .compile_incremental(&base, &same)
            .unwrap_err();
        assert_eq!(error.code, OrgErrorCode::RevisionNotAdvanced);
    }

    #[test]
    fn compiler_version_mismatch_still_matches_oracle() {
        // base 由 v1 编译，增量编译切换到 v0-test → 保守全量重算，
        // 结果与同版本 full oracle 逐字节等价（语义无漂移）。
        let compiler_b = OrgCompiler::with_compiler_version("org-compiler-v0-test").unwrap();
        let input = root_input(root_node(1), vec![root_grant(1, "doc:42", "read", true)]);
        let base = applied(OrgCompiler::new().compile_full(&input).unwrap());
        let advanced_input = root_input(root_node(2), vec![root_grant(1, "doc:42", "read", true)]);
        let incremental = applied(
            compiler_b
                .compile_incremental(&base, &advanced_input)
                .unwrap(),
        );
        let full = applied(compiler_b.compile_full(&advanced_input).unwrap());
        assert_eq!(incremental, full);
    }

    /// 取编译状态（Applied/Pending 皆可）：parity 断言针对状态本身，
    /// 与 Applied/Pending 分类解耦。
    fn state_of(outcome: OrgCompileOutcome) -> OrgCompiledState {
        match outcome {
            OrgCompileOutcome::Applied(state) => state,
            OrgCompileOutcome::Pending { state, .. } => state,
        }
    }

    fn parent_dependency_of(publication: &OrgPublication) -> OrgDependency {
        OrgDependency {
            tenant_id: publication.tenant_id,
            generation: publication.generation,
            revoke_fence: publication.revoke_fence,
            relationship_revision: publication.relationship_revision,
        }
    }

    #[test]
    fn parent_identity_is_none_for_root_and_pinned_for_child() {
        let root_state = applied(
            OrgCompiler::new()
                .compile_full(&root_input(root_node(1), vec![]))
                .unwrap(),
        );
        // root：无父 ⇒ 身份必须为 None。
        assert!(root_state.parent_identity.is_none());

        let g1 = root_grant(1, "doc:42", "read", true);
        let parent = root_state_publication(vec![g1.clone()]);
        let c1 = child_grant(2, root_ref(&g1), child_scope("doc:42", "read"), false);
        let child_state = applied(
            OrgCompiler::new()
                .compile_full(&OrgCompileInput {
                    node: child_node(1),
                    dependencies: vec![parent_dependency_of(&parent)],
                    parent_publications: vec![parent.clone()],
                    grants: vec![c1],
                    masks: Vec::new(),
                    operation_id: "op-child-compile".to_owned(),
                })
                .unwrap(),
        );
        // child：身份逐项钉住直接父（tenant + manifest digest）。
        let identity = child_state.parent_identity.as_ref().unwrap();
        assert_eq!(identity.tenant_id, ROOT_TENANT);
        assert_eq!(identity.manifest_digest_hex, parent.manifest_digest_hex);
    }

    /// 根单元 publication 工厂：gen 1，给定 grant 集。
    fn root_state_publication(grants: Vec<OrgGrant>) -> OrgPublication {
        applied(
            OrgCompiler::new()
                .compile_full(&root_input(root_node(1), grants))
                .unwrap(),
        )
        .to_publication()
        .unwrap()
    }

    #[test]
    fn parent_manifest_identity_change_forces_full_rebuild_matching_oracle() {
        // 直接父 publication 在头栅栏（generation/revoke_fence/relationship_revision）
        // 完全不变的前提下换了一份证据工件（g1 scope 从 doc:42 改为 doc:43，
        // manifest digest 变化）。依赖栅栏向量因此仍然逐项匹配：
        // 增量护栏不得据此走快路径，必须保守全量重算，且结果与 full oracle
        // 逐字段等价（不得复用按旧父工件编译的段）。
        let g1 = root_grant(1, "doc:42", "read", true);
        let g2 = root_grant(3, "doc:100", "read", true);
        let parent_v1 = root_state_publication(vec![g1.clone(), g2.clone()]);
        let mut g1_moved = g1.clone();
        g1_moved.scope = root_scope("doc:43", "read");
        let parent_v2 = root_state_publication(vec![g1_moved, g2.clone()]);
        assert_ne!(parent_v1.manifest_digest_hex, parent_v2.manifest_digest_hex);
        // 头栅栏逐项相同（这正是本测试要击穿的快路径前提）。
        assert_eq!(
            parent_dependency_of(&parent_v1),
            parent_dependency_of(&parent_v2)
        );

        let c1 = child_grant(2, root_ref(&g1), child_scope("doc:42", "read"), false);
        let c2 = child_grant(4, root_ref(&g2), child_scope("doc:100", "read"), false);
        let base = applied(
            OrgCompiler::new()
                .compile_full(&OrgCompileInput {
                    node: child_node(1),
                    dependencies: vec![parent_dependency_of(&parent_v1)],
                    parent_publications: vec![parent_v1.clone()],
                    grants: vec![c1.clone(), c2.clone()],
                    masks: Vec::new(),
                    operation_id: "op-child-compile".to_owned(),
                })
                .unwrap(),
        );
        assert!(base.admission_ready());
        assert_eq!(base.segments.len(), 2);

        // 增量输入：grants/masks 完全未变，仅父工件换成 parent_v2。
        let second = OrgCompileInput {
            node: child_node(2),
            dependencies: vec![parent_dependency_of(&parent_v2)],
            parent_publications: vec![parent_v2],
            grants: vec![c1, c2],
            masks: Vec::new(),
            operation_id: "op-child-compile-2".to_owned(),
        };
        let incremental = OrgCompiler::new()
            .compile_incremental(&base, &second)
            .unwrap();
        // c1 的父 scope 不再覆盖 → 显式 PENDING（不得静默沿用旧段放行）。
        assert_eq!(
            pending_codes(incremental.clone()),
            vec![OrgPendingCode::ScopeNotCovered]
        );
        // 与 full oracle 逐字段等价（旧快路径会复用 stale 段 ⇒ 违反 parity）。
        let full = OrgCompiler::new().compile_full(&second).unwrap();
        assert_eq!(state_of(incremental.clone()), state_of(full.clone()));
        assert_eq!(incremental, full);

        // 保守全量重算的证据：段 Arc 不得复用 base 的句柄。
        let incremental_state = state_of(incremental);
        let full_state = state_of(full);
        let kept_key = scope_key_of(&child_scope("doc:100", "read"));
        let before = base.segment_cell(&kept_key).unwrap();
        let after = incremental_state.segment_cell(&kept_key).unwrap();
        assert!(!Arc::ptr_eq(&before, &after));
        // 旧父工件派生的 stale 段必须消失。
        assert!(incremental_state
            .segment_cell(&scope_key_of(&child_scope("doc:42", "read")))
            .is_none());
        assert_eq!(full_state.segments.len(), 1);
    }

    #[test]
    fn parent_manifest_identity_change_rejects_segment_arc_reuse() {
        // 更尖锐的情形：换装父工件后派生结果完全相同（仅 publication
        // operation_id 不同 → manifest digest 不同）。ledger diff 与解析均无变化，
        // 但增量护栏仍必须拒绝未变段 Arc 复用（保守全量重算），
        // 不得因依赖栅栏向量恰好匹配而走快路径。
        let g1 = root_grant(1, "doc:42", "read", true);
        let parent_v1 = root_state_publication(vec![g1.clone()]);
        let mut root_input_v2 = root_input(root_node(1), vec![g1.clone()]);
        root_input_v2.operation_id = "op-root-compile-b".to_owned();
        let parent_v2 = applied(OrgCompiler::new().compile_full(&root_input_v2).unwrap())
            .to_publication()
            .unwrap();
        assert_ne!(parent_v1.manifest_digest_hex, parent_v2.manifest_digest_hex);
        assert_eq!(
            parent_dependency_of(&parent_v1),
            parent_dependency_of(&parent_v2)
        );

        let c1 = child_grant(2, root_ref(&g1), child_scope("doc:42", "read"), false);
        let base = applied(
            OrgCompiler::new()
                .compile_full(&OrgCompileInput {
                    node: child_node(1),
                    dependencies: vec![parent_dependency_of(&parent_v1)],
                    parent_publications: vec![parent_v1],
                    grants: vec![c1.clone()],
                    masks: Vec::new(),
                    operation_id: "op-child-compile".to_owned(),
                })
                .unwrap(),
        );
        let key = scope_key_of(&child_scope("doc:42", "read"));
        let before = base.segment_cell(&key).unwrap();

        let second = OrgCompileInput {
            node: child_node(2),
            dependencies: vec![parent_dependency_of(&parent_v2)],
            parent_publications: vec![parent_v2],
            grants: vec![c1],
            masks: Vec::new(),
            operation_id: "op-child-compile-2".to_owned(),
        };
        let incremental = OrgCompiler::new()
            .compile_incremental(&base, &second)
            .unwrap();
        let next = state_of(incremental);
        // 派生结果未变 ⇒ 仍准入就绪。
        assert!(next.admission_ready());
        let after = next.segment_cell(&key).unwrap();
        // 内容相同也不得复用 base 的 Arc：快路径被父身份护栏拒绝。
        assert!(!Arc::ptr_eq(&before, &after));
        // 且与 full oracle 逐字段等价。
        let full = state_of(OrgCompiler::new().compile_full(&second).unwrap());
        assert_eq!(next, full);
    }

    #[test]
    fn query_index_candidates_cover_resource_forms_aliases_and_subjects() {
        let g1 = root_grant(1, "doc:42", "read", true);
        let g2 = root_grant(3, "doc:*", "write", true);
        let mut personal = root_grant(4, "doc:7", "read", false);
        personal.subject = Some(OrgSubject {
            user_id: 11,
            card_id: 222,
        });
        let input = root_input(root_node(1), vec![g1.clone(), g2.clone(), personal.clone()]);
        let state = applied(OrgCompiler::new().compile_full(&input).unwrap());
        let index = OrgQueryIndex::from_state(&state);

        let request = |resource: &str, action: &str, now: i64| OrgReadRequest {
            resource: resource.to_owned(),
            action: action.to_owned(),
            resource_tenant_id: ROOT_TENANT,
            domain_id: None,
            now_unix_seconds: now,
        };

        // 对象请求命中对象级 grant。
        let hits = index.candidates(
            &request("doc:42", "read", 1_500),
            OrgSubjectFilter::SharedOnly,
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].grant_ref.grant_id, uuid(1));

        // 对象请求命中类型级桶 + write 别名（create 命中 write 源）。
        let hits = index.candidates(
            &request("doc:50", "create", 1_500),
            OrgSubjectFilter::SharedOnly,
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].grant_ref.grant_id, uuid(3));

        // 类型级请求不命中对象桶，但命中类型级桶。
        let hits = index.candidates(
            &request("doc:*", "read", 1_500),
            OrgSubjectFilter::SharedOnly,
        );
        assert!(hits.is_empty());
        let hits = index.candidates(
            &request("doc:*", "write", 1_500),
            OrgSubjectFilter::SharedOnly,
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].grant_ref.grant_id, uuid(3));

        // 个人主体过滤。
        let hits = index.candidates(
            &request("doc:7", "read", 1_500),
            OrgSubjectFilter::PersonalOf {
                user_id: 11,
                card_id: 222,
            },
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].grant_ref.grant_id, uuid(4));
        let hits = index.candidates(
            &request("doc:7", "read", 1_500),
            OrgSubjectFilter::SharedOnly,
        );
        assert!(hits.is_empty());

        // 统一时钟有效期：过期后零命中。
        let hits = index.candidates(
            &request("doc:42", "read", 2_500),
            OrgSubjectFilter::SharedOnly,
        );
        assert!(hits.is_empty());
    }

    #[test]
    fn query_index_from_publication_validates_digests() {
        let g1 = root_grant(1, "doc:42", "read", true);
        let input = root_input(root_node(1), vec![g1]);
        let state = applied(OrgCompiler::new().compile_full(&input).unwrap());
        let publication = state.to_publication().unwrap();
        let index = OrgQueryIndex::from_publication(&publication).unwrap();
        assert_eq!(index.segment_count(), 1);

        let mut tampered = publication.clone();
        tampered.segments[0].digest_hex = String::new();
        let error = OrgQueryIndex::from_publication(&tampered).unwrap_err();
        assert_eq!(error.code, OrgErrorCode::DigestMismatch);
    }

    #[test]
    fn dependency_digest_is_order_independent() {
        let a = OrgDependency {
            tenant_id: 100,
            generation: 3,
            revoke_fence: 1,
            relationship_revision: 2,
        };
        let b = OrgDependency {
            tenant_id: 200,
            generation: 7,
            revoke_fence: 0,
            relationship_revision: 5,
        };
        let left = org_dependency_digest_hex(&[a, b]).unwrap();
        let right = org_dependency_digest_hex(&[b, a]).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn bounds_are_enforced_on_compile_input() {
        let mut node = root_node(1);
        node.tenant_id = -1;
        let input = root_input(node, vec![]);
        let error = OrgCompiler::new().compile_full(&input).unwrap_err();
        assert_eq!(error.code, OrgErrorCode::InvalidField);
    }
}
