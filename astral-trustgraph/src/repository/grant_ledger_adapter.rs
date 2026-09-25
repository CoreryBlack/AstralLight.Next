//! 审批授权账本适配器 — GrantLedgerAdapter
//!
//! 把一次已批准的审批（approve_with_rule，CAS `PENDING -> APPROVED` 后取得的稳定
//! rule_id）组装为 Phase 1 授权账本的 typed 写入请求
//! （`astral_db::GrantRevisionAppendRequest` / `astral_db::DeltaEventAppendRequest`），
//! 并在调用方已持有的 source transaction 内追加 revision 与 delta event。
//!
//! 本模块只做**无网络的纯 DTO 组装与错误映射**，不发起任何 SQL：
//! - 业务身份（operation_id / event_id / grant_id / aggregate identity）全部由调用链
//!   传入或从稳定的 request context 派生一次；这里绝不生成随机业务 identity。
//!   随机值只允许出现在更深层各自 owner 的职责里（projection outbox event、worker
//!   lease token），它们以 durable 身份回传后仍通过本模块显式绑定。
//! - Aggregate 维度固定为 aggregate_type=`APPROVAL`、aggregate_id=request_id，
//!   source_entry=rule_id，binding_key=卡片作用域；grant id 由
//!   `GrantIdentityKey::derive_grant_id()` 确定性派生。
//! - 租户/用户/卡片/有效期/projection 身份无法证明时一律 fail-closed
//!   （`AstralError::Validation` / `AstralError::Internal`），不填假值、不回退 raw source。

use sqlx::MySql;

use astral_types::{
    AstralError, BindingLayer, CanonicalGrant, DeltaEventIdentity, DependencyVector,
    DependencyVersion, GrantDelta, GrantEffect, GrantEvidence, GrantId, GrantIdentityKey,
    GrantProvenance, GrantRevision, GrantSourceKind, GrantState, TenantScope, ValidityWindow,
};
use policy_engine::COMPILER_VERSION;
// ─────────────────────────────────────────────────────────────────────────────
// 公共组装层（已下沉 astral-db::grant_ledger —— 单一事实源，等价 re-export）
//
// 规则集（RULE_SET 来源）授权账本纯组装族与跨家族共用低层 helper 已下沉至
// astral-db `grant_ledger` 模块：identity 与 trustgraph 是两个独立服务二进制，
// 两者共用同一 GrantIdentityKey / DeltaEventIdentity / CanonicalGrant / GrantDelta
// 组装实现，同一张卡的同一条目绑定在两侧派生逐字节一致的 grant_id /
// contribution event id / canonical payload，不会制造重复或冲突的账本身份。
// 本文件保留同名 re-export，既有 crate 内调用方与结构守卫不受影响。
// ─────────────────────────────────────────────────────────────────────────────
pub(crate) use astral_db::grant_ledger::{
    append_direct_grant_delta_in_tx, append_ruleset_grant_delta_in_tx, binding_key_for,
    build_direct_add_draft, build_direct_remove_draft, build_direct_update_draft,
    build_ruleset_add_draft, build_ruleset_remove_draft, build_ruleset_update_draft,
    canonical_resource_key, card_dependency_id, derive_direct_identity, derive_direct_tenant,
    derive_ruleset_contribution_event_id, derive_ruleset_identity,
    direct_update_authorization_content_changed, map_contract_error, map_grant_repository_error,
    parse_validity_window, payload_id_mismatch, reject_unrepresentable_condition,
    require_direct_rule_positive_ids, require_positive,
    ruleset_update_authorization_content_changed, sha256_hex_of,
    update_authorization_content_changed, validated_contribution_event_id,
    validated_projection_identity, DirectRuleLedgerFacts, RuleSetEntryLedgerFacts,
    RuleSetMutationKind, DIRECT_AGGREGATE_TYPE, MAX_HEADER_OPERATION_ID_LENGTH,
    RULE_SET_AGGREGATE_TYPE,
};

#[cfg(test)]
pub(crate) use astral_db::grant_ledger::DirectGrantDeltaDraft;

/// 授权账本中审批来源的聚合类型（受 `validated_aggregate_type` 字符集约束）。
pub(crate) const APPROVAL_AGGREGATE_TYPE: &str = "APPROVAL";

// ─────────────────────────────────────────────────────────────────────────────
// 稳定业务身份派生（纯函数）
// ─────────────────────────────────────────────────────────────────────────────

/// 从稳定 request context 派生一次 durable operation id：
/// - 调用方提供了非空 request-id 头且只含安全 ASCII 字符时原样复用；
/// - 否则从审批请求主键确定性派生 `approval:{request_id}`。
///
/// 非法头部字符直接 Validation fail-closed，不做静默替换。
pub(crate) fn derive_approval_operation_id(
    request_id_header: Option<&str>,
    request_id: i64,
) -> Result<String, AstralError> {
    if request_id <= 0 {
        return Err(AstralError::Validation(
            "approval operation identity requires a positive permission_request id".into(),
        ));
    }
    let header = request_id_header.map(str::trim).filter(|v| !v.is_empty());
    let Some(header) = header else {
        return Ok(format!("approval:{request_id}"));
    };
    let usable = header.len() <= MAX_HEADER_OPERATION_ID_LENGTH
        && header.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        });
    if !usable {
        return Err(AstralError::Validation(format!(
            "approval request-id header is not reusable as a durable operation id: {header:?}"
        )));
    }
    Ok(header.to_owned())
}

// ─────────────────────────────────────────────────────────────────────────────
// APPROVAL REMOVE（与 Add 对称的撤销草稿；卡级联删除等 source removal 使用）
// ─────────────────────────────────────────────────────────────────────────────

/// 组装审批 REMOVE 撤销贡献所需的全部事实输入。每个字段都必须来自调用方
/// 已锁定（FOR UPDATE）的 source 行（user_card + PERMISSION_REQUEST 规则）；
/// 无法证明的值不允许组装期回填。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovalRemoveLedgerFacts {
    /// 锁定中的 user_card.tenant_id；NULL 在组装期 fail-closed。
    pub tenant_id: Option<i64>,
    /// 锁定中的 user_card.domain_id；允许 None（TenantScope 合同允许）。
    pub domain_id: Option<i64>,
    pub card_id: i64,
    pub user_id: i64,
    /// 锁定中 permission_rule.source_id（PERMISSION_REQUEST 规则携带的请求主键）。
    pub request_id: i64,
    /// 锁定规则主键：本贡献在 APPROVAL 聚合内的 source_entry。
    pub rule_id: i64,
}

/// 审批贡献操作语义 token（DeltaEventIdentity.mutation_kind）。当前撤销链路只
/// 需要 remove；枚举与 direct/rule set 同族，扩展新语义时共享同一事件号门禁。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApprovalContributionKind {
    Remove,
}

impl ApprovalContributionKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Remove => "remove",
        }
    }
}

fn require_approval_positive_ids(facts: &ApprovalRemoveLedgerFacts) -> Result<(), AstralError> {
    require_positive(facts.card_id, "card id")?;
    require_positive(facts.user_id, "card owner user id")?;
    require_positive(facts.request_id, "permission_request id")?;
    require_positive(facts.rule_id, "permission_rule id")?;
    Ok(())
}

/// 由单个 builder 共用的审批身份解析结果。
struct ApprovalIdentityContext {
    tenant_scope: TenantScope,
    tenant_id: i64,
    grant_id: GrantId,
}

/// 解析租户作用域并确定性派生审批贡献身份（aggregate=`APPROVAL`、
/// aggregate_id=request、source_entry=rule、binding scope=卡片承载作用域）。
/// 与 [`build_approval_add_draft`] 完全同一路径，不存在第二套身份实现。
fn resolve_approval_identity(
    facts: &ApprovalRemoveLedgerFacts,
) -> Result<ApprovalIdentityContext, AstralError> {
    require_approval_positive_ids(facts)?;
    let tenant_id = facts.tenant_id.ok_or_else(|| {
        AstralError::Validation(
            "locked user_card has a NULL tenant_id; a tenant-scoped approval grant cannot be assembled"
                .into(),
        )
    })?;
    require_positive(tenant_id, "tenant id")?;
    let tenant_scope = TenantScope::new(tenant_id, facts.domain_id).map_err(map_contract_error)?;
    let identity_key = GrantIdentityKey::approval(
        tenant_scope.clone(),
        &facts.request_id.to_string(),
        &facts.rule_id.to_string(),
        &binding_key_for(facts.card_id),
    )
    .map_err(map_contract_error)?;
    let grant_id = identity_key.derive_grant_id().map_err(map_contract_error)?;
    Ok(ApprovalIdentityContext {
        tenant_scope,
        tenant_id,
        grant_id,
    })
}

/// 通过与 Add builder 完全相同的路径派生审批 grant 身份主键；调用方据此在锁定
/// 事务内定位账本 head（head 缺失即 fail-closed，见卡级联删除路径）。
pub(crate) fn derive_approval_identity(
    facts: &ApprovalRemoveLedgerFacts,
) -> Result<GrantId, AstralError> {
    Ok(resolve_approval_identity(facts)?.grant_id)
}

/// 从批次共享的稳定 operation id + 单条审批撤销贡献的稳定维度
/// （租户/APPROVAL 聚合×request/rule/kind）派生该贡献独立且可重放的
/// delta event id。相同输入重放得到相同 id，唯一冲突只可能来自真实重复提交。
pub(crate) fn derive_approval_contribution_event_id(
    operation_id: &str,
    facts: &ApprovalRemoveLedgerFacts,
    kind: ApprovalContributionKind,
) -> Result<String, AstralError> {
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "approval contribution identity requires the shared durable operation id".into(),
        ));
    }
    require_approval_positive_ids(facts)?;
    let tenant_id = facts.tenant_id.ok_or_else(|| {
        AstralError::Validation(
            "locked user_card has a NULL tenant_id; an approval contribution event id cannot be derived without a tenant scope"
                .into(),
        )
    })?;
    require_positive(tenant_id, "tenant id")?;
    let identity = DeltaEventIdentity {
        operation_id,
        tenant_id,
        aggregate_type: APPROVAL_AGGREGATE_TYPE,
        aggregate_id: facts.request_id,
        source_entry: &facts.rule_id.to_string(),
        mutation_kind: kind.as_str(),
    };
    let event_id = identity
        .derive_event_id()
        .map_err(map_contract_error)?
        .to_string();
    validated_contribution_event_id(&event_id)?;
    Ok(event_id)
}

/// 校验 head 快照与本次审批撤销声明的身份一致：grant id / source kind /
/// binding layer / provenance.source_entry(=rule) / provenance.source_id(=request) /
/// 租户域 / 卡与用户归属任一漂移都 fail-closed，禁止把 tombstone 打到另一份
/// 账本记录上（对齐 direct / rule set 的既有对齐校验族）。
fn assert_approval_head_alignment(
    head: &astral_db::GrantHeadSnapshot,
    expected_grant_id: GrantId,
    tenant_scope: &TenantScope,
    card_id: i64,
    user_id: i64,
    request_id: i64,
    rule_id: i64,
) -> Result<(), AstralError> {
    if head.grant_id != expected_grant_id || head.payload.grant_id != expected_grant_id {
        return Err(AstralError::Internal(format!(
            "grant ledger head {0} does not match the derived approval identity",
            head.grant_id.as_str()
        )));
    }
    if head.payload.source_kind != GrantSourceKind::Approval
        || head.payload.binding_layer != BindingLayer::None
    {
        return Err(AstralError::Validation(
            "grant ledger head is not an APPROVAL none-layer grant; refusing to revoke it from the approval path".into(),
        ));
    }
    if payload_id_mismatch(
        head.payload.provenance.source_entry.as_deref(),
        &rule_id.to_string(),
    ) {
        return Err(AstralError::Internal(
            "grant ledger head provenance source_entry does not match the locked approval rule id"
                .into(),
        ));
    }
    if payload_id_mismatch(
        Some(head.payload.provenance.source_id.as_str()),
        &request_id.to_string(),
    ) {
        return Err(AstralError::Internal(
            "grant ledger head provenance source_id does not match the locked permission_request id"
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

/// 组装完成的审批 REMOVE 贡献草稿：revision 与 delta event 共享同一数据。
/// before-image/digest 成对出现（REMOVE 必带旧 canonical grant 输入）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovalRemoveDraft {
    tenant_id: i64,
    card_id: i64,
    request_id: i64,
    event_id: String,
    operation_id: String,
    grant_id: GrantId,
    delta: GrantDelta,
    semantic_hash_hex: String,
    dependency_hash_hex: String,
    before_image_json: String,
    before_digest_hex: String,
    /// 本批次共享 CARD 投影事件身份绑定的 generation/fence。
    source_generation: u64,
    revoke_fence: u64,
}

impl ApprovalRemoveDraft {
    fn revision_request(&self) -> astral_db::GrantRevisionAppendRequest {
        astral_db::GrantRevisionAppendRequest {
            tenant_id: self.tenant_id,
            card_id_scope: Some(self.card_id),
            aggregate_type: APPROVAL_AGGREGATE_TYPE.to_owned(),
            aggregate_id: self.request_id,
            delta: self.delta.clone(),
            event_id: self.event_id.clone(),
            operation_id: self.operation_id.clone(),
            semantic_hash_hex: self.semantic_hash_hex.clone(),
            dependency_hash_hex: self.dependency_hash_hex.clone(),
            compiler_version: COMPILER_VERSION.to_owned(),
        }
    }

    fn delta_event_request(
        &self,
        base_version: i64,
        target_version: i64,
    ) -> Result<astral_db::DeltaEventAppendRequest, AstralError> {
        let delta_json = serde_json::to_string(&self.delta).map_err(|error| {
            AstralError::Internal(format!("delta serialization failed: {error}"))
        })?;
        Ok(astral_db::DeltaEventAppendRequest {
            tenant_id: self.tenant_id,
            card_id: Some(self.card_id),
            aggregate_type: APPROVAL_AGGREGATE_TYPE.to_owned(),
            aggregate_id: self.request_id,
            grant_id: self.grant_id,
            event_id: self.event_id.clone(),
            operation_id: self.operation_id.clone(),
            // approval remove 与 direct/rule set 同为 tombstone kind=`REMOVE`
            // （source removal 语义）；revoke fence 由 CARD REVOKE 投影事件递增。
            event_type: astral_db::DeltaEventType::Remove,
            base_version,
            target_version,
            source_generation: self.source_generation,
            revoke_fence: self.revoke_fence,
            invalidates_published_evidence: true,
            before_image_json: Some(self.before_image_json.clone()),
            before_digest_hex: Some(self.before_digest_hex.clone()),
            delta_json,
            semantic_hash_hex: self.semantic_hash_hex.clone(),
            dependency_hash_hex: self.dependency_hash_hex.clone(),
            compiler_version: COMPILER_VERSION.to_owned(),
            next_attempt_at: None,
        })
    }
}

/// 纯组装一条审批规则撤销贡献（REMOVE rev=head+1）。旧 canonical grant 作为
/// before-image 成对落库，semantic hash 锚定被移除的旧授权内容；不把审批 REMOVE
/// 当普通 DENY、也不删除/篡改账本行 —— 只追加版本化 tombstone。
///
/// - `projection`：本批次共享的 CARD parent 投影事件身份，仅提供 generation/fence
///   绑定与形状校验；
/// - `contribution_event_id`：本贡献自身落库使用的独立稳定事件号（批量路径由
///   `derive_approval_contribution_event_id` 派生）。
pub(crate) fn build_approval_remove_draft(
    facts: &ApprovalRemoveLedgerFacts,
    head: &astral_db::GrantHeadSnapshot,
    operation_id: &str,
    projection: &astral_db::ProjectionEventIdentity,
    contribution_event_id: &str,
) -> Result<ApprovalRemoveDraft, AstralError> {
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "approval remove operation id must not be empty".into(),
        ));
    }
    let identity_context = resolve_approval_identity(facts)?;
    assert_approval_head_alignment(
        head,
        identity_context.grant_id,
        &identity_context.tenant_scope,
        facts.card_id,
        facts.user_id,
        facts.request_id,
        facts.rule_id,
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

    Ok(ApprovalRemoveDraft {
        tenant_id: identity_context.tenant_id,
        card_id: facts.card_id,
        request_id: facts.request_id,
        event_id: contribution,
        operation_id: operation_id.to_owned(),
        grant_id: identity_context.grant_id,
        delta,
        semantic_hash_hex,
        dependency_hash_hex: dependency_vector
            .canonical_hash()
            .map_err(map_contract_error)?,
        before_image_json,
        before_digest_hex,
        source_generation: projection_identity.generation,
        revoke_fence: projection_identity.fence,
    })
}

/// 在调用方事务内追加一条审批 REMOVE 贡献：revision（immutable）+ delta event。
/// 任一错误向上传播触发整体回滚；本函数不 commit、不访问 Redis/MQ、不吞错。
pub(crate) async fn append_approval_remove_in_tx(
    tx: &mut sqlx::Transaction<'_, MySql>,
    draft: &ApprovalRemoveDraft,
    base_version: i64,
    target_version: i64,
) -> Result<(), AstralError> {
    if target_version <= base_version || base_version < 0 {
        return Err(AstralError::Validation(
            "approval remove delta version must strictly advance from a non-negative base".into(),
        ));
    }
    astral_db::append_grant_revision_in_tx(&mut *tx, &draft.revision_request())
        .await
        .map_err(map_grant_repository_error)?;
    astral_db::append_delta_event(
        &mut **tx,
        &draft.delta_event_request(base_version, target_version)?,
    )
    .await
    .map_err(map_grant_repository_error)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// DIRECT 来源（permission_rule 卡载直授权）— 稳定身份派生
// ─────────────────────────────────────────────────────────────────────────────

/// Gateway 已验证的操作者上下文，贯穿整个 direct permission-rule mutation：
/// provenance/evidence/delta/audit/outbox 共享同一 actor 与 operation id。
#[derive(Debug, Clone)]
pub struct DirectRuleMutationContext {
    /// 操作者用户 id（必须来自已验证身份头，正数）。
    pub actor_user_id: i64,
    /// 可选的 HTTP request-id 头（安全 ASCII 时复用为 durable operation id）。
    pub request_id_header: Option<String>,
}

impl DirectRuleMutationContext {
    /// 构造上下文；缺省/空白 request-id 允许（回退到确定性派生），但
    /// actor 缺失或非正数一律拒绝。
    pub fn user(actor_user_id: i64, request_id_header: Option<&str>) -> Result<Self, AstralError> {
        if actor_user_id <= 0 {
            return Err(AstralError::Permission(
                "direct permission-rule mutation requires a verified positive actor id".into(),
            ));
        }
        let header = request_id_header
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        Ok(Self {
            actor_user_id,
            request_id_header: header,
        })
    }

    pub(crate) fn header(&self) -> Option<&str> {
        self.request_id_header.as_deref()
    }
}

/// direct 规则 operation 的稳定语义段（同一 operation 内所有 durable 记录共享
/// 同一个 operation id；不同 invocation 由 rule 主键/request-id 区分）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectRuleOperationKind {
    Create,
    Update,
    Remove,
}

impl DirectRuleOperationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Remove => "remove",
        }
    }
}

/// 单规则 direct operation id：安全 request-id 头优先原样复用，否则从
/// `{kind}:{rule_id}` 确定性派生 `permission-rule:{kind}:{rule_id}`。
/// 非法头部字符直接 fail-closed，不做静默替换。
pub(crate) fn derive_direct_rule_operation_id(
    kind: DirectRuleOperationKind,
    rule_id: i64,
    request_id_header: Option<&str>,
) -> Result<String, AstralError> {
    if rule_id <= 0 {
        return Err(AstralError::Validation(
            "direct permission-rule operation identity requires a positive rule id".into(),
        ));
    }
    let header = request_id_header.map(str::trim).filter(|v| !v.is_empty());
    let Some(header) = header else {
        return Ok(format!("permission-rule:{}:{rule_id}", kind.as_str()));
    };
    let usable = header.len() <= MAX_HEADER_OPERATION_ID_LENGTH
        && header.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        });
    if !usable {
        return Err(AstralError::Validation(format!(
            "direct rule request-id header is not reusable as a durable operation id: {header:?}"
        )));
    }
    Ok(header.to_owned())
}

/// 批量删除（by-card / by-source）一次调用共用一个稳定 operation id，
/// 覆盖该调用产生的全部 REMOVE delta 与审计关联。
pub(crate) fn derive_direct_rule_batch_operation_id(
    scope: &'static str,
    scope_id: &str,
    request_id_header: Option<&str>,
) -> Result<String, AstralError> {
    if scope.trim().is_empty() || scope_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "batch removal operation identity requires a non-empty scope".into(),
        ));
    }
    let header = request_id_header.map(str::trim).filter(|v| !v.is_empty());
    let Some(header) = header else {
        return Ok(format!("permission-rule:{scope}:{scope_id}"));
    };
    let usable = header.len() <= MAX_HEADER_OPERATION_ID_LENGTH
        && header.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        });
    if !usable {
        return Err(AstralError::Validation(format!(
            "batch removal request-id header is not reusable as a durable operation id: {header:?}"
        )));
    }
    Ok(header.to_owned())
}

/// 从批次共享的稳定 operation id + 单条规则贡献的稳定身份维度（租户/卡/rule）
/// 派生该贡献独立且可重放的 delta event id。
///
/// - 同一批次内两条不同 rule 必然得到不同 event id（满足
///   `authorization_delta_event.uk_ade_event` 全局唯一），不再把 source 投影
///   事件号重复用作多个 delta 的事件号；
/// - 相同 (operation, tenant, card, rule, kind) 重试得到相同 id —— 因此该键上的
///   唯一冲突只可能来自真实重复提交，并按既有 fail-closed 映射显式拒绝；
/// - 租户/卡/rule 任一维度不同必然不同，跨租户/跨批次永不碰撞；
/// - 派生经 astral-types 固定 namespace helper 完成（域分离于 grant identity），
///   不引入任何随机业务身份。
pub(crate) fn derive_direct_contribution_event_id(
    operation_id: &str,
    facts: &DirectRuleLedgerFacts<'_>,
    kind: DirectRuleOperationKind,
) -> Result<String, AstralError> {
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "direct contribution identity requires the shared durable operation id".into(),
        ));
    }
    require_direct_rule_positive_ids(facts)?;
    let tenant_id = derive_direct_tenant(facts)?;
    let identity = DeltaEventIdentity {
        operation_id,
        tenant_id,
        aggregate_type: DIRECT_AGGREGATE_TYPE,
        aggregate_id: facts.card_id,
        source_entry: &facts.rule_id.to_string(),
        mutation_kind: kind.as_str(),
    };
    let event_id = identity
        .derive_event_id()
        .map_err(map_contract_error)?
        .to_string();
    validated_contribution_event_id(&event_id)?;
    Ok(event_id)
}

/// 审批授权账本的输入快照：全部来自锁定中的 source 行与已批准请求内容。
pub(crate) struct ApprovalGrantLedgerContext<'a> {
    /// 锁定中的 user_card.tenant_id；旧 schema 允许 NULL，None 会在组装期 fail-closed。
    pub user_card_tenant_id: Option<i64>,
    /// 锁定中的 user_card.domain_id；可为 None（TenantScope 契约允许）。
    pub domain_id: Option<i64>,
    pub card_id: i64,
    pub user_id: i64,
    pub request_id: i64,
    pub reviewer_id: i64,
    /// INSERT permission_rule 取得的稳定规则主键，作为本贡献的 source_entry。
    pub rule_id: i64,
    pub resource: &'a str,
    /// 锁定行的对象作用域主键；Some(id) → canonical resource `type:id`，
    /// None → `type:*`。审批请求内容（deny_unknown_fields）当前无法携带
    /// resource id，调用方显式传 None。
    pub resource_id: Option<i64>,
    pub action: &'a str,
    /// 审批规则的真实条件文本（原样传入，不解析）；非空值在 ADD 组装期
    /// fail-closed（canonical 合同无 condition 槽位）。
    pub condition_json: Option<&'a str>,
    pub valid_from: Option<&'a str>,
    pub valid_to: Option<&'a str>,
    /// 已由 approve 调用链派生一次的 durable operation id。
    pub operation_id: &'a str,
}

/// 组装完成的 ADD 贡献草稿：revision 与 delta event 两个请求共享同一份数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovalAddDraft {
    tenant_id: i64,
    card_id: i64,
    request_id: i64,
    card_generation: u64,
    revoke_fence: u64,
    event_id: String,
    operation_id: String,
    grant_id: GrantId,
    delta: GrantDelta,
    semantic_hash_hex: String,
    dependency_hash_hex: String,
}

impl ApprovalAddDraft {
    fn revision_request(&self) -> astral_db::GrantRevisionAppendRequest {
        astral_db::GrantRevisionAppendRequest {
            tenant_id: self.tenant_id,
            card_id_scope: Some(self.card_id),
            aggregate_type: APPROVAL_AGGREGATE_TYPE.to_owned(),
            aggregate_id: self.request_id,
            delta: self.delta.clone(),
            event_id: self.event_id.clone(),
            operation_id: self.operation_id.clone(),
            semantic_hash_hex: self.semantic_hash_hex.clone(),
            dependency_hash_hex: self.dependency_hash_hex.clone(),
            compiler_version: COMPILER_VERSION.to_owned(),
        }
    }

    fn delta_event_request(&self) -> Result<astral_db::DeltaEventAppendRequest, AstralError> {
        let delta_json = serde_json::to_string(&self.delta).map_err(|error| {
            AstralError::Internal(format!("delta serialization failed: {error}"))
        })?;
        Ok(astral_db::DeltaEventAppendRequest {
            tenant_id: self.tenant_id,
            card_id: Some(self.card_id),
            aggregate_type: APPROVAL_AGGREGATE_TYPE.to_owned(),
            aggregate_id: self.request_id,
            grant_id: self.grant_id,
            event_id: self.event_id.clone(),
            operation_id: self.operation_id.clone(),
            event_type: astral_db::DeltaEventType::Add,
            base_version: 0,
            target_version: 1,
            source_generation: self.card_generation,
            revoke_fence: self.revoke_fence,
            invalidates_published_evidence: false,
            // 无 before-image：ADD 天然没有前像，两个字段必须成对为空。
            before_image_json: None,
            before_digest_hex: None,
            delta_json,
            semantic_hash_hex: self.semantic_hash_hex.clone(),
            dependency_hash_hex: self.dependency_hash_hex.clone(),
            compiler_version: COMPILER_VERSION.to_owned(),
            next_attempt_at: None,
        })
    }
}

/// 纯组装一个 ADD 贡献草稿（无网络、无随机业务身份）。
pub(crate) fn build_approval_add_draft(
    context: &ApprovalGrantLedgerContext<'_>,
    projection: &astral_db::ProjectionEventIdentity,
) -> Result<ApprovalAddDraft, AstralError> {
    // 1. 租户作用域：锁定行 tenant 为空则不能拼出租户边界 —— fail-closed。
    let tenant_id = context.user_card_tenant_id.ok_or_else(|| {
        AstralError::Validation(
            "locked user_card has a NULL tenant_id; a tenant-scoped approval grant cannot be assembled"
                .into(),
        )
    })?;
    let tenant_scope =
        TenantScope::new(tenant_id, context.domain_id).map_err(map_contract_error)?;

    // 2. 全部参与恒等/授权数据的 id 必须为正。
    require_positive(context.card_id, "card id")?;
    require_positive(context.user_id, "requester user id")?;
    require_positive(context.request_id, "permission_request id")?;
    require_positive(context.reviewer_id, "reviewer actor id")?;
    require_positive(context.rule_id, "permission_rule id")?;
    if context.operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "approval operation id must not be empty".into(),
        ));
    }

    // 3. 投影事件身份（CARD APPROVED 的 durable generation/fence/event）。
    let projection_identity = validated_projection_identity(projection)?;

    // 3b. canonical 语义保真门禁：条件授权与对象作用域在进入 canonical 前显式裁决。
    reject_unrepresentable_condition(context.condition_json, "approval approve_with_rule")?;
    let resource = canonical_resource_key(context.resource, context.resource_id)?;

    // 4. 有效期：仅接受可证明的 UTC 时间串；两端缺失即 perpetual。
    let validity = parse_validity_window(context.valid_from, context.valid_to)?;

    // 5. 确定性身份键：aggregate=APPROVAL/request_id，source_entry=rule_id，
    //    binding_key=卡片承载作用域。
    let identity_key = GrantIdentityKey::approval(
        tenant_scope.clone(),
        &context.request_id.to_string(),
        &context.rule_id.to_string(),
        &binding_key_for(context.card_id),
    )
    .map_err(map_contract_error)?;
    let grant_id = identity_key.derive_grant_id().map_err(map_contract_error)?;

    // 6. Canonical grant：ACTIVE/ALLOW/APPROVAL+NONE 对齐由 canonicalized 门禁复核。
    let provisional_grant = CanonicalGrant {
        grant_id,
        revision: GrantRevision::initial(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::Approval,
        binding_layer: BindingLayer::None,
        tenant: tenant_scope.clone(),
        card_id: context.card_id,
        user_id: context.user_id,
        resource,
        action: context.action.to_owned(),
        effect: GrantEffect::Allow,
        validity,
        provenance: GrantProvenance {
            source_id: context.request_id.to_string(),
            source_entry: Some(context.rule_id.to_string()),
            // 审批贡献直接绑在卡上：无 binding/delegation 记录可携带，保持 None。
            binding_id: None,
            delegation_id: None,
            operation_id: context.operation_id.to_owned(),
            event_id: Some(projection_identity.event_id.clone()),
            actor_user_id: Some(context.reviewer_id),
        },
    };
    let canonical_grant = provisional_grant
        .canonicalized()
        .map_err(map_contract_error)?;

    // 7. ADD delta + evidence 校验：evidence 把 grant 绑定到 CARD generation fence。
    let delta = GrantDelta::add(canonical_grant.clone());
    delta.validate().map_err(map_contract_error)?;
    let dependency_vector = DependencyVector::new(vec![DependencyVersion::new(
        card_dependency_id(context.card_id),
        projection_identity.generation,
        projection_identity.fence,
    )
    .map_err(map_contract_error)?])
    .map_err(map_contract_error)?;
    let evidence = GrantEvidence {
        grant: canonical_grant.clone(),
        event_id: projection_identity.event_id.clone(),
        operation_id: context.operation_id.to_owned(),
        source_generation: projection_identity.generation,
        revoke_fence: projection_identity.fence,
        dependency_vector,
    };
    evidence.validate().map_err(map_contract_error)?;

    // 8. 合同规定的小写 SHA-256 hex：语义哈希取 canonical grant，依赖哈希取向量。
    let semantic_hash_hex = canonical_grant
        .canonical_hash()
        .map_err(map_contract_error)?;
    let dependency_hash_hex = evidence
        .dependency_vector
        .canonical_hash()
        .map_err(map_contract_error)?;

    Ok(ApprovalAddDraft {
        tenant_id,
        card_id: context.card_id,
        request_id: context.request_id,
        card_generation: projection_identity.generation,
        revoke_fence: projection_identity.fence,
        event_id: projection_identity.event_id,
        operation_id: context.operation_id.to_owned(),
        grant_id,
        delta,
        semantic_hash_hex,
        dependency_hash_hex,
    })
}

/// 在调用方事务内追加审批贡献：revision 1 的 immutable Add 与对应 delta event。
///
/// 两个 append 都属于同一事务，任一错误向上传播即可触发整体回滚；
/// 本函数不 commit、不访问 Redis/MQ、不吞错、不降级。
pub(crate) async fn append_approval_grant_in_tx(
    tx: &mut sqlx::Transaction<'_, MySql>,
    context: &ApprovalGrantLedgerContext<'_>,
    projection: &astral_db::ProjectionEventIdentity,
) -> Result<(), AstralError> {
    let draft = build_approval_add_draft(context, projection)?;

    astral_db::append_grant_revision_in_tx(&mut *tx, &draft.revision_request())
        .await
        .map_err(map_grant_repository_error)?;
    astral_db::append_delta_event(&mut **tx, &draft.delta_event_request()?)
        .await
        .map_err(map_grant_repository_error)?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// DELEGATION 来源（permission_delegation × 被委托承载卡）— 稳定身份派生与 delta 组装
// ─────────────────────────────────────────────────────────────────────────────

/// 授权账本中委托来源的聚合类型。每个委托聚合（permission_delegation 行）当前
/// 只产出**一条** DELEGATION ALLOW 规则贡献；贡献身份以稳定的 `delegation_id`
/// 为 source-entry 粒度（而不是每次重建都会漂移的 permission_rule.rule_id），
/// 因此 resource/action/effective_until 的更新复用同一 GrantId 做 UPDATE。
pub(crate) const DELEGATION_AGGREGATE_TYPE: &str = "DELEGATION";

/// 委托 mutation 的稳定语义段（同一 operation 内所有 durable 记录共享同一个
/// operation id；不同 mutation kind / 不同委托必然分叉）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DelegationMutationKind {
    Create,
    Update,
    Revoke,
}

impl DelegationMutationKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Revoke => "revoke",
        }
    }
}

/// 委托贡献的 mutation-kind token（DeltaEventIdentity.mutation_kind）。生命周期
/// 撤权固定使用 `revoke`（与 direct/rule set 的 source removal 语义 `remove`
/// 严格分离），确保 create/update/revoke 三类事件号互不交叉。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DelegationContributionKind {
    Add,
    Update,
    Revoke,
}

impl DelegationContributionKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Update => "update",
            Self::Revoke => "revoke",
        }
    }
}

/// 委托 operation id：安全 request-id 头优先原样复用（≤64 字节、安全 ASCII），
/// 否则确定性派生，缺失头部绝不随机 fallback；非法头部字符直接 Validation
/// fail-closed。
///
/// fallback 的身份绑定（M1 修复契约）：
/// - `identity_bound_revision = None`：`delegation:{kind}:{delegation_id}` —— 仅用于
///   create（每次新建都是全新委托主键，天然不复用 identity）与幂等审计分支；
/// - `identity_bound_revision = Some(rev)`：update/revoke 等可能在**同一委托聚合上
///   连续成功多次**的 mutation 必须先锁定 grant head FOR UPDATE，再把锁定中的
///   durable revision 折入 id：`delegation:{kind}:{id}:r{rev}`。这样同一业务重试
///   （事务失败已对账且 head 未推进）重放得到同一 operation/contribution event id，
///   而 revision 推进后的下一次真实更新必然分叉，不再复用全局唯一的
///   `uk_ade_event` 事件号。
///
/// revision 必须为正数（head 存在即 ≥1），非正一律 Validation fail-closed；
/// 派生结果恒 <64 字节，与 `audit_log.request_id VARCHAR(64)` 同一 canonical 上限。
pub(crate) fn derive_delegation_operation_id(
    kind: DelegationMutationKind,
    delegation_id: i64,
    request_id_header: Option<&str>,
    identity_bound_revision: Option<u64>,
) -> Result<String, AstralError> {
    if delegation_id <= 0 {
        return Err(AstralError::Validation(
            "delegation operation identity requires a positive delegation id".into(),
        ));
    }
    let header = request_id_header.map(str::trim).filter(|v| !v.is_empty());
    let Some(header) = header else {
        return Ok(match identity_bound_revision {
            None => format!("delegation:{}:{delegation_id}", kind.as_str()),
            // 显式绑定锁定 head revision：同代重试相同、代次推进后必然分叉。
            Some(revision) => {
                if revision == 0 {
                    return Err(AstralError::Validation(
                        "revision-bound delegation operation identity requires a positive locked ledger revision".into(),
                    ));
                }
                let derived = format!("delegation:{}:{delegation_id}:r{revision}", kind.as_str());
                debug_assert!(
                    derived.len() < MAX_HEADER_OPERATION_ID_LENGTH,
                    "derived delegation operation id must stay under the audit column width"
                );
                if derived.len() >= MAX_HEADER_OPERATION_ID_LENGTH {
                    return Err(AstralError::Internal(format!(
                        "derived delegation operation id exceeds the {MAX_HEADER_OPERATION_ID_LENGTH}-byte audit column width"
                    )));
                }
                derived
            }
        });
    };
    let usable = header.len() <= MAX_HEADER_OPERATION_ID_LENGTH
        && header.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        });
    if !usable {
        return Err(AstralError::Validation(format!(
            "delegation request-id header is not reusable as a durable operation id: {header:?}"
        )));
    }
    Ok(header.to_owned())
}

/// 组装委托授权账本条目所需的全部事实输入。每个字段都必须来自调用方已锁定
/// （FOR UPDATE）的 source 行：tenant/domain/user/card 来自锁定的 ACTIVE 被委托
/// user_card（授权承载卡），resource/action/有效期来自锁定中的 delegation 聚合；
/// 无法证明的值不允许组装期回填。
#[derive(Debug, Clone)]
pub(crate) struct DelegationLedgerFacts<'a> {
    /// 锁定中的被委托卡 tenant_id；NULL 会在组装期 fail-closed。
    pub tenant_id: i64,
    /// 锁定中的被委托卡 domain_id；允许 None（TenantScope 合同允许）。
    pub domain_id: Option<i64>,
    /// 授权承载卡 = 被委托卡主键（delegator 卡绝不进入 CanonicalGrant）。
    pub card_id: i64,
    /// 被委托卡属主用户 id（授权受益人）。
    pub user_id: i64,
    /// 委托聚合主键：aggregate 身份、source-entry 粒度与 provenance.delegation_id。
    pub delegation_id: i64,
    pub resource: &'a str,
    pub action: &'a str,
    /// 有效期下界（UTC Unix 秒；None 即 perpetual 下界）。
    pub not_before_unix: Option<i64>,
    /// 有效期上界（UTC Unix 秒；委托合同恒有界）。
    pub expires_at_unix: i64,
}

fn require_delegation_positive_ids(facts: &DelegationLedgerFacts<'_>) -> Result<(), AstralError> {
    require_positive(facts.tenant_id, "delegate card tenant id")?;
    require_positive(facts.card_id, "delegate card id")?;
    require_positive(facts.user_id, "delegate card owner user id")?;
    require_positive(facts.delegation_id, "delegation id")?;
    if facts.expires_at_unix <= 0 {
        return Err(AstralError::Validation(
            "delegation canonical grant requires a positive expires_at unix timestamp".into(),
        ));
    }
    if let Some(not_before) = facts.not_before_unix {
        require_positive(not_before, "not_before unix timestamp")?;
    }
    Ok(())
}

/// 由单个 builder 共用的委托身份解析结果。
struct DelegationIdentityContext {
    tenant_scope: TenantScope,
    grant_id: GrantId,
}

/// 解析租户作用域并确定性派生委托贡献身份（aggregate=`DELEGATION`/
/// delegation_id，source_entry=稳定委托子句粒度=delegation_id，binding scope=
/// 同一委托链身份）。资源/action/有效期不进入身份：更新它们复用同一 GrantId。
fn resolve_delegation_identity(
    facts: &DelegationLedgerFacts<'_>,
) -> Result<DelegationIdentityContext, AstralError> {
    require_delegation_positive_ids(facts)?;
    let tenant_scope =
        TenantScope::new(facts.tenant_id, facts.domain_id).map_err(map_contract_error)?;
    let delegation_key = facts.delegation_id.to_string();
    // 当前模型一条委托恰好一条规则贡献；source_entry 采用稳定 delegation 主键，
    // rule_id churn（删旧插新）不影响身份。若未来单委托支持多子句，必须为每个
    // 子句派生独立 source-entry，禁止共享该粒度。
    let identity_key =
        GrantIdentityKey::delegation(tenant_scope.clone(), &delegation_key, &delegation_key)
            .map_err(map_contract_error)?;
    let grant_id = identity_key.derive_grant_id().map_err(map_contract_error)?;
    Ok(DelegationIdentityContext {
        tenant_scope,
        grant_id,
    })
}

/// 通过与 builder 完全相同的路径派生委托贡献的身份主键；调用方据此在锁定事务内
/// 定位账本 head（head 缺失即 fail-closed）。
pub(crate) fn derive_delegation_identity(
    facts: &DelegationLedgerFacts<'_>,
) -> Result<GrantId, AstralError> {
    Ok(resolve_delegation_identity(facts)?.grant_id)
}

/// 从批次共享的稳定 operation id + 单条委托贡献的稳定维度
/// （租户/DELEGATION 聚合×delegation/kind）派生该贡献独立且可重放的 delta event
/// id。parent CARD 投影事件与 contribution 事件号分离：同一 CARD parent 下
/// create/update/revoke 各自派生互异事件号，满足 `uk_ade_event` 全局唯一。
pub(crate) fn derive_delegation_contribution_event_id(
    operation_id: &str,
    facts: &DelegationLedgerFacts<'_>,
    kind: DelegationContributionKind,
) -> Result<String, AstralError> {
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "delegation contribution identity requires the shared durable operation id".into(),
        ));
    }
    require_delegation_positive_ids(facts)?;
    let identity = DeltaEventIdentity {
        operation_id,
        tenant_id: facts.tenant_id,
        aggregate_type: DELEGATION_AGGREGATE_TYPE,
        aggregate_id: facts.delegation_id,
        source_entry: &facts.delegation_id.to_string(),
        mutation_kind: kind.as_str(),
    };
    let event_id = identity
        .derive_event_id()
        .map_err(map_contract_error)?
        .to_string();
    validated_contribution_event_id(&event_id)?;
    Ok(event_id)
}

/// 校验 head 快照与本次委托 mutation 声明的身份一致：grant id / source kind /
/// binding layer（必须 NONE）/ provenance.delegation_id+source_id+source_entry(=
/// delegation) / 租户域 / 卡与用户归属任一漂移都 fail-closed，禁止把 delta 打到
/// 另一份账本记录上或把 delegator/delegate scope 混淆。
fn assert_delegation_head_alignment(
    head: &astral_db::GrantHeadSnapshot,
    expected_grant_id: GrantId,
    tenant_scope: &TenantScope,
    card_id: i64,
    user_id: i64,
    delegation_id: i64,
) -> Result<(), AstralError> {
    if head.grant_id != expected_grant_id || head.payload.grant_id != expected_grant_id {
        return Err(AstralError::Internal(format!(
            "grant ledger head {0} does not match the derived delegation identity",
            head.grant_id.as_str()
        )));
    }
    if head.payload.source_kind != GrantSourceKind::Delegation
        || head.payload.binding_layer != BindingLayer::None
    {
        return Err(AstralError::Validation(
            "grant ledger head is not a DELEGATION none-layer grant; refusing to mutate it from the delegation path".into(),
        ));
    }
    let delegation_key = delegation_id.to_string();
    match head.payload.provenance.delegation_id.as_deref() {
        Some(stored) if stored.trim() == delegation_key.trim() => {}
        _ => {
            return Err(AstralError::Internal(
                "grant ledger head provenance delegation_id does not match the locked permission_delegation row".into(),
            ));
        }
    }
    if payload_id_mismatch(
        head.payload.provenance.source_entry.as_deref(),
        &delegation_key,
    ) {
        return Err(AstralError::Internal(
            "grant ledger head provenance source_entry does not match the locked delegation identity"
                .into(),
        ));
    }
    if payload_id_mismatch(
        Some(head.payload.provenance.source_id.as_str()),
        &delegation_key,
    ) {
        return Err(AstralError::Internal(
            "grant ledger head provenance source_id does not match the locked delegation identity"
                .into(),
        ));
    }
    if head.payload.tenant != *tenant_scope {
        return Err(AstralError::Validation(
            "grant ledger head tenant/domain drifts from the locked delegate card row".into(),
        ));
    }
    if head.payload.card_id != card_id || head.payload.user_id != user_id {
        return Err(AstralError::Validation(
            "grant ledger head card/user context drifts from the locked delegate card row; delegator/delegate scope must not be confused".into(),
        ));
    }
    Ok(())
}

/// ADD/UPDATE 与 REVOKE 共用的组装完成的委托贡献草稿。revision 与 delta event
/// 请求共享同一份数据；before-image/digest 成对出现或同时缺席（ADD 双空）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DelegationGrantDeltaDraft {
    tenant_id: i64,
    card_id: i64,
    delegation_id: i64,
    event_id: String,
    operation_id: String,
    grant_id: GrantId,
    delta: GrantDelta,
    semantic_hash_hex: String,
    dependency_hash_hex: String,
    before_image_json: Option<String>,
    before_digest_hex: Option<String>,
    /// 带 metadata 的 CARD 投影事件身份（构造期绑定，防止 request 双写漂移）。
    source_generation: u64,
    revoke_fence: u64,
    /// This delta may leave published evidence authorizing pre-update access.
    invalidates_published_evidence: bool,
}

impl DelegationGrantDeltaDraft {
    fn revision_request(&self) -> astral_db::GrantRevisionAppendRequest {
        astral_db::GrantRevisionAppendRequest {
            tenant_id: self.tenant_id,
            card_id_scope: Some(self.card_id),
            aggregate_type: DELEGATION_AGGREGATE_TYPE.to_owned(),
            aggregate_id: self.delegation_id,
            delta: self.delta.clone(),
            event_id: self.event_id.clone(),
            operation_id: self.operation_id.clone(),
            semantic_hash_hex: self.semantic_hash_hex.clone(),
            dependency_hash_hex: self.dependency_hash_hex.clone(),
            compiler_version: COMPILER_VERSION.to_owned(),
        }
    }

    fn event_type(&self) -> astral_db::DeltaEventType {
        match self.delta.operation_name() {
            "ADD" => astral_db::DeltaEventType::Add,
            "UPDATE" => astral_db::DeltaEventType::Update,
            "REMOVE" => astral_db::DeltaEventType::Remove,
            // 生命周期撤权固定 tombstone kind=`REVOKE`（不含普通 DENY）。
            _ => astral_db::DeltaEventType::Revoke,
        }
    }

    fn delta_event_request(
        &self,
        base_version: i64,
        target_version: i64,
    ) -> Result<astral_db::DeltaEventAppendRequest, AstralError> {
        let delta_json = serde_json::to_string(&self.delta).map_err(|error| {
            AstralError::Internal(format!("delta serialization failed: {error}"))
        })?;
        Ok(astral_db::DeltaEventAppendRequest {
            tenant_id: self.tenant_id,
            card_id: Some(self.card_id),
            aggregate_type: DELEGATION_AGGREGATE_TYPE.to_owned(),
            aggregate_id: self.delegation_id,
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

    /// 本贡献自身的独立稳定事件号（审计 correlation 用）。
    pub(crate) fn event_id(&self) -> &str {
        &self.event_id
    }

    /// 确定性派生的账本身份主键（审计 correlation 用）。
    pub(crate) fn grant_id(&self) -> GrantId {
        self.grant_id
    }

    /// 成对 before-image digest（ADD 恒 None；UPDATE/REVOKE 必有）。
    pub(crate) fn before_digest_hex(&self) -> Option<&str> {
        self.before_digest_hex.as_deref()
    }

    /// 本 delta 生效后的账本 revision 值（组装期已通过合同校验）。
    pub(crate) fn resulting_revision_value(&self) -> u64 {
        self.delta
            .revision()
            .map(|revision| revision.value())
            .unwrap_or(0)
    }
}

/// 在调用方事务内追加一个委托贡献：revision（immutable）+ delta event，
/// 两者共享草稿身份；任一错误向上传播触发整体回滚。本函数不 commit、
/// 不访问 Redis/MQ、不吞错、不降级。
pub(crate) async fn append_delegation_grant_delta_in_tx(
    tx: &mut sqlx::Transaction<'_, MySql>,
    draft: &DelegationGrantDeltaDraft,
    base_version: i64,
    target_version: i64,
) -> Result<(), AstralError> {
    if target_version <= base_version || base_version < 0 {
        return Err(AstralError::Validation(
            "delegation delta version must strictly advance from a non-negative base".into(),
        ));
    }
    astral_db::append_grant_revision_in_tx(&mut *tx, &draft.revision_request())
        .await
        .map_err(map_grant_repository_error)?;
    astral_db::append_delta_event(
        &mut **tx,
        &draft.delta_event_request(base_version, target_version)?,
    )
    .await
    .map_err(map_grant_repository_error)?;
    Ok(())
}

/// 纯组装一条委托创建贡献（ADD rev1）。ADD 天然没有 before-image，两个字段保持
/// 成对缺席。provenance.delegation_id 必填且只在 DELEGATION 源出现（合同门禁）。
pub(crate) fn build_delegation_add_draft(
    facts: &DelegationLedgerFacts<'_>,
    operation_id: &str,
    actor_user_id: i64,
    projection: &astral_db::ProjectionEventIdentity,
    contribution_event_id: &str,
) -> Result<DelegationGrantDeltaDraft, AstralError> {
    require_delegation_positive_ids(facts)?;
    require_positive(actor_user_id, "actor user id")?;
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "delegation operation id must not be empty".into(),
        ));
    }
    let identity_context = resolve_delegation_identity(facts)?;
    // CARD（parent）投影事件提供 durable generation/fence 绑定与形状校验。
    let projection_identity = validated_projection_identity(projection)?;
    // 本贡献自身的独立事件号（parent 与 contribution 分离）。
    let contribution = validated_contribution_event_id(contribution_event_id)?;
    let validity = ValidityWindow {
        not_before: facts.not_before_unix,
        expires_at: Some(facts.expires_at_unix),
    };
    validity.validate().map_err(map_contract_error)?;
    let delegation_key = facts.delegation_id.to_string();

    let provisional_grant = CanonicalGrant {
        grant_id: identity_context.grant_id,
        revision: GrantRevision::initial(),
        state: GrantState::Active,
        source_kind: GrantSourceKind::Delegation,
        binding_layer: BindingLayer::None,
        tenant: identity_context.tenant_scope.clone(),
        card_id: facts.card_id,
        user_id: facts.user_id,
        resource: facts.resource.to_owned(),
        action: facts.action.to_owned(),
        effect: GrantEffect::Allow,
        validity,
        provenance: GrantProvenance {
            source_id: delegation_key.clone(),
            source_entry: Some(delegation_key.clone()),
            // 委托贡献直接绑在被委托卡上：无 rule-set binding 可携带，保持 None。
            binding_id: None,
            // 合同强制 DELEGATION 贡献携带 durable 委托证据链。
            delegation_id: Some(delegation_key.clone()),
            operation_id: operation_id.to_owned(),
            event_id: Some(contribution.clone()),
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
        event_id: contribution.clone(),
        operation_id: operation_id.to_owned(),
        source_generation: projection_identity.generation,
        revoke_fence: projection_identity.fence,
        dependency_vector,
    };
    evidence.validate().map_err(map_contract_error)?;

    Ok(DelegationGrantDeltaDraft {
        tenant_id: identity_context.tenant_scope.tenant_id,
        card_id: facts.card_id,
        delegation_id: facts.delegation_id,
        event_id: contribution,
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

/// 纯组装一条委托更新贡献（UPDATE rev=head+1），保留旧 canonical grant JSON 作为
/// 成对 before-image + digest。identity（delegation 粒度）不变 —— resource/action/
/// effective_until 只是可变属性。head 缺失、CAS/stale/gap 与 provenance 不一致仍由
/// repository / decide_revision_transition fail-closed。
///
/// effect 不从 head.payload 继承，而是显式钉为 `GrantEffect::Allow`（与
/// `build_ruleset_update_draft` 同一 ALLOW-only 纵深防御）：即使未来 head 形状
/// 演化携带其他 effect 语义，DELEGATION UPDATE 也绝不把非 ALLOW 放行写入账本。
pub(crate) fn build_delegation_update_draft(
    facts: &DelegationLedgerFacts<'_>,
    head: &astral_db::GrantHeadSnapshot,
    operation_id: &str,
    actor_user_id: i64,
    projection: &astral_db::ProjectionEventIdentity,
    contribution_event_id: &str,
) -> Result<DelegationGrantDeltaDraft, AstralError> {
    require_delegation_positive_ids(facts)?;
    require_positive(actor_user_id, "actor user id")?;
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "delegation operation id must not be empty".into(),
        ));
    }
    let identity_context = resolve_delegation_identity(facts)?;
    assert_delegation_head_alignment(
        head,
        identity_context.grant_id,
        &identity_context.tenant_scope,
        facts.card_id,
        facts.user_id,
        facts.delegation_id,
    )?;
    let projection_identity = validated_projection_identity(projection)?;
    let contribution = validated_contribution_event_id(contribution_event_id)?;
    let validity = ValidityWindow {
        not_before: facts.not_before_unix,
        expires_at: Some(facts.expires_at_unix),
    };
    validity.validate().map_err(map_contract_error)?;
    let expected_revision = head.entry.revision;
    let next_revision = expected_revision.next().map_err(map_contract_error)?;

    let mut updated = head.payload.clone();
    updated.resource = facts.resource.to_owned();
    updated.action = facts.action.to_owned();
    // ALLOW-only 纵深防御：effect 显式钉为 ALLOW，绝不继承 head.payload.effect
    //（对齐 build_ruleset_update_draft；head 形状演化时 UPDATE 仍只能产出放行语义）。
    updated.effect = GrantEffect::Allow;
    updated.validity = validity;
    updated.revision = next_revision;
    updated.state = GrantState::Active;
    updated.provenance.operation_id = operation_id.to_owned();
    updated.provenance.event_id = Some(contribution.clone());
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
        event_id: contribution.clone(),
        operation_id: operation_id.to_owned(),
        source_generation: projection_identity.generation,
        revoke_fence: projection_identity.fence,
        dependency_vector,
    };
    evidence.validate().map_err(map_contract_error)?;
    let invalidates_published_evidence =
        delegation_update_authorization_content_changed(facts, head)?;

    Ok(DelegationGrantDeltaDraft {
        tenant_id: identity_context.tenant_scope.tenant_id,
        card_id: facts.card_id,
        delegation_id: facts.delegation_id,
        event_id: contribution,
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

/// delegation UPDATE 的 before-image（head.payload）与新 grant 的
/// authorization-content 比较（与 [`build_delegation_update_draft`] 完全同源：
/// resource/action 取规范化 facts，validity 由 `not_before_unix`/`expires_at_unix`
/// 组成、上界恒有界）。调用方必须在追加 CARD 父投影事件**之前**调用，以便按
/// 结果选择 REVOKE（抬 fence）或原 DELEGATION_UPDATED 事件语义。判定语义
/// （保守 revoke-class、provenance-only 不参与）见 astral-db
/// `grant_ledger::update_authorization_content_changed`。
pub(crate) fn delegation_update_authorization_content_changed(
    facts: &DelegationLedgerFacts<'_>,
    head: &astral_db::GrantHeadSnapshot,
) -> Result<bool, AstralError> {
    let after_validity = ValidityWindow {
        not_before: facts.not_before_unix,
        expires_at: Some(facts.expires_at_unix),
    };
    Ok(update_authorization_content_changed(
        &head.payload,
        facts.resource,
        facts.action,
        &after_validity,
    ))
}

/// 纯组装一条委托生命周期撤权贡献（REVOKE rev=head+1）。tombstone kind 固定为
/// `REVOKE`（生命周期撤权语义，revoke fence 由本批 CARD REVOKE 投影事件递增）；
/// 旧 canonical grant JSON 作为 before-image 成对落库，semantic hash 锚定被撤的
/// 旧授权内容。重复撤销进入账本时由 decide_revision_transition 显式判为
/// DuplicateTombstone，不会生成新身份绕过。
pub(crate) fn build_delegation_revoke_draft(
    facts: &DelegationLedgerFacts<'_>,
    head: &astral_db::GrantHeadSnapshot,
    operation_id: &str,
    projection: &astral_db::ProjectionEventIdentity,
    contribution_event_id: &str,
) -> Result<DelegationGrantDeltaDraft, AstralError> {
    require_delegation_positive_ids(facts)?;
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "delegation revoke operation id must not be empty".into(),
        ));
    }
    let identity_context = resolve_delegation_identity(facts)?;
    assert_delegation_head_alignment(
        head,
        identity_context.grant_id,
        &identity_context.tenant_scope,
        facts.card_id,
        facts.user_id,
        facts.delegation_id,
    )?;
    // CARD（parent）投影事件只提供 durable generation/fence 绑定。
    let projection_identity = validated_projection_identity(projection)?;
    // 本贡献自身的独立事件号。
    let contribution = validated_contribution_event_id(contribution_event_id)?;
    let expected_revision = head.entry.revision;

    let before_image_json = head.payload.canonical_input().map_err(map_contract_error)?;
    let before_digest_hex = sha256_hex_of(&before_image_json);
    let delta = GrantDelta::revoke(identity_context.grant_id, expected_revision);
    delta.validate().map_err(map_contract_error)?;
    // REVOKE 无 canonical grant payload；semantic hash 锚定被撤销的旧授权内容。
    let semantic_hash_hex = sha256_hex_of(&before_image_json);

    // 依赖向量仅做合同级校验 + hash（Revoke evidence 不存在 canonical grant 对）。
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

    Ok(DelegationGrantDeltaDraft {
        tenant_id: identity_context.tenant_scope.tenant_id,
        card_id: facts.card_id,
        delegation_id: facts.delegation_id,
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

#[cfg(test)]
mod tests {
    use super::*;
    use astral_db::grant_ledger::{ruleset_binding_layer, RuleSetGrantDeltaDraft};
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    const TENANT_ID: i64 = 7;
    const DOMAIN_ID: i64 = 11;
    const CARD_ID: i64 = 21;
    const USER_ID: i64 = 42;
    const REQUEST_ID: i64 = 9001;
    const REVIEWER_ID: i64 = 3;
    const RULE_ID: i64 = 5077;

    /// 组装默认上下文；空串端点表示无有效期边界（组装为 None）。
    fn context(validity: (&'static str, &'static str)) -> ApprovalGrantLedgerContext<'static> {
        ApprovalGrantLedgerContext {
            user_card_tenant_id: Some(TENANT_ID),
            domain_id: Some(DOMAIN_ID),
            card_id: CARD_ID,
            user_id: USER_ID,
            request_id: REQUEST_ID,
            reviewer_id: REVIEWER_ID,
            rule_id: RULE_ID,
            resource: "learn_course",
            resource_id: None,
            action: "read",
            condition_json: None,
            valid_from: Some(validity.0),
            valid_to: Some(validity.1),
            operation_id: "approval:9001",
        }
    }

    /// 无有效期边界的上下文（两端皆 None → 合同 perpetual 显式形态）。
    fn perpetual_context() -> ApprovalGrantLedgerContext<'static> {
        context(("", ""))
    }

    fn projection(generation: i64, fence: i64) -> astral_db::ProjectionEventIdentity {
        astral_db::ProjectionEventIdentity {
            event_id: "e1111111-2222-4333-8444-555555555555".to_owned(),
            source_generation: generation,
            revoke_fence: fence,
            tenant_id: Some(TENANT_ID),
        }
    }

    #[test]
    fn derive_operation_id_reuses_safe_header_deterministically() {
        assert_eq!(
            derive_approval_operation_id(Some(" req-5-a "), REQUEST_ID).unwrap(),
            "req-5-a"
        );
        // 缺失/空白头部 → 从稳定 request 主键派生，而非随机生成。
        assert_eq!(
            derive_approval_operation_id(None, REQUEST_ID).unwrap(),
            format!("approval:{REQUEST_ID}")
        );
        assert_eq!(
            derive_approval_operation_id(Some("   "), REQUEST_ID).unwrap(),
            format!("approval:{REQUEST_ID}")
        );
        assert!(matches!(
            derive_approval_operation_id(None, 0),
            Err(AstralError::Validation(_))
        ));
    }

    #[test]
    fn derive_operation_id_fails_closed_on_unsafe_header() {
        for unsafe_header in [
            "a b",
            "x\ny",
            "控制\u{1F}",
            &"z".repeat(MAX_HEADER_OPERATION_ID_LENGTH + 1),
        ] {
            assert!(
                matches!(
                    derive_approval_operation_id(Some(unsafe_header), REQUEST_ID),
                    Err(AstralError::Validation(_))
                ),
                "unsafe header must fail closed: {unsafe_header:?}"
            );
        }
    }

    #[test]
    fn draft_is_deterministic_and_binds_identity_provenance_and_hashes() {
        let projection = projection(4, 0);
        let first = build_approval_add_draft(&context(("2026-01-01", "2026-12-31")), &projection)
            .expect("draft must assemble");
        let second = build_approval_add_draft(&context(("2026-01-01", "2026-12-31")), &projection)
            .expect("draft must assemble");
        // 同一稳定上下文必须得到完全相同的业务身份与 hash（不含时间/随机成分）。
        assert_eq!(first, second);

        // grant_id 必须来自确定性派生而非随机构造。
        let identity_key = GrantIdentityKey::approval(
            TenantScope::new(TENANT_ID, Some(DOMAIN_ID)).unwrap(),
            &REQUEST_ID.to_string(),
            &RULE_ID.to_string(),
            &format!("user-card:{CARD_ID}"),
        )
        .unwrap();
        assert_eq!(first.grant_id, identity_key.derive_grant_id().unwrap());

        let grant = match &first.delta {
            GrantDelta::Add { grant } => grant,
            other => panic!("expected ADD delta, got {other:?}"),
        };
        assert_eq!(grant.grant_id, first.grant_id);
        assert_eq!(grant.revision, GrantRevision::initial());
        assert_eq!(grant.state, GrantState::Active);
        assert_eq!(grant.source_kind, GrantSourceKind::Approval);
        assert_eq!(grant.binding_layer, BindingLayer::None);
        assert_eq!(grant.effect, GrantEffect::Allow);
        assert_eq!(grant.tenant.tenant_id, TENANT_ID);
        assert_eq!(grant.tenant.domain_id, Some(DOMAIN_ID));
        assert_eq!(grant.card_id, CARD_ID);
        assert_eq!(grant.user_id, USER_ID);
        // 审批请求内容不携带 resource id：canonical 资源是显式类型级通配形态。
        assert_eq!(grant.resource, "learn_course:*");
        assert_eq!(grant.action, "read");

        // provenance：真实 reviewer/请求主键/rule entry/projection 事件绑定。
        let provenance = &grant.provenance;
        assert_eq!(provenance.source_id, REQUEST_ID.to_string());
        assert_eq!(
            provenance.source_entry.as_deref(),
            Some(RULE_ID.to_string()).as_deref()
        );
        assert_eq!(provenance.binding_id, None);
        assert_eq!(provenance.delegation_id, None);
        assert_eq!(provenance.actor_user_id, Some(REVIEWER_ID));
        assert_eq!(provenance.operation_id, "approval:9001");
        assert_eq!(
            provenance.event_id.as_deref(),
            Some(projection.event_id.as_str())
        );

        // 合同哈希：小写 64 位 SHA-256 hex 且等于 canonical 输入摘要。
        assert_eq!(first.semantic_hash_hex, grant.canonical_hash().unwrap());
        for hash in [&first.semantic_hash_hex, &first.dependency_hash_hex] {
            assert_eq!(hash.len(), 64);
            assert!(
                hash.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "hash must be lowercase hex: {hash}"
            );
        }
    }

    #[test]
    fn revision_request_pins_aggregate_scope_and_compiler_contract() {
        let draft =
            build_approval_add_draft(&context(("2026-01-01", "")), &projection(3, 1)).unwrap();
        let request = draft.revision_request();
        assert_eq!(request.tenant_id, TENANT_ID);
        assert_eq!(request.card_id_scope, Some(CARD_ID));
        assert_eq!(request.aggregate_type, APPROVAL_AGGREGATE_TYPE);
        assert_eq!(request.aggregate_id, REQUEST_ID);
        assert_eq!(request.event_id, "e1111111-2222-4333-8444-555555555555");
        assert_eq!(request.operation_id, "approval:9001");
        assert_eq!(request.semantic_hash_hex, draft.semantic_hash_hex);
        assert_eq!(request.dependency_hash_hex, draft.dependency_hash_hex);
        // compiler contract 只能引用 policy-engine 公共常量，禁止另造版本串。
        assert_eq!(request.compiler_version, COMPILER_VERSION);
        assert_eq!(request.compiler_version, policy_engine::COMPILER_VERSION);
    }

    #[test]
    fn delta_event_request_matches_revision_identity_and_add_semantics() {
        let draft = build_approval_add_draft(&perpetual_context(), &projection(2, 0)).unwrap();
        let request = draft.delta_event_request().unwrap();
        assert_eq!(request.base_version, 0);
        assert_eq!(request.target_version, 1);
        assert!(request.target_version > request.base_version);
        assert_eq!(request.source_generation, 2);
        assert_eq!(request.revoke_fence, 0);
        assert_eq!(request.card_id, Some(CARD_ID));
        assert_eq!(request.aggregate_type, APPROVAL_AGGREGATE_TYPE);
        assert_eq!(request.aggregate_id, REQUEST_ID);
        assert_eq!(request.grant_id, draft.grant_id);
        assert_eq!(request.event_id, draft.event_id);
        assert_eq!(request.operation_id, draft.operation_id);
        assert_eq!(request.before_image_json, None);
        assert_eq!(request.before_digest_hex, None);
        assert_eq!(request.next_attempt_at, None);
        // delta_json 与 grant_id/event type 一致（decode 侧按 kind tag 反序列化）。
        let parsed: Value = serde_json::from_str(&request.delta_json).unwrap();
        assert_eq!(parsed["kind"], "ADD");
        assert_eq!(parsed["grant"]["grantId"], draft.grant_id.as_str());
        let delta = astral_db::decode_delta_event_payload(&request.delta_json).unwrap();
        assert_eq!(
            delta.operation_name(),
            astral_db::DeltaEventType::Add.as_str()
        );
        assert_eq!(delta.target_grant_id().unwrap(), draft.grant_id);
    }

    #[test]
    fn perpetual_and_bounded_validity_use_utc_unix_seconds() {
        // 双端缺失 → 合同允许的显式 perpetual（不硬编码业务区间）。
        let none = build_approval_add_draft(&perpetual_context(), &projection(1, 0)).unwrap();
        match &none.delta {
            GrantDelta::Add { grant } => {
                assert_eq!(grant.validity.not_before, None);
                assert_eq!(grant.validity.expires_at, None);
            }
            _ => unreachable!(),
        }

        let bounded = build_approval_add_draft(
            &context(("2026-01-02 03:04:05", "2026-03-01")),
            &projection(1, 0),
        )
        .unwrap();
        match &bounded.delta {
            GrantDelta::Add { grant } => {
                let from = time::PrimitiveDateTime::new(
                    time::Date::from_calendar_date(2026, time::Month::January, 2).unwrap(),
                    time::Time::from_hms(3, 4, 5).unwrap(),
                )
                .assume_utc()
                .unix_timestamp();
                let to = time::PrimitiveDateTime::new(
                    time::Date::from_calendar_date(2026, time::Month::March, 1).unwrap(),
                    time::Time::MIDNIGHT,
                )
                .assume_utc()
                .unix_timestamp();
                assert_eq!(grant.validity.not_before, Some(from));
                assert_eq!(grant.validity.expires_at, Some(to));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn unprovable_inputs_fail_closed_without_inventing_values() {
        let p = projection(1, 0);
        // NULL tenant → 不向 NOT NULL 租户列装配假值。
        let mut null_tenant = perpetual_context();
        null_tenant.user_card_tenant_id = None;
        assert!(build_approval_add_draft(&null_tenant, &p).is_err());

        // 越界 ids（负值/零）→ Validation。
        for mutate in [
            ContextMutation::Card(0),
            ContextMutation::User(-5),
            ContextMutation::Request(0),
            ContextMutation::Reviewer(-1),
            ContextMutation::Rule(0),
        ] {
            let describe = format!("{mutate:?}");
            let mut ctx = perpetual_context();
            apply(&mut ctx, mutate);
            assert!(
                matches!(
                    build_approval_add_draft(&ctx, &p),
                    Err(AstralError::Validation(_))
                ),
                "non-positive id must fail closed: {describe}"
            );
        }

        // 无法证明的有效期格式 → Validation，不猜测时区/格式。
        const BAD_DATES: [&str; 4] = ["not-a-date", "2026/01/01", "2026-13-01", "20260101"];
        for bad_to in BAD_DATES {
            let ctx = context(("2026-01-01", bad_to));
            assert!(
                matches!(
                    build_approval_add_draft(&ctx, &p),
                    Err(AstralError::Validation(_))
                ),
                "invalid expiry must fail closed: {bad_to}"
            );
        }
        for bad_from in BAD_DATES {
            let ctx = context((bad_from, "2026-12-31"));
            assert!(
                matches!(
                    build_approval_add_draft(&ctx, &p),
                    Err(AstralError::Validation(_))
                ),
                "invalid start must fail closed: {bad_from}"
            );
        }

        // 投影身份非法：空白事件号 / 非正代次 / 负围栏。
        let mut empty = p.clone();
        empty.event_id = "  ".to_owned();
        assert!(matches!(
            build_approval_add_draft(&perpetual_context(), &empty),
            Err(AstralError::Validation(_))
        ));
        let mut zero = p.clone();
        zero.source_generation = 0;
        assert!(matches!(
            build_approval_add_draft(&perpetual_context(), &zero),
            Err(AstralError::Validation(_))
        ));
        let mut negative_gen = p.clone();
        negative_gen.source_generation = -1;
        assert!(
            matches!(
                build_approval_add_draft(&perpetual_context(), &negative_gen),
                Err(AstralError::Validation(_))
            ),
            "negative generation must fail closed with an explicit validation error"
        );
        let mut negative_fence = p.clone();
        negative_fence.revoke_fence = -2;
        assert!(matches!(
            build_approval_add_draft(&perpetual_context(), &negative_fence),
            Err(AstralError::Internal(_))
        ));

        // 围栏不得超前于代次（DependencyVersion 合同门禁）。
        let ahead = build_approval_add_draft(&perpetual_context(), &projection(1, 3));
        assert!(matches!(ahead, Err(AstralError::Validation(_))));
    }

    #[derive(Debug)]
    enum ContextMutation {
        Card(i64),
        User(i64),
        Request(i64),
        Reviewer(i64),
        Rule(i64),
    }

    fn apply(ctx: &mut ApprovalGrantLedgerContext<'_>, mutation: ContextMutation) {
        match mutation {
            ContextMutation::Card(v) => ctx.card_id = v,
            ContextMutation::User(v) => ctx.user_id = v,
            ContextMutation::Request(v) => ctx.request_id = v,
            ContextMutation::Reviewer(v) => ctx.reviewer_id = v,
            ContextMutation::Rule(v) => ctx.rule_id = v,
        }
    }

    /// 结构守卫：适配器源码内不允许出现任何随机业务身份构造入口。
    #[test]
    fn adapter_never_mints_random_business_identity() {
        let source = include_str!("grant_ledger_adapter.rs");
        // 用拼接构造 forbidden 字符串，避免本测试自身字面量被 include_str! 命中。
        let forbidden: Vec<(&str, String)> = vec![
            ("random v4 identity vec", vec!["Uuid", "new_v4"]),
            ("random grant id ctor", vec!["GrantId", "rand"]),
            ("default (random) ctor", vec!["GrantId", "de"]),
            ("direct crate randomness", vec!["rand", ""]),
        ]
        .into_iter()
        .map(|(label, parts)| {
            // 路径段在运行时才拼接成完整符号名，测试源码内不出现该字面量。
            (label, parts.join("::"))
        })
        .collect();
        for (label, needle) in &forbidden {
            assert!(
                !source.contains(needle.as_str()),
                "adapter must not mint random business identity via {label}"
            );
        }
    }

    /// 结构守卫：revision 追加先于 delta event，均映射错误并向上传播。
    #[test]
    fn transaction_append_order_is_revision_then_delta_event() {
        let source = include_str!("grant_ledger_adapter.rs");
        let body = source
            .split("pub(crate) async fn append_approval_grant_in_tx")
            .nth(1)
            .expect("transaction wrapper must exist");
        let revision = body
            .find("append_grant_revision_in_tx")
            .expect("revision append call");
        let delta = body.find("append_delta_event").expect("delta append call");
        assert!(revision < delta, "revision append must precede delta event");
        assert!(
            body.contains("map_err(map_grant_repository_error)"),
            "errors must propagate as mapped failures"
        );
    }

    /// 错误映射保持 fail-closed 分类：驱动错误 → Database；重复 → Validation；合同 → Validation。
    #[test]
    fn repository_errors_map_without_success_shortcuts() {
        use astral_db::{GrantRepositoryError, LedgerTransitionConflict};
        let duplicate = map_grant_repository_error(GrantRepositoryError::DuplicateDeltaEvent(
            "uk_ade_target_version".into(),
        ));
        assert!(matches!(duplicate, AstralError::Validation(_)));

        let grant_id = GrantId::parse("11111111-2222-4333-8444-555555555555").unwrap();
        let conflict = map_grant_repository_error(GrantRepositoryError::RevisionConflict(
            LedgerTransitionConflict::UnknownGrant { grant_id },
        ));
        assert!(matches!(conflict, AstralError::Validation(_)));

        let scope = map_grant_repository_error(GrantRepositoryError::ScopeViolation(
            "cross_tenant_delta".into(),
        ));
        assert!(matches!(scope, AstralError::Internal(_)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DIRECT（permission_rule）draft 组装
    // ─────────────────────────────────────────────────────────────────────────

    const DIRECT_ACTOR: i64 = 17;
    const DIRECT_OPERATION: &str = "permission-rule:update:5077";

    fn direct_facts<'a>(validity: Option<(&'a str, &'a str)>) -> DirectRuleLedgerFacts<'a> {
        DirectRuleLedgerFacts {
            tenant_id: Some(TENANT_ID),
            domain_id: Some(DOMAIN_ID),
            card_id: CARD_ID,
            user_id: USER_ID,
            rule_id: RULE_ID,
            resource: "learn_course",
            resource_id: None,
            action: "read",
            condition_json: None,
            valid_from: validity.map(|pair| pair.0),
            valid_to: validity.map(|pair| pair.1),
        }
    }

    fn direct_add_draft(validity: Option<(&str, &str)>) -> DirectGrantDeltaDraft {
        build_direct_add_draft(
            &direct_facts(validity),
            DIRECT_OPERATION,
            DIRECT_ACTOR,
            &projection(3, 0),
        )
        .expect("direct add draft must assemble")
    }

    fn active_head_from(draft: &DirectGrantDeltaDraft) -> astral_db::GrantHeadSnapshot {
        let payload = match &draft.delta {
            GrantDelta::Add { grant } => grant.clone(),
            other => panic!("expected ADD delta, got {other:?}"),
        };
        astral_db::GrantHeadSnapshot {
            grant_id: draft.grant_id,
            entry: astral_db::CurrentLedgerEntry {
                revision: GrantRevision::initial(),
                state: GrantState::Active,
                status_active: true,
            },
            payload,
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // canonical 资源保真（type:id / type:*）与非空 condition fail-closed
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn canonical_resource_key_preserves_object_scope_and_never_widens() {
        // 携带 resource_id 的 source 行必须保留对象作用域，绝不放宽成裸类型。
        assert_eq!(
            canonical_resource_key("learn_course", Some(42)).unwrap(),
            "learn_course:42"
        );
        // 无 id 的 source 行是显式类型级通配形态，而不是裸类型。
        assert_eq!(
            canonical_resource_key("  learn_course  ", None).unwrap(),
            "learn_course:*"
        );
        // 空类型与携带 ':' 分隔符的类型无法安全组成 scoped key → fail-closed。
        assert!(matches!(
            canonical_resource_key("   ", Some(1)),
            Err(AstralError::Validation(_))
        ));
        assert!(matches!(
            canonical_resource_key("learn:course", Some(1)),
            Err(AstralError::Validation(_))
        ));
    }

    #[test]
    fn direct_add_and_update_preserve_object_scope_without_rekeying_identity() {
        let object_facts = DirectRuleLedgerFacts {
            resource_id: Some(42),
            ..direct_facts(None)
        };
        let add = build_direct_add_draft(
            &object_facts,
            DIRECT_OPERATION,
            DIRECT_ACTOR,
            &projection(3, 0),
        )
        .unwrap();
        match &add.delta {
            GrantDelta::Add { grant } => {
                assert_eq!(grant.resource, "learn_course:42");
                assert_ne!(
                    grant.resource, "learn_course",
                    "object grant must not widen"
                );
            }
            other => panic!("expected ADD delta, got {other:?}"),
        }

        // UPDATE 同样保留对象作用域，且 resource 变更不重键身份。
        let head = active_head_from(&direct_add_draft(None));
        let updated = build_direct_update_draft(
            &object_facts,
            &head,
            DIRECT_OPERATION,
            DIRECT_ACTOR,
            &projection(4, 0),
        )
        .unwrap();
        match &updated.delta {
            GrantDelta::Update { grant, .. } => assert_eq!(grant.resource, "learn_course:42"),
            other => panic!("expected UPDATE delta, got {other:?}"),
        }

        // resource/resource_id 是可变属性而非身份维度：两种作用域共享同一 GrantId。
        assert_eq!(
            derive_direct_identity(&object_facts).unwrap(),
            derive_direct_identity(&direct_facts(None)).unwrap(),
            "object scope is mutable payload, never an identity re-key"
        );
    }

    #[test]
    fn ruleset_add_and_update_preserve_object_scope_in_canonical_resource() {
        let object_facts = RuleSetEntryLedgerFacts {
            resource_id: Some(7),
            ..default_ruleset_facts()
        };
        let op = RULESET_OP;
        let add = build_ruleset_add_draft(
            &object_facts,
            op,
            None,
            &card_projection(3, 0),
            &"e".repeat(36),
        )
        .unwrap();
        match &add.delta {
            GrantDelta::Add { grant } => {
                assert_eq!(grant.resource, "learn_course:7");
                assert_ne!(
                    grant.resource, "learn_course",
                    "object grant must not widen"
                );
            }
            other => panic!("expected ADD delta, got {other:?}"),
        }

        let head = ruleset_head_from_add(&add);
        let update = build_ruleset_update_draft(
            &object_facts,
            &head,
            op,
            None,
            &card_projection(4, 0),
            &"f".repeat(36),
        )
        .unwrap();
        match &update.delta {
            GrantDelta::Update { grant, .. } => assert_eq!(grant.resource, "learn_course:7"),
            other => panic!("expected UPDATE delta, got {other:?}"),
        }
    }

    #[test]
    fn non_empty_condition_json_fails_closed_for_every_canonical_add_and_update() {
        const CONDITION: &str = r#"{"ownerOnly":true}"#;

        // 审批 ADD：非空条件拒绝（fail-closed Validation），空白视为无条件。
        let mut conditioned = perpetual_context();
        conditioned.condition_json = Some(CONDITION);
        assert!(matches!(
            build_approval_add_draft(&conditioned, &projection(1, 0)),
            Err(AstralError::Validation(message))
                if message.contains("condition_json") && message.contains("fail-closed")
        ));
        let mut blank = perpetual_context();
        blank.condition_json = Some("   ");
        assert!(build_approval_add_draft(&blank, &projection(1, 0)).is_ok());

        // direct ADD/UPDATE：非空条件拒绝。
        let direct_conditioned = DirectRuleLedgerFacts {
            condition_json: Some(CONDITION),
            ..direct_facts(None)
        };
        assert!(build_direct_add_draft(
            &direct_conditioned,
            DIRECT_OPERATION,
            DIRECT_ACTOR,
            &projection(3, 0),
        )
        .is_err());
        let head = active_head_from(&direct_add_draft(None));
        assert!(build_direct_update_draft(
            &direct_conditioned,
            &head,
            DIRECT_OPERATION,
            DIRECT_ACTOR,
            &projection(4, 0),
        )
        .is_err());

        // 规则集 ADD/UPDATE：非空条件拒绝。
        let ruleset_conditioned = RuleSetEntryLedgerFacts {
            condition_json: Some(CONDITION),
            ..default_ruleset_facts()
        };
        assert!(build_ruleset_add_draft(
            &ruleset_conditioned,
            RULESET_OP,
            None,
            &card_projection(3, 0),
            &"e".repeat(36),
        )
        .is_err());
        let clean_add = build_ruleset_add_draft(
            &default_ruleset_facts(),
            RULESET_OP,
            None,
            &card_projection(3, 0),
            &"e".repeat(36),
        )
        .unwrap();
        assert!(build_ruleset_update_draft(
            &ruleset_conditioned,
            &ruleset_head_from_add(&clean_add),
            RULESET_OP,
            None,
            &card_projection(4, 0),
            &"f".repeat(36),
        )
        .is_err());

        // tombstone 不受影响：source 行带条件的 REMOVE 照常组装（不丢撤销能力）。
        assert!(build_direct_remove_draft(
            &direct_conditioned,
            &head,
            DIRECT_OPERATION,
            &projection(5, 0),
            "remove-event-0000-0000-000000000001",
        )
        .is_ok());
    }

    #[test]
    fn direct_add_draft_is_deterministic_and_scoped_to_the_user_card_aggregate() {
        let first = direct_add_draft(Some(("2026-01-01", "")));
        let second = direct_add_draft(Some(("2026-01-01", "")));
        assert_eq!(
            first, second,
            "same stable context must produce identical identity"
        );

        let expected_key = GrantIdentityKey::direct(
            TenantScope::new(TENANT_ID, Some(DOMAIN_ID)).unwrap(),
            &CARD_ID.to_string(),
            &RULE_ID.to_string(),
        )
        .unwrap();
        assert_eq!(first.grant_id, expected_key.derive_grant_id().unwrap());

        let request = first.revision_request();
        assert_eq!(request.tenant_id, TENANT_ID);
        assert_eq!(request.card_id_scope, Some(CARD_ID));
        assert_eq!(request.aggregate_type, DIRECT_AGGREGATE_TYPE);
        assert_eq!(request.aggregate_id, CARD_ID);
        assert_eq!(request.compiler_version, policy_engine::COMPILER_VERSION);
        assert_eq!(request.operation_id, DIRECT_OPERATION);

        match &first.delta {
            GrantDelta::Add { grant } => {
                assert_eq!(grant.source_kind, GrantSourceKind::Direct);
                assert_eq!(grant.binding_layer, BindingLayer::None);
                assert_eq!(grant.state, GrantState::Active);
                assert_eq!(grant.effect, GrantEffect::Allow);
                assert_eq!(grant.revision, GrantRevision::initial());
                assert_eq!(grant.card_id, CARD_ID);
                assert_eq!(grant.user_id, USER_ID);
                assert_eq!(grant.provenance.source_id, CARD_ID.to_string());
                assert_eq!(
                    grant.provenance.source_entry.as_deref(),
                    Some(RULE_ID.to_string()).as_deref()
                );
                assert_eq!(grant.provenance.binding_id, None);
                assert_eq!(grant.provenance.delegation_id, None);
                assert_eq!(grant.provenance.actor_user_id, Some(DIRECT_ACTOR));
                assert_eq!(grant.provenance.operation_id, DIRECT_OPERATION);
            }
            other => panic!("expected ADD delta, got {other:?}"),
        }

        for hash in [&first.semantic_hash_hex, &first.dependency_hash_hex] {
            assert_eq!(hash.len(), 64);
            assert!(
                hash.bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "hash must be lowercase hex: {hash}"
            );
        }
    }

    #[test]
    fn direct_add_delta_event_chains_from_base_zero_with_projection_identity() {
        let draft = direct_add_draft(None);
        let request = draft.delta_event_request(0, 1).unwrap();
        assert_eq!(request.base_version, 0);
        assert_eq!(request.target_version, 1);
        assert_eq!(request.aggregate_type, DIRECT_AGGREGATE_TYPE);
        assert_eq!(request.aggregate_id, CARD_ID);
        assert_eq!(request.card_id, Some(CARD_ID));
        assert_eq!(request.source_generation, 3);
        assert_eq!(request.revoke_fence, 0);
        assert_eq!(request.before_image_json, None);
        assert_eq!(request.before_digest_hex, None);
        assert_eq!(
            astral_db::decode_delta_event_payload(&request.delta_json)
                .unwrap()
                .operation_name(),
            "ADD"
        );
    }

    #[test]
    fn direct_update_draft_pairs_before_image_and_successor_revision() {
        let head_draft = direct_add_draft(None);
        let head = active_head_from(&head_draft);

        let mut facts = direct_facts(None);
        facts.action = "write";
        // 真实链路里每次 source mutation 都会产生新的 CARD 投影事件；
        // 测试 fixture 用不同的 event_id 反映这一事实。
        let fresh_projection = astral_db::ProjectionEventIdentity {
            event_id: "e9999999-2222-4333-8444-555555555555".to_owned(),
            source_generation: 5,
            revoke_fence: 1,
            tenant_id: Some(TENANT_ID),
        };
        let updated = build_direct_update_draft(
            &facts,
            &head,
            DIRECT_OPERATION,
            DIRECT_ACTOR,
            &fresh_projection,
        )
        .expect("update draft must assemble from the active head");

        let expected = head.entry.revision.next().unwrap();
        match &updated.delta {
            GrantDelta::Update {
                grant,
                expected_revision,
            } => {
                assert_eq!(*expected_revision, head.entry.revision);
                assert_eq!(grant.revision, expected);
                assert_eq!(grant.action, "write");
                assert_eq!(grant.resource, "learn_course:*");
                // ALLOW-only 纵深防御：UPDATE 产出恒为显式 ALLOW，不继承 head。
                assert_eq!(grant.effect, GrantEffect::Allow);
                assert_eq!(grant.provenance.operation_id, DIRECT_OPERATION);
                assert_ne!(
                    grant.provenance.event_id, head.payload.provenance.event_id,
                    "update must bind the fresh projection event"
                );
            }
            other => panic!("expected UPDATE delta, got {other:?}"),
        }

        let before_json = updated.before_image_json.as_deref().expect("before image");
        let digest_hex = updated.before_digest_hex.as_deref().expect("digest pair");
        assert_eq!(digest_hex, sha256_hex_of(before_json));
        // before-image 必须忠实还原旧 canonical grant（旧 action），可被严格解码。
        let decoded_before =
            astral_db::decode_stored_grant_payload(before_json).expect("canonical before image");
        assert_eq!(decoded_before.action, "read");
        assert_eq!(decoded_before.revision, GrantRevision::initial());

        assert_eq!(updated.semantic_hash_hex.len(), 64);
        assert_eq!(updated.dependency_hash_hex.len(), 64);

        let request = updated.delta_event_request(1, 2).unwrap();
        assert_eq!(request.base_version, 1);
        assert_eq!(request.target_version, 2);
        assert_eq!(
            astral_db::decode_delta_event_payload(&request.delta_json)
                .unwrap()
                .operation_name(),
            "UPDATE"
        );
    }

    #[test]
    fn direct_update_and_remove_fail_closed_on_head_drift() {
        let head_draft = direct_add_draft(None);
        let head = active_head_from(&head_draft);

        // 卡身份漂移：不得把 tombstone / update 写到另一份账本记录上。
        let mut wrong_card = direct_facts(None);
        wrong_card.card_id = CARD_ID + 1;
        assert!(build_direct_update_draft(
            &wrong_card,
            &head,
            DIRECT_OPERATION,
            DIRECT_ACTOR,
            &projection(6, 0),
        )
        .is_err());
        let source_event = projection(6, 0);
        assert!(build_direct_remove_draft(
            &wrong_card,
            &head,
            DIRECT_OPERATION,
            &source_event,
            &source_event.event_id
        )
        .is_err());

        // 属主用户漂移 fail-closed。
        let mut wrong_user = direct_facts(None);
        wrong_user.user_id = USER_ID + 1;
        assert!(build_direct_update_draft(
            &wrong_user,
            &head,
            DIRECT_OPERATION,
            DIRECT_ACTOR,
            &projection(6, 0),
        )
        .is_err());

        // 租户/域漂移 fail-closed。
        let mut wrong_domain = direct_facts(None);
        wrong_domain.domain_id = Some(DOMAIN_ID + 1);
        assert!(build_direct_remove_draft(
            &wrong_domain,
            &head,
            DIRECT_OPERATION,
            &source_event,
            &source_event.event_id
        )
        .is_err());
        let mut null_tenant = direct_facts(None);
        null_tenant.tenant_id = None;
        assert!(matches!(
            build_direct_remove_draft(
                &null_tenant,
                &head,
                DIRECT_OPERATION,
                &source_event,
                &source_event.event_id
            ),
            Err(AstralError::Validation(_))
        ));

        // 非正主键 / NULL 租户在派生阶段就拒绝。
        {
            let mut zero_card = direct_facts(None);
            zero_card.card_id = 0;
            assert!(derive_direct_identity(&zero_card).is_err());

            let mut negative_user = direct_facts(None);
            negative_user.user_id = -5;
            assert!(derive_direct_identity(&negative_user).is_err());

            let mut zero_rule = direct_facts(None);
            zero_rule.rule_id = 0;
            assert!(derive_direct_identity(&zero_rule).is_err());
        }

        // 直接构造错键的 head（source_entry 与 rule 不符）→ Internal/Validation，不放行。
        let mut poisoned_payload = head.payload.clone();
        poisoned_payload.provenance.source_entry = Some("999".to_owned());
        let poisoned_head = astral_db::GrantHeadSnapshot {
            grant_id: head.grant_id,
            entry: head.entry,
            payload: poisoned_payload,
        };
        assert!(build_direct_update_draft(
            &direct_facts(None),
            &poisoned_head,
            DIRECT_OPERATION,
            DIRECT_ACTOR,
            &projection(6, 0),
        )
        .is_err());
    }

    #[test]
    fn direct_remove_draft_targets_expected_revision_with_pairing_evidence() {
        let head_draft = direct_add_draft(None);
        let head = active_head_from(&head_draft);
        // 单条删除路径（1 rule : 1 投影事件）保持 source/contribution 同一事件号。
        let single_source = projection(7, 1);
        let removed = build_direct_remove_draft(
            &direct_facts(None),
            &head,
            DIRECT_OPERATION,
            &single_source,
            &single_source.event_id,
        )
        .expect("remove draft must assemble");

        match &removed.delta {
            GrantDelta::Remove {
                grant_id,
                expected_revision,
            } => {
                assert_eq!(*grant_id, head_draft.grant_id);
                assert_eq!(*expected_revision, GrantRevision::initial());
            }
            other => panic!("expected REMOVE delta, got {other:?}"),
        }

        let before_json = removed.before_image_json.clone().expect("before image");
        assert_eq!(
            removed.before_digest_hex.as_deref(),
            Some(sha256_hex_of(&before_json)).as_deref()
        );
        // REMOVE semantic hash 锚定被移除的旧授权内容。
        assert_eq!(removed.semantic_hash_hex, sha256_hex_of(&before_json));

        let request = removed.delta_event_request(1, 2).unwrap();
        assert_eq!(
            request.before_image_json.is_some(),
            request.before_digest_hex.is_some()
        );
        assert_eq!(request.source_generation, 7);
        assert_eq!(request.revoke_fence, 1);
        let decoded = astral_db::decode_delta_event_payload(&request.delta_json).unwrap();
        assert_eq!(decoded.operation_name(), "REMOVE");
        assert_eq!(decoded.target_grant_id().unwrap(), head_draft.grant_id);
    }

    /// 批量删除核心合同：同一 operation id 下两条不同 rule 必然派生不同
    /// contribution event id（满足 uk_ade_event 全局唯一）；相同
    /// (operation, tenant, card, rule, kind) 重试得到相同 id；派生值永不与
    /// parent 投影事件号混淆，也不与同维度的 grant identity 相等。
    #[test]
    fn batch_contribution_event_ids_are_distinct_per_rule_and_stable_on_retry() {
        const BATCH_OPERATION: &str = "permission-rule:remove-by-card:29";
        let first = direct_facts(None);
        let mut second = direct_facts(None);
        second.rule_id = RULE_ID + 1;

        let first_id = derive_direct_contribution_event_id(
            BATCH_OPERATION,
            &first,
            DirectRuleOperationKind::Remove,
        )
        .unwrap();
        let second_id = derive_direct_contribution_event_id(
            BATCH_OPERATION,
            &second,
            DirectRuleOperationKind::Remove,
        )
        .unwrap();
        // 批量两条规则 -> 两个不同事件号：不再复用同一个 source 事件号。
        assert_ne!(
            first_id, second_id,
            "sibling contributions of one batch must not share a delta event id"
        );

        // 重试确定性：相同 (operation, rule, kind) 派生恒等。
        assert_eq!(
            first_id,
            derive_direct_contribution_event_id(
                BATCH_OPERATION,
                &first,
                DirectRuleOperationKind::Remove
            )
            .unwrap()
        );

        // 与 parent CARD 投影事件号明确区分（source vs contribution）。
        let parent = projection(9, 2);
        assert_ne!(first_id, parent.event_id);
        assert_ne!(second_id, parent.event_id);

        // 不与同维度 grant identity 混淆：grant id 由独立合同派生。
        let grant_id = derive_direct_identity(&first).unwrap();
        assert_ne!(first_id, grant_id.as_str());
        assert_ne!(second_id, derive_direct_identity(&second).unwrap().as_str());
    }

    /// 跨 operation / 租户 / 卡（aggregate）维度互不碰撞；跨租户共享
    /// 卡号+rule 号也不可能得到同一事件身份。
    #[test]
    fn contribution_event_ids_do_not_collide_across_operation_tenant_or_aggregate() {
        const BATCH_OPERATION: &str = "permission-rule:remove-by-card:29";
        const OTHER_OPERATION: &str = "permission-rule:remove-by-source:MANUAL:8";
        let facts = direct_facts(None);

        let base = derive_direct_contribution_event_id(
            BATCH_OPERATION,
            &facts,
            DirectRuleOperationKind::Remove,
        )
        .unwrap();

        let by_operation = derive_direct_contribution_event_id(
            OTHER_OPERATION,
            &facts,
            DirectRuleOperationKind::Remove,
        )
        .unwrap();
        let mut other_tenant = direct_facts(None);
        other_tenant.tenant_id = Some(TENANT_ID + 1);
        let by_tenant = derive_direct_contribution_event_id(
            BATCH_OPERATION,
            &other_tenant,
            DirectRuleOperationKind::Remove,
        )
        .unwrap();
        let mut other_card = direct_facts(None);
        other_card.card_id = CARD_ID + 1;
        let by_aggregate = derive_direct_contribution_event_id(
            BATCH_OPERATION,
            &other_card,
            DirectRuleOperationKind::Remove,
        )
        .unwrap();

        assert_ne!(base, by_operation);
        assert_ne!(base, by_tenant);
        assert_ne!(base, by_aggregate);
    }

    /// 贡献事件号必须同时绑定 revision 与 delta event 两个请求；parent 投影
    /// 事件的 generation/fence 绑定不受影响（依赖向量仍锚定 CARD 流）。
    #[test]
    fn remove_draft_binds_contribution_event_id_to_both_requests_while_keeping_parent_fence() {
        let head_draft = direct_add_draft(None);
        let head = active_head_from(&head_draft);
        const BATCH_OPERATION: &str = "permission-rule:remove-by-card:29";
        let contribution = derive_direct_contribution_event_id(
            BATCH_OPERATION,
            &direct_facts(None),
            DirectRuleOperationKind::Remove,
        )
        .unwrap();
        let parent = projection(11, 3);

        let draft = build_direct_remove_draft(
            &direct_facts(None),
            &head,
            BATCH_OPERATION,
            &parent,
            &contribution,
        )
        .expect("batch remove draft must assemble");

        assert_eq!(draft.event_id, contribution);
        assert_eq!(draft.revision_request().event_id, contribution);
        let request = draft.delta_event_request(1, 2).unwrap();
        assert_eq!(request.event_id, contribution);
        assert_eq!(request.operation_id, BATCH_OPERATION);
        // parent 投影事件的代次/围栏仍然进入依赖向量绑定。
        assert_eq!(draft.source_generation, 11);
        assert_eq!(draft.revoke_fence, 3);
        assert_eq!(request.source_generation, 11);
        assert_eq!(request.revoke_fence, 3);
        assert_eq!(draft.before_digest_hex.as_deref(), {
            let before_json = draft.before_image_json.as_deref().expect("before image");
            Some(sha256_hex_of(before_json)).as_deref()
        });
    }

    /// 形状不合法的输入一律 fail-closed：空 operation、非正主键、NULL 租户，
    /// 以及派生结果之外的任意非法 event id 文本（空/空白/控制字符/超长）。
    #[test]
    fn contribution_event_identity_fails_closed_on_malformed_shapes() {
        let facts = direct_facts(None);

        assert!(matches!(
            derive_direct_contribution_event_id(" ", &facts, DirectRuleOperationKind::Remove),
            Err(AstralError::Validation(_))
        ));

        let mut zero_rule = direct_facts(None);
        zero_rule.rule_id = 0;
        assert!(matches!(
            derive_direct_contribution_event_id(
                "op-1",
                &zero_rule,
                DirectRuleOperationKind::Remove
            ),
            Err(AstralError::Validation(_))
        ));

        let mut null_tenant = direct_facts(None);
        null_tenant.tenant_id = None;
        assert!(matches!(
            derive_direct_contribution_event_id(
                "op-1",
                &null_tenant,
                DirectRuleOperationKind::Remove
            ),
            Err(AstralError::Validation(_))
        ));

        // 任意非法文本都不能作为贡献事件号持久化。
        let oversized = "y".repeat(astral_db::MAX_EVENT_ID_LENGTH + 1);
        for invalid in ["", "   ", "a b", "evt\nid", "\u{7}", oversized.as_str()] {
            assert!(
                matches!(
                    validated_contribution_event_id(invalid),
                    Err(AstralError::Validation(_))
                ),
                "malformed contribution event id must fail closed: {invalid:?}"
            );
        }
        // 合法形状放行且 trim 边界。
        assert_eq!(validated_contribution_event_id("evt-77").unwrap(), "evt-77");
    }

    #[test]
    fn direct_operation_ids_are_deterministic_header_guarded_and_kind_distinct() {
        for kind in [
            DirectRuleOperationKind::Create,
            DirectRuleOperationKind::Update,
            DirectRuleOperationKind::Remove,
        ] {
            let derived = derive_direct_rule_operation_id(kind, RULE_ID, None).unwrap();
            assert_eq!(
                derived,
                format!("permission-rule:{}:{RULE_ID}", kind.as_str())
            );
            // 稳定性：同一 (kind, rule) 派生两次完全一致，不引入随机成分。
            assert_eq!(
                derived,
                derive_direct_rule_operation_id(kind, RULE_ID, None).unwrap()
            );
        }
        // 不同 kind 派生不同 operation id，避免跨语义串写。
        let create =
            derive_direct_rule_operation_id(DirectRuleOperationKind::Create, RULE_ID, None)
                .unwrap();
        let remove =
            derive_direct_rule_operation_id(DirectRuleOperationKind::Remove, RULE_ID, None)
                .unwrap();
        assert_ne!(create, remove);

        // 安全 ASCII 头原样复用（含 trim）。
        assert_eq!(
            derive_direct_rule_operation_id(
                DirectRuleOperationKind::Update,
                RULE_ID,
                Some(" req-9-a ")
            )
            .unwrap(),
            "req-9-a"
        );

        // 非法字符 / 超长头 fail-closed。
        for unsafe_header in [
            "a b",
            "x\ny",
            "控制\u{7}",
            &"z".repeat(MAX_HEADER_OPERATION_ID_LENGTH + 1),
        ] {
            assert!(
                derive_direct_rule_operation_id(
                    DirectRuleOperationKind::Update,
                    RULE_ID,
                    Some(unsafe_header)
                )
                .is_err(),
                "unsafe header must fail closed: {unsafe_header:?}"
            );
        }
        assert!(derive_direct_rule_operation_id(DirectRuleOperationKind::Update, 0, None).is_err());
        assert!(
            derive_direct_rule_operation_id(DirectRuleOperationKind::Update, -3, None).is_err()
        );

        // 批量删除共享一个稳定 operation id。
        assert_eq!(
            derive_direct_rule_batch_operation_id("remove-by-card", "21", None).unwrap(),
            "permission-rule:remove-by-card:21"
        );
        assert_eq!(
            derive_direct_rule_batch_operation_id("remove-by-source", "MANUAL:8", None).unwrap(),
            "permission-rule:remove-by-source:MANUAL:8"
        );
        assert!(derive_direct_rule_batch_operation_id(" ", "21", None).is_err());
    }

    #[test]
    fn direct_mutation_context_requires_a_verified_actor() {
        assert!(DirectRuleMutationContext::user(17, Some("req-1")).is_ok());
        assert!(DirectRuleMutationContext::user(0, None).is_err());
        assert!(DirectRuleMutationContext::user(-1, None).is_err());
        let context = DirectRuleMutationContext::user(17, Some("   ")).unwrap();
        assert_eq!(context.request_id_header, None);
    }

    /// 结构守卫：事务追加先 revision 后 delta event，错误必须以映射后的
    /// fail-closed 形式向上传播。
    #[test]
    fn direct_transaction_append_is_revision_then_delta() {
        let source = include_str!("../../../astral-db/src/grant_ledger.rs");
        let body = source
            .split("pub async fn append_direct_grant_delta_in_tx")
            .nth(1)
            .expect("direct transaction wrapper must exist")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let revision = body
            .find("append_grant_revision_in_tx")
            .expect("revision append call");
        let delta = body.find("append_delta_event").expect("delta event call");
        assert!(revision < delta);
        assert!(body.contains("map_err(map_grant_repository_error)"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // RULE_SET 贡献（规则集条目 × 绑定卡 × 绑定行）
    // ─────────────────────────────────────────────────────────────────────────

    const RULE_SET_ID: i64 = 31;
    const REF_ID: i64 = 77;

    #[allow(clippy::too_many_arguments)]
    fn ruleset_facts<'a>(
        rule_set_id: i64,
        entry_id: i64,
        ref_id: i64,
        card_id: i64,
        tenant_id: i64,
        ref_type: &'a str,
        resource: &'a str,
        action: &'a str,
        validity: (&'a str, &'a str),
    ) -> RuleSetEntryLedgerFacts<'a> {
        RuleSetEntryLedgerFacts {
            tenant_id,
            domain_id: Some(DOMAIN_ID),
            card_id,
            user_id: USER_ID,
            rule_set_id,
            entry_id,
            ref_id,
            ref_type,
            resource,
            resource_id: None,
            action,
            condition_json: None,
            valid_from: if validity.0.is_empty() {
                None
            } else {
                Some(validity.0)
            },
            valid_to: if validity.1.is_empty() {
                None
            } else {
                Some(validity.1)
            },
        }
    }

    fn default_ruleset_facts() -> RuleSetEntryLedgerFacts<'static> {
        ruleset_facts(
            RULE_SET_ID,
            RULE_ID,
            REF_ID,
            CARD_ID,
            TENANT_ID,
            "BASE",
            "learn_course",
            "read",
            ("", ""),
        )
    }

    /// 与 production 相同结构的 CARD 投影事件身份（带 metadata 语义的形状输入）。
    fn card_projection(generation: i64, fence: i64) -> astral_db::ProjectionEventIdentity {
        astral_db::ProjectionEventIdentity {
            event_id: "card-11111111-2222-4333-8444-555555555555".to_owned(),
            source_generation: generation,
            revoke_fence: fence,
            tenant_id: Some(TENANT_ID),
        }
    }

    fn ruleset_head_from_add(draft: &RuleSetGrantDeltaDraft) -> astral_db::GrantHeadSnapshot {
        let grant = match &draft.delta {
            GrantDelta::Add { grant } => grant.clone(),
            other => panic!("expected ADD delta, got {other:?}"),
        };
        astral_db::GrantHeadSnapshot {
            grant_id: draft.grant_id,
            payload: grant.clone(),
            entry: astral_db::CurrentLedgerEntry {
                revision: grant.revision,
                state: grant.state,
                status_active: true,
            },
        }
    }

    const RULESET_OP: &str = "ruleset:test-op";

    #[test]
    fn ruleset_add_draft_is_deterministic_and_binds_full_provenance() {
        let facts = default_ruleset_facts();
        let contribution =
            derive_ruleset_contribution_event_id(RULESET_OP, &facts, RuleSetMutationKind::Add)
                .unwrap();
        let draft = build_ruleset_add_draft(
            &facts,
            RULESET_OP,
            Some(REVIEWER_ID),
            &card_projection(5, 2),
            &contribution,
        )
        .unwrap();
        // 同一稳定上下文重放完全一致（无时间/随机成分）。
        let second = build_ruleset_add_draft(
            &facts,
            RULESET_OP,
            Some(REVIEWER_ID),
            &card_projection(5, 2),
            &derive_ruleset_contribution_event_id(RULESET_OP, &facts, RuleSetMutationKind::Add)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(draft.clone(), second);

        // 身份必须来自合同构造器的确定性派生：BASE 层 + rule set aggregate +
        // 稳定 entry + 卡×绑定行×层标 binding_key。
        let identity_key = GrantIdentityKey::rule_set(
            TenantScope::new(TENANT_ID, Some(DOMAIN_ID)).unwrap(),
            BindingLayer::Base,
            &RULE_SET_ID.to_string(),
            &RULE_ID.to_string(),
            &format!("user-card:{CARD_ID}:rule-set:{RULE_SET_ID}:binding:{REF_ID}:BASE"),
        )
        .unwrap();
        assert_eq!(draft.grant_id, identity_key.derive_grant_id().unwrap());

        let request = draft.revision_request();
        assert_eq!(request.tenant_id, TENANT_ID);
        assert_eq!(request.card_id_scope, Some(CARD_ID));
        assert_eq!(request.aggregate_type, RULE_SET_AGGREGATE_TYPE);
        assert_eq!(request.aggregate_id, RULE_SET_ID);
        assert_eq!(request.event_id, contribution);
        assert_eq!(request.operation_id, RULESET_OP);
        assert_eq!(request.compiler_version, COMPILER_VERSION);

        let event_request = draft.delta_event_request(0, 1).unwrap();
        assert_eq!(event_request.base_version, 0);
        assert_eq!(event_request.target_version, 1);
        assert_eq!(event_request.source_generation, 5);
        assert_eq!(event_request.revoke_fence, 2);
        // ADD 天然没有 before-image；成对缺席。
        assert_eq!(event_request.before_image_json, None);
        assert_eq!(event_request.before_digest_hex, None);

        let grant = match &draft.delta {
            GrantDelta::Add { grant } => grant,
            other => panic!("expected ADD delta, got {other:?}"),
        };
        assert_eq!(grant.source_kind, GrantSourceKind::RuleSet);
        assert_eq!(grant.binding_layer, BindingLayer::Base);
        assert_eq!(grant.effect, GrantEffect::Allow);
        assert_eq!(grant.state, GrantState::Active);
        assert_eq!(grant.tenant.tenant_id, TENANT_ID);
        assert_eq!(grant.tenant.domain_id, Some(DOMAIN_ID));
        assert_eq!(grant.card_id, CARD_ID);
        assert_eq!(grant.user_id, USER_ID);
        // provenance 必须携带 source(rule_set)/source_entry(entry)/binding(ref)/
        // contribution event/operation/actor —— 缺一即合同拒绝。
        assert_eq!(grant.provenance.source_id, RULE_SET_ID.to_string());
        assert_eq!(
            grant.provenance.source_entry.as_deref(),
            Some(RULE_ID.to_string()).as_deref()
        );
        assert_eq!(
            grant.provenance.binding_id.as_deref(),
            Some(REF_ID.to_string()).as_deref()
        );
        assert_eq!(grant.provenance.delegation_id, None);
        assert_eq!(grant.provenance.operation_id, RULESET_OP);
        assert_eq!(
            grant.provenance.event_id.as_deref(),
            Some(contribution.as_str())
        );
        assert_eq!(grant.provenance.actor_user_id, Some(REVIEWER_ID));

        // 合同哈希：语义 hash = canonical grant 摘要；依赖 hash = CARD 向量摘要。
        assert_eq!(draft.semantic_hash_hex, grant.canonical_hash().unwrap());
        assert_eq!(draft.dependency_hash_hex.len(), 64);
        let parsed: Value = serde_json::from_str(&event_request.delta_json).unwrap();
        assert_eq!(parsed["kind"], "ADD");
        assert_eq!(parsed["grant"]["grantId"], draft.grant_id.as_str());
    }

    #[test]
    fn ruleset_identity_diverges_by_card_layer_entry_tenant_and_reuses_mutable_changes() {
        let base = derive_ruleset_identity(&default_ruleset_facts()).unwrap();

        // 不同绑定卡 / 绑定行 / 层标 / 条目 / 租户 —— 全部派生互异 GrantId。
        let variants = [
            ruleset_facts(
                RULE_SET_ID,
                RULE_ID,
                REF_ID,
                CARD_ID + 1,
                TENANT_ID,
                "BASE",
                "r",
                "a",
                ("", ""),
            ),
            ruleset_facts(
                RULE_SET_ID,
                RULE_ID,
                REF_ID + 1,
                CARD_ID,
                TENANT_ID,
                "BASE",
                "r",
                "a",
                ("", ""),
            ),
            ruleset_facts(
                RULE_SET_ID,
                RULE_ID,
                REF_ID,
                CARD_ID,
                TENANT_ID,
                "OVERLAY",
                "r",
                "a",
                ("", ""),
            ),
            ruleset_facts(
                RULE_SET_ID,
                RULE_ID + 1,
                REF_ID,
                CARD_ID,
                TENANT_ID,
                "BASE",
                "r",
                "a",
                ("", ""),
            ),
            ruleset_facts(
                RULE_SET_ID,
                RULE_ID,
                REF_ID,
                CARD_ID,
                TENANT_ID + 1,
                "BASE",
                "r",
                "a",
                ("", ""),
            ),
            ruleset_facts(
                RULE_SET_ID + 1,
                RULE_ID,
                REF_ID,
                CARD_ID,
                TENANT_ID,
                "BASE",
                "r",
                "a",
                ("", ""),
            ),
        ];
        for variant in &variants {
            let diverged = derive_ruleset_identity(variant).unwrap();
            assert_ne!(
                base, diverged,
                "stable scope change must re-key the grant identity"
            );
        }

        // 可变属性（resource/action/priority 不进 identity，validity 也不进）：
        // 更新复用同一 GrantId。
        let mutated = ruleset_facts(
            RULE_SET_ID,
            RULE_ID,
            REF_ID,
            CARD_ID,
            TENANT_ID,
            "BASE",
            "other_resource",
            "write",
            ("2026-01-01", "2026-02-01"),
        );
        assert_eq!(
            base,
            derive_ruleset_identity(&mutated).unwrap(),
            "mutable payload attributes must not re-key the identity"
        );

        // 非法层标 fail-closed：不猜测 NONE/lowercase 的语义。
        for bad_ref_type in ["NONE", "base", "", "DIRECT"] {
            let facts = ruleset_facts(
                RULE_SET_ID,
                RULE_ID,
                REF_ID,
                CARD_ID,
                TENANT_ID,
                bad_ref_type,
                "r",
                "a",
                ("", ""),
            );
            assert!(
                matches!(
                    ruleset_binding_layer(bad_ref_type),
                    Err(AstralError::Validation(_))
                ),
                "ref type {bad_ref_type:?} must be rejected"
            );
            assert!(derive_ruleset_identity(&facts).is_err());
        }

        // 无法证明的租户与非法 id fail-closed。
        let tenantless = ruleset_facts(
            RULE_SET_ID,
            RULE_ID,
            REF_ID,
            CARD_ID,
            0,
            "BASE",
            "r",
            "a",
            ("", ""),
        );
        assert!(matches!(
            derive_ruleset_identity(&tenantless),
            Err(AstralError::Validation(_))
        ));
        let zero_entry = ruleset_facts(
            RULE_SET_ID,
            0,
            REF_ID,
            CARD_ID,
            TENANT_ID,
            "BASE",
            "r",
            "a",
            ("", ""),
        );
        assert!(derive_ruleset_identity(&zero_entry).is_err());
        let zero_ref = ruleset_facts(
            RULE_SET_ID,
            RULE_ID,
            0,
            CARD_ID,
            TENANT_ID,
            "BASE",
            "r",
            "a",
            ("", ""),
        );
        assert!(derive_ruleset_identity(&zero_ref).is_err());
    }

    #[test]
    fn ruleset_contribution_event_ids_are_independent_stable_and_kind_scoped() {
        let facts_a = default_ruleset_facts();
        let mut facts_b = default_ruleset_facts();
        facts_b.card_id = CARD_ID + 1;
        facts_b.ref_id = REF_ID + 1;

        let parent_event = card_projection(4, 1).event_id;
        // 同一 operation 下两张卡的同一条目贡献事件号互异且不等于父投影事件号。
        let id_a1 =
            derive_ruleset_contribution_event_id(RULESET_OP, &facts_a, RuleSetMutationKind::Add)
                .unwrap();
        let id_b1 =
            derive_ruleset_contribution_event_id(RULESET_OP, &facts_b, RuleSetMutationKind::Add)
                .unwrap();
        assert_ne!(id_a1, id_b1);
        assert_ne!(id_a1, parent_event);

        // 同一贡献不同 mutation kind 事件号互异。
        let id_update =
            derive_ruleset_contribution_event_id(RULESET_OP, &facts_a, RuleSetMutationKind::Update)
                .unwrap();
        let id_remove =
            derive_ruleset_contribution_event_id(RULESET_OP, &facts_a, RuleSetMutationKind::Remove)
                .unwrap();
        assert_ne!(id_a1, id_update);
        assert_ne!(id_a1, id_remove);
        assert_ne!(id_update, id_remove);

        // 重放稳定。
        assert_eq!(
            id_a1,
            derive_ruleset_contribution_event_id(RULESET_OP, &facts_a, RuleSetMutationKind::Add)
                .unwrap()
        );
        // 操作 id 变化则事件号随之变化（避免跨批次碰撞）。
        assert_ne!(
            id_a1,
            derive_ruleset_contribution_event_id(
                "ruleset:other-op",
                &facts_a,
                RuleSetMutationKind::Add
            )
            .unwrap()
        );
        // 形状校验：36 字符 UUID 文本。
        assert_eq!(id_a1.len(), 36);
    }

    #[test]
    fn ruleset_update_draft_keeps_identity_with_paired_before_image() {
        let facts = default_ruleset_facts();
        let add = build_ruleset_add_draft(
            &facts,
            RULESET_OP,
            Some(REVIEWER_ID),
            &card_projection(4, 1),
            &derive_ruleset_contribution_event_id(RULESET_OP, &facts, RuleSetMutationKind::Add)
                .unwrap(),
        )
        .unwrap();
        let head = ruleset_head_from_add(&add);

        let updated_facts = ruleset_facts(
            RULE_SET_ID,
            RULE_ID,
            REF_ID,
            CARD_ID,
            TENANT_ID,
            "BASE",
            "learn_course_v2",
            "read",
            ("2026-01-01", "2026-03-01T00:00:00"),
        );
        let contribution = derive_ruleset_contribution_event_id(
            RULESET_OP,
            &updated_facts,
            RuleSetMutationKind::Update,
        )
        .unwrap();
        let update = build_ruleset_update_draft(
            &updated_facts,
            &head,
            RULESET_OP,
            Some(REVIEWER_ID),
            &card_projection(9, 3),
            &contribution,
        )
        .unwrap();

        // UPDATE 保持同一身份（source_entry=entry、binding/card 不变）且版本严格递增。
        assert_eq!(update.grant_id, head.grant_id);
        match &update.delta {
            GrantDelta::Update {
                grant,
                expected_revision,
            } => {
                assert_eq!(*expected_revision, head.entry.revision);
                assert_eq!(grant.revision.value(), head.entry.revision.value() + 1);
                assert_eq!(grant.resource, "learn_course_v2:*");
                assert_eq!(grant.action, "read");
                // expires_at exclusive 边界：日期解析为 UTC 零点。
                let from = time::PrimitiveDateTime::new(
                    time::Date::from_calendar_date(2026, time::Month::January, 1).unwrap(),
                    time::Time::MIDNIGHT,
                )
                .assume_utc()
                .unix_timestamp();
                assert_eq!(grant.validity.not_before, Some(from));
                assert_eq!(grant.validity.expires_at, Some(from + 59 * 86_400));
            }
            other => panic!("expected UPDATE delta, got {other:?}"),
        }

        // before-image = 旧 canonical grant JSON，digest 成对且可独立复算。
        let before_image = update.before_image_json.as_ref().unwrap();
        assert_eq!(before_image, &head.payload.canonical_input().unwrap());
        let mut hasher = Sha256::new();
        hasher.update(before_image.as_bytes());
        let expected_digest: String = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            update.before_digest_hex.as_deref(),
            Some(expected_digest.as_str())
        );

        let event_request = update.delta_event_request(6, 7).unwrap();
        assert_eq!(event_request.base_version, 6);
        assert_eq!(event_request.target_version, 7);
        assert_eq!(event_request.event_type, astral_db::DeltaEventType::Update);
        assert_eq!(event_request.grant_id, head.grant_id);
        let parsed: Value = serde_json::from_str(&event_request.delta_json).unwrap();
        assert_eq!(parsed["kind"], "UPDATE");
        // 反序列化侧按共享合同解码：expectedRevision 必须等于旧 head revision。
        let decoded = astral_db::decode_delta_event_payload(&event_request.delta_json).unwrap();
        match decoded {
            GrantDelta::Update {
                grant,
                expected_revision,
            } => {
                assert_eq!(expected_revision.value(), head.entry.revision.value());
                assert_eq!(grant.grant_id, head.grant_id);
                assert_eq!(expected_revision.value() + 1, grant.revision.value());
            }
            other => panic!("expected UPDATE payload, got {other:?}"),
        }
    }

    #[test]
    fn ruleset_remove_draft_pairs_before_image_and_rejects_drift() {
        let facts = default_ruleset_facts();
        let add = build_ruleset_add_draft(
            &facts,
            RULESET_OP,
            Some(REVIEWER_ID),
            &card_projection(2, 1),
            &derive_ruleset_contribution_event_id(RULESET_OP, &facts, RuleSetMutationKind::Add)
                .unwrap(),
        )
        .unwrap();
        let head = ruleset_head_from_add(&add);
        let contribution =
            derive_ruleset_contribution_event_id(RULESET_OP, &facts, RuleSetMutationKind::Remove)
                .unwrap();
        let removal = build_ruleset_remove_draft(
            &facts,
            &head,
            RULESET_OP,
            &card_projection(8, 5),
            &contribution,
        )
        .unwrap();

        match &removal.delta {
            GrantDelta::Remove {
                grant_id,
                expected_revision,
            } => {
                assert_eq!(*grant_id, head.grant_id);
                assert_eq!(*expected_revision, head.entry.revision);
            }
            other => panic!("expected REMOVE delta, got {other:?}"),
        }
        // semantic hash 锚定被移除的旧授权内容。
        assert_eq!(
            removal.semantic_hash_hex,
            removal.before_digest_hex.as_deref().unwrap()
        );
        assert_eq!(
            removal.before_image_json.as_deref(),
            Some(head.payload.canonical_input().unwrap().as_str())
        );
        let event_request = removal.delta_event_request(3, 4).unwrap();
        assert_eq!(event_request.event_type, astral_db::DeltaEventType::Remove);

        // 头部漂移 fail-closed：另一份账本记录绝不能被本条 mutation 改写。
        let mut drifted = head.clone();
        drifted.payload.provenance.source_entry = Some((RULE_ID + 9).to_string());
        assert!(build_ruleset_remove_draft(
            &facts,
            &drifted,
            RULESET_OP,
            &card_projection(8, 5),
            &contribution
        )
        .is_err());

        let mut wrong_binding = head;
        wrong_binding.payload.provenance.binding_id = Some((REF_ID + 1).to_string());
        assert!(build_ruleset_remove_draft(
            &facts,
            &wrong_binding,
            RULESET_OP,
            &card_projection(8, 5),
            &contribution
        )
        .is_err());
    }

    #[test]
    fn ruleset_unprovable_or_overreaching_inputs_fail_closed() {
        let p = card_projection(1, 0);
        let op = RULESET_OP;

        // 空 operation id。
        assert!(build_ruleset_add_draft(
            &default_ruleset_facts(),
            "  ",
            Some(REVIEWER_ID),
            &p,
            &"e".repeat(36)
        )
        .is_err());

        // 系统 actor（None）合法；非正数 actor 拒绝。
        let ok_system =
            build_ruleset_add_draft(&default_ruleset_facts(), op, None, &p, &"e".repeat(36))
                .unwrap();
        match &ok_system.delta {
            GrantDelta::Add { grant } => assert_eq!(grant.provenance.actor_user_id, None),
            other => panic!("expected ADD delta, got {other:?}"),
        }
        assert!(build_ruleset_add_draft(
            &default_ruleset_facts(),
            op,
            Some(0),
            &p,
            &"e".repeat(36)
        )
        .is_err());
        assert!(build_ruleset_add_draft(
            &default_ruleset_facts(),
            op,
            Some(-3),
            &p,
            &"e".repeat(36)
        )
        .is_err());

        // 空 resource/action 不能进入 canonical 合同。
        let no_resource = ruleset_facts(
            RULE_SET_ID,
            RULE_ID,
            REF_ID,
            CARD_ID,
            TENANT_ID,
            "BASE",
            "",
            "a",
            ("", ""),
        );
        assert!(build_ruleset_add_draft(&no_resource, op, None, &p, &"e".repeat(36)).is_err());
        let no_action = ruleset_facts(
            RULE_SET_ID,
            RULE_ID,
            REF_ID,
            CARD_ID,
            TENANT_ID,
            "BASE",
            "r",
            " ",
            ("", ""),
        );
        assert!(build_ruleset_add_draft(&no_action, op, None, &p, &"e".repeat(36)).is_err());

        // 无法解析的有效期 fail-closed（不猜测时区/格式）。
        let bad_validity = ruleset_facts(
            RULE_SET_ID,
            RULE_ID,
            REF_ID,
            CARD_ID,
            TENANT_ID,
            "BASE",
            "r",
            "a",
            ("2026-13-40", ""),
        );
        assert!(build_ruleset_add_draft(&bad_validity, op, None, &p, &"e".repeat(36)).is_err());

        // 负代次/负围栏的投影事件身份 fail-closed。
        assert!(
            validated_projection_identity(&astral_db::ProjectionEventIdentity {
                event_id: "evt".to_owned(),
                source_generation: -1,
                revoke_fence: 0,
                tenant_id: Some(TENANT_ID),
            })
            .is_err()
        );

        // 贡献事件号形态校验（空/超长/空白）fail-closed。
        assert!(derive_ruleset_contribution_event_id(
            op,
            &default_ruleset_facts(),
            RuleSetMutationKind::Add
        )
        .is_ok());
        assert!(build_ruleset_add_draft(&default_ruleset_facts(), op, None, &p, "").is_err());
        assert!(
            build_ruleset_add_draft(&default_ruleset_facts(), op, None, &p, "has space").is_err()
        );
    }

    /// 结构守卫：事务追加先 revision 后 delta event（RuleSet wrapper）。
    #[test]
    fn ruleset_transaction_append_is_revision_then_delta() {
        // 实现已下沉至 astral-db::grant_ledger（identity / trustgraph 共用同一
        // 组装层），结构守卫改为锚定公共模块源码，防止两侧事务追加顺序漂移。
        let source = include_str!("../../../astral-db/src/grant_ledger.rs");
        let body = source
            .split("pub async fn append_ruleset_grant_delta_in_tx")
            .nth(1)
            .expect("rule set transaction wrapper must exist")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let revision = body
            .find("append_grant_revision_in_tx")
            .expect("revision append call");
        let delta = body.find("append_delta_event").expect("delta event call");
        assert!(revision < delta);
        assert!(body.contains("map_grant_repository_error"));
        assert!(body.contains("target_version <= base_version"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // APPROVAL REMOVE（与 Add 对称的撤销草稿）
    // ─────────────────────────────────────────────────────────────────────────

    /// 与 Add 同路径构造的假 head：payload 直接来自 approval ADD 草稿，
    /// identity/provenance/租户/卡归属天然对齐 —— 对齐校验的“合法基线”。
    fn approval_head_from_add() -> astral_db::GrantHeadSnapshot {
        let add = build_approval_add_draft(&perpetual_context(), &projection(5, 1))
            .expect("approval add draft must assemble for fake head");
        let payload = match &add.delta {
            GrantDelta::Add { grant } => grant.clone(),
            other => panic!("expected ADD delta, got {other:?}"),
        };
        astral_db::GrantHeadSnapshot {
            grant_id: add.grant_id,
            entry: astral_db::CurrentLedgerEntry {
                revision: GrantRevision::initial(),
                state: GrantState::Active,
                status_active: true,
            },
            payload,
        }
    }

    fn approval_remove_facts(rule_id: i64) -> ApprovalRemoveLedgerFacts {
        ApprovalRemoveLedgerFacts {
            tenant_id: Some(TENANT_ID),
            domain_id: Some(DOMAIN_ID),
            card_id: CARD_ID,
            user_id: USER_ID,
            request_id: REQUEST_ID,
            rule_id,
        }
    }

    #[test]
    fn approval_remove_draft_pairs_before_image_with_digest_and_pins_request_identity() {
        let head = approval_head_from_add();
        let parent = projection(6, 2);
        let contribution = derive_approval_contribution_event_id(
            "approval:9001",
            &approval_remove_facts(RULE_ID),
            ApprovalContributionKind::Remove,
        )
        .unwrap();
        let draft = build_approval_remove_draft(
            &approval_remove_facts(RULE_ID),
            &head,
            "approval:9001",
            &parent,
            &contribution,
        )
        .expect("approval remove draft must assemble");

        // 确定性：同一稳定上下文重放得到完全相同的草稿。
        let replayed = build_approval_remove_draft(
            &approval_remove_facts(RULE_ID),
            &head,
            "approval:9001",
            &parent,
            &contribution,
        )
        .unwrap();
        assert_eq!(draft, replayed);

        // before-image = 旧 canonical grant 输入，digest 成对且为小写 64 hex。
        assert_eq!(
            draft
                .delta_event_request(0, 1)
                .unwrap()
                .before_image_json
                .as_deref(),
            Some(head.payload.canonical_input().unwrap().as_str())
        );
        let digest = draft
            .delta_event_request(0, 1)
            .unwrap()
            .before_digest_hex
            .unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));

        // identity/provenance：APPROVAL×request 聚合、source_entry=rule。
        match &draft.delta {
            GrantDelta::Remove { .. } => {}
            other => panic!("expected REMOVE delta, got {other:?}"),
        }
        let revision_request = draft.revision_request();
        assert_eq!(revision_request.aggregate_type, APPROVAL_AGGREGATE_TYPE);
        assert_eq!(revision_request.aggregate_id, REQUEST_ID);
        assert_eq!(revision_request.card_id_scope, Some(CARD_ID));
        assert_eq!(revision_request.operation_id, "approval:9001");

        let event_request = draft.delta_event_request(0, 1).unwrap();
        // 本贡献使用自己的独立事件号，绝不复用 parent 投影事件号。
        assert_eq!(event_request.event_id, contribution);
        assert_ne!(event_request.event_id, parent.event_id);
        assert_eq!(event_request.aggregate_type, APPROVAL_AGGREGATE_TYPE);
        assert_eq!(event_request.aggregate_id, REQUEST_ID);
        assert_eq!(event_request.source_generation, 6);
        assert_eq!(event_request.revoke_fence, 2);
        // 解码后的 delta 指向同一 grant 身份。
        let decoded = astral_db::decode_delta_event_payload(&event_request.delta_json).unwrap();
        assert_eq!(decoded.target_grant_id().unwrap(), draft.grant_id);
        // 二者成对出现（REMOVE 必带旧 canonical grant 输入）。
        assert!(event_request.before_image_json.is_some());
        assert!(event_request.before_digest_hex.is_some());
    }

    #[test]
    fn approval_remove_contribution_ids_are_unique_per_rule_and_stable_per_operation() {
        let first = derive_approval_contribution_event_id(
            "approval:9001",
            &approval_remove_facts(RULE_ID),
            ApprovalContributionKind::Remove,
        )
        .unwrap();
        let second_rule = derive_approval_contribution_event_id(
            "approval:9001",
            &approval_remove_facts(RULE_ID + 1),
            ApprovalContributionKind::Remove,
        )
        .unwrap();
        assert_ne!(
            first, second_rule,
            "two rules under one card-delete operation must never share a contribution id"
        );
        assert_eq!(
            derive_approval_contribution_event_id(
                "approval:9001",
                &approval_remove_facts(RULE_ID),
                ApprovalContributionKind::Remove
            )
            .unwrap(),
            first,
            "replay of the same logical operation must reuse the same contribution id"
        );
        assert_ne!(
            derive_approval_contribution_event_id(
                "other-op",
                &approval_remove_facts(RULE_ID),
                ApprovalContributionKind::Remove
            )
            .unwrap(),
            first,
            "a different operation context must fork the identity"
        );
    }

    #[test]
    fn approval_remove_fails_closed_on_identity_drift_and_missing_scope() {
        let head = approval_head_from_add();

        // request 主键漂移 → Internal（head provenance 不再对得上锁定行）。
        let drifted_request = ApprovalRemoveLedgerFacts {
            request_id: REQUEST_ID + 7,
            ..approval_remove_facts(RULE_ID)
        };
        assert!(matches!(
            build_approval_remove_draft(&drifted_request, &head, "op", &projection(1, 0), "evt-x"),
            Err(AstralError::Internal(_))
        ));
        // rule 漂移同理。
        let drifted_rule = approval_remove_facts(RULE_ID + 3);
        assert!(matches!(
            build_approval_remove_draft(&drifted_rule, &head, "op", &projection(1, 0), "evt-y"),
            Err(AstralError::Internal(_))
        ));
        // 卡漂移先命中 grant-id 分支（binding scope 参与身份派生）→ Internal。
        let wrong_card = ApprovalRemoveLedgerFacts {
            card_id: CARD_ID + 1,
            ..approval_remove_facts(RULE_ID)
        };
        assert!(matches!(
            build_approval_remove_draft(&wrong_card, &head, "op", &projection(1, 0), "evt-z"),
            Err(AstralError::Internal(_))
        ));
        // 毒化 head（grant id 对、payload 归属被改写）→ Validation fail-closed：
        // 禁止把 tombstone 打到另一份卡/租户上下文的账本记录上。
        let mut poisoned_payload = head.payload.clone();
        poisoned_payload.card_id = CARD_ID + 1;
        let poisoned_head = astral_db::GrantHeadSnapshot {
            grant_id: head.grant_id,
            entry: astral_db::CurrentLedgerEntry {
                revision: GrantRevision::initial(),
                state: GrantState::Active,
                status_active: true,
            },
            payload: poisoned_payload,
        };
        assert!(matches!(
            build_approval_remove_draft(
                &approval_remove_facts(RULE_ID),
                &poisoned_head,
                "op",
                &projection(1, 0),
                "evt-p"
            ),
            Err(AstralError::Validation(_))
        ));
        // NULL 租户无法拼出审批撤销身份 → fail-closed，不回填假值。
        let tenantless = ApprovalRemoveLedgerFacts {
            tenant_id: None,
            ..approval_remove_facts(RULE_ID)
        };
        assert!(matches!(
            derive_approval_identity(&tenantless),
            Err(AstralError::Validation(_))
        ));
        // 非 ALLOW-only 合同拒绝出现在别处；这里守空 operation / 非法事件号。
        assert!(build_approval_remove_draft(
            &approval_remove_facts(RULE_ID),
            &head,
            "",
            &projection(1, 0),
            "evt-a"
        )
        .is_err());
        assert!(build_approval_remove_draft(
            &approval_remove_facts(RULE_ID),
            &head,
            "op",
            &projection(1, 0),
            "has space"
        )
        .is_err());
    }

    /// 结构守卫：事务追加先 revision 后 delta event（approval remove wrapper），
    /// 且版本号必须严格前进（base 非负、target > base），错误一律 fail-closed。
    #[test]
    fn approval_transaction_append_is_revision_then_delta_with_version_gate() {
        let source = include_str!("grant_ledger_adapter.rs");
        let body = source
            .split("pub(crate) async fn append_approval_remove_in_tx")
            .nth(1)
            .expect("approval remove transaction wrapper must exist")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let revision = body
            .find("append_grant_revision_in_tx")
            .expect("revision append call");
        let delta = body.find("append_delta_event").expect("delta event call");
        assert!(revision < delta);
        assert!(body.contains("map_grant_repository_error"));
        assert!(body.contains("target_version <= base_version"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DELEGATION builders
    // ─────────────────────────────────────────────────────────────────────────

    const DEL_DELEGATION_ID: i64 = 7001;
    const DEL_CARD_ID: i64 = 310; // 被委托承载卡
    const DEL_USER_ID: i64 = 77;
    const DEL_NOT_BEFORE: i64 = 1_760_000_000;
    const DEL_EXPIRES: i64 = 1_770_000_000;

    fn delegation_facts_test(
        resource: &'static str,
        action: &'static str,
    ) -> DelegationLedgerFacts<'static> {
        DelegationLedgerFacts {
            tenant_id: TENANT_ID,
            domain_id: Some(DOMAIN_ID),
            card_id: DEL_CARD_ID,
            user_id: DEL_USER_ID,
            delegation_id: DEL_DELEGATION_ID,
            resource,
            action,
            not_before_unix: Some(DEL_NOT_BEFORE),
            expires_at_unix: DEL_EXPIRES,
        }
    }

    fn delegation_head_for(
        facts: &DelegationLedgerFacts<'_>,
        revision: u64,
    ) -> astral_db::GrantHeadSnapshot {
        let grant_id = derive_delegation_identity(facts).unwrap();
        let payload = CanonicalGrant {
            grant_id,
            revision: GrantRevision::new(revision).unwrap(),
            state: GrantState::Active,
            source_kind: GrantSourceKind::Delegation,
            binding_layer: BindingLayer::None,
            tenant: TenantScope::new(TENANT_ID, Some(DOMAIN_ID)).unwrap(),
            card_id: facts.card_id,
            user_id: facts.user_id,
            resource: facts.resource.to_owned(),
            action: facts.action.to_owned(),
            effect: GrantEffect::Allow,
            validity: ValidityWindow {
                not_before: facts.not_before_unix,
                expires_at: Some(facts.expires_at_unix),
            },
            provenance: GrantProvenance {
                source_id: facts.delegation_id.to_string(),
                source_entry: Some(facts.delegation_id.to_string()),
                binding_id: None,
                delegation_id: Some(facts.delegation_id.to_string()),
                operation_id: "delegation:create:7001".into(),
                event_id: None,
                actor_user_id: Some(DEL_USER_ID),
            },
        };
        astral_db::GrantHeadSnapshot {
            grant_id,
            payload: payload.canonicalized().unwrap(),
            entry: astral_db::CurrentLedgerEntry {
                revision: GrantRevision::new(revision).unwrap(),
                state: GrantState::Active,
                status_active: true,
            },
        }
    }

    #[test]
    fn delegation_add_draft_is_deterministic_and_binds_delegation_provenance() {
        let facts = delegation_facts_test("learn_course", "read");
        let projection = projection(5, 0);
        let first =
            build_delegation_add_draft(&facts, "delegation:create:7001", 10, &projection, "e1")
                .unwrap();
        let second =
            build_delegation_add_draft(&facts, "delegation:create:7001", 10, &projection, "e1")
                .unwrap();
        assert_eq!(first, second);

        // grant id 必须来自确定性委托身份而非随机构造。
        let identity_key = GrantIdentityKey::delegation(
            TenantScope::new(TENANT_ID, Some(DOMAIN_ID)).unwrap(),
            &DEL_DELEGATION_ID.to_string(),
            &DEL_DELEGATION_ID.to_string(),
        )
        .unwrap();
        assert_eq!(first.grant_id(), identity_key.derive_grant_id().unwrap());

        let grant = match &first.delta {
            GrantDelta::Add { grant } => grant,
            other => panic!("expected ADD delta, got {other:?}"),
        };
        assert_eq!(grant.revision, GrantRevision::initial());
        assert_eq!(grant.state, GrantState::Active);
        assert_eq!(grant.source_kind, GrantSourceKind::Delegation);
        assert_eq!(grant.binding_layer, BindingLayer::None);
        assert_eq!(grant.effect, GrantEffect::Allow);
        // 授权承载事实必须是被委托卡，而不是 delegator。
        assert_eq!(grant.card_id, DEL_CARD_ID);
        assert_eq!(grant.user_id, DEL_USER_ID);
        // 有效期 UTC 秒：下界含界、上界排他由合同表达。
        assert_eq!(grant.validity.not_before, Some(DEL_NOT_BEFORE));
        assert_eq!(grant.validity.expires_at, Some(DEL_EXPIRES));

        // provenance：delegation_id 必填且仅出现在 DELEGATION 源。
        assert_eq!(
            grant.provenance.delegation_id.as_deref(),
            Some(DEL_DELEGATION_ID.to_string()).as_deref()
        );
        assert_eq!(grant.provenance.source_id, DEL_DELEGATION_ID.to_string());
        assert_eq!(
            grant.provenance.source_entry.as_deref(),
            Some(DEL_DELEGATION_ID.to_string()).as_deref()
        );
        assert_eq!(grant.provenance.binding_id, None);
        assert_eq!(grant.provenance.operation_id, "delegation:create:7001");

        let request = first.delta_event_request(0, 1).unwrap();
        assert_eq!(request.event_type, astral_db::DeltaEventType::Add);
        assert_eq!(request.base_version, 0);
        assert_eq!(request.target_version, 1);
        assert_eq!(request.aggregate_type, DELEGATION_AGGREGATE_TYPE);
        assert_eq!(request.aggregate_id, DEL_DELEGATION_ID);
        assert!(request.before_image_json.is_none());
        assert!(request.before_digest_hex.is_none());
    }

    #[test]
    fn delegation_contribution_event_ids_fork_by_kind_delegation_and_tenant() {
        let op = "req-fixed";
        let facts = delegation_facts_test("learn_course", "read");
        let add =
            derive_delegation_contribution_event_id(op, &facts, DelegationContributionKind::Add)
                .unwrap();
        let update =
            derive_delegation_contribution_event_id(op, &facts, DelegationContributionKind::Update)
                .unwrap();
        let revoke =
            derive_delegation_contribution_event_id(op, &facts, DelegationContributionKind::Revoke)
                .unwrap();
        // 同一贡献不同 mutation kind 必然分叉；重放确定一致。
        assert_ne!(add, update);
        assert_ne!(add, revoke);
        assert_ne!(update, revoke);
        assert_eq!(
            add,
            derive_delegation_contribution_event_id(op, &facts, DelegationContributionKind::Add)
                .unwrap()
        );

        // 不同委托/租户/operation 必然分叉。
        let mut other = delegation_facts_test("learn_course", "read");
        other.delegation_id = DEL_DELEGATION_ID + 1;
        assert_ne!(
            add,
            derive_delegation_contribution_event_id(op, &other, DelegationContributionKind::Add)
                .unwrap()
        );
        let mut cross_tenant = delegation_facts_test("learn_course", "read");
        cross_tenant.tenant_id += 1;
        assert_ne!(
            add,
            derive_delegation_contribution_event_id(
                op,
                &cross_tenant,
                DelegationContributionKind::Add
            )
            .unwrap()
        );
        assert_ne!(
            add,
            derive_delegation_contribution_event_id(
                "other-op",
                &facts,
                DelegationContributionKind::Add
            )
            .unwrap()
        );
    }

    #[test]
    fn delegation_operation_id_reuses_safe_header_or_derives_without_randomness() {
        use DelegationMutationKind as K;
        // 安全头部原样复用（与 identity_bound_revision 无关：显式 header 语义不变）。
        assert_eq!(
            derive_delegation_operation_id(K::Create, DEL_DELEGATION_ID, Some("req-9"), None)
                .unwrap(),
            "req-9"
        );
        assert_eq!(
            derive_delegation_operation_id(K::Update, DEL_DELEGATION_ID, Some("req-9"), Some(4))
                .unwrap(),
            "req-9",
            "explicit header must be reused verbatim; revision only shapes the fallback"
        );
        // 缺失/空白 → 从 kind + delegation 主键（+ 可选锁定 revision）确定性派生，
        // 绝不随机。create 由调用方传 None（head 尚不存在）；update/revoke 必须绑定。
        for (kind, token) in [
            (K::Create, "create"),
            (K::Update, "update"),
            (K::Revoke, "revoke"),
        ] {
            let bound = match kind {
                K::Create => None,
                _ => Some(3u64),
            };
            let expected = match kind {
                K::Create => format!("delegation:{token}:{DEL_DELEGATION_ID}"),
                _ => format!("delegation:{token}:{DEL_DELEGATION_ID}:r3"),
            };
            assert_eq!(
                derive_delegation_operation_id(kind, DEL_DELEGATION_ID, None, bound).unwrap(),
                expected
            );
            assert_eq!(
                derive_delegation_operation_id(kind, DEL_DELEGATION_ID, Some("   "), bound)
                    .unwrap(),
                expected
            );
        }
        // create 不绑定 head（尚不存在）：fallback 保持 kind+主键 形态。
        assert_eq!(
            derive_delegation_operation_id(K::Create, DEL_DELEGATION_ID, None, None).unwrap(),
            format!("delegation:create:{DEL_DELEGATION_ID}")
        );
        // 非法头部字符 fail-closed；非正主键 / 非正 revision 拒绝。
        assert!(
            derive_delegation_operation_id(K::Create, DEL_DELEGATION_ID, Some("a b"), None)
                .is_err()
        );
        assert!(derive_delegation_operation_id(K::Create, 0, None, None).is_err());
        assert!(
            derive_delegation_operation_id(K::Update, DEL_DELEGATION_ID, None, Some(0)).is_err(),
            "revision-bound fallback requires a positive locked ledger revision"
        );
    }

    /// M1 契约：同一业务重试（head 未推进）必然得到相同 operation id；revision
    /// 推进后的后续真实更新必然分叉 —— 连续更新不再复用全局唯一的 delta 事件号。
    #[test]
    fn delegation_fallback_identity_is_retry_stable_and_forks_after_revision_advance() {
        use DelegationMutationKind as K;
        let first_update =
            derive_delegation_operation_id(K::Update, DEL_DELEGATION_ID, None, Some(4)).unwrap();
        // 同代重放完全一致（确定性、无随机成分）。
        assert_eq!(
            derive_delegation_operation_id(K::Update, DEL_DELEGATION_ID, None, Some(4)).unwrap(),
            first_update
        );
        // 代次推进后是新操作身份。
        let advanced =
            derive_delegation_operation_id(K::Update, DEL_DELEGATION_ID, None, Some(5)).unwrap();
        assert_ne!(
            first_update, advanced,
            "a subsequent real update after a committed update must carry its own identity"
        );
        // 不同 mutation kind 即便同代也不交叉。
        assert_ne!(
            derive_delegation_operation_id(K::Revoke, DEL_DELEGATION_ID, None, Some(4)).unwrap(),
            first_update
        );
        // 不同委托必然分叉。
        assert_ne!(
            derive_delegation_operation_id(K::Update, DEL_DELEGATION_ID + 1, None, Some(4))
                .unwrap(),
            first_update
        );

        // 分叉的 operation id 穿透 DeltaEventIdentity 后事件号同样分叉：
        // 同一代次重试得到同一 contribution event id，不同代次的事件号不同。
        let facts = delegation_facts_test("learn_course", "read");
        let event_first = derive_delegation_contribution_event_id(
            &first_update,
            &facts,
            DelegationContributionKind::Update,
        )
        .unwrap();
        assert_eq!(
            event_first,
            derive_delegation_contribution_event_id(
                &first_update,
                &facts,
                DelegationContributionKind::Update,
            )
            .unwrap()
        );
        assert_ne!(
            event_first,
            derive_delegation_contribution_event_id(
                &advanced,
                &facts,
                DelegationContributionKind::Update,
            )
            .unwrap()
        );
    }

    /// 内部确定性派生的 operation id 必须落在 audit_log.request_id VARCHAR(64)
    /// 的 canonical 宽度内（含最大 i64/hex 场景），且显式 header 在 64/65 边界
    /// 处分别接受/拒绝 —— 绝不截断或静默归一化 65..=96 的旧区间。
    #[test]
    fn derived_operation_ids_stay_within_audit_column_width_and_header_bounds_at_64() {
        use DelegationMutationKind as K;
        const MAX_I64: i64 = i64::MAX;
        for id in [1i64, MAX_I64] {
            for revision in [1u64, u64::MAX - 1] {
                for kind in [K::Create, K::Update, K::Revoke] {
                    let bound = if kind == K::Create {
                        None
                    } else {
                        Some(revision)
                    };
                    let derived = derive_delegation_operation_id(kind, id, None, bound).unwrap();
                    assert!(
                        derived.len() < MAX_HEADER_OPERATION_ID_LENGTH,
                        "derived operation id {derived:?} must stay under {} bytes",
                        MAX_HEADER_OPERATION_ID_LENGTH
                    );
                }
            }
        }
        // 显式 header 边界：恰好 64 字节接受，65 字节 Validation 拒绝。
        let boundary_ok = "h".repeat(MAX_HEADER_OPERATION_ID_LENGTH);
        assert_eq!(boundary_ok.len(), 64);
        assert_eq!(
            derive_delegation_operation_id(
                K::Update,
                DEL_DELEGATION_ID,
                Some(&boundary_ok),
                Some(2),
            )
            .unwrap(),
            boundary_ok
        );
        let over = "h".repeat(MAX_HEADER_OPERATION_ID_LENGTH + 1);
        assert!(matches!(
            derive_delegation_operation_id(K::Update, DEL_DELEGATION_ID, Some(&over), Some(2)),
            Err(AstralError::Validation(_))
        ));
    }

    /// 贡献事件身份与 grant 身份严格分离：同一 facts 下两者都是确定性 UUID，
    /// 但派生自不同的域分离 helper，输出永不混同。
    #[test]
    fn delegation_contribution_event_id_is_never_the_grant_identity() {
        let facts = delegation_facts_test("learn_course", "read");
        let event_id = derive_delegation_contribution_event_id(
            "op-grant-vs-event",
            &facts,
            DelegationContributionKind::Add,
        )
        .unwrap();
        let grant_id = derive_delegation_identity(&facts).unwrap();
        assert_ne!(event_id, grant_id.as_str());
        // 重放稳定。
        assert_eq!(
            event_id,
            derive_delegation_contribution_event_id(
                "op-grant-vs-event",
                &facts,
                DelegationContributionKind::Add,
            )
            .unwrap()
        );
    }

    #[test]
    fn delegation_update_draft_keeps_identity_carries_cas_successor_and_before_pair() {
        let old_facts = delegation_facts_test("learn_course", "read");
        let head = delegation_head_for(&old_facts, 3);
        // 更新只改可变属性（resource/action/effective_until）；身份不变。
        let new_facts = delegation_facts_test("learn_quiz", "write");
        let projection = projection(6, 0);
        let draft = build_delegation_update_draft(
            &new_facts,
            &head,
            "delegation:update:7001",
            11,
            &projection,
            "contrib-update",
        )
        .unwrap();

        assert_eq!(draft.grant_id(), head.grant_id);
        match &draft.delta {
            GrantDelta::Update {
                grant,
                expected_revision,
            } => {
                assert_eq!(*expected_revision, GrantRevision::new(3).unwrap());
                assert_eq!(grant.revision.value(), 4);
                assert_eq!(grant.state, GrantState::Active);
                // ALLOW-only 纵深防御：UPDATE 产出恒为显式 ALLOW，不继承 head。
                assert_eq!(grant.effect, GrantEffect::Allow);
                assert_eq!(grant.source_kind, GrantSourceKind::Delegation);
                assert_eq!(grant.grant_id, head.grant_id);
                assert_eq!(grant.resource, "learn_quiz");
                assert_eq!(grant.action, "write");
                assert_eq!(grant.validity.expires_at, Some(DEL_EXPIRES));
            }
            other => panic!("expected UPDATE delta, got {other:?}"),
        }
        // before-image/digest 成对出现且锚定旧 canonical grant。
        let before = draft
            .delta_event_request(2, 3)
            .unwrap()
            .before_image_json
            .expect("UPDATE must carry a paired before-image");
        assert_eq!(before, head.payload.canonical_input().unwrap());
        let digest = draft.before_digest_hex().expect("paired digest");
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }

    /// 纵深防御：DIRECT 与 DELEGATION 的 UPDATE 组装不得从 head.payload 继承
    /// effect —— 即使未来 canonical head 形状演化出非 ALLOW 载荷，更新草稿也必须
    /// 显式产出 ALLOW-only 语义，并把该语义锚进 semantic hash（对齐
    /// `build_ruleset_update_draft` 既有钉死）。
    ///
    /// `GrantEffect` 当前是单变体 ALLOW-only 枚举，无法在运行时构造非 ALLOW head；
    /// 因此除运行时断言外，另加源码结构守卫：两个 UPDATE builder 体内必须存在
    /// `updated.effect = GrantEffect::Allow;`，且先于 `GrantDelta::update` 组装 ——
    /// head 形状演化若移除/挪动该钉死，此测试立即失败。
    #[test]
    fn direct_and_delegation_update_drafts_explicitly_pin_allow_effect() {
        // 运行时证明：UPDATE 结果 grant 恒为 ALLOW，且 semantic hash 锚定该 ALLOW 内容。
        let direct_head = active_head_from(&direct_add_draft(None));
        let direct_update = build_direct_update_draft(
            &direct_facts(None),
            &direct_head,
            DIRECT_OPERATION,
            DIRECT_ACTOR,
            &projection(6, 0),
        )
        .expect("direct update draft must assemble");
        match &direct_update.delta {
            GrantDelta::Update { grant, .. } => {
                assert_eq!(grant.effect, GrantEffect::Allow);
                assert_eq!(
                    direct_update.semantic_hash_hex,
                    grant.canonical_hash().unwrap(),
                    "direct semantic hash must anchor the pinned ALLOW grant"
                );
            }
            other => panic!("expected UPDATE delta, got {other:?}"),
        }

        let delegation_facts = delegation_facts_test("learn_course", "read");
        let delegation_head = delegation_head_for(&delegation_facts, 3);
        let delegation_update = build_delegation_update_draft(
            &delegation_facts,
            &delegation_head,
            "delegation:update:7001",
            11,
            &projection(6, 0),
            "contrib-update-allow",
        )
        .expect("delegation update draft must assemble");
        match &delegation_update.delta {
            GrantDelta::Update { grant, .. } => {
                assert_eq!(grant.effect, GrantEffect::Allow);
                assert_eq!(
                    delegation_update.semantic_hash_hex,
                    grant.canonical_hash().unwrap(),
                    "delegation semantic hash must anchor the pinned ALLOW grant"
                );
            }
            other => panic!("expected UPDATE delta, got {other:?}"),
        }

        // 结构守卫：两个 UPDATE builder 的函数体内必须显式钉死 effect = ALLOW，
        // 且该钉死先于 UPDATE delta 的组装（钉在 delta 之后即失效）。
        let adapter_source = include_str!("grant_ledger_adapter.rs");
        let gl_source = include_str!("../../../astral-db/src/grant_ledger.rs");
        for (marker, source) in [
            ("pub fn build_direct_update_draft", gl_source),
            (
                "pub(crate) fn build_delegation_update_draft",
                adapter_source,
            ),
        ] {
            let body = source
                .split(marker)
                .nth(1)
                .unwrap_or_else(|| panic!("update builder must exist: {marker}"))
                .split("#[cfg(test)]")
                .next()
                .expect("test module must trail the update builders");
            let pin = body
                .find("updated.effect = GrantEffect::Allow;")
                .unwrap_or_else(|| {
                    panic!("{marker} must explicitly pin effect to ALLOW instead of inheriting head.payload.effect")
                });
            let delta = body
                .find("GrantDelta::update(")
                .unwrap_or_else(|| panic!("{marker} must assemble the UPDATE delta"));
            assert!(
                pin < delta,
                "the ALLOW pin must be applied before the UPDATE delta is built: {marker}"
            );
        }
    }

    #[test]
    fn delegation_revoke_draft_is_revoked_tombstone_anchored_to_before_image() {
        let facts = delegation_facts_test("learn_course", "read");
        let head = delegation_head_for(&facts, 2);
        let projection = projection(7, 1);
        let draft = build_delegation_revoke_draft(
            &facts,
            &head,
            "delegation:revoke:7001",
            &projection,
            "contrib-revoke",
        )
        .unwrap();
        match &draft.delta {
            GrantDelta::Revoke {
                grant_id,
                expected_revision,
            } => {
                assert_eq!(*grant_id, head.grant_id);
                assert_eq!(*expected_revision, GrantRevision::new(2).unwrap());
            }
            other => panic!("expected REVOKE delta, got {other:?}"),
        }
        let request = draft.delta_event_request(4, 5).unwrap();
        // 生命周期撤权 tombstone kind=REVOKE（与 REMOVE/DENY 不交叉）。
        assert_eq!(request.event_type, astral_db::DeltaEventType::Revoke);
        let before = request.before_image_json.expect("revoke before-image");
        assert_eq!(before, head.payload.canonical_input().unwrap());
        assert_eq!(draft.semantic_hash_hex, sha256_hex_of(&before));
    }

    /// 结构守卫：DELEGATION 的 parent CARD 投影事件号与每条贡献的独立事件号
    /// 分离 —— builder 必须把传入的 contribution event id 用于 provenance 与
    /// 账本事件维度，parent 只提供 generation/fence 绑定。
    #[test]
    fn delegation_parent_projection_event_is_distinct_from_contribution_event() {
        let facts = delegation_facts_test("learn_course", "read");
        let projection = projection(8, 0);
        let draft = build_delegation_add_draft(
            &facts,
            "op-parent-vs-contrib",
            10,
            &projection,
            "contribution-eid",
        )
        .unwrap();
        assert_eq!(draft.event_id(), "contribution-eid");
        let grant = match &draft.delta {
            GrantDelta::Add { grant } => grant,
            other => panic!("expected ADD delta, got {other:?}"),
        };
        assert_eq!(
            grant.provenance.event_id.as_deref(),
            Some("contribution-eid")
        );
        assert_ne!(projection.event_id, draft.event_id());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 收窄 UPDATE 的 stale-ALLOW 闭合（2026-09-04）：authorization-content gate
    // 精确单元测试。判定语义见 astral-db grant_ledger::
    // update_authorization_content_changed。
    // ─────────────────────────────────────────────────────────────────────────

    fn update_grant_content(delta: &GrantDelta) -> (&str, &str, &astral_types::ValidityWindow) {
        match delta {
            GrantDelta::Update { grant, .. } => (&grant.resource, &grant.action, &grant.validity),
            other => panic!("expected UPDATE delta, got {other:?}"),
        }
    }

    #[test]
    fn authorization_content_gate_flags_every_content_change_and_ignores_provenance() {
        let validity = |not_before: Option<i64>, expires_at: Option<i64>| ValidityWindow {
            not_before,
            expires_at,
        };
        let before = direct_add_draft(None);
        let payload = match &before.delta {
            GrantDelta::Add { grant } => grant.clone(),
            other => panic!("expected ADD delta, got {other:?}"),
        };
        // no-op：四元组逐项相等 → false（保持原事件语义，不打 PENDING）。
        assert!(!update_authorization_content_changed(
            &payload,
            &payload.resource,
            &payload.action,
            &payload.validity,
        ));
        // resource 移动（type:1 → type:2 同形）：旧对象授权被移除 → true。
        assert!(update_authorization_content_changed(
            &payload,
            "learn_quiz:*",
            &payload.action,
            &payload.validity,
        ));
        // action 变化 → true。
        assert!(update_authorization_content_changed(
            &payload,
            &payload.resource,
            "write",
            &payload.validity,
        ));
        // 有效期收窄/移动（上界提前）→ true。
        assert!(update_authorization_content_changed(
            &payload,
            &payload.resource,
            &payload.action,
            &validity(payload.validity.not_before, Some(1)),
        ));
        // 有效期下界移动 → true。
        assert!(update_authorization_content_changed(
            &payload,
            &payload.resource,
            &payload.action,
            &validity(Some(1), payload.validity.expires_at),
        ));
        // effect 维度说明：GrantEffect 是单变体 ALLOW-only 枚举，运行时无法构造
        // 非 ALLOW before-image；`before.effect != GrantEffect::Allow` 分支由
        // `direct_and_delegation_update_drafts_explicitly_pin_allow_effect` 的
        // 结构守卫覆盖（builder 恒产出 ALLOW，非 ALLOW head 即内容变化）。
    }

    /// 零漂移守卫：三条 UPDATE 链的 pre-check 判定必须与 builder 实际产出的
    /// UPDATE grant 内容一致 —— pre-check 为 false ⟺ builder 结果与
    /// before-image 的 authorization-content 逐项相等；pre-check 为 true ⟺
    /// builder 结果内容确实变化。gate 与落库分叉即收窄窗口重新打开。
    #[test]
    fn update_content_gates_agree_with_built_drafts_across_all_three_families() {
        // direct：no-op → false；resource_id 对象作用域变化 → true；有效期变化 → true。
        let direct_head = active_head_from(&direct_add_draft(None));
        for (facts, expected) in [
            (direct_facts(None), false),
            (
                DirectRuleLedgerFacts {
                    resource_id: Some(42),
                    ..direct_facts(None)
                },
                true,
            ),
            (direct_facts(Some(("2026-01-01", "2026-12-31"))), true),
            (
                DirectRuleLedgerFacts {
                    action: "write",
                    ..direct_facts(None)
                },
                true,
            ),
        ] {
            let gate = direct_update_authorization_content_changed(&facts, &direct_head).unwrap();
            assert_eq!(gate, expected, "direct gate drifted for {facts:?}");
            let draft = build_direct_update_draft(
                &facts,
                &direct_head,
                DIRECT_OPERATION,
                DIRECT_ACTOR,
                &projection(6, 0),
            )
            .unwrap();
            let (resource, action, validity) = update_grant_content(&draft.delta);
            assert_eq!(
                update_authorization_content_changed(
                    &direct_head.payload,
                    resource,
                    action,
                    validity,
                ),
                gate,
                "direct pre-check must equal the built-draft content diff"
            );
            assert_eq!(
                draft.invalidates_published_evidence, gate,
                "direct draft flag must equal the authorization-content gate"
            );
        }

        // provenance-only（operation/actor 不同、内容全等）→ false：两条草稿的
        // UPDATE 内容逐项相等，gate 均不命中。
        let left = build_direct_update_draft(
            &direct_facts(None),
            &direct_head,
            "op-left",
            1,
            &projection(6, 0),
        )
        .unwrap();
        let right = build_direct_update_draft(
            &direct_facts(None),
            &direct_head,
            "op-right",
            2,
            &projection(7, 0),
        )
        .unwrap();
        assert_ne!(left.operation_id, right.operation_id);
        let (left_resource, left_action, left_validity) = update_grant_content(&left.delta);
        let (right_resource, right_action, right_validity) = update_grant_content(&right.delta);
        assert_eq!(
            (left_resource, left_action, left_validity),
            (right_resource, right_action, right_validity),
            "provenance-only updates must not change the authorization content"
        );
        assert!(
            !direct_update_authorization_content_changed(&direct_facts(None), &direct_head)
                .unwrap()
        );

        // rule-set：no-op → false；resource/action/有效期变化 → true。
        let ruleset_add = build_ruleset_add_draft(
            &default_ruleset_facts(),
            RULESET_OP,
            None,
            &card_projection(3, 0),
            &"e".repeat(36),
        )
        .unwrap();
        let ruleset_head = ruleset_head_from_add(&ruleset_add);
        for (facts, expected) in [
            (default_ruleset_facts(), false),
            (
                ruleset_facts(
                    RULE_SET_ID,
                    RULE_ID,
                    REF_ID,
                    CARD_ID,
                    TENANT_ID,
                    "BASE",
                    "learn_quiz",
                    "read",
                    ("", ""),
                ),
                true,
            ),
            (
                ruleset_facts(
                    RULE_SET_ID,
                    RULE_ID,
                    REF_ID,
                    CARD_ID,
                    TENANT_ID,
                    "BASE",
                    "learn_course",
                    "write",
                    ("", ""),
                ),
                true,
            ),
            (
                ruleset_facts(
                    RULE_SET_ID,
                    RULE_ID,
                    REF_ID,
                    CARD_ID,
                    TENANT_ID,
                    "BASE",
                    "learn_course",
                    "read",
                    ("2026-01-01", "2026-12-31"),
                ),
                true,
            ),
        ] {
            let gate = ruleset_update_authorization_content_changed(&facts, &ruleset_head).unwrap();
            assert_eq!(gate, expected, "ruleset gate drifted for {facts:?}");
            let contribution = derive_ruleset_contribution_event_id(
                RULESET_OP,
                &facts,
                RuleSetMutationKind::Update,
            )
            .unwrap();
            let draft = build_ruleset_update_draft(
                &facts,
                &ruleset_head,
                RULESET_OP,
                None,
                &card_projection(4, 0),
                &contribution,
            )
            .unwrap();
            let (resource, action, validity) = update_grant_content(&draft.delta);
            assert_eq!(
                update_authorization_content_changed(
                    &ruleset_head.payload,
                    resource,
                    action,
                    validity
                ),
                gate,
                "ruleset pre-check must equal the built-draft content diff"
            );
            assert_eq!(
                draft.invalidates_published_evidence, gate,
                "ruleset draft flag must equal the authorization-content gate"
            );
        }

        // delegation：no-op → false；resource/action/上界变化 → true；provenance-only
        // （仅 operation/actor 不同）→ false。
        let delegation_old = delegation_facts_test("learn_course", "read");
        let delegation_head = delegation_head_for(&delegation_old, 3);
        for (facts, expected) in [
            (delegation_facts_test("learn_course", "read"), false),
            (delegation_facts_test("learn_quiz", "write"), true),
            (
                DelegationLedgerFacts {
                    expires_at_unix: DEL_EXPIRES - 1,
                    ..delegation_facts_test("learn_course", "read")
                },
                true,
            ),
        ] {
            let gate =
                delegation_update_authorization_content_changed(&facts, &delegation_head).unwrap();
            assert_eq!(gate, expected, "delegation gate drifted for {facts:?}");
            let draft = build_delegation_update_draft(
                &facts,
                &delegation_head,
                "delegation:update:7001",
                11,
                &projection(6, 0),
                "contrib-gate-agree",
            )
            .unwrap();
            let (resource, action, validity) = update_grant_content(&draft.delta);
            assert_eq!(
                update_authorization_content_changed(
                    &delegation_head.payload,
                    resource,
                    action,
                    validity
                ),
                gate,
                "delegation pre-check must equal the built-draft content diff"
            );
            assert_eq!(
                draft.invalidates_published_evidence, gate,
                "delegation draft flag must equal the authorization-content gate"
            );
        }
    }

    /// ADD 不受影响：三条链的 ADD 草稿事件类型恒为 `ADD`（非 REMOVE/REVOKE），
    /// 且不携带任何 fence 抬升输入 —— ADD 未发布 delta 不命中 freshness 门
    /// （缺新授权只是 deny-biased EC 的 ms 级漏授权窗口）。
    #[test]
    fn add_drafts_keep_add_event_types_and_never_trip_the_revoke_gate() {
        let direct = direct_add_draft(None).delta_event_request(0, 1).unwrap();
        assert_eq!(direct.event_type, astral_db::DeltaEventType::Add);
        assert!(!direct.invalidates_published_evidence);

        let ruleset_facts = default_ruleset_facts();
        let ruleset = build_ruleset_add_draft(
            &ruleset_facts,
            RULESET_OP,
            None,
            &card_projection(3, 0),
            &"e".repeat(36),
        )
        .unwrap()
        .delta_event_request(0, 1)
        .unwrap();
        assert_eq!(ruleset.event_type, astral_db::DeltaEventType::Add);
        assert!(!ruleset.invalidates_published_evidence);

        let delegation = build_delegation_add_draft(
            &delegation_facts_test("learn_course", "read"),
            "op-add-unaffected",
            10,
            &projection(3, 0),
            "contrib-add-unaffected",
        )
        .unwrap()
        .delta_event_request(0, 1)
        .unwrap();
        assert_eq!(delegation.event_type, astral_db::DeltaEventType::Add);
        assert!(!delegation.invalidates_published_evidence);
    }
}
