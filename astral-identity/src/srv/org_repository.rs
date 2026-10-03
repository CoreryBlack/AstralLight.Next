//! 组织/域/租户数据访问 — OrgRepository
//!
//! 对齐 Java `TenantMapper` / `PlatformDomainMapper` 边界。
//! `tenant`（tenant_type='ENTERPRISE' 承载组织）、`platform_domain`、
//! `tenant_domain_map` 的 CRUD 集中在 repository。
//!
//! 有效资格变更的 durable 语义（与 trustgraph 源事务同契约）：
//! - tenant/org 状态变化与删除前的资格捕获，在**同一短事务**内成对落
//!   ELIGIBILITY 投影事件 + `ELIGIBILITY_INVALIDATED` typed invalidation
//!   intent（`al_message_outbox`），receipt 事务内先注册；扇出上限 512
//!   （与 trustgraph 对等），超限在任何 mutation 之前拒绝；
//! - 只有被证明成功的 commit 才按序直投 LocalBus（整批共享一个 5s 总预算，
//!   预算耗尽后剩余 receipts 保持 durable pending，失败仅记录，unknown 绝不
//!   重放）；
//! - source 事务 begin 前取得 generic hub 写者栅栏并持有到 commit+dispatch，
//!   commit 未知 → `mark_uncertain`（`uncertain_source` 挡住在线对账清除，
//!   仅独立 durable 对账可解），pre-commit 错误（已知回滚）只释放；
//! - 每张受影响卡在提交前进程内 evict 正向 L1 资格缓存并推进 per-card 纪元
//!   （`evict_l1_card_active_cache`）；evict 单调，commit 未知绝不恢复旧条目。

use std::time::{Duration, Instant};

use async_trait::async_trait;
use sqlx::{MySql, MySqlPool, Transaction};

use astral_db::grant_ledger::validated_request_operation_id;
use astral_db::memory_projection_hub::SourceTransactionGuard;
use astral_db::{
    append_in_tx, append_projection_event_with_metadata_and_tenant_in_tx,
    evict_l1_card_active_cache, LocalMessageInput,
};
use astral_mq::config::{QUEUE_AUTHORIZATION_INVALIDATION, ROUTING_KEY_AUTHORIZATION_INVALIDATION};
use astral_mq::invalidation::{
    EligibilityInvalidated, InvalidationEvent, ELIGIBILITY_INVALIDATED, INVALIDATION_QUEUE,
};
use astral_mq::{local_bus, MessageEnvelope};
use astral_types::{AstralError, ProjectionAggregate, EVENT_TYPE_ELIGIBILITY_UPDATE};

/// Gateway-verified identity and scope captured for one Identity org mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrgMutationContext {
    actor_id: i64,
    actor_card_id: i64,
    actor_tenant_id: i64,
    actor_domain_id: i64,
    request_id: String,
}

impl OrgMutationContext {
    pub(crate) fn new(
        actor_id: i64,
        actor_card_id: i64,
        actor_tenant_id: i64,
        actor_domain_id: i64,
        request_id: Option<&str>,
    ) -> Result<Self, AstralError> {
        if actor_id <= 0 || actor_card_id <= 0 || actor_tenant_id <= 0 || actor_domain_id <= 0 {
            return Err(AstralError::Auth(
                "org mutation requires positive Gateway-verified user-card context".into(),
            ));
        }
        let request_id = validated_request_operation_id(request_id)?.ok_or_else(|| {
            AstralError::Auth("org mutation requires a canonical request id".into())
        })?;
        Ok(Self {
            actor_id,
            actor_card_id,
            actor_tenant_id,
            actor_domain_id,
            request_id,
        })
    }

    fn audit_request_id(&self) -> Result<String, AstralError> {
        validated_request_operation_id(Some(&self.request_id))?.ok_or_else(|| {
            AstralError::Validation("org mutation audit requires a stable request id".into())
        })
    }
}

fn unsafe_org_mutation_context() -> AstralError {
    AstralError::Auth(
        "org/domain/tenant mutation requires Gateway-verified user-card context".into(),
    )
}

type OrgActorCardRow = (Option<i64>, Option<i64>, Option<i64>, String);

async fn verify_org_mutation_actor_in_tx(
    tx: &mut Transaction<'_, MySql>,
    context: &OrgMutationContext,
) -> Result<(), AstralError> {
    let actor: Option<OrgActorCardRow> = sqlx::query_as(ORG_MUTATION_ACTOR_LOCK_SQL)
        .bind(context.actor_card_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_error)?;
    match actor {
        Some((Some(user_id), Some(tenant_id), Some(domain_id), status))
            if user_id == context.actor_id
                && tenant_id == context.actor_tenant_id
                && domain_id == context.actor_domain_id
                && status == "ACTIVE" =>
        {
            Ok(())
        }
        _ => Err(AstralError::Auth(
            "Gateway org mutation card context no longer matches an active user_card".into(),
        )),
    }
}

async fn insert_org_mutation_audit_in_tx(
    tx: &mut Transaction<'_, MySql>,
    context: &OrgMutationContext,
    action: &str,
    resource: &str,
    target_id: i64,
    operation_id: &str,
    detail: serde_json::Value,
) -> Result<String, AstralError> {
    if context.actor_id <= 0
        || context.actor_card_id <= 0
        || context.actor_tenant_id <= 0
        || context.actor_domain_id <= 0
        || target_id <= 0
        || action.is_empty()
        || resource.is_empty()
    {
        return Err(AstralError::Validation(
            "org mutation audit requires positive actor scope and target".into(),
        ));
    }
    if operation_id.trim().is_empty() || operation_id.trim() != operation_id {
        return Err(AstralError::Validation(
            "org mutation audit requires a canonical operation id".into(),
        ));
    }
    let operation_id = operation_id.to_owned();
    let request_id = context.audit_request_id()?;
    let detail = serde_json::to_string(&serde_json::json!({
        "actorId": context.actor_id,
        "actorCardId": context.actor_card_id,
        "actorTenantId": context.actor_tenant_id,
        "actorDomainId": context.actor_domain_id,
        "targetType": resource,
        "targetId": target_id,
        "action": action,
        "operationId": operation_id,
        "mutation": detail,
    }))
    .map_err(|error| {
        AstralError::Validation(format!(
            "org mutation audit detail serialization failed: {error}"
        ))
    })?;
    sqlx::query(ORG_MUTATION_AUDIT_INSERT_SQL)
        .bind(context.actor_id)
        .bind(context.actor_card_id)
        .bind(action)
        .bind(resource)
        .bind(request_id)
        .bind(context.actor_domain_id)
        .bind(context.actor_tenant_id)
        .bind(detail)
        .execute(&mut **tx)
        .await
        .map_err(|error| {
            AstralError::Database(format!("org mutation audit insert failed: {error}"))
        })?;
    Ok(operation_id)
}

async fn commit_org_mutation_tx(
    tx: Transaction<'_, MySql>,
    source_guard: &Option<SourceTransactionGuard>,
) -> Result<(), AstralError> {
    arm_org_commit_fence(source_guard);
    let commit_result = tx.commit().await;
    settle_org_commit_fence_on_proven(source_guard, &commit_result);
    match commit_result {
        Ok(()) => Ok(()),
        Err(error) => {
            close_memory_authority_on_unknown_commit(source_guard, &error.to_string());
            Err(db_error(error))
        }
    }
}

/// 组织行（tenant_type='ENTERPRISE' 的租户）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OrganizationRecord {
    pub id: i64,
    pub name: String,
    pub code: String,
    pub status: String,
    pub created_at: Option<String>,
}

/// 域行（platform_domain）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DomainRecord {
    pub id: i64,
    pub name: String,
    pub code: Option<String>,
    pub status: String,
    pub created_at: Option<String>,
}

/// 租户行（tenant）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantRecord {
    pub id: i64,
    pub name: String,
    pub code: String,
    pub status: String,
    pub created_at: Option<String>,
}

const ORG_ROW_SQL: &str =
    "SELECT tenant_id as id, tenant_name as name, tenant_code as code, status, \
     DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at \
     FROM tenant WHERE tenant_type = 'ENTERPRISE'";
const DOMAIN_ROW_SQL: &str =
    "SELECT domain_id as id, domain_name as name, domain_code as code, status, \
     DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at \
     FROM platform_domain";
const TENANT_ROW_SQL: &str =
    "SELECT tenant_id as id, tenant_name as name, tenant_code as code, status, \
     DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at \
     FROM tenant";
const ORG_MUTATION_ACTOR_LOCK_SQL: &str =
    "SELECT user_id, tenant_id, domain_id, card_status FROM user_card WHERE card_id = ? FOR UPDATE";
const ORG_MUTATION_AUDIT_INSERT_SQL: &str = "INSERT INTO audit_log (user_id, card_id, action, resource, decision, reason, event_type, request_id, domain_id, tenant_id, detail) VALUES (?, ?, ?, ?, 'SUCCESS', NULL, 'IDENTITY_ORG_MUTATION', ?, ?, ?, ?)";
/// Domain deletion would cascade this relation, which is part of live card eligibility.
/// Lock even inactive rows and reject the destructive operation rather than silently
/// dropping the mapping or trying to fan out beyond the bounded tenant-child contract.
const DOMAIN_MAPPING_REFERENCE_LOCK_SQL: &str = "SELECT tenant_id FROM tenant_domain_map WHERE domain_id = ? ORDER BY tenant_id LIMIT 1 FOR UPDATE";
const DOMAIN_USER_CARD_REFERENCE_LOCK_SQL: &str =
    "SELECT card_id FROM user_card WHERE domain_id = ? ORDER BY card_id LIMIT 1 FOR UPDATE";
const TENANT_STATUS_LOCK_SQL: &str = "SELECT status FROM tenant WHERE tenant_id = ? FOR UPDATE";
const TENANT_ID_LOCK_SQL: &str = "SELECT tenant_id FROM tenant WHERE tenant_id = ? FOR UPDATE";
const ENTERPRISE_STATUS_LOCK_SQL: &str =
    "SELECT status FROM tenant WHERE tenant_id = ? AND tenant_type = 'ENTERPRISE' FOR UPDATE";
const ENTERPRISE_ID_LOCK_SQL: &str =
    "SELECT tenant_id FROM tenant WHERE tenant_id = ? AND tenant_type = 'ENTERPRISE' FOR UPDATE";
/// `delete_tenant`/`delete_org` 共用的 user_card 引用守卫：`user_card.tenant_id`
/// 无外键约束（运行时 schema 契约见 `astral-db::migration`，既有索引不含
/// `tenant_id`），不限 card_status（含 DISABLED 等非 ACTIVE 卡），任何引用行都
/// 在事务内 `FOR UPDATE` 锁定并 fail-closed 拒绝删除。
///
/// 并发语义（仓库默认 MySQL 8.0，服务端默认 `REPEATABLE-READ`；仓库代码不设
/// 隔离级别覆盖）：`tenant_id` 无可用索引 → 守卫为聚簇索引全扫描。RR 下
/// next-key 锁覆盖全部已扫记录与间隙（含末尾 supremum 间隙），事务存续期间
/// 并发 INSERT `user_card` 会被 insert-intention 冲突阻塞（MySQL 8.0 手册
/// 17.7.1/17.7.2.1/17.7.3）。命中引用时扫描提前停止（`LIMIT 1`），但该路径
/// 本就拒绝删除，锁覆盖不影响裁决。若隔离级别被显式降为 READ-COMMITTED，
/// 搜索/扫描的 gap 锁被禁用，零命中路径不再阻塞并发插入（见残余风险）。
const TENANT_CARD_REFERENCE_LOCK_SQL: &str =
    "SELECT card_id FROM user_card WHERE tenant_id = ? ORDER BY card_id LIMIT 1 FOR UPDATE";

// ===== ELIGIBILITY typed invalidation intent + commit receipt（同事务成对） ====
//
// 与 trustgraph `authorization_source_transaction` 的 ELIGIBILITY 接线同契约：
// - 同一短事务内，每张 ACTIVE 卡各落一对 durable 事实：ELIGIBILITY 投影事件
//   （head + `authorization_projection_outbox`）与 `ELIGIBILITY_INVALIDATED`
//   typed intent（`al_message_outbox`，messageId = 投影事件 id，唯一性由它
//   承担，绝不复用随机身份）；receipt 在事务内先注册、后提交；
// - 只有被证明成功的 commit 才投递：有界单次 LocalBus publish，失败仅记录，
//   durable 行保持 relay 恢复路径（默认单机无 polling，恢复腿不在本文件）；
// - commit 未知/失败一律不发送，并把 memory projection hub 置 sticky suspect
//   （既有 guard 接口，只有显式对账可清除），未证明的内存快照不得继续回答。

/// commit 后待投递的 typed invalidation receipt。
#[derive(Debug, Clone)]
struct InvalidationReceipt {
    event_id: String,
    operation_id: String,
    envelope: MessageEnvelope,
}

/// 生产投递总预算（与 trustgraph invalidation dispatcher 同值 5s）：**整批
/// receipts 共享一个 5s 总预算**，绝不逐卡 5s 无界放大；预算耗尽后剩余
/// receipts 停止直投，durable outbox 行保持 PENDING 作为 relay 恢复路径。
const INVALIDATION_DISPATCH_BUDGET: Duration = Duration::from_secs(5);

/// ELIGIBILITY 扇出上限（与 trustgraph 对等的 512）：选择器 SQL 取 cap+1 行，
/// 超限在任何 mutation 之前 fail-closed 拒绝；receipts 上限与之对等。
const ELIGIBILITY_FANOUT_CAP: usize = 512;

const MAX_ORIGIN_REGION_CHARS: usize = 64;

/// org 四条 source 事务（update_tenant/update_org/delete_tenant/delete_org）
/// 的 generic hub 写者栅栏：begin 前取得、持有到 commit+dispatch；commit
/// 未知先 `mark_uncertain`（`uncertain_source` 挡住在线 reconcile），pre-commit
/// 错误（已知回滚）只随 Drop 释放。hub 已装则栅栏必须可得——不可静默 no-op。
fn begin_org_source_writer_guard() -> Result<Option<SourceTransactionGuard>, AstralError> {
    match astral_db::memory_projection_hub() {
        None => Ok(None),
        Some(hub) => hub.begin_source_transaction().map(Some).ok_or_else(|| {
            AstralError::Internal(
                "memory projection hub is installed but the source writer guard is \
                     unavailable"
                    .to_owned(),
            )
        }),
    }
}

/// 实际写事务的 commit await 前武装取消栅栏：guard 私有 `commit_unproven=true`。
/// await 窗口内任务被取消/连接掉线时 Drop 见 atomic=true → sticky uncertain
/// ——覆盖"结果后标记"无法覆盖的取消窗口。hub 未装（None）为 no-op。
fn arm_org_commit_fence(source_guard: &Option<SourceTransactionGuard>) {
    if let Some(guard) = source_guard {
        guard.mark_commit_started();
    }
}

/// 已判定的 commit 结果收尾：Ok → `mark_commit_proven` 清私有 atomic（Drop
/// 正常释放）。Err 不在此清——close_memory_authority_on_unknown_commit 显式
/// `mark_uncertain`（uncertain_source sticky），Drop 的 atomic 分支同向幂等。
fn settle_org_commit_fence_on_proven(
    source_guard: &Option<SourceTransactionGuard>,
    commit_result: &Result<(), sqlx::Error>,
) {
    if commit_result.is_ok() {
        if let Some(guard) = source_guard {
            guard.mark_commit_proven();
        }
    }
}

/// 校验 origin region（纯函数）：trim 后非空且 ≤64 字符（对齐 AppConfig
/// `validate_region_id` 与冻结消息规范的 region 边界）。canonical 单例只查
/// 非空，64 上界由本调用方在委托前补齐。
fn validated_origin_region(region: &str) -> Result<String, String> {
    let region = region.trim();
    if region.is_empty() || region.chars().count() > MAX_ORIGIN_REGION_CHARS {
        return Err("origin region must be non-empty and at most 64 characters".to_owned());
    }
    Ok(region.to_owned())
}

/// 启动期安装进程级 origin region（identity runtime 在配置校验后、路由/worker
/// 装配前调用）。**委托 canonical `astral_mq::invalidation::ORIGIN_REGION`
/// 单例**——本文件不保留第二个静态源，Identity 本地 durable intent 与
/// astral-mq 内部（revocation shard append）及 trustgraph 全部共享同一进程
/// 身份：首值生效、同值幂等、异值 fail-closed。
pub fn install_origin_region(region: impl Into<String>) -> Result<(), AstralError> {
    let region = validated_origin_region(&region.into()).map_err(AstralError::Config)?;
    astral_mq::invalidation::install_origin_region(region).map_err(AstralError::Config)
}

/// 进程级 origin region（只读，委托 canonical 单例）：未安装即拒绝 durable
/// append（fail-closed，不猜测、不回退 env 默认——安装由 identity runtime
/// 启动装配负责）。
fn origin_region() -> Result<String, AstralError> {
    astral_mq::invalidation::origin_region().map_err(|error| AstralError::Config(error.to_string()))
}

/// 选择器语义与 astral-db `append_eligibility_events_for_cards_in_tx` 的
/// `ByTenantId` 选择器一致：ACTIVE 卡、`card_id` 升序、事务内 `FOR UPDATE`、
/// 同条查询捕获 tenant（无逐卡二次 source 读）；`LIMIT ?` 绑定 cap+1，超限
/// 在任何 mutation 之前拒绝。
const ELIGIBILITY_CARDS_BY_TENANT_SQL: &str = "SELECT card_id, tenant_id FROM user_card WHERE tenant_id = ? AND card_status = 'ACTIVE' ORDER BY card_id LIMIT ? FOR UPDATE";
const ELIGIBILITY_CARDS_BY_DOMAIN_SQL: &str = "SELECT card_id, tenant_id FROM user_card WHERE domain_id = ? AND card_status = 'ACTIVE' ORDER BY card_id LIMIT ? FOR UPDATE";

/// 事务内 ELIGIBILITY 扇出扫描（仅锁读，零 mutation）：取 cap+1 窗口，超过
/// cap 即拒绝——调用方在任何写入之前拿到裁决，绝不落半途 mutation。
async fn scan_tenant_eligibility_cards_in_tx(
    tx: &mut Transaction<'_, MySql>,
    tenant_id: i64,
) -> Result<Vec<(i64, Option<i64>)>, AstralError> {
    if tenant_id <= 0 {
        return Err(AstralError::Validation(format!(
            "tenant eligibility fanout requires a positive tenant id, got {tenant_id}"
        )));
    }
    let window = i64::try_from(ELIGIBILITY_FANOUT_CAP + 1)
        .map_err(|_| AstralError::Internal("eligibility fanout cap overflow".into()))?;
    let cards: Vec<(i64, Option<i64>)> = sqlx::query_as(ELIGIBILITY_CARDS_BY_TENANT_SQL)
        .bind(tenant_id)
        .bind(window)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)?;
    if cards.len() > ELIGIBILITY_FANOUT_CAP {
        return Err(AstralError::Validation(format!(
            "tenant {tenant_id} has more than {ELIGIBILITY_FANOUT_CAP} ACTIVE cards; \
             refusing the mutation before any write (eligibility fanout cap)"
        )));
    }
    Ok(cards)
}

/// 纯判定：receipts 数量是否仍在扇出上限内（与扫描 cap 对等；防御第二道）。
fn eligibility_receipts_cap_ok(receipts_len: usize) -> bool {
    receipts_len < ELIGIBILITY_FANOUT_CAP
}

/// 纯组装 ELIGIBILITY typed invalidation envelope（无 IO，可单测）。
///
/// `projection_event_id` 是同一事务内刚落库的 ELIGIBILITY 投影事件 id：它同时
/// 充当 intent 的稳定 messageId（outbox 唯一性由它承担，同一事务内每个资格
/// 事件各自对应一条 intent）。`operation_id` 是源 mutation 的稳定操作身份。
fn eligibility_invalidation_envelope(
    card_id: i64,
    operation_id: &str,
    projection_event_id: &str,
    region: &str,
) -> Result<MessageEnvelope, AstralError> {
    if card_id <= 0 {
        return Err(AstralError::Validation(format!(
            "eligibility invalidation requires a positive card id, got {card_id}"
        )));
    }
    if operation_id.trim().is_empty() || projection_event_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "eligibility invalidation requires stable source operation and projection event ids"
                .into(),
        ));
    }
    let event = InvalidationEvent::EligibilityInvalidated(EligibilityInvalidated { card_id });
    event
        .to_envelope(projection_event_id, operation_id, region)
        .map_err(|error| AstralError::Validation(error.to_string()))
}

/// 稳定 source operation id（纯函数）：org 路径没有独立 durable 代次，以锁定
/// 的租户身份 + 状态迁移语义确定性派生。同一 mutation 语义共享同一 operation
/// id（相关性）；intent 唯一性由 messageId（投影事件 id）承担，语义相同的新
/// 一次迁移会生成新事件 id，因此 A→B→A→B 的第三次迁移绝不会被前一次去重。
fn tenant_status_operation_id(tenant_id: i64, from: &str, to: &str) -> String {
    format!("org:tenant-status:{tenant_id}:{from}->{to}")
}

/// 删除路径的稳定 source operation id（纯函数）。
fn tenant_delete_operation_id(tenant_id: i64) -> String {
    format!("org:tenant-delete:{tenant_id}")
}

/// 同事务 ELIGIBILITY 事件 + typed invalidation intent 成对落库（不 commit）。
///
/// `cards` 必须来自 [`scan_tenant_eligibility_cards_in_tx`]（cap 内、事务内
/// `FOR UPDATE` 锁定）。每张卡：提交前进程内 evict 正向 L1 资格缓存并推进
/// per-card 纪元（单调失效，commit 未知绝不恢复旧条目）→ 一条投影事件
/// （durable 事实，tenant 走 Captured 语义）→ 一条 intent（durable 通知，
/// 同一 envelope 实例落 outbox + receipt）。receipts 上限与扫描 cap 对等。
/// 任一步失败 Validation/Database fail-closed，整个 source 事务回滚（含已
/// append 的 mutation 与事件对；evict 单调，回滚只是保守多失效一次）。
async fn append_tenant_eligibility_with_invalidation_in_tx(
    tx: &mut Transaction<'_, MySql>,
    tenant_id: i64,
    operation_id: &str,
    cards: Vec<(i64, Option<i64>)>,
    receipts: &mut Vec<InvalidationReceipt>,
) -> Result<(), AstralError> {
    if tenant_id <= 0 {
        return Err(AstralError::Validation(format!(
            "tenant eligibility fanout requires a positive tenant id, got {tenant_id}"
        )));
    }
    if operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "tenant eligibility fanout requires a stable source operation id".into(),
        ));
    }
    let region = origin_region()?;
    for (card_id, card_tenant_id) in cards {
        if !eligibility_receipts_cap_ok(receipts.len()) {
            return Err(AstralError::Validation(format!(
                "tenant {tenant_id} eligibility receipts exceeded the fanout cap \
                 {ELIGIBILITY_FANOUT_CAP}; refusing before any further write"
            )));
        }
        // 0) 提交前进程内失效：正向 L1 卡缓存 + ELIGIBILITY head 条目移除、
        //    per-card 纪元推进（单调；回滚/未知只多失效，绝不恢复旧条目）。
        evict_l1_card_active_cache(card_id);
        // 1) ELIGIBILITY 投影事件（head + authorization_projection_outbox），
        //    取回 durable 事件身份（tenant 走 Captured 语义，与公共批量 helper
        //    对 `ByTenantId` 的行为一致）。
        let identity = append_projection_event_with_metadata_and_tenant_in_tx(
            tx,
            ProjectionAggregate::Eligibility,
            card_id,
            EVENT_TYPE_ELIGIBILITY_UPDATE,
            None,
            card_tenant_id,
        )
        .await?;
        // 2) typed invalidation intent：同一 envelope 实例落 outbox + receipt。
        let envelope =
            eligibility_invalidation_envelope(card_id, operation_id, &identity.event_id, &region)?;
        let payload_json = envelope.envelope_json().map_err(AstralError::Internal)?;
        let input = LocalMessageInput {
            message_id: &envelope.message_id,
            operation_id: &envelope.operation_id,
            message_type: ELIGIBILITY_INVALIDATED,
            queue_name: INVALIDATION_QUEUE,
            ordering_key: envelope.ordering_key.as_deref(),
            tenant_id: envelope.tenant_id,
            origin_region: &envelope.origin_region,
            target_region: envelope.target_region.as_deref(),
            schema_version: envelope.schema_version,
            payload_json: &payload_json,
            headers_json: None,
            payload_sha256: &envelope.payload_sha256,
        };
        append_in_tx(tx, &input)
            .await
            .map_err(|error| AstralError::Database(error.to_string()))?;
        receipts.push(InvalidationReceipt {
            event_id: envelope.message_id.clone(),
            operation_id: envelope.operation_id.clone(),
            envelope,
        });
    }
    Ok(())
}

/// 只投递被证明成功的 commit 的 receipts；commit 未知/失败一律返回空集——
/// "源提交未知绝不发送" 的唯一决策点（与 trustgraph 同语义）。
fn receipts_for_proven_commit(
    receipts: &mut Vec<InvalidationReceipt>,
    commit_result: &Result<(), sqlx::Error>,
) -> Vec<InvalidationReceipt> {
    match commit_result {
        Ok(()) => std::mem::take(receipts),
        Err(_) => Vec::new(),
    }
}

/// 单次有界 LocalBus 投递（deadline 参数化便于测试；生产走 deadline 常量）。
async fn dispatch_invalidation_receipt_with_deadline(
    bus: &local_bus::LocalBus,
    receipt: InvalidationReceipt,
    deadline: Duration,
) -> Result<(), String> {
    bus.publish_and_wait(
        QUEUE_AUTHORIZATION_INVALIDATION,
        ROUTING_KEY_AUTHORIZATION_INVALIDATION,
        receipt.envelope,
        deadline,
    )
    .await
    .map_err(|error| error.to_string())
}

/// 整批共享一个 5s 总预算的逐条投递：预算耗尽后剩余 receipts 停止直投并记录，
/// durable outbox 行（事务内已 append）保持 PENDING 作为 relay 恢复路径。
/// 单次有界尝试：任何失败（无 in-process LocalBus / admission 拒绝 / handler
/// 报错 / 剩余预算到期）只记录日志，不向上传播，不重试 —— 绝不伪装源回滚，
/// 绝不 replay source（unknown 不重放）。
async fn dispatch_proven_invalidation_receipts(receipts: Vec<InvalidationReceipt>) {
    let Some(bus) = local_bus::global_local_bus() else {
        tracing::debug!(
            receipts = receipts.len(),
            "no in-process LocalBus installed; tenant eligibility invalidations stay on the \
             durable outbox relay"
        );
        return;
    };
    let started = Instant::now();
    for receipt in receipts {
        let remaining = dispatch_budget_remaining(started.elapsed());
        if remaining.is_zero() {
            tracing::warn!(
                event_id = %receipt.event_id,
                "invalidation dispatch budget exhausted; remaining receipts stay durable \
                 pending on the outbox relay (no rollback, no replay)"
            );
            break;
        }
        let event_id = receipt.event_id.clone();
        let operation_id = receipt.operation_id.clone();
        match dispatch_invalidation_receipt_with_deadline(&bus, receipt, remaining).await {
            Ok(()) => tracing::debug!(
                event_id = %event_id,
                operation_id = %operation_id,
                "tenant eligibility invalidation receipt dispatched on the local bus"
            ),
            Err(reason) => tracing::warn!(
                event_id = %event_id,
                operation_id = %operation_id,
                reason = %reason,
                "tenant eligibility invalidation dispatch failed after a proven commit; \
                 keeping the durable outbox row as the recovery path (no rollback, no replay)"
            ),
        }
    }
}

/// 纯函数：给定整批已耗时长，单条投递可用的剩余预算（可为 0 = 停止直投）。
fn dispatch_budget_remaining(elapsed: Duration) -> Duration {
    INVALIDATION_DISPATCH_BUDGET.saturating_sub(elapsed)
}

/// commit 未知/失败时的 fail-closed：先 `guard.mark_uncertain()`——
/// `uncertain_source` 挡住在线 reconcile 清除（源提交结果未独立对账前，任何
/// 对账不得丢弃/覆盖本批 intent），再对进程内内存权威读面置 sticky suspect，
/// 未证明的内存快照不得继续参与判定。
fn close_memory_authority_on_unknown_commit(
    source_guard: &Option<SourceTransactionGuard>,
    reason: &str,
) {
    if let Some(guard) = source_guard {
        guard.mark_uncertain();
    }
    if let Some(hub) = astral_db::memory_projection_hub() {
        hub.mark_channel_suspect(format!(
            "identity org source commit unknown; in-memory authority closed until durable \
             reconciliation: {reason}"
        ));
    }
}

#[async_trait]
pub trait OrgRepository: Send + Sync {
    async fn list_orgs(&self) -> Result<Vec<OrganizationRecord>, AstralError>;
    /// Compatibility API retained for non-HTTP callers; production adapters fail closed.
    async fn create_org(&self, _name: &str, _status: &str) -> Result<i64, AstralError> {
        Err(unsafe_org_mutation_context())
    }
    async fn create_org_with_context(
        &self,
        name: &str,
        status: &str,
        context: &OrgMutationContext,
    ) -> Result<i64, AstralError> {
        let _ = (name, status, context);
        Err(unsafe_org_mutation_context())
    }
    async fn get_org(&self, id: i64) -> Result<Option<OrganizationRecord>, AstralError>;
    async fn update_org(
        &self,
        id: i64,
        name: &str,
        code: &str,
        status: &str,
    ) -> Result<(), AstralError> {
        let _ = (id, name, code, status);
        Err(unsafe_org_mutation_context())
    }
    async fn update_org_with_context(
        &self,
        id: i64,
        name: &str,
        code: &str,
        status: &str,
        context: &OrgMutationContext,
    ) -> Result<(), AstralError> {
        let _ = (id, name, code, status, context);
        Err(unsafe_org_mutation_context())
    }
    /// 删除企业组织（tenant_type='ENTERPRISE' 租户行）；任何 `user_card` 仍
    /// 引用该租户时 fail-closed 拒绝（与 `delete_tenant` 同一守卫，不级联吊销）。
    async fn delete_org(&self, id: i64) -> Result<(), AstralError> {
        let _ = id;
        Err(unsafe_org_mutation_context())
    }
    async fn delete_org_with_context(
        &self,
        id: i64,
        context: &OrgMutationContext,
    ) -> Result<(), AstralError>;

    async fn list_org_domains(&self, org_id: i64) -> Result<Vec<DomainRecord>, AstralError>;

    async fn list_all_domains(&self) -> Result<Vec<DomainRecord>, AstralError>;
    async fn create_domain(
        &self,
        name: &str,
        code: Option<&str>,
        status: &str,
    ) -> Result<i64, AstralError> {
        let _ = (name, code, status);
        Err(unsafe_org_mutation_context())
    }
    async fn create_domain_with_context(
        &self,
        name: &str,
        code: Option<&str>,
        status: &str,
        context: &OrgMutationContext,
    ) -> Result<i64, AstralError>;
    async fn get_domain(&self, id: i64) -> Result<Option<DomainRecord>, AstralError>;
    async fn update_domain(
        &self,
        id: i64,
        name: &str,
        code: Option<&str>,
        status: &str,
    ) -> Result<(), AstralError> {
        let _ = (id, name, code, status);
        Err(unsafe_org_mutation_context())
    }
    async fn update_domain_with_context(
        &self,
        id: i64,
        name: &str,
        code: Option<&str>,
        status: &str,
        context: &OrgMutationContext,
    ) -> Result<(), AstralError> {
        let _ = (id, name, code, status, context);
        Err(unsafe_org_mutation_context())
    }
    async fn delete_domain(&self, id: i64) -> Result<(), AstralError> {
        let _ = id;
        Err(unsafe_org_mutation_context())
    }
    async fn delete_domain_with_context(
        &self,
        id: i64,
        context: &OrgMutationContext,
    ) -> Result<(), AstralError> {
        let _ = (id, context);
        Err(unsafe_org_mutation_context())
    }

    async fn list_domain_tenants(&self, domain_id: i64) -> Result<Vec<TenantRecord>, AstralError>;

    async fn list_all_tenants(&self) -> Result<Vec<TenantRecord>, AstralError>;
    async fn create_tenant(&self, name: &str, status: &str) -> Result<i64, AstralError> {
        let _ = (name, status);
        Err(unsafe_org_mutation_context())
    }
    async fn create_tenant_with_context(
        &self,
        name: &str,
        status: &str,
        context: &OrgMutationContext,
    ) -> Result<i64, AstralError> {
        let _ = (name, status, context);
        Err(unsafe_org_mutation_context())
    }
    async fn get_tenant(&self, id: i64) -> Result<Option<TenantRecord>, AstralError>;
    async fn update_tenant(
        &self,
        id: i64,
        name: &str,
        code: &str,
        status: &str,
    ) -> Result<(), AstralError> {
        let _ = (id, name, code, status);
        Err(unsafe_org_mutation_context())
    }
    async fn update_tenant_with_context(
        &self,
        id: i64,
        name: &str,
        code: &str,
        status: &str,
        context: &OrgMutationContext,
    ) -> Result<(), AstralError> {
        let _ = (id, name, code, status, context);
        Err(unsafe_org_mutation_context())
    }
    /// 删除租户；任何 `user_card` 仍引用该租户时 fail-closed 拒绝（不级联吊销）。
    async fn delete_tenant(&self, id: i64) -> Result<(), AstralError> {
        let _ = id;
        Err(unsafe_org_mutation_context())
    }
    async fn delete_tenant_with_context(
        &self,
        id: i64,
        context: &OrgMutationContext,
    ) -> Result<(), AstralError> {
        let _ = (id, context);
        Err(unsafe_org_mutation_context())
    }
}

pub struct SqlxOrgRepository {
    db: MySqlPool,
}

impl SqlxOrgRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl OrgRepository for SqlxOrgRepository {
    async fn list_orgs(&self) -> Result<Vec<OrganizationRecord>, AstralError> {
        sqlx::query_as::<_, OrganizationRecord>(&format!("{ORG_ROW_SQL} ORDER BY tenant_id"))
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn create_org(&self, _name: &str, _status: &str) -> Result<i64, AstralError> {
        Err(unsafe_org_mutation_context())
    }

    async fn create_org_with_context(
        &self,
        name: &str,
        status: &str,
        context: &OrgMutationContext,
    ) -> Result<i64, AstralError> {
        let source_guard = begin_org_source_writer_guard()?;
        let mut tx = self.db.begin().await.map_err(db_error)?;
        verify_org_mutation_actor_in_tx(&mut tx, context).await?;
        let result = sqlx::query(
            "INSERT INTO tenant (tenant_code, tenant_name, tenant_type, status) \
             VALUES (CONCAT('T', UNIX_TIMESTAMP()), ?, 'ENTERPRISE', ?)",
        )
        .bind(name)
        .bind(status)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let id = i64::try_from(result.last_insert_id())
            .map_err(|_| AstralError::Database("created org id exceeds i64".into()))?;
        let audit_operation_id = context.request_id.clone();
        insert_org_mutation_audit_in_tx(
            &mut tx,
            context,
            "create",
            "organization",
            id,
            &audit_operation_id,
            serde_json::json!({ "name": name, "status": status }),
        )
        .await?;
        commit_org_mutation_tx(tx, &source_guard).await?;
        Ok(id)
    }

    async fn get_org(&self, id: i64) -> Result<Option<OrganizationRecord>, AstralError> {
        sqlx::query_as::<_, OrganizationRecord>(&format!("{ORG_ROW_SQL} AND tenant_id = ?"))
            .bind(id)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error)
    }

    async fn update_org(
        &self,
        _id: i64,
        _name: &str,
        _code: &str,
        _status: &str,
    ) -> Result<(), AstralError> {
        Err(unsafe_org_mutation_context())
    }

    async fn update_org_with_context(
        &self,
        id: i64,
        name: &str,
        code: &str,
        status: &str,
        context: &OrgMutationContext,
    ) -> Result<(), AstralError> {
        // generic hub 写者栅栏：begin 前取得，持有到 commit+dispatch。
        let source_guard = begin_org_source_writer_guard()?;
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AstralError::Database(format!("Begin update org tx failed: {e}")))?;
        let current: Option<(String,)> = sqlx::query_as(ENTERPRISE_STATUS_LOCK_SQL)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        let Some((current_status,)) = current else {
            return Err(AstralError::NotFound(format!("organization {id}")));
        };
        verify_org_mutation_actor_in_tx(&mut tx, context).await?;
        let mut invalidation_receipts = Vec::new();
        let fanout = if status_changed(&current_status, status) {
            Some(scan_tenant_eligibility_cards_in_tx(&mut tx, id).await?)
        } else {
            None
        };

        sqlx::query(
            "UPDATE tenant SET tenant_name = ?, tenant_code = ?, status = ? \
             WHERE tenant_id = ? AND tenant_type = 'ENTERPRISE'",
        )
        .bind(name)
        .bind(code)
        .bind(status)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let operation_id = if status_changed(&current_status, status) {
            tenant_status_operation_id(id, &current_status, status)
        } else {
            format!("org:tenant-update:{id}")
        };
        if let Some(cards) = fanout {
            append_tenant_eligibility_with_invalidation_in_tx(
                &mut tx,
                id,
                &operation_id,
                cards,
                &mut invalidation_receipts,
            )
            .await?;
        }
        insert_org_mutation_audit_in_tx(
            &mut tx,
            context,
            "update",
            "organization",
            id,
            &operation_id,
            serde_json::json!({
                "name": name,
                "code": code,
                "fromStatus": current_status,
                "toStatus": status,
            }),
        )
        .await?;
        arm_org_commit_fence(&source_guard);
        let commit_result = tx.commit().await;
        let proven_receipts =
            receipts_for_proven_commit(&mut invalidation_receipts, &commit_result);
        settle_org_commit_fence_on_proven(&source_guard, &commit_result);
        match commit_result {
            Ok(()) => {
                dispatch_proven_invalidation_receipts(proven_receipts).await;
                Ok(())
            }
            Err(error) => {
                // commit 未知/失败：receipts 绝不投递（随函数丢弃），uncertain_source
                // + sticky suspect 关闭内存权威读面（fail-closed），错误上抛。
                close_memory_authority_on_unknown_commit(&source_guard, &error.to_string());
                Err(db_error(error))
            }
        }
    }

    async fn delete_org(&self, id: i64) -> Result<(), AstralError> {
        let _ = id;
        Err(unsafe_org_mutation_context())
    }

    async fn delete_org_with_context(
        &self,
        id: i64,
        context: &OrgMutationContext,
    ) -> Result<(), AstralError> {
        // generic hub 写者栅栏：begin 前取得，持有到 commit+dispatch。
        let source_guard = begin_org_source_writer_guard()?;
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AstralError::Database(format!("Begin delete org tx failed: {e}")))?;
        let existing: Option<(i64,)> = sqlx::query_as(ENTERPRISE_ID_LOCK_SQL)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        if existing.is_none() {
            tx.rollback().await.map_err(db_error)?;
            return Err(AstralError::NotFound(format!("organization {id}")));
        }
        verify_org_mutation_actor_in_tx(&mut tx, context).await?;

        // 与 delete_tenant 同一引用守卫（共用 SQL 与纯 helper）：企业租户行同属
        // `tenant`，user_card 引用未守卫会留下第二条旁路。守卫先于 eligibility
        // 捕获与 DELETE，命中即在持有租户行锁的同一事务内拒绝删除。
        let referenced_card: Option<(i64,)> = sqlx::query_as(TENANT_CARD_REFERENCE_LOCK_SQL)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        if let Some(error) =
            card_reference_guard_error(id, referenced_card.map(|(card_id,)| card_id))
        {
            tx.rollback().await.ok();
            return Err(error);
        }

        // cap 扫描与资格成对捕获都必须先于硬 DELETE（capture-before-delete；
        // 超限在零写入时拒绝）。receipt 事务内先注册。
        let mut invalidation_receipts = Vec::new();
        let cards = scan_tenant_eligibility_cards_in_tx(&mut tx, id).await?;
        let operation_id = tenant_delete_operation_id(id);
        append_tenant_eligibility_with_invalidation_in_tx(
            &mut tx,
            id,
            &operation_id,
            cards,
            &mut invalidation_receipts,
        )
        .await?;
        let result =
            sqlx::query("DELETE FROM tenant WHERE tenant_id = ? AND tenant_type = 'ENTERPRISE'")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
        if result.rows_affected() != 1 {
            // 行在锁定期间消失属于持久层不变量破坏：tx drop 即回滚，receipts
            // 随之丢弃，绝不投递。
            return Err(AstralError::Database(format!(
                "enterprise tenant {id} disappeared during locked delete"
            )));
        }
        insert_org_mutation_audit_in_tx(
            &mut tx,
            context,
            "delete",
            "organization",
            id,
            &operation_id,
            serde_json::json!({ "status": "deleted" }),
        )
        .await?;
        arm_org_commit_fence(&source_guard);
        let commit_result = tx.commit().await;
        let proven_receipts =
            receipts_for_proven_commit(&mut invalidation_receipts, &commit_result);
        settle_org_commit_fence_on_proven(&source_guard, &commit_result);
        match commit_result {
            Ok(()) => {
                dispatch_proven_invalidation_receipts(proven_receipts).await;
                Ok(())
            }
            Err(error) => {
                close_memory_authority_on_unknown_commit(&source_guard, &error.to_string());
                Err(db_error(error))
            }
        }
    }

    async fn list_org_domains(&self, org_id: i64) -> Result<Vec<DomainRecord>, AstralError> {
        sqlx::query_as::<_, DomainRecord>(
            "SELECT d.domain_id as id, d.domain_name as name, d.domain_code as code, \
             d.status, DATE_FORMAT(d.created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at \
             FROM platform_domain d \
             INNER JOIN tenant_domain_map m ON m.domain_id = d.domain_id \
             WHERE m.tenant_id = ? AND m.status = 'ACTIVE'",
        )
        .bind(org_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_all_domains(&self) -> Result<Vec<DomainRecord>, AstralError> {
        sqlx::query_as::<_, DomainRecord>(&format!("{DOMAIN_ROW_SQL} ORDER BY domain_id"))
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn create_domain(
        &self,
        _name: &str,
        _code: Option<&str>,
        _status: &str,
    ) -> Result<i64, AstralError> {
        Err(unsafe_org_mutation_context())
    }

    async fn create_domain_with_context(
        &self,
        name: &str,
        code: Option<&str>,
        status: &str,
        context: &OrgMutationContext,
    ) -> Result<i64, AstralError> {
        let source_guard = begin_org_source_writer_guard()?;
        let mut tx = self.db.begin().await.map_err(db_error)?;
        verify_org_mutation_actor_in_tx(&mut tx, context).await?;
        let result = sqlx::query(
            "INSERT INTO platform_domain (domain_name, domain_code, status) VALUES (?, ?, ?)",
        )
        .bind(name)
        .bind(code)
        .bind(status)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let id = i64::try_from(result.last_insert_id())
            .map_err(|_| AstralError::Database("created domain id exceeds i64".into()))?;
        insert_org_mutation_audit_in_tx(
            &mut tx,
            context,
            "create",
            "domain",
            id,
            &context.request_id,
            serde_json::json!({ "name": name, "code": code, "status": status }),
        )
        .await?;
        commit_org_mutation_tx(tx, &source_guard).await?;
        Ok(id)
    }

    async fn get_domain(&self, id: i64) -> Result<Option<DomainRecord>, AstralError> {
        sqlx::query_as::<_, DomainRecord>(&format!("{DOMAIN_ROW_SQL} WHERE domain_id = ?"))
            .bind(id)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error)
    }

    async fn update_domain(
        &self,
        _id: i64,
        _name: &str,
        _code: Option<&str>,
        _status: &str,
    ) -> Result<(), AstralError> {
        Err(unsafe_org_mutation_context())
    }

    async fn update_domain_with_context(
        &self,
        id: i64,
        name: &str,
        code: Option<&str>,
        status: &str,
        context: &OrgMutationContext,
    ) -> Result<(), AstralError> {
        let source_guard = begin_org_source_writer_guard()?;
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let current: Option<(String,)> =
            sqlx::query_as("SELECT status FROM platform_domain WHERE domain_id = ? FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_error)?;
        let Some((current_status,)) = current else {
            tx.rollback().await.map_err(db_error)?;
            return Err(AstralError::NotFound(format!("domain {id}")));
        };
        verify_org_mutation_actor_in_tx(&mut tx, context).await?;
        if status_changed(&current_status, status) {
            let mapped_tenant: Option<(i64,)> = sqlx::query_as(DOMAIN_MAPPING_REFERENCE_LOCK_SQL)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_error)?;
            let referenced_card: Option<(i64,)> =
                sqlx::query_as(DOMAIN_USER_CARD_REFERENCE_LOCK_SQL)
                    .bind(id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(db_error)?;
            if let Some((tenant_id,)) = mapped_tenant {
                return Err(AstralError::Validation(format!(
                    "domain {id} status change blocked by tenant_domain_map reference (tenant_id={tenant_id}); use a bounded tenant mapping mutation"
                )));
            }
            if let Some((card_id,)) = referenced_card {
                return Err(AstralError::Validation(format!(
                    "domain {id} status change blocked by user_card reference (card_id={card_id})"
                )));
            }
        }
        sqlx::query(
            "UPDATE platform_domain SET domain_name = ?, domain_code = ?, status = ? \
             WHERE domain_id = ?",
        )
        .bind(name)
        .bind(code)
        .bind(status)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        insert_org_mutation_audit_in_tx(
            &mut tx,
            context,
            "update",
            "domain",
            id,
            &context.request_id,
            serde_json::json!({ "name": name, "code": code, "status": status }),
        )
        .await?;
        commit_org_mutation_tx(tx, &source_guard).await
    }

    async fn delete_domain(&self, _id: i64) -> Result<(), AstralError> {
        Err(unsafe_org_mutation_context())
    }

    async fn delete_domain_with_context(
        &self,
        id: i64,
        context: &OrgMutationContext,
    ) -> Result<(), AstralError> {
        let source_guard = begin_org_source_writer_guard()?;
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let existing: Option<(i64,)> =
            sqlx::query_as("SELECT domain_id FROM platform_domain WHERE domain_id = ? FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_error)?;
        if existing.is_none() {
            tx.rollback().await.map_err(db_error)?;
            return Err(AstralError::NotFound(format!("domain {id}")));
        }
        verify_org_mutation_actor_in_tx(&mut tx, context).await?;
        let tenant_mapping: Option<(i64,)> = sqlx::query_as(DOMAIN_MAPPING_REFERENCE_LOCK_SQL)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        let card_reference: Option<(i64,)> = sqlx::query_as(DOMAIN_USER_CARD_REFERENCE_LOCK_SQL)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        if let Some((tenant_id,)) = tenant_mapping {
            tx.rollback().await.map_err(db_error)?;
            return Err(AstralError::Validation(format!(
                "domain {id} deletion blocked by tenant_domain_map reference (tenant_id={tenant_id}); disable it through a bounded tenant mutation first"
            )));
        }
        if let Some((card_id,)) = card_reference {
            tx.rollback().await.map_err(db_error)?;
            return Err(AstralError::Validation(format!(
                "domain {id} deletion blocked by user_card reference (card_id={card_id}); reassign cards first"
            )));
        }
        insert_org_mutation_audit_in_tx(
            &mut tx,
            context,
            "delete",
            "domain",
            id,
            &context.request_id,
            serde_json::json!({}),
        )
        .await?;
        sqlx::query("DELETE FROM platform_domain WHERE domain_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        commit_org_mutation_tx(tx, &source_guard).await
    }

    async fn list_domain_tenants(&self, domain_id: i64) -> Result<Vec<TenantRecord>, AstralError> {
        sqlx::query_as::<_, TenantRecord>(
            "SELECT t.tenant_id as id, t.tenant_name as name, t.tenant_code as code, \
             t.status, DATE_FORMAT(t.created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at \
             FROM tenant t \
             INNER JOIN tenant_domain_map m ON m.tenant_id = t.tenant_id \
             WHERE m.domain_id = ? AND m.status = 'ACTIVE'",
        )
        .bind(domain_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_all_tenants(&self) -> Result<Vec<TenantRecord>, AstralError> {
        sqlx::query_as::<_, TenantRecord>(&format!("{TENANT_ROW_SQL} ORDER BY tenant_id"))
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn create_tenant(&self, _name: &str, _status: &str) -> Result<i64, AstralError> {
        Err(unsafe_org_mutation_context())
    }

    async fn create_tenant_with_context(
        &self,
        name: &str,
        status: &str,
        context: &OrgMutationContext,
    ) -> Result<i64, AstralError> {
        let source_guard = begin_org_source_writer_guard()?;
        let mut tx = self.db.begin().await.map_err(db_error)?;
        verify_org_mutation_actor_in_tx(&mut tx, context).await?;
        let result = sqlx::query(
            "INSERT INTO tenant (tenant_code, tenant_name, tenant_type, status) \
             VALUES (CONCAT('T', UNIX_TIMESTAMP()), ?, 'ENTERPRISE', ?)",
        )
        .bind(name)
        .bind(status)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let id = i64::try_from(result.last_insert_id())
            .map_err(|_| AstralError::Database("created tenant id exceeds i64".into()))?;
        insert_org_mutation_audit_in_tx(
            &mut tx,
            context,
            "create",
            "tenant",
            id,
            &context.request_id,
            serde_json::json!({ "name": name, "status": status }),
        )
        .await?;
        commit_org_mutation_tx(tx, &source_guard).await?;
        Ok(id)
    }

    async fn get_tenant(&self, id: i64) -> Result<Option<TenantRecord>, AstralError> {
        sqlx::query_as::<_, TenantRecord>(&format!("{TENANT_ROW_SQL} WHERE tenant_id = ?"))
            .bind(id)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error)
    }

    async fn update_tenant(
        &self,
        _id: i64,
        _name: &str,
        _code: &str,
        _status: &str,
    ) -> Result<(), AstralError> {
        Err(unsafe_org_mutation_context())
    }

    async fn update_tenant_with_context(
        &self,
        id: i64,
        name: &str,
        code: &str,
        status: &str,
        context: &OrgMutationContext,
    ) -> Result<(), AstralError> {
        // generic hub 写者栅栏：begin 前取得，持有到 commit+dispatch。
        let source_guard = begin_org_source_writer_guard()?;
        let mut tx =
            self.db.begin().await.map_err(|e| {
                AstralError::Database(format!("Begin update tenant tx failed: {e}"))
            })?;
        let current: Option<(String,)> = sqlx::query_as(TENANT_STATUS_LOCK_SQL)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        let Some((current_status,)) = current else {
            return Err(AstralError::NotFound(format!("tenant {id}")));
        };
        verify_org_mutation_actor_in_tx(&mut tx, context).await?;
        let mut invalidation_receipts = Vec::new();
        let fanout = if status_changed(&current_status, status) {
            // cap 扫描先于任何 mutation：超限即拒绝（此时仅锁读，零写入）。
            Some(scan_tenant_eligibility_cards_in_tx(&mut tx, id).await?)
        } else {
            None
        };

        sqlx::query(
            "UPDATE tenant SET tenant_name = ?, tenant_code = ?, status = ? WHERE tenant_id = ?",
        )
        .bind(name)
        .bind(code)
        .bind(status)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let operation_id = if status_changed(&current_status, status) {
            tenant_status_operation_id(id, &current_status, status)
        } else {
            format!("org:tenant-update:{id}")
        };
        if let Some(cards) = fanout {
            append_tenant_eligibility_with_invalidation_in_tx(
                &mut tx,
                id,
                &operation_id,
                cards,
                &mut invalidation_receipts,
            )
            .await?;
        }
        insert_org_mutation_audit_in_tx(
            &mut tx,
            context,
            "update",
            "tenant",
            id,
            &operation_id,
            serde_json::json!({
                "name": name,
                "code": code,
                "fromStatus": current_status,
                "toStatus": status,
            }),
        )
        .await?;
        arm_org_commit_fence(&source_guard);
        let commit_result = tx.commit().await;
        let proven_receipts =
            receipts_for_proven_commit(&mut invalidation_receipts, &commit_result);
        settle_org_commit_fence_on_proven(&source_guard, &commit_result);
        match commit_result {
            Ok(()) => {
                dispatch_proven_invalidation_receipts(proven_receipts).await;
                Ok(())
            }
            Err(error) => {
                // commit 未知/失败：receipts 绝不投递（随函数丢弃），uncertain_source
                // + sticky suspect 关闭内存权威读面（fail-closed），错误上抛。
                close_memory_authority_on_unknown_commit(&source_guard, &error.to_string());
                Err(db_error(error))
            }
        }
    }

    async fn delete_tenant(&self, _id: i64) -> Result<(), AstralError> {
        Err(unsafe_org_mutation_context())
    }

    async fn delete_tenant_with_context(
        &self,
        id: i64,
        context: &OrgMutationContext,
    ) -> Result<(), AstralError> {
        // generic hub 写者栅栏：begin 前取得，持有到 commit+dispatch。
        let source_guard = begin_org_source_writer_guard()?;
        let mut tx =
            self.db.begin().await.map_err(|e| {
                AstralError::Database(format!("Begin delete tenant tx failed: {e}"))
            })?;
        let existing: Option<(i64,)> = sqlx::query_as(TENANT_ID_LOCK_SQL)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        if existing.is_none() {
            // 无写早退提交：仅锁读零写，不 arm 取消栅栏（无 durable mutation
            // 可被取消中断）。
            tx.commit().await.map_err(db_error)?;
            return Err(AstralError::NotFound(format!("tenant {id}")));
        }
        verify_org_mutation_actor_in_tx(&mut tx, context).await?;

        // 引用守卫先于 eligibility 捕获与 DELETE：任何 user_card（不限
        // card_status）仍引用该租户时，在持有租户行锁的同一事务内锁定引用行
        // 并拒绝删除，fail-closed，不实现级联吊销。
        let referenced_card: Option<(i64,)> = sqlx::query_as(TENANT_CARD_REFERENCE_LOCK_SQL)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        if let Some(error) =
            card_reference_guard_error(id, referenced_card.map(|(card_id,)| card_id))
        {
            tx.rollback().await.ok();
            return Err(error);
        }

        // cap 扫描与资格成对捕获都必须先于硬 DELETE（capture-before-delete；
        // 超限在零写入时拒绝）。receipt 事务内先注册。
        let mut invalidation_receipts = Vec::new();
        let cards = scan_tenant_eligibility_cards_in_tx(&mut tx, id).await?;
        let operation_id = tenant_delete_operation_id(id);
        append_tenant_eligibility_with_invalidation_in_tx(
            &mut tx,
            id,
            &operation_id,
            cards,
            &mut invalidation_receipts,
        )
        .await?;
        insert_org_mutation_audit_in_tx(
            &mut tx,
            context,
            "delete",
            "tenant",
            id,
            &operation_id,
            serde_json::json!({ "status": "deleted" }),
        )
        .await?;
        let result = sqlx::query("DELETE FROM tenant WHERE tenant_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        if result.rows_affected() != 1 {
            // 行在锁定期间消失属于持久层不变量破坏：tx drop 即回滚，receipts
            // 随之丢弃，绝不投递。
            return Err(AstralError::Database(format!(
                "tenant {id} disappeared during locked delete"
            )));
        }
        arm_org_commit_fence(&source_guard);
        let commit_result = tx.commit().await;
        let proven_receipts =
            receipts_for_proven_commit(&mut invalidation_receipts, &commit_result);
        settle_org_commit_fence_on_proven(&source_guard, &commit_result);
        match commit_result {
            Ok(()) => {
                dispatch_proven_invalidation_receipts(proven_receipts).await;
                Ok(())
            }
            Err(error) => {
                close_memory_authority_on_unknown_commit(&source_guard, &error.to_string());
                Err(db_error(error))
            }
        }
    }
}

fn status_changed(current: &str, requested: &str) -> bool {
    current != requested
}

/// `delete_tenant`/`delete_org` 引用守卫裁决（纯函数，便于无 DB 测试）：任何
/// `user_card` 引用（任意 card_status）都 fail-closed 拒绝删除；无引用时返回
/// `None` 放行。两条删除路径（`/tenants/{id}` 与 `/orgs/{id}`）共用本裁决，
/// 消息按 tenant 表主键表述（两路径删除的是同一 `tenant` 行）。
fn card_reference_guard_error(
    tenant_id: i64,
    referenced_card_id: Option<i64>,
) -> Option<AstralError> {
    referenced_card_id.map(|card_id| {
        AstralError::Validation(format!(
            "tenant {tenant_id} delete blocked by user_card reference (card_id={card_id}); \
             revoke or reassign cards first (fail-closed)"
        ))
    })
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Org repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Execute;

    #[test]
    fn emitted_identity_org_sql_has_no_backslashes() {
        for statement in [
            ORG_MUTATION_ACTOR_LOCK_SQL,
            ORG_MUTATION_AUDIT_INSERT_SQL,
            DOMAIN_MAPPING_REFERENCE_LOCK_SQL,
            DOMAIN_USER_CARD_REFERENCE_LOCK_SQL,
            TENANT_STATUS_LOCK_SQL,
            TENANT_ID_LOCK_SQL,
            ENTERPRISE_STATUS_LOCK_SQL,
            ENTERPRISE_ID_LOCK_SQL,
            TENANT_CARD_REFERENCE_LOCK_SQL,
        ] {
            assert!(
                !statement.as_bytes().contains(&0x5c),
                "emitted Identity SQL must not contain a backslash: {statement}"
            );
        }
        let emitted_actor_lock_sql = sqlx::query::<MySql>(ORG_MUTATION_ACTOR_LOCK_SQL).sql();
        let emitted_audit_sql = sqlx::query::<MySql>(ORG_MUTATION_AUDIT_INSERT_SQL).sql();
        let emitted_multiline_mutation_sql = sqlx::query::<MySql>(
            "UPDATE tenant SET tenant_name = ?, tenant_code = ?, status = ? \
             WHERE tenant_id = ?",
        )
        .sql();
        for emitted_sql in [
            emitted_actor_lock_sql,
            emitted_audit_sql,
            emitted_multiline_mutation_sql,
        ] {
            assert!(
                !emitted_sql.as_bytes().contains(&0x5c),
                "sqlx-emitted mutation SQL must not contain a backslash: {emitted_sql}"
            );
        }
    }

    #[test]
    fn tenant_mutations_lock_source_rows_before_fanout() {
        for query in [
            TENANT_STATUS_LOCK_SQL,
            TENANT_ID_LOCK_SQL,
            ENTERPRISE_STATUS_LOCK_SQL,
            ENTERPRISE_ID_LOCK_SQL,
        ] {
            assert!(query.contains("tenant_id = ?"));
            assert!(query.ends_with("FOR UPDATE"));
        }
    }

    #[test]
    fn unchanged_tenant_status_does_not_emit_eligibility_event() {
        assert!(!status_changed("ACTIVE", "ACTIVE"));
        assert!(status_changed("ACTIVE", "DISABLED"));
    }

    #[test]
    fn tenant_card_reference_guard_locks_any_card_status() {
        // 守卫必须覆盖任意 card_status（eligibility 选择器只筛 ACTIVE），
        // 且是参数化 SQL、事务内行锁。
        assert!(TENANT_CARD_REFERENCE_LOCK_SQL.contains("FROM user_card"));
        assert!(TENANT_CARD_REFERENCE_LOCK_SQL.contains("tenant_id = ?"));
        assert!(!TENANT_CARD_REFERENCE_LOCK_SQL.contains("card_status"));
        assert!(TENANT_CARD_REFERENCE_LOCK_SQL.ends_with("FOR UPDATE"));
    }

    #[test]
    fn tenant_delete_guard_rejects_any_card_reference() {
        let error = card_reference_guard_error(11, Some(42))
            .expect("any user_card reference must block deletion");
        assert!(matches!(error, AstralError::Validation(_)));
        let message = error.to_string();
        assert!(message.contains("tenant 11"), "message: {message}");
        assert!(message.contains("card_id=42"), "message: {message}");
    }

    #[test]
    fn tenant_delete_guard_allows_tenants_without_references() {
        assert!(card_reference_guard_error(11, None).is_none());
    }

    #[test]
    fn tenant_delete_guard_runs_before_delete_statement() {
        // Impl 签名以 ` {` 结尾（trait 声明以 `;` 结尾），锚定实现函数体，
        // 避免把同文件内另一条 DELETE FROM tenant 误计入窗口。
        guard_precedes_delete_in_impl_body("async fn delete_tenant_with_context(", "delete_tenant");
    }

    #[test]
    fn org_delete_guard_runs_before_delete_statement() {
        // delete_org 删除同一 `tenant` 表（ENTERPRISE 行），必须接入同一守卫，
        // 不得留下第二条无守卫删除旁路。
        guard_precedes_delete_in_impl_body("async fn delete_org_with_context(", "delete_org");
    }

    /// 源形状守卫：在指定实现函数体内，user_card 引用守卫必须先于
    /// `DELETE FROM tenant` 出现（编译期嵌入源码，纯测试无 IO）。
    fn guard_precedes_delete_in_impl_body(impl_anchor: &str, label: &str) {
        let source = org_impl_source();
        let body_start = source
            .find(impl_anchor)
            .unwrap_or_else(|| panic!("{label} implementation must stay in org_repository.rs"));
        let body = &source[body_start..];
        let guard = body
            .find("TENANT_CARD_REFERENCE_LOCK_SQL")
            .unwrap_or_else(|| panic!("{label} must consult the user_card reference guard"));
        let delete = body
            .find("DELETE FROM tenant")
            .unwrap_or_else(|| panic!("{label} must issue its tenant DELETE in this file"));
        assert!(
            guard < delete,
            "{label}: user_card reference guard must run before the tenant DELETE"
        );
    }

    // ===== ELIGIBILITY typed invalidation intent / commit receipt 回归 =====

    fn org_impl_source() -> &'static str {
        let source = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/srv/org_repository.rs"
        ));
        let impl_start = source
            .find("impl OrgRepository for SqlxOrgRepository")
            .expect("org impl must stay in org_repository.rs");
        // impl 块到首个模块级 helper 之前为止：排除文件尾部的测试模块自身，
        // 避免把测试代码计入实现形状断言。
        let impl_end = source[impl_start..]
            .find("fn status_changed")
            .expect("status_changed helper must follow the impl block");
        &source[impl_start..impl_start + impl_end]
    }

    #[test]
    fn every_tenant_eligibility_fanout_is_paired_with_typed_invalidation() {
        // 四条资格变更路径（update_tenant/update_org/delete_tenant/delete_org）
        // 都必须以同事务成对 helper 发出资格事件，且投递决策走
        // receipts_for_proven_commit（未知/失败 commit 绝不投递）。
        for (impl_anchor, label) in [
            ("async fn update_tenant_with_context(", "update_tenant"),
            ("async fn update_org_with_context(", "update_org"),
            ("async fn delete_tenant_with_context(", "delete_tenant"),
            ("async fn delete_org_with_context(", "delete_org"),
        ] {
            let impl_source = org_impl_source();
            let body_start = impl_source
                .find(impl_anchor)
                .unwrap_or_else(|| panic!("{label} implementation must stay in org_repository.rs"));
            let body = &impl_source[body_start..];
            let pairing = body
                .find("append_tenant_eligibility_with_invalidation_in_tx")
                .unwrap_or_else(|| {
                    panic!("{label} must pair eligibility events with typed invalidation intents")
                });
            let commit = body
                .find("receipts_for_proven_commit")
                .unwrap_or_else(|| panic!("{label} must gate dispatch on a proven commit"));
            assert!(
                pairing < commit,
                "{label}: invalidation receipts must be registered inside the tx before the \
                 commit decision"
            );
        }
    }

    #[test]
    fn unpaired_eligibility_fanout_is_gone_from_the_impl() {
        let impl_source = org_impl_source();
        assert_eq!(
            impl_source
                .matches("append_tenant_eligibility_with_invalidation_in_tx")
                .count(),
            4,
            "exactly the four tenant mutation paths pair events with intents"
        );
        assert!(
            !impl_source.contains("append_eligibility_events_for_cards_in_tx"),
            "no unpaired eligibility fanout may remain in the impl"
        );
    }

    #[test]
    fn tenant_eligibility_selector_locks_active_cards_in_card_id_order() {
        // 选择器必须与 astral-db 公共批量 helper 的 ByTenantId 语义一致：
        // ACTIVE 卡、card_id 升序、事务内 FOR UPDATE、参数化 tenant_id，
        // 并以 LIMIT ? 绑定 cap+1 窗口（超限在任何 mutation 前拒绝）。
        assert!(ELIGIBILITY_CARDS_BY_TENANT_SQL.contains("FROM user_card"));
        assert!(ELIGIBILITY_CARDS_BY_TENANT_SQL.contains("tenant_id = ?"));
        assert!(ELIGIBILITY_CARDS_BY_TENANT_SQL.contains("card_status = 'ACTIVE'"));
        assert!(ELIGIBILITY_CARDS_BY_TENANT_SQL.contains("ORDER BY card_id LIMIT ? FOR UPDATE"));
    }

    #[test]
    fn eligibility_fanout_cap_matches_trustgraph_and_bounds_receipts() {
        // cap 与 trustgraph 对等（512）；扫描窗口为 cap+1（用多出的一行判定
        // 超限），receipts 上限与扫描 cap 对等。
        assert_eq!(ELIGIBILITY_FANOUT_CAP, 512);
        assert!(eligibility_receipts_cap_ok(0));
        assert!(eligibility_receipts_cap_ok(ELIGIBILITY_FANOUT_CAP - 1));
        assert!(!eligibility_receipts_cap_ok(ELIGIBILITY_FANOUT_CAP));
        assert!(!eligibility_receipts_cap_ok(ELIGIBILITY_FANOUT_CAP + 1));
    }

    #[test]
    fn dispatch_budget_is_shared_by_the_whole_batch_never_per_card() {
        // 整批共享 5s 总预算：起始时剩余 = 5s；超时后剩余为 0（停止直投，
        // 剩余 receipts 保持 durable pending）。绝不逐卡 5s 无界放大。
        assert_eq!(
            dispatch_budget_remaining(Duration::ZERO),
            INVALIDATION_DISPATCH_BUDGET
        );
        assert_eq!(
            dispatch_budget_remaining(Duration::from_millis(1500)),
            Duration::from_millis(3500)
        );
        assert!(dispatch_budget_remaining(Duration::from_secs(6)).is_zero());
        assert_eq!(INVALIDATION_DISPATCH_BUDGET, Duration::from_secs(5));
    }

    #[test]
    fn every_org_source_transaction_holds_the_generic_writer_guard() {
        // 四条 source 事务都必须 begin 前取得 generic hub 写者栅栏（Result+?，
        // hub 已装即强制），并把栅栏交给 commit-unknown 关闭路径（mark_uncertain
        // 设置 uncertain_source，在线 reconcile 不得清除）。匹配在去除空白后的
        // 源文本上进行，避免 rustfmt 换行影响锚点。两种事务初始化格式均检查。
        for (impl_anchor, label, begin_anchor) in [
            (
                "async fn update_tenant_with_context(",
                "update_tenant",
                "self.db.begin()",
            ),
            (
                "async fn update_org_with_context(",
                "update_org",
                "self\n            .db\n            .begin()",
            ),
            (
                "async fn delete_tenant_with_context(",
                "delete_tenant",
                "self.db.begin()",
            ),
            (
                "async fn delete_org_with_context(",
                "delete_org",
                "self\n            .db\n            .begin()",
            ),
        ] {
            let impl_source = org_impl_source();
            let body_start = impl_source
                .find(impl_anchor)
                .unwrap_or_else(|| panic!("{label} implementation must stay in org_repository.rs"));
            let body = &impl_source[body_start..];
            // 函数体边界：到下一个 impl 方法声明为止；最后一条方法（delete_org）
            // 之后没有下一个声明，直接取 impl 切片剩余部分。
            let body_end = body.find("\n    async fn ").unwrap_or(body.len());
            let compact: String = body[..body_end]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let guard = compact
                .find("letsource_guard=begin_org_source_writer_guard()?;")
                .unwrap_or_else(|| panic!("{label} must acquire the generic writer guard with ?"));
            let normalized_begin_anchor: String = begin_anchor
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect();
            let begin = compact
                .find(&normalized_begin_anchor)
                .unwrap_or_else(|| panic!("{label} must begin its tx in this file"));
            let close = compact
                .find("close_memory_authority_on_unknown_commit(&source_guard")
                .unwrap_or_else(|| {
                    panic!("{label} must hand the guard to the unknown-commit closure")
                });
            assert!(
                guard < begin,
                "{label}: writer guard must be acquired before pool.begin"
            );
            assert!(
                begin < close,
                "{label}: the guard must be held through commit into the unknown-commit path"
            );
        }
    }

    #[test]
    fn eligibility_cap_scan_precedes_every_mutation() {
        // 超限拒绝必须发生在任何写入之前：update 路径先扫描后 UPDATE tenant，
        // delete 路径先扫描（且在引用守卫之后）后 DELETE。
        for (impl_anchor, mutation_sql, label) in [
            (
                "async fn update_tenant_with_context(",
                "UPDATE tenant SET",
                "update_tenant",
            ),
            (
                "async fn update_org_with_context(",
                "UPDATE tenant SET",
                "update_org",
            ),
            (
                "async fn delete_tenant_with_context(",
                "DELETE FROM tenant",
                "delete_tenant",
            ),
            (
                "async fn delete_org_with_context(",
                "DELETE FROM tenant",
                "delete_org",
            ),
        ] {
            let impl_source = org_impl_source();
            let body_start = impl_source
                .find(impl_anchor)
                .unwrap_or_else(|| panic!("{label} implementation must stay in org_repository.rs"));
            let body = &impl_source[body_start..];
            let scan = body
                .find("scan_tenant_eligibility_cards_in_tx")
                .unwrap_or_else(|| panic!("{label} must cap-scan its eligibility fanout"));
            let mutation = body
                .find(mutation_sql)
                .unwrap_or_else(|| panic!("{label} must mutate tenant in this file"));
            assert!(
                scan < mutation,
                "{label}: eligibility cap scan must reject before any mutation"
            );
        }
    }

    #[test]
    fn org_write_commits_arm_cancellation_fence_and_early_exits_stay_unarmed() {
        // 取消栅栏钉（源形状，无 IO）：四条实际写事务的 commit await 前必须
        // arm（mark_commit_started），结果判定后 settle（Ok → proven 清私有
        // atomic；Err → close 路径显式 mark_uncertain）。四条无写早退提交
        // （仅锁读零写）必须保持不 arm，并带显式豁免注释。
        let impl_source = org_impl_source();
        assert_eq!(
            impl_source
                .matches("arm_org_commit_fence(&source_guard);")
                .count(),
            4,
            "exactly the four actual-write commits arm the cancellation fence"
        );
        assert_eq!(
            impl_source
                .matches("settle_org_commit_fence_on_proven(&source_guard, &commit_result);")
                .count(),
            4,
            "every armed commit must settle proven after a judged result"
        );
        assert_eq!(
            impl_source.matches("不 arm 取消栅栏").count(),
            1,
            "only delete_tenant has a no-write early commit; the other source paths either \
             roll back on missing rows or write before commit"
        );
        let delete_tenant_body = impl_source
            .split("async fn delete_tenant_with_context(")
            .nth(1)
            .expect("delete_tenant source mutation must exist");
        let delete_tenant_body_end = delete_tenant_body
            .find("\n    async fn ")
            .unwrap_or(delete_tenant_body.len());
        let delete_tenant_body = &delete_tenant_body[..delete_tenant_body_end];
        let early_commit = delete_tenant_body
            .find("tx.commit().await")
            .expect("missing-tenant path must settle its read-only transaction");
        let first_write = delete_tenant_body
            .find("append_tenant_eligibility_with_invalidation_in_tx")
            .expect("tenant delete write path must append eligibility");
        assert!(
            early_commit < first_write,
            "the missing-tenant early commit must precede every durable write"
        );
        assert!(
            !delete_tenant_body[..early_commit].contains("arm_org_commit_fence"),
            "read-only early commit must not arm the commit cancellation fence"
        );
        for (impl_anchor, label) in [
            ("async fn update_tenant_with_context(", "update_tenant"),
            ("async fn update_org_with_context(", "update_org"),
            ("async fn delete_tenant_with_context(", "delete_tenant"),
            ("async fn delete_org_with_context(", "delete_org"),
        ] {
            let body_start = impl_source
                .find(impl_anchor)
                .unwrap_or_else(|| panic!("{label} implementation must stay in org_repository.rs"));
            let body = &impl_source[body_start..];
            // 去空白匹配，避免 rustfmt 换行影响锚点。
            let body_end = body.find("\n    async fn ").unwrap_or(body.len());
            let compact: String = body[..body_end]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let arm = compact
                .find("arm_org_commit_fence(&source_guard);")
                .unwrap_or_else(|| panic!("{label} must arm the cancellation fence"));
            let commit = compact
                .find("letcommit_result=tx.commit().await;")
                .unwrap_or_else(|| panic!("{label} must await its commit in this file"));
            let settle = compact
                .find("settle_org_commit_fence_on_proven(&source_guard,&commit_result);")
                .unwrap_or_else(|| panic!("{label} must settle the fence after the result"));
            assert!(
                arm < commit,
                "{label}: the fence must be armed before the commit await"
            );
            assert!(
                commit < settle,
                "{label}: fence settlement must follow the judged result"
            );
        }
    }

    #[test]
    fn eligibility_intent_envelope_carries_event_identity_and_global_scope() {
        let envelope = eligibility_invalidation_envelope(9, "op-org-1", "evt-org-1", "region-a")
            .expect("valid envelope");
        assert_eq!(envelope.message_id, "evt-org-1", "messageId = 投影事件 id");
        assert_eq!(envelope.operation_id, "op-org-1");
        assert_eq!(envelope.message_type, ELIGIBILITY_INVALIDATED);
        assert_eq!(envelope.origin_region, "region-a");
        assert_eq!(
            envelope.tenant_id, None,
            "eligibility scope is globally card-scoped; no invented tenant filter"
        );
        assert_eq!(
            envelope.ordering_key.as_deref(),
            Some("authorization:eligibility/card/9")
        );
        // 端到端 typed 契约：消费侧解码必须成功且保留 card 语义。
        match InvalidationEvent::from_envelope(&envelope) {
            Ok(InvalidationEvent::EligibilityInvalidated(value)) => assert_eq!(value.card_id, 9),
            other => panic!("unexpected decode: {other:?}"),
        }
    }

    #[test]
    fn eligibility_intent_envelope_fails_closed_on_unstable_identity() {
        assert!(matches!(
            eligibility_invalidation_envelope(0, "op", "evt", "region-a"),
            Err(AstralError::Validation(_))
        ));
        assert!(matches!(
            eligibility_invalidation_envelope(9, " ", "evt", "region-a"),
            Err(AstralError::Validation(_))
        ));
        assert!(matches!(
            eligibility_invalidation_envelope(9, "op", "", "region-a"),
            Err(AstralError::Validation(_))
        ));
        // 空 origin region 无法过 envelope 校验（originRegion required）。
        assert!(eligibility_invalidation_envelope(9, "op", "evt", "  ").is_err());
    }

    #[test]
    fn proven_commit_hands_over_receipts_and_unknown_commit_dispatches_nothing() {
        let envelope =
            eligibility_invalidation_envelope(9, "op-1", "evt-1", "region-a").expect("envelope");
        let mut receipts = vec![InvalidationReceipt {
            event_id: envelope.message_id.clone(),
            operation_id: envelope.operation_id.clone(),
            envelope,
        }];
        let handed = receipts_for_proven_commit(&mut receipts, &Ok(()));
        assert_eq!(handed.len(), 1);
        assert!(receipts.is_empty(), "receipts drain once commit is proven");

        let envelope =
            eligibility_invalidation_envelope(9, "op-1", "evt-2", "region-a").expect("envelope");
        let mut receipts = vec![InvalidationReceipt {
            event_id: envelope.message_id.clone(),
            operation_id: envelope.operation_id.clone(),
            envelope,
        }];
        // 连接中断/提交失败都表现为 Err：未知结果按未知处理，绝不发送。
        let handed = receipts_for_proven_commit(&mut receipts, &Err(sqlx::Error::RowNotFound));
        assert!(handed.is_empty());
        assert_eq!(receipts.len(), 1, "receipts stay un-dispatched with the tx");
    }

    #[test]
    fn operation_ids_are_deterministic_and_scope_bound() {
        assert_eq!(
            tenant_status_operation_id(7, "ACTIVE", "DISABLED"),
            "org:tenant-status:7:ACTIVE->DISABLED"
        );
        assert_eq!(
            tenant_status_operation_id(7, "ACTIVE", "DISABLED"),
            tenant_status_operation_id(7, "ACTIVE", "DISABLED"),
            "same mutation semantics share the correlation id"
        );
        assert_ne!(
            tenant_status_operation_id(7, "ACTIVE", "DISABLED"),
            tenant_status_operation_id(8, "ACTIVE", "DISABLED")
        );
        assert_eq!(tenant_delete_operation_id(7), "org:tenant-delete:7");
    }

    #[test]
    fn origin_region_validation_bounds_and_trims() {
        assert_eq!(
            validated_origin_region("  region-a "),
            Ok("region-a".to_owned())
        );
        assert!(validated_origin_region("").is_err());
        assert!(validated_origin_region("   ").is_err());
        assert!(validated_origin_region(&"r".repeat(65)).is_err());
        assert_eq!(validated_origin_region(&"r".repeat(64)), Ok("r".repeat(64)));
    }

    #[test]
    fn origin_region_uninstalled_fails_closed() {
        // 测试进程内没有 install 调用：未安装即拒绝 durable append（不回退
        // env 默认——runtime 启动装配是唯一安装来源）。
        assert!(origin_region().is_err());
    }

    #[tokio::test]
    async fn proven_receipt_dispatch_completes_when_consumer_handles_delivery() {
        // 真 LocalBus 行为回归：入队即触发 typed invalidation 契约校验
        // （契约破坏会 admission 拒绝），消费者 complete 后等待方拿到 Ok。
        let bus = local_bus::LocalBus::new(local_bus::LocalBusLimits::default()).expect("bus");
        let mut receiver = bus
            .register(
                astral_mq::config::QUEUE_AUTHORIZATION_INVALIDATION,
                local_bus::LocalOwner::AuthorizationInvalidation,
            )
            .expect("register invalidation owner");
        let handler = tokio::spawn(async move {
            while let Some(delivery) = receiver.recv().await {
                delivery.complete(Ok(()));
            }
        });
        let envelope = eligibility_invalidation_envelope(9, "op-1", "evt-dispatch-1", "region-a")
            .expect("envelope");
        let receipt = InvalidationReceipt {
            event_id: envelope.message_id.clone(),
            operation_id: envelope.operation_id.clone(),
            envelope,
        };
        let result =
            dispatch_invalidation_receipt_with_deadline(&bus, receipt, Duration::from_millis(500))
                .await;
        assert!(
            result.is_ok(),
            "handled delivery must resolve Ok: {result:?}"
        );
        handler.abort();
    }

    #[tokio::test]
    async fn dispatch_without_completion_is_bounded_and_unknown() {
        // 消费者注册但从不 complete：deadline 到期必须成为有界的 Err（unknown），
        // 调用方按单次失败记录，绝不重试。
        let bus = local_bus::LocalBus::new(local_bus::LocalBusLimits::default()).expect("bus");
        let _receiver = bus
            .register(
                astral_mq::config::QUEUE_AUTHORIZATION_INVALIDATION,
                local_bus::LocalOwner::AuthorizationInvalidation,
            )
            .expect("register invalidation owner");
        let envelope = eligibility_invalidation_envelope(9, "op-1", "evt-dispatch-2", "region-a")
            .expect("envelope");
        let receipt = InvalidationReceipt {
            event_id: envelope.message_id.clone(),
            operation_id: envelope.operation_id.clone(),
            envelope,
        };
        let result =
            dispatch_invalidation_receipt_with_deadline(&bus, receipt, Duration::from_millis(80))
                .await;
        assert!(result.is_err(), "deadline expiry must surface as unknown");
    }
}
