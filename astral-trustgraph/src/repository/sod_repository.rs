//! SoD 职责分离数据访问 — SodRepository
//!
//! 对齐 Java `SodPolicyMapper` / `SodViolationMapper` 边界。
//! 冲突检测的比对逻辑（内存循环）保留在 service/handler，数据访问收口本层。
//!
//! 卡权限读取（`card_permissions` / `card_has_permission`）一律派生自
//! Rust-owned published card evidence：读取统一经
//! `astral_db::cached_load_published_card_grant_evidence`（进程内 evidence
//! 缓存 + 指针对牌：命中前提是当前指针版本组 + 缓存时代与填充时刻逐项相等
//! 且复读未漂移；miss/漂移回源严格 reader
//! `astral_db::load_published_card_grant_evidence` 在单个短事务内锁定并整链
//! 校验）；不存在 legacy 快照 / 旧链 head / raw source 回退——对牌失败与
//! 读取失败同样报错，绝不降级为空证据。
//!
//! ## sod_policy 写路径：proof-bound source transaction
//!
//! `create_policy` / `update_policy` / `delete_policy` 是 SoD 判定输入表的
//! source mutation，且是**用户面 HTTP 授权面变更**（新增/修改/删除 deny-only
//! 判定输入会改变后续请求的准入结论）。三者必须以
//! `AuthorizationSourceTransaction::begin_with_admission` 打开携带 F1
//! proof-bound admission 的源事务：
//! - 与既有写点同一 canonical source-activity 栅栏（`acquire_source_guard`，
//!   由源事务包装器统一获取）；
//! - COMMIT await 之前在**同一事务内**对牌 durable
//!   `authorization_authority_frontier`/`authorization_authority_proof` 行并
//!   `consume_once` 一次性消费 admission（`validate_authorization_admission_in_tx`）；
//!   drift/缺失/重复消费一律 fail-closed 回滚；
//! - commit 未知/失败绝不投递 receipts（本路径不 stage receipts），取消安全
//!   arm/uncertain/proven 语义由源事务包装器承担。
//!
//! `insert_violation` 仅为 bookkeeping 记录（非授权输入），不需要 admission
//! 或栅栏。

use async_trait::async_trait;
use sqlx::MySqlPool;

use super::authorization_source_transaction::AuthorizationSourceTransaction;
use astral_db::{
    cached_load_published_card_grant_evidence, sod_load_card_tenant, sod_partner_matches_grant,
    sod_resource_type_from_scoped_key, AuthorizationEvidenceError, TypedRowOperation,
    TypedSourceRowLookup, TypedSourceTable,
};
use astral_db::{validate_dynamic_sod_condition_script, MAX_DYNAMIC_CONDITION_SCRIPT_BYTES};
use astral_types::{
    AstralError, AuthorizationAdmission, DomainScopeRequirement, PublishedCardAuthorization,
    PublishedCardEvidenceScope,
};
use time::OffsetDateTime;

/// SoD 策略记录（sod_policy）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SodPolicyRecord {
    pub policy_id: Option<i64>,
    pub policy_name: String,
    pub description: Option<String>,
    pub conflict_type: String,
    pub resource_type: Option<String>,
    pub action_code: Option<String>,
    pub permission_a: Option<String>,
    pub permission_b: Option<String>,
    pub condition_script: Option<String>,
    pub status: String,
    pub limit_count: Option<i32>,
    pub limit_window: Option<String>,
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
}

/// SoD 违规记录（sod_violation）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SodViolationRecord {
    pub violation_id: Option<i64>,
    pub policy_id: i64,
    pub policy_name: String,
    pub card_id: i64,
    pub user_id: Option<i64>,
    pub operator_id: Option<i64>,
    pub violation_type: String,
    pub details_json: Option<String>,
    pub blocked: bool,
    pub created_at: Option<OffsetDateTime>,
}

const POLICY_SELECT: &str = "policy_id, policy_name, description, conflict_type, resource_type, action_code, \
     permission_a, permission_b, condition_script, status, limit_count, limit_window, created_at, updated_at";
const VIOLATION_SELECT: &str =
    "violation_id, policy_id, policy_name, card_id, user_id, operator_id, \
     violation_type, CAST(details_json AS CHAR) as details_json, blocked, created_at";

#[async_trait]
pub trait SodRepository: Send + Sync {
    async fn count_policies(&self) -> Result<i64, AstralError>;
    async fn list_policies(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SodPolicyRecord>, AstralError>;
    async fn get_policy(&self, policy_id: i64) -> Result<Option<SodPolicyRecord>, AstralError>;
    /// 新建策略，返回 policy_id。
    ///
    /// `admission` 必填：SoD 策略是授权判定的 deny-only 输入表，写路径必须
    /// 携带本次请求的 F1 proof-bound admission 并在 COMMIT 前同事务对牌消费。
    async fn create_policy(
        &self,
        policy: &SodPolicyRecord,
        admission: AuthorizationAdmission,
    ) -> Result<i64, AstralError>;
    /// 全量更新策略（admission 合同同 [`SodRepository::create_policy`]）。
    async fn update_policy(
        &self,
        policy_id: i64,
        policy: &SodPolicyRecord,
        admission: AuthorizationAdmission,
    ) -> Result<(), AstralError>;
    /// 删除策略（expanding：移除 deny 约束；admission 合同同 create_policy）。
    async fn delete_policy(
        &self,
        policy_id: i64,
        admission: AuthorizationAdmission,
    ) -> Result<(), AstralError>;
    /// 活跃策略列表（冲突检测/授权校验用）
    async fn list_active_policies(&self) -> Result<Vec<SodPolicyRecord>, AstralError>;
    /// 违规总数（按 policy_id 可选过滤）
    async fn count_violations(&self, policy_id: Option<i64>) -> Result<i64, AstralError>;
    /// 违规分页列表（ORDER BY created_at DESC，按 policy_id 可选过滤）
    async fn list_violations(
        &self,
        policy_id: Option<i64>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SodViolationRecord>, AstralError>;
    /// 写入违规记录，返回 violation_id
    async fn insert_violation(&self, v: &SodViolationRecord) -> Result<i64, AstralError>;
    /// 卡当前权限（已发布 evidence 的 `effective_grants` 全集，scoped resource
    /// key 归一化为 plain `(resource_type, action_code)` 后去重升序）。
    ///
    /// evidence 不可读（tenant 缺失/非正、指针缺失/未 READY、链校验失败、
    /// 读取期间指针漂移、scope 合同拒绝）时返回数据库错误；绝不降级为空
    /// 权限列表——空列表会在冲突检测中漏报冲突，等价于放行。
    async fn card_permissions(&self, card_id: i64) -> Result<Vec<(String, String)>, AstralError>;
    /// 卡是否持有指定权限（已发布 evidence 成员判定，归一化语义同
    /// [`SodRepository::card_permissions`]；入参为 plain resource type + action）。
    ///
    /// evidence 不可读时同样返回数据库错误，绝不返回"不持有"。
    async fn card_has_permission(
        &self,
        card_id: i64,
        resource_key: &str,
        action_code: &str,
    ) -> Result<bool, AstralError>;
}

pub struct SqlxSodRepository {
    db: MySqlPool,
}

/// Validate persisted SoD source rows at the repository boundary as well as the
/// HTTP adapter. No raw writer may bypass the exact dynamic expression grammar.
fn validate_sod_policy_source(policy: &SodPolicyRecord) -> Result<(), AstralError> {
    if policy.policy_name.trim().is_empty() {
        return Err(AstralError::Validation("policy_name is required".into()));
    }
    match policy.conflict_type.as_str() {
        "STATIC" => {
            if policy.permission_a.as_deref().is_none_or(str::is_empty)
                || policy.permission_b.as_deref().is_none_or(str::is_empty)
            {
                return Err(AstralError::Validation(
                    "STATIC SoD policies require permission_a and permission_b".into(),
                ));
            }
        }
        "DYNAMIC" => {
            let script = policy.condition_script.as_deref().ok_or_else(|| {
                AstralError::Validation("DYNAMIC SoD policies require condition_script".into())
            })?;
            if script.len() > MAX_DYNAMIC_CONDITION_SCRIPT_BYTES {
                return Err(AstralError::Validation(
                    "condition_script exceeds configured size limit".into(),
                ));
            }
            validate_dynamic_sod_condition_script(script)?;
        }
        _ => {
            return Err(AstralError::Validation(
                "conflict_type must be STATIC or DYNAMIC".into(),
            ))
        }
    }
    Ok(())
}

// 单条 sod_policy source 语句的 proof-bound 执行合同（由下方三个方法承担）：
// `AuthorizationSourceTransaction::begin_with_admission` 先取 canonical
// source-activity 栅栏再 `pool.begin()`；语句在事务内执行；COMMIT await 前
// 先对牌 durable authority frontier/proof 行并 `consume_once` 消费 admission
// （`commit_consuming` 内建），arm → await → Ok proven / Err sticky uncertain
// / 取消 Drop → unknown，与 Identity/card 写点同一合同。
impl SqlxSodRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }

    /// 读取卡级已发布授权证据（SoD 读路径统一门禁入口）。
    ///
    /// - tenant 定位输入：`sod_load_card_tenant`（`user_card.tenant_id`；缺失/
    ///   非正 → 稳定前缀 `sod_card_tenant_missing;` 报错，绝不折算成空证据）；
    /// - 卡级 lens：不按 user 收窄、不限 domain（对齐 astral-db 卡级摘要语义）；
    /// - 读取经进程内 evidence 缓存 + 指针对牌（miss/漂移回源）：严格 reader
    ///   在单短事务内 FOR UPDATE 锁定当前指针并复核未漂移，"读取后复核"语义
    ///   由 reader 与对牌双读协议共同承担；
    /// - Ready 证据再过一次合同校验（纵深防御，对齐 astral-db 卡级摘要）：
    ///   形状矛盾 → `sod_card_evidence_corrupt;` 报错。
    ///
    /// fail-closed：evidence 不可用一律报错，绝不降级为空证据（空证据会在
    /// 冲突检测中漏报冲突 → 放行）。
    async fn load_card_evidence(
        &self,
        card_id: i64,
    ) -> Result<std::sync::Arc<PublishedCardAuthorization>, AstralError> {
        let tenant_id = sod_load_card_tenant(&self.db, card_id)
            .await
            .map_err(db_error)?;

        let scope = PublishedCardEvidenceScope {
            tenant_id,
            card_id,
            user_filter: None,
            domain: DomainScopeRequirement::Unconstrained,
        };
        match cached_load_published_card_grant_evidence(&self.db, &scope).await {
            Ok(evidence) => {
                if let Err(contract_error) = evidence.validate() {
                    return Err(AstralError::Database(format!(
                        "SoD repository query failed: {}",
                        astral_db::sod_evidence_contract_message(card_id, &contract_error)
                    )));
                }
                Ok(evidence)
            }
            Err(error) => Err(sod_evidence_db_error(card_id, error)),
        }
    }
}

#[async_trait]
impl SodRepository for SqlxSodRepository {
    async fn count_policies(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sod_policy")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_policies(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SodPolicyRecord>, AstralError> {
        sqlx::query_as::<_, SodPolicyRecord>(&format!(
            "SELECT {POLICY_SELECT} FROM sod_policy ORDER BY policy_id LIMIT ? OFFSET ?"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get_policy(&self, policy_id: i64) -> Result<Option<SodPolicyRecord>, AstralError> {
        sqlx::query_as::<_, SodPolicyRecord>(&format!(
            "SELECT {POLICY_SELECT} FROM sod_policy WHERE policy_id=?"
        ))
        .bind(policy_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_policy(
        &self,
        policy: &SodPolicyRecord,
        admission: AuthorizationAdmission,
    ) -> Result<i64, AstralError> {
        validate_sod_policy_source(policy)?;
        // proof-bound source transaction（见模块文档）：canonical activity 栅栏
        // 由 begin 取得；COMMIT 前同事务对牌并一次性消费 F1 admission。
        let audit_admission = admission.clone();
        let mut tx =
            AuthorizationSourceTransaction::begin_with_admission(&self.db, admission).await?;
        let mut capture =
            tx.typed_row_capture(TypedSourceTable::SodPolicy, TypedRowOperation::Insert);
        let policy_name = policy.policy_name.clone();
        capture
            .capture_before_in_tx(&TypedSourceRowLookup::SodPolicyName {
                name: policy_name.clone(),
            })
            .await?;
        let result = capture
            .with_tx_mut(move |tx| {
                let policy = policy.clone();
                Box::pin(async move {
                    sqlx::query(
                        r#"INSERT INTO sod_policy (policy_name, description, conflict_type, resource_type, action_code,
                           permission_a, permission_b, condition_script, status, limit_count, limit_window)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
                    )
                    .bind(&policy.policy_name)
                    .bind(&policy.description)
                    .bind(&policy.conflict_type)
                    .bind(&policy.resource_type)
                    .bind(&policy.action_code)
                    .bind(&policy.permission_a)
                    .bind(&policy.permission_b)
                    .bind(&policy.condition_script)
                    .bind("ACTIVE")
                    .bind(policy.limit_count)
                    .bind(&policy.limit_window)
                    .execute(&mut **tx)
                    .await
                    .map_err(|error| AstralError::Database(format!("SoD policy insert failed: {error}")))
                })
            })
            .await?;
        require_one_row(result.rows_affected(), "SoD policy insert")?;
        let policy_id = i64::try_from(result.last_insert_id())
            .ok()
            .filter(|id| *id > 0)
            .ok_or_else(|| AstralError::Pending("SoD policy insert returned invalid id".into()))?;
        capture
            .capture_after_in_tx(&TypedSourceRowLookup::SodPolicyName {
                name: policy.policy_name.clone(),
            })
            .await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        tx.stage_typed_source_image(image)?;
        let audit_id = insert_sod_policy_audit(
            &mut tx,
            &audit_admission,
            policy_id,
            "CREATE",
            serde_json::json!({"policyName": policy.policy_name}),
        )
        .await?;
        tx.stage_typed_source_audit_insert_id(audit_id)?;
        tx.commit_consuming().await?;
        astral_db::evict_sod_policy_cache();
        Ok(policy_id)
    }

    async fn update_policy(
        &self,
        policy_id: i64,
        policy: &SodPolicyRecord,
        admission: AuthorizationAdmission,
    ) -> Result<(), AstralError> {
        validate_sod_policy_source(policy)?;
        // proof-bound source transaction（同 create_policy）。
        let audit_admission = admission.clone();
        let mut tx =
            AuthorizationSourceTransaction::begin_with_admission(&self.db, admission).await?;
        let lookup = TypedSourceRowLookup::PrimaryId { id: policy_id };
        let mut capture =
            tx.typed_row_capture(TypedSourceTable::SodPolicy, TypedRowOperation::Update);
        capture.capture_before_in_tx(&lookup).await?;
        let update_policy = policy.clone();
        let result = capture
            .with_tx_mut(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        r#"UPDATE sod_policy SET policy_name=?, description=?, conflict_type=?, resource_type=?,
                           action_code=?, permission_a=?, permission_b=?, condition_script=?, status=?
                           WHERE policy_id=?"#,
                    )
                    .bind(&update_policy.policy_name)
                    .bind(&update_policy.description)
                    .bind(&update_policy.conflict_type)
                    .bind(&update_policy.resource_type)
                    .bind(&update_policy.action_code)
                    .bind(&update_policy.permission_a)
                    .bind(&update_policy.permission_b)
                    .bind(&update_policy.condition_script)
                    .bind(&update_policy.status)
                    .bind(policy_id)
                    .execute(&mut **tx)
                    .await
                    .map_err(|error| AstralError::Database(format!("SoD policy update failed: {error}")))
                })
            })
            .await?;
        require_one_row(result.rows_affected(), "SoD policy update")?;
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        tx.stage_typed_source_image(image)?;
        let audit_id = insert_sod_policy_audit(
            &mut tx,
            &audit_admission,
            policy_id,
            "UPDATE",
            serde_json::json!({"policyName": policy.policy_name}),
        )
        .await?;
        tx.stage_typed_source_audit_insert_id(audit_id)?;
        tx.commit_consuming().await?;
        // sod_policy 写路径 evict 钩子（同 create_policy：本进程立即失效，
        // composite 另有 token 精确失效，跨实例 ≤TTL 兜底；仅 proven commit）。
        astral_db::evict_sod_policy_cache();
        Ok(())
    }

    async fn delete_policy(
        &self,
        policy_id: i64,
        admission: AuthorizationAdmission,
    ) -> Result<(), AstralError> {
        // proof-bound source transaction（同 create_policy；删除移除 deny 约束，
        // 属扩大授权面的用户面 mutation，admission 不可省略）。
        let audit_admission = admission.clone();
        let mut tx =
            AuthorizationSourceTransaction::begin_with_admission(&self.db, admission).await?;
        let lookup = TypedSourceRowLookup::PrimaryId { id: policy_id };
        let mut capture =
            tx.typed_row_capture(TypedSourceTable::SodPolicy, TypedRowOperation::Delete);
        capture.capture_before_in_tx(&lookup).await?;
        let result = capture
            .with_tx_mut(move |tx| {
                Box::pin(async move {
                    sqlx::query("DELETE FROM sod_policy WHERE policy_id=?")
                        .bind(policy_id)
                        .execute(&mut **tx)
                        .await
                        .map_err(|error| {
                            AstralError::Database(format!("SoD policy delete failed: {error}"))
                        })
                })
            })
            .await?;
        require_one_row(result.rows_affected(), "SoD policy delete")?;
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        tx.stage_typed_source_image(image)?;
        let audit_id = insert_sod_policy_audit(
            &mut tx,
            &audit_admission,
            policy_id,
            "DELETE",
            serde_json::json!({"status": "deleted"}),
        )
        .await?;
        tx.stage_typed_source_audit_insert_id(audit_id)?;
        tx.commit_consuming().await?;
        // sod_policy 写路径 evict 钩子（同 create_policy：本进程立即失效，
        // composite 另有 token 精确失效，跨实例 ≤TTL 兜底；仅 proven commit）。
        astral_db::evict_sod_policy_cache();
        Ok(())
    }

    async fn list_active_policies(&self) -> Result<Vec<SodPolicyRecord>, AstralError> {
        sqlx::query_as::<_, SodPolicyRecord>(&format!(
            "SELECT {POLICY_SELECT} FROM sod_policy WHERE status='ACTIVE'"
        ))
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn count_violations(&self, policy_id: Option<i64>) -> Result<i64, AstralError> {
        match policy_id {
            Some(pid) => {
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sod_violation WHERE policy_id=?")
                    .bind(pid)
                    .fetch_one(&self.db)
                    .await
                    .map_err(db_error)
            }
            None => sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sod_violation")
                .fetch_one(&self.db)
                .await
                .map_err(db_error),
        }
    }

    async fn list_violations(
        &self,
        policy_id: Option<i64>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SodViolationRecord>, AstralError> {
        match policy_id {
            Some(pid) => sqlx::query_as::<_, SodViolationRecord>(&format!(
                "SELECT {VIOLATION_SELECT} FROM sod_violation WHERE policy_id=? \
                 ORDER BY created_at DESC LIMIT ? OFFSET ?"
            ))
            .bind(pid)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(db_error),
            None => sqlx::query_as::<_, SodViolationRecord>(&format!(
                "SELECT {VIOLATION_SELECT} FROM sod_violation ORDER BY created_at DESC LIMIT ? OFFSET ?"
            ))
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.db)
            .await
            .map_err(db_error),
        }
    }

    async fn insert_violation(&self, v: &SodViolationRecord) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO sod_violation (policy_id, policy_name, card_id, violation_type, details_json, blocked) \
             VALUES (?, ?, ?, ?, ?, true)",
        )
        .bind(v.policy_id)
        .bind(&v.policy_name)
        .bind(v.card_id)
        .bind(&v.violation_type)
        .bind(&v.details_json)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn card_permissions(&self, card_id: i64) -> Result<Vec<(String, String)>, AstralError> {
        // 新链 evidence 数据源：全集遍历 `effective_grants`（当前有效授权集合，
        // ACTIVE/窗口/完整性判定已由 reader 在统一 UTC 时钟下完成，不再重复）。
        //
        // 来源覆盖面（语义决策）：包含全部来源（DIRECT/APPROVAL/RULE_SET/
        // DELEGATION）的生效 ALLOW——SoD 关心"实际持有的权限组合"，来源无关；
        // 旧实现只读卡规则快照、看不到 RULE_SET/DELEGATION 是旧快照能力限制
        // 而非语义选择。切换后 detect_conflicts 的持有面变严（漏报减少），属
        // 修复；【上线灰度观察项】关注 RULE_SET/DELEGATION 来源带来的新增
        // 违规记录量。
        //
        // resource_key 归一化：scoped key（`type:*` / `type:id`）→ plain type，
        // 与策略权限对（`type:action`）的 plain 形状对齐；旧快照 resource_key
        // 直接拼接比较导致形状错位漏报，此处为修复点。
        let evidence = self.load_card_evidence(card_id).await?;
        Ok(normalize_sod_permission_pairs(
            evidence
                .effective_grants
                .iter()
                .map(|grant| (grant.resource.clone(), grant.action.clone())),
        ))
    }

    async fn card_has_permission(
        &self,
        card_id: i64,
        resource_key: &str,
        action_code: &str,
    ) -> Result<bool, AstralError> {
        // 成员判定：与 card_permissions 同一 evidence 数据源与归一化语义；
        // `resource_key` 入参是 plain resource type（调用方传入策略权限对的
        // parts[0]），grant 侧 scoped key 先归一再精确比较。evidence 不可读
        // 必须报错，绝不把"读不到"折算成"不持有"（那会漏报冲突 → 放行）。
        let evidence = self.load_card_evidence(card_id).await?;
        Ok(evidence.effective_grants.iter().any(|grant| {
            sod_partner_matches_grant(&grant.resource, &grant.action, resource_key, action_code)
        }))
    }
}

/// 纯逻辑：把 evidence 的 (resource, action) 权限对映射为 SoD 策略匹配所需的
/// 去重升序集合。resource 侧 scoped key（`type:*` / `type:id`）归一化为 plain
/// type，与策略权限对（`type:action`）的 plain 形状对齐；多来源等价授权只产生
/// 一个条目，排序保证输出确定。输入约定：grants 已是发布时验证过的生效 ALLOW
/// 集合（完整性由 reader 保证），此处不重复做有效性判定。
fn normalize_sod_permission_pairs<I>(pairs: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut permissions: Vec<(String, String)> = pairs
        .into_iter()
        .map(|(resource, action)| (sod_resource_type_from_scoped_key(&resource), action))
        .collect();
    permissions.sort();
    permissions.dedup();
    permissions
}

/// 将 published card evidence 读取失败映射为仓库层错误。
///
/// `NotReady`/`Corrupt`/`InvalidRequest` 保持 astral_db 的 SoD 稳定前缀
/// （`sod_card_evidence_not_ready;` / `sod_card_evidence_corrupt;` /
/// `sod_card_evidence_invalid_scope;`）穿透到 `AstralError::Database`，供
/// 审计/告警按前缀分类；`Query` 属 DB 传输错误，走统一 `db_error`。
fn sod_evidence_db_error(card_id: i64, error: AuthorizationEvidenceError) -> AstralError {
    match error {
        AuthorizationEvidenceError::Query(query) => db_error(query),
        other => AstralError::Database(format!(
            "SoD repository query failed: {}",
            astral_db::sod_evidence_error_message(card_id, &other)
        )),
    }
}

async fn insert_sod_policy_audit(
    tx: &mut AuthorizationSourceTransaction,
    admission: &AuthorizationAdmission,
    policy_id: i64,
    action: &str,
    details: serde_json::Value,
) -> Result<i64, AstralError> {
    let actor_id = admission
        .proof()
        .scope
        .user_id
        .filter(|id| *id > 0)
        .ok_or_else(|| {
            AstralError::Permission("SoD policy audit requires a user-bound admission".into())
        })?;
    if policy_id <= 0 || action.trim().is_empty() {
        return Err(AstralError::Validation(
            "SoD policy audit identity is invalid".into(),
        ));
    }
    let detail = serde_json::to_string(&serde_json::json!({
        "operationId": admission.proof().operation_id.as_str(),
        "policyId": policy_id,
        "mutation": details,
    }))
    .map_err(|error| {
        AstralError::Validation(format!("SoD policy audit serialization failed: {error}"))
    })?;
    let result = sqlx::query(
        "INSERT INTO audit_log (user_id, action, resource, decision, event_type, request_id, detail) \
         VALUES (?, ?, 'sod_policy', 'ALLOW', 'SOD_POLICY_MUTATION', ?, ?)",
    )
    .bind(actor_id)
    .bind(action)
    .bind(admission.proof().operation_id.as_str())
    .bind(detail)
    .execute(&mut ***tx)
    .await
    .map_err(|error| AstralError::Database(format!("SoD policy audit insert failed: {error}")))?;
    if result.rows_affected() != 1 {
        return Err(AstralError::Pending(
            "SoD policy audit insert affected an unexpected row count".into(),
        ));
    }
    i64::try_from(result.last_insert_id())
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| AstralError::Pending("SoD policy audit insert returned invalid id".into()))
}

fn require_one_row(affected: u64, operation: &str) -> Result<(), AstralError> {
    if affected != 1 {
        return Err(AstralError::Validation(format!(
            "{operation} affected {affected} rows; refusing an unproven mutation"
        )));
    }
    Ok(())
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("SoD repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_db::{sod_evidence_contract_message, sod_evidence_error_message, sod_gate_error};

    // ===== SoD 权限对收集：归一化 + 去重 + 确定性排序（纯逻辑） =====

    #[test]
    fn sod_permission_pairs_normalize_scoped_keys_dedup_and_sort() {
        let pairs = normalize_sod_permission_pairs([
            ("permission_rule:*".to_string(), "read".to_string()),
            ("user".to_string(), "read".to_string()),
            ("permission_rule:42".to_string(), "read".to_string()),
            ("user".to_string(), "read".to_string()),
            ("permission_rule".to_string(), "delete".to_string()),
            ("permission_rule".to_string(), "create".to_string()),
        ]);
        // scoped key 归一化为 plain type；多来源等价授权去重为单条目；
        // 升序输出保证确定性（detect_conflicts 的持有面语义）。
        assert_eq!(
            pairs,
            vec![
                ("permission_rule".to_string(), "create".to_string()),
                ("permission_rule".to_string(), "delete".to_string()),
                ("permission_rule".to_string(), "read".to_string()),
                ("user".to_string(), "read".to_string()),
            ]
        );
    }

    #[test]
    fn sod_permission_pairs_plain_keys_pass_through_and_empty_stays_empty() {
        assert!(normalize_sod_permission_pairs([]).is_empty());
        assert_eq!(
            normalize_sod_permission_pairs([("user".to_string(), "read".to_string())]),
            vec![("user".to_string(), "read".to_string())]
        );
    }

    // ===== evidence 错误形状（数据库错误族 + 稳定前缀穿透） =====

    #[test]
    fn sod_evidence_not_ready_error_keeps_stable_prefix_through_db_error() {
        let error = AuthorizationEvidenceError::NotReady(
            "code=published_card_evidence.current_pointer_missing;tenant=1;card=7".into(),
        );
        match sod_evidence_db_error(7, error) {
            AstralError::Database(message) => {
                assert!(message.contains("SoD repository query failed"));
                assert!(
                    message.contains("sod_card_evidence_not_ready"),
                    "evidence prefix must survive the repository error mapping, got: {message}"
                );
                assert!(message.contains("card_id=7"));
                assert!(message.contains("current_pointer_missing"));
            }
            other => panic!("evidence failure must map onto AstralError::Database, got {other:?}"),
        }
    }

    #[test]
    fn sod_evidence_corrupt_error_keeps_stable_prefix_through_db_error() {
        // 读取期间指针漂移（Corrupt）同样只允许报错，不得降级为成功结果。
        let error = AuthorizationEvidenceError::Corrupt(
            "code=published_card_evidence.pointer_moved_under_read".into(),
        );
        match sod_evidence_db_error(9, error) {
            AstralError::Database(message) => {
                assert!(message.contains("sod_card_evidence_corrupt"));
                assert!(message.contains("card_id=9"));
                assert!(message.contains("pointer_moved_under_read"));
            }
            other => panic!("expected Database error, got {other:?}"),
        }
    }

    #[test]
    fn sod_query_transport_error_keeps_db_error_family() {
        let error = AuthorizationEvidenceError::Query(sqlx::Error::ColumnNotFound("x".into()));
        match sod_evidence_db_error(5, error) {
            AstralError::Database(message) => {
                assert!(message.contains("SoD repository query failed"));
                // 传输错误不伪装成 evidence 语义前缀
                assert!(!message.contains("sod_card_evidence_not_ready"));
                assert!(!message.contains("sod_card_evidence_corrupt"));
            }
            other => panic!("expected Database error, got {other:?}"),
        }
    }

    #[test]
    fn sod_evidence_error_helpers_keep_stable_prefixes() {
        let not_ready = AuthorizationEvidenceError::NotReady("code=not_ready.detail".into());
        let message = sod_evidence_error_message(21, &not_ready);
        assert!(message.starts_with("sod_card_evidence_not_ready;"));
        assert!(message.contains("card_id=21"));

        let contract = sod_evidence_contract_message(22, "gate counters disagree");
        assert!(contract.starts_with("sod_card_evidence_corrupt;"));
        assert!(contract.contains("card_id=22"));

        // 稳定前缀在 sod_gate_error（Configuration 族）中同样保留
        match sod_gate_error("sod_card_tenant_missing;card_id=23;tenant_id=0") {
            sqlx::Error::Configuration(boxed) => {
                let message = boxed.to_string();
                assert!(message.contains("sod_card_tenant_missing"));
                assert!(message.contains("card_id=23"));
            }
            other => panic!("expected Configuration error, got {other:?}"),
        }
    }

    // ===== 形状守卫（evidence 调用顺序 + 旧链读取清除） =====

    /// 形状守卫：`card_permissions` / `card_has_permission` 必须经统一入口
    /// `load_card_evidence`（tenant 定位 → 卡级 evidence scope → 严格 reader →
    /// 合同校验），之后再做归一匹配/全集遍历；入口之前不得有成功结果，
    /// 也不得读 legacy 快照表或旧链 head 表。
    #[test]
    fn sod_permission_reads_load_published_evidence_before_matching() {
        let source = include_str!("sod_repository.rs");
        let impl_body = source
            .split("impl SodRepository for SqlxSodRepository")
            .nth(1)
            .expect("SqlxSodRepository impl must exist");

        for (method, matcher_marker) in [
            (
                "async fn card_permissions(",
                "normalize_sod_permission_pairs",
            ),
            ("async fn card_has_permission(", "sod_partner_matches_grant"),
        ] {
            let body = impl_body.split(method).nth(1).expect("impl exists");
            let reader = body
                .find("self.load_card_evidence(card_id)")
                .unwrap_or_else(|| panic!("{method} must go through load_card_evidence"));
            let matcher = body
                .find(matcher_marker)
                .unwrap_or_else(|| panic!("{method} must normalize scoped resource keys"));

            assert!(
                reader < matcher,
                "{method} order must be evidence reader -> normalized matching"
            );

            let prefix = &body[..reader];
            assert!(
                !prefix.contains("Ok("),
                "{method} must not return a success before the evidence reader"
            );
            assert!(
                !prefix.contains("permission_rule_snapshot"),
                "{method} must not read legacy snapshots before the evidence reader"
            );
        }
    }

    /// 全文件守卫（生产代码段）：legacy 快照 SQL 与旧链 head 门禁不得再出现；
    /// 严格 reader + tenant 定位 + 归一化纯函数是仅有的数据通路。
    #[test]
    fn sod_repository_reads_no_legacy_snapshot_or_head_tables() {
        let source = include_str!("sod_repository.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("test module must be separable");

        assert!(
            !production.contains("permission_rule_snapshot"),
            "legacy snapshot table must not be read by SoD repository any more"
        );
        assert!(
            !production.contains("authorization_projection_head"),
            "legacy CARD head gate must not be read by SoD repository any more"
        );
        assert!(!production.contains("CARD_PERMISSIONS_SQL"));
        assert!(!production.contains("CARD_HAS_PERMISSION_SQL"));
        assert!(!production.contains("ensure_sod_card_gate_readable"));
        assert!(!production.contains("ensure_sod_card_gate_unchanged"));

        // 新链数据通路在位（经指针对牌的进程内 evidence 缓存入口回源严格 reader）
        assert!(production.contains("cached_load_published_card_grant_evidence"));
        assert!(production.contains("sod_load_card_tenant"));
        assert!(production.contains("PublishedCardEvidenceScope"));
        assert!(production.contains("sod_resource_type_from_scoped_key"));
    }

    // ===== sod_policy 写路径 source writer 栅栏（形状守卫，无 IO/无 hub 全局态） =====

    /// 形状守卫：create/update/delete 三条 sod_policy source mutation 必须
    /// 以 `AuthorizationSourceTransaction::begin_with_admission` 携带 F1
    /// proof-bound admission（canonical source-activity 栅栏由该 begin 统一
    /// 取得），语句在事务内执行，`commit_consuming` 在 COMMIT 前对牌并一次性
    /// 消费 admission，最后 evict 进程缓存。写点不得回退为无 admission 的
    /// autocommit。
    #[test]
    fn dynamic_policy_source_write_rejects_unrecognized_operator() {
        let policy = SodPolicyRecord {
            policy_id: None,
            policy_name: "owner self approve".into(),
            description: None,
            conflict_type: "DYNAMIC".into(),
            resource_type: Some("approval".into()),
            action_code: Some("approve".into()),
            permission_a: None,
            permission_b: None,
            condition_script: Some("resourceOwnerId != currentUserId".into()),
            status: "ACTIVE".into(),
            limit_count: None,
            limit_window: None,
            created_at: None,
            updated_at: None,
        };
        assert!(validate_sod_policy_source(&policy).is_err());
    }

    #[test]
    fn sod_policy_mutations_carry_and_consume_proof_bound_admission() {
        let source = include_str!("sod_repository.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        // 锚定 impl 块（trait 声明与方法同名，先切出 impl 再取方法体）。
        let impl_block = production
            .split("impl SodRepository for SqlxSodRepository")
            .nth(1)
            .expect("SqlxSodRepository impl must exist");

        for method in [
            "async fn create_policy(",
            "async fn update_policy(",
            "async fn delete_policy(",
        ] {
            let body = impl_block
                .split(method)
                .nth(1)
                .unwrap_or_else(|| panic!("{method} must exist"));
            let body = body.split("\n    async fn ").next().unwrap();
            let admission_param = body
                .find("admission: AuthorizationAdmission")
                .unwrap_or_else(|| {
                    panic!("{method} must require the proof-bound admission by value")
                });
            let begin = body
                .find("AuthorizationSourceTransaction::begin_with_admission(&self.db, admission)")
                .unwrap_or_else(|| panic!("{method} must open an admission-carrying source tx"));
            let evict = body
                .find("evict_sod_policy_cache()")
                .unwrap_or_else(|| panic!("{method} must evict the process cache after write"));
            let commit = body
                .find("tx.commit_consuming()")
                .unwrap_or_else(|| panic!("{method} must commit through the source tx wrapper"));
            assert!(
                admission_param < begin && begin < commit && commit < evict,
                "{method} order must be admission param -> begin_with_admission -> \
                 commit_consuming -> cache evict"
            );
            // 语句必须在源事务内执行，不得回退为 autocommit（`&self.db` executor）。
            assert!(
                !body.contains(".execute(&self.db)"),
                "{method} must not execute the source statement outside the source transaction"
            );
            assert!(
                body.contains(".execute(&mut **tx)"),
                "{method} must execute the statement inside the source transaction"
            );
        }

        // trait 契约：三个写方法签名都要求 admission（缺失即编译失败）。
        for trait_method in [
            "async fn create_policy(\n        &self,\n        policy: &SodPolicyRecord,\n        admission: AuthorizationAdmission,\n    )",
            "async fn update_policy(\n        &self,\n        policy_id: i64,\n        policy: &SodPolicyRecord,\n        admission: AuthorizationAdmission,\n    )",
            "async fn delete_policy(\n        &self,\n        policy_id: i64,\n        admission: AuthorizationAdmission,\n    )",
        ] {
            assert!(
                production.contains(trait_method),
                "trait signature must require admission: {trait_method}"
            );
        }
    }

    /// 形状守卫：`insert_violation` 只是 bookkeeping 记录（非授权输入），
    /// 不携带 admission/源事务——admission 语义只属于 sod_policy source
    /// mutation。
    #[test]
    fn violation_insert_is_bookkeeping_without_source_guard() {
        let source = include_str!("sod_repository.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        let impl_block = production
            .split("impl SodRepository for SqlxSodRepository")
            .nth(1)
            .expect("SqlxSodRepository impl must exist");
        let body = impl_block
            .split("async fn insert_violation(")
            .nth(1)
            .expect("insert_violation impl must exist");
        let body = body.split("\n    async fn ").next().unwrap();
        assert!(
            !body.contains("begin_with_admission"),
            "violation bookkeeping must not open an admission-carrying source transaction"
        );
        assert!(body.contains("INSERT INTO sod_violation"));
    }
}
