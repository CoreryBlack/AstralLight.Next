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

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_db::{
    cached_load_published_card_grant_evidence, sod_load_card_tenant, sod_partner_matches_grant,
    sod_resource_type_from_scoped_key, AuthorizationEvidenceError,
};
use astral_types::{
    AstralError, DomainScopeRequirement, PublishedCardAuthorization, PublishedCardEvidenceScope,
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
    /// 新建策略，返回 policy_id
    async fn create_policy(&self, policy: &SodPolicyRecord) -> Result<i64, AstralError>;
    /// 全量更新策略
    async fn update_policy(
        &self,
        policy_id: i64,
        policy: &SodPolicyRecord,
    ) -> Result<(), AstralError>;
    async fn delete_policy(&self, policy_id: i64) -> Result<(), AstralError>;
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
    ) -> Result<PublishedCardAuthorization, AstralError> {
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

    async fn create_policy(&self, policy: &SodPolicyRecord) -> Result<i64, AstralError> {
        let result = sqlx::query(
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
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        // sod_policy 写路径 evict 钩子：进程级策略缓存（astral_db::sod_check，
        // TTL 30s）本进程立即失效；跨实例无广播，由 TTL 兜底（≤30s 失效窗口
        // 取舍见 astral_db::sod_check 模块文档）。
        astral_db::evict_sod_policy_cache();
        Ok(result.last_insert_id() as i64)
    }

    async fn update_policy(
        &self,
        policy_id: i64,
        policy: &SodPolicyRecord,
    ) -> Result<(), AstralError> {
        sqlx::query(
            r#"UPDATE sod_policy SET policy_name=?, description=?, conflict_type=?, resource_type=?,
               action_code=?, permission_a=?, permission_b=?, condition_script=?, status=?
               WHERE policy_id=?"#,
        )
        .bind(&policy.policy_name)
        .bind(&policy.description)
        .bind(&policy.conflict_type)
        .bind(&policy.resource_type)
        .bind(&policy.action_code)
        .bind(&policy.permission_a)
        .bind(&policy.permission_b)
        .bind(&policy.condition_script)
        .bind(&policy.status)
        .bind(policy_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        // sod_policy 写路径 evict 钩子（同 create_policy：本进程立即失效，
        // 跨实例 ≤TTL 兜底）。
        astral_db::evict_sod_policy_cache();
        Ok(())
    }

    async fn delete_policy(&self, policy_id: i64) -> Result<(), AstralError> {
        sqlx::query("DELETE FROM sod_policy WHERE policy_id=?")
            .bind(policy_id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        // sod_policy 写路径 evict 钩子（同 create_policy：本进程立即失效，
        // 跨实例 ≤TTL 兜底）。
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
            ("learn_subject:*".to_string(), "read".to_string()),
            ("user".to_string(), "read".to_string()),
            ("learn_subject:42".to_string(), "read".to_string()),
            ("user".to_string(), "read".to_string()),
            ("learn_exam".to_string(), "publish".to_string()),
            ("learn_question".to_string(), "delete".to_string()),
        ]);
        // scoped key 归一化为 plain type；多来源等价授权去重为单条目；
        // 升序输出保证确定性（detect_conflicts 的持有面语义）。
        assert_eq!(
            pairs,
            vec![
                ("learn_exam".to_string(), "publish".to_string()),
                ("learn_question".to_string(), "delete".to_string()),
                ("learn_subject".to_string(), "read".to_string()),
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
}
