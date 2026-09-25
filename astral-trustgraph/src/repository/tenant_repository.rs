//! 租户数据访问 — TenantRepository
//!
//! 对齐 Java `TenantMapper` / `TenantMemberMapper` / `TenantInvitationMapper` /
//! `TenantPurchaseMapper` / `TenantDomainMapMapper` / `TenantAuditLogMapper` 边界。
//! 事务性方法（create 双步写 path、use_invitation_code 接受邀请）收口为聚合方法。

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

use astral_db::{append_eligibility_events_for_cards_in_tx, EligibilityCardSelector};
use astral_types::AstralError;

// ===== Records =====

/// 租户记录（platform_v4.tenant，domain_id 用 0 占位——真实表无该列）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantRecord {
    pub id: i64,
    pub domain_id: i64,
    pub name: String,
    pub status: String,
    pub parent_tenant_id: Option<i64>,
    pub path: String,
    pub depth: i32,
}

/// 租户成员记录（platform_v4.tenant_members）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantMemberRecord {
    pub id: i64,
    pub tenant_id: i64,
    pub user_id: i64,
    pub role: String,
    pub status: String,
    pub display_name: Option<String>,
    pub joined_at: Option<i64>,
    pub left_at: Option<i64>,
}

/// 租户邀请记录（platform_v4.tenant_invitation）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantInvitationRecord {
    pub id: i64,
    pub tenant_id: i64,
    pub inviter_id: i64,
    pub invitee_email: Option<String>,
    pub invitee_user_id: Option<i64>,
    pub token: String,
    pub role: String,
    pub status: String,
    pub expires_at: Option<i64>,
    pub message: Option<String>,
    pub accepted_at: Option<i64>,
}

/// 租户购买记录（platform_v4.tenant_purchase，业务字段占位）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantPurchaseRecord {
    pub id: i64,
    pub tenant_id: i64,
    pub plan_id: Option<i64>,
    pub plan_name: String,
    pub amount: i64,
    pub currency: String,
    pub billing_cycle: String,
    pub status: String,
    pub payment_method: Option<String>,
    pub payment_channel: Option<String>,
    pub transaction_id: Option<String>,
    pub period_start: Option<i64>,
    pub period_end: Option<i64>,
    pub paid_at: Option<i64>,
    pub refunded_at: Option<i64>,
    pub remark: Option<String>,
}

/// 租户域映射记录（platform_v4.tenant_domain_map）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantDomainMapRecord {
    pub id: i64,
    pub tenant_id: i64,
    pub domain_id: i64,
    pub is_primary: bool,
    pub mapping_type: String,
    pub status: String,
}

/// 租户审计日志记录（platform_v4.tenant_audit_log）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TenantAuditLogRecord {
    pub id: i64,
    pub tenant_id: i64,
    pub actor_id: Option<i64>,
    pub actor_name: Option<String>,
    pub action: String,
    pub action_label: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub detail: Option<String>,
    pub result: String,
    pub reason: Option<String>,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: Option<i64>,
}

// ===== 参数 =====

/// 列表过滤（keyword / status 可选）
#[derive(Debug, Default)]
pub struct TenantFilter {
    pub keyword: Option<String>,
    pub status: Option<String>,
}

/// 新建租户参数（service 完成 path/depth 推算）
#[derive(Debug, Clone)]
pub struct NewTenant {
    pub name: String,
    pub parent_tenant_id: Option<i64>,
    pub path: String,
    pub depth: i32,
}

/// 新建购买参数（service 完成到期推算）
#[derive(Debug, Clone)]
pub struct NewPurchase {
    pub tenant_id: i64,
    pub plan_id: i64,
    pub expired_secs: Option<i64>,
}

// ===== SQL 常量 =====

const TENANT_SELECT: &str = "tenant_id as id, 0 as domain_id, tenant_name as name, status, \
     parent_tenant_id, path, depth";
/// JOIN 场景（tenant 带前缀的版本，0 占位字面量不带前缀）
const TENANT_SELECT_T: &str =
    "t.tenant_id as id, 0 as domain_id, t.tenant_name as name, t.status, \
     t.parent_tenant_id, t.path, t.depth";
const MEMBER_SELECT: &str = "member_id as id, tenant_id, user_id, role_type as role, \
     member_status as status, NULL as display_name, UNIX_TIMESTAMP(joined_at) as joined_at, NULL as left_at";
const INVITATION_SELECT: &str = "invitation_id as id, tenant_id, invited_by as inviter_id, \
     NULL as invitee_email, NULL as invitee_user_id, invite_code as token, role, status, \
     UNIX_TIMESTAMP(expires_at) as expires_at, NULL as message, NULL as accepted_at";
const PURCHASE_SELECT: &str = "purchase_id as id, tenant_id, package_id as plan_id, \
     '' as plan_name, 0 as amount, 'CNY' as currency, 'MONTHLY' as billing_cycle, status, \
     NULL as payment_method, NULL as payment_channel, NULL as transaction_id, \
     UNIX_TIMESTAMP(purchased_at) as period_start, UNIX_TIMESTAMP(expired_at) as period_end, \
     UNIX_TIMESTAMP(purchased_at) as paid_at, NULL as refunded_at, NULL as remark";
const DOMAIN_MAP_SELECT: &str = "id, tenant_id, domain_id, false as is_primary, \
     'OWNED' as mapping_type, status";
const AUDIT_LOG_SELECT: &str = "log_id as id, tenant_id, operator_id as actor_id, \
     NULL as actor_name, action, NULL as action_label, target_type, \
     CAST(target_id AS CHAR) as target_id, CAST(detail_json AS CHAR) as detail, \
     'SUCCESS' as result, NULL as reason, ip as source_ip, NULL as user_agent, \
     UNIX_TIMESTAMP(created_at) as created_at";

const TENANT_STATUS_LOCK_SQL: &str = "SELECT status FROM tenant WHERE tenant_id = ? FOR UPDATE";
const TENANT_ID_LOCK_SQL: &str = "SELECT tenant_id FROM tenant WHERE tenant_id = ? FOR UPDATE";
const TENANT_DOMAIN_STATUS_LOCK_SQL: &str = "SELECT status FROM tenant_domain_map \
     WHERE tenant_id = ? AND domain_id = ? FOR UPDATE";
/// 硬删除前置守卫：统计仍引用该租户的 user_card 行数（锁定读，参数化 SQL）。
/// 锁定读在守卫通过后阻止并发为该租户新增 user_card 行，直到事务结束。
/// 不按 card_status 过滤：任何状态（含 DISABLED/PENDING/INACTIVE）的引用行
/// 都会被级联删除销毁，且非 ACTIVE 行不在 ELIGIBILITY 捕获范围内。
const TENANT_CARD_REFERENCES_LOCK_SQL: &str = "SELECT COUNT(*) FROM user_card \
     WHERE tenant_id = ? FOR UPDATE";

#[async_trait]
pub trait TenantRepository: Send + Sync {
    // ---- Tenant ----
    async fn count_tenants(&self, filter: &TenantFilter) -> Result<i64, AstralError>;
    async fn list_tenants(
        &self,
        filter: &TenantFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<TenantRecord>, AstralError>;
    async fn get_tenant(&self, tenant_id: i64) -> Result<Option<TenantRecord>, AstralError>;
    async fn get_tenant_path_depth(
        &self,
        tenant_id: i64,
    ) -> Result<Option<(String, i32)>, AstralError>;
    /// 新建租户（INSERT + path 更新在单事务内，修复崩溃中间态）
    async fn create_tenant(&self, new: &NewTenant) -> Result<i64, AstralError>;
    async fn update_tenant_name(&self, tenant_id: i64, name: &str) -> Result<(), AstralError>;
    async fn update_tenant_status(&self, tenant_id: i64, status: &str) -> Result<(), AstralError>;
    /// 硬删除租户，返回是否命中。fail-closed：事务内先锁租户行证明存在，
    /// 再以锁定读守卫统计仍引用该租户的 user_card 行；存在引用行时返回
    /// Validation 冲突错误并整体回滚（无部分删除）。完整级联（捕获并持久
    /// 吊销所有受影响的规范授权贡献）不在本仓库范围，须先回收/迁移全部卡片。
    async fn delete_tenant(&self, tenant_id: i64) -> Result<bool, AstralError>;
    /// 状态迁移（ACTIVE→SUSPENDED / SUSPENDED→ACTIVE），返回是否命中
    async fn transition_tenant_status(
        &self,
        tenant_id: i64,
        from: &str,
        to: &str,
    ) -> Result<bool, AstralError>;
    async fn list_my_tenants(&self, user_id: i64) -> Result<Vec<TenantRecord>, AstralError>;
    async fn list_sub_tenants(&self, tenant_id: i64) -> Result<Vec<TenantRecord>, AstralError>;
    async fn list_tenant_tree(&self, tenant_id: i64) -> Result<Vec<TenantRecord>, AstralError>;

    // ---- Members ----
    async fn list_members(&self, tenant_id: i64) -> Result<Vec<TenantMemberRecord>, AstralError>;
    /// upsert 成员（ON DUPLICATE KEY UPDATE）
    async fn upsert_member(
        &self,
        tenant_id: i64,
        user_id: i64,
        role: &str,
    ) -> Result<(), AstralError>;
    async fn get_member(
        &self,
        tenant_id: i64,
        user_id: i64,
    ) -> Result<TenantMemberRecord, AstralError>;
    /// 移除成员（member_status → REMOVED），返回是否命中
    async fn remove_member(&self, tenant_id: i64, user_id: i64) -> Result<bool, AstralError>;
    /// 更新成员字段（admin_level / dept_id / role_type），返回是否命中
    async fn update_member_field(
        &self,
        tenant_id: i64,
        user_id: i64,
        column: &str,
        value: String,
    ) -> Result<bool, AstralError>;

    // ---- Invitations ----
    async fn list_invitations(
        &self,
        tenant_id: i64,
    ) -> Result<Vec<TenantInvitationRecord>, AstralError>;
    async fn create_invitation(
        &self,
        tenant_id: i64,
        token: &str,
        role: &str,
        inviter_id: i64,
        expires_secs: i64,
    ) -> Result<TenantInvitationRecord, AstralError>;
    async fn get_invitation_by_code(
        &self,
        code: &str,
    ) -> Result<Option<TenantInvitationRecord>, AstralError>;
    /// 按邀请码查 ACTIVE 邀请（use_invitation_code 用）
    async fn get_invitation_by_code_active(
        &self,
        code: &str,
    ) -> Result<Option<TenantInvitationRecord>, AstralError>;
    /// 撤销邀请（ACTIVE → REVOKED），返回是否命中
    async fn cancel_invitation(
        &self,
        tenant_id: i64,
        invitation_id: i64,
    ) -> Result<bool, AstralError>;
    /// 标记过期（status → EXPIRED）
    async fn mark_invitation_expired(&self, invitation_id: i64) -> Result<(), AstralError>;
    /// 接受邀请：事务（置 ACCEPTED + current_uses+1 + 成员 upsert）
    async fn accept_invitation(
        &self,
        invitation_id: i64,
        tenant_id: i64,
        user_id: i64,
        role: &str,
    ) -> Result<(), AstralError>;

    // ---- Purchases ----
    async fn list_purchases(
        &self,
        tenant_id: i64,
    ) -> Result<Vec<TenantPurchaseRecord>, AstralError>;
    async fn create_purchase(&self, new: &NewPurchase) -> Result<i64, AstralError>;
    async fn get_purchase(&self, purchase_id: i64) -> Result<TenantPurchaseRecord, AstralError>;

    // ---- Domain map ----
    async fn list_tenant_domains(
        &self,
        tenant_id: i64,
    ) -> Result<Vec<TenantDomainMapRecord>, AstralError>;
    /// upsert 域映射（ON DUPLICATE KEY UPDATE）
    async fn upsert_tenant_domain(&self, tenant_id: i64, domain_id: i64)
        -> Result<(), AstralError>;
    async fn get_tenant_domain(
        &self,
        tenant_id: i64,
        domain_id: i64,
    ) -> Result<TenantDomainMapRecord, AstralError>;
    async fn remove_tenant_domain(
        &self,
        tenant_id: i64,
        domain_id: i64,
    ) -> Result<bool, AstralError>;

    // ---- Audit log ----
    async fn list_audit_log(
        &self,
        tenant_id: i64,
    ) -> Result<Vec<TenantAuditLogRecord>, AstralError>;
}

pub struct SqlxTenantRepository {
    db: MySqlPool,
}

impl SqlxTenantRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

/// 追加租户过滤（列表与总数共用）
fn push_tenant_filter<'args>(
    builder: &mut QueryBuilder<'args, sqlx::MySql>,
    filter: &TenantFilter,
) {
    if let Some(kw) = &filter.keyword {
        builder
            .push(" AND tenant_name LIKE ")
            .push_bind(format!("%{kw}%"));
    }
    if let Some(status) = &filter.status {
        builder.push(" AND status = ").push_bind(status.clone());
    }
}

#[async_trait]
impl TenantRepository for SqlxTenantRepository {
    async fn count_tenants(&self, filter: &TenantFilter) -> Result<i64, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new("SELECT COUNT(*) FROM tenant WHERE 1=1");
        push_tenant_filter(&mut builder, filter);
        builder
            .build_query_scalar::<i64>()
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_tenants(
        &self,
        filter: &TenantFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<TenantRecord>, AstralError> {
        let mut builder = QueryBuilder::<sqlx::MySql>::new(&format!(
            "SELECT {TENANT_SELECT} FROM tenant WHERE 1=1"
        ));
        push_tenant_filter(&mut builder, filter);
        builder
            .push(" ORDER BY tenant_id LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        builder
            .build_query_as::<TenantRecord>()
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn get_tenant(&self, tenant_id: i64) -> Result<Option<TenantRecord>, AstralError> {
        sqlx::query_as::<_, TenantRecord>(&format!(
            "SELECT {TENANT_SELECT} FROM tenant WHERE tenant_id = ?"
        ))
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get_tenant_path_depth(
        &self,
        tenant_id: i64,
    ) -> Result<Option<(String, i32)>, AstralError> {
        sqlx::query_as::<_, (String, i32)>("SELECT path, depth FROM tenant WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error)
    }

    async fn create_tenant(&self, new: &NewTenant) -> Result<i64, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;

        let result = sqlx::query(
            "INSERT INTO tenant (tenant_code, tenant_name, tenant_type, status, parent_tenant_id, path, depth) \
             VALUES (CONCAT('T', UNIX_TIMESTAMP()), ?, 'ENTERPRISE', 'ACTIVE', ?, ?, ?)",
        )
        .bind(&new.name)
        .bind(new.parent_tenant_id)
        .bind(&new.path)
        .bind(new.depth)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let inserted_id = result.last_insert_id() as i64;

        // 更新新建租户的 path（自引用于 path）——同事务，修复 INSERT 后崩溃的中间态
        let tenant_path = if new.depth == 0 {
            format!("/{inserted_id}")
        } else {
            format!("{}/{}", new.path, inserted_id)
        };
        sqlx::query("UPDATE tenant SET path = ? WHERE tenant_id = ?")
            .bind(&tenant_path)
            .bind(inserted_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        tx.commit().await.map_err(db_error)?;
        Ok(inserted_id)
    }

    async fn update_tenant_name(&self, tenant_id: i64, name: &str) -> Result<(), AstralError> {
        sqlx::query("UPDATE tenant SET tenant_name = ? WHERE tenant_id = ?")
            .bind(name)
            .bind(tenant_id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn update_tenant_status(&self, tenant_id: i64, status: &str) -> Result<(), AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let current: Option<(String,)> = sqlx::query_as(TENANT_STATUS_LOCK_SQL)
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        let Some((current_status,)) = current else {
            tx.commit().await.map_err(db_error)?;
            return Ok(());
        };

        sqlx::query("UPDATE tenant SET status = ? WHERE tenant_id = ?")
            .bind(status)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;

        if status_changed(&current_status, status) {
            append_eligibility_events_for_cards_in_tx(
                &mut tx,
                EligibilityCardSelector::ByTenantId { tenant_id },
            )
            .await?;
        }
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn delete_tenant(&self, tenant_id: i64) -> Result<bool, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        // 先锁租户行证明存在（FOR UPDATE），再执行后续守卫与删除。
        let tenant: Option<(i64,)> = sqlx::query_as(TENANT_ID_LOCK_SQL)
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        if tenant.is_none() {
            tx.commit().await.map_err(db_error)?;
            return Ok(false);
        }

        // 锁定读前置守卫：仍被 user_card 引用的租户禁止硬删除（fail-closed）。
        // 完整级联（捕获并持久吊销所有受影响的规范授权贡献）不在本仓库范围内；
        // 引用行存在时返回 Validation 冲突错误，事务随 Err 丢弃而整体回滚，
        // 不产生部分删除。守卫错误先于任何写入返回。
        let (card_references,) = sqlx::query_as::<_, (i64,)>(TENANT_CARD_REFERENCES_LOCK_SQL)
            .bind(tenant_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_error)?;
        guard_tenant_delete(card_references, tenant_id)?;

        // Capture and enqueue eligibility before a hard delete can cascade user_card rows.
        // 守卫通过后引用行数为 0，此 fanout 为空操作；保留调用点以维持删除路径
        // 的既有 ELIGIBILITY 捕获语义（与 update/transition 状态路径一致）。
        append_eligibility_events_for_cards_in_tx(
            &mut tx,
            EligibilityCardSelector::ByTenantId { tenant_id },
        )
        .await?;

        let result = sqlx::query("DELETE FROM tenant WHERE tenant_id = ?")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Database(format!(
                "tenant {tenant_id} disappeared during locked delete"
            )));
        }
        tx.commit().await.map_err(db_error)?;
        Ok(true)
    }

    async fn transition_tenant_status(
        &self,
        tenant_id: i64,
        from: &str,
        to: &str,
    ) -> Result<bool, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let current: Option<(String,)> = sqlx::query_as(TENANT_STATUS_LOCK_SQL)
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        let Some((current_status,)) = current else {
            tx.commit().await.map_err(db_error)?;
            return Ok(false);
        };
        if !status_transition_changes(&current_status, from, to) {
            tx.commit().await.map_err(db_error)?;
            return Ok(false);
        }

        let result = sqlx::query("UPDATE tenant SET status = ? WHERE tenant_id = ? AND status = ?")
            .bind(to)
            .bind(tenant_id)
            .bind(from)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        if result.rows_affected() == 0 {
            tx.commit().await.map_err(db_error)?;
            return Ok(false);
        }

        append_eligibility_events_for_cards_in_tx(
            &mut tx,
            EligibilityCardSelector::ByTenantId { tenant_id },
        )
        .await?;
        tx.commit().await.map_err(db_error)?;
        Ok(true)
    }

    async fn list_my_tenants(&self, user_id: i64) -> Result<Vec<TenantRecord>, AstralError> {
        sqlx::query_as::<_, TenantRecord>(&format!(
            "SELECT {TENANT_SELECT_T} FROM tenant t \
             JOIN tenant_members tm ON tm.tenant_id = t.tenant_id \
             WHERE tm.user_id = ? AND tm.member_status = 'ACTIVE' AND t.status = 'ACTIVE' \
             ORDER BY t.tenant_id"
        ))
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_sub_tenants(&self, tenant_id: i64) -> Result<Vec<TenantRecord>, AstralError> {
        sqlx::query_as::<_, TenantRecord>(&format!(
            "SELECT {TENANT_SELECT} FROM tenant WHERE parent_tenant_id = ? ORDER BY tenant_id"
        ))
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_tenant_tree(&self, tenant_id: i64) -> Result<Vec<TenantRecord>, AstralError> {
        sqlx::query_as::<_, TenantRecord>(&format!(
            "SELECT {TENANT_SELECT} FROM tenant \
             WHERE path LIKE (SELECT CONCAT(path, '/%') FROM tenant WHERE tenant_id = ?) \
             ORDER BY path"
        ))
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_members(&self, tenant_id: i64) -> Result<Vec<TenantMemberRecord>, AstralError> {
        sqlx::query_as::<_, TenantMemberRecord>(&format!(
            "SELECT {MEMBER_SELECT} FROM tenant_members WHERE tenant_id = ? ORDER BY role_type, joined_at"
        ))
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn upsert_member(
        &self,
        tenant_id: i64,
        user_id: i64,
        role: &str,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT INTO tenant_members (tenant_id, user_id, role_type, member_status) \
             VALUES (?, ?, ?, 'ACTIVE') \
             ON DUPLICATE KEY UPDATE role_type = VALUES(role_type), member_status = 'ACTIVE'",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(role)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn get_member(
        &self,
        tenant_id: i64,
        user_id: i64,
    ) -> Result<TenantMemberRecord, AstralError> {
        sqlx::query_as::<_, TenantMemberRecord>(&format!(
            "SELECT {MEMBER_SELECT} FROM tenant_members WHERE tenant_id = ? AND user_id = ?"
        ))
        .bind(tenant_id)
        .bind(user_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn remove_member(&self, tenant_id: i64, user_id: i64) -> Result<bool, AstralError> {
        let result = sqlx::query(
            "UPDATE tenant_members SET member_status = 'REMOVED' WHERE tenant_id = ? AND user_id = ?",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn update_member_field(
        &self,
        tenant_id: i64,
        user_id: i64,
        column: &str,
        value: String,
    ) -> Result<bool, AstralError> {
        let sql = format!(
            "UPDATE tenant_members SET {column} = ? WHERE tenant_id = ? AND user_id = ? AND member_status = 'ACTIVE'"
        );
        let result = sqlx::query(&sql)
            .bind(value)
            .bind(tenant_id)
            .bind(user_id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_invitations(
        &self,
        tenant_id: i64,
    ) -> Result<Vec<TenantInvitationRecord>, AstralError> {
        sqlx::query_as::<_, TenantInvitationRecord>(&format!(
            "SELECT {INVITATION_SELECT} FROM tenant_invitation WHERE tenant_id = ? ORDER BY created_at DESC"
        ))
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_invitation(
        &self,
        tenant_id: i64,
        token: &str,
        role: &str,
        inviter_id: i64,
        expires_secs: i64,
    ) -> Result<TenantInvitationRecord, AstralError> {
        sqlx::query(
            "INSERT INTO tenant_invitation (tenant_id, invite_code, role, invited_by, status, expires_at) \
             VALUES (?, ?, ?, ?, 'ACTIVE', FROM_UNIXTIME(?))",
        )
        .bind(tenant_id)
        .bind(token)
        .bind(role)
        .bind(inviter_id)
        .bind(expires_secs)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        self.get_invitation_by_code(token)
            .await?
            .ok_or_else(|| AstralError::Database("invitation not found after insert".into()))
    }

    async fn get_invitation_by_code(
        &self,
        code: &str,
    ) -> Result<Option<TenantInvitationRecord>, AstralError> {
        sqlx::query_as::<_, TenantInvitationRecord>(&format!(
            "SELECT {INVITATION_SELECT} FROM tenant_invitation WHERE invite_code = ?"
        ))
        .bind(code)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get_invitation_by_code_active(
        &self,
        code: &str,
    ) -> Result<Option<TenantInvitationRecord>, AstralError> {
        sqlx::query_as::<_, TenantInvitationRecord>(&format!(
            "SELECT {INVITATION_SELECT} FROM tenant_invitation WHERE invite_code = ? AND status = 'ACTIVE'"
        ))
        .bind(code)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn cancel_invitation(
        &self,
        tenant_id: i64,
        invitation_id: i64,
    ) -> Result<bool, AstralError> {
        let result = sqlx::query(
            "UPDATE tenant_invitation SET status = 'REVOKED' \
             WHERE invitation_id = ? AND tenant_id = ? AND status = 'ACTIVE'",
        )
        .bind(invitation_id)
        .bind(tenant_id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn mark_invitation_expired(&self, invitation_id: i64) -> Result<(), AstralError> {
        sqlx::query("UPDATE tenant_invitation SET status = 'EXPIRED' WHERE invitation_id = ?")
            .bind(invitation_id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
    }

    async fn accept_invitation(
        &self,
        invitation_id: i64,
        tenant_id: i64,
        user_id: i64,
        role: &str,
    ) -> Result<(), AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;

        // ACTIVE 守卫：并发使用同一邀请码时仅一次成功（rows_affected==1）。
        // 已 ACCEPTED/REVOKED 的邀请再次接受返回明确错误，防重复入会。
        let result = sqlx::query(
            "UPDATE tenant_invitation SET status = 'ACCEPTED', current_uses = current_uses + 1 \
             WHERE invitation_id = ? AND status = 'ACTIVE'",
        )
        .bind(invitation_id)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        if result.rows_affected() == 0 {
            return Err(AstralError::Validation(
                "invitation is no longer active".into(),
            ));
        }
        sqlx::query(
            "INSERT INTO tenant_members (tenant_id, user_id, role_type, member_status) \
             VALUES (?, ?, ?, 'ACTIVE') \
             ON DUPLICATE KEY UPDATE role_type = VALUES(role_type), member_status = 'ACTIVE'",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(role)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;

        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn list_purchases(
        &self,
        tenant_id: i64,
    ) -> Result<Vec<TenantPurchaseRecord>, AstralError> {
        sqlx::query_as::<_, TenantPurchaseRecord>(&format!(
            "SELECT {PURCHASE_SELECT} FROM tenant_purchase WHERE tenant_id = ? ORDER BY purchased_at DESC"
        ))
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_purchase(&self, new: &NewPurchase) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO tenant_purchase (tenant_id, package_id, status, purchased_at, expired_at) \
             VALUES (?, ?, 'ACTIVE', NOW(), FROM_UNIXTIME(?))",
        )
        .bind(new.tenant_id)
        .bind(new.plan_id)
        .bind(new.expired_secs)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
    }

    async fn get_purchase(&self, purchase_id: i64) -> Result<TenantPurchaseRecord, AstralError> {
        sqlx::query_as::<_, TenantPurchaseRecord>(&format!(
            "SELECT {PURCHASE_SELECT} FROM tenant_purchase WHERE purchase_id = ?"
        ))
        .bind(purchase_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_tenant_domains(
        &self,
        tenant_id: i64,
    ) -> Result<Vec<TenantDomainMapRecord>, AstralError> {
        sqlx::query_as::<_, TenantDomainMapRecord>(&format!(
            "SELECT {DOMAIN_MAP_SELECT} FROM tenant_domain_map WHERE tenant_id = ? ORDER BY id"
        ))
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn upsert_tenant_domain(
        &self,
        tenant_id: i64,
        domain_id: i64,
    ) -> Result<(), AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let tenant: Option<(i64,)> = sqlx::query_as(TENANT_ID_LOCK_SQL)
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        if tenant.is_none() {
            tx.commit().await.map_err(db_error)?;
            return Ok(());
        }

        let current: Option<(String,)> = sqlx::query_as(TENANT_DOMAIN_STATUS_LOCK_SQL)
            .bind(tenant_id)
            .bind(domain_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;

        let changed = match current {
            Some((status,)) if status == "ACTIVE" => false,
            Some(_) => {
                sqlx::query(
                    "UPDATE tenant_domain_map SET status = 'ACTIVE' \
                     WHERE tenant_id = ? AND domain_id = ?",
                )
                .bind(tenant_id)
                .bind(domain_id)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
                true
            }
            None => {
                // The unique key serializes a concurrent insert after the absent-row lock.
                let result = sqlx::query(
                    "INSERT INTO tenant_domain_map (tenant_id, domain_id, granted_by, status) \
                     VALUES (?, ?, 1, 'ACTIVE') \
                     ON DUPLICATE KEY UPDATE status = 'ACTIVE'",
                )
                .bind(tenant_id)
                .bind(domain_id)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
                result.rows_affected() > 0
            }
        };

        if changed {
            append_eligibility_events_for_cards_in_tx(
                &mut tx,
                EligibilityCardSelector::ByTenantAndDomain {
                    tenant_id,
                    domain_id,
                },
            )
            .await?;
        }
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn get_tenant_domain(
        &self,
        tenant_id: i64,
        domain_id: i64,
    ) -> Result<TenantDomainMapRecord, AstralError> {
        sqlx::query_as::<_, TenantDomainMapRecord>(&format!(
            "SELECT {DOMAIN_MAP_SELECT} FROM tenant_domain_map WHERE tenant_id = ? AND domain_id = ?"
        ))
        .bind(tenant_id)
        .bind(domain_id)
        .fetch_one(&self.db)
        .await
        .map_err(db_error)
    }

    async fn remove_tenant_domain(
        &self,
        tenant_id: i64,
        domain_id: i64,
    ) -> Result<bool, AstralError> {
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let tenant: Option<(i64,)> = sqlx::query_as(TENANT_ID_LOCK_SQL)
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        if tenant.is_none() {
            tx.commit().await.map_err(db_error)?;
            return Ok(false);
        }

        let current: Option<(String,)> = sqlx::query_as(TENANT_DOMAIN_STATUS_LOCK_SQL)
            .bind(tenant_id)
            .bind(domain_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        if current.is_none() {
            tx.commit().await.map_err(db_error)?;
            return Ok(false);
        }

        let result =
            sqlx::query("DELETE FROM tenant_domain_map WHERE tenant_id = ? AND domain_id = ?")
                .bind(tenant_id)
                .bind(domain_id)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
        if result.rows_affected() == 0 {
            tx.commit().await.map_err(db_error)?;
            return Ok(false);
        }

        append_eligibility_events_for_cards_in_tx(
            &mut tx,
            EligibilityCardSelector::ByTenantAndDomain {
                tenant_id,
                domain_id,
            },
        )
        .await?;
        tx.commit().await.map_err(db_error)?;
        Ok(true)
    }

    async fn list_audit_log(
        &self,
        tenant_id: i64,
    ) -> Result<Vec<TenantAuditLogRecord>, AstralError> {
        sqlx::query_as::<_, TenantAuditLogRecord>(&format!(
            "SELECT {AUDIT_LOG_SELECT} FROM tenant_audit_log WHERE tenant_id = ? ORDER BY created_at DESC LIMIT 100"
        ))
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Tenant repository query failed: {error}"))
}

fn status_changed(current: &str, requested: &str) -> bool {
    current != requested
}

fn status_transition_changes(current: &str, from: &str, to: &str) -> bool {
    current == from && from != to
}

/// 硬删除前置守卫决策（纯函数，便于单元测试）：引用行数为 0 才放行；
/// 否则返回明确的 Validation 冲突错误（消息含租户与引用行数）。
/// COUNT(*) 恒为非负，正数一律视为仍有卡片引用，禁止删除。
fn guard_tenant_delete(referencing_cards: i64, tenant_id: i64) -> Result<(), AstralError> {
    if referencing_cards > 0 {
        return Err(AstralError::Validation(format!(
            "tenant {tenant_id} hard delete blocked: {referencing_cards} user_card row(s) \
             still reference it; revoke or reassign all cards before delete"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_mutations_lock_source_rows_before_card_fanout() {
        assert!(TENANT_STATUS_LOCK_SQL.ends_with("FOR UPDATE"));
        assert!(TENANT_ID_LOCK_SQL.ends_with("FOR UPDATE"));
        assert!(TENANT_DOMAIN_STATUS_LOCK_SQL.ends_with("FOR UPDATE"));
        assert!(TENANT_STATUS_LOCK_SQL.contains("tenant_id = ?"));
        assert!(TENANT_DOMAIN_STATUS_LOCK_SQL.contains("tenant_id = ? AND domain_id = ?"));
    }

    #[test]
    fn domain_mutations_use_tenant_then_mapping_then_cards_order() {
        let source_lock = TENANT_ID_LOCK_SQL;
        let mapping_lock = TENANT_DOMAIN_STATUS_LOCK_SQL;
        assert!(source_lock.contains("FROM tenant"));
        assert!(mapping_lock.contains("FROM tenant_domain_map"));
        assert!(source_lock.ends_with("FOR UPDATE"));
        assert!(mapping_lock.ends_with("FOR UPDATE"));
        assert!(
            source_lock.find("tenant").unwrap() < mapping_lock.find("tenant_domain_map").unwrap()
        );
        assert!(
            mapping_lock.find("tenant_domain_map").unwrap()
                < mapping_lock.find("FOR UPDATE").unwrap()
        );
    }

    #[test]
    fn unchanged_status_does_not_request_eligibility_fanout() {
        assert!(!status_changed("ACTIVE", "ACTIVE"));
        assert!(status_changed("ACTIVE", "SUSPENDED"));
        assert!(!status_transition_changes("ACTIVE", "ACTIVE", "ACTIVE"));
        assert!(status_transition_changes("ACTIVE", "ACTIVE", "SUSPENDED"));
        assert!(!status_transition_changes(
            "SUSPENDED",
            "ACTIVE",
            "SUSPENDED"
        ));
    }

    #[test]
    fn delete_guard_allows_only_when_no_card_references() {
        assert!(guard_tenant_delete(0, 42).is_ok());

        for referencing in [1, 3, 100] {
            let err = guard_tenant_delete(referencing, 42)
                .expect_err("guard must block while user_card rows reference the tenant");
            match err {
                AstralError::Validation(message) => {
                    assert!(
                        message.contains("42"),
                        "message must name the tenant: {message}"
                    );
                    assert!(
                        message.contains(&referencing.to_string()),
                        "message must state the reference count: {message}"
                    );
                    assert!(
                        message.contains("user_card"),
                        "message must name the referencing table: {message}"
                    );
                }
                other => panic!("expected Validation error, got {other:?}"),
            }
        }
    }

    #[test]
    fn delete_card_guard_sql_is_locked_and_parameterized() {
        assert!(TENANT_CARD_REFERENCES_LOCK_SQL.contains("FROM user_card"));
        assert!(TENANT_CARD_REFERENCES_LOCK_SQL.contains("tenant_id = ?"));
        assert!(TENANT_CARD_REFERENCES_LOCK_SQL.ends_with("FOR UPDATE"));
        let tenant_lock = TENANT_ID_LOCK_SQL;
        assert!(
            tenant_lock.find("tenant").unwrap()
                < TENANT_CARD_REFERENCES_LOCK_SQL.find("user_card").unwrap(),
            "guard must read cards after the tenant source row lock (tenant -> cards order)"
        );
    }
}
