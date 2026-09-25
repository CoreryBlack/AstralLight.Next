//! Identity /me 查询仓储
//!
//! 对齐 Java `UserDirectoryPort`、`CardPermissionContextQuery` 和 Mapper 只读边界。
//! 该模块只返回领域查询结果，不依赖 Axum 或 HTTP 响应类型。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

#[derive(Debug, Clone)]
pub struct ProfileRecord {
    pub user_id: i64,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub status: String,
    pub domain_id: Option<i64>,
    pub tenant_id: Option<i64>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserCardRecord {
    pub card_id: i64,
    pub user_id: Option<i64>,
    pub domain_id: Option<i64>,
    pub card_type: String,
    pub card_status: String,
    pub template_id: Option<i64>,
    pub level_id: Option<i64>,
    pub priority: Option<i32>,
    pub is_primary: Option<bool>,
    pub tenant_id: Option<i64>,
    pub template_code: Option<String>,
    pub template_name: Option<String>,
    pub level_code: Option<String>,
    pub level_name: Option<String>,
    pub level_no: Option<i32>,
    pub card_name: Option<String>,
    pub action_codes: Option<String>,
    pub rule_set_ids: Option<String>,
    pub overlay_rule_set_ids: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IdentityRecord {
    pub id: i64,
    pub provider: String,
    pub subject_key: String,
    pub account_key: Option<String>,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionRecord {
    pub resource_type: String,
    pub action_code: String,
}

#[async_trait]
pub trait MeRepository: Send + Sync {
    async fn find_profile(&self, user_id: i64) -> Result<Option<ProfileRecord>, AstralError>;

    async fn find_active_cards(&self, user_id: i64) -> Result<Vec<UserCardRecord>, AstralError>;

    async fn find_identities(&self, user_id: i64) -> Result<Vec<IdentityRecord>, AstralError>;

    /// Resolve only an explicitly requested or primary active user card.
    /// Identity cards are authentication records and never enter permission reads.
    async fn resolve_card(
        &self,
        user_id: i64,
        requested_card_id: Option<i64>,
    ) -> Result<Option<i64>, AstralError>;

    /// Load both CARD_ONLY and rule-set permissions using the current validity window.
    async fn find_effective_permissions(
        &self,
        card_id: i64,
    ) -> Result<Vec<PermissionRecord>, AstralError>;
}

pub struct SqlxMeRepository {
    db: MySqlPool,
}

impl SqlxMeRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl MeRepository for SqlxMeRepository {
    async fn find_profile(&self, user_id: i64) -> Result<Option<ProfileRecord>, AstralError> {
        let row = sqlx::query_as::<_, ProfileRow>(
            "SELECT u.user_id, u.display_name, u.email, u.phone, u.status, \
             uc.domain_id, uc.tenant_id \
             FROM platform_user u \
             LEFT JOIN user_card uc ON uc.user_id = u.user_id \
               AND uc.card_status = 'ACTIVE' \
               AND uc.card_type != 'LEVEL_TEMPLATE_CARD' \
               AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
               AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
             WHERE u.user_id = ? \
             ORDER BY uc.is_primary DESC, uc.priority ASC, uc.card_id ASC LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)?;

        Ok(row.map(|row| ProfileRecord {
            user_id: row.user_id,
            display_name: row.display_name,
            email: row.email,
            phone: row.phone,
            status: row.status,
            domain_id: row.domain_id,
            tenant_id: row.tenant_id,
        }))
    }

    async fn find_active_cards(&self, user_id: i64) -> Result<Vec<UserCardRecord>, AstralError> {
        // 卡域查询只含身份/平台目录展示字段（不含权限表）；权限摘要由共享快照查询批量回填
        let mut cards: Vec<UserCardRecord> = sqlx::query_as::<_, UserCardRecord>(
            "SELECT uc.card_id, uc.user_id, uc.domain_id, uc.card_type, uc.card_status, uc.template_id, \
             uc.level_id, uc.priority, uc.is_primary, uc.tenant_id, \
             t.template_code, t.template_name, l.level_code, l.level_name, l.level_no, \
             CONCAT(IFNULL(t.template_name,''), ' · ', IFNULL(l.level_name,'')) as card_name, \
             NULL as action_codes, NULL as rule_set_ids, NULL as overlay_rule_set_ids \
             FROM user_card uc \
             LEFT JOIN user_card_template t ON t.template_id = uc.template_id \
             LEFT JOIN user_card_level_definition l ON l.level_id = uc.level_id \
             WHERE uc.user_id = ? AND uc.card_status = 'ACTIVE' \
               AND uc.card_type != 'LEVEL_TEMPLATE_CARD' \
               AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
               AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
             ORDER BY uc.card_id",
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)?;

        // 批量回填权限摘要（快照读，无 N+1）
        let ids: Vec<i64> = cards.iter().map(|c| c.card_id).collect();
        let summaries = astral_db::load_card_permission_summaries(&self.db, &ids)
            .await
            .map_err(|e| AstralError::Database(format!("Identity card summaries failed: {e}")))?;
        for card in &mut cards {
            let summary = summaries.get(&card.card_id);
            card.action_codes = summary.and_then(|s| s.action_codes.clone());
            card.rule_set_ids = summary.and_then(|s| s.base_rule_set_ids.clone());
            card.overlay_rule_set_ids = summary.and_then(|s| s.overlay_rule_set_ids.clone());
        }
        Ok(cards)
    }

    async fn find_identities(&self, user_id: i64) -> Result<Vec<IdentityRecord>, AstralError> {
        let rows = sqlx::query_as::<_, IdentityRow>(
            "SELECT identity_id, provider, subject_key, account_key, verified \
             FROM user_identity WHERE user_id = ? ORDER BY identity_id",
        )
        .bind(user_id)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)?;

        Ok(rows
            .into_iter()
            .map(|row| IdentityRecord {
                id: row.identity_id,
                provider: row.provider,
                subject_key: row.subject_key,
                account_key: row.account_key,
                verified: row.verified,
            })
            .collect())
    }

    async fn resolve_card(
        &self,
        user_id: i64,
        requested_card_id: Option<i64>,
    ) -> Result<Option<i64>, AstralError> {
        if let Some(card_id) = requested_card_id {
            return sqlx::query_scalar::<_, i64>(
                "SELECT card_id FROM user_card \
                 WHERE card_id = ? AND user_id = ? AND card_status = 'ACTIVE' \
                   AND card_type != 'LEVEL_TEMPLATE_CARD' \
                   AND (valid_from IS NULL OR valid_from <= UTC_TIMESTAMP()) \
                   AND (valid_until IS NULL OR valid_until >= UTC_TIMESTAMP()) \
                 LIMIT 1",
            )
            .bind(card_id)
            .bind(user_id)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error);
        }

        sqlx::query_scalar::<_, i64>(
            "SELECT card_id FROM user_card \
             WHERE user_id = ? AND card_status = 'ACTIVE' \
               AND card_type != 'LEVEL_TEMPLATE_CARD' \
               AND (valid_from IS NULL OR valid_from <= UTC_TIMESTAMP()) \
               AND (valid_until IS NULL OR valid_until >= UTC_TIMESTAMP()) \
             ORDER BY is_primary DESC, priority ASC, card_id ASC LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn find_effective_permissions(
        &self,
        card_id: i64,
    ) -> Result<Vec<PermissionRecord>, AstralError> {
        // 权限视图读投影快照缓存（Cache-Aside + 投影门禁），不直读源表
        let rows = astral_db::find_effective_permissions_cached(&self.db, card_id)
            .await
            .map_err(|e| AstralError::Database(format!("Identity permissions failed: {e}")))?;

        Ok(rows
            .into_iter()
            .map(|row| PermissionRecord {
                resource_type: row.resource_type,
                action_code: row.action_code,
            })
            .collect())
    }
}

#[derive(Debug, sqlx::FromRow)]
struct ProfileRow {
    user_id: i64,
    display_name: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    status: String,
    domain_id: Option<i64>,
    tenant_id: Option<i64>,
}

#[derive(Debug, sqlx::FromRow)]
struct IdentityRow {
    identity_id: i64,
    provider: String,
    subject_key: String,
    account_key: Option<String>,
    verified: bool,
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Identity repository query failed: {error}"))
}
