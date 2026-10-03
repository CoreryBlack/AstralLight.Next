//! 会话 durable 状态仓储 — SessionStateRepository（Redis-free 路径）。
//!
//! 职责边界：
//! - **strict 读取**：单条 JOIN（`auth_session_jti_index` ×
//!   `auth_device_session` × `auth_token_family` × `user_card` ×
//!   `identity_card`）返回会话 durable 事实，供
//!   `astral_common::session_projection_store` 逐项绑定评估。任何 JOIN
//!   不上（含 identity/user card 失活）→ `Ok(None)` → Gateway Deny；
//!   SQL 失败 → `Err` → Gateway 503（fail-closed，绝不折算成 None）。
//! - **durable 写入**：签发 proof（jti index INSERT...SELECT 门控）、撤销
//!   关闭（单语句 CAS）与 MQ 可调用的撤销投影 helper（durable 关闭 +
//!   进程内镜像/注册表登记；无 Redis 依赖）。
//! - **durable nonce/replay guard**：`auth_internal_request_guard` 表上的
//!   "purge 过期 + UNIQUE INSERT" 原子声明，多节点安全（UNIQUE 约束即
//!   分布式互斥），替代本地 HashSet/Redis SET NX。
//!
//! 编排（撤销顺序、事务边界、family 级联）仍保留在调用方（astral-identity
//! `srv::session` / astral-mq consumers），本文件只承载单语句原子 SQL 与
//! 纯评估函数。

use sqlx::MySqlPool;
use time::PrimitiveDateTime;

use astral_common::session_projection_store::{
    evaluate_access_fact, AccessSessionDurableFact, AccessSessionSource, IssuedAccessGrant,
    SessionBindContext, SessionProjectionDecision, SessionProjectionStore,
    VerifiedAccessSessionFact,
};
use astral_types::AstralError;

/// 撤销登记 TTL：进程内镜像/注册表撤销条目覆盖窗口（对齐既有
/// `jwt:revoked:{jti}` 7 天语义，覆盖 access token 最大生命周期）。
pub const REVOCATION_MIRROR_TTL_SECS: u64 = 7 * 24 * 3600;

/// Strict durable session fact lookup using the historical card-anchored reader contract.
pub async fn load_active_access_session_fact(
    pool: &MySqlPool,
    jti: &str,
    identity_card_id: i64,
) -> Result<Option<AccessSessionDurableFact>, sqlx::Error> {
    Ok(
        load_verified_platform_access_session_fact(pool, jti, identity_card_id)
            .await?
            .map(|verified| verified.fact),
    )
}

/// Strict PlatformUser session facts; historical rows with NULL/mismatched
/// credential revisions are not backfilled or accepted as proof.
pub async fn load_active_platform_access_session_fact(
    pool: &MySqlPool,
    jti: &str,
    identity_card_id: i64,
) -> Result<Option<AccessSessionDurableFact>, sqlx::Error> {
    Ok(
        load_verified_platform_access_session_fact(pool, jti, identity_card_id)
            .await?
            .map(|verified| verified.fact),
    )
}

#[allow(dead_code)]
async fn load_verified_access_session_fact(
    pool: &MySqlPool,
    jti: &str,
    identity_card_id: i64,
) -> Result<Option<VerifiedAccessSessionFact>, sqlx::Error> {
    if jti.trim().is_empty() || jti.len() > 255 || identity_card_id <= 0 {
        return Ok(None);
    }
    let row = sqlx::query_as::<_, AccessSessionFactRow>(
        "SELECT i.session_id, i.user_id, i.session_epoch, i.status AS jti_status, \
                i.expires_at, s.family_id, s.status AS session_status, s.session_state, \
                s.session_version, s.current_user_card_id, \
                uc.tenant_id AS user_card_tenant_id, \
                uc.domain_id AS user_card_domain_id, uc.card_status AS user_card_status, \
                f.status AS family_status, ic.expires_at AS identity_expires_at, \
                uc.valid_until AS card_valid_until, f.expires_at AS family_expires_at, \
                s.refresh_expires_at AS session_expires_at \
         FROM auth_session_jti_index i \
         INNER JOIN auth_device_session s ON s.session_id = i.session_id AND s.user_id = i.user_id \
           AND s.session_epoch = i.session_epoch \
         INNER JOIN platform_user pu ON pu.user_id = s.user_id \
           AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
         LEFT JOIN auth_token_family f ON f.family_id = s.family_id AND f.user_id = s.user_id \
           AND (f.expires_at IS NULL OR f.expires_at > UTC_TIMESTAMP()) \
         INNER JOIN identity_card ic ON ic.card_id = ? AND ic.user_id = s.user_id \
           AND ic.status = 'ACTIVE' \
           AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
         LEFT JOIN user_card uc ON uc.card_id = s.current_user_card_id AND uc.user_id = s.user_id \
           AND uc.card_type != 'LEVEL_TEMPLATE_CARD' \
           AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
           AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
         LEFT JOIN tenant t ON t.tenant_id = uc.tenant_id \
         LEFT JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id AND tdm.domain_id = uc.domain_id \
         WHERE i.jti = ? \
           AND (s.refresh_expires_at IS NULL OR s.refresh_expires_at > UTC_TIMESTAMP()) \
           AND (s.current_user_card_id IS NULL OR (uc.card_id IS NOT NULL AND t.status = 'ACTIVE' AND tdm.status = 'ACTIVE')) \
         LIMIT 1",
    )
    .bind(identity_card_id)
    .bind(jti)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| {
        let cache_valid_until_epoch_second = row.cache_valid_until_epoch_second();
        VerifiedAccessSessionFact {
            fact: row.into_durable_fact(),
            cache_valid_until_epoch_second,
        }
    }))
}

async fn load_verified_app_access_session_fact(
    pool: &MySqlPool,
    jti: &str,
) -> Result<Option<VerifiedAccessSessionFact>, sqlx::Error> {
    if jti.trim().is_empty() || jti.len() > 255 {
        return Ok(None);
    }
    let row = sqlx::query_as::<_, AccessSessionFactRow>(
        "SELECT i.session_id, i.user_id, i.session_epoch, i.status AS jti_status, \
                i.expires_at, s.family_id, s.status AS session_status, s.session_state, \
                s.session_version, s.current_user_card_id, NULL AS session_credential_version, \
                NULL AS user_card_tenant_id, NULL AS user_card_domain_id, NULL AS user_card_status, \
                f.status AS family_status, ic.expires_at AS identity_expires_at, \
                NULL AS card_valid_until, f.expires_at AS family_expires_at, \
                s.refresh_expires_at AS session_expires_at \
         FROM auth_session_jti_index i \
         INNER JOIN auth_device_session s ON s.session_id = i.session_id AND s.user_id = i.user_id \
           AND s.session_epoch = i.session_epoch \
         INNER JOIN platform_user pu ON pu.user_id = s.user_id \
           AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
         INNER JOIN identity_card ic ON ic.user_id = s.user_id AND ic.status = 'ACTIVE' \
           AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
         LEFT JOIN auth_token_family f ON f.family_id = s.family_id AND f.user_id = s.user_id \
           AND (f.expires_at IS NULL OR f.expires_at > UTC_TIMESTAMP()) \
         WHERE i.jti = ? AND s.current_user_card_id IS NULL \
           AND s.credential_version IS NULL \
           AND (s.refresh_expires_at IS NULL OR s.refresh_expires_at > UTC_TIMESTAMP()) \
         LIMIT 1",
    )
    .bind(jti)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| {
        let cache_valid_until_epoch_second = row.cache_valid_until_epoch_second();
        VerifiedAccessSessionFact {
            fact: row.into_durable_fact(),
            cache_valid_until_epoch_second,
        }
    }))
}

async fn load_verified_platform_access_session_fact(
    pool: &MySqlPool,
    jti: &str,
    identity_card_id: i64,
) -> Result<Option<VerifiedAccessSessionFact>, sqlx::Error> {
    if jti.trim().is_empty() || jti.len() > 255 || identity_card_id <= 0 {
        return Ok(None);
    }
    let row = sqlx::query_as::<_, AccessSessionFactRow>(
        "SELECT i.session_id, i.user_id, i.session_epoch, i.status AS jti_status, \
                i.expires_at, s.family_id, s.status AS session_status, s.session_state, \
                s.session_version, s.current_user_card_id, s.credential_version AS session_credential_version, \
                uc.tenant_id AS user_card_tenant_id, \
                uc.domain_id AS user_card_domain_id, uc.card_status AS user_card_status, \
                f.status AS family_status, ic.expires_at AS identity_expires_at, \
                uc.valid_until AS card_valid_until, f.expires_at AS family_expires_at, \
                s.refresh_expires_at AS session_expires_at \
         FROM auth_session_jti_index i \
         INNER JOIN auth_device_session s ON s.session_id = i.session_id AND s.user_id = i.user_id \
           AND s.session_epoch = i.session_epoch \
         INNER JOIN platform_user pu ON pu.user_id = s.user_id \
           AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
         INNER JOIN user_local_credential lc ON lc.user_id = s.user_id AND lc.status = 'ACTIVE' \
           AND s.credential_version IS NOT NULL AND s.credential_version > 0 \
           AND lc.credential_version = s.credential_version \
         LEFT JOIN auth_token_family f ON f.family_id = s.family_id AND f.user_id = s.user_id \
           AND (f.expires_at IS NULL OR f.expires_at > UTC_TIMESTAMP()) \
         INNER JOIN identity_card ic ON ic.card_id = ? AND ic.user_id = s.user_id \
           AND ic.status = 'ACTIVE' \
           AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
         LEFT JOIN user_card uc ON uc.card_id = s.current_user_card_id AND uc.user_id = s.user_id \
           AND uc.card_type != 'LEVEL_TEMPLATE_CARD' \
           AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
           AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
         LEFT JOIN tenant t ON t.tenant_id = uc.tenant_id \
         LEFT JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id AND tdm.domain_id = uc.domain_id \
         WHERE i.jti = ? \
           AND (s.refresh_expires_at IS NULL OR s.refresh_expires_at > UTC_TIMESTAMP()) \
           AND (s.current_user_card_id IS NULL OR (uc.card_id IS NOT NULL AND t.status = 'ACTIVE' AND tdm.status = 'ACTIVE')) \
         LIMIT 1",
    )
    .bind(identity_card_id)
    .bind(jti)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|row| {
        let cache_valid_until_epoch_second = row.cache_valid_until_epoch_second();
        VerifiedAccessSessionFact {
            fact: row.into_durable_fact(),
            cache_valid_until_epoch_second,
        }
    }))
}

/// sqlx 行映射（私有；DATETIME 经 `time` feature 映射为 `PrimitiveDateTime`）。
#[derive(Debug, sqlx::FromRow)]
struct AccessSessionFactRow {
    session_id: i64,
    user_id: i64,
    session_epoch: i64,
    jti_status: String,
    session_version: i64,
    #[allow(dead_code)]
    session_credential_version: Option<i64>,
    expires_at: Option<PrimitiveDateTime>,
    family_id: i64,
    session_status: String,
    session_state: String,
    current_user_card_id: Option<i64>,
    user_card_tenant_id: Option<i64>,
    user_card_domain_id: Option<i64>,
    user_card_status: Option<String>,
    family_status: Option<String>,
    identity_expires_at: Option<PrimitiveDateTime>,
    card_valid_until: Option<PrimitiveDateTime>,
    family_expires_at: Option<PrimitiveDateTime>,
    session_expires_at: Option<PrimitiveDateTime>,
}

impl AccessSessionFactRow {
    fn cache_valid_until_epoch_second(&self) -> Option<i64> {
        [
            self.expires_at,
            self.identity_expires_at,
            self.card_valid_until,
            self.family_expires_at,
            self.session_expires_at,
        ]
        .into_iter()
        .flatten()
        .map(primitive_to_epoch_second)
        .min()
    }

    fn into_durable_fact(self) -> AccessSessionDurableFact {
        AccessSessionDurableFact {
            session_id: self.session_id,
            user_id: self.user_id,
            session_version: self.session_version,
            session_epoch: self.session_epoch,
            family_id: self.family_id,
            current_user_card_id: self.current_user_card_id,
            user_card_tenant_id: self.user_card_tenant_id,
            user_card_domain_id: self.user_card_domain_id,
            jti_status: self.jti_status,
            session_status: self.session_status,
            session_state: self.session_state,
            family_status: self.family_status,
            user_card_status: self.user_card_status,
            jti_expires_at_epoch_second: self.expires_at.map(primitive_to_epoch_second),
        }
    }
}

/// DATETIME（UTC 会话时区，见 astral-db 连接契约）→ epoch second。
fn primitive_to_epoch_second(value: PrimitiveDateTime) -> i64 {
    let offset = value.assume_utc();
    offset.unix_timestamp()
}

/// `AccessSessionSource` 的 MySQL 实现（strict，无缓存语义；
/// 进程内镜像加速由 [`SessionProjectionStore`] 组合层负责）。
pub struct MySqlAccessSessionSource {
    pool: MySqlPool,
}

impl MySqlAccessSessionSource {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl AccessSessionSource for MySqlAccessSessionSource {
    async fn load_access_fact_with_validity(
        &self,
        jti: &str,
        bind: &SessionBindContext,
    ) -> Result<Option<VerifiedAccessSessionFact>, String> {
        let fact = match astral_common::token_contract::PrincipalKind::parse(bind.principal_kind) {
            Some(astral_common::token_contract::PrincipalKind::PlatformUser) => {
                load_verified_platform_access_session_fact(
                    &self.pool,
                    jti,
                    bind.identity_card_id.unwrap_or(0),
                )
                .await
            }
            Some(astral_common::token_contract::PrincipalKind::AppUser) => {
                load_verified_app_access_session_fact(&self.pool, jti).await
            }
            None => Ok(None),
        };
        fact.map_err(|error| format!("load access session fact failed: {error}"))
    }

    async fn load_access_fact(
        &self,
        jti: &str,
        bind: &SessionBindContext,
    ) -> Result<Option<AccessSessionDurableFact>, String> {
        // identity_card 绑定取自 claims；缺失/非法直接按"事实不存在"处理
        // （Gateway 侧已有 validated_subject / principal 校验，这里双保险）。
        match astral_common::token_contract::PrincipalKind::parse(bind.principal_kind) {
            Some(astral_common::token_contract::PrincipalKind::PlatformUser) => {
                load_active_platform_access_session_fact(
                    &self.pool,
                    jti,
                    bind.identity_card_id.unwrap_or(0),
                )
                .await
            }
            Some(astral_common::token_contract::PrincipalKind::AppUser) => {
                load_verified_app_access_session_fact(&self.pool, jti)
                    .await
                    .map(|verified| verified.map(|verified| verified.fact))
            }
            None => Ok(None),
        }
        .map_err(|error| format!("load access session fact failed: {error}"))
    }
}

/// 便捷安装：以 MySQL source（可选镜像）安装进程级
/// [`SessionProjectionStore`]。first-wins；重复安装返回 `false`。
pub fn install_global_mysql_session_projection_store(
    pool: MySqlPool,
    mirror: Option<astral_common::session_projection_store::SessionProjectionMirror>,
    policy: astral_common::session_projection_store::MirrorPolicy,
) -> bool {
    astral_common::session_projection_store::install_global_session_projection_store(
        std::sync::Arc::new(SessionProjectionStore::new(
            std::sync::Arc::new(MySqlAccessSessionSource::new(pool)),
            mirror,
            policy,
        )),
    )
}

/// 签发 proof：jti index INSERT...SELECT 门控于 durable session 仍 ACTIVE
/// 且 epoch 一致（自 `srv::session` 下沉的单语句原子写；行数 != 1 视为
/// 会话已不活跃，签发必须失败）。
pub async fn record_session_jti_proof(
    pool: &MySqlPool,
    session_id: i64,
    jti: &str,
    user_id: i64,
    session_epoch: i64,
    expires_at_epoch_second: i64,
) -> Result<(), AstralError> {
    let guard = crate::memory_projection_hub::acquire_source_guard()?;
    if let Some(guard) = guard.as_ref() {
        guard.mark_commit_started();
    }
    let result = sqlx::query(
        "INSERT INTO auth_session_jti_index \
         (session_id, jti, user_id, session_epoch, status, issued_at, expires_at) \
         SELECT ?, ?, ?, ?, 'ACTIVE', UTC_TIMESTAMP(), FROM_UNIXTIME(?) \
         FROM auth_device_session \
         WHERE session_id = ? AND user_id = ? AND status = 'ACTIVE' \
           AND session_state = 'ACTIVE' AND session_epoch = ?",
    )
    .bind(session_id)
    .bind(jti)
    .bind(user_id)
    .bind(session_epoch)
    .bind(expires_at_epoch_second)
    .bind(session_id)
    .bind(user_id)
    .bind(session_epoch)
    .execute(pool)
    .await
    .map_err(|e| AstralError::Database(format!("Record session JTI index failed: {e}")))?;
    if let Some(guard) = guard.as_ref() {
        guard.mark_commit_proven();
    }
    if result.rows_affected() != 1 {
        return Err(AstralError::Auth(
            "Session is no longer active for access projection".into(),
        ));
    }
    Ok(())
}

/// Strict PlatformUser proof: fence the current local credential revision and
/// verify the pinned identity/user-card pair, status windows, tenant and domain.
pub async fn record_platform_session_jti_proof(
    pool: &MySqlPool,
    session_id: i64,
    jti: &str,
    user_id: i64,
    session_epoch: i64,
    expires_at_epoch_second: i64,
    identity_card_id: i64,
) -> Result<(), AstralError> {
    let guard = crate::memory_projection_hub::acquire_source_guard()?;
    if let Some(guard) = guard.as_ref() {
        guard.mark_commit_started();
    }
    let result = sqlx::query(
        "INSERT INTO auth_session_jti_index \
         (session_id, jti, user_id, session_epoch, status, issued_at, expires_at) \
         SELECT ?, ?, ?, ?, 'ACTIVE', UTC_TIMESTAMP(), FROM_UNIXTIME(?) \
         FROM auth_device_session s \
         INNER JOIN user_local_credential lc ON lc.user_id = s.user_id \
           AND lc.status = 'ACTIVE' AND lc.credential_version = s.credential_version \
         INNER JOIN platform_user pu ON pu.user_id = s.user_id \
           AND pu.status = 'ACTIVE' AND pu.deleted_at IS NULL \
         INNER JOIN identity_card ic ON ic.user_id = s.user_id AND ic.card_id = ? \
           AND ic.status = 'ACTIVE' AND (ic.expires_at IS NULL OR ic.expires_at >= UTC_TIMESTAMP()) \
         INNER JOIN user_card uc ON uc.card_id = s.current_user_card_id AND uc.user_id = s.user_id \
           AND uc.card_status = 'ACTIVE' AND uc.card_type != 'LEVEL_TEMPLATE_CARD' \
           AND (uc.valid_from IS NULL OR uc.valid_from <= UTC_TIMESTAMP()) \
           AND (uc.valid_until IS NULL OR uc.valid_until >= UTC_TIMESTAMP()) \
         INNER JOIN tenant t ON t.tenant_id = uc.tenant_id AND t.status = 'ACTIVE' \
         INNER JOIN tenant_domain_map tdm ON tdm.tenant_id = uc.tenant_id \
           AND tdm.domain_id = uc.domain_id AND tdm.status = 'ACTIVE' \
         WHERE s.session_id = ? AND s.user_id = ? AND s.status = 'ACTIVE' \
           AND s.session_state = 'ACTIVE' AND s.session_epoch = ? \
           AND s.credential_version IS NOT NULL AND s.credential_version > 0 \
           AND uc.tenant_id > 0 AND uc.domain_id > 0",
    )
    .bind(session_id)
    .bind(jti)
    .bind(user_id)
    .bind(session_epoch)
    .bind(expires_at_epoch_second)
    .bind(identity_card_id)
    .bind(session_id)
    .bind(user_id)
    .bind(session_epoch)
    .execute(pool)
    .await
    .map_err(|e| AstralError::Database(format!("Record PlatformUser session JTI proof failed: {e}")))?;
    if let Some(guard) = guard.as_ref() {
        guard.mark_commit_proven();
    }
    if result.rows_affected() != 1 {
        return Err(AstralError::Auth(
            "PlatformUser session is not eligible for access proof".into(),
        ));
    }
    Ok(())
}

/// 列出会话当前 ACTIVE 且未过期的 jti（撤销 fan-out 输入）。
pub async fn load_active_jtis_by_session(
    pool: &MySqlPool,
    session_id: i64,
) -> Result<Vec<String>, AstralError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT jti FROM auth_session_jti_index \
         WHERE session_id = ? AND status = 'ACTIVE' \
           AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())",
    )
    .bind(session_id)
    .fetch_all(pool)
    .await
    .map_err(|e| AstralError::Database(format!("Load session JTI index failed: {e}")))?;
    Ok(rows.into_iter().map(|(jti,)| jti).collect())
}

/// 列出会话指定 epoch 之前的 ACTIVE jti（refresh/switch 轮换 fan-out 输入）。
pub async fn load_active_jtis_by_session_before_epoch(
    pool: &MySqlPool,
    session_id: i64,
    epoch_exclusive: i64,
) -> Result<Vec<String>, AstralError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT jti FROM auth_session_jti_index \
         WHERE session_id = ? AND session_epoch < ? AND status = 'ACTIVE' \
           AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())",
    )
    .bind(session_id)
    .bind(epoch_exclusive)
    .fetch_all(pool)
    .await
    .map_err(|e| AstralError::Database(format!("Load prior session JTI index failed: {e}")))?;
    Ok(rows.into_iter().map(|(jti,)| jti).collect())
}

/// 列出用户全部 ACTIVE jti（user 级撤销 fan-out 输入）。
pub async fn load_active_jtis_by_user(
    pool: &MySqlPool,
    user_id: i64,
) -> Result<Vec<String>, AstralError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT jti FROM auth_session_jti_index \
         WHERE user_id = ? AND status = 'ACTIVE' \
           AND (expires_at IS NULL OR expires_at > UTC_TIMESTAMP())",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .map_err(|e| AstralError::Database(format!("Load user JTI index failed: {e}")))?;
    Ok(rows.into_iter().map(|(jti,)| jti).collect())
}

/// 按 jti 关闭 durable proof（单语句 CAS；返回影响行数）。
pub async fn close_jti_proof(pool: &MySqlPool, jti: &str) -> Result<u64, AstralError> {
    let guard = crate::memory_projection_hub::acquire_source_guard()?;
    if let Some(guard) = guard.as_ref() {
        guard.mark_commit_started();
    }
    let result = sqlx::query(
        "UPDATE auth_session_jti_index SET status = 'DELETED', updated_at = UTC_TIMESTAMP() \
         WHERE jti = ? AND status = 'ACTIVE'",
    )
    .bind(jti)
    .execute(pool)
    .await
    .map_err(|e| AstralError::Database(format!("Close access JTI index failed: {e}")))?;
    if let Some(guard) = guard.as_ref() {
        guard.mark_commit_proven();
    }
    Ok(result.rows_affected())
}

/// 按会话关闭 durable proof。
pub async fn close_jti_proofs_by_session(
    pool: &MySqlPool,
    session_id: i64,
) -> Result<u64, AstralError> {
    let guard = crate::memory_projection_hub::acquire_source_guard()?;
    if let Some(guard) = guard.as_ref() {
        guard.mark_commit_started();
    }
    let result = sqlx::query(
        "UPDATE auth_session_jti_index SET status = 'DELETED', updated_at = UTC_TIMESTAMP() \
         WHERE session_id = ? AND status = 'ACTIVE'",
    )
    .bind(session_id)
    .execute(pool)
    .await
    .map_err(|e| AstralError::Database(format!("Close session JTI index failed: {e}")))?;
    if let Some(guard) = guard.as_ref() {
        guard.mark_commit_proven();
    }
    Ok(result.rows_affected())
}

/// 按会话 + epoch 上界关闭 durable proof（轮换路径）。
pub async fn close_jti_proofs_by_session_before_epoch(
    pool: &MySqlPool,
    session_id: i64,
    epoch_exclusive: i64,
) -> Result<u64, AstralError> {
    let guard = crate::memory_projection_hub::acquire_source_guard()?;
    if let Some(guard) = guard.as_ref() {
        guard.mark_commit_started();
    }
    let result = sqlx::query(
        "UPDATE auth_session_jti_index SET status = 'DELETED', updated_at = UTC_TIMESTAMP() \
         WHERE session_id = ? AND session_epoch < ? AND status = 'ACTIVE'",
    )
    .bind(session_id)
    .bind(epoch_exclusive)
    .execute(pool)
    .await
    .map_err(|e| AstralError::Database(format!("Close prior session JTI index failed: {e}")))?;
    if let Some(guard) = guard.as_ref() {
        guard.mark_commit_proven();
    }
    Ok(result.rows_affected())
}

/// 按 jti 清单登记撤销到进程内加速面（镜像 + 既有 session_revocation_registry）。
///
/// 幂等、无 Redis 依赖；TTL 7 天对齐既有 `jwt:revoked:{jti}` 覆盖窗口。
pub fn note_revocations_in_process(jtis: &[String], ttl_seconds: u64) {
    let Some(store) = astral_common::session_projection_store::global_session_projection_store()
    else {
        return;
    };
    for jti in jtis {
        store.note_revocation(jti, ttl_seconds);
    }
}

/// MQ 可调用撤销投影 helper（Redis-free）：
/// 1. durable 关闭 jti proof（`status='DELETED'`，严格 Err 传播）；
/// 2. 进程内镜像/注册表登记（best-effort 加速面）。
///
/// 调用方（astral-mq consumers / Identity 撤销编排）在此之外自行处理
/// outbox 状态迁移与可选的 Redis 兼容 adapter 写入。Redis-free 默认路径
/// 下，第 1 步即为 Gateway strict 判定的权威事实。
pub async fn apply_revocation_projection_mysql(
    pool: &MySqlPool,
    jtis: &[String],
) -> Result<(), AstralError> {
    for jti in jtis {
        if jti.trim().is_empty() {
            continue;
        }
        close_jti_proof(pool, jti).await?;
    }
    note_revocations_in_process(jtis, REVOCATION_MIRROR_TTL_SECS);
    Ok(())
}

/// strict 租户状态读取（Gateway Step 6 的 Redis-free 替代；
/// `Ok(None)` = 租户状态不可证明 → 调用方 503）。
pub async fn load_tenant_status_strict(
    pool: &MySqlPool,
    tenant_id: i64,
) -> Result<Option<String>, sqlx::Error> {
    if tenant_id <= 0 {
        return Ok(None);
    }
    let status: Option<(String,)> =
        sqlx::query_as("SELECT status FROM tenant WHERE tenant_id = ? LIMIT 1")
            .bind(tenant_id)
            .fetch_optional(pool)
            .await?;
    Ok(status.map(|(status,)| status))
}

// ===== durable nonce/replay & idempotency guard（多节点安全） =====

/// guard 表 scope 常量（调用方共用，防止漂移）。
pub const GUARD_SCOPE_GATEWAY_REPLAY: &str = "gateway-replay";
pub const GUARD_SCOPE_GATEWAY_IDEMPOTENCY: &str = "gateway-idempotency";
/// Identity 侧 internal session guard scope：与 Gateway 声明按服务隔离
/// （replay_key/idempotency_key 已按 namespace 分域，scope 再分域一层，
/// 防止跨服务同键互踩）。
pub const GUARD_SCOPE_IDENTITY_REPLAY: &str = "identity-replay";
pub const GUARD_SCOPE_IDENTITY_IDEMPOTENCY: &str = "identity-idempotency";

/// guard 声明结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardClaim {
    /// 首次声明成功（UNIQUE INSERT 命中）。
    Claimed,
    /// 已存在（重放/重复请求）。
    Duplicate,
}

/// 幂等 marker 判定拒绝原因（typed，避免 `Result<_, ()>`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardMarkerRejection {
    /// 同 key 绑定不同请求体：幂等键冲突（调用方 409）。
    Conflict,
    /// guard 行不存在（并发 purge 竞态）：按拒绝处理，绝不重放。
    Missing,
}

/// guard 输入校验（纯函数）：scope/key 非空且有界，防止超长键打满表。
pub fn guard_input_is_valid(scope: &str, key: &str) -> bool {
    !scope.trim().is_empty() && scope.len() <= 64 && !key.trim().is_empty() && key.len() <= 255
}

/// durable nonce/replay 声明：purge 过期行 + UNIQUE INSERT。
///
/// 两节点并发声明同一 key 时只有一个 INSERT 成功（UNIQUE 约束即分布式
/// 互斥）；其余收到 duplicate-key → 按调用方语义转为 `Duplicate`。
/// TTL 由 `expires_at` 承载（purge 后同 key 可重新声明，等价 SET NX EX）。
pub async fn claim_replay_guard(
    pool: &MySqlPool,
    scope: &str,
    key: &str,
    ttl_seconds: i64,
) -> Result<GuardClaim, AstralError> {
    insert_guard_row(pool, scope, key, "1", ttl_seconds).await
}

/// durable 幂等声明（processing 标记，等价 Redis `SET NX EX processing:{hash}`）。
pub async fn claim_idempotency_guard(
    pool: &MySqlPool,
    scope: &str,
    key: &str,
    body_hash: &str,
    ttl_seconds: i64,
) -> Result<GuardClaim, AstralError> {
    insert_guard_row(
        pool,
        scope,
        key,
        &format!("processing:{body_hash}"),
        ttl_seconds,
    )
    .await
}

/// durable 幂等完成标记（等价 `SET completed:{hash} EX`）。
pub async fn complete_idempotency_guard(
    pool: &MySqlPool,
    scope: &str,
    key: &str,
    body_hash: &str,
    ttl_seconds: i64,
) -> Result<(), AstralError> {
    let marker = format!("completed:{body_hash}");
    let result = sqlx::query(
        "UPDATE auth_internal_request_guard \
         SET marker = ?, expires_at = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND) \
         WHERE guard_scope = ? AND guard_key = ?",
    )
    .bind(&marker)
    .bind(ttl_seconds.max(1))
    .bind(scope)
    .bind(key)
    .execute(pool)
    .await
    .map_err(|e| AstralError::Database(format!("Complete request guard failed: {e}")))?;
    if result.rows_affected() != 1 {
        return Err(AstralError::Internal("request guard row vanished".into()));
    }
    Ok(())
}

/// durable 幂等释放（等价 `DEL`；处理失败回滚 in-flight 标记时调用）。
pub async fn release_idempotency_guard(
    pool: &MySqlPool,
    scope: &str,
    key: &str,
) -> Result<(), AstralError> {
    sqlx::query("DELETE FROM auth_internal_request_guard WHERE guard_scope = ? AND guard_key = ?")
        .bind(scope)
        .bind(key)
        .execute(pool)
        .await
        .map_err(|e| AstralError::Database(format!("Release request guard failed: {e}")))?;
    Ok(())
}

/// 读取 guard 当前 marker（幂等重放判定用）。
pub async fn load_guard_marker(
    pool: &MySqlPool,
    scope: &str,
    key: &str,
) -> Result<Option<String>, AstralError> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT marker FROM auth_internal_request_guard WHERE guard_scope = ? AND guard_key = ?",
    )
    .bind(scope)
    .bind(key)
    .fetch_optional(pool)
    .await
    .map_err(|e| AstralError::Database(format!("Load request guard failed: {e}")))?;
    Ok(row.map(|(marker,)| marker))
}

/// 幂等 marker 判定（纯函数）：与 body hash 匹配 → Duplicate（同请求重放）；
/// 不匹配 → `Conflict`（同 key 异请求）；行消失 → `Missing`。
pub fn idempotency_marker_decision(
    marker: Option<&str>,
    body_hash: &str,
) -> Result<GuardClaim, GuardMarkerRejection> {
    match marker {
        Some(existing) if existing.ends_with(body_hash) => Ok(GuardClaim::Duplicate),
        Some(_) => Err(GuardMarkerRejection::Conflict),
        None => Err(GuardMarkerRejection::Missing),
    }
}

async fn insert_guard_row(
    pool: &MySqlPool,
    scope: &str,
    key: &str,
    marker: &str,
    ttl_seconds: i64,
) -> Result<GuardClaim, AstralError> {
    if !guard_input_is_valid(scope, key) {
        return Err(AstralError::Validation(
            "Request guard key is invalid".into(),
        ));
    }
    let purge = sqlx::query(
        "DELETE FROM auth_internal_request_guard \
         WHERE expires_at IS NOT NULL AND expires_at <= UTC_TIMESTAMP()",
    )
    .execute(pool)
    .await
    .map_err(|e| AstralError::Database(format!("Purge request guard failed: {e}")))?;
    tracing::debug!(deleted = purge.rows_affected(), "request guard purge");
    let insert = sqlx::query(
        "INSERT INTO auth_internal_request_guard \
         (guard_scope, guard_key, marker, expires_at) \
         VALUES (?, ?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND))",
    )
    .bind(scope)
    .bind(key)
    .bind(marker)
    .bind(ttl_seconds.max(1))
    .execute(pool)
    .await;
    match insert {
        Ok(_) => Ok(GuardClaim::Claimed),
        Err(sqlx::Error::Database(db_error)) if db_error.is_unique_violation() => {
            Ok(GuardClaim::Duplicate)
        }
        Err(error) => Err(AstralError::Database(format!(
            "Claim request guard failed: {error}"
        ))),
    }
}

// ===== 启动期 schema 契约（auth_internal_request_guard，fail-early） =====
//
// `auth_internal_request_guard`（迁移 20261001000001）承载 Redis-free
// Gateway/Identity 重放与幂等路径的 durable 互斥：UNIQUE `(guard_scope,
// guard_key)` 就是多节点互斥，`expires_at` 承载 TTL。缺表/缺列/唯一键漂移
// 属于启动期契约破坏——`connect_and_validate_schema` →
// `validate_schema_contract` 在服务接受任何请求前调用本检查，契约不满足即
// 启动失败（fail-early），绝不等到首个内部请求 claim 时才以 5xx 暴露。
// 迁移未应用的新部署同样在此拒绝启动：外部验收以"应用全部迁移后启动成功"
// 为最后一步。

/// guard 表名（迁移 `20261001000001_auth_internal_request_guard` 创建）。
pub const AUTH_INTERNAL_REQUEST_GUARD_TABLE: &str = "auth_internal_request_guard";

/// 分布式互斥唯一键名（迁移 DDL：`UNIQUE KEY uk_airg_scope_key`）。
pub const AUTH_INTERNAL_REQUEST_GUARD_UNIQUE_KEY: &str = "uk_airg_scope_key";

/// 仓储 SQL 触达的列（INSERT/UPDATE/SELECT/DELETE 全覆盖）+ AUTO_INCREMENT
/// 主键 `guard_id`；缺任一列都使上面的 durable 语义失效，按漂移拒绝启动。
const AUTH_INTERNAL_REQUEST_GUARD_REQUIRED_COLUMNS: &[&str] = &[
    "guard_id",
    "guard_scope",
    "guard_key",
    "marker",
    "expires_at",
];

/// 唯一键列序契约 `(seq_in_index, column)`：顺序/成员漂移即互斥键语义漂移
/// （例如 UNIQUE (guard_scope, guard_key, x) 不再阻止同 key 不同 x 的并发声明）。
const AUTH_INTERNAL_REQUEST_GUARD_UNIQUE_KEY_COLUMNS: &[(u64, &str)] =
    &[(1, "guard_scope"), (2, "guard_key")];

// information_schema 文本列在部分 sqlx 结果路径下呈现为 VARBINARY：与
// astral-db 迁移契约同形态——计数 CAST(... AS BINARY) 读取、严格 utf8 解码、
// 严格数字解析；任何解码/解析失败一律 fail-closed 报错而非放行。
const GUARD_TABLE_EXISTS_SQL: &str =
    "SELECT CAST(COUNT(*) AS BINARY) FROM information_schema.TABLES \
     WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) \
       AND CAST(TABLE_NAME AS BINARY) = CAST(? AS BINARY) \
       AND CAST(TABLE_TYPE AS BINARY) = CAST('BASE TABLE' AS BINARY)";
const GUARD_COLUMN_EXISTS_SQL: &str =
    "SELECT CAST(COUNT(*) AS BINARY) FROM information_schema.COLUMNS \
     WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) \
       AND CAST(TABLE_NAME AS BINARY) = CAST(? AS BINARY) \
       AND CAST(COLUMN_NAME AS BINARY) = CAST(? AS BINARY)";
const GUARD_KEY_COLUMN_STATS_SQL: &str =
    "SELECT CAST(COUNT(*) AS BINARY), CAST(MIN(NON_UNIQUE) AS BINARY), CAST(MAX(NON_UNIQUE) AS BINARY) \
     FROM information_schema.STATISTICS \
     WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) \
       AND CAST(TABLE_NAME AS BINARY) = CAST(? AS BINARY) \
       AND CAST(INDEX_NAME AS BINARY) = CAST(? AS BINARY)";
const GUARD_KEY_COLUMN_AT_SQL: &str =
    "SELECT CAST(COUNT(*) AS BINARY) FROM information_schema.STATISTICS \
     WHERE CAST(TABLE_SCHEMA AS BINARY) = CAST(DATABASE() AS BINARY) \
       AND CAST(TABLE_NAME AS BINARY) = CAST(? AS BINARY) \
       AND CAST(INDEX_NAME AS BINARY) = CAST(? AS BINARY) \
       AND SEQ_IN_INDEX = ? \
       AND CAST(COLUMN_NAME AS BINARY) = CAST(? AS BINARY)";

/// 严格解析 information_schema 的 `CAST(COUNT(...) AS BINARY)` 计数。
fn guard_metadata_count_value(raw: &[u8]) -> Result<u64, String> {
    let text = std::str::from_utf8(raw).map_err(|_| {
        format!("auth_internal_request_guard schema metadata is not valid UTF-8: {raw:02x?}")
    })?;
    text.trim()
        .parse::<u64>()
        .map_err(|_| format!("auth_internal_request_guard schema metadata is not a count: {text}"))
}

async fn guard_metadata_count(
    pool: &MySqlPool,
    sql: &'static str,
    binds: &[String],
) -> Result<u64, String> {
    let mut query = sqlx::query_scalar::<_, Vec<u8>>(sql);
    for bind in binds {
        query = query.bind(bind);
    }
    let raw = query.fetch_one(pool).await.map_err(|error| {
        format!("inspect {AUTH_INTERNAL_REQUEST_GUARD_TABLE} schema contract failed: {error}")
    })?;
    guard_metadata_count_value(&raw)
}

/// 唯一键实测形状：是否 UNIQUE、是否恰好按序覆盖 `(guard_scope, guard_key)`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuardUniqueKeyShape {
    is_unique: bool,
    covers_scope_key: bool,
}

async fn guard_unique_key_shape(pool: &MySqlPool) -> Result<GuardUniqueKeyShape, String> {
    let (count_raw, min_raw, max_raw): (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>) =
        sqlx::query_as(GUARD_KEY_COLUMN_STATS_SQL)
            .bind(AUTH_INTERNAL_REQUEST_GUARD_TABLE)
            .bind(AUTH_INTERNAL_REQUEST_GUARD_UNIQUE_KEY)
            .fetch_one(pool)
            .await
            .map_err(|error| {
                format!("inspect {AUTH_INTERNAL_REQUEST_GUARD_TABLE} unique key failed: {error}")
            })?;
    let column_count = guard_metadata_count_value(&count_raw)?;
    // 索引不存在时 MIN/MAX 为 NULL（None）；存在则必为 0（UNIQUE）。
    let is_unique = column_count > 0
        && matches!(
            (
                min_raw.as_deref().map(guard_metadata_count_value),
                max_raw.as_deref().map(guard_metadata_count_value),
            ),
            (Some(Ok(0)), Some(Ok(0)))
        );
    let mut covers_scope_key =
        column_count == AUTH_INTERNAL_REQUEST_GUARD_UNIQUE_KEY_COLUMNS.len() as u64;
    if covers_scope_key {
        for (seq_in_index, column) in AUTH_INTERNAL_REQUEST_GUARD_UNIQUE_KEY_COLUMNS {
            let at = guard_metadata_count(
                pool,
                GUARD_KEY_COLUMN_AT_SQL,
                &[
                    AUTH_INTERNAL_REQUEST_GUARD_TABLE.to_owned(),
                    AUTH_INTERNAL_REQUEST_GUARD_UNIQUE_KEY.to_owned(),
                    seq_in_index.to_string(),
                    (*column).to_owned(),
                ],
            )
            .await?;
            if at != 1 {
                covers_scope_key = false;
                break;
            }
        }
    }
    Ok(GuardUniqueKeyShape {
        is_unique,
        covers_scope_key,
    })
}

/// 纯裁决（无 IO，可单测）：契约事实 → 失败原因（`None` = 通过）。
/// 判定顺序即运维修复顺序：缺表 → 缺列 → 唯一键漂移。
fn auth_guard_contract_violation(
    table_exists: bool,
    missing_columns: &[String],
    unique_key_is_unique: bool,
    unique_key_covers_scope_key: bool,
) -> Option<String> {
    if !table_exists {
        return Some(
            "auth_internal_request_guard table is missing; the Redis-free replay/idempotency \
             guard would fail closed on every internal request: run migration \
             20261001000001_auth_internal_request_guard (with preflight and backup per \
             Docs/迁移/README.md) before starting services"
                .to_owned(),
        );
    }
    if !missing_columns.is_empty() {
        return Some(format!(
            "auth_internal_request_guard is missing required column(s) {}: schema drift fails closed",
            missing_columns.join(", ")
        ));
    }
    if !unique_key_is_unique || !unique_key_covers_scope_key {
        return Some(format!(
            "auth_internal_request_guard index {AUTH_INTERNAL_REQUEST_GUARD_UNIQUE_KEY} must be \
             UNIQUE and cover exactly (guard_scope, guard_key) in order; the UNIQUE constraint \
             is the multi-node claim mutex"
        ));
    }
    None
}

/// 启动期 `auth_internal_request_guard` schema 契约检查（fail-early）。
///
/// 由 `astral_db::validate_schema_contract` 在 `connect_and_validate_schema`
/// 启动链路中调用；返回的字符串是给运维的精确修复指引，调用方以
/// `MigrationError::Failed` 承载并拒绝启动。
pub async fn validate_auth_internal_request_guard_schema(pool: &MySqlPool) -> Result<(), String> {
    let table_count = guard_metadata_count(
        pool,
        GUARD_TABLE_EXISTS_SQL,
        &[AUTH_INTERNAL_REQUEST_GUARD_TABLE.to_owned()],
    )
    .await?;
    let table_exists = table_count == 1;
    let mut missing_columns = Vec::new();
    if table_exists {
        for column in AUTH_INTERNAL_REQUEST_GUARD_REQUIRED_COLUMNS {
            let count = guard_metadata_count(
                pool,
                GUARD_COLUMN_EXISTS_SQL,
                &[
                    AUTH_INTERNAL_REQUEST_GUARD_TABLE.to_owned(),
                    (*column).to_owned(),
                ],
            )
            .await?;
            if count == 0 {
                missing_columns.push((*column).to_owned());
            }
        }
    }
    let shape = if table_exists {
        guard_unique_key_shape(pool).await?
    } else {
        GuardUniqueKeyShape {
            is_unique: false,
            covers_scope_key: false,
        }
    };
    match auth_guard_contract_violation(
        table_exists,
        &missing_columns,
        shape.is_unique,
        shape.covers_scope_key,
    ) {
        Some(reason) => Err(reason),
        None => Ok(()),
    }
}

/// 签发侧镜像登记（**verified-only**）：任意外部快照不得直接进入镜像
/// Allow。本函数在登记前强制 strict DB 复核——用与 Gateway 完全相同的
/// durable fact JOIN + [`evaluate_access_fact`] 逐项绑定评估，仅当 durable
/// 事实判定 Allow 时才写入镜像。复核不过（proof 缺失/会话已关/绑定漂移）
/// 时不登记（返回 `false`），签发主链路仍以 durable proof 为准；镜像缺失
/// 只退化为 Gateway strict DB 读取，绝不放大授权。
pub async fn install_verified_access_grant(
    pool: &MySqlPool,
    grant: IssuedAccessGrant,
    bind: &SessionBindContext,
) -> Result<bool, AstralError> {
    // 无进程级 store（或 DenyOnly 策略 / 永久 suspect）时 positive 镜像无
    // 意义：跳过复核查询直接返回（durable proof 已由调用方写入；判定面每
    // 请求 strict DB）。
    let Some(store) = astral_common::session_projection_store::global_session_projection_store()
    else {
        return Ok(false);
    };
    if !store.mirror_positive_allowed() {
        return Ok(false);
    }
    let hub = crate::memory_projection_hub();
    let token = match hub.map(|hub| hub.auxiliary_read_gate()) {
        Some(crate::memory_projection_hub::AuxiliaryReadGate::Ready(token)) => Some(token),
        Some(
            crate::memory_projection_hub::AuxiliaryReadGate::WriterActive
            | crate::memory_projection_hub::AuxiliaryReadGate::Uncertain,
        ) => return Ok(false),
        Some(crate::memory_projection_hub::AuxiliaryReadGate::StrictRequired) => return Ok(false),
        None => None,
    };
    if !grant.matches_bind(bind) {
        return Ok(false);
    }
    let verification = async {
        match astral_common::token_contract::PrincipalKind::parse(bind.principal_kind) {
            Some(astral_common::token_contract::PrincipalKind::PlatformUser) => {
                load_verified_platform_access_session_fact(
                    pool,
                    grant.jti.trim(),
                    bind.identity_card_id.unwrap_or(0),
                )
                .await
            }
            Some(astral_common::token_contract::PrincipalKind::AppUser) => {
                load_verified_app_access_session_fact(pool, grant.jti.trim()).await
            }
            None => Ok(None),
        }
    };
    let verified = tokio::time::timeout(std::time::Duration::from_secs(3), verification)
        .await
        .map_err(|_| AstralError::Database("verify access grant proof timed out".to_owned()))?
        .map_err(|error| {
            AstralError::Database(format!("Verify access grant proof failed: {error}"))
        })?;
    let Some(verified) = verified else {
        return Ok(false);
    };
    if evaluate_access_fact(&verified.fact, bind).is_err() {
        return Ok(false);
    }
    let Some(valid_until) = verified.cache_valid_until_epoch_second else {
        return Ok(false);
    };
    if let (Some(hub), Some(token)) = (hub, token) {
        if !hub.auxiliary_read_matches(token) {
            return Ok(false);
        }
    }
    if let Some(mirror) = store.mirror() {
        mirror.install_grant_until(grant, valid_until);
    }
    if let (Some(hub), Some(token)) = (hub, token) {
        if !hub.auxiliary_read_matches(token) {
            if let Some(mirror) = store.mirror() {
                mirror.invalidate_all_grants();
            }
            return Ok(false);
        }
    }
    Ok(true)
}

/// 会话级保守镜像失效（撤销方没有逐 jti 清单时调用；no-op 安全）。
pub fn note_session_invalidated_in_process(session_id: i64) {
    if let Some(store) = astral_common::session_projection_store::global_session_projection_store()
    {
        store.note_session_invalidated(session_id);
    }
}

// ===== Identity credential/MFA schema contract (migration 20261003000001) =====

const IDENTITY_FENCE_REQUIRED_COLUMNS: &[(&str, &str)] = &[
    ("user_local_credential", "credential_version"),
    ("auth_device_session", "credential_version"),
    ("user_mfa", "last_totp_counter"),
    ("mfa_attempt_log", "attempt_code"),
    ("mfa_attempt_log", "status"),
    ("mfa_attempt_log", "user_agent"),
];

/// Startup contract for MFA attempt reservation, one-time factor consumption, and
/// credential-version fencing. The owning schema validator calls this before serving requests.
pub async fn validate_identity_credential_fence_schema(pool: &MySqlPool) -> Result<(), String> {
    for (table, column) in IDENTITY_FENCE_REQUIRED_COLUMNS {
        let count = guard_metadata_count(
            pool,
            GUARD_COLUMN_EXISTS_SQL,
            &[(*table).to_owned(), (*column).to_owned()],
        )
        .await?;
        if count != 1 {
            return Err(format!(
                "Identity credential/MFA schema missing {table}.{column}; apply migration 20261003000001_identity_credential_fence before starting Identity"
            ));
        }
    }
    for (table, index, columns) in [
        (
            "mfa_attempt_log",
            "uk_mal_attempt_code",
            &["attempt_code"][..],
        ),
        (
            "auth_device_session",
            "idx_ads_user_credential_version",
            &["user_id", "credential_version", "status"][..],
        ),
    ] {
        let (count_raw, min_raw, max_raw): (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>) =
            sqlx::query_as(GUARD_KEY_COLUMN_STATS_SQL)
                .bind(table)
                .bind(index)
                .fetch_one(pool)
                .await
                .map_err(|error| {
                    format!("Inspect Identity index {table}.{index} failed: {error}")
                })?;
        let count = guard_metadata_count_value(&count_raw)?;
        let unique = count > 0
            && matches!(
                (
                    min_raw.as_deref().map(guard_metadata_count_value),
                    max_raw.as_deref().map(guard_metadata_count_value)
                ),
                (Some(Ok(0)), Some(Ok(0)))
            );
        let expected_count = columns.len() as u64;
        let mut matches = count == expected_count;
        if matches {
            for (offset, column) in columns.iter().enumerate() {
                if guard_metadata_count(
                    pool,
                    GUARD_KEY_COLUMN_AT_SQL,
                    &[
                        table.to_owned(),
                        index.to_owned(),
                        (offset + 1).to_string(),
                        (*column).to_owned(),
                    ],
                )
                .await?
                    != 1
                {
                    matches = false;
                    break;
                }
            }
        }
        if !matches || (index == "uk_mal_attempt_code" && !unique) {
            return Err(format!(
                "Identity index {table}.{index} has incompatible columns/uniqueness; apply migration 20261003000001_identity_credential_fence"
            ));
        }
    }
    Ok(())
}

/// Gateway strict 判定入口：全局 store 缺失 → `Unavailable`（fail-closed）。
pub async fn verify_access_via_global_store(
    jti: &str,
    bind: &SessionBindContext,
) -> SessionProjectionDecision {
    let Some(store) = astral_common::session_projection_store::global_session_projection_store()
    else {
        return SessionProjectionDecision::Unavailable;
    };
    let Some(hub) = crate::memory_projection_hub() else {
        return store.verify_access(jti, bind).await;
    };
    match hub.auxiliary_read_gate() {
        crate::memory_projection_hub::AuxiliaryReadGate::Ready(token) => {
            store
                .verify_access_with_fence(jti, bind, || hub.auxiliary_read_matches(token))
                .await
        }
        crate::memory_projection_hub::AuxiliaryReadGate::StrictRequired => {
            let Some(token) = hub.strict_read_token() else {
                return SessionProjectionDecision::Unavailable;
            };
            let decision = store.verify_access_strict(jti, bind).await;
            if hub.strict_read_matches(token) {
                decision
            } else {
                SessionProjectionDecision::Unavailable
            }
        }
        crate::memory_projection_hub::AuxiliaryReadGate::WriterActive
        | crate::memory_projection_hub::AuxiliaryReadGate::Uncertain => {
            SessionProjectionDecision::Unavailable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::{Date, Month, Time};

    #[test]
    fn strict_platform_session_sql_requires_current_credential_and_epoch() {
        let source = include_str!("session_state_repository.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        let platform = source
            .split("async fn load_verified_platform_access_session_fact(")
            .nth(1)
            .unwrap()
            .split("struct AccessSessionFactRow")
            .next()
            .unwrap();
        assert!(platform.contains("lc.credential_version = s.credential_version"));
        assert!(platform.contains("s.credential_version IS NOT NULL AND s.credential_version > 0"));
        assert!(platform.contains("s.session_epoch = i.session_epoch"));
        let app = source
            .split("async fn load_verified_app_access_session_fact(")
            .nth(1)
            .unwrap()
            .split("async fn load_verified_platform_access_session_fact(")
            .next()
            .unwrap();
        assert!(app.contains("NULL AS session_credential_version"));
        assert!(app.contains("s.session_epoch = i.session_epoch"));
        assert!(!app.contains("JOIN user_local_credential"));
        assert!(!app.contains("JOIN user_card"));
        assert!(!source.contains("\\\\\n"));
    }

    fn utc(y: i32, m: Month, d: u8, h: u8) -> PrimitiveDateTime {
        PrimitiveDateTime::new(
            Date::from_calendar_date(y, m, d).unwrap(),
            Time::from_hms(h, 0, 0).unwrap(),
        )
    }

    #[test]
    fn session_cache_lifetime_uses_the_earliest_durable_physical_expiry() {
        let mut row = AccessSessionFactRow {
            session_id: 7,
            user_id: 42,
            session_epoch: 3,
            jti_status: "ACTIVE".into(),
            session_version: 2,
            session_credential_version: Some(1),
            expires_at: Some(utc(2026, Month::October, 1, 20)),
            family_id: 11,
            session_status: "ACTIVE".into(),
            session_state: "ACTIVE".into(),
            current_user_card_id: Some(40),
            user_card_tenant_id: Some(20),
            user_card_domain_id: Some(30),
            user_card_status: Some("ACTIVE".into()),
            family_status: Some("ACTIVE".into()),
            identity_expires_at: Some(utc(2026, Month::October, 1, 19)),
            card_valid_until: Some(utc(2026, Month::October, 1, 18)),
            family_expires_at: Some(utc(2026, Month::October, 1, 17)),
            session_expires_at: Some(utc(2026, Month::October, 1, 16)),
        };
        for hour in 16..=20 {
            assert_eq!(
                row.cache_valid_until_epoch_second(),
                Some(primitive_to_epoch_second(utc(
                    2026,
                    Month::October,
                    1,
                    hour
                )))
            );
            match hour {
                16 => row.session_expires_at = None,
                17 => row.family_expires_at = None,
                18 => row.card_valid_until = None,
                19 => row.identity_expires_at = None,
                _ => row.expires_at = None,
            }
        }
        assert_eq!(row.cache_valid_until_epoch_second(), None);
    }

    #[test]
    fn session_source_mutations_arm_before_autocommit_and_disarm_after_success() {
        let source = include_str!("session_state_repository.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for name in [
            "record_session_jti_proof",
            "close_jti_proof",
            "close_jti_proofs_by_session",
            "close_jti_proofs_by_session_before_epoch",
        ] {
            let start = production.find(&format!("pub async fn {name}(")).unwrap();
            let body = &production[start..];
            let end = body[1..]
                .find("\npub ")
                .map(|index| index + 1)
                .unwrap_or(body.len());
            let body = &body[..end];
            let guard = body.find("acquire_source_guard()?").unwrap();
            let arm = body.find("mark_commit_started()").unwrap();
            let statement = body.find("sqlx::query(").unwrap();
            let proven = body.find("mark_commit_proven()").unwrap();
            assert!(
                guard < arm && arm < statement && statement < proven,
                "{name}"
            );
        }
    }

    #[test]
    fn guard_input_boundaries_are_enforced() {
        assert!(guard_input_is_valid("gateway-replay", "nonce-1"));
        assert!(!guard_input_is_valid("", "k"));
        assert!(!guard_input_is_valid("s", ""));
        assert!(!guard_input_is_valid("s", "   "));
        let long_scope = "x".repeat(65);
        assert!(!guard_input_is_valid(&long_scope, "k"));
        let long_key = "x".repeat(256);
        assert!(!guard_input_is_valid("s", &long_key));
    }

    #[test]
    fn idempotency_marker_decision_matches_hash_suffix_only() {
        assert_eq!(
            idempotency_marker_decision(Some("processing:abc"), "abc"),
            Ok(GuardClaim::Duplicate)
        );
        assert_eq!(
            idempotency_marker_decision(Some("completed:abc"), "abc"),
            Ok(GuardClaim::Duplicate)
        );
        // 同 key 绑定不同 body → Conflict（调用方 409）。
        assert_eq!(
            idempotency_marker_decision(Some("processing:abc"), "abd"),
            Err(GuardMarkerRejection::Conflict)
        );
        // 行消失（并发 purge 竞态）→ Missing（调用方拒绝，不重放）。
        assert_eq!(
            idempotency_marker_decision(None, "abc"),
            Err(GuardMarkerRejection::Missing)
        );
    }

    #[test]
    fn datetime_to_epoch_conversion_is_utc_based() {
        let epoch = primitive_to_epoch_second(utc(2026, Month::January, 1, 0));
        assert_eq!(epoch, 1_767_225_600);
    }

    // ===== 启动期 auth_internal_request_guard 契约（纯裁决） =====

    #[test]
    fn guard_contract_missing_table_fails_with_migration_guidance() {
        let violation = auth_guard_contract_violation(false, &[], false, false)
            .expect("a missing guard table must fail the contract");
        assert!(violation.contains("auth_internal_request_guard table is missing"));
        assert!(violation.contains("20261001000001_auth_internal_request_guard"));
    }

    #[test]
    fn guard_contract_missing_columns_are_named_fail_closed() {
        let missing = vec!["expires_at".to_owned(), "marker".to_owned()];
        let violation = auth_guard_contract_violation(true, &missing, true, true)
            .expect("missing columns must fail the contract");
        assert!(violation.contains("expires_at"), "message: {violation}");
        assert!(violation.contains("marker"), "message: {violation}");
    }

    #[test]
    fn guard_contract_unique_key_drift_fails_closed() {
        // 非唯一索引：互斥语义被破坏。
        let violation = auth_guard_contract_violation(true, &[], false, true)
            .expect("a non-unique scope/key index must fail the contract");
        assert!(violation.contains(AUTH_INTERNAL_REQUEST_GUARD_UNIQUE_KEY));
        // 列成员/顺序漂移（如多出一列）：同 key 声明可被绕过。
        let violation = auth_guard_contract_violation(true, &[], true, false)
            .expect("a drifted key column set must fail the contract");
        assert!(violation.contains("guard_scope"));
        assert!(violation.contains("guard_key"));
    }

    #[test]
    fn guard_contract_passes_only_with_table_columns_and_exact_unique_key() {
        assert_eq!(
            auth_guard_contract_violation(true, &[], true, true),
            None,
            "complete table + columns + exact unique key must pass"
        );
    }

    #[test]
    fn guard_unique_key_columns_pin_scope_then_key_order() {
        // 列序是互斥键语义的一部分：必须恰好是 (guard_scope, guard_key)。
        assert_eq!(
            AUTH_INTERNAL_REQUEST_GUARD_UNIQUE_KEY_COLUMNS,
            &[(1, "guard_scope"), (2, "guard_key")]
        );
    }

    #[test]
    fn guard_required_columns_cover_every_repository_sql_column() {
        // 仓储 SQL 触达的列全部在契约内（guard_scope/guard_key/marker/expires_at
        // + 自增主键 guard_id）；新增 SQL 触达列时必须同步扩展该契约。
        for column in [
            "guard_id",
            "guard_scope",
            "guard_key",
            "marker",
            "expires_at",
        ] {
            assert!(
                AUTH_INTERNAL_REQUEST_GUARD_REQUIRED_COLUMNS.contains(&column),
                "column {column} must stay in the startup contract"
            );
        }
    }

    #[test]
    fn guard_metadata_count_strictly_parses_binary_counts() {
        assert_eq!(guard_metadata_count_value(b"3"), Ok(3));
        assert_eq!(guard_metadata_count_value(b" 12 "), Ok(12));
        assert_eq!(guard_metadata_count_value(b"0"), Ok(0));
        assert!(guard_metadata_count_value(b"x").is_err());
        assert!(guard_metadata_count_value(b"1.5").is_err());
        assert!(guard_metadata_count_value(&[0xff, 0xfe]).is_err());
    }

    /// strict 判定拒绝路径必须在触碰 DB 之前由纯评估完成：
    /// 非法 jti / 非法 identity card 直接 None（Gateway → Deny）。
    #[tokio::test]
    async fn strict_fact_lookup_guards_inputs_before_db() {
        let pool = sqlx::MySqlPool::connect_lazy("mysql://127.0.0.1:1/astral")
            .expect("lazy pool construction should succeed");
        assert!(load_active_access_session_fact(&pool, "", 1)
            .await
            .unwrap()
            .is_none());
        assert!(load_active_access_session_fact(&pool, "jti", 0)
            .await
            .unwrap()
            .is_none());
        assert!(load_active_access_session_fact(&pool, "jti", -1)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn tenant_status_lookup_rejects_non_positive_ids() {
        let pool = sqlx::MySqlPool::connect_lazy("mysql://127.0.0.1:1/astral")
            .expect("lazy pool construction should succeed");
        assert!(load_tenant_status_strict(&pool, 0).await.unwrap().is_none());
    }
}
