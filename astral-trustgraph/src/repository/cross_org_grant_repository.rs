//! 跨组织授权数据访问 — CrossOrgGrantRepository
//!
//! 对齐 Java `CrossOrgGrantService` 边界（cross_org_grant 表）。
//!
//! **fail-closed 写边界**：`GrantSourceKind` 是封闭的规范来源集
//! （RULE_SET / DIRECT / DELEGATION / APPROVAL / SYSTEM，见
//! `astral_types::grant::GrantSourceKind`），cross_org_grant 不属于其中任何
//! 来源族，且当前没有任何 policy/projection 读者消费该表。因此本仓库的写入
//! 方法（`upsert_grant` / `revoke_grant` / `revoke_grant_with_reason`）在执行
//! 任何 INSERT/UPDATE 之前显式返回 `AstralError::NotImplemented`，防止端点
//! 制造无法被授权链路解释的误导性 durable 授权记录。
//!
//! `count_grants` / `list_grants` 保留为**纯 SELECT 的管理侧读取**
//! （administrative read），不是正式授权事实（authorization fact）；
//! 它们不参与 PolicyEngine 评估，也不得被用作放行依据。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::AstralError;

/// 跨组织授权写入统一返回的 fail-closed 说明（API 层经 `?` 透传为 501）。
pub(crate) const CROSS_ORG_GRANT_WRITE_UNSUPPORTED_MESSAGE: &str =
    "cross_org_grant durable writes are unsupported: GrantSourceKind is a closed canonical set \
     and no policy/projection reader consumes cross_org_grant, so an INSERT/UPDATE here would \
     create a misleading authorization record; list/count remain administrative reads only";

/// 跨组织授权记录（cross_org_grant）。
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CrossOrgGrantRecord {
    pub id: i64,
    pub from_org_id: i64,
    pub to_org_id: i64,
    pub resource: String,
    pub action: String,
    pub status: String,
    pub expires_at: Option<i64>,
    pub created_at: Option<i64>,
}

/// 撤销请求（Java 兼容 revokeCrossOrgPermission）
#[derive(Debug)]
pub struct RevokeGrant {
    pub id: i64,
    pub reason: Option<String>,
    pub revoked_by: Option<i64>,
}

const GRANT_SELECT_COLUMNS: &str = "id, from_org_id, to_org_id, resource, action, status, \
     UNIX_TIMESTAMP(expires_at) as expires_at, \
     UNIX_TIMESTAMP(created_at) as created_at";

#[async_trait]
pub trait CrossOrgGrantRepository: Send + Sync {
    /// 全量总数（管理侧读取，非授权事实）
    async fn count_grants(&self) -> Result<i64, AstralError>;
    /// 分页列表（ORDER BY id；管理侧读取，非授权事实）
    async fn list_grants(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<CrossOrgGrantRecord>, AstralError>;
    /// fail-closed：跨组织授权写入不受支持，在任何 INSERT/UPDATE 之前返回
    /// `AstralError::NotImplemented`（见模块文档的写边界说明）。
    async fn upsert_grant(
        &self,
        from_org_id: i64,
        to_org_id: i64,
        resource: &str,
        action: &str,
        expires_at: Option<i64>,
    ) -> Result<CrossOrgGrantRecord, AstralError>;
    /// fail-closed：撤销写入不受支持，在任何 UPDATE 之前返回
    /// `AstralError::NotImplemented`（见模块文档的写边界说明）。
    async fn revoke_grant(&self, id: i64) -> Result<bool, AstralError>;
    /// fail-closed：撤销写入不受支持，在任何 UPDATE 之前返回
    /// `AstralError::NotImplemented`（见模块文档的写边界说明）。
    async fn revoke_grant_with_reason(&self, revoke: &RevokeGrant) -> Result<bool, AstralError>;
}

pub struct SqlxCrossOrgGrantRepository {
    db: MySqlPool,
}

impl SqlxCrossOrgGrantRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl CrossOrgGrantRepository for SqlxCrossOrgGrantRepository {
    async fn count_grants(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM cross_org_grant")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_grants(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<CrossOrgGrantRecord>, AstralError> {
        sqlx::query_as::<_, CrossOrgGrantRecord>(&format!(
            "SELECT {GRANT_SELECT_COLUMNS} FROM cross_org_grant ORDER BY id LIMIT ? OFFSET ?"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn upsert_grant(
        &self,
        _from_org_id: i64,
        _to_org_id: i64,
        _resource: &str,
        _action: &str,
        _expires_at: Option<i64>,
    ) -> Result<CrossOrgGrantRecord, AstralError> {
        // fail-closed：在任何 INSERT/UPDATE 之前拒绝。若此处出现任何 SQL 执行，
        // 形状守卫测试（no_write_sql_is_present_in_the_write_paths）会失败。
        Err(AstralError::NotImplemented(
            CROSS_ORG_GRANT_WRITE_UNSUPPORTED_MESSAGE.into(),
        ))
    }

    async fn revoke_grant(&self, _id: i64) -> Result<bool, AstralError> {
        // fail-closed：在任何 UPDATE 之前拒绝。
        Err(AstralError::NotImplemented(
            CROSS_ORG_GRANT_WRITE_UNSUPPORTED_MESSAGE.into(),
        ))
    }

    async fn revoke_grant_with_reason(&self, _revoke: &RevokeGrant) -> Result<bool, AstralError> {
        // fail-closed：在任何 UPDATE 之前拒绝。
        Err(AstralError::NotImplemented(
            CROSS_ORG_GRANT_WRITE_UNSUPPORTED_MESSAGE.into(),
        ))
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Cross org grant repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// fail-closed 说明必须完整陈述边界依据：封闭的 GrantSourceKind 规范集、
    /// 无 policy/projection 读者消费、list/count 仅为管理侧读取。
    #[test]
    fn write_guard_message_states_the_closed_source_kind_boundary() {
        let message = CROSS_ORG_GRANT_WRITE_UNSUPPORTED_MESSAGE;
        assert!(message.contains("GrantSourceKind"));
        assert!(message.contains("closed canonical set"));
        assert!(message.contains("no policy/projection reader consumes cross_org_grant"));
        assert!(message.contains("INSERT/UPDATE"));
        assert!(message.contains("administrative reads only"));
    }

    /// 行为守卫：写入方法在任何 SQL 执行之前 fail-closed。使用 lazy 池（不发起
    /// 真实连接）：若实现越过守卫执行 SQL，将得到 Database 连接错误而非
    /// NotImplemented，测试即失败。
    #[tokio::test]
    async fn upsert_grant_fails_closed_before_any_write_sql() {
        let pool = MySqlPool::connect_lazy("mysql://localhost:1/astral_test").unwrap();
        let repo = SqlxCrossOrgGrantRepository::new(pool);

        let error = repo
            .upsert_grant(1, 2, "learn_course", "read", None)
            .await
            .expect_err("cross_org_grant upsert must fail closed");

        assert!(matches!(error, AstralError::NotImplemented(_)));
    }

    #[tokio::test]
    async fn revoke_grant_fails_closed_before_any_write_sql() {
        let pool = MySqlPool::connect_lazy("mysql://localhost:1/astral_test").unwrap();
        let repo = SqlxCrossOrgGrantRepository::new(pool);

        let error = repo
            .revoke_grant(7)
            .await
            .expect_err("cross_org_grant revoke must fail closed");

        assert!(matches!(error, AstralError::NotImplemented(_)));
    }

    #[tokio::test]
    async fn revoke_grant_with_reason_fails_closed_before_any_write_sql() {
        let pool = MySqlPool::connect_lazy("mysql://localhost:1/astral_test").unwrap();
        let repo = SqlxCrossOrgGrantRepository::new(pool);

        let error = repo
            .revoke_grant_with_reason(&RevokeGrant {
                id: 7,
                reason: Some("audit".into()),
                revoked_by: Some(1),
            })
            .await
            .expect_err("cross_org_grant revoke with reason must fail closed");

        assert!(matches!(error, AstralError::NotImplemented(_)));
    }

    /// 提取 impl 块中某个方法的函数体（到下一个列 0 的 `}` 为止）。
    fn impl_fn_body<'a>(impl_body: &'a str, fn_name: &str) -> &'a str {
        let marker = format!("async fn {fn_name}");
        let after = impl_body
            .split(marker.as_str())
            .nth(1)
            .expect("fail-closed write method must exist in the sqlx impl");
        let end = after.find("\n}").unwrap_or(after.len());
        &after[..end]
    }

    /// 形状守卫：生产代码部分不得包含任何 cross_org_grant 写 SQL
    /// （INSERT/UPDATE/ON DUPLICATE KEY），管理侧读取只能是 SELECT。
    #[test]
    fn no_write_sql_is_present_in_the_write_paths() {
        let source = include_str!("cross_org_grant_repository.rs");
        // 剥离测试模块，仅对生产代码断言（测试自身的断言文本不算 SQL 出现）。
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("INSERT INTO cross_org_grant"));
        assert!(!production.contains("UPDATE cross_org_grant"));
        assert!(!production.contains("ON DUPLICATE KEY"));
        // 保留的读取路径必须是纯 SELECT。
        assert!(production.contains("SELECT COUNT(*) FROM cross_org_grant"));
        assert!(production.contains("SELECT {GRANT_SELECT_COLUMNS} FROM cross_org_grant"));
    }

    /// 形状守卫：三个写入方法的 impl 体内只能出现 fail-closed 守卫，不得出现
    /// 任何 SQL 构造/绑定/执行调用。
    #[test]
    fn write_method_bodies_contain_only_the_fail_closed_guard() {
        let source = include_str!("cross_org_grant_repository.rs");
        let impl_body = source
            .split("impl CrossOrgGrantRepository for SqlxCrossOrgGrantRepository")
            .nth(1)
            .expect("sqlx impl must exist")
            .split("#[cfg(test)]")
            .next()
            .unwrap();

        for fn_name in ["upsert_grant", "revoke_grant", "revoke_grant_with_reason"] {
            let body = impl_fn_body(impl_body, fn_name);
            assert!(
                body.contains("CROSS_ORG_GRANT_WRITE_UNSUPPORTED_MESSAGE"),
                "{fn_name} must return the shared fail-closed guard message"
            );
            assert!(
                body.contains("AstralError::NotImplemented"),
                "{fn_name} must fail closed with NotImplemented"
            );
            for forbidden in ["sqlx::", ".bind(", ".execute(", ".fetch_", "FROM_UNIXTIME"] {
                assert!(
                    !body.contains(forbidden),
                    "{fn_name} must not execute or bind any SQL (found {forbidden})"
                );
            }
        }
    }

    /// 形状守卫：写入方法的返回类型形状保持稳定（trait 合同未变，仅 fail-closed），
    /// 避免静默收缩为“永不成功但签名也变了”。
    #[test]
    fn trait_contract_keeps_write_signatures_declared() {
        let source = include_str!("cross_org_grant_repository.rs");
        let trait_body = source
            .split("impl CrossOrgGrantRepository for SqlxCrossOrgGrantRepository")
            .next()
            .unwrap();
        for marker in [
            "async fn upsert_grant(",
            "async fn revoke_grant(&self, id: i64) -> Result<bool, AstralError>",
            "async fn revoke_grant_with_reason(&self, revoke: &RevokeGrant) -> Result<bool, AstralError>",
        ] {
            assert!(
                trait_body.contains(marker),
                "trait must keep declaring the write signature for fail-closed surfacing"
            );
        }
    }
}
