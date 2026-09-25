//! 组织/域/租户数据访问 — OrgRepository
//!
//! 对齐 Java `TenantMapper` / `PlatformDomainMapper` 边界。
//! `tenant`（tenant_type='ENTERPRISE' 承载组织）、`platform_domain`、
//! `tenant_domain_map` 的 CRUD 集中在 repository。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_db::{append_eligibility_events_for_cards_in_tx, EligibilityCardSelector};
use astral_types::AstralError;

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
const TENANT_STATUS_LOCK_SQL: &str = "SELECT status FROM tenant WHERE tenant_id = ? FOR UPDATE";
const TENANT_ID_LOCK_SQL: &str = "SELECT tenant_id FROM tenant WHERE tenant_id = ? FOR UPDATE";
const ENTERPRISE_STATUS_LOCK_SQL: &str =
    "SELECT status FROM tenant WHERE tenant_id = ? AND tenant_type = 'ENTERPRISE' FOR UPDATE";
const ENTERPRISE_ID_LOCK_SQL: &str =
    "SELECT tenant_id FROM tenant WHERE tenant_id = ? AND tenant_type = 'ENTERPRISE' FOR UPDATE";

#[async_trait]
pub trait OrgRepository: Send + Sync {
    async fn list_orgs(&self) -> Result<Vec<OrganizationRecord>, AstralError>;
    async fn create_org(&self, name: &str, status: &str) -> Result<i64, AstralError>;
    async fn get_org(&self, id: i64) -> Result<Option<OrganizationRecord>, AstralError>;
    async fn update_org(
        &self,
        id: i64,
        name: &str,
        code: &str,
        status: &str,
    ) -> Result<(), AstralError>;
    async fn delete_org(&self, id: i64) -> Result<(), AstralError>;

    async fn list_org_domains(&self, org_id: i64) -> Result<Vec<DomainRecord>, AstralError>;

    async fn list_all_domains(&self) -> Result<Vec<DomainRecord>, AstralError>;
    async fn create_domain(
        &self,
        name: &str,
        code: Option<&str>,
        status: &str,
    ) -> Result<i64, AstralError>;
    async fn get_domain(&self, id: i64) -> Result<Option<DomainRecord>, AstralError>;
    async fn update_domain(
        &self,
        id: i64,
        name: &str,
        code: Option<&str>,
        status: &str,
    ) -> Result<(), AstralError>;
    async fn delete_domain(&self, id: i64) -> Result<(), AstralError>;

    async fn list_domain_tenants(&self, domain_id: i64) -> Result<Vec<TenantRecord>, AstralError>;

    async fn list_all_tenants(&self) -> Result<Vec<TenantRecord>, AstralError>;
    async fn create_tenant(&self, name: &str, status: &str) -> Result<i64, AstralError>;
    async fn get_tenant(&self, id: i64) -> Result<Option<TenantRecord>, AstralError>;
    async fn update_tenant(
        &self,
        id: i64,
        name: &str,
        code: &str,
        status: &str,
    ) -> Result<(), AstralError>;
    async fn delete_tenant(&self, id: i64) -> Result<(), AstralError>;
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

    async fn create_org(&self, name: &str, status: &str) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO tenant (tenant_code, tenant_name, tenant_type, status) \
             VALUES (CONCAT('T', UNIX_TIMESTAMP()), ?, 'ENTERPRISE', ?)",
        )
        .bind(name)
        .bind(status)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
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
        id: i64,
        name: &str,
        code: &str,
        status: &str,
    ) -> Result<(), AstralError> {
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
            tx.commit().await.map_err(db_error)?;
            return Ok(());
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
        if status_changed(&current_status, status) {
            append_eligibility_events_for_cards_in_tx(
                &mut tx,
                EligibilityCardSelector::ByTenantId { tenant_id: id },
            )
            .await?;
        }
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn delete_org(&self, id: i64) -> Result<(), AstralError> {
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
            tx.commit().await.map_err(db_error)?;
            return Ok(());
        }

        append_eligibility_events_for_cards_in_tx(
            &mut tx,
            EligibilityCardSelector::ByTenantId { tenant_id: id },
        )
        .await?;
        let result =
            sqlx::query("DELETE FROM tenant WHERE tenant_id = ? AND tenant_type = 'ENTERPRISE'")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Database(format!(
                "enterprise tenant {id} disappeared during locked delete"
            )));
        }
        tx.commit().await.map_err(db_error)?;
        Ok(())
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
        name: &str,
        code: Option<&str>,
        status: &str,
    ) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO platform_domain (domain_name, domain_code, status) VALUES (?, ?, ?)",
        )
        .bind(name)
        .bind(code)
        .bind(status)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
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
        id: i64,
        name: &str,
        code: Option<&str>,
        status: &str,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "UPDATE platform_domain SET domain_name = ?, domain_code = ?, status = ? \
             WHERE domain_id = ?",
        )
        .bind(name)
        .bind(code)
        .bind(status)
        .bind(id)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn delete_domain(&self, id: i64) -> Result<(), AstralError> {
        sqlx::query("DELETE FROM platform_domain WHERE domain_id = ?")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(())
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

    async fn create_tenant(&self, name: &str, status: &str) -> Result<i64, AstralError> {
        let result = sqlx::query(
            "INSERT INTO tenant (tenant_code, tenant_name, tenant_type, status) \
             VALUES (CONCAT('T', UNIX_TIMESTAMP()), ?, 'ENTERPRISE', ?)",
        )
        .bind(name)
        .bind(status)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.last_insert_id() as i64)
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
        id: i64,
        name: &str,
        code: &str,
        status: &str,
    ) -> Result<(), AstralError> {
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
            tx.commit().await.map_err(db_error)?;
            return Ok(());
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
        if status_changed(&current_status, status) {
            append_eligibility_events_for_cards_in_tx(
                &mut tx,
                EligibilityCardSelector::ByTenantId { tenant_id: id },
            )
            .await?;
        }
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }

    async fn delete_tenant(&self, id: i64) -> Result<(), AstralError> {
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
            tx.commit().await.map_err(db_error)?;
            return Ok(());
        }

        // Capture eligibility before a hard delete can remove the source cards.
        append_eligibility_events_for_cards_in_tx(
            &mut tx,
            EligibilityCardSelector::ByTenantId { tenant_id: id },
        )
        .await?;
        let result = sqlx::query("DELETE FROM tenant WHERE tenant_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Database(format!(
                "tenant {id} disappeared during locked delete"
            )));
        }
        tx.commit().await.map_err(db_error)?;
        Ok(())
    }
}

fn status_changed(current: &str, requested: &str) -> bool {
    current != requested
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Org repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
