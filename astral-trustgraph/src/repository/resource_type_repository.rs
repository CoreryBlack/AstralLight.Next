//! 资源类型数据访问 — ResourceTypeRepository
//!
//! 对齐 Java `DomainResourceTypeMapper` / `ResourceTypeRegistryMapper` 边界
//! （domain_resource_type + resource_type_registry 表）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_types::{
    AstralError, CustomResourceRegistration, RegistryRegistrationError, ResourceRegistry,
    MAX_CUSTOM_RESOURCE_REGISTRY_BYTES, MAX_CUSTOM_RESOURCE_TYPES,
};

/// Bounded persisted registry read. One extra row detects oversized startup data.
pub const RESOURCE_TYPE_REGISTRY_READ_LIMIT: i64 = (MAX_CUSTOM_RESOURCE_TYPES + 1) as i64;

/// Load persisted rows into the shared registry through its validated additive API.
///
/// The input should come from the bounded `list_registry` reader below; cap+1 rows
/// are rejected before any registry mutation. JSON parse or registration errors
/// are surfaced and must abort startup rather than leave a partially loaded registry.
pub fn load_registry_rows(rows: &[ResourceTypeRegistryRecord]) -> Result<(), AstralError> {
    if rows.len() > MAX_CUSTOM_RESOURCE_TYPES {
        return Err(AstralError::Validation(
            "persisted resource registry exceeds configured resource limit".into(),
        ));
    }
    let mut registrations = Vec::with_capacity(rows.len());
    let mut total_bytes = 0usize;
    for row in rows {
        total_bytes = total_bytes
            .saturating_add(row.resource_type.len())
            .saturating_add(row.actions_json.len());
        if total_bytes > MAX_CUSTOM_RESOURCE_REGISTRY_BYTES {
            return Err(AstralError::Validation(
                "persisted resource registry exceeds configured byte limit".into(),
            ));
        }
        let actions: Vec<String> = serde_json::from_str(&row.actions_json).map_err(|error| {
            AstralError::Validation(format!(
                "invalid actions_json for resource '{}': {error}",
                row.resource_type
            ))
        })?;
        registrations.push(CustomResourceRegistration {
            resource_type: row.resource_type.clone(),
            actions,
        });
    }
    ResourceRegistry::global()
        .validate_custom_resources(registrations.clone())
        .map_err(registry_registration_error)?;
    ResourceRegistry::global()
        .register_custom_resources(registrations)
        .map_err(registry_registration_error)
}

fn registry_registration_error(error: RegistryRegistrationError) -> AstralError {
    AstralError::Validation(format!("invalid persisted resource registry: {error}"))
}

/// domain_resource_type 行（通过别名映射）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DomainResourceTypeRecord {
    pub id: i64,
    pub domain_id: Option<i64>,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub sensitivity_level: Option<String>,
    pub status: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// resource_type_registry 行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ResourceTypeRegistryRecord {
    pub id: i64,
    pub resource_type: String,
    pub actions_json: String,
    pub description: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[async_trait]
pub trait ResourceTypeRepository: Send + Sync {
    /// domain_resource_type 总数
    async fn count_domain_resource_types(&self) -> Result<i64, AstralError>;
    /// domain_resource_type 分页列表（ORDER BY resource_type_id）
    async fn list_domain_resource_types(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DomainResourceTypeRecord>, AstralError>;
    /// resource_type_registry 全量列表（ORDER BY resource_type）
    async fn list_registry(&self) -> Result<Vec<ResourceTypeRegistryRecord>, AstralError>;
    /// 注册新资源（resource_type 已存在时返回错误，不忽略冲突）
    async fn insert_registry(
        &self,
        resource_type: &str,
        actions_json: &str,
        description: Option<&str>,
    ) -> Result<(), AstralError>;
    /// 更新（actions_json + description），返回是否命中
    async fn update_registry(
        &self,
        resource_type: &str,
        actions_json: &str,
        description: Option<&str>,
    ) -> Result<bool, AstralError>;
    /// 注销（DELETE），返回是否命中
    async fn delete_registry(&self, resource_type: &str) -> Result<bool, AstralError>;
    /// 异步扫描用：INSERT ... ON DUPLICATE KEY UPDATE
    async fn upsert_registry(
        &self,
        resource_type: &str,
        actions_json: &str,
    ) -> Result<(), AstralError>;
}

pub struct SqlxResourceTypeRepository {
    db: MySqlPool,
}

impl SqlxResourceTypeRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl ResourceTypeRepository for SqlxResourceTypeRepository {
    async fn count_domain_resource_types(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM domain_resource_type")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_domain_resource_types(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<DomainResourceTypeRecord>, AstralError> {
        sqlx::query_as::<_, DomainResourceTypeRecord>(
            "SELECT resource_type_id as id, domain_id, type_code as code, type_name as name, \
             type_description as description, sensitivity_level, status, \
             DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
             DATE_FORMAT(updated_at, '%Y-%m-%dT%H:%i:%sZ') as updated_at \
             FROM domain_resource_type ORDER BY resource_type_id LIMIT ? OFFSET ?",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn list_registry(&self) -> Result<Vec<ResourceTypeRegistryRecord>, AstralError> {
        let query = format!(
            "SELECT id, resource_type, actions_json, description, \
             DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%sZ') as created_at, \
             DATE_FORMAT(updated_at, '%Y-%m-%dT%H:%i:%sZ') as updated_at \
             FROM resource_type_registry ORDER BY resource_type LIMIT {RESOURCE_TYPE_REGISTRY_READ_LIMIT}"
        );
        sqlx::query_as::<_, ResourceTypeRegistryRecord>(&query)
            .fetch_all(&self.db)
            .await
            .map_err(db_error)
    }

    async fn insert_registry(
        &self,
        resource_type: &str,
        actions_json: &str,
        description: Option<&str>,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT INTO resource_type_registry (resource_type, actions_json, description) \
             VALUES (?, ?, ?)",
        )
        .bind(resource_type)
        .bind(actions_json)
        .bind(description)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }

    async fn update_registry(
        &self,
        resource_type: &str,
        actions_json: &str,
        description: Option<&str>,
    ) -> Result<bool, AstralError> {
        let result = sqlx::query(
            "UPDATE resource_type_registry SET actions_json = ?, description = ? WHERE resource_type = ?",
        )
        .bind(actions_json)
        .bind(description)
        .bind(resource_type)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_registry(&self, resource_type: &str) -> Result<bool, AstralError> {
        let result = sqlx::query("DELETE FROM resource_type_registry WHERE resource_type = ?")
            .bind(resource_type)
            .execute(&self.db)
            .await
            .map_err(db_error)?;
        Ok(result.rows_affected() > 0)
    }

    async fn upsert_registry(
        &self,
        resource_type: &str,
        actions_json: &str,
    ) -> Result<(), AstralError> {
        sqlx::query(
            "INSERT INTO resource_type_registry (resource_type, actions_json) VALUES (?, ?) \
             ON DUPLICATE KEY UPDATE actions_json = VALUES(actions_json), updated_at = NOW()",
        )
        .bind(resource_type)
        .bind(actions_json)
        .execute(&self.db)
        .await
        .map_err(db_error)?;
        Ok(())
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Resource type repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{
        load_registry_rows, ResourceTypeRegistryRecord, RESOURCE_TYPE_REGISTRY_READ_LIMIT,
    };
    use crate::service::rule_set_write_service::validate_entry_fields;
    use astral_types::{AstralError, ResourceRegistry, MAX_CUSTOM_RESOURCE_TYPES};

    fn row(resource_type: String, actions_json: &str) -> ResourceTypeRegistryRecord {
        ResourceTypeRegistryRecord {
            id: 1,
            resource_type,
            actions_json: actions_json.into(),
            description: None,
            created_at: None,
            updated_at: None,
        }
    }

    #[test]
    fn bounded_startup_loader_registers_custom_actions_that_grant_validation_accepts() {
        let resource = format!("test_loaded_{}", std::process::id());
        let rows = [row(resource.clone(), r#"["read","approve"]"#)];
        assert!(load_registry_rows(&rows).is_ok());
        assert!(ResourceRegistry::global()
            .validate(&resource, "approve")
            .is_ok());
        assert_eq!(
            validate_entry_fields("ALLOW", Some(&resource), Some("approve"), None)
                .expect("registered custom actions must be grantable"),
            "ALLOW"
        );
        assert!(
            load_registry_rows(&rows).is_ok(),
            "startup reload is idempotent"
        );
        assert_eq!(
            RESOURCE_TYPE_REGISTRY_READ_LIMIT,
            (MAX_CUSTOM_RESOURCE_TYPES + 1) as i64
        );
    }

    #[test]
    fn invalid_registry_batch_is_rejected_before_any_custom_resource_is_registered() {
        let resource = format!("test_atomic_{}", std::process::id());
        let rows = [
            row(resource.clone(), r#"["read"]"#),
            row("monitor".into(), r#"["read","unknown"]"#),
        ];
        let error = load_registry_rows(&rows).expect_err("incompatible built-in action must fail");
        assert!(matches!(error, AstralError::Validation(_)));
        assert!(ResourceRegistry::global()
            .validate(&resource, "read")
            .is_err());
    }

    #[test]
    fn startup_loader_rejects_malformed_actions_json() {
        let rows = [row(
            format!("test_malformed_{}", std::process::id()),
            r#"{"read":true}"#,
        )];
        assert!(matches!(
            load_registry_rows(&rows),
            Err(AstralError::Validation(_))
        ));
    }
}
