//! 管理组数据访问 — AdminGroupRepository
//!
//! 对齐 Java `AdminGroupController` 的持久化边界（admin_group + admin_group_member 表）。
//! 删除组先级联删除成员再删组，收敛为**单事务**聚合方法（此前两条独立 DELETE
//! 存在崩溃中间态：成员已删但组残留或反之）。

use async_trait::async_trait;
use sqlx::MySqlPool;

use astral_db::{TypedRowOperation, TypedSourceRowLookup, TypedSourceTable};
use astral_types::{AstralError, AuthorizationAdmission};

use crate::repository::authorization_source_transaction::AuthorizationSourceTransaction;

/// 管理组行
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AdminGroupRecord {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub scope: String,
}

/// 管理组行（含成员数，LEFT JOIN + GROUP BY 防 N+1）
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AdminGroupCountRecord {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub scope: String,
    pub member_count: i64,
}

#[async_trait]
pub trait AdminGroupRepository: Send + Sync {
    /// 全部管理组（含成员数，防 N+1）
    async fn list_with_counts(&self) -> Result<Vec<AdminGroupCountRecord>, AstralError>;
    /// 新建。用户面写入必须携带 PolicyEngine 产生的 proof-bound admission。
    async fn create(
        &self,
        name: &str,
        description: Option<&str>,
        scope: &str,
        admission: AuthorizationAdmission,
    ) -> Result<i64, AstralError>;
    /// 单条
    async fn get(&self, id: i64) -> Result<Option<AdminGroupRecord>, AstralError>;
    async fn update(
        &self,
        id: i64,
        name: &str,
        description: Option<&str>,
        scope: &str,
        admission: AuthorizationAdmission,
    ) -> Result<(), AstralError>;
    /// 删除（单事务：先级联删成员再删组）。
    async fn delete(&self, id: i64, admission: AuthorizationAdmission) -> Result<(), AstralError>;
    /// 组成员 user_id 列表
    async fn list_member_ids(&self, group_id: i64) -> Result<Vec<i64>, AstralError>;
    /// 添加成员（INSERT IGNORE 幂等）。
    async fn add_member(
        &self,
        group_id: i64,
        user_id: i64,
        admission: AuthorizationAdmission,
    ) -> Result<(), AstralError>;
    /// 移除成员。
    async fn remove_member(
        &self,
        group_id: i64,
        user_id: i64,
        admission: AuthorizationAdmission,
    ) -> Result<(), AstralError>;
}

pub struct SqlxAdminGroupRepository {
    db: MySqlPool,
}

impl SqlxAdminGroupRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

const ADMIN_GROUP_SELECT: &str = "SELECT id, name, description, scope FROM admin_group";

#[async_trait]
impl AdminGroupRepository for SqlxAdminGroupRepository {
    async fn list_with_counts(&self) -> Result<Vec<AdminGroupCountRecord>, AstralError> {
        sqlx::query_as::<_, AdminGroupCountRecord>(
            "SELECT g.id, g.name, g.description, g.scope, COUNT(m.user_id) AS member_count \
             FROM admin_group g LEFT JOIN admin_group_member m ON g.id = m.group_id \
             GROUP BY g.id, g.name, g.description, g.scope \
             ORDER BY g.id",
        )
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create(
        &self,
        name: &str,
        description: Option<&str>,
        scope: &str,
        admission: AuthorizationAdmission,
    ) -> Result<i64, AstralError> {
        validate_group_input(name, scope)?;
        let actor_id = admission_actor_id(&admission)?;
        let operation_id = admission.operation_id().to_owned();
        let mut tx =
            AuthorizationSourceTransaction::begin_with_admission(&self.db, admission).await?;
        let intent = TypedSourceRowLookup::AdminGroupInsertIntent {
            id: 0,
            name: name.to_owned(),
            description: description.map(str::to_owned),
            scope: Some(scope.to_owned()),
        };
        let mut capture =
            tx.typed_row_capture(TypedSourceTable::AdminGroup, TypedRowOperation::Insert);
        let group_id = capture
            .insert_admin_group_and_capture_in_tx(&intent)
            .await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        tx.stage_typed_source_image(image)?;
        let audit_id = insert_admin_group_audit(
            &mut tx,
            actor_id,
            group_id,
            operation_id.as_str(),
            "CREATE",
            None,
        )
        .await?;
        tx.stage_typed_source_audit_insert_id(audit_id)?;
        tx.commit_consuming().await?;
        Ok(group_id)
    }

    async fn get(&self, id: i64) -> Result<Option<AdminGroupRecord>, AstralError> {
        sqlx::query_as::<_, AdminGroupRecord>(&format!("{ADMIN_GROUP_SELECT} WHERE id = ?"))
            .bind(id)
            .fetch_optional(&self.db)
            .await
            .map_err(db_error)
    }

    async fn update(
        &self,
        id: i64,
        name: &str,
        description: Option<&str>,
        scope: &str,
        admission: AuthorizationAdmission,
    ) -> Result<(), AstralError> {
        validate_group_id(id)?;
        validate_group_input(name, scope)?;
        let actor_id = admission_actor_id(&admission)?;
        let operation_id = admission.operation_id().to_owned();
        let mut tx =
            AuthorizationSourceTransaction::begin_with_admission(&self.db, admission).await?;
        lock_group(&mut tx, id).await?;
        let lookup = TypedSourceRowLookup::PrimaryId { id };
        let mut capture =
            tx.typed_row_capture(TypedSourceTable::AdminGroup, TypedRowOperation::Update);
        capture.capture_before_in_tx(&lookup).await?;
        let result = capture
            .with_tx_mut(move |tx| {
                let name = name.to_owned();
                let description = description.map(str::to_owned);
                let scope = scope.to_owned();
                Box::pin(async move {
                    sqlx::query(
                        "UPDATE admin_group SET name = ?, description = ?, scope = ? WHERE id = ?",
                    )
                    .bind(name)
                    .bind(description)
                    .bind(scope)
                    .bind(id)
                    .execute(&mut **tx)
                    .await
                    .map_err(db_error)
                })
            })
            .await?;
        require_one_row(result.rows_affected(), "admin group update")?;
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        tx.stage_typed_source_image(image)?;
        let audit_id =
            insert_admin_group_audit(&mut tx, actor_id, id, operation_id.as_str(), "UPDATE", None)
                .await?;
        tx.stage_typed_source_audit_insert_id(audit_id)?;
        tx.commit_consuming().await
    }

    async fn delete(&self, id: i64, admission: AuthorizationAdmission) -> Result<(), AstralError> {
        validate_group_id(id)?;
        let actor_id = admission_actor_id(&admission)?;
        let operation_id = admission.operation_id().to_owned();
        let mut tx =
            AuthorizationSourceTransaction::begin_with_admission(&self.db, admission).await?;
        lock_group(&mut tx, id).await?;
        let member_ids: Vec<(i64,)> = sqlx::query_as(
            "SELECT user_id FROM admin_group_member WHERE group_id = ? ORDER BY user_id FOR UPDATE",
        )
        .bind(id)
        .fetch_all(&mut **tx)
        .await
        .map_err(db_error)?;
        let member_count = member_ids.len() as u64;
        for (user_id,) in member_ids {
            validate_user_id(user_id)?;
            let lookup = TypedSourceRowLookup::AdminGroupMember {
                group_id: id,
                user_id,
            };
            let mut capture = tx.typed_row_capture(
                TypedSourceTable::AdminGroupMember,
                TypedRowOperation::Delete,
            );
            capture.capture_before_in_tx(&lookup).await?;
            let result = capture
                .with_tx_mut(move |tx| {
                    Box::pin(async move {
                        sqlx::query(
                            "DELETE FROM admin_group_member WHERE group_id = ? AND user_id = ?",
                        )
                        .bind(id)
                        .bind(user_id)
                        .execute(&mut **tx)
                        .await
                        .map_err(|error| {
                            AstralError::Database(format!(
                                "admin group member cascade delete failed: {error}"
                            ))
                        })
                    })
                })
                .await?;
            require_one_row(result.rows_affected(), "admin group member cascade delete")?;
            capture.capture_after_in_tx(&lookup).await?;
            let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
            tx.stage_typed_source_image(image)?;
        }
        let group_lookup = TypedSourceRowLookup::PrimaryId { id };
        let mut group_capture =
            tx.typed_row_capture(TypedSourceTable::AdminGroup, TypedRowOperation::Delete);
        group_capture.capture_before_in_tx(&group_lookup).await?;
        let group = group_capture
            .with_tx_mut(move |tx| {
                Box::pin(async move {
                    sqlx::query("DELETE FROM admin_group WHERE id = ?")
                        .bind(id)
                        .execute(&mut **tx)
                        .await
                        .map_err(|error| {
                            AstralError::Database(format!("admin group delete failed: {error}"))
                        })
                })
            })
            .await?;
        require_one_row(group.rows_affected(), "admin group delete")?;
        group_capture.capture_after_in_tx(&group_lookup).await?;
        let group_image = astral_db::seal_typed_source_row_capture_tx(group_capture)?;
        tx.stage_typed_source_image(group_image)?;
        let audit_id = insert_admin_group_audit(
            &mut tx,
            actor_id,
            id,
            operation_id.as_str(),
            "DELETE",
            Some(member_count),
        )
        .await?;
        tx.stage_typed_source_audit_insert_id(audit_id)?;
        tx.commit_consuming().await
    }

    async fn list_member_ids(&self, group_id: i64) -> Result<Vec<i64>, AstralError> {
        let rows: Vec<(i64,)> =
            sqlx::query_as("SELECT user_id FROM admin_group_member WHERE group_id = ?")
                .bind(group_id)
                .fetch_all(&self.db)
                .await
                .map_err(db_error)?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn add_member(
        &self,
        group_id: i64,
        user_id: i64,
        admission: AuthorizationAdmission,
    ) -> Result<(), AstralError> {
        validate_group_id(group_id)?;
        validate_user_id(user_id)?;
        let actor_id = admission_actor_id(&admission)?;
        let operation_id = admission.operation_id().to_owned();
        let mut tx =
            AuthorizationSourceTransaction::begin_with_admission(&self.db, admission).await?;
        lock_group(&mut tx, group_id).await?;
        let lookup = TypedSourceRowLookup::AdminGroupMember { group_id, user_id };
        let mut capture = tx.typed_row_capture(
            TypedSourceTable::AdminGroupMember,
            TypedRowOperation::Insert,
        );
        capture.capture_before_in_tx(&lookup).await?;
        let result = capture
            .with_tx_mut(move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT IGNORE INTO admin_group_member (group_id, user_id) VALUES (?, ?)",
                    )
                    .bind(group_id)
                    .bind(user_id)
                    .execute(&mut **tx)
                    .await
                    .map_err(db_error)
                })
            })
            .await?;
        if result.rows_affected() != 1 {
            return Err(AstralError::Pending(
                "admin group member insert was a no-op; refusing empty config completion".into(),
            ));
        }
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        tx.stage_typed_source_image(image)?;
        let audit_id = insert_admin_group_audit(
            &mut tx,
            actor_id,
            group_id,
            operation_id.as_str(),
            "ADD_MEMBER",
            Some(user_id as u64),
        )
        .await?;
        tx.stage_typed_source_audit_insert_id(audit_id)?;
        tx.commit_consuming().await
    }

    async fn remove_member(
        &self,
        group_id: i64,
        user_id: i64,
        admission: AuthorizationAdmission,
    ) -> Result<(), AstralError> {
        validate_group_id(group_id)?;
        validate_user_id(user_id)?;
        let actor_id = admission_actor_id(&admission)?;
        let operation_id = admission.operation_id().to_owned();
        let mut tx =
            AuthorizationSourceTransaction::begin_with_admission(&self.db, admission).await?;
        lock_group(&mut tx, group_id).await?;
        let lookup = TypedSourceRowLookup::AdminGroupMember { group_id, user_id };
        let mut capture = tx.typed_row_capture(
            TypedSourceTable::AdminGroupMember,
            TypedRowOperation::Delete,
        );
        capture.capture_before_in_tx(&lookup).await?;
        let result = capture
            .with_tx_mut(move |tx| {
                Box::pin(async move {
                    sqlx::query("DELETE FROM admin_group_member WHERE group_id = ? AND user_id = ?")
                        .bind(group_id)
                        .bind(user_id)
                        .execute(&mut **tx)
                        .await
                        .map_err(db_error)
                })
            })
            .await?;
        require_one_row(result.rows_affected(), "admin group member removal")?;
        capture.capture_after_in_tx(&lookup).await?;
        let image = astral_db::seal_typed_source_row_capture_tx(capture)?;
        tx.stage_typed_source_image(image)?;
        let audit_id = insert_admin_group_audit(
            &mut tx,
            actor_id,
            group_id,
            operation_id.as_str(),
            "REMOVE_MEMBER",
            Some(user_id as u64),
        )
        .await?;
        tx.stage_typed_source_audit_insert_id(audit_id)?;
        tx.commit_consuming().await
    }
}

fn validate_group_input(name: &str, scope: &str) -> Result<(), AstralError> {
    if name.trim().is_empty() || name.len() > 255 {
        return Err(AstralError::Validation(
            "admin group name must be non-empty and at most 255 bytes".into(),
        ));
    }
    if scope.trim().is_empty() || scope.len() > 32 {
        return Err(AstralError::Validation(
            "admin group scope must be non-empty and at most 32 bytes".into(),
        ));
    }
    Ok(())
}

fn validate_group_id(id: i64) -> Result<(), AstralError> {
    if id <= 0 {
        return Err(AstralError::Validation(
            "admin group id must be positive".into(),
        ));
    }
    Ok(())
}

fn validate_user_id(id: i64) -> Result<(), AstralError> {
    if id <= 0 {
        return Err(AstralError::Validation(
            "admin group member user id must be positive".into(),
        ));
    }
    Ok(())
}

fn require_one_row(affected: u64, operation: &str) -> Result<(), AstralError> {
    if affected != 1 {
        return Err(AstralError::Validation(format!(
            "{operation} affected {affected} rows; refusing an unproven mutation"
        )));
    }
    Ok(())
}

fn admission_actor_id(admission: &AuthorizationAdmission) -> Result<i64, AstralError> {
    admission
        .proof()
        .scope
        .user_id
        .filter(|id| *id > 0)
        .ok_or_else(|| {
            AstralError::Permission(
                "admin group mutation requires a user-bound authorization admission".into(),
            )
        })
}

async fn lock_group(
    tx: &mut AuthorizationSourceTransaction,
    group_id: i64,
) -> Result<(), AstralError> {
    let found: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM admin_group WHERE id = ? FOR UPDATE")
            .bind(group_id)
            .fetch_optional(&mut ***tx)
            .await
            .map_err(db_error)?;
    if found.is_none() {
        return Err(AstralError::NotFound(format!(
            "admin group {group_id} not found"
        )));
    }
    Ok(())
}

async fn insert_admin_group_audit(
    tx: &mut AuthorizationSourceTransaction,
    actor_id: i64,
    group_id: i64,
    operation_id: &str,
    action: &str,
    member_user_id: Option<u64>,
) -> Result<i64, AstralError> {
    if actor_id <= 0 || group_id <= 0 || operation_id.trim().is_empty() {
        return Err(AstralError::Validation(
            "admin group audit requires positive actor/group ids and operation identity".into(),
        ));
    }
    let detail = serde_json::to_string(&serde_json::json!({
        "actorId": actor_id,
        "groupId": group_id,
        "memberUserId": member_user_id,
        "operationId": operation_id,
    }))
    .map_err(|error| {
        AstralError::Validation(format!("admin group audit serialization failed: {error}"))
    })?;
    let result = sqlx::query(
        "INSERT INTO audit_log \
         (user_id, action, resource, decision, event_type, request_id, detail) \
         VALUES (?, ?, 'admin_group', 'ALLOW', 'ADMIN_GROUP_MUTATION', ?, ?)",
    )
    .bind(actor_id)
    .bind(action)
    .bind(operation_id)
    .bind(detail)
    .execute(&mut ***tx)
    .await
    .map_err(|error| AstralError::Database(format!("Admin group audit insert failed: {error}")))?;
    if result.rows_affected() != 1 {
        return Err(AstralError::Pending(
            "admin group audit insert did not affect exactly one row".into(),
        ));
    }
    i64::try_from(result.last_insert_id())
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| AstralError::Pending("admin group audit insert returned invalid id".into()))
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Admin group repository query failed: {error}"))
}
