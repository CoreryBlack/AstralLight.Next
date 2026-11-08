//! Platform package repository.
//!
//! Package mutations are ProtectedBusiness source mutations: the caller must
//! provide the middleware-verified PolicyContext/admission pair and a stable
//! operation id. The transaction records the actual package before/after rows,
//! consumes the admission once, and writes the audit/source-outcome evidence
//! before COMMIT. Package data is commerce data and does not grant policy rights.

use async_trait::async_trait;
use sqlx::{MySqlPool, QueryBuilder};

use astral_db::{
    begin_protected_mutation_in_tx, finish_protected_mutation_in_tx, ProtectedMutationContext,
    ProtectedMutationStart, ProtectedSourceEvidence, RowPresence, TargetRowEvidence, WriteKind,
};
use astral_types::AstralError;
use serde::{Deserialize, Serialize};

const VALID_BILLING_CYCLES: [&str; 4] = ["MONTHLY", "QUARTERLY", "YEARLY", "ONETIME"];

/// Canonical platform_package row. `price` stays as the exact database decimal
/// text until the HTTP adapter performs checked cents conversion.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct PlatformPackageRecord {
    pub package_id: i64,
    pub package_name: String,
    pub stable_code: String,
    pub description: Option<String>,
    pub price: Option<String>,
    pub baseline: i32,
    pub billing_cycle: Option<String>,
    pub status: String,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

/// Explicit tri-state patch field. Missing JSON fields remain `Omitted`, while
/// an explicit JSON null is `Clear`; this distinction is part of the source
/// mutation contract and must survive the HTTP-to-repository boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub enum PatchField<T> {
    #[default]
    Omitted,
    Set(T),
    Clear,
}

impl<'de, T> Deserialize<'de> for PatchField<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match Option::<T>::deserialize(deserializer)? {
            Some(value) => Self::Set(value),
            None => Self::Clear,
        })
    }
}

/// Canonical package creation values. `billing_cycle` is deliberately owned
/// and non-null: legacy NULL package cycles are unknown, not a default.
#[derive(Debug, Clone)]
pub struct NewPlatformPackage {
    pub package_name: String,
    pub stable_code: String,
    pub description: Option<String>,
    pub price: Option<String>,
    pub baseline: i32,
    pub billing_cycle: String,
}

/// Partial package update. Values have already passed HTTP validation; the
/// repository still binds every value and never interpolates user input.
#[derive(Debug, Default)]
pub struct PlatformPackagePatch {
    pub package_name: PatchField<String>,
    pub stable_code: PatchField<String>,
    pub description: PatchField<String>,
    pub price: PatchField<String>,
    pub baseline: PatchField<i32>,
    pub billing_cycle: PatchField<String>,
    pub status: PatchField<String>,
}

#[derive(Debug, Serialize)]
struct PackageEvidence {
    package_id: i64,
    package_name: String,
    stable_code: String,
    description: Option<String>,
    price: Option<String>,
    baseline: i32,
    billing_cycle: Option<String>,
    status: String,
    created_at: Option<i64>,
    updated_at: Option<i64>,
}

const PKG_SELECT_COLUMNS: &str = "package_id, package_name, package_code AS stable_code, \
     description, CAST(price AS CHAR) AS price, version_no AS baseline, billing_cycle, status, \
     UNIX_TIMESTAMP(created_at) AS created_at, UNIX_TIMESTAMP(updated_at) AS updated_at";
const PACKAGE_BY_ID_FOR_UPDATE: &str = "SELECT package_id, package_name, package_code, \
     description, CAST(price AS CHAR) AS price, version_no AS baseline, billing_cycle, status, \
     CAST(UNIX_TIMESTAMP(created_at) AS SIGNED) AS created_at, \
     CAST(UNIX_TIMESTAMP(updated_at) AS SIGNED) AS updated_at \
     FROM platform_package WHERE package_id = ? FOR UPDATE";
const PACKAGE_BY_CODE_FOR_UPDATE: &str = "SELECT package_id, package_name, package_code, \
     description, CAST(price AS CHAR) AS price, version_no AS baseline, billing_cycle, status, \
     CAST(UNIX_TIMESTAMP(created_at) AS SIGNED) AS created_at, \
     CAST(UNIX_TIMESTAMP(updated_at) AS SIGNED) AS updated_at \
     FROM platform_package WHERE package_code = ? FOR UPDATE";

#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
struct PackageRow {
    package_id: i64,
    package_name: String,
    package_code: String,
    description: Option<String>,
    price: Option<String>,
    baseline: i32,
    billing_cycle: Option<String>,
    status: String,
    created_at: Option<i64>,
    updated_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageRowExpectation {
    package_id: i64,
    package_name: String,
    stable_code: String,
    description: Option<String>,
    price: Option<String>,
    baseline: i32,
    billing_cycle: Option<String>,
    status: String,
}

#[async_trait]
pub trait PlatformPackageRepository: Send + Sync {
    async fn count_packages(&self) -> Result<i64, AstralError>;
    async fn list_packages(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PlatformPackageRecord>, AstralError>;
    async fn get_package(&self, id: i64) -> Result<Option<PlatformPackageRecord>, AstralError>;
    async fn create_package_with_context(
        &self,
        new: &NewPlatformPackage,
        context: &ProtectedMutationContext,
    ) -> Result<i64, AstralError>;
    async fn update_package_with_context(
        &self,
        id: i64,
        patch: &PlatformPackagePatch,
        context: &ProtectedMutationContext,
    ) -> Result<(), AstralError>;
    async fn soft_delete_package_with_context(
        &self,
        id: i64,
        context: &ProtectedMutationContext,
    ) -> Result<bool, AstralError>;
}

pub struct SqlxPlatformPackageRepository {
    db: MySqlPool,
}

impl SqlxPlatformPackageRepository {
    pub fn new(db: MySqlPool) -> Self {
        Self { db }
    }
}

#[async_trait]
impl PlatformPackageRepository for SqlxPlatformPackageRepository {
    async fn count_packages(&self) -> Result<i64, AstralError> {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM platform_package")
            .fetch_one(&self.db)
            .await
            .map_err(db_error)
    }

    async fn list_packages(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<PlatformPackageRecord>, AstralError> {
        sqlx::query_as::<_, PlatformPackageRecord>(&format!(
            "SELECT {PKG_SELECT_COLUMNS} FROM platform_package ORDER BY package_id LIMIT ? OFFSET ?"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(db_error)
    }

    async fn get_package(&self, id: i64) -> Result<Option<PlatformPackageRecord>, AstralError> {
        sqlx::query_as::<_, PlatformPackageRecord>(&format!(
            "SELECT {PKG_SELECT_COLUMNS} FROM platform_package WHERE package_id = ?"
        ))
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(db_error)
    }

    async fn create_package_with_context(
        &self,
        new: &NewPlatformPackage,
        context: &ProtectedMutationContext,
    ) -> Result<i64, AstralError> {
        context.require_request("platform_package", "create", None)?;
        if new.billing_cycle.is_empty()
            || !VALID_BILLING_CYCLES.contains(&new.billing_cycle.as_str())
        {
            return Err(AstralError::Validation(
                "billingCycle is required and cannot be inferred".into(),
            ));
        }
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let payload = serde_json::json!({
            "packageName": &new.package_name,
            "stableCode": &new.stable_code,
            "description": &new.description,
            "price": &new.price,
            "baseline": new.baseline,
            "billingCycle": &new.billing_cycle,
        });
        if let ProtectedMutationStart::Completed(result) =
            begin_protected_mutation_in_tx(&mut tx, context, &payload).await?
        {
            return result
                .get("packageId")
                .and_then(serde_json::Value::as_i64)
                .filter(|id| *id > 0)
                .ok_or_else(|| AstralError::Database("invalid durable package result".into()));
        }

        let before: Option<PackageRow> = sqlx::query_as(PACKAGE_BY_CODE_FOR_UPDATE)
            .bind(&new.stable_code)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        if before.is_some() {
            return Err(AstralError::Validation(
                "stableCode is already used by another package".into(),
            ));
        }
        let insert = sqlx::query(
            "INSERT INTO platform_package \
             (package_name, package_code, description, price, version_no, billing_cycle, status) \
             VALUES (?, ?, ?, ?, ?, ?, 'ACTIVE')",
        )
        .bind(&new.package_name)
        .bind(&new.stable_code)
        .bind(new.description.as_deref())
        .bind(new.price.as_deref())
        .bind(new.baseline)
        .bind(&new.billing_cycle)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        if insert.rows_affected() != 1 {
            return Err(AstralError::Pending(format!(
                "package insert affected {} rows; refusing unproven source evidence",
                insert.rows_affected()
            )));
        }
        let package_id = i64::try_from(insert.last_insert_id())
            .ok()
            .filter(|id| *id > 0)
            .ok_or_else(|| AstralError::Pending("package insert returned an unusable id".into()))?;
        let after: Option<PackageRow> = sqlx::query_as(PACKAGE_BY_ID_FOR_UPDATE)
            .bind(package_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        let Some(after_row) = after.clone() else {
            return Err(AstralError::Pending(
                "inserted package has no same-transaction source readback".into(),
            ));
        };
        let expected = PackageRowExpectation {
            package_id,
            package_name: new.package_name.clone(),
            stable_code: new.stable_code.clone(),
            description: new.description.clone(),
            price: new.price.clone(),
            baseline: new.baseline,
            billing_cycle: Some(new.billing_cycle.clone()),
            status: "ACTIVE".into(),
        };
        if !package_row_matches(&after_row, &expected) {
            return Err(AstralError::Pending(
                "package source readback differs from the requested values".into(),
            ));
        }
        let evidence = ProtectedSourceEvidence::new()
            .target_row(TargetRowEvidence {
                entity: "platform_package",
                key: serde_json::json!({ "packageId": package_id }),
                before: RowPresence::from_option(before.map(package_evidence)),
                after: RowPresence::from_option(after.map(package_evidence)),
            })
            .map_err(|error| AstralError::Pending(error.to_string()))?
            .receipt(
                "platform_package",
                serde_json::json!({ "packageId": package_id }),
                WriteKind::Insert,
                insert.rows_affected(),
            );
        let result = serde_json::json!({ "packageId": package_id });
        finish_protected_mutation_in_tx(&mut tx, context, &result, &evidence).await?;
        tx.commit().await.map_err(|error| {
            AstralError::Pending(format!(
                "package COMMIT outcome unknown; reconcile operation {} before retry: {error}",
                context.operation_id(),
            ))
        })?;
        Ok(package_id)
    }

    async fn update_package_with_context(
        &self,
        id: i64,
        patch: &PlatformPackagePatch,
        context: &ProtectedMutationContext,
    ) -> Result<(), AstralError> {
        context.require_request("platform_package", "update", Some(id))?;
        if id <= 0 {
            return Err(AstralError::Validation(
                "package id must be positive".into(),
            ));
        }
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let payload = serde_json::json!({
            "packageId": id,
            "packageName": patch_field_json(&patch.package_name),
            "stableCode": patch_field_json(&patch.stable_code),
            "description": patch_field_json(&patch.description),
            "price": patch_field_json(&patch.price),
            "baseline": patch_field_json(&patch.baseline),
            "billingCycle": patch_field_json(&patch.billing_cycle),
            "status": patch_field_json(&patch.status),
        });
        if let ProtectedMutationStart::Completed(_) =
            begin_protected_mutation_in_tx(&mut tx, context, &payload).await?
        {
            return Ok(());
        }
        let before: Option<PackageRow> = sqlx::query_as(PACKAGE_BY_ID_FOR_UPDATE)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        let Some(before_row) = before.clone() else {
            return Err(AstralError::NotFound(format!("platform package {id}")));
        };
        let expected = package_expectation_after_patch(&before_row, patch)?;
        if package_row_matches(&before_row, &expected) {
            let after: Option<PackageRow> = sqlx::query_as(PACKAGE_BY_ID_FOR_UPDATE)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_error)?;
            if after.as_ref() != Some(&before_row) {
                return Err(AstralError::Pending(
                    "package no-op source readback differs from the locked before row".into(),
                ));
            }
            let evidence = ProtectedSourceEvidence::new()
                .target_row(TargetRowEvidence {
                    entity: "platform_package",
                    key: serde_json::json!({ "packageId": id }),
                    before: RowPresence::Present(package_evidence(before_row.clone())),
                    after: RowPresence::from_option(after.map(package_evidence)),
                })
                .map_err(|error| AstralError::Pending(error.to_string()))?
                .receipt(
                    "platform_package",
                    serde_json::json!({ "packageId": id }),
                    WriteKind::Probe,
                    0,
                );
            finish_protected_mutation_in_tx(
                &mut tx,
                context,
                &serde_json::json!({ "packageId": id, "changed": false }),
                &evidence,
            )
            .await?;
            tx.commit().await.map_err(|error| {
                AstralError::Pending(format!(
                    "package update COMMIT outcome unknown; reconcile operation {} before retry: {error}",
                    context.operation_id(),
                ))
            })?;
            return Ok(());
        }

        let mut builder = QueryBuilder::<sqlx::MySql>::new("UPDATE platform_package SET ");
        append_package_patch_sql(&mut builder, patch);
        builder.push(" WHERE package_id = ").push_bind(id);
        let update = builder.build().execute(&mut *tx).await.map_err(db_error)?;
        if update.rows_affected() != 1 {
            return Err(AstralError::Pending(format!(
                "package update affected {} rows; refusing unproven source evidence",
                update.rows_affected()
            )));
        }
        let after: Option<PackageRow> = sqlx::query_as(PACKAGE_BY_ID_FOR_UPDATE)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        let Some(after_row) = after.clone() else {
            return Err(AstralError::Pending(
                "updated package disappeared before source readback".into(),
            ));
        };
        if !package_row_matches(&after_row, &expected)
            || !package_timestamps_follow_mutation(&before_row, &after_row)
        {
            return Err(AstralError::Pending(
                "package update source readback differs from the requested patch".into(),
            ));
        }
        let evidence = ProtectedSourceEvidence::new()
            .target_row(TargetRowEvidence {
                entity: "platform_package",
                key: serde_json::json!({ "packageId": id }),
                before: RowPresence::from_option(before.map(package_evidence)),
                after: RowPresence::from_option(after.map(package_evidence)),
            })
            .map_err(|error| AstralError::Pending(error.to_string()))?
            .receipt(
                "platform_package",
                serde_json::json!({ "packageId": id }),
                WriteKind::Update,
                update.rows_affected(),
            );
        let result = serde_json::json!({ "packageId": id });
        finish_protected_mutation_in_tx(&mut tx, context, &result, &evidence).await?;
        tx.commit().await.map_err(|error| {
            AstralError::Pending(format!(
                "package update COMMIT outcome unknown; reconcile operation {} before retry: {error}",
                context.operation_id(),
            ))
        })?;
        Ok(())
    }

    async fn soft_delete_package_with_context(
        &self,
        id: i64,
        context: &ProtectedMutationContext,
    ) -> Result<bool, AstralError> {
        context.require_request("platform_package", "delete", Some(id))?;
        if id <= 0 {
            return Err(AstralError::Validation(
                "package id must be positive".into(),
            ));
        }
        let mut tx = self.db.begin().await.map_err(db_error)?;
        let payload = serde_json::json!({ "packageId": id, "status": "INACTIVE" });
        if let ProtectedMutationStart::Completed(result) =
            begin_protected_mutation_in_tx(&mut tx, context, &payload).await?
        {
            return result
                .get("deleted")
                .and_then(serde_json::Value::as_bool)
                .ok_or_else(|| {
                    AstralError::Database("invalid durable package delete result".into())
                });
        }
        let before: Option<PackageRow> = sqlx::query_as(PACKAGE_BY_ID_FOR_UPDATE)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        let Some(before_row) = before.clone() else {
            let evidence = ProtectedSourceEvidence::new()
                .target_row(TargetRowEvidence::<PackageEvidence> {
                    entity: "platform_package",
                    key: serde_json::json!({ "packageId": id }),
                    before: RowPresence::Absent,
                    after: RowPresence::Absent,
                })
                .map_err(|error| AstralError::Pending(error.to_string()))?
                .receipt(
                    "platform_package",
                    serde_json::json!({ "packageId": id }),
                    WriteKind::Probe,
                    0,
                );
            let result = serde_json::json!({ "packageId": id, "deleted": false });
            finish_protected_mutation_in_tx(&mut tx, context, &result, &evidence).await?;
            tx.commit().await.map_err(|error| {
                AstralError::Pending(format!(
                    "package delete COMMIT outcome unknown; reconcile operation {} before retry: {error}",
                    context.operation_id(),
                ))
            })?;
            return Ok(false);
        };
        if before_row.status == "INACTIVE" {
            let after: Option<PackageRow> = sqlx::query_as(PACKAGE_BY_ID_FOR_UPDATE)
                .bind(id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_error)?;
            if after.as_ref() != Some(&before_row) {
                return Err(AstralError::Pending(
                    "package delete no-op readback differs from the locked before row".into(),
                ));
            }
            let evidence = ProtectedSourceEvidence::new()
                .target_row(TargetRowEvidence {
                    entity: "platform_package",
                    key: serde_json::json!({ "packageId": id }),
                    before: RowPresence::Present(package_evidence(before_row)),
                    after: RowPresence::from_option(after.map(package_evidence)),
                })
                .map_err(|error| AstralError::Pending(error.to_string()))?
                .receipt(
                    "platform_package",
                    serde_json::json!({ "packageId": id }),
                    WriteKind::Probe,
                    0,
                );
            let result = serde_json::json!({ "packageId": id, "deleted": true });
            finish_protected_mutation_in_tx(&mut tx, context, &result, &evidence).await?;
            tx.commit().await.map_err(|error| {
                AstralError::Pending(format!(
                    "package delete COMMIT outcome unknown; reconcile operation {} before retry: {error}",
                    context.operation_id(),
                ))
            })?;
            return Ok(true);
        }
        let update =
            sqlx::query("UPDATE platform_package SET status = 'INACTIVE' WHERE package_id = ?")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?;
        if update.rows_affected() != 1 {
            return Err(AstralError::Pending(format!(
                "package delete affected {} rows; refusing unproven source evidence",
                update.rows_affected()
            )));
        }
        let after: Option<PackageRow> = sqlx::query_as(PACKAGE_BY_ID_FOR_UPDATE)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_error)?;
        let Some(after_row) = after.clone() else {
            return Err(AstralError::Pending(
                "deleted package disappeared before source readback".into(),
            ));
        };
        let expected = PackageRowExpectation {
            package_id: before_row.package_id,
            package_name: before_row.package_name.clone(),
            stable_code: before_row.package_code.clone(),
            description: before_row.description.clone(),
            price: before_row.price.clone(),
            baseline: before_row.baseline,
            billing_cycle: before_row.billing_cycle.clone(),
            status: "INACTIVE".into(),
        };
        if !package_row_matches(&after_row, &expected)
            || !package_timestamps_follow_mutation(&before_row, &after_row)
        {
            return Err(AstralError::Pending(
                "deleted package source readback changed fields other than status".into(),
            ));
        }
        let evidence = ProtectedSourceEvidence::new()
            .target_row(TargetRowEvidence {
                entity: "platform_package",
                key: serde_json::json!({ "packageId": id }),
                before: RowPresence::from_option(before.map(package_evidence)),
                after: RowPresence::from_option(after.map(package_evidence)),
            })
            .map_err(|error| AstralError::Pending(error.to_string()))?
            .receipt(
                "platform_package",
                serde_json::json!({ "packageId": id }),
                WriteKind::Update,
                update.rows_affected(),
            );
        let result = serde_json::json!({ "packageId": id, "deleted": true });
        finish_protected_mutation_in_tx(&mut tx, context, &result, &evidence).await?;
        tx.commit().await.map_err(|error| {
            AstralError::Pending(format!(
                "package delete COMMIT outcome unknown; reconcile operation {} before retry: {error}",
                context.operation_id(),
            ))
        })?;
        Ok(true)
    }
}

fn append_package_patch_sql(
    builder: &mut QueryBuilder<'_, sqlx::MySql>,
    patch: &PlatformPackagePatch,
) {
    let mut separated = builder.separated(", ");
    match &patch.package_name {
        PatchField::Omitted => {}
        PatchField::Set(value) => {
            separated
                .push("package_name = ")
                .push_bind_unseparated(value.clone());
        }
        PatchField::Clear => unreachable!("non-null package_name clear rejected above"),
    }
    match &patch.stable_code {
        PatchField::Omitted => {}
        PatchField::Set(value) => {
            separated
                .push("package_code = ")
                .push_bind_unseparated(value.clone());
        }
        PatchField::Clear => unreachable!("non-null stable_code clear rejected above"),
    }
    match &patch.description {
        PatchField::Omitted => {}
        PatchField::Set(value) => {
            separated
                .push("description = ")
                .push_bind_unseparated(value.clone());
        }
        PatchField::Clear => {
            separated
                .push("description = ")
                .push_bind_unseparated(None::<String>);
        }
    }
    match &patch.price {
        PatchField::Omitted => {}
        PatchField::Set(value) => {
            separated
                .push("price = ")
                .push_bind_unseparated(value.clone());
        }
        PatchField::Clear => {
            separated
                .push("price = ")
                .push_bind_unseparated(None::<String>);
        }
    }
    match &patch.baseline {
        PatchField::Omitted => {}
        PatchField::Set(value) => {
            separated
                .push("version_no = ")
                .push_bind_unseparated(*value);
        }
        PatchField::Clear => unreachable!("non-null baseline clear rejected above"),
    }
    match &patch.billing_cycle {
        PatchField::Omitted => {}
        PatchField::Set(value) => {
            separated
                .push("billing_cycle = ")
                .push_bind_unseparated(value.clone());
        }
        PatchField::Clear => unreachable!("billing_cycle clear rejected above"),
    }
    match &patch.status {
        PatchField::Omitted => {}
        PatchField::Set(value) => {
            separated
                .push("status = ")
                .push_bind_unseparated(value.clone());
        }
        PatchField::Clear => unreachable!("non-null status clear rejected above"),
    }
}

fn package_row_matches(row: &PackageRow, expected: &PackageRowExpectation) -> bool {
    row.package_id == expected.package_id
        && row.package_name == expected.package_name
        && row.package_code == expected.stable_code
        && row.description == expected.description
        && row.price == expected.price
        && row.baseline == expected.baseline
        && row.billing_cycle == expected.billing_cycle
        && row.status == expected.status
}

fn package_timestamps_follow_mutation(before: &PackageRow, after: &PackageRow) -> bool {
    before.created_at == after.created_at
        && match (before.updated_at, after.updated_at) {
            (Some(before), Some(after)) => after >= before,
            (None, _) => true,
            (Some(_), None) => false,
        }
}

fn package_expectation_after_patch(
    row: &PackageRow,
    patch: &PlatformPackagePatch,
) -> Result<PackageRowExpectation, AstralError> {
    let package_name = patch_string(&patch.package_name, &row.package_name, "packageName")?;
    let stable_code = patch_string(&patch.stable_code, &row.package_code, "stableCode")?;
    let description = patch_optional_string(&patch.description, &row.description);
    let price = patch_optional_string(&patch.price, &row.price);
    let baseline = patch_i32(&patch.baseline, row.baseline, "baseline")?;
    let billing_cycle = match &patch.billing_cycle {
        PatchField::Omitted => row.billing_cycle.clone(),
        PatchField::Set(value) if VALID_BILLING_CYCLES.contains(&value.as_str()) => {
            Some(value.clone())
        }
        PatchField::Set(_) => {
            return Err(AstralError::Validation(
                "billingCycle must be MONTHLY, QUARTERLY, YEARLY, or ONETIME".into(),
            ))
        }
        PatchField::Clear => {
            return Err(AstralError::Validation(
                "billingCycle cannot be cleared because purchases require a known cycle".into(),
            ))
        }
    };
    let status = patch_string(&patch.status, &row.status, "status")?;
    Ok(PackageRowExpectation {
        package_id: row.package_id,
        package_name,
        stable_code,
        description,
        price,
        baseline,
        billing_cycle,
        status,
    })
}

fn patch_string(
    patch: &PatchField<String>,
    current: &str,
    field: &str,
) -> Result<String, AstralError> {
    match patch {
        PatchField::Omitted => Ok(current.to_owned()),
        PatchField::Set(value) => Ok(value.clone()),
        PatchField::Clear => Err(AstralError::Validation(format!(
            "{field} cannot be cleared"
        ))),
    }
}

fn patch_optional_string(patch: &PatchField<String>, current: &Option<String>) -> Option<String> {
    match patch {
        PatchField::Omitted => current.clone(),
        PatchField::Set(value) => Some(value.clone()),
        PatchField::Clear => None,
    }
}

fn patch_i32(patch: &PatchField<i32>, current: i32, field: &str) -> Result<i32, AstralError> {
    match patch {
        PatchField::Omitted => Ok(current),
        PatchField::Set(value) => Ok(*value),
        PatchField::Clear => Err(AstralError::Validation(format!(
            "{field} cannot be cleared"
        ))),
    }
}

fn patch_field_json<T: Serialize>(patch: &PatchField<T>) -> serde_json::Value {
    match patch {
        PatchField::Omitted => serde_json::json!({ "omitted": true }),
        PatchField::Set(value) => serde_json::json!({ "value": value }),
        PatchField::Clear => serde_json::Value::Null,
    }
}

fn package_evidence(row: PackageRow) -> PackageEvidence {
    PackageEvidence {
        package_id: row.package_id,
        package_name: row.package_name,
        stable_code: row.package_code,
        description: row.description,
        price: row.price,
        baseline: row.baseline,
        billing_cycle: row.billing_cycle,
        status: row.status,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

fn db_error(error: sqlx::Error) -> AstralError {
    AstralError::Database(format!("Platform package repository query failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_builder_keeps_assignment_binds_and_where_bind_unseparated() {
        let patch = PlatformPackagePatch {
            package_name: PatchField::Set("starter".into()),
            description: PatchField::Clear,
            ..Default::default()
        };
        let mut builder = QueryBuilder::<sqlx::MySql>::new("UPDATE platform_package SET ");
        append_package_patch_sql(&mut builder, &patch);
        builder.push(" WHERE package_id = ").push_bind(7_i64);
        assert_eq!(
            builder.sql(),
            "UPDATE platform_package SET package_name = ?, description = ? WHERE package_id = ?"
        );
        assert!(!builder.sql().contains("= ,"));
        assert!(!builder.sql().contains(", ? WHERE"));
    }

    #[test]
    fn comparator_requires_all_non_status_fields_to_match() {
        let row = PackageRow {
            package_id: 1,
            package_name: "starter".into(),
            package_code: "starter.v1".into(),
            description: None,
            price: Some("10.00".into()),
            baseline: 1,
            billing_cycle: Some("MONTHLY".into()),
            status: "INACTIVE".into(),
            created_at: Some(1),
            updated_at: Some(2),
        };
        let mut expected = PackageRowExpectation {
            package_id: 1,
            package_name: "starter".into(),
            stable_code: "starter.v1".into(),
            description: None,
            price: Some("10.00".into()),
            baseline: 1,
            billing_cycle: Some("MONTHLY".into()),
            status: "INACTIVE".into(),
        };
        assert!(package_row_matches(&row, &expected));
        let mut changed = row.clone();
        changed.updated_at = Some(3);
        assert!(package_timestamps_follow_mutation(&row, &changed));
        changed.created_at = Some(2);
        assert!(!package_timestamps_follow_mutation(&row, &changed));
        changed.created_at = row.created_at;
        changed.updated_at = Some(1);
        assert!(!package_timestamps_follow_mutation(&row, &changed));
        changed.updated_at = None;
        assert!(!package_timestamps_follow_mutation(&row, &changed));
        expected.price = Some("11.00".into());
        assert!(!package_row_matches(&row, &expected));
    }

    #[test]
    fn billing_cycle_cannot_be_explicitly_cleared() {
        let row = PackageRow {
            package_id: 1,
            package_name: "starter".into(),
            package_code: "starter.v1".into(),
            description: None,
            price: Some("10.00".into()),
            baseline: 1,
            billing_cycle: Some("MONTHLY".into()),
            status: "ACTIVE".into(),
            created_at: Some(1),
            updated_at: Some(1),
        };
        let patch = PlatformPackagePatch {
            billing_cycle: PatchField::Clear,
            ..Default::default()
        };
        assert!(package_expectation_after_patch(&row, &patch).is_err());
    }
}
