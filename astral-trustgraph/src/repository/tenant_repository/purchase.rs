//! Commerce source owner. A purchase records a subscription; it does not grant
//! policy rights or create authorization projection events.

use super::{db_error, NewPurchase};
use astral_db::{
    begin_protected_mutation_in_tx, finish_protected_mutation_in_tx, ProtectedMutationContext,
    ProtectedMutationStart, ProtectedSourceEvidence, RowPresence, TargetRowEvidence, WriteKind,
};
use astral_types::AstralError;
use serde::Serialize;
use sqlx::MySqlPool;

const VALID_BILLING_CYCLES: [&str; 4] = ["MONTHLY", "QUARTERLY", "YEARLY", "ONETIME"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
struct PurchaseEvidence {
    purchase_id: i64,
    tenant_id: i64,
    sub_tenant_id: Option<i64>,
    package_id: i64,
    status: String,
    purchased_at: Option<i64>,
    expired_at: Option<i64>,
    created_at: Option<i64>,
    updated_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
struct TenantIdentityEvidence {
    tenant_id: i64,
    tenant_name: String,
    status: String,
    parent_tenant_id: Option<i64>,
    path: Option<String>,
    depth: i32,
    created_at: Option<i64>,
    updated_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, sqlx::FromRow)]
struct PackageIdentityEvidence {
    package_id: i64,
    package_name: String,
    stable_code: String,
    description: Option<String>,
    price: Option<String>,
    baseline: i32,
    status: String,
    billing_cycle: Option<String>,
    created_at: Option<i64>,
    updated_at: Option<i64>,
}

const TENANT_LOCK_SQL: &str =
    "SELECT tenant_id, tenant_name, status, parent_tenant_id, path, depth, \
    CAST(UNIX_TIMESTAMP(created_at) AS SIGNED) AS created_at, \
    CAST(UNIX_TIMESTAMP(updated_at) AS SIGNED) AS updated_at \
    FROM tenant WHERE tenant_id = ? FOR UPDATE";
const PACKAGE_LOCK_SQL: &str = "SELECT package_id, package_name, package_code AS stable_code, \
    description, CAST(price AS CHAR) AS price, version_no AS baseline, status, billing_cycle, \
    CAST(UNIX_TIMESTAMP(created_at) AS SIGNED) AS created_at, \
    CAST(UNIX_TIMESTAMP(updated_at) AS SIGNED) AS updated_at \
    FROM platform_package WHERE package_id = ? FOR UPDATE";
const PURCHASE_LOCK_SQL: &str =
    "SELECT purchase_id, tenant_id, sub_tenant_id, package_id, status, \
    CAST(UNIX_TIMESTAMP(purchased_at) AS SIGNED) AS purchased_at, \
    CAST(UNIX_TIMESTAMP(expired_at) AS SIGNED) AS expired_at, \
    CAST(UNIX_TIMESTAMP(created_at) AS SIGNED) AS created_at, \
    CAST(UNIX_TIMESTAMP(updated_at) AS SIGNED) AS updated_at \
    FROM tenant_purchase WHERE purchase_id = ? FOR UPDATE";

pub(super) async fn create_purchase_with_context(
    pool: &MySqlPool,
    new: &NewPurchase,
    billing_cycle: &str,
    context: &ProtectedMutationContext,
) -> Result<i64, AstralError> {
    context.require_request("platform_tenant", "create", Some(new.tenant_id))?;
    if new.tenant_id <= 0 || new.plan_id <= 0 || new.tenant_id != context.tenant_id() {
        return Err(AstralError::Permission(
            "purchase tenant does not match the verified actor scope".into(),
        ));
    }
    if !VALID_BILLING_CYCLES.contains(&billing_cycle) {
        return Err(AstralError::Validation(
            "purchase billing cycle is not supported".into(),
        ));
    }
    let mut tx = pool.begin().await.map_err(db_error)?;
    let payload = serde_json::json!({
        "tenantId": new.tenant_id,
        "packageId": new.plan_id,
        "billingCycle": billing_cycle,
        "expiredAt": new.expired_secs,
    });
    if let ProtectedMutationStart::Completed(result) =
        begin_protected_mutation_in_tx(&mut tx, context, &payload).await?
    {
        return result
            .get("purchaseId")
            .and_then(serde_json::Value::as_i64)
            .filter(|id| *id > 0)
            .ok_or_else(|| AstralError::Database("invalid durable purchase result".into()));
    }

    // Lock the actor tenant and package before the source INSERT. These are
    // tenant/package facts, not authorization grants, and both are captured
    // again after the write in this same short transaction.
    let tenant_before: Option<TenantIdentityEvidence> = sqlx::query_as(TENANT_LOCK_SQL)
        .bind(new.tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
    if !matches!(tenant_before.as_ref(), Some(row) if row.tenant_id == new.tenant_id && row.status == "ACTIVE")
    {
        return Err(AstralError::Permission(
            "purchase tenant is absent or inactive".into(),
        ));
    }
    let package_before: Option<PackageIdentityEvidence> = sqlx::query_as(PACKAGE_LOCK_SQL)
        .bind(new.plan_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
    match &package_before {
        Some(row)
            if row.package_id == new.plan_id
                && row.status == "ACTIVE"
                && row.billing_cycle.as_deref() == Some(billing_cycle) => {}
        _ => {
            return Err(AstralError::Validation(
                "purchase package is absent, inactive, has an unknown billing cycle, or uses another billing cycle".into(),
            ))
        }
    }

    let insert = sqlx::query(
        "INSERT INTO tenant_purchase \
         (tenant_id, sub_tenant_id, package_id, status, purchased_at, expired_at) \
         VALUES (?, ?, ?, 'ACTIVE', UTC_TIMESTAMP(), FROM_UNIXTIME(?))",
    )
    .bind(new.tenant_id)
    .bind(None::<i64>)
    .bind(new.plan_id)
    .bind(new.expired_secs)
    .execute(&mut *tx)
    .await
    .map_err(db_error)?;
    if insert.rows_affected() != 1 {
        return Err(AstralError::Pending(format!(
            "purchase insert affected {} rows; refusing unproven source evidence",
            insert.rows_affected()
        )));
    }
    let purchase_id = i64::try_from(insert.last_insert_id())
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| AstralError::Pending("purchase insert returned an unusable id".into()))?;
    let purchase_after: Option<PurchaseEvidence> = sqlx::query_as(PURCHASE_LOCK_SQL)
        .bind(purchase_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
    let Some(actual_purchase) = &purchase_after else {
        return Err(AstralError::Pending(
            "inserted purchase has no same-transaction source readback".into(),
        ));
    };
    if actual_purchase.purchase_id != purchase_id
        || actual_purchase.tenant_id != new.tenant_id
        || actual_purchase.package_id != new.plan_id
        || actual_purchase.sub_tenant_id.is_some()
        || actual_purchase.status != "ACTIVE"
        || actual_purchase.expired_at != new.expired_secs
        || actual_purchase.purchased_at.is_none()
        || actual_purchase.created_at.is_none()
        || actual_purchase.updated_at.is_none()
    {
        return Err(AstralError::Pending(
            "purchase source readback differs from the requested row or lacks generated timestamps"
                .into(),
        ));
    }
    let tenant_after: Option<TenantIdentityEvidence> = sqlx::query_as(TENANT_LOCK_SQL)
        .bind(new.tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
    if !matches!(tenant_after.as_ref(), Some(row) if row.tenant_id == new.tenant_id && row.status == "ACTIVE")
    {
        return Err(AstralError::Pending(
            "purchase tenant source readback is absent or no longer ACTIVE".into(),
        ));
    }
    let package_after: Option<PackageIdentityEvidence> = sqlx::query_as(PACKAGE_LOCK_SQL)
        .bind(new.plan_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_error)?;
    if !matches!(
        package_after.as_ref(),
        Some(row)
            if row.package_id == new.plan_id
                && row.status == "ACTIVE"
                && row.billing_cycle.as_deref() == Some(billing_cycle)
    ) {
        return Err(AstralError::Pending(
            "purchase package source readback differs from the requested active package or has an unknown billing cycle".into(),
        ));
    }
    if tenant_before != tenant_after || package_before != package_after {
        return Err(AstralError::Pending(
            "purchase tenant or package changed between locked validation and source readback"
                .into(),
        ));
    }

    let evidence = ProtectedSourceEvidence::new()
        .target_row(TargetRowEvidence {
            entity: "tenant_purchase",
            key: serde_json::json!({ "purchaseId": purchase_id }),
            before: RowPresence::Absent,
            after: RowPresence::from_option(purchase_after),
        })
        .map_err(|error| AstralError::Pending(error.to_string()))?
        .target_row(TargetRowEvidence {
            entity: "tenant",
            key: serde_json::json!({ "tenantId": new.tenant_id }),
            before: RowPresence::from_option(tenant_before.clone()),
            after: RowPresence::from_option(tenant_after.clone()),
        })
        .map_err(|error| AstralError::Pending(error.to_string()))?
        .target_row(TargetRowEvidence {
            entity: "platform_package",
            key: serde_json::json!({ "packageId": new.plan_id }),
            before: RowPresence::from_option(package_before.clone()),
            after: RowPresence::from_option(package_after.clone()),
        })
        .map_err(|error| AstralError::Pending(error.to_string()))?
        .receipt(
            "tenant_purchase",
            serde_json::json!({
                "purchaseId": purchase_id,
                "tenantId": new.tenant_id,
                "packageId": new.plan_id,
            }),
            WriteKind::Insert,
            insert.rows_affected(),
        );
    let result = serde_json::json!({ "purchaseId": purchase_id });
    finish_protected_mutation_in_tx(&mut tx, context, &result, &evidence).await?;
    tx.commit().await.map_err(|error| {
        AstralError::Pending(format!(
            "purchase COMMIT outcome unknown; reconcile operation {} before retry: {error}",
            context.operation_id(),
        ))
    })?;
    Ok(purchase_id)
}
