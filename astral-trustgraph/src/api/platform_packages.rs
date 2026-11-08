//! Platform package CRUD API.
//!
//! Package mutations are ProtectedBusiness mutations. The permission middleware
//! supplies the verified PolicyContext and one-use AuthorizationAdmission; the
//! handler binds both to the exact route target and the repository commits the
//! commerce source, audit, idempotency result, and typed evidence together.
//! Packages are commerce data and never create authorization grants.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Extension, Json, Router};
use serde::{Deserialize, Serialize};

use astral_common::contract::{ApiResponse, EmptyResponse, PageResponse, PaginationParams};
use astral_common::error::AppError;
use astral_db::ProtectedMutationContext;
use astral_types::{AstralError, AuthorizationAdmission, PolicyContext};

use crate::repository::platform_package_repository::{
    NewPlatformPackage, PatchField, PlatformPackagePatch, PlatformPackageRecord,
};
use crate::AppState;

const VALID_BILLING_CYCLES: [&str; 4] = ["MONTHLY", "QUARTERLY", "YEARLY", "ONETIME"];
const VALID_STATUSES: [&str; 2] = ["ACTIVE", "INACTIVE"];
const MAX_PRICE_CENTS: i64 = 9_999_999_999;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformPackage {
    pub package_id: i64,
    pub package_name: String,
    pub stable_code: String,
    pub description: Option<String>,
    pub price_cents: Option<i64>,
    pub baseline: i32,
    pub billing_cycle: Option<String>,
    pub status: String,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

impl TryFrom<PlatformPackageRecord> for PlatformPackage {
    type Error = AstralError;

    fn try_from(record: PlatformPackageRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            package_id: record.package_id,
            package_name: record.package_name,
            stable_code: record.stable_code,
            description: record.description,
            price_cents: record.price.as_deref().map(decimal_to_cents).transpose()?,
            baseline: record.baseline,
            billing_cycle: record.billing_cycle,
            status: record.status,
            created_at: record.created_at,
            updated_at: record.updated_at,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePlatformPackageRequest {
    pub package_name: String,
    pub stable_code: String,
    pub description: Option<String>,
    pub price_cents: Option<i64>,
    #[serde(default = "default_baseline")]
    pub baseline: i32,
    pub billing_cycle: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdatePlatformPackageRequest {
    #[serde(default)]
    pub package_name: PatchField<String>,
    #[serde(default)]
    pub stable_code: PatchField<String>,
    #[serde(default)]
    pub description: PatchField<String>,
    #[serde(default)]
    pub price_cents: PatchField<i64>,
    #[serde(default)]
    pub baseline: PatchField<i32>,
    #[serde(default)]
    pub billing_cycle: PatchField<String>,
    #[serde(default)]
    pub status: PatchField<String>,
}

pub fn platform_package_routes() -> Router<AppState> {
    Router::new()
        .route("/platform-packages", get(list_platform_packages))
        .route("/platform-packages", post(create_platform_package))
        .route("/platform-packages/{id}", get(get_platform_package))
        .route("/platform-packages/{id}", put(update_platform_package))
        .route("/platform-packages/{id}", delete(delete_platform_package))
}

async fn list_platform_packages(
    State(state): State<AppState>,
    Query(page): Query<PaginationParams>,
) -> Result<Json<ApiResponse<PageResponse<PlatformPackage>>>, AppError> {
    let total = state.platform_package_repository.count_packages().await?;
    let rows = state
        .platform_package_repository
        .list_packages(page.effective_size(), page.offset())
        .await?
        .into_iter()
        .map(PlatformPackage::try_from)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(ApiResponse::success(PageResponse::new(
        rows,
        total,
        page.page,
        page.effective_size(),
    ))))
}

async fn create_platform_package(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Json(req): Json<CreatePlatformPackageRequest>,
) -> Result<Json<ApiResponse<PlatformPackage>>, AppError> {
    let context = ProtectedMutationContext::from_policy_context(
        &policy,
        admission,
        request_id(&headers),
        "platform_package",
        "create",
        None,
    )?;
    validate_package_name(&req.package_name)?;
    validate_stable_code(&req.stable_code)?;
    validate_baseline(req.baseline)?;
    let price = req.price_cents.map(cents_to_decimal).transpose()?;
    let billing_cycle = validate_required_billing_cycle(&req.billing_cycle)?;
    let package_id = state
        .platform_package_repository
        .create_package_with_context(
            &NewPlatformPackage {
                package_name: req.package_name,
                stable_code: req.stable_code,
                description: req.description,
                price,
                baseline: req.baseline,
                billing_cycle: billing_cycle.to_owned(),
            },
            &context,
        )
        .await?;
    let row = state
        .platform_package_repository
        .get_package(package_id)
        .await?
        .ok_or_else(|| {
            AppError(AstralError::Pending(format!(
                "package {package_id} committed without a readable postcondition"
            )))
        })?
        .try_into()?;
    Ok(Json(ApiResponse::success(row)))
}

async fn get_platform_package(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<PlatformPackage>>, AppError> {
    let row = state
        .platform_package_repository
        .get_package(id)
        .await?
        .ok_or_else(|| AppError(AstralError::NotFound(format!("platform package {id}"))))?
        .try_into()?;
    Ok(Json(ApiResponse::success(row)))
}

async fn update_platform_package(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(id): Path<i64>,
    Json(req): Json<UpdatePlatformPackageRequest>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    if id <= 0 {
        return Err(AppError(AstralError::Validation(
            "package id must be positive".into(),
        )));
    }
    let context = ProtectedMutationContext::from_policy_context(
        &policy,
        admission,
        request_id(&headers),
        "platform_package",
        "update",
        Some(id),
    )?;
    if let PatchField::Set(value) = &req.package_name {
        validate_package_name(value)?;
    }
    if let PatchField::Set(value) = &req.stable_code {
        validate_stable_code(value)?;
    }
    if let PatchField::Set(value) = &req.baseline {
        validate_baseline(*value)?;
    }
    let price = match &req.price_cents {
        PatchField::Omitted => PatchField::Omitted,
        PatchField::Clear => PatchField::Clear,
        PatchField::Set(value) => PatchField::Set(cents_to_decimal(*value)?),
    };
    let billing_cycle = match &req.billing_cycle {
        PatchField::Omitted => PatchField::Omitted,
        PatchField::Clear => PatchField::Clear,
        PatchField::Set(value) => {
            PatchField::Set(validate_required_billing_cycle(value)?.to_owned())
        }
    };
    let status = match &req.status {
        PatchField::Omitted => PatchField::Omitted,
        PatchField::Clear => PatchField::Clear,
        PatchField::Set(value) => PatchField::Set(
            validate_status(Some(value))?
                .ok_or_else(|| AppError(AstralError::Validation("status is required".into())))?
                .to_owned(),
        ),
    };
    let patch = PlatformPackagePatch {
        package_name: req.package_name,
        stable_code: req.stable_code,
        description: req.description,
        price,
        baseline: req.baseline,
        billing_cycle,
        status,
    };
    state
        .platform_package_repository
        .update_package_with_context(id, &patch, &context)
        .await?;
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

async fn delete_platform_package(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(policy): Extension<PolicyContext>,
    Extension(admission): Extension<AuthorizationAdmission>,
    Path(id): Path<i64>,
) -> Result<Json<ApiResponse<EmptyResponse>>, AppError> {
    if id <= 0 {
        return Err(AppError(AstralError::Validation(
            "package id must be positive".into(),
        )));
    }
    let context = ProtectedMutationContext::from_policy_context(
        &policy,
        admission,
        request_id(&headers),
        "platform_package",
        "delete",
        Some(id),
    )?;
    if !state
        .platform_package_repository
        .soft_delete_package_with_context(id, &context)
        .await?
    {
        return Err(AppError(AstralError::NotFound(format!(
            "platform package {id} not found"
        ))));
    }
    Ok(Json(ApiResponse::success(EmptyResponse)))
}

fn request_id(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
}

fn default_baseline() -> i32 {
    1
}

fn validate_package_name(value: &str) -> Result<(), AppError> {
    if value.is_empty() || value.len() > 64 {
        return Err(AppError(AstralError::Validation(
            "packageName must contain 1..64 bytes".into(),
        )));
    }
    Ok(())
}

fn validate_stable_code(value: &str) -> Result<(), AppError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(AppError(AstralError::Validation(
            "stableCode must be 1..64 ASCII letters, digits, '-', '_', or '.'".into(),
        )));
    }
    Ok(())
}

fn validate_baseline(value: i32) -> Result<(), AppError> {
    if value <= 0 {
        return Err(AppError(AstralError::Validation(
            "baseline must be positive".into(),
        )));
    }
    Ok(())
}

fn validate_required_billing_cycle(value: &str) -> Result<&str, AppError> {
    if value.is_empty() || !VALID_BILLING_CYCLES.contains(&value) {
        return Err(AppError(AstralError::Validation(
            "billingCycle is required and must be MONTHLY, QUARTERLY, YEARLY, or ONETIME".into(),
        )));
    }
    Ok(value)
}

fn validate_status(value: Option<&str>) -> Result<Option<&str>, AppError> {
    match value {
        Some(value) if !VALID_STATUSES.contains(&value) => Err(AppError(AstralError::Validation(
            "status must be ACTIVE or INACTIVE".into(),
        ))),
        other => Ok(other),
    }
}

fn cents_to_decimal(cents: i64) -> Result<String, AppError> {
    if !(0..=MAX_PRICE_CENTS).contains(&cents) {
        return Err(AppError(AstralError::Validation(
            "priceCents must be between 0 and 9999999999".into(),
        )));
    }
    Ok(format!("{}.{:02}", cents / 100, cents % 100))
}

fn decimal_to_cents(value: &str) -> Result<i64, AstralError> {
    let (whole, fraction) = value
        .split_once('.')
        .ok_or_else(|| AstralError::Database("package price is not an exact decimal".into()))?;
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() != 2
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(AstralError::Database(
            "package price is not an exact DECIMAL(10,2) value".into(),
        ));
    }
    let whole = whole
        .parse::<i64>()
        .map_err(|_| AstralError::Database("package price exceeds integer range".into()))?;
    let fraction = fraction
        .parse::<i64>()
        .map_err(|_| AstralError::Database("package price fraction is invalid".into()))?;
    let cents = whole
        .checked_mul(100)
        .and_then(|value| value.checked_add(fraction))
        .ok_or_else(|| AstralError::Database("package price exceeds cents range".into()))?;
    if cents > MAX_PRICE_CENTS {
        return Err(AstralError::Database(
            "package price exceeds DECIMAL(10,2) range".into(),
        ));
    }
    Ok(cents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn price_cents_conversion_is_exact_and_checked() {
        assert_eq!(cents_to_decimal(0).unwrap(), "0.00");
        assert_eq!(cents_to_decimal(9_999_999_999).unwrap(), "99999999.99");
        assert_eq!(decimal_to_cents("12.30").unwrap(), 1230);
        assert!(cents_to_decimal(-1).is_err());
        assert!(cents_to_decimal(10_000_000_000).is_err());
        assert!(decimal_to_cents("12.3").is_err());
        assert!(decimal_to_cents("12.345").is_err());
        assert!(decimal_to_cents("-1.00").is_err());
    }

    #[test]
    fn create_requires_an_explicit_supported_billing_cycle() {
        assert!(validate_required_billing_cycle("").is_err());
        assert!(validate_required_billing_cycle("MONTHLY").is_ok());
        assert!(validate_required_billing_cycle("UNKNOWN").is_err());
    }

    #[test]
    fn update_patch_distinguishes_omitted_null_and_value() {
        let omitted: UpdatePlatformPackageRequest =
            serde_json::from_value(serde_json::json!({})).expect("empty patch should deserialize");
        assert!(matches!(omitted.description, PatchField::Omitted));

        let cleared: UpdatePlatformPackageRequest =
            serde_json::from_value(serde_json::json!({ "description": null }))
                .expect("explicit null should deserialize");
        assert!(matches!(cleared.description, PatchField::Clear));

        let set: UpdatePlatformPackageRequest =
            serde_json::from_value(serde_json::json!({ "description": "updated" }))
                .expect("explicit value should deserialize");
        assert!(matches!(set.description, PatchField::Set(value) if value == "updated"));
    }

    #[test]
    fn mutations_bind_verified_context_and_do_not_use_global_admin_bypass() {
        let source = include_str!("platform_packages.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for name in [
            "create_platform_package",
            "update_platform_package",
            "delete_platform_package",
        ] {
            let start = production
                .find(&format!("async fn {name}"))
                .unwrap_or_else(|| panic!("{name} handler must exist"));
            let body = &production[start..];
            assert!(body.contains("Extension(policy): Extension<PolicyContext>"));
            assert!(body.contains("Extension(admission): Extension<AuthorizationAdmission>"));
            assert!(body.contains("ProtectedMutationContext::from_policy_context"));
            assert!(!body.contains("require_platform_admin"));
        }
    }
}
