//! Assemble protected Monitor mutations from the permission middleware extension.

use astral_common::error::AppError;
use astral_db::ProtectedMutationContext;
use astral_types::{AstralError, AuthorizationAdmission, PolicyContext};
use axum::http::HeaderMap;

pub(crate) fn context(
    headers: &HeaderMap,
    policy: &PolicyContext,
    admission: AuthorizationAdmission,
    resource: &str,
    action: &str,
    target_id: Option<i64>,
) -> Result<ProtectedMutationContext, AppError> {
    ProtectedMutationContext::from_policy_context(
        policy,
        admission,
        headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok()),
        resource,
        action,
        target_id,
    )
    .map_err(AppError::from)
}

pub(crate) fn unexpected_result() -> AppError {
    AppError(AstralError::Internal(
        "Monitor mutation returned an incompatible result".into(),
    ))
}
