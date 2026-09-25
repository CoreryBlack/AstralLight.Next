use astral_common::error::AppError;
use astral_types::AstralError;
use axum::http::HeaderMap;

pub fn authenticated_user_id(headers: &HeaderMap) -> Result<i64, AppError> {
    headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .filter(|id: &i64| *id > 0)
        .ok_or_else(|| AppError(AstralError::Auth("Authenticated user is required".into())))
}

pub fn require_same_user(authenticated: i64, target: i64) -> Result<(), AppError> {
    if authenticated <= 0 {
        return Err(AppError(AstralError::Auth(
            "Authenticated user is required".into(),
        )));
    }
    if authenticated != target {
        return Err(AppError(AstralError::Permission(
            "User ownership mismatch".into(),
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn missing_user_header_is_rejected() {
        assert!(matches!(
            authenticated_user_id(&HeaderMap::new()),
            Err(AppError(AstralError::Auth(_)))
        ));
    }

    #[test]
    fn malformed_user_header_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("x-user-id", HeaderValue::from_static("not-a-user-id"));
        assert!(matches!(
            authenticated_user_id(&headers),
            Err(AppError(AstralError::Auth(_)))
        ));
    }

    #[test]
    fn ownership() {
        assert!(matches!(
            require_same_user(0, 1),
            Err(AppError(AstralError::Auth(_)))
        ));
        assert!(matches!(
            require_same_user(1, 2),
            Err(AppError(AstralError::Permission(_)))
        ));
        assert!(require_same_user(3, 3).is_ok());
    }
}
