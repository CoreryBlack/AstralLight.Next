//! Dedicated SDK ingress, outside CRUD route-to-permission inference.

use std::sync::Arc;
use std::time::Duration;

use astral_common::contract::ApiResponse;
use astral_sdk_contracts::{SignedAuthorizationRequest, MAX_REQUEST_BODY_BYTES};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;

use crate::service::integration_authorization::IntegrationAuthorizationService;

pub(crate) fn routes(service: Arc<IntegrationAuthorizationService>) -> Router {
    Router::new()
        .route(
            "/main/api/v1/integrations/authorization-decisions",
            post(authorize),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        .with_state(service)
}

async fn authorize(
    State(service): State<Arc<IntegrationAuthorizationService>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_none_or(|value| {
            !value
                .split(';')
                .next()
                .is_some_and(|v| v.trim() == "application/json")
        })
    {
        return rejection(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "INVALID_INTEGRATION_REQUEST",
        );
    }
    let signed: SignedAuthorizationRequest = match serde_json::from_slice(&body) {
        Ok(signed) => signed,
        Err(_) => return rejection(StatusCode::BAD_REQUEST, "INVALID_INTEGRATION_REQUEST"),
    };
    match tokio::time::timeout(Duration::from_secs(5), service.authorize(&headers, &signed)).await {
        Ok(Ok(decision)) => {
            let trace_id = signed.request.request_id.clone();
            let response = ApiResponse::success(decision).with_trace_id(trace_id.clone());
            ([("x-trace-id", trace_id)], axum::Json(response)).into_response()
        }
        Ok(Err(code)) => rejection(status_for(code), code),
        Err(_) => rejection(StatusCode::SERVICE_UNAVAILABLE, "AUTHORIZATION_PENDING"),
    }
}

fn status_for(code: &str) -> StatusCode {
    match code {
        "AUTHORIZATION_PENDING" => StatusCode::SERVICE_UNAVAILABLE,
        "INVALID_INTEGRATION_REQUEST" | "INVALID_MANIFEST" => StatusCode::BAD_REQUEST,
        "IDENTITY_REQUIRED" | "SESSION_INVALID" => StatusCode::UNAUTHORIZED,
        _ => StatusCode::FORBIDDEN,
    }
}

fn rejection(status: StatusCode, code: &'static str) -> Response {
    let mut response = ApiResponse::<serde_json::Value>::error(
        status.as_u16().into(),
        "Integration request refused",
    );
    response.reason_code = Some(code.into());
    response.decision = Some(code.into());
    response.error_type = Some(
        if status == StatusCode::UNAUTHORIZED {
            "AUTHENTICATION_ERROR"
        } else {
            "INTEGRATION_REFUSED"
        }
        .into(),
    );
    response.request_path = Some(astral_sdk_contracts::AUTHORIZATION_DECISIONS_PATH.into());
    response.request_method = Some("POST".into());
    let trace_id = uuid::Uuid::new_v4().to_string();
    response.trace_id = Some(trace_id.clone());
    (status, [("x-trace-id", trace_id)], axum::Json(response)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn malformed_requests_are_refused_before_database_access() {
        let pool = sqlx::mysql::MySqlPoolOptions::new()
            .connect_lazy("mysql://unused@localhost/unused")
            .unwrap();
        let service = Arc::new(IntegrationAuthorizationService {
            db: pool,
            engine: Arc::new(policy_engine::PolicyEngine::new()),
            config: crate::service::integration_authorization::IntegrationConfig::test_config(),
            org_scope_enabled: false,
        });
        let app = routes(service);
        for (content_type, body, expected) in [
            ("text/plain", "{}", StatusCode::UNSUPPORTED_MEDIA_TYPE),
            ("application/json", "{}", StatusCode::BAD_REQUEST),
            (
                "application/json",
                "{\"role\":\"admin\"}",
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(astral_sdk_contracts::AUTHORIZATION_PATH)
                        .header("content-type", content_type)
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(astral_sdk_contracts::AUTHORIZATION_PATH)
                    .header("content-type", "application/json")
                    .body(Body::from(vec![b' '; MAX_REQUEST_BODY_BYTES + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn unknown_and_mapping_failures_are_not_success() {
        assert_eq!(
            status_for("INTEGRATION_NOT_AUTHORIZED"),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status_for("AUTHORIZATION_PENDING"),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(status_for("SESSION_INVALID"), StatusCode::UNAUTHORIZED);
    }
}
