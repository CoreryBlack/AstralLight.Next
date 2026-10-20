use astral_common::config::{AppConfig, GatewayCfg};
use astral_common::middleware::gateway_signature::compute_hmac_signature_v3;
use axum::body::{to_bytes, Body};
use axum::http::{Method, Request, StatusCode};
use axum::{middleware, routing::get, Router};
use hmac::Mac;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

const PATH: &str = "/v1/app/learn/progress/42";
const USER_ID: &str = "42";
const TOKEN_ID: &str = "token-1";
const ACTION_CODES: &str = "read";
const USER_ROLES: &str = "STUDENT";

fn gateway_secret() -> String {
    format!("gateway-contract-{}", "s".repeat(32))
}

fn config() -> AppConfig {
    AppConfig {
        gateway: GatewayCfg {
            hmac_secret: gateway_secret(),
            internal_service_secret: "gateway-internal-test-secret-0123456789".into(),
            timestamp_tolerance_secs: 30,
            trusted_proxy_ips: vec![],
        },
        ..Default::default()
    }
}

fn signed_request(method: &str, path: &str) -> Request<Body> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string();
    let signature = compute_hmac_signature_v3(
        &gateway_secret(),
        method,
        path,
        USER_ID,
        "APP_USER",
        TOKEN_ID,
        "identity-card",
        "",
        "",
        "",
        "ACCESS",
        "2",
        ACTION_CODES,
        USER_ROLES,
        &timestamp,
    );
    Request::builder()
        .method(method)
        .uri(path)
        .header("x-gateway-auth", "verified")
        .header("x-gateway-ts", timestamp)
        .header("x-gateway-signature", signature)
        .header("x-user-id", USER_ID)
        .header("x-principal-kind", "APP_USER")
        .header("x-token-id", TOKEN_ID)
        .header("x-identity-card-id", "identity-card")
        .header("x-token-use", "ACCESS")
        .header("x-claims-version", "2")
        .header("x-action-codes", ACTION_CODES)
        .header("x-user-roles", USER_ROLES)
        .body(Body::empty())
        .unwrap()
}

fn platform_signed_request(method: &str, path: &str) -> Request<Body> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string();
    let signature = compute_hmac_signature_v3(
        &gateway_secret(),
        method,
        path,
        USER_ID,
        "PLATFORM_USER",
        TOKEN_ID,
        "identity-card",
        "user-card",
        "user-domain",
        "user-tenant",
        "ACCESS",
        "2",
        ACTION_CODES,
        USER_ROLES,
        &timestamp,
    );
    Request::builder()
        .method(method)
        .uri(path)
        .header("x-gateway-auth", "verified")
        .header("x-gateway-ts", timestamp)
        .header("x-gateway-signature", signature)
        .header("x-user-id", USER_ID)
        .header("x-principal-kind", "PLATFORM_USER")
        .header("x-token-id", TOKEN_ID)
        .header("x-identity-card-id", "identity-card")
        .header("x-user-card-id", "user-card")
        .header("x-user-card-domain-id", "user-domain")
        .header("x-user-card-tenant-id", "user-tenant")
        .header("x-token-use", "ACCESS")
        .header("x-claims-version", "2")
        .header("x-action-codes", ACTION_CODES)
        .header("x-user-roles", USER_ROLES)
        .body(Body::empty())
        .unwrap()
}

fn resign_request(request: &mut Request<Body>) {
    let method = request.method().as_str().to_owned();
    let path = request
        .headers()
        .get("x-original-path")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| request.uri().path().to_owned());
    let value = |name: &str| {
        request
            .headers()
            .get(name)
            .and_then(|header| header.to_str().ok())
            .unwrap_or("")
            .trim()
            .to_owned()
    };
    let timestamp = value("x-gateway-ts");
    let signature = compute_hmac_signature_v3(
        &gateway_secret(),
        &method,
        &path,
        &value("x-user-id"),
        &value("x-principal-kind"),
        &value("x-token-id"),
        &value("x-identity-card-id"),
        &value("x-user-card-id"),
        &value("x-user-card-domain-id"),
        &value("x-user-card-tenant-id"),
        &value("x-token-use"),
        &value("x-claims-version"),
        &value("x-action-codes"),
        &value("x-user-roles"),
        &timestamp,
    );
    request
        .headers_mut()
        .insert("x-gateway-signature", signature.parse().unwrap());
}

/// 用于构造旧契约签名请求，验证 v3-only 中间件拒绝 v2 签名。
#[allow(clippy::too_many_arguments)]
fn legacy_v2_signature(
    secret: &str,
    method: &str,
    path: &str,
    user_id: &str,
    token_id: &str,
    identity_card_id: &str,
    user_card_id: &str,
    identity_domain_id: &str,
    identity_tenant_id: &str,
    user_card_domain_id: &str,
    user_card_tenant_id: &str,
    token_use: &str,
    claims_version: &str,
    action_codes: &str,
    user_roles: &str,
    timestamp: &str,
) -> String {
    let payload = format!(
        "astral-gateway-v2\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        method.trim(),
        path.trim(),
        user_id.trim(),
        token_id.trim(),
        identity_card_id.trim(),
        user_card_id.trim(),
        identity_domain_id.trim(),
        identity_tenant_id.trim(),
        user_card_domain_id.trim(),
        user_card_tenant_id.trim(),
        token_use.trim(),
        claims_version.trim(),
        action_codes.trim(),
        user_roles.trim(),
        timestamp.trim(),
    );
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn legacy_v2_signed_request(method: &str, path: &str) -> Request<Body> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string();
    let signature = legacy_v2_signature(
        &gateway_secret(),
        method,
        path,
        USER_ID,
        TOKEN_ID,
        "identity-card",
        "user-card",
        "identity-domain",
        "identity-tenant",
        "user-domain",
        "user-tenant",
        "ACCESS",
        "2",
        ACTION_CODES,
        USER_ROLES,
        &timestamp,
    );
    Request::builder()
        .method(method)
        .uri(path)
        .header("x-gateway-auth", "verified")
        .header("x-gateway-ts", timestamp)
        .header("x-gateway-signature", signature)
        .header("x-user-id", USER_ID)
        .header("x-principal-kind", "PLATFORM_USER")
        .header("x-token-id", TOKEN_ID)
        .header("x-identity-card-id", "identity-card")
        .header("x-user-card-id", "user-card")
        .header("x-identity-tenant-id", "identity-tenant")
        .header("x-user-card-domain-id", "user-domain")
        .header("x-user-card-tenant-id", "user-tenant")
        .header("x-token-use", "ACCESS")
        .header("x-claims-version", "2")
        .header("x-action-codes", ACTION_CODES)
        .header("x-user-roles", USER_ROLES)
        .body(Body::empty())
        .unwrap()
}

fn app_with_counter(counter: Arc<AtomicUsize>) -> Router {
    Router::new()
        .route(
            PATH,
            get(move || {
                let counter = Arc::clone(&counter);
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    "gateway-handler-marker"
                }
            }),
        )
        .layer(middleware::from_fn_with_state(
            config(),
            astral_common::middleware::gateway_signature::gateway_signature_middleware,
        ))
        .with_state(config())
}

#[tokio::test]
async fn signed_request_with_unchanged_fields_reaches_handler() {
    let counter = Arc::new(AtomicUsize::new(0));
    let response = app_with_counter(Arc::clone(&counter))
        .oneshot(signed_request("GET", PATH))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .as_ref(),
        b"gateway-handler-marker"
    );
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "valid request must invoke handler exactly once"
    );
}

#[tokio::test]
async fn changing_method_path_or_identity_invalidates_signature_and_skips_handler() {
    for (label, mut request) in [
        ("method", signed_request("GET", PATH)),
        ("path", signed_request("GET", PATH)),
        ("identity", signed_request("GET", PATH)),
    ] {
        match label {
            "method" => *request.method_mut() = Method::POST,
            "path" => *request.uri_mut() = "/v1/app/learn/progress/43".parse().unwrap(),
            "identity" => {
                request
                    .headers_mut()
                    .insert("x-user-id", "43".parse().unwrap());
            }
            _ => unreachable!(),
        }
        let counter = Arc::new(AtomicUsize::new(0));
        let response = app_with_counter(Arc::clone(&counter))
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{label} mutation");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "{label} mutation must not invoke handler"
        );
    }
}

#[tokio::test]
async fn missing_gateway_auth_and_invalid_signature_are_rejected_before_handler() {
    for (label, mut request) in [
        ("missing auth", signed_request("GET", PATH)),
        ("invalid signature", signed_request("GET", PATH)),
    ] {
        if label == "missing auth" {
            request.headers_mut().remove("x-gateway-auth");
        } else {
            request
                .headers_mut()
                .insert("x-gateway-signature", "not-a-signature".parse().unwrap());
        }
        let counter = Arc::new(AtomicUsize::new(0));
        let response = app_with_counter(Arc::clone(&counter))
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{label}");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "{label} must not invoke handler"
        );
    }
}

#[tokio::test]
async fn app_user_with_any_user_card_field_is_rejected() {
    for field in [
        "x-user-card-id",
        "x-user-card-domain-id",
        "x-user-card-tenant-id",
    ] {
        let mut request = signed_request("GET", PATH);
        request
            .headers_mut()
            .insert(field, "unexpected-card-context".parse().unwrap());
        resign_request(&mut request);

        let counter = Arc::new(AtomicUsize::new(0));
        let response = app_with_counter(Arc::clone(&counter))
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{field}");
        let body: serde_json::Value = serde_json::from_slice(
            to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        assert_eq!(
            body["reasonCode"], "PRINCIPAL_CARD_CONTEXT_INVALID",
            "APP_USER with {field} must expose the card-context rejection reason"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "APP_USER with {field} must not invoke handler"
        );
    }
}

#[tokio::test]
async fn platform_user_missing_any_user_card_field_is_rejected() {
    for field in [
        "x-user-card-id",
        "x-user-card-domain-id",
        "x-user-card-tenant-id",
    ] {
        let mut request = platform_signed_request("GET", PATH);
        request.headers_mut().remove(field);
        resign_request(&mut request);

        let counter = Arc::new(AtomicUsize::new(0));
        let response = app_with_counter(Arc::clone(&counter))
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{field}");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "PLATFORM_USER without {field} must not invoke handler"
        );
    }
}

#[tokio::test]
async fn identity_and_user_card_field_tampering_invalidates_signature() {
    let cases = vec![
        (
            "APP_USER identity card",
            signed_request("GET", PATH),
            "x-identity-card-id",
        ),
        (
            "PLATFORM_USER identity card",
            platform_signed_request("GET", PATH),
            "x-identity-card-id",
        ),
        (
            "PLATFORM_USER user card",
            platform_signed_request("GET", PATH),
            "x-user-card-id",
        ),
        (
            "PLATFORM_USER user card domain",
            platform_signed_request("GET", PATH),
            "x-user-card-domain-id",
        ),
        (
            "PLATFORM_USER user card tenant",
            platform_signed_request("GET", PATH),
            "x-user-card-tenant-id",
        ),
    ];

    for (label, mut request, field) in cases {
        request
            .headers_mut()
            .insert(field, "tampered-card-context".parse().unwrap());
        let counter = Arc::new(AtomicUsize::new(0));
        let response = app_with_counter(Arc::clone(&counter))
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{label}");
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "{label} must not invoke handler"
        );
    }
}

#[tokio::test]
async fn legacy_v2_signature_is_rejected_by_v3_only_middleware() {
    // 构造 legacy v2 签名请求（含身份侧 tenant/domain 头）。
    // v3-only 中间件按 v3 canonical payload 重新计算，v2 签名必然不匹配，
    // 断言 403 且 handler 不执行（不恢复生产 v2 验证路径）。
    let request = legacy_v2_signed_request("GET", PATH);
    let counter = Arc::new(AtomicUsize::new(0));
    let response = app_with_counter(Arc::clone(&counter))
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        counter.load(Ordering::SeqCst),
        0,
        "legacy v2 request must not invoke handler"
    );
}
