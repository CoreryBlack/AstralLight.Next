//! Gateway 签名验证中间件
//!
//! 对齐 Java `GatewayIdentityHeaders.isVerified()`：
//! 下游服务验证 X-Gateway-Auth / X-Gateway-Ts / X-Gateway-Signature 头，
//! 确保请求确实来自 Gateway 而非伪造。

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use hmac::Mac;

use crate::config::AppConfig;
use crate::token_contract::PrincipalKind;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// 计算 Rust v3 HMAC-SHA256 签名。
///
/// v3 相对 v2 的变化（问题 1 修正）：identity_card 不承担组织归属，
/// canonical payload 移除 identity tenant/domain 字段（与 claims 契约同步）。
/// 保留绑定：method/path、token profile、identity card id、user-card 三字段。
/// 空值用空行表示，保证所有 producer/verifier 字段顺序一致。
#[allow(clippy::too_many_arguments)]
pub fn compute_hmac_signature_v3(
    secret: &str,
    method: &str,
    path: &str,
    user_id: &str,
    principal_kind: &str,
    token_id: &str,
    identity_card_id: &str,
    user_card_id: &str,
    user_card_domain_id: &str,
    user_card_tenant_id: &str,
    token_use: &str,
    claims_version: &str,
    action_codes: &str,
    user_roles: &str,
    timestamp: &str,
) -> String {
    let payload = format!(
        "astral-gateway-v3\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        method.trim(),
        path.trim(),
        user_id.trim(),
        principal_kind.trim(),
        token_id.trim(),
        identity_card_id.trim(),
        user_card_id.trim(),
        user_card_domain_id.trim(),
        user_card_tenant_id.trim(),
        token_use.trim(),
        claims_version.trim(),
        action_codes.trim(),
        user_roles.trim(),
        timestamp.trim(),
    );

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Gateway 签名验证中间件
///
/// 验证步骤（对齐 Java `GatewayIdentityHeaders.isVerified()`）：
/// 1. 检查 X-Gateway-Auth == "verified"
/// 2. 检查 X-Gateway-Ts / X-Gateway-Signature 存在
/// 3. 时间戳容差检查（默认 30 秒）
/// 4. 重新计算签名并做常量时间比较
///
/// 注意：Gateway 自身不添加此中间件（它是签名生成方，不是验证方）
pub async fn gateway_signature_middleware(
    State(config): State<AppConfig>,
    req: Request,
    next: Next,
) -> Response {
    let headers = req.headers();

    // Step 1: 检查 X-Gateway-Auth
    let gateway_auth = headers
        .get("x-gateway-auth")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");

    if !gateway_auth.eq_ignore_ascii_case("verified") {
        return gateway_error(
            &req,
            403,
            "Missing or invalid gateway auth",
            "FORBIDDEN",
            "GATEWAY_AUTH_INVALID",
        );
    }

    // Step 2: 检查必要头存在
    let timestamp = headers
        .get("x-gateway-ts")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");

    let signature = headers
        .get("x-gateway-signature")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");

    if timestamp.is_empty() || signature.is_empty() {
        return gateway_error(
            &req,
            403,
            "Missing gateway timestamp or signature",
            "FORBIDDEN",
            "GATEWAY_SIGNATURE_MISSING",
        );
    }

    // Step 3: 时间戳容差检查
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    let tolerance_ms = match config.gateway.timestamp_tolerance_secs.checked_mul(1000) {
        Some(value) if value > 0 => value,
        _ => {
            return gateway_error(
                &req,
                500,
                "Gateway timestamp tolerance is invalid",
                "INTERNAL_ERROR",
                "GATEWAY_TIMESTAMP_TOLERANCE_INVALID",
            )
        }
    };
    let ts_ms: i64 = match timestamp.parse() {
        Ok(v) => v,
        Err(_) => {
            return gateway_error(
                &req,
                403,
                "Invalid gateway timestamp",
                "FORBIDDEN",
                "GATEWAY_TIMESTAMP_INVALID",
            )
        }
    };

    if (now_ms - ts_ms).abs() > tolerance_ms {
        return gateway_error(
            &req,
            403,
            "Gateway timestamp skew too large",
            "FORBIDDEN",
            "GATEWAY_TIMESTAMP_SKEW",
        );
    }

    // Step 4: 重新计算签名并比较
    let method = req.method().as_str();
    let path = headers
        .get("x-original-path")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| req.uri().path());

    let user_id = headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let principal_kind = headers
        .get("x-principal-kind")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token_id = headers
        .get("x-token-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let identity_card_id = headers
        .get("x-identity-card-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let user_card_id = headers
        .get("x-user-card-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let user_card_domain_id = headers
        .get("x-user-card-domain-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let user_card_tenant_id = headers
        .get("x-user-card-tenant-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token_use = headers
        .get("x-token-use")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let claims_version = headers
        .get("x-claims-version")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let action_codes = headers
        .get("x-action-codes")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let user_roles = headers
        .get("x-user-roles")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let principal_kind = match PrincipalKind::parse(principal_kind) {
        Some(kind) => kind,
        None => {
            return gateway_error(
                &req,
                403,
                "Invalid principal kind",
                "FORBIDDEN",
                "PRINCIPAL_KIND_INVALID",
            )
        }
    };
    let identity_present = !identity_card_id.trim().is_empty();
    let user_card_fields_present = [user_card_id, user_card_domain_id, user_card_tenant_id]
        .iter()
        .all(|value| !value.trim().is_empty());
    let user_card_fields_absent = [user_card_id, user_card_domain_id, user_card_tenant_id]
        .iter()
        .all(|value| value.trim().is_empty());
    let context_valid = identity_present
        && match principal_kind {
            PrincipalKind::PlatformUser => user_card_fields_present,
            PrincipalKind::AppUser => user_card_fields_absent,
        };
    if !context_valid {
        return gateway_error(
            &req,
            403,
            "Invalid principal card context",
            "FORBIDDEN",
            "PRINCIPAL_CARD_CONTEXT_INVALID",
        );
    }

    // v3 签名（问题 1 修正后唯一契约：identity_card 不承担组织归属，
    // payload 不含身份侧 tenant/domain 字段）。
    let expected = compute_hmac_signature_v3(
        &config.gateway.hmac_secret,
        method,
        path,
        user_id,
        principal_kind.as_str(),
        token_id,
        identity_card_id,
        user_card_id,
        user_card_domain_id,
        user_card_tenant_id,
        token_use,
        claims_version,
        action_codes,
        user_roles,
        timestamp,
    );

    // 常量时间比较（对齐 Java MessageDigest.isEqual）
    if !constant_time_eq(signature.as_bytes(), expected.as_bytes()) {
        return gateway_error(
            &req,
            403,
            "Gateway signature mismatch",
            "FORBIDDEN",
            "GATEWAY_SIGNATURE_MISMATCH",
        );
    }

    next.run(req).await
}

/// 常量时间字节比较
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Shared gateway contract error shape. The verifier does not expose internal details.
fn gateway_error(
    req: &Request,
    status: u16,
    message: &str,
    error_type: &str,
    reason: &str,
) -> Response {
    let trace_id = req
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("gateway-signature-error");
    let body = serde_json::json!({
        "code": status,
        "message": message,
        "traceId": trace_id,
        "requestPath": req.uri().path(),
        "requestMethod": req.method().as_str(),
        "errorType": error_type,
        "decision": reason,
        "reasonCode": reason,
    });
    let mut response = (
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        axum::Json(body),
    )
        .into_response();
    if let Ok(value) = trace_id.parse() {
        response.headers_mut().insert("X-Trace-Id", value);
    }
    if status == 503 {
        response
            .headers_mut()
            .insert("Retry-After", axum::http::HeaderValue::from_static("3"));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-at-least-32-chars-long!!";

    fn baseline_signature() -> String {
        compute_hmac_signature_v3(
            SECRET,
            "GET",
            "/v1/app/learn/progress/12",
            "42",
            "PLATFORM_USER",
            "jti-abc",
            "identity-card",
            "user-card",
            "user-domain",
            "user-tenant",
            "ACCESS",
            "2",
            "read",
            "USER",
            "1700000000000",
        )
    }

    #[test]
    fn signature_is_deterministic_for_same_payload() {
        let sig1 = baseline_signature();
        let sig2 = baseline_signature();
        assert_eq!(sig1, sig2);
        assert!(constant_time_eq(sig1.as_bytes(), sig2.as_bytes()));
    }

    #[test]
    fn method_change_produces_different_signature() {
        let baseline = baseline_signature();
        let altered = compute_hmac_signature_v3(
            SECRET,
            "POST",
            "/v1/app/learn/progress/12",
            "42",
            "PLATFORM_USER",
            "jti-abc",
            "identity-card",
            "user-card",
            "user-domain",
            "user-tenant",
            "ACCESS",
            "2",
            "read",
            "USER",
            "1700000000000",
        );
        assert_ne!(baseline, altered);
    }

    #[test]
    fn path_change_produces_different_signature() {
        let baseline = baseline_signature();
        let altered = compute_hmac_signature_v3(
            SECRET,
            "GET",
            "/v1/app/learn/progress/13",
            "42",
            "PLATFORM_USER",
            "jti-abc",
            "identity-card",
            "user-card",
            "user-domain",
            "user-tenant",
            "ACCESS",
            "2",
            "read",
            "USER",
            "1700000000000",
        );
        assert_ne!(baseline, altered);
    }

    #[test]
    fn user_id_change_produces_different_signature() {
        // 客户端伪造身份头不能覆盖 JWT 身份：签名包含 user_id，
        // 篡改 x-user-id 会导致签名不匹配 → GATEWAY_SIGNATURE_MISMATCH。
        let baseline = baseline_signature();
        let altered = compute_hmac_signature_v3(
            SECRET,
            "GET",
            "/v1/app/learn/progress/12",
            "43",
            "PLATFORM_USER",
            "jti-abc",
            "identity-card",
            "user-card",
            "user-domain",
            "user-tenant",
            "ACCESS",
            "2",
            "read",
            "USER",
            "1700000000000",
        );
        assert_ne!(baseline, altered);
    }

    #[test]
    fn principal_kind_change_produces_different_signature() {
        // principal_kind 是 v3 canonical payload 的一部分：
        // 篡改 x-principal-kind 会导致签名不匹配 → GATEWAY_SIGNATURE_MISMATCH。
        let baseline = baseline_signature();
        let altered = compute_hmac_signature_v3(
            SECRET,
            "GET",
            "/v1/app/learn/progress/12",
            "42",
            "APP_USER",
            "jti-abc",
            "identity-card",
            "user-card",
            "user-domain",
            "user-tenant",
            "ACCESS",
            "2",
            "read",
            "USER",
            "1700000000000",
        );
        assert_ne!(baseline, altered);
    }

    #[test]
    fn timestamp_change_produces_different_signature() {
        let baseline = baseline_signature();
        let altered = compute_hmac_signature_v3(
            SECRET,
            "GET",
            "/v1/app/learn/progress/12",
            "42",
            "PLATFORM_USER",
            "jti-abc",
            "identity-card",
            "user-card",
            "user-domain",
            "user-tenant",
            "ACCESS",
            "2",
            "read",
            "USER",
            "1700000000001",
        );
        assert_ne!(baseline, altered);
    }

    #[test]
    fn secret_change_produces_different_signature() {
        let baseline = baseline_signature();
        let altered = compute_hmac_signature_v3(
            "another-secret-at-least-32-chars-long!",
            "GET",
            "/v1/app/learn/progress/12",
            "42",
            "PLATFORM_USER",
            "jti-abc",
            "identity-card",
            "user-card",
            "user-domain",
            "user-tenant",
            "ACCESS",
            "2",
            "read",
            "USER",
            "1700000000000",
        );
        assert_ne!(baseline, altered);
    }

    #[test]
    fn constant_time_eq_rejects_unequal_lengths() {
        assert!(!constant_time_eq(b"a", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn constant_time_eq_rejects_equal_length_but_different_bytes() {
        let baseline = baseline_signature();
        let mut tampered = baseline.clone();
        // 翻转最后一个字符以制造差异
        let last = tampered.pop().unwrap();
        let flipped = if last == '0' { '1' } else { '0' };
        tampered.push(flipped);
        assert!(!constant_time_eq(baseline.as_bytes(), tampered.as_bytes()));
    }

    /// 固定 v3 golden vector：锁定 canonical payload 与字段顺序，
    /// 防止后续修改（如字段增删、顺序调整）在未察觉的情况下改变签名语义。
    /// 该值由本实现独立计算，不声称与任何 Java legacy 黄金值相等。
    #[test]
    fn v3_golden_vector_is_stable() {
        let signature = baseline_signature();
        assert_eq!(
            signature,
            "dab71988d282189ecdfe643fb112034d9d0b5c1df3e1906781f73f729bd65b46"
        );
    }
}
