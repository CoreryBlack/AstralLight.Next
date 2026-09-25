//! Versioned service-to-service request assertions.
//!
//! This contract is deliberately separate from the Gateway v3 identity
//! signature. Internal assertions bind the complete request context and are
//! consumed exactly once by the receiving service.

use hmac::Mac;
use sha2::{Digest, Sha256};

pub const INTERNAL_PROTOCOL_VERSION: &str = "astral-internal-v1";

pub const INTERNAL_PROTOCOL_HEADER: &str = "x-internal-protocol";
pub const INTERNAL_SERVICE_HEADER: &str = "x-internal-service";
pub const INTERNAL_CALLER_HEADER: &str = "x-internal-caller";
pub const INTERNAL_TIMESTAMP_HEADER: &str = "x-internal-timestamp";
pub const INTERNAL_NONCE_HEADER: &str = "x-internal-nonce";
pub const INTERNAL_REQUEST_ID_HEADER: &str = "x-internal-request-id";
pub const INTERNAL_IDEMPOTENCY_HEADER: &str = "x-idempotency-key";
pub const INTERNAL_BODY_SHA256_HEADER: &str = "x-internal-body-sha256";
pub const INTERNAL_SIGNATURE_HEADER: &str = "x-internal-signature";
pub const INTERNAL_KEY_ID_HEADER: &str = "x-internal-key-id";
pub const INTERNAL_ROUTE_HEADER: &str = "x-internal-route";

pub const KEY_ID_LEARN_TO_GATEWAY: &str = "k-lg";
pub const KEY_ID_GATEWAY_TO_IDENTITY: &str = "k-gi";
pub const ROUTE_LEARN_TO_GATEWAY: &str = "learn-to-gateway";
pub const ROUTE_GATEWAY_TO_IDENTITY: &str = "gateway-to-identity";

pub const INTERNAL_SESSION_PATH: &str = "/api/v1/auth/internal/sessions";
pub const INTERNAL_CALLER_LEARN: &str = "astral-learn";
pub const INTERNAL_CALLER_GATEWAY: &str = "astral-gateway";

type HmacSha256 = hmac::Hmac<Sha256>;

/// All values that participate in an internal assertion canonical payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalSignatureInput<'a> {
    pub protocol_version: &'a str,
    pub key_id: &'a str,
    pub caller_service: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub normalized_query: &'a str,
    pub body_sha256: &'a str,
    pub target_user_id: &'a str,
    pub timestamp: &'a str,
    pub nonce: &'a str,
    pub request_id: &'a str,
    pub idempotency_key: &'a str,
    pub route: &'a str,
}

/// Normalize query parameters without decoding them. Sorting raw key/value
/// pairs makes equivalent parameter order deterministic while preserving the
/// exact bytes that were signed, including duplicate parameters.
pub fn normalize_query(query: Option<&str>) -> String {
    let Some(query) = query.filter(|value| !value.is_empty()) else {
        return String::new();
    };
    let mut parts: Vec<&str> = query.split('&').collect();
    parts.sort_unstable();
    parts.join("&")
}

/// Canonical payload for `astral-internal-v1`.
pub fn canonical_payload(input: &InternalSignatureInput<'_>) -> String {
    format!(
        "{}\nkey-id:{}\ncaller:{}\nmethod:{}\npath:{}\nquery:{}\nbody-sha256:{}\ntarget-user-id:{}\ntimestamp:{}\nnonce:{}\nrequest-id:{}\nidempotency-key:{}\nroute:{}",
        input.protocol_version,
        input.key_id,
        input.caller_service,
        input.method.trim().to_ascii_uppercase(),
        input.path,
        input.normalized_query,
        input.body_sha256,
        input.target_user_id,
        input.timestamp,
        input.nonce,
        input.request_id,
        input.idempotency_key,
        input.route,
    )
}

pub fn compute_internal_signature(secret: &str, input: &InternalSignatureInput<'_>) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(canonical_payload(input).as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_internal_signature(
    secret: &str,
    input: &InternalSignatureInput<'_>,
    signature: &str,
) -> bool {
    constant_time_eq(
        compute_internal_signature(secret, input).as_bytes(),
        signature.as_bytes(),
    )
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |accumulator, (a, b)| accumulator | (a ^ b))
        == 0
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Validate a signed header component before it enters the line-oriented
/// canonical payload. Control characters are rejected to prevent ambiguity.
pub fn valid_component(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.bytes().all(|byte| !byte.is_ascii_control())
}

pub fn timestamp_is_within_tolerance(timestamp: &str, tolerance_secs: i64, now_ms: i128) -> bool {
    let Ok(timestamp_ms) = timestamp.parse::<i128>() else {
        return false;
    };
    let Some(tolerance_ms) = i128::from(tolerance_secs).checked_mul(1_000) else {
        return false;
    };
    tolerance_ms > 0 && (now_ms - timestamp_ms).abs() <= tolerance_ms
}

/// Derive a bounded Redis replay key from protocol/request context. The marker
/// contains no token or secret material and namespaces each hop.
pub fn replay_key(namespace: &str, input: &InternalSignatureInput<'_>) -> String {
    let context = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        input.protocol_version,
        input.key_id,
        input.caller_service,
        input.route,
        input.path,
        input.request_id,
        input.idempotency_key,
        input.nonce,
    );
    format!(
        "astral:internal:v1:replay:{}:{}",
        namespace,
        sha256_hex(context.as_bytes())
    )
}

pub fn idempotency_key(namespace: &str, caller_service: &str, route: &str, key: &str) -> String {
    let context = format!(
        "{}|{}|{}|{}",
        INTERNAL_PROTOCOL_VERSION, caller_service, route, key
    );
    format!(
        "astral:internal:v1:idempotency:{}:{}",
        namespace,
        sha256_hex(context.as_bytes())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "internal-test-secret-at-least-32-bytes";

    #[test]
    fn canonical_payload_is_deterministic_and_binds_protocol_context() {
        let body_hash = "a".repeat(64);
        let first = InternalSignatureInput {
            protocol_version: INTERNAL_PROTOCOL_VERSION,
            key_id: KEY_ID_LEARN_TO_GATEWAY,
            caller_service: INTERNAL_CALLER_LEARN,
            method: "POST",
            path: INTERNAL_SESSION_PATH,
            normalized_query: "a=1&b=2",
            body_sha256: &body_hash,
            target_user_id: "42",
            timestamp: "1700000000000",
            nonce: "nonce-1",
            request_id: "req-1",
            idempotency_key: "idem-1",
            route: ROUTE_LEARN_TO_GATEWAY,
        };
        let second = first;
        assert_eq!(canonical_payload(&first), canonical_payload(&second));
        assert_eq!(
            compute_internal_signature(SECRET, &first),
            compute_internal_signature(SECRET, &second)
        );
        assert!(canonical_payload(&first).starts_with("astral-internal-v1\n"));
    }

    #[test]
    fn query_normalization_is_order_independent_but_duplicate_safe() {
        assert_eq!(normalize_query(Some("b=2&a=1")), "a=1&b=2");
        assert_eq!(normalize_query(Some("a=1&a=1")), "a=1&a=1");
        assert_eq!(normalize_query(None), "");
    }

    #[test]
    fn every_security_field_tamper_changes_signature() {
        let body_hash = "a".repeat(64);
        let baseline = InternalSignatureInput {
            protocol_version: INTERNAL_PROTOCOL_VERSION,
            key_id: KEY_ID_LEARN_TO_GATEWAY,
            caller_service: INTERNAL_CALLER_LEARN,
            method: "POST",
            path: INTERNAL_SESSION_PATH,
            normalized_query: "",
            body_sha256: &body_hash,
            target_user_id: "42",
            timestamp: "1700000000000",
            nonce: "nonce-1",
            request_id: "req-1",
            idempotency_key: "idem-1",
            route: ROUTE_LEARN_TO_GATEWAY,
        };
        let signature = compute_internal_signature(SECRET, &baseline);
        let mut tampered = baseline;
        let cases = [
            ("protocol_version", "astral-internal-v2"),
            ("key_id", KEY_ID_GATEWAY_TO_IDENTITY),
            ("caller_service", INTERNAL_CALLER_GATEWAY),
            ("method", "GET"),
            ("path", "/other"),
            ("normalized_query", "a=1"),
            ("body_sha256", "b"),
            ("target_user_id", "43"),
            ("timestamp", "1700000000001"),
            ("nonce", "nonce-2"),
            ("request_id", "req-2"),
            ("idempotency_key", "idem-2"),
            ("route", ROUTE_GATEWAY_TO_IDENTITY),
        ];
        for (field, value) in cases {
            match field {
                "protocol_version" => tampered.protocol_version = value,
                "key_id" => tampered.key_id = value,
                "caller_service" => tampered.caller_service = value,
                "method" => tampered.method = value,
                "path" => tampered.path = value,
                "normalized_query" => tampered.normalized_query = value,
                "body_sha256" => tampered.body_sha256 = value,
                "target_user_id" => tampered.target_user_id = value,
                "timestamp" => tampered.timestamp = value,
                "nonce" => tampered.nonce = value,
                "request_id" => tampered.request_id = value,
                "idempotency_key" => tampered.idempotency_key = value,
                "route" => tampered.route = value,
                _ => unreachable!(),
            }
            assert!(!verify_internal_signature(SECRET, &tampered, &signature));
            tampered = baseline;
        }
    }

    #[test]
    fn distinct_internal_keys_are_separated_for_the_same_context() {
        let body_hash = "a".repeat(64);
        let input = InternalSignatureInput {
            protocol_version: INTERNAL_PROTOCOL_VERSION,
            key_id: KEY_ID_LEARN_TO_GATEWAY,
            caller_service: INTERNAL_CALLER_LEARN,
            method: "POST",
            path: INTERNAL_SESSION_PATH,
            normalized_query: "",
            body_sha256: &body_hash,
            target_user_id: "42",
            timestamp: "1700000000000",
            nonce: "nonce-1",
            request_id: "req-1",
            idempotency_key: "idem-1",
            route: ROUTE_LEARN_TO_GATEWAY,
        };
        let learn_to_gateway_key = "learn-to-gateway-secret-at-least-32";
        let gateway_to_identity_key = "gateway-to-identity-secret-at-least-32";
        let learn_signature = compute_internal_signature(learn_to_gateway_key, &input);
        let identity_signature = compute_internal_signature(gateway_to_identity_key, &input);

        assert_ne!(learn_signature, identity_signature);
        assert!(verify_internal_signature(
            learn_to_gateway_key,
            &input,
            &learn_signature
        ));
        assert!(!verify_internal_signature(
            gateway_to_identity_key,
            &input,
            &learn_signature
        ));
    }

    #[test]
    fn wrong_key_and_invalid_timestamp_are_rejected() {
        let body_hash = "a".repeat(64);
        let value = InternalSignatureInput {
            protocol_version: INTERNAL_PROTOCOL_VERSION,
            key_id: KEY_ID_LEARN_TO_GATEWAY,
            caller_service: INTERNAL_CALLER_LEARN,
            method: "POST",
            path: INTERNAL_SESSION_PATH,
            normalized_query: "",
            body_sha256: &body_hash,
            target_user_id: "42",
            timestamp: "1700000000000",
            nonce: "nonce-1",
            request_id: "req-1",
            idempotency_key: "idem-1",
            route: ROUTE_LEARN_TO_GATEWAY,
        };
        let signature = compute_internal_signature(SECRET, &value);
        assert!(verify_internal_signature(SECRET, &value, &signature));
        assert!(!verify_internal_signature(
            "another-internal-secret-at-least-32",
            &value,
            &signature
        ));
        assert!(timestamp_is_within_tolerance(
            "1700000000000",
            30,
            1_700_000_000_000
        ));
        assert!(!timestamp_is_within_tolerance(
            "invalid",
            30,
            1_700_000_000_000
        ));
        assert!(!timestamp_is_within_tolerance(
            "1700000000000",
            30,
            1_700_000_040_001
        ));
    }

    #[test]
    fn body_hash_and_components_are_validated() {
        assert_eq!(
            sha256_hex(b"{}"),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
        assert!(valid_sha256_hex(&"a".repeat(64)));
        assert!(!valid_sha256_hex("not-a-hash"));
        assert!(valid_component("req-1", 128));
        assert!(!valid_component("", 128));
        assert!(!valid_component("bad\nvalue", 128));
    }
}
