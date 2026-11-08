//! Bind permission evaluation to the exact bounded HTTP request without retaining its payload.

use axum::{
    body::{to_bytes, Body},
    extract::{OriginalUri, Request},
    http::StatusCode,
};
use sha2::{Digest, Sha256};
use std::time::Duration;

const MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_DOMAIN: &[u8] = b"ASTRAL_HTTP_REQUEST_V7\0";

/// Buffer once, hash the original URI and bytes, then restore the body for the handler.
/// On failure the request must be rejected; a partially read body cannot be reused.
pub async fn bind_http_request(request: &mut Request) -> Result<String, StatusCode> {
    let body = std::mem::replace(request.body_mut(), Body::empty());
    let bytes = tokio::time::timeout(BODY_READ_TIMEOUT, to_bytes(body, MAX_REQUEST_BODY_BYTES))
        .await
        .map_err(|_| StatusCode::REQUEST_TIMEOUT)?
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    let uri = request
        .extensions()
        .get::<OriginalUri>()
        .map(|original| &original.0)
        .unwrap_or_else(|| request.uri());
    let fingerprint = fingerprint(request.method().as_str(), &uri.to_string(), &bytes);
    *request.body_mut() = Body::from(bytes);
    Ok(fingerprint)
}

/// Freeze the request operation before proof issuance. Writes require a caller
/// request id; read-only requests may use a request-local UUID.
pub fn request_operation_id(request: &Request) -> Result<String, StatusCode> {
    let mut values = request.headers().get_all("x-request-id").iter();
    let raw = values.next();
    if values.next().is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    match raw {
        Some(raw) => {
            let value = raw.to_str().map_err(|_| StatusCode::BAD_REQUEST)?;
            if value.is_empty()
                || value.len() > 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(&byte))
            {
                return Err(StatusCode::BAD_REQUEST);
            }
            Ok(value.to_owned())
        }
        None if matches!(
            *request.method(),
            axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
        ) =>
        {
            Ok(uuid::Uuid::now_v7().to_string())
        }
        None => Err(StatusCode::BAD_REQUEST),
    }
}

fn fingerprint(method: &str, uri: &str, body: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(REQUEST_DOMAIN);
    for part in [method.as_bytes(), uri.as_bytes(), body] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn preserves_body_and_uses_original_uri() {
        let mut request = Request::builder()
            .method("POST")
            .uri("/items?mode=one")
            .body(Body::from(r#"{"id":7}"#))
            .unwrap();
        request
            .extensions_mut()
            .insert(OriginalUri("/api/v1/items?mode=one".parse().unwrap()));
        let actual = bind_http_request(&mut request).await.unwrap();
        assert_eq!(
            actual,
            fingerprint("POST", "/api/v1/items?mode=one", br#"{"id":7}"#)
        );
        assert_eq!(
            to_bytes(request.into_body(), MAX_REQUEST_BODY_BYTES)
                .await
                .unwrap()
                .as_ref(),
            br#"{"id":7}"#
        );
    }

    #[test]
    fn binds_method_uri_query_body_and_field_boundaries() {
        let original = fingerprint("POST", "/a?x=1", b"abc");
        for other in [
            fingerprint("PUT", "/a?x=1", b"abc"),
            fingerprint("POST", "/b?x=1", b"abc"),
            fingerprint("POST", "/a?x=2", b"abc"),
            fingerprint("POST", "/a?x=1", b"abd"),
            fingerprint("POST", "/a?x=1a", b"bc"),
        ] {
            assert_ne!(original, other);
        }
    }

    #[test]
    fn writes_require_one_canonical_operation_and_reads_get_independent_ids() {
        let mut write = Request::builder()
            .method("POST")
            .body(Body::empty())
            .unwrap();
        assert_eq!(request_operation_id(&write), Err(StatusCode::BAD_REQUEST));
        for invalid in ["", " padded", "has space", "line\ttab", &"a".repeat(65)] {
            write
                .headers_mut()
                .insert("x-request-id", invalid.parse().unwrap());
            assert_eq!(request_operation_id(&write), Err(StatusCode::BAD_REQUEST));
        }
        write
            .headers_mut()
            .insert("x-request-id", "op-1.a_b:c/d".parse().unwrap());
        assert_eq!(request_operation_id(&write).unwrap(), "op-1.a_b:c/d");
        write
            .headers_mut()
            .append("x-request-id", "op-2".parse().unwrap());
        assert_eq!(request_operation_id(&write), Err(StatusCode::BAD_REQUEST));
        for method in ["GET", "HEAD", "OPTIONS"] {
            let read = Request::builder()
                .method(method)
                .body(Body::empty())
                .unwrap();
            let first = request_operation_id(&read).unwrap();
            assert!(uuid::Uuid::parse_str(&first).is_ok());
            assert_ne!(first, request_operation_id(&read).unwrap());
        }
    }

    #[tokio::test]
    async fn refuses_oversized_body() {
        let mut request = Request::new(Body::from(vec![0; MAX_REQUEST_BODY_BYTES + 1]));
        assert_eq!(
            bind_http_request(&mut request).await,
            Err(StatusCode::PAYLOAD_TOO_LARGE)
        );
    }
}
