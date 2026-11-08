//! HTTPS relay/webhook transport (reqwest).
//!
//! Hardening: redirection is disabled, DNS resolution is pinned through the
//! endpoint guard, timeouts and body sizes are bounded, and the response
//! truth is explicit:
//! - 2xx from a **webhook** is `Delivered` under one exact, documented
//!   assumption: the configured webhook URL is the FINAL receiver of the
//!   event and its 2xx response is its synchronous consumption receipt. If
//!   the configured endpoint is a fronting/queueing service instead, it MUST
//!   be modeled as a relay (`delivered_on_2xx = false`) with an explicit
//!   `receiptField`/`receiptDeliveredValue` mapping — a queueing front's 2xx
//!   is acceptance, not delivery.
//! - 2xx from a **relay** is at most `Accepted` — `Delivered` only when the
//!   provider body carries the configured explicit receipt proof.
//! - Connection failures before any byte was sent are `Failed`; timeouts or
//!   truncated responses after dispatch began are `InDoubt`.

use serde_json::Value;

use crate::delivery::channel_config::HttpRelayConfig;
use crate::delivery::endpoint::EndpointGuard;
use crate::delivery::state::DeliveryError;

/// Bounded response read: receipt bodies beyond this are not parsed (the
/// outcome then caps at ACCEPTED for relays).
const MAX_RESPONSE_BYTES: usize = 65_536;

/// Typed per-send HTTP outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayOutcome {
    /// Explicit end-delivery proof (relay receipt or webhook 2xx).
    Delivered { reference: Option<String> },
    /// Provider acknowledged into its queue without delivery proof.
    Accepted { reference: Option<String> },
    /// Definitive refusal (non-2xx, redirect, or pre-send connection error).
    Failed { detail: String },
    /// Request dispatched but the outcome is unknown.
    InDoubt { detail: String },
}

/// HTTPS transport built on a guarded client.
pub struct HttpRelayTransport {
    client: reqwest::Client,
}

impl HttpRelayTransport {
    /// Production transport over the shared guarded client (public policy).
    pub fn public() -> Result<Self, DeliveryError> {
        Self::with_guard(EndpointGuard::public(Vec::new()))
    }

    /// Transport with an explicit endpoint policy (loopback fixtures pass the
    /// fixture guard).
    pub fn with_guard(guard: EndpointGuard) -> Result<Self, DeliveryError> {
        Ok(Self {
            client: crate::delivery::endpoint::guarded_client(guard)?,
        })
    }

    /// POST one JSON payload with optional auth header.
    pub async fn post_json(
        &self,
        config: &HttpRelayConfig,
        payload: &Value,
    ) -> Result<RelayOutcome, DeliveryError> {
        let mut request = self.client.post(config.url.as_str()).json(payload);
        if let (Some(name), Some(value)) = (
            config.auth_header_name.as_deref(),
            config.auth_header_value.as_deref(),
        ) {
            request = request.header(name, value);
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => return Ok(map_send_error(error)),
        };
        let status = response.status();
        if status.is_redirection() {
            // Redirection is disabled; a 3xx therefore means the configured
            // endpoint moved and the payload was NOT accepted there.
            return Ok(RelayOutcome::Failed {
                detail: format!("relay responded {status}; redirection is disabled by policy"),
            });
        }
        if !status.is_success() {
            return Ok(RelayOutcome::Failed {
                detail: format!("relay responded {status}"),
            });
        }
        let body = match read_bounded_body(response).await {
            Ok(body) => body,
            Err(_) => {
                // Dispatch succeeded but the receipt body is unreadable:
                // 2xx proves acceptance; delivery proof stays unproven.
                return Ok(RelayOutcome::Accepted { reference: None });
            }
        };
        let parsed: Option<Value> = serde_json::from_slice(&body).ok();
        if config.delivered_on_2xx {
            // Synchronous webhook receiver: the 2xx response is the receipt.
            return Ok(RelayOutcome::Delivered {
                reference: extract_reference(parsed.as_ref()),
            });
        }
        // Relay: 2xx is acceptance. DELIVERED requires the explicit receipt
        // field to carry the configured delivered value.
        let delivered = match (&config.receipt_field, &config.receipt_delivered_value) {
            (Some(field), Some(expected)) => parsed
                .as_ref()
                .and_then(|value| lookup_pointer(value, field))
                .and_then(Value::as_str)
                .map(|actual| actual.eq_ignore_ascii_case(expected))
                .unwrap_or(false),
            _ => false,
        };
        if delivered {
            Ok(RelayOutcome::Delivered {
                reference: extract_reference(parsed.as_ref()),
            })
        } else {
            Ok(RelayOutcome::Accepted {
                reference: extract_reference(parsed.as_ref()),
            })
        }
    }
}

/// Map a reqwest send error to the truthful outcome. Connection errors mean
/// the request never left; timeouts and mid-flight failures leave the
/// outcome unknown.
fn map_send_error(error: reqwest::Error) -> RelayOutcome {
    if error.is_connect() {
        RelayOutcome::Failed {
            detail: format!("relay connection failed before dispatch: {error}"),
        }
    } else if error.is_timeout() || error.is_request() || error.is_body() || error.is_decode() {
        RelayOutcome::InDoubt {
            detail: format!("relay outcome unknown after dispatch began: {error}"),
        }
    } else {
        RelayOutcome::InDoubt {
            detail: format!("relay outcome unknown: {error}"),
        }
    }
}

async fn read_bounded_body(response: reqwest::Response) -> Result<Vec<u8>, DeliveryError> {
    if let Some(length) = response.content_length() {
        if length as usize > MAX_RESPONSE_BYTES {
            return Err(DeliveryError::Bounds("relay response body"));
        }
    }
    let mut buffer: Vec<u8> = Vec::new();
    let mut response = response;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| DeliveryError::Transport(format!("relay body read failed: {error}")))?
    {
        if buffer.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(DeliveryError::Bounds("relay response body"));
        }
        buffer.extend_from_slice(&chunk);
    }
    Ok(buffer)
}

/// Look up a dotted receipt field ("result.status") in the provider body.
fn lookup_pointer<'a>(value: &'a Value, pointer: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in pointer.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Extract a non-secret provider reference (bounded, control-free).
fn extract_reference(body: Option<&Value>) -> Option<String> {
    let body = body?;
    for key in [
        "messageId",
        "message_id",
        "msgId",
        "requestId",
        "request_id",
        "id",
    ] {
        if let Some(value) = body.get(key).and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() && trimmed.len() <= 256 {
                let mut owned = trimmed.to_owned();
                owned.retain(|c| !c.is_control());
                if !owned.is_empty() {
                    return Some(owned);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::channel_config::test_support::relay_config_for_test;
    use axum::routing::post;
    use axum::Router;
    use std::sync::Arc;

    struct Loopback {
        port: u16,
        task: tokio::task::JoinHandle<()>,
    }

    async fn spawn_route(
        status: axum::http::StatusCode,
        body: &'static str,
        capture: Arc<std::sync::Mutex<Vec<String>>>,
        redirect: bool,
    ) -> Loopback {
        let seen = capture;
        let app = Router::new().route(
            "/hook",
            post(move |payload: axum::body::Bytes| {
                let seen = seen.clone();
                async move {
                    seen.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&payload).to_string());
                    use axum::response::IntoResponse;
                    if redirect {
                        (
                            axum::http::StatusCode::FOUND,
                            [("location", "/moved")],
                            String::new(),
                        )
                            .into_response()
                    } else {
                        (status, body.to_owned()).into_response()
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Loopback { port, task }
    }

    impl Loopback {
        fn url(&self) -> String {
            format!("http://127.0.0.1:{}/hook", self.port)
        }

        fn shutdown(self) {
            self.task.abort();
        }
    }

    fn transport() -> HttpRelayTransport {
        HttpRelayTransport::with_guard(EndpointGuard::loopback_fixture(vec![])).unwrap()
    }

    #[tokio::test]
    async fn relay_2xx_without_receipt_is_accepted_not_delivered() {
        let capture: Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let server =
            spawn_route(axum::http::StatusCode::OK, r#"{"ok":true}"#, capture, false).await;
        let mut config = relay_config_for_test(&server.url(), false);
        config.receipt_field = None;
        config.receipt_delivered_value = None;
        let outcome = transport()
            .post_json(&config, &serde_json::json!({"text": "hi"}))
            .await
            .unwrap();
        server.shutdown();
        assert_eq!(
            outcome,
            RelayOutcome::Accepted { reference: None },
            "2xx without receipt proof must not claim delivery"
        );
    }

    #[tokio::test]
    async fn relay_2xx_with_receipt_proof_is_delivered() {
        let capture: Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let server = spawn_route(
            axum::http::StatusCode::OK,
            r#"{"status":"DELIVERED","messageId":"prov-77"}"#,
            capture,
            false,
        )
        .await;
        let config = relay_config_for_test(&server.url(), false);
        let outcome = transport()
            .post_json(&config, &serde_json::json!({"text": "hi"}))
            .await
            .unwrap();
        server.shutdown();
        assert_eq!(
            outcome,
            RelayOutcome::Delivered {
                reference: Some("prov-77".to_owned())
            }
        );
    }

    #[tokio::test]
    async fn relay_receipt_value_mismatch_caps_at_accepted() {
        let capture: Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let server = spawn_route(
            axum::http::StatusCode::OK,
            r#"{"status":"ACCEPTED"}"#,
            capture,
            false,
        )
        .await;
        let config = relay_config_for_test(&server.url(), false);
        let outcome = transport()
            .post_json(&config, &serde_json::json!({"text": "hi"}))
            .await
            .unwrap();
        server.shutdown();
        assert_eq!(outcome, RelayOutcome::Accepted { reference: None });
    }

    #[tokio::test]
    async fn webhook_2xx_is_delivered() {
        let capture: Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let server = spawn_route(axum::http::StatusCode::OK, r#"{}"#, capture.clone(), false).await;
        let config = relay_config_for_test(&server.url(), true);
        let outcome = transport()
            .post_json(&config, &serde_json::json!({"event": "test"}))
            .await
            .unwrap();
        let payloads = capture.lock().unwrap().clone();
        server.shutdown();
        assert_eq!(outcome, RelayOutcome::Delivered { reference: None });
        assert_eq!(payloads.len(), 1);
        assert!(payloads[0].contains("\"event\":\"test\""), "{payloads:?}");
    }

    #[tokio::test]
    async fn non_2xx_is_failed() {
        let capture: Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let server = spawn_route(axum::http::StatusCode::BAD_GATEWAY, "no", capture, false).await;
        let config = relay_config_for_test(&server.url(), true);
        let outcome = transport()
            .post_json(&config, &serde_json::json!({"event": "test"}))
            .await
            .unwrap();
        server.shutdown();
        assert!(
            matches!(outcome, RelayOutcome::Failed { .. }),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn redirect_response_is_failed_by_policy() {
        let capture: Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let server = spawn_route(axum::http::StatusCode::OK, "{}", capture, true).await;
        let config = relay_config_for_test(&server.url(), true);
        let outcome = transport()
            .post_json(&config, &serde_json::json!({"event": "test"}))
            .await
            .unwrap();
        server.shutdown();
        assert!(
            matches!(&outcome, RelayOutcome::Failed { detail } if detail.contains("redirection")),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn connect_refusal_is_failed_before_dispatch() {
        // Port 1 on loopback has no listener: connect fails pre-send.
        let mut config = relay_config_for_test("http://127.0.0.1:1/hook", true);
        config.guard = EndpointGuard::loopback_fixture(vec![]);
        let outcome = transport()
            .post_json(&config, &serde_json::json!({"event": "test"}))
            .await
            .unwrap();
        assert!(
            matches!(outcome, RelayOutcome::Failed { .. }),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn timeout_after_dispatch_is_in_doubt() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            // Accept and never respond.
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        let mut config = relay_config_for_test(&format!("http://127.0.0.1:{port}/hook"), true);
        config.guard = EndpointGuard::loopback_fixture(vec![]);
        // Client with a short timeout for the fixture.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_millis(300))
            .dns_resolver(Arc::new(crate::delivery::endpoint::GuardedResolver::new(
                EndpointGuard::loopback_fixture(vec![]),
            )))
            .build()
            .unwrap();
        let transport = HttpRelayTransport { client };
        let outcome = transport
            .post_json(&config, &serde_json::json!({"event": "test"}))
            .await
            .unwrap();
        task.abort();
        assert!(
            matches!(outcome, RelayOutcome::InDoubt { .. }),
            "{outcome:?}"
        );
    }

    #[tokio::test]
    async fn auth_header_is_applied_from_resolved_config() {
        let capture: Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let seen_header = capture.clone();
        let app = Router::new().route(
            "/hook",
            post(
                move |headers: axum::http::HeaderMap, payload: axum::body::Bytes| {
                    let seen = seen_header.clone();
                    async move {
                        seen.lock().unwrap().push(format!(
                            "{}|{}",
                            headers
                                .get("authorization")
                                .map(|v| v.to_str().unwrap_or(""))
                                .unwrap_or(""),
                            String::from_utf8_lossy(&payload)
                        ));
                        axum::http::StatusCode::OK
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let mut config = relay_config_for_test(&format!("http://127.0.0.1:{port}/hook"), true);
        config.auth_header_name = Some("Authorization".to_owned());
        config.auth_header_value = Some("Bearer fixture-token".to_owned());
        let outcome = transport()
            .post_json(&config, &serde_json::json!({"event": "test"}))
            .await
            .unwrap();
        task.abort();
        assert_eq!(outcome, RelayOutcome::Delivered { reference: None });
        let seen = capture.lock().unwrap();
        assert!(
            seen.first().unwrap().starts_with("Bearer fixture-token|"),
            "{seen:?}"
        );
    }

    #[test]
    fn receipt_pointer_lookup_supports_dotted_paths() {
        let body: Value = serde_json::json!({"result": {"status": "DELIVERED"}});
        assert_eq!(
            lookup_pointer(&body, "result.status").and_then(Value::as_str),
            Some("DELIVERED")
        );
        assert!(lookup_pointer(&body, "missing.path").is_none());
    }
}
