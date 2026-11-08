//! Authenticated, bounded internal HTTP listener.
//!
//! Security properties enforced here:
//! - TLS is mandatory. The listener refuses to start without a server
//!   certificate, key, and client CA; plaintext HTTP is never served.
//! - Client certificate authentication is mandatory (mTLS). Callers are
//!   identified by the SHA-256 fingerprint of their certificate and matched
//!   against the configured trusted-source allowlist; unknown fingerprints
//!   are rejected before any handler runs.
//! - Request bodies are bounded, requests are time-bounded, and connection
//!   concurrency is bounded by a strict semaphore.
//! - The body-declared `caller.service_id` must equal the transport-derived
//!   identity; mismatches fail closed.
//! - Connection lifecycle (bounded handshake, bounded connection lifetime,
//!   semaphore permits held for the whole connection, `JoinSet`-owned tasks
//!   aborted deterministically on shutdown) lives in the private
//!   [`lifecycle`] submodule.

mod lifecycle;

use std::sync::Arc;
use std::time::Duration;

use astral_types::{
    AuthorityAbortRequest, AuthorityCertifyRequest, AuthorityCloseReservationRequest,
    AuthorityCommitRequest, AuthorityConfigCompletionRequest,
    AuthorityEligibilityCompletionRequest, AuthorityFenceReadRequest, AuthorityPrepareRequest,
    AuthorityReconcileRequest, AuthoritySourceBootstrapFinalizeRequest,
    AuthoritySourceBootstrapPrepareRequest, AuthoritySourceBootstrapReconcileRequest,
    AuthorityWireError, AuthorityWireErrorCode, AUTHORITY_PATH_CONFIG_COMPLETIONS,
    AUTHORITY_PATH_ELIGIBILITY_COMPLETIONS, AUTHORITY_PATH_RESERVATION_ABORTS,
    AUTHORITY_PATH_SOURCE_BOOTSTRAP_FINALIZE, AUTHORITY_PATH_SOURCE_BOOTSTRAP_PREPARE,
    AUTHORITY_PATH_SOURCE_BOOTSTRAP_RECONCILE,
};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use crate::error::AuthorityServiceError;
use crate::service::AuthorityService;

/// Transport-derived caller identity attached to every request.
#[derive(Debug, Clone)]
pub struct AuthenticatedCaller {
    pub service_id: String,
    pub certificate_fingerprint: String,
}

/// Fingerprint a DER certificate the way the configuration allowlist does:
/// `sha256:<64 lowercase hex>`.
pub fn certificate_fingerprint(der: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(der)))
}

fn wire_error_response(status: StatusCode, error: &AuthorityWireError) -> Response {
    (status, Json(error.clone())).into_response()
}

fn service_error_response(error: &AuthorityServiceError, service: &AuthorityService) -> Response {
    let protocol = match error {
        AuthorityServiceError::Protocol(protocol_error) => Some(protocol_error.clone()),
        _ => None,
    };
    let mut wire = protocol
        .as_ref()
        .map(AuthorityWireError::from_protocol)
        .unwrap_or(AuthorityWireError {
            code: AuthorityWireErrorCode::Internal,
            message: error.to_string(),
            leader_hint: None,
            current_frontier: None,
            current_certificate_hash: None,
            reservation_id: None,
        });
    match error {
        AuthorityServiceError::NotLeader => {
            wire.code = AuthorityWireErrorCode::NotLeader;
            wire.leader_hint = Some(service.config().quorum.authority_name.clone());
        }
        AuthorityServiceError::UnknownOutcome { operation_hint } => {
            wire.code = AuthorityWireErrorCode::UnknownOutcome;
            wire.reservation_id = Some(operation_hint.clone());
        }
        AuthorityServiceError::NotAuthorized { .. } => {
            wire.code = AuthorityWireErrorCode::CallerIdentityMismatch;
        }
        AuthorityServiceError::Store(store_error) => {
            if matches!(
                store_error,
                crate::error::AuthorityStoreError::Unavailable(_)
            ) {
                wire.code = AuthorityWireErrorCode::QuorumUnavailable;
            }
        }
        _ => {}
    }
    let status = match wire.code {
        AuthorityWireErrorCode::NotLeader => StatusCode::CONFLICT,
        AuthorityWireErrorCode::UnknownOutcome => StatusCode::SERVICE_UNAVAILABLE,
        AuthorityWireErrorCode::QuorumUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        AuthorityWireErrorCode::ReadsBlocked => StatusCode::CONFLICT,
        AuthorityWireErrorCode::LeaseExpired => StatusCode::CONFLICT,
        AuthorityWireErrorCode::FrontierDiverged => StatusCode::CONFLICT,
        AuthorityWireErrorCode::NotFound => StatusCode::NOT_FOUND,
        AuthorityWireErrorCode::AlreadyExists => StatusCode::CONFLICT,
        AuthorityWireErrorCode::StateConflict => StatusCode::CONFLICT,
        AuthorityWireErrorCode::CallerIdentityMismatch => StatusCode::FORBIDDEN,
        AuthorityWireErrorCode::TrustRootMismatch => StatusCode::FORBIDDEN,
        AuthorityWireErrorCode::EditionMismatch => StatusCode::BAD_REQUEST,
        AuthorityWireErrorCode::Rejected => StatusCode::BAD_REQUEST,
        AuthorityWireErrorCode::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    };
    wire_error_response(status, &wire)
}

// The Err variant carries a full wire error response body by design; the
// handler converts it directly into the HTTP response.
#[allow(clippy::result_large_err)]
fn check_caller(caller: &AuthenticatedCaller, body_service_id: &str) -> Result<(), Response> {
    if caller.service_id != body_service_id {
        let wire = AuthorityWireError {
            code: AuthorityWireErrorCode::CallerIdentityMismatch,
            message: "body caller does not match the authenticated transport identity".to_owned(),
            leader_hint: None,
            current_frontier: None,
            current_certificate_hash: None,
            reservation_id: None,
        };
        return Err(wire_error_response(StatusCode::FORBIDDEN, &wire));
    }
    Ok(())
}

async fn handle_attestation(
    State(service): State<Arc<AuthorityService>>,
    Extension(caller): Extension<AuthenticatedCaller>,
) -> Response {
    // Attestation requires a registered caller but no specific operation.
    if service
        .config()
        .trusted_source_by_id(&caller.service_id)
        .is_none()
    {
        return service_error_response(
            &AuthorityServiceError::NotAuthorized {
                caller: caller.service_id,
                operation: "attestation",
            },
            &service,
        );
    }
    match service.startup_attestation(&caller.service_id).await {
        Ok(attestation) => (StatusCode::OK, Json(attestation)).into_response(),
        Err(error) => service_error_response(&error, &service),
    }
}

async fn handle_fence_read(
    State(service): State<Arc<AuthorityService>>,
    Extension(caller): Extension<AuthenticatedCaller>,
    Json(request): Json<AuthorityFenceReadRequest>,
) -> Response {
    if let Err(response) = check_caller(&caller, &request.caller.service_id) {
        return response;
    }
    match service.read_fence(&request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => service_error_response(&error, &service),
    }
}

async fn handle_prepare(
    State(service): State<Arc<AuthorityService>>,
    Extension(caller): Extension<AuthenticatedCaller>,
    Json(request): Json<AuthorityPrepareRequest>,
) -> Response {
    if let Err(response) = check_caller(&caller, &request.caller.service_id) {
        return response;
    }
    match service.prepare_source_mutation(&request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => service_error_response(&error, &service),
    }
}

async fn handle_commit(
    State(service): State<Arc<AuthorityService>>,
    Extension(caller): Extension<AuthenticatedCaller>,
    Json(request): Json<AuthorityCommitRequest>,
) -> Response {
    if let Err(response) = check_caller(&caller, &request.caller.service_id) {
        return response;
    }
    match service.record_source_commit(&request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => service_error_response(&error, &service),
    }
}

async fn handle_eligibility_completion(
    State(service): State<Arc<AuthorityService>>,
    Extension(caller): Extension<AuthenticatedCaller>,
    Json(request): Json<AuthorityEligibilityCompletionRequest>,
) -> Response {
    if let Err(response) = check_caller(&caller, &request.caller.service_id) {
        return response;
    }
    match service.record_eligibility_completion(&request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => service_error_response(&error, &service),
    }
}

async fn handle_config_completion(
    State(service): State<Arc<AuthorityService>>,
    Extension(caller): Extension<AuthenticatedCaller>,
    Json(request): Json<AuthorityConfigCompletionRequest>,
) -> Response {
    if let Err(response) = check_caller(&caller, &request.caller.service_id) {
        return response;
    }
    match service.record_config_completion(&request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => service_error_response(&error, &service),
    }
}

async fn handle_certify(
    State(service): State<Arc<AuthorityService>>,
    Extension(caller): Extension<AuthenticatedCaller>,
    Json(request): Json<AuthorityCertifyRequest>,
) -> Response {
    if let Err(response) = check_caller(&caller, &request.caller.service_id) {
        return response;
    }
    match service.certify_publication(&request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => service_error_response(&error, &service),
    }
}

async fn handle_abort(
    State(service): State<Arc<AuthorityService>>,
    Extension(caller): Extension<AuthenticatedCaller>,
    Json(request): Json<AuthorityAbortRequest>,
) -> Response {
    if let Err(response) = check_caller(&caller, &request.caller.service_id) {
        return response;
    }
    match service.abort_reservation(&request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => service_error_response(&error, &service),
    }
}

async fn handle_close(
    State(service): State<Arc<AuthorityService>>,
    Extension(caller): Extension<AuthenticatedCaller>,
    Json(request): Json<AuthorityCloseReservationRequest>,
) -> Response {
    if let Err(response) = check_caller(&caller, &request.caller.service_id) {
        return response;
    }
    match service.close_reservation(&request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => service_error_response(&error, &service),
    }
}

async fn handle_reconcile(
    State(service): State<Arc<AuthorityService>>,
    Extension(caller): Extension<AuthenticatedCaller>,
    Json(request): Json<AuthorityReconcileRequest>,
) -> Response {
    if let Err(response) = check_caller(&caller, &request.caller.service_id) {
        return response;
    }
    match service.reconcile_reservation(&request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => service_error_response(&error, &service),
    }
}

async fn handle_source_bootstrap_prepare(
    State(service): State<Arc<AuthorityService>>,
    Extension(caller): Extension<AuthenticatedCaller>,
    Json(request): Json<AuthoritySourceBootstrapPrepareRequest>,
) -> Response {
    if let Err(response) = check_caller(&caller, &request.caller.service_id) {
        return response;
    }
    match service.prepare_root_source_bootstrap(&request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => service_error_response(&error, &service),
    }
}

async fn handle_source_bootstrap_finalize(
    State(service): State<Arc<AuthorityService>>,
    Extension(caller): Extension<AuthenticatedCaller>,
    Json(request): Json<AuthoritySourceBootstrapFinalizeRequest>,
) -> Response {
    if let Err(response) = check_caller(&caller, &request.caller.service_id) {
        return response;
    }
    match service.finalize_root_source_bootstrap(&request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => service_error_response(&error, &service),
    }
}

async fn handle_source_bootstrap_reconcile(
    State(service): State<Arc<AuthorityService>>,
    Extension(caller): Extension<AuthenticatedCaller>,
    Json(request): Json<AuthoritySourceBootstrapReconcileRequest>,
) -> Response {
    if let Err(response) = check_caller(&caller, &request.caller.service_id) {
        return response;
    }
    match service.reconcile_root_source_bootstrap(&request).await {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => service_error_response(&error, &service),
    }
}

/// Build the authenticated router.
pub fn build_router(service: Arc<AuthorityService>, max_body_bytes: usize) -> Router {
    Router::new()
        .route(
            astral_types::AUTHORITY_PATH_FENCE_CURRENT,
            post(handle_fence_read),
        )
        .route(
            astral_types::AUTHORITY_PATH_SOURCE_INTENTS,
            post(handle_prepare),
        )
        .route(
            astral_types::AUTHORITY_PATH_SOURCE_COMMITS,
            post(handle_commit),
        )
        .route(
            AUTHORITY_PATH_ELIGIBILITY_COMPLETIONS,
            post(handle_eligibility_completion),
        )
        .route(
            AUTHORITY_PATH_CONFIG_COMPLETIONS,
            post(handle_config_completion),
        )
        .route(
            astral_types::AUTHORITY_PATH_PUBLICATION_CERTIFICATIONS,
            post(handle_certify),
        )
        .route(
            astral_types::AUTHORITY_PATH_RESERVATION_RECONCILE,
            post(handle_reconcile),
        )
        .route(
            astral_types::AUTHORITY_PATH_RESERVATION_CLOSE,
            post(handle_close),
        )
        .route(AUTHORITY_PATH_RESERVATION_ABORTS, post(handle_abort))
        .route(
            AUTHORITY_PATH_SOURCE_BOOTSTRAP_PREPARE,
            post(handle_source_bootstrap_prepare),
        )
        .route(
            AUTHORITY_PATH_SOURCE_BOOTSTRAP_FINALIZE,
            post(handle_source_bootstrap_finalize),
        )
        .route(
            AUTHORITY_PATH_SOURCE_BOOTSTRAP_RECONCILE,
            post(handle_source_bootstrap_reconcile),
        )
        .route(
            astral_types::AUTHORITY_PATH_ATTESTATION_STARTUP,
            post(handle_attestation),
        )
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(service)
}

/// Load the mandatory TLS material and build the mTLS acceptor.
pub fn build_tls_acceptor(
    server_cert_path: &std::path::Path,
    server_key_path: &std::path::Path,
    client_ca_path: &std::path::Path,
) -> Result<TlsAcceptor, String> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(server_cert_path)
            .map_err(|error| format!("server cert {}: {error}", server_cert_path.display()))?,
    ))
    .collect::<Result<_, _>>()
    .map_err(|error| format!("parse server cert: {error}"))?;
    if certs.is_empty() {
        return Err("server certificate file contains no certificates".to_owned());
    }
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(server_key_path)
            .map_err(|error| format!("server key {}: {error}", server_key_path.display()))?,
    ))
    .map_err(|error| format!("parse server key: {error}"))?
    .ok_or("server key file contains no private key")?;

    let mut client_roots = RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(client_ca_path)
            .map_err(|error| format!("client CA {}: {error}", client_ca_path.display()))?,
    ))
    .map_while(Result::ok)
    {
        client_roots
            .add(certificate)
            .map_err(|error| format!("add client CA: {error}"))?;
    }
    if client_roots.is_empty() {
        return Err("client CA file contains no certificates".to_owned());
    }

    // Both providers select the crate-pinned `ring` explicitly: the feature
    // graph can enable more than one rustls crypto provider (etcd-client's
    // TLS chain), so the process-level default is ambiguous and must never
    // be relied on at startup.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), Arc::clone(&provider))
            .build()
            .map_err(|error| format!("build client verifier: {error}"))?;
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("protocol versions: {error}"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|error| format!("server certificate/key: {error}"))?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Serve the authenticated mTLS listener until the process is stopped.
///
/// This is the ONLY serving path: there is no plaintext fallback.
///
/// Connection lifecycle is owned by [`lifecycle`]: per-phase timeouts (the
/// TLS handshake and the whole connection lifetime are hard-capped; the
/// request timeout stays the configured `request_timeout_seconds`), a strict
/// connection semaphore whose permit is held for the whole connection, and a
/// `JoinSet` that aborts every in-flight connection when this future
/// returns, is dropped, or is cancelled (process shutdown / runtime
/// cancellation), so shutdown is deterministic. A request cut by a cap or
/// by shutdown is never replayed by callers: the client library maps a
/// dropped transport to an unknown outcome and reconciles by the stable
/// operation/reservation id.
pub async fn serve(
    service: Arc<AuthorityService>,
    bind_address: &str,
    tls_acceptor: TlsAcceptor,
    request_timeout: Duration,
    connection_limit: Arc<Semaphore>,
) -> Result<(), String> {
    lifecycle::serve_with_timeouts(
        service,
        bind_address,
        tls_acceptor,
        lifecycle::PhaseTimeouts::derive(request_timeout),
        connection_limit,
    )
    .await
}
