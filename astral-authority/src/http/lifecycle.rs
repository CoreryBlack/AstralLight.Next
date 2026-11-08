//! Connection lifecycle for the authority mTLS listener.
//!
//! Transport hygiene is owned entirely by this module:
//! - every phase is time-bounded: the TLS handshake and the whole connection
//!   lifetime have hard caps, and each request keeps its own
//!   `request_timeout` (existing behavior);
//! - the connection semaphore is strict: a connection task exists only while
//!   its permit is held, and a failed acquisition (closed semaphore) refuses
//!   the connection instead of spawning it without a permit — fail-closed;
//! - connection tasks are owned by a [`tokio::task::JoinSet`] held in the
//!   serve frame. When the serve future returns, is dropped, or is cancelled
//!   (process shutdown / runtime cancellation), the JoinSet aborts every
//!   in-flight connection deterministically. Aborting a connection
//!   mid-request NEVER causes a source replay: clients map a dropped
//!   transport to an unknown outcome and reconcile by the stable
//!   operation/reservation id (authority protocol contract), they never
//!   resend;
//! - disconnects are logged with connection metadata only — peer address,
//!   logical service id, phase, elapsed time, transport error — never
//!   request bodies, headers, or URLs. The certificate fingerprint appears
//!   only in the pre-existing unknown-fingerprint rejection warning.
//!
//! Phase model and budgets:
//! 1. permit acquisition — the accept-loop backpressure point. It can wait,
//!    but cannot starve: every permit holder is itself time-bounded by the
//!    phases below, so permits are always returned.
//! 2. TLS handshake — fixed [`HANDSHAKE_TIMEOUT`].
//! 3. identity resolution — synchronous allowlist lookup, cannot hang.
//! 4. request serving — per-request `request_timeout`, and the whole
//!    connection capped at [`PhaseTimeouts::connection_lifetime`] so an idle
//!    keep-alive connection can never hold a permit indefinitely.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Extension;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{timeout, timeout_at, Instant as TokioInstant};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

use crate::http::{certificate_fingerprint, AuthenticatedCaller};
use crate::service::AuthorityService;

/// Fixed TLS handshake budget. A handshake is pure crypto plus network I/O;
/// registered control-plane peers complete it in milliseconds, so ten
/// seconds is generous while still guaranteeing that a stalled peer frees
/// its connection slot instead of holding a semaphore permit forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Total connection lifetime is derived from the per-request budget: at
/// least this many worst-case sequential requests fit on one keep-alive
/// connection before the cap closes it (the client reconnects; a request
/// cut by the cap is reconciled, never replayed).
const CONNECTION_LIFETIME_REQUEST_FACTOR: u32 = 4;

/// Floor for the derived connection lifetime so a short configured request
/// timeout (the configuration gate allows 1 second) cannot churn
/// connections pathologically.
const CONNECTION_LIFETIME_FLOOR: Duration = Duration::from_secs(30);

/// Per-phase transport timeouts. Constructed with [`PhaseTimeouts::derive`]
/// from the configured request timeout; tests may construct exact values.
#[derive(Debug, Clone, Copy)]
pub(super) struct PhaseTimeouts {
    /// Cap on the TLS handshake phase (permit is held during it).
    pub handshake: Duration,
    /// Cap on the total connection lifetime, including idle keep-alive
    /// gaps and every request.
    pub connection_lifetime: Duration,
    /// Cap on each individual request (unchanged existing behavior).
    pub request: Duration,
}

impl PhaseTimeouts {
    /// Derive the phase budgets from the configured request timeout. The
    /// configuration gate bounds the request timeout to 1..=120 seconds, so
    /// `checked_mul` overflow cannot happen; the defensive fallback keeps
    /// the derivation total even for out-of-range callers.
    pub(super) fn derive(request_timeout: Duration) -> Self {
        let connection_lifetime = request_timeout
            .checked_mul(CONNECTION_LIFETIME_REQUEST_FACTOR)
            .unwrap_or(CONNECTION_LIFETIME_FLOOR)
            .max(CONNECTION_LIFETIME_FLOOR);
        Self {
            handshake: HANDSHAKE_TIMEOUT,
            connection_lifetime,
            request: request_timeout,
        }
    }
}

/// Everything a connection task needs; moved into the spawned task so the
/// accept loop stays allocation-light and the task is fully owned.
struct ConnectionDeps {
    service: Arc<AuthorityService>,
    router: axum::Router,
    acceptor: TlsAcceptor,
    timeouts: PhaseTimeouts,
}

/// Bind `bind_address` and serve with explicit phase budgets.
pub(super) async fn serve_with_timeouts(
    service: Arc<AuthorityService>,
    bind_address: &str,
    tls_acceptor: TlsAcceptor,
    timeouts: PhaseTimeouts,
    connection_limit: Arc<Semaphore>,
) -> Result<(), String> {
    let listener = TcpListener::bind(bind_address)
        .await
        .map_err(|error| format!("bind {bind_address}: {error}"))?;
    serve_on_listener(service, listener, tls_acceptor, timeouts, connection_limit).await;
    Ok(())
}

/// Serve on an already-bound listener until the serve future is dropped.
///
/// Ownership contract: `connections` lives in THIS frame, so any exit or
/// cancellation of this future (process shutdown, runtime cancellation of
/// `serve`) drops the JoinSet and aborts every in-flight connection task.
/// In-flight authority requests cut this way surface to callers as unknown
/// outcomes, which the client library maps to reconciliation by stable
/// operation/reservation id — a source replay is never produced by the
/// transport.
pub(super) async fn serve_on_listener(
    service: Arc<AuthorityService>,
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    timeouts: PhaseTimeouts,
    connection_limit: Arc<Semaphore>,
) {
    let router = crate::http::build_router(
        Arc::clone(&service),
        service.config().listener.max_body_bytes,
    );
    tracing::info!(
        bind_address = %listener
            .local_addr()
            .map(|address| address.to_string())
            .unwrap_or_else(|_| "unknown".to_owned()),
        "authority mTLS listener started"
    );
    let mut connections: JoinSet<()> = JoinSet::new();
    loop {
        let (tcp_stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, "accept failed");
                continue;
            }
        };
        // Strict semaphore: acquisition happens in the accept loop so the
        // backlog (not unbounded tasks) absorbs saturation, and a failed
        // acquisition is fail-closed — the connection is dropped unserved,
        // never spawned without a permit.
        let permit = match Arc::clone(&connection_limit).acquire_owned().await {
            Ok(permit) => permit,
            Err(error) => {
                tracing::warn!(
                    %peer, %error,
                    "connection semaphore is closed; refusing connection without serving"
                );
                continue;
            }
        };
        connections.spawn(handle_connection(
            ConnectionDeps {
                service: Arc::clone(&service),
                router: router.clone(),
                acceptor: tls_acceptor.clone(),
                timeouts,
            },
            tcp_stream,
            peer,
            permit,
        ));
        // Reap completed tasks after each spawn so a long-lived process does
        // not accumulate finished handles in the set. The unit output carries
        // no state; only panics are surfaced.
        while let Some(joined) = connections.try_join_next() {
            if let Err(error) = joined {
                if !error.is_cancelled() {
                    tracing::warn!(%error, "authority connection task panicked");
                }
            }
        }
    }
}

/// Handle one accepted connection: bounded handshake, allowlist-derived
/// identity (unchanged semantics), bounded serving, and a disconnect log
/// that carries no request content.
async fn handle_connection(
    deps: ConnectionDeps,
    tcp_stream: TcpStream,
    peer: SocketAddr,
    permit: OwnedSemaphorePermit,
) {
    let started = Instant::now();
    let connection_deadline = TokioInstant::now() + deps.timeouts.connection_lifetime;
    // RAII: the permit is held for the ENTIRE connection lifetime —
    // handshake, identity resolution and serving — and released exactly when
    // this task ends, however it ends (clean close, phase cap, or shutdown
    // abort of the owning JoinSet).
    let _permit = permit;

    // Phase 1: bounded TLS handshake.
    let handshake_deadline = connection_deadline.min(TokioInstant::now() + deps.timeouts.handshake);
    let tls_stream = match timeout_at(handshake_deadline, deps.acceptor.accept(tcp_stream)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error)) => {
            tracing::debug!(
                %peer, phase = "handshake", elapsed = ?started.elapsed(), %error,
                "connection dropped: tls handshake failed"
            );
            return;
        }
        Err(_) => {
            tracing::debug!(
                %peer, phase = "handshake", elapsed = ?started.elapsed(),
                timeout = ?deps.timeouts.handshake,
                "connection dropped: tls handshake timed out"
            );
            return;
        }
    };

    // Phase 2: transport-derived identity (synchronous; cannot hang).
    let Some(authenticated) = resolve_transport_identity(&deps.service, &tls_stream, peer) else {
        return;
    };

    // Phase 3: serving. Per-request timeout (unchanged) plus a hard cap on
    // the whole connection so an idle keep-alive connection can never hold a
    // semaphore permit indefinitely.
    let service_id = authenticated.service_id.clone();
    let request_timeout = deps.timeouts.request;
    let router = deps.router;
    let hyper_service = hyper::service::service_fn(move |request| {
        let router = router.clone();
        let authenticated = authenticated.clone();
        async move {
            let served = timeout(
                request_timeout,
                router.layer(Extension(authenticated)).oneshot(request),
            )
            .await;
            match served {
                Ok(Ok(response)) => Ok(response),
                Ok(Err(error)) => Err(std::io::Error::other(error.to_string())),
                Err(_elapsed) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "request timed out",
                )),
            }
        }
    });
    // Bind the builder first: `serve_connection_with_upgrades` borrows it, so
    // the temporary cannot be freed at the end of the statement.
    let connection_builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    let serving = connection_builder
        .serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(tls_stream), hyper_service);
    let outcome = timeout_at(connection_deadline, serving).await;
    let elapsed = started.elapsed();
    match outcome {
        Ok(Ok(())) => {
            tracing::debug!(%peer, %service_id, phase = "serving", ?elapsed, "connection closed")
        }
        Ok(Err(error)) => {
            tracing::debug!(
                %peer, %service_id, phase = "serving", ?elapsed, %error,
                "stream disconnect"
            )
        }
        Err(_) => {
            tracing::info!(
                %peer, %service_id, phase = "serving", ?elapsed,
                timeout = ?deps.timeouts.connection_lifetime,
                "connection lifetime cap reached; closing"
            )
        }
    }
}

/// Derive the caller identity from the client certificate chain exactly as
/// before: SHA-256 fingerprint of the first peer certificate, resolved
/// through the configured trusted-source allowlist. Unknown fingerprints
/// are rejected before any handler runs; the allowlist and fingerprint
/// derivation are unchanged by the lifecycle work.
fn resolve_transport_identity(
    service: &AuthorityService,
    tls_stream: &TlsStream<TcpStream>,
    peer: SocketAddr,
) -> Option<AuthenticatedCaller> {
    let Some(certificate) = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
    else {
        tracing::debug!(%peer, "mTLS connection without client certificate rejected");
        return None;
    };
    let fingerprint = certificate_fingerprint(certificate.as_ref());
    let Some(service_id) = service
        .config()
        .trusted_source_by_fingerprint(&fingerprint)
        .map(|source| source.service_id.clone())
    else {
        tracing::warn!(
            %peer, fingerprint = %fingerprint,
            "unknown client certificate fingerprint rejected"
        );
        return None;
    };
    Some(AuthenticatedCaller {
        service_id,
        certificate_fingerprint: fingerprint,
    })
}

#[cfg(test)]
mod tests;
