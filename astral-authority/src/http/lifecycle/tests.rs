//! Behavior tests for the authority transport lifecycle.
//!
//! These tests exercise the REAL listener end to end over loopback TCP with
//! a locally generated test PKI (mTLS both ways). They assert the transport
//! hygiene contract: bounded handshake, closed-semaphore fail-closed,
//! allowlist rejection before serving, full mTLS round trip, connection
//! lifetime cap, and deterministic abort of open connections when the serve
//! future is cancelled. Quorum/TLS-cluster integration against a real etcd
//! deployment is NOT covered here and must carry separate environment
//! evidence (per AGENTS §5/§7).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use astral_types::{AuthorityRootKey, AuthorityRootKeyRole, AuthorityTrustRoot};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::RootCertStore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

use super::{serve_on_listener, PhaseTimeouts};
use crate::config::{
    AuthorityIdentityConfig, AuthorityServiceConfig, AuthoritySignerConfig, AuthorityTrustedSource,
};
use crate::service::AuthorityService;
use crate::signing::ProtectedAuthoritySigner;
use crate::store::memory::MemoryAuthorityStore;

#[test]
fn lifetime_cap_is_derived_from_request_budget_with_floor() {
    // Default production request timeout (10s) -> 4x lifetime cap.
    let default = PhaseTimeouts::derive(Duration::from_secs(10));
    assert_eq!(default.handshake, Duration::from_secs(10));
    assert_eq!(default.connection_lifetime, Duration::from_secs(40));
    assert_eq!(default.request, Duration::from_secs(10));

    // Configuration minimum (1s) -> the 30s floor prevents pathological churn.
    let floored = PhaseTimeouts::derive(Duration::from_secs(1));
    assert_eq!(floored.connection_lifetime, Duration::from_secs(30));

    // Configuration maximum (120s) -> bounded, still far above one request.
    let maximum = PhaseTimeouts::derive(Duration::from_secs(120));
    assert_eq!(maximum.connection_lifetime, Duration::from_secs(480));
}

/// One PEM file under the OS temp dir with a run-scoped unique name, removed
/// on drop (including test panics).
struct TempPem(PathBuf);

impl Drop for TempPem {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct TestPki {
    server_cert_pem: String,
    server_key_pem: String,
    client_ca_pem: String,
    client_cert_der: CertificateDer<'static>,
    client_key_pkcs8_der: Vec<u8>,
    client_fingerprint: String,
}

fn generate_test_pki() -> TestPki {
    let mut ca_params =
        rcgen::CertificateParams::new(vec!["astral-authority-test-ca".to_owned()]).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut server_params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    server_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    let server_key = rcgen::KeyPair::generate().unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    let mut client_params =
        rcgen::CertificateParams::new(vec!["astral-authority-test-client".to_owned()]).unwrap();
    client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    client_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    let client_key = rcgen::KeyPair::generate().unwrap();
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();

    let client_fingerprint = crate::http::certificate_fingerprint(client_cert.der().as_ref());
    TestPki {
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_ca_pem: ca_cert.pem(),
        client_cert_der: CertificateDer::from(client_cert.der().to_vec()),
        client_key_pkcs8_der: client_key.serialize_der(),
        client_fingerprint,
    }
}

fn write_temp_pem(suffix: &str, content: &str) -> TempPem {
    let path = std::env::temp_dir().join(format!(
        "astral-authority-lifecycle-test-{}-{suffix}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::write(&path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    TempPem(path)
}

struct ServerFixture {
    addr: SocketAddr,
    limit: Arc<Semaphore>,
    handle: JoinHandle<()>,
    pki: TestPki,
    _pem_files: Vec<TempPem>,
}

impl Drop for ServerFixture {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Spawn the real listener on an ephemeral loopback port. `register_client`
/// controls whether the generated client certificate is in the allowlist.
async fn spawn_server(
    timeouts: PhaseTimeouts,
    register_client: bool,
    permits: usize,
) -> ServerFixture {
    let pki = generate_test_pki();
    let server_crt = write_temp_pem("server.crt", &pki.server_cert_pem);
    let server_key = write_temp_pem("server.key", &pki.server_key_pem);
    let client_ca = write_temp_pem("client-ca.crt", &pki.client_ca_pem);
    let acceptor = crate::http::build_tls_acceptor(&server_crt.0, &server_key.0, &client_ca.0)
        .expect("test TLS material must build");

    // The signer is constructed directly below (same shape as the runtime
    // tests); the config path field is only present so the struct is honest.
    let mut config = AuthorityServiceConfig {
        identity: AuthorityIdentityConfig {
            authority_id: "authority-transport-test".to_owned(),
            pinned_genesis_trust_root_digest: "ab".repeat(32),
        },
        signer: AuthoritySignerConfig {
            signing_key_path: Some(PathBuf::from("/not-used-by-transport-tests")),
            signing_key_env: None,
            expected_signer_key_id: "signer-1".to_owned(),
        },
        ..Default::default()
    };
    if register_client {
        config.trusted_sources.push(AuthorityTrustedSource {
            service_id: "astral-db-primary".to_owned(),
            certificate_fingerprint: pki.client_fingerprint.clone(),
            allowed_database_ids: vec!["db-1".to_owned()],
            allowed_operations: vec![
                "attestation".to_owned(),
                "prepare".to_owned(),
                "commit".to_owned(),
                "certify".to_owned(),
                "reconcile".to_owned(),
                "close".to_owned(),
            ],
        });
    }
    let service = test_service(config);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let limit = Arc::new(Semaphore::new(permits));
    let handle = tokio::spawn(serve_on_listener(
        service,
        listener,
        acceptor,
        timeouts,
        Arc::clone(&limit),
    ));
    ServerFixture {
        addr,
        limit,
        handle,
        pki,
        _pem_files: vec![server_crt, server_key, client_ca],
    }
}

/// Build a real AuthorityService: protected signer bound to a genesis-style
/// trust root over an empty memory store. Handlers therefore return error
/// responses, which is all the transport tests need (a complete HTTP round
/// trip, not business outcomes).
fn test_service(config: AuthorityServiceConfig) -> Arc<AuthorityService> {
    let signer_seed = [0xA5u8; 32];
    let signer_signing = ed25519_dalek::SigningKey::from_bytes(&signer_seed);
    let root_signing = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
    let genesis_signing = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
    let trust_root = AuthorityTrustRoot {
        root_id: "root-transport-test".to_owned(),
        keys: vec![
            AuthorityRootKey {
                key_id: "signer-1".to_owned(),
                key_epoch: 1,
                role: AuthorityRootKeyRole::Signer,
                verifying_key_hex: hex::encode(signer_signing.verifying_key().as_bytes()),
            },
            AuthorityRootKey {
                key_id: "root-1".to_owned(),
                key_epoch: 1,
                role: AuthorityRootKeyRole::Root,
                verifying_key_hex: hex::encode(root_signing.verifying_key().as_bytes()),
            },
            AuthorityRootKey {
                key_id: "genesis-1".to_owned(),
                key_epoch: 1,
                role: AuthorityRootKeyRole::Genesis,
                verifying_key_hex: hex::encode(genesis_signing.verifying_key().as_bytes()),
            },
        ],
        created_at: 1_000,
    };
    let signer = Arc::new(
        ProtectedAuthoritySigner::from_seed(signer_seed, "signer-1", &trust_root)
            .expect("transport-test signer must bind"),
    );
    Arc::new(AuthorityService::new(
        config,
        Arc::new(MemoryAuthorityStore::new()),
        signer,
    ))
}

/// A real mTLS client trusting the test CA and presenting the test client
/// certificate (or none, for the unknown-fingerprint case the certificate is
/// simply not in the server allowlist).
fn test_tls_client(pki: &TestPki) -> TlsConnector {
    let mut roots = RootCertStore::empty();
    let ca_pem = rustls_pemfile::certs(&mut std::io::BufReader::new(pki.client_ca_pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    for certificate in ca_pem {
        roots.add(certificate).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![pki.client_cert_der.clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.client_key_pkcs8_der.clone())),
        )
        .unwrap();
    TlsConnector::from(Arc::new(config))
}

/// The fixed loopback server name used by the test TLS client.
fn server_name() -> rustls::pki_types::ServerName<'static> {
    rustls::pki_types::ServerName::try_from("localhost".to_owned()).unwrap()
}

/// Observe a connection ending: `Ok(Some(bytes))` = server sent data,
/// `Ok(None)` = clean EOF, `Err(elapsed_kind)` = reset/error, `Err(_)`
/// variant on the outer timeout means the connection was never closed.
enum CloseObservation {
    Closed(Duration),
    NotClosed(Duration),
    DataReceived(Duration, Vec<u8>),
}

async fn observe_close<S>(stream: &mut S, deadline: Duration) -> CloseObservation
where
    S: tokio::io::AsyncRead + Unpin,
{
    let started = Instant::now();
    let mut buffer = [0u8; 64];
    match tokio::time::timeout(deadline, stream.read(&mut buffer)).await {
        Err(_) => CloseObservation::NotClosed(started.elapsed()),
        Ok(Ok(0)) => CloseObservation::Closed(started.elapsed()),
        Ok(Ok(read)) => CloseObservation::DataReceived(started.elapsed(), buffer[..read].to_vec()),
        Ok(Err(_)) => CloseObservation::Closed(started.elapsed()),
    }
}

fn assert_closed(observation: CloseObservation, context: &str) -> Duration {
    match observation {
        CloseObservation::Closed(elapsed) => elapsed,
        CloseObservation::DataReceived(elapsed, bytes) => {
            panic!("{context}: server sent data instead of closing ({elapsed:?}): {bytes:?}")
        }
        CloseObservation::NotClosed(elapsed) => {
            panic!("{context}: connection was never closed within the deadline ({elapsed:?})")
        }
    }
}

async fn write_attestation_request<S>(stream: &mut S)
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
        astral_types::AUTHORITY_PATH_ATTESTATION_STARTUP
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
}

/// Read one complete response so body bytes cannot be mistaken for a later
/// connection-lifetime failure.
async fn read_response<S>(stream: &mut S, buffer: &mut Vec<u8>) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut chunk = [0u8; 512];
    loop {
        if let Some(header_end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&buffer[..header_end])
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            let content_length = headers
                .split("\r\n")
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "test response must declare its content length",
                    )
                })?;
            if content_length > 64 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "test response exceeds its byte budget",
                ));
            }
            if buffer.len() >= header_end + 4 + content_length {
                return Ok(());
            }
        }
        if buffer.len() > 65 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "test response exceeds its byte budget",
            ));
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed before the response completed",
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

#[tokio::test]
async fn slow_tls_handshake_is_bounded() {
    let timeouts = PhaseTimeouts {
        handshake: Duration::from_millis(300),
        connection_lifetime: Duration::from_secs(30),
        request: Duration::from_secs(5),
    };
    let server = spawn_server(timeouts, false, 8).await;
    let mut stalled = TcpStream::connect(server.addr).await.unwrap();
    // A peer that connects and then sends nothing must be dropped by the
    // handshake cap instead of holding a permit forever.
    let elapsed = assert_closed(
        observe_close(&mut stalled, Duration::from_secs(5)).await,
        "stalled handshake",
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "handshake stall must be dropped near the 300ms cap, took {elapsed:?}"
    );
    // The listener must keep serving after dropping the stalled peer.
    let _next = TcpStream::connect(server.addr).await.unwrap();
    server.handle.abort();
}

#[tokio::test]
async fn total_connection_budget_also_bounds_the_handshake() {
    let timeouts = PhaseTimeouts {
        handshake: Duration::from_secs(30),
        connection_lifetime: Duration::from_millis(250),
        request: Duration::from_secs(5),
    };
    let server = spawn_server(timeouts, false, 1).await;
    let mut stalled = TcpStream::connect(server.addr).await.unwrap();
    assert_closed(
        observe_close(&mut stalled, Duration::from_secs(3)).await,
        "the total connection deadline must bound a stalled handshake",
    );
    tokio::time::timeout(Duration::from_secs(1), async {
        while server.limit.available_permits() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the closed handshake must return its connection permit");
}

#[tokio::test]
async fn handshake_and_serving_share_one_connection_deadline() {
    let timeouts = PhaseTimeouts {
        handshake: Duration::from_secs(5),
        connection_lifetime: Duration::from_secs(2),
        request: Duration::from_secs(5),
    };
    let server = spawn_server(timeouts, true, 1).await;
    let connector = test_tls_client(&server.pki);
    let tcp = TcpStream::connect(server.addr).await.unwrap();
    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(1), async {
        while server.limit.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the listener must own the connection before delaying TLS");
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut tls = connector.connect(server_name(), tcp).await.unwrap();
    write_attestation_request(&mut tls).await;
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(1),
        read_response(&mut tls, &mut response),
    )
    .await
    .expect("the registered client must receive headers before the total deadline")
    .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 "));
    assert_closed(
        observe_close(&mut tls, Duration::from_millis(1_600)).await,
        "TLS time must not be added to the serving lifetime",
    );
    assert!(started.elapsed() >= Duration::from_millis(1_800));
    assert!(started.elapsed() < Duration::from_millis(2_600));
}

#[tokio::test]
async fn closed_semaphore_refuses_without_spawning() {
    let timeouts = PhaseTimeouts {
        handshake: Duration::from_secs(5),
        connection_lifetime: Duration::from_secs(30),
        request: Duration::from_secs(5),
    };
    let server = spawn_server(timeouts, false, 4).await;
    server.limit.close();
    for _ in 0..2 {
        let mut refused = TcpStream::connect(server.addr).await.unwrap();
        assert_closed(
            observe_close(&mut refused, Duration::from_secs(3)).await,
            "closed semaphore must drop the connection without serving",
        );
    }
    // The accept loop stays alive after refusals.
    let _next = TcpStream::connect(server.addr).await.unwrap();
    server.handle.abort();
}

#[tokio::test]
async fn unknown_fingerprint_is_rejected_before_serving() {
    let timeouts = PhaseTimeouts {
        handshake: Duration::from_secs(5),
        connection_lifetime: Duration::from_secs(30),
        request: Duration::from_secs(5),
    };
    // The client certificate is valid against the CA but NOT registered.
    let server = spawn_server(timeouts, false, 8).await;
    let connector = test_tls_client(&server.pki);
    let tcp = TcpStream::connect(("localhost", server.addr.port()))
        .await
        .unwrap();
    let mut tls = connector
        .connect(server_name(), tcp)
        .await
        .expect("rustls handshake with a CA-valid client cert must succeed");
    write_attestation_request(&mut tls).await;
    // The server resolves identity, finds no allowlist entry, and closes
    // before any handler runs: no HTTP response bytes may arrive.
    let observation = observe_close(&mut tls, Duration::from_secs(3)).await;
    match &observation {
        CloseObservation::Closed(_) => {}
        CloseObservation::DataReceived(_, bytes) => {
            panic!("unregistered fingerprint must never be served, got: {bytes:?}")
        }
        CloseObservation::NotClosed(_) => {
            panic!("unregistered fingerprint connection was never closed")
        }
    }
    server.handle.abort();
}

#[tokio::test]
async fn registered_client_round_trips_then_idle_connection_is_capped() {
    let timeouts = PhaseTimeouts {
        handshake: Duration::from_secs(5),
        connection_lifetime: Duration::from_millis(1_500),
        request: Duration::from_secs(5),
    };
    let server = spawn_server(timeouts, true, 8).await;
    let connector = test_tls_client(&server.pki);
    let tcp = TcpStream::connect(("localhost", server.addr.port()))
        .await
        .unwrap();
    let mut tls = connector
        .connect(server_name(), tcp)
        .await
        .expect("registered client must complete mTLS");
    write_attestation_request(&mut tls).await;
    let mut response = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        read_response(&mut tls, &mut response),
    )
    .await
    .expect("registered client must receive a response within the deadline")
    .expect("headers must complete on a live connection");
    assert!(
        response.starts_with(b"HTTP/1.1 "),
        "expected an HTTP/1.1 response, got: {:?}",
        String::from_utf8_lossy(&response)
    );

    // Keep-alive idle: the connection lifetime cap must close it. The lower
    // bound guards against an accidental early close unrelated to the cap.
    let started = Instant::now();
    let closed = assert_closed(
        observe_close(&mut tls, Duration::from_secs(8)).await,
        "idle keep-alive connection",
    );
    assert!(
        started.elapsed() >= Duration::from_millis(1_000),
        "connection closed too early to be the lifetime cap: {closed:?}"
    );
    server.handle.abort();
}

#[tokio::test]
async fn serve_cancellation_aborts_open_connections() {
    let timeouts = PhaseTimeouts {
        // Long caps: only the cancellation of the serve future may close the
        // connection in this test.
        handshake: Duration::from_secs(30),
        connection_lifetime: Duration::from_secs(600),
        request: Duration::from_secs(30),
    };
    let server = spawn_server(timeouts, true, 8).await;
    let connector = test_tls_client(&server.pki);
    let tcp = TcpStream::connect(("localhost", server.addr.port()))
        .await
        .unwrap();
    let mut tls = connector.connect(server_name(), tcp).await.unwrap();

    // Runtime cancellation of serve: the owned JoinSet drops and aborts the
    // open connection task deterministically.
    server.handle.abort();

    let elapsed = assert_closed(
        observe_close(&mut tls, Duration::from_secs(3)).await,
        "open connection after serve cancellation",
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "cancellation must abort open connections promptly, took {elapsed:?}"
    );
}
