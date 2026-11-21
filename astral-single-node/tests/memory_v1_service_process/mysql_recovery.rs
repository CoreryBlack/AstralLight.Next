//! memory—v1: Real child process and MySQL with controlled loss of dependency transport.

use super::*;
use astral_db::memory_v1_apply::read_memory_v1_apply_progress;
use astral_single_node::memory_v1_durable_journal::{
    CheckpointInstallId, DurableJournalLimits, MemoryV1DurableJournal, RecoveryRecord,
};
use astral_types::memory_v1_journal::{JournalAnchor, RecordKind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;

pub(super) struct Fixture<'a> {
    pub(super) env: Vec<(String, String)>,
    pub(super) cwd: &'a Path,
    pub(super) evidence_dir: &'a Path,
    pub(super) journal_dir: &'a Path,
    pub(super) db: &'a MySqlPool,
    pub(super) scope: [u8; 32],
    pub(super) stream: MemoryId,
    pub(super) epoch: MemoryId,
    pub(super) genesis: [u8; 32],
    pub(super) rows: usize,
}

struct Relay {
    address: SocketAddr,
    offline: Arc<AtomicBool>,
    rejected: Arc<AtomicUsize>,
    worker: JoinHandle<()>,
}

impl Relay {
    // memory—v1: Reserve one private port for the whole run. The upstream server is not stopped.
    async fn start(upstream: SocketAddr) -> Self {
        assert!(upstream.ip().is_loopback());
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let offline = Arc::new(AtomicBool::new(false));
        let rejected = Arc::new(AtomicUsize::new(0));
        let unavailable = Arc::clone(&offline);
        let refusals = Arc::clone(&rejected);
        let worker = tokio::spawn(async move {
            let mut streams = JoinSet::new();
            let mut requests = 0;
            loop {
                tokio::select! {
                    Some(result) = streams.join_next(), if !streams.is_empty() => result.unwrap(),
                    incoming = listener.accept() => {
                        let (mut client, _) = incoming.unwrap();
                        requests += 1;
                        assert!(requests <= 128 && streams.len() < 8, "relay budget exceeded");
                        if unavailable.load(Ordering::Acquire) {
                            refusals.fetch_add(1, Ordering::Release);
                            continue;
                        }
                        streams.spawn(async move {
                            let mut server = timeout(Duration::from_secs(3), TcpStream::connect(upstream))
                                .await.unwrap().unwrap();
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                        });
                    }
                }
            }
        });
        Self {
            address,
            offline,
            rejected,
            worker,
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

#[tokio::test]
#[ignore = "requires an approved isolated numeric-loopback MySQL fixture; stages and drops one run-scoped schema"]
async fn real_service_recovers_after_mysql_transport_loss() {
    with_run_scoped_mysql_fixture(true).await;
}

// memory—v1: Show availability on the warm root and fail-closed cold startup separately.
pub(super) async fn exercise(fixture: Fixture<'_>) {
    let original = fixture
        .env
        .iter()
        .find(|(key, _)| key == "DATABASE_URL")
        .unwrap();
    let mut url = reqwest::Url::parse(&original.1).unwrap();
    let upstream = SocketAddr::new(
        url.host_str()
            .unwrap()
            .trim_matches(['[', ']'])
            .parse()
            .expect("numeric loopback MySQL"),
        url.port().unwrap_or(3306),
    );
    assert!(!url.query_pairs().any(|(key, _)| key == "socket"));
    let relay = Relay::start(upstream).await;
    url.set_host(Some("127.0.0.1")).unwrap();
    url.set_port(Some(relay.address.port())).unwrap();
    let env = with_var(fixture.env.clone(), "DATABASE_URL", url.as_str());
    let mut subject =
        startup_issuer::inspect_fixture_subject(&env, fixture.cwd, fixture.scope).await;
    assert_eq!(
        (subject.journal_sequence, subject.mutation_sequence),
        (0, 0)
    );
    let signed = startup_issuer::sign_fixture(env.clone(), fixture.evidence_dir, subject.clone());
    let mut warm = start(&signed, fixture.cwd);
    let address = ready_address(&mut warm, fixture.rows).await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let alice = login(&client, address, "alice", CARD_ALLOW).await;
    let unbound = login(&client, address, "alice", CARD_UNBOUND).await;
    assert_read(&client, address, &alice, 200).await;

    let fault = Instant::now();
    relay.offline.store(true, Ordering::Release);
    assert_read(&client, address, &alice, 200).await;
    let reply = assert_read(&client, address, &unbound, 403).await;
    assert_eq!(reply.body["decision"], "AUTHORIZATION_CARD_UNBOUND");
    let warm_correct = fault.elapsed();
    stop(&mut warm).await;
    let (record, frame_hash) = retained_deny(&fixture, subject.installation_id);
    assert_eq!(record.journal_sequence, 1);

    let old_envelope = refused(&signed).await;
    assert!(
        old_envelope.contains("does not bind the captured startup state"),
        "{old_envelope}"
    );
    assert_eq!(
        relay.rejected.load(Ordering::Acquire),
        0,
        "stale checkpoint must refuse before MySQL"
    );
    let progress = read_memory_v1_apply_progress(fixture.db, fixture.stream)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            progress.last_journal_sequence,
            progress.last_mutation_sequence,
            progress.last_frame_hash
        ),
        (0, 0, fixture.genesis)
    );

    // The fixture independently knows this is a DENY-only suffix: the nine fact
    // tables, registry and mutation frontier cannot change. The real issuer
    // must independently establish such a recovery subject, not copy this signer.
    subject.journal_sequence = record.journal_sequence;
    subject.journal_tail_hash = frame_hash;
    let signed = startup_issuer::sign_fixture(env, fixture.evidence_dir, subject);
    let down = refused(&signed).await;
    assert!(
        down.contains("connect the memory-v1 candidate database"),
        "{down}"
    );
    let detected = fault.elapsed();
    let rejected = relay.rejected.load(Ordering::Acquire);
    assert!(
        rejected > 0,
        "cold startup must actually hit the private dependency cutoff"
    );

    let restored = Instant::now();
    relay.offline.store(false, Ordering::Release);
    let mut recovered = start(&signed, fixture.cwd);
    let (first_correct, backlog_verified) = tokio::join!(
        async {
            let addr = ready_address(&mut recovered, fixture.rows).await;
            assert_read(&client, addr, &alice, 401).await;
            let token = login(&client, addr, "alice", CARD_ALLOW).await;
            assert_read(&client, addr, &token, 200).await;
            restored.elapsed()
        },
        async {
            timeout(Duration::from_secs(30), async {
                loop {
                    let progress = read_memory_v1_apply_progress(fixture.db, fixture.stream)
                        .await
                        .unwrap()
                        .unwrap();
                    if progress.last_journal_sequence == record.journal_sequence {
                        assert_eq!(progress.last_mutation_sequence, 0);
                        assert_eq!(progress.last_frame_hash, frame_hash);
                        break;
                    }
                    assert_eq!(progress.last_journal_sequence, 0);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let joined: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
                    "SELECT r.frame_digest, r.outcome, a.message_id, a.decision \
                     FROM mv1_apply_receipt r JOIN mv1_apply_audit_event a \
                     USING (stream_id, journal_sequence, operation_id, audit_row_digest) \
                     WHERE r.stream_id = ? AND r.operation_id = ? AND a.message_id = r.message_id",
                )
                .bind(fixture.stream.as_bytes().as_slice())
                .bind(&record.operation_id)
                .fetch_one(fixture.db)
                .await
                .unwrap();
                assert_eq!(
                    joined,
                    (
                        frame_hash.to_vec(),
                        b"DENY".to_vec(),
                        record.message_id.as_bytes().to_vec(),
                        b"DENY:card_unbound".to_vec()
                    )
                );
                restored.elapsed()
            })
            .await
            .expect("durable suffix readback deadline")
        },
    );
    stop(&mut recovered).await;
    assert!(
        !relay.worker.is_finished(),
        "the relay must not have stopped unexpectedly"
    );
    eprintln!("mysql_transport_recovery warm_correct_ms={} cold_refusal_ms={} first_correct_after_restore_ms={} durable_backlog_verified_after_restore_ms={} rejected_connections={} deny_frames=1 mutation_frames=0",
        warm_correct.as_millis(), detected.as_millis(), first_correct.as_millis(), backlog_verified.as_millis(), rejected);
}

async fn ready_address(running: &mut Running, rows: usize) -> SocketAddr {
    let ready = running
        .wait_ready(Duration::from_secs(30))
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(
        ready.contains("grade=Production") && ready.contains(&format!("rows={rows} ")),
        "{ready}"
    );
    let addr: SocketAddr = ready
        .split_whitespace()
        .find_map(|part| part.strip_prefix("addr="))
        .unwrap()
        .parse()
        .unwrap();
    assert!(addr.ip().is_loopback());
    addr
}

async fn assert_read(
    client: &reqwest::Client,
    addr: SocketAddr,
    token: &str,
    status: u16,
) -> Reply {
    let reply = call(
        client,
        addr,
        reqwest::Method::GET,
        REGISTRY,
        Some(token),
        None,
    )
    .await;
    assert_eq!(reply.status, status, "{}", reply.body);
    assert_eq!(reply.body["data"].is_null(), status != 200);
    reply
}

async fn stop(running: &mut Running) {
    terminate(running);
    assert!(
        running.exit(Duration::from_secs(10)).await.success(),
        "{}",
        running.output()
    );
    running.drain(Duration::from_secs(2)).await;
}

// memory—v1: Correlate the recovery subject with the independent retained checkpoint.
fn retained_deny(fixture: &Fixture<'_>, installation: MemoryId) -> (RecoveryRecord, [u8; 32]) {
    let (journal, _durability) = MemoryV1DurableJournal::open_checkpointed(
        &fixture.journal_dir.join("memory-v1-durable.bin"),
        &fixture.journal_dir.join("memory-v1-durable"),
        CheckpointInstallId::from_install_uuid(installation.into_bytes()).unwrap(),
        fixture.stream,
        fixture.epoch,
        JournalAnchor::new(fixture.stream, 0, 0, fixture.genesis).unwrap(),
        DurableJournalLimits::conservative(),
    )
    .unwrap();
    let [record] = journal.recovery_records() else {
        panic!("expected one checkpointed DENY")
    };
    assert_eq!(
        (record.kind, record.mutation_sequence),
        (RecordKind::Deny, 0)
    );
    assert_eq!(
        journal.position().journal_sequence(),
        record.journal_sequence
    );
    (record.clone(), *journal.position().frame_hash())
}
