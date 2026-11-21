//! memory—v1: Synthetic snapshots, real loopback HTTP and retained local journal.
//! This module is compiled only by the binary's Rust test target; it never
//! calls the executable startup path or supplies independently verified facts.

use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use astral_authorization_root::memory_v1_db_rows::CandidateRows;
use astral_authorization_root::memory_v1_root::{ManagementMutationV2, RootError, RootHandle};
use astral_common::config::AppConfig;
use astral_identity::memory_v1_service::MemoryV1FileCredentials;
use astral_single_node::memory_v1_durable_journal::{JournalDurability, MemoryV1DurableJournal};
use astral_trustgraph::service::memory_v1_mutation_coordinator::{
    decode_deny_journal_payload_with_origin, decode_journal_payload, journal_producer_boot_id,
};
use astral_types::memory_v1::MemoryId;
use astral_types::memory_v1_journal::RecordKind;
use serde_json::{json, Value};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use super::super::{assemble_production, open_durable_journal, production_fixture, serve};
use super::{attested_facts, http, login, login_body, CredentialsFile, LOGIN, LOGOUT, UNADAPTED};
use crate::memory_v1_composition::full_path_tests::{
    fixture, ALICE, BOB, CARD_ALLOW, CARD_BOB, CARD_OVERLAY_DENY, CARD_UNBOUND, REGISTRY,
};
use crate::memory_v1_composition::MemoryV1Composition;

#[path = "../tests/memory_v1_service_process/paper_mysql/expected.rs"]
mod paper_expected;

const CARD_NEW: [u8; 16] = [0x35; 16];
const TENANT: [u8; 16] = [0x13; 16];
const ALICE_BINDING: [u8; 16] = [0x51; 16];

pub(super) struct JournalDir(pub(super) PathBuf);

impl JournalDir {
    // memory—v1: Each scenario owns one private, automatically removed journal directory.
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "astral-memory-v1-synthetic-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }

    // memory—v1: Reopen the journal against its independent retained checkpoint.
    pub(super) fn reopen(&self) -> (MemoryV1DurableJournal, JournalDurability) {
        assert!(open_durable_journal(&self.0, MemoryId::from_bytes([62; 16])).is_err());
        open_durable_journal(&self.0, production_fixture::INSTALLATION).unwrap()
    }

    // memory—v1: Verify cleanup before returning positive evidence.
    pub(super) fn remove(self) {
        std::fs::remove_dir_all(&self.0).unwrap();
        assert!(!self.0.exists());
    }
}

impl Drop for JournalDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(super) struct SyntheticService {
    pub(super) addr: std::net::SocketAddr,
    pub(super) root: RootHandle,
    stop: oneshot::Sender<()>,
    server: JoinHandle<anyhow::Result<()>>,
    composition: MemoryV1Composition,
    dir: JournalDir,
}

impl SyntheticService {
    // memory—v1: Bind the real serving ports to an isolated fixture root, never the process root.
    pub(super) async fn start(rows: CandidateRows) -> Self {
        let facts = attested_facts(&rows);
        let owner = production_fixture::owner(rows);
        owner
            .install_registry(&super::super::registry_declarations())
            .unwrap();
        let (_, admission) = owner
            .adopt_with_production_evidence(
                &facts,
                &production_fixture::input(facts.captured_at_unix_seconds),
            )
            .expect("the isolated test root accepts the synthetic facts");
        let root = owner.handle();
        let credentials_file = CredentialsFile::write();
        let credentials = MemoryV1FileCredentials::load(&credentials_file.path).unwrap();
        let dir = JournalDir::new();
        let journal = production_fixture::journal(&dir.0);
        assert_eq!(journal.0.record_count(), 0);
        let mut config = AppConfig::default();
        config.gateway.hmac_secret = uuid::Uuid::new_v4().to_string();
        let composition = assemble_production(
            Arc::new(owner),
            Arc::new(admission),
            journal,
            config,
            credentials,
        )
        .unwrap();
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let server = tokio::spawn(serve(listener, composition.router(), async move {
            let _ = stopped.await;
        }));
        Self {
            addr,
            root,
            stop,
            server,
            composition,
            dir,
        }
    }

    // memory—v1: Stop serving and drop the sole owner before journal readback.
    pub(super) async fn drain(self) -> JournalDir {
        self.stop.send(()).unwrap();
        timeout(Duration::from_secs(10), self.server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(self.composition.request_scope_budget().active(), 0);
        drop(self.composition);
        assert!(matches!(self.root.metadata(), Err(RootError::OwnerGone)));
        assert!(
            TcpStream::connect(self.addr).await.is_err(),
            "the listener must be closed"
        );
        self.dir
    }

    // memory—v1: Check registry admission or the exact denial, without disclosing data on refusal.
    async fn registry(&self, token: &str, denial: Option<(&str, &str)>) {
        let reply = http(self.addr, "GET", REGISTRY, Some(token), None, &[]).await;
        if let Some((field, reason)) = denial {
            assert_eq!(reply.status, 403, "{}", reply.body);
            assert_eq!(reply.body[field], reason);
            assert!(reply.body["data"].is_null());
        } else {
            assert_eq!(reply.status, 200, "{}", reply.body);
            assert!(!reply.body["data"].is_null());
        }
    }

    // memory—v1: Require the operation-correlated receipt to match the published root.
    async fn publish(&self, token: &str, method: &str, path: &str, operation: &str, body: Value) {
        let before = self.root.metadata().unwrap();
        let reply = http(
            self.addr,
            method,
            path,
            Some(token),
            Some(&body),
            &[("x-request-id", operation)],
        )
        .await;
        assert_eq!(reply.status, 200, "{}", reply.body);
        let after = self.root.metadata().unwrap();
        let data = &reply.body["data"];
        assert_eq!(data["operationId"], operation);
        assert_eq!(after.version, before.version + 1);
        assert_eq!(data["rootVersion"], after.version);
        assert_eq!(data["rootDigest"], hex::encode(after.digest));
        assert_ne!(after.digest, [0; 32]);
        assert_ne!(after.digest, before.digest);
    }
}

// memory—v1: Correlate a retained DENY with the card and the mutation prefix it observed.
fn assert_deny(
    frame: &astral_single_node::memory_v1_durable_journal::RecoveryRecord,
    card: [u8; 16],
    sequence: u64,
) {
    assert_eq!(frame.kind, RecordKind::Deny);
    assert_eq!(frame.mutation_sequence, sequence);
    let (origin, observation) = decode_deny_journal_payload_with_origin(&frame.payload).unwrap();
    assert_eq!(origin, Some(journal_producer_boot_id()));
    assert_eq!(observation.operation_id(), frame.operation_id.as_bytes());
    assert_eq!(
        observation.identity().user_card_id,
        MemoryId::from_bytes(card)
    );
    assert_eq!(
        (observation.resource(), observation.action()),
        ("permission_rule", "read")
    );
}

// memory—v1: Share the independent 23-row paper oracle across loopback tests.
pub(super) fn paper_warm_rows() -> CandidateRows {
    let rows = paper_expected::expected_rows();
    assert_eq!(rows.table_counts(), paper_expected::COUNTS);
    assert_eq!(paper_expected::COUNTS.total(), Some(23));
    rows
}

// memory—v1: The paper's independent 23-row oracle drives warm self-scope governance.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "selected by the DarkStar synthetic warm-governance suite"]
async fn paper_warm_governance_with_synthetic_snapshot() {
    let service = SyntheticService::start(paper_warm_rows()).await;
    let addr = service.addr;
    let run = uuid::Uuid::new_v4().simple();
    let create = format!("synthetic-{run}-card-create");
    let revoke = format!("synthetic-{run}-binding-remove");
    let alice = login(addr, "alice", "alice-secret", CARD_ALLOW).await;
    let bob = login(addr, "bob", "bob-secret", CARD_BOB).await;
    let unbound = login(addr, "alice", "alice-secret", CARD_UNBOUND).await;
    let unbound_reason = Some(("decision", "AUTHORIZATION_CARD_UNBOUND"));
    service.registry(&alice, None).await;
    service.registry(&bob, None).await;
    service.registry(&unbound, unbound_reason).await;

    service
        .publish(
            &bob,
            "POST",
            "/main/api/v1/governance/user-cards",
            &create,
            json!({
                "user_card_id": MemoryId::from_bytes(CARD_NEW).to_string(),
                "user_id": MemoryId::from_bytes(BOB).to_string(),
                "tenant_id": MemoryId::from_bytes(TENANT).to_string(),
            }),
        )
        .await;
    let new_card = login(addr, "bob", "bob-secret", CARD_NEW).await;
    service.registry(&new_card, unbound_reason).await;
    service.registry(&alice, None).await;
    service
        .publish(
            &alice,
            "DELETE",
            "/main/api/v1/governance/bindings",
            &revoke,
            json!({
                "binding_id": MemoryId::from_bytes(ALICE_BINDING).to_string(),
            }),
        )
        .await;
    service
        .registry(&alice, Some(("decision", "AUTHORIZATION_NO_MATCH")))
        .await;
    service.registry(&bob, None).await;

    let dir = service.drain().await;
    {
        let (journal, _sync) = dir.reopen();
        let [before, created, unbound, removed, after] = journal.recovery_records() else {
            panic!("expected two mutations and three DENYs in the reopened checkpointed prefix");
        };
        assert_eq!(journal.position().mutation_sequence(), 2);
        assert_deny(before, CARD_UNBOUND, 0);
        assert_deny(unbound, CARD_NEW, 1);
        assert_deny(after, CARD_ALLOW, 2);
        for (frame, operation, sequence) in [(created, create, 1), (removed, revoke, 2)] {
            assert_eq!(frame.kind, RecordKind::Mutation);
            assert_eq!(frame.mutation_sequence, sequence);
            assert_eq!(frame.operation_id, operation);
            let decoded = decode_journal_payload(&frame.payload).unwrap();
            assert_eq!(decoded.operation_id(), operation);
            assert_eq!(decoded.origin_boot_id(), Some(journal_producer_boot_id()));
            match (sequence, decoded.mutation()) {
                (1, ManagementMutationV2::UserCardCreate { row }) => {
                    assert_eq!(
                        (row.user_card_id, row.user_id, row.tenant_id),
                        (CARD_NEW, BOB, TENANT)
                    );
                }
                (
                    2,
                    ManagementMutationV2::BindingRemove {
                        binding_id,
                        removed_by,
                        ..
                    },
                ) => {
                    assert_eq!((*binding_id, *removed_by), (ALICE_BINDING, ALICE));
                }
                _ => panic!("unexpected retained mutation at sequence {sequence}"),
            }
        }
    }
    dir.remove();
    eprintln!("synthetic warm governance: rows=23 mutations=2 denials=3 journal_reopened=true listener_drained=true");
    eprintln!("synthetic_evidence scenario=paper-warm-governance");
}

// memory—v1: Exercise the composed session and authorization lifecycle, not executable startup.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "selected by the DarkStar synthetic binary-lifecycle suite"]
async fn binary_lifecycle_with_synthetic_snapshot() {
    let service = SyntheticService::start(fixture().0).await;
    let addr = service.addr;
    assert_eq!(
        http(addr, "GET", REGISTRY, None, None, &[]).await.status,
        401
    );
    let reply = http(
        addr,
        "POST",
        LOGIN,
        None,
        Some(&login_body("alice", "alice-secret", CARD_ALLOW)),
        &[],
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert_eq!(reply.body["data"]["tokenType"], "Bearer");
    assert!((1..=1_800).contains(&reply.body["data"]["expiresIn"].as_i64().unwrap()));
    let alice = reply.body["data"]["accessToken"].as_str().unwrap();
    service.registry(alice, None).await;
    let overlay = login(addr, "alice", "alice-secret", CARD_OVERLAY_DENY).await;
    service
        .registry(&overlay, Some(("reasonCode", "AUTHORIZATION_RULE_DENIED")))
        .await;
    let unbound = login(addr, "alice", "alice-secret", CARD_UNBOUND).await;
    service
        .registry(&unbound, Some(("decision", "AUTHORIZATION_CARD_UNBOUND")))
        .await;
    let bob = login(addr, "bob", "bob-secret", CARD_BOB).await;
    service.registry(&bob, None).await;
    let pending = http(addr, "GET", UNADAPTED, Some(&bob), None, &[]).await;
    assert_eq!(pending.status, 503, "{}", pending.body);
    assert_eq!(
        pending.body["reasonCode"],
        "AUTHORIZATION_ROUTE_NOT_ADAPTED"
    );
    assert!(pending.body["data"].is_null());
    let logged_out = http(addr, "POST", LOGOUT, Some(alice), None, &[]).await;
    assert_eq!(logged_out.status, 200);
    assert_eq!(logged_out.body["success"], true);
    assert_eq!(
        http(addr, "GET", REGISTRY, Some(alice), None, &[])
            .await
            .status,
        401
    );
    service.registry(&bob, None).await;

    let dir = service.drain().await;
    {
        let (journal, _sync) = dir.reopen();
        let [overlay, unbound] = journal.recovery_records() else {
            panic!("expected two DENYs and no records for PENDING or session revocation");
        };
        assert_eq!(journal.position().mutation_sequence(), 0);
        assert_deny(overlay, CARD_OVERLAY_DENY, 0);
        assert_deny(unbound, CARD_UNBOUND, 0);
    }
    dir.remove();
    eprintln!("synthetic binary lifecycle: denials=2 mutations=0 journal_reopened=true listener_drained=true");
    eprintln!("synthetic_evidence scenario=binary-lifecycle");
}
