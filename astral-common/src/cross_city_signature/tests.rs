//! Tests for the cross-city signature boundary.
//!
//! Pure by construction: no network, no database, no cache, no external
//! service, no runtime callers. The only secret material lives inside this
//! test module (fixed test seeds) and never appears in production types,
//! `Debug` output, or error output.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use super::{
    cross_city_signature_message, verify_zero_decision_evidence, CrossCityEvidenceReplayKey,
    CrossCityNodeIdentity, CrossCityNodeKeyRecord, CrossCityNodeKeyResolver, CrossCityReplayGuard,
    CrossCitySignatureError, CROSS_CITY_NODE_SIGNATURE_DOMAIN_PREFIX,
    CROSS_CITY_SIGNATURE_MESSAGE_LEN,
};
use astral_types::{MutationProposal, NodeDecision, ZeroDecisionEvidence};

/// The module source itself, pinned at compile time for source-shape tests.
const MODULE_SOURCE: &str = include_str!("../cross_city_signature.rs");

// ---------------------------------------------------------------------------
// RFC 8032 known-answer material (section 7.1, TEST 1)
// ---------------------------------------------------------------------------

/// RFC 8032 section 7.1 TEST 1 secret seed.
const RFC8032_TEST1_SEED_HEX: &str =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
/// RFC 8032 section 7.1 TEST 1 public key.
const RFC8032_TEST1_PUBLIC_KEY_HEX: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
/// RFC 8032 section 7.1 TEST 1 signature over the empty message.
const RFC8032_TEST1_SIGNATURE_HEX: &str =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

// ---------------------------------------------------------------------------
// Fixed cross-city golden vector material
// ---------------------------------------------------------------------------

/// Fixed test-only signing seed of the golden node (never a production key).
const GOLDEN_SEED: [u8; 32] = *b"astral-cross-city-signature-seed";
/// Second fixed test-only signing seed, used for wrong-key / two-node tests.
const SECOND_SEED: [u8; 32] = *b"astral-cross-city-signature-0000";

const GOLDEN_CITY_ID: &str = "city-alpha";
const GOLDEN_NODE_ID: &str = "node-01";
const GOLDEN_NODE_EPOCH: u64 = 7;
const GOLDEN_OPERATION_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
/// 64 lowercase hex characters used as the golden scope digest input.
const GOLDEN_SCOPE_DIGEST: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
/// 64 lowercase hex characters used as the golden request digest input.
const GOLDEN_REQUEST_DIGEST: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
/// 64 lowercase hex characters used as the golden mutation digest input.
const GOLDEN_MUTATION_DIGEST: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
/// 64 lowercase hex characters used as the golden frontier digest input.
const GOLDEN_FRONTIER_DIGEST: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";
/// Mutation digest of a second, different proposal (replay-binding test).
const OTHER_MUTATION_DIGEST: &str =
    "9999999999999999999999999999999999999999999999999999999999999999";
const GOLDEN_COMPILER_VERSION: &str = "golden-v1";
const GOLDEN_POLICY_VERSION: &str = "golden-v1";
const GOLDEN_NONCE: &str = "golden-nonce-001";
const GOLDEN_EXPIRES_AT: i64 = 4102444800;

// The following values are pinned from a one-time generation run; the tests
// assert that the live derivation still matches them byte for byte.
/// Canonical digest of the golden mutation proposal.
const GOLDEN_PROPOSAL_DIGEST: &str =
    "b10314f979f937e394e30baae624e9de58b62c47b427be60e9957239a7e5f051";
/// Canonical digest of the golden evidence signed payload.
const GOLDEN_EVIDENCE_DIGEST: &str =
    "183d69f096c983c24bf479bb04898245eb893a230ca73c483f6386de830a6404";
/// Hex of the exact domain-separated signed message bytes
/// (`ASTRAL_CROSS_CITY_NODE_SIGNATURE_V1\0` + 32 raw digest bytes).
const GOLDEN_MESSAGE_HEX: &str = "41535452414c5f43524f53535f434954595f4e4f44455f5349474e41545552455f563100183d69f096c983c24bf479bb04898245eb893a230ca73c483f6386de830a6404";
/// Hex of the golden node's Ed25519 public key.
const GOLDEN_PUBLIC_KEY_HEX: &str =
    "e504869fc8ea879592397de29bda61e9621a69a3fdb5a2ae5f7bc9474d566b24";
/// Hex of the golden node's Ed25519 signature over the golden message.
const GOLDEN_SIGNATURE_HEX: &str = "5cec1473578236c15da8911b24e5de4c625ff7d1c21c487c92d8d201e3cac0c58848ba0449aebdc8bbd0d530ce1d42d0bb6f24775e341ea27f912e23e4f58700";

/// A 32-byte value that is NOT a decompressible Ed25519 public key encoding.
const NON_DECOMPRESSIBLE_PUBLIC_KEY: [u8; 32] = [0xDC; 32];

// ---------------------------------------------------------------------------
// Test doubles (test-only resolver and replay guard)
// ---------------------------------------------------------------------------

/// Shared call-order log: records which boundary components were invoked.
type EventLog = Rc<RefCell<Vec<&'static str>>>;

fn event_log() -> EventLog {
    Rc::new(RefCell::new(Vec::new()))
}

/// Resolver over a fixed in-test key registry, with call recording and an
/// optional forced failure.
struct FixedKeyResolver {
    records: HashMap<(String, String, u64), CrossCityNodeKeyRecord>,
    forced_error: Option<CrossCitySignatureError>,
    events: EventLog,
}

impl FixedKeyResolver {
    fn new(events: EventLog) -> Self {
        Self {
            records: HashMap::new(),
            forced_error: None,
            events,
        }
    }

    /// Register a record under its own exact identity.
    fn with_record(self, record: CrossCityNodeKeyRecord) -> Self {
        let key = (
            record.identity().city_id().to_owned(),
            record.identity().node_id().to_owned(),
            record.identity().node_epoch(),
        );
        self.with_record_under(key, record)
    }

    /// Register a record under an arbitrary lookup key (used to simulate a
    /// misbehaving resolver returning a mismatched identity).
    fn with_record_under(
        mut self,
        key: (String, String, u64),
        record: CrossCityNodeKeyRecord,
    ) -> Self {
        self.records.insert(key, record);
        self
    }
}

impl CrossCityNodeKeyResolver for FixedKeyResolver {
    fn resolve_node_key(
        &self,
        identity: &CrossCityNodeIdentity,
    ) -> Result<CrossCityNodeKeyRecord, CrossCitySignatureError> {
        self.events.borrow_mut().push("resolver");
        if let Some(forced) = &self.forced_error {
            return Err(*forced);
        }
        let key = (
            identity.city_id().to_owned(),
            identity.node_id().to_owned(),
            identity.node_epoch(),
        );
        self.records
            .get(&key)
            .cloned()
            .ok_or(CrossCitySignatureError::UnknownNodeKey)
    }
}

/// In-memory replay guard. This is TEST-ONLY proof: it is neither durable nor
/// shared across replicas and must never be presented as production replay
/// protection.
struct InMemoryReplayGuard {
    reserved: RefCell<HashSet<CrossCityEvidenceReplayKey>>,
    forced_error: Option<CrossCitySignatureError>,
    events: EventLog,
}

impl InMemoryReplayGuard {
    fn new(events: EventLog) -> Self {
        Self {
            reserved: RefCell::new(HashSet::new()),
            forced_error: None,
            events,
        }
    }

    fn with_forced_error(mut self, error: CrossCitySignatureError) -> Self {
        self.forced_error = Some(error);
        self
    }

    fn reserved_count(&self) -> usize {
        self.reserved.borrow().len()
    }

    fn contains(&self, key: &CrossCityEvidenceReplayKey) -> bool {
        self.reserved.borrow().contains(key)
    }
}

impl CrossCityReplayGuard for InMemoryReplayGuard {
    fn reserve(&self, key: &CrossCityEvidenceReplayKey) -> Result<(), CrossCitySignatureError> {
        self.events.borrow_mut().push("replay_guard");
        if let Some(forced) = &self.forced_error {
            return Err(*forced);
        }
        if !self.reserved.borrow_mut().insert(key.clone()) {
            return Err(CrossCitySignatureError::NonceReplay);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn decode_hex32(value: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(value, &mut out).ok()?;
    Some(out)
}

fn golden_signing_key() -> SigningKey {
    SigningKey::from_bytes(&GOLDEN_SEED)
}

fn golden_proposal() -> MutationProposal {
    MutationProposal::new(
        GOLDEN_OPERATION_ID,
        GOLDEN_SCOPE_DIGEST,
        GOLDEN_REQUEST_DIGEST,
        GOLDEN_MUTATION_DIGEST,
        GOLDEN_FRONTIER_DIGEST,
        3,
        1,
        4,
        2,
        GOLDEN_COMPILER_VERSION,
        GOLDEN_POLICY_VERSION,
        GOLDEN_EXPIRES_AT,
    )
    .expect("golden proposal is valid")
}

fn golden_proposal_digest() -> String {
    golden_proposal()
        .proposal_digest()
        .expect("golden proposal digest")
}

fn other_proposal_digest() -> String {
    MutationProposal::new(
        GOLDEN_OPERATION_ID,
        GOLDEN_SCOPE_DIGEST,
        GOLDEN_REQUEST_DIGEST,
        OTHER_MUTATION_DIGEST,
        GOLDEN_FRONTIER_DIGEST,
        3,
        1,
        4,
        2,
        GOLDEN_COMPILER_VERSION,
        GOLDEN_POLICY_VERSION,
        GOLDEN_EXPIRES_AT,
    )
    .expect("other proposal is valid")
    .proposal_digest()
    .expect("other proposal digest")
}

/// Build an evidence with a placeholder signature, compute the exact signed
/// message from its canonical digest, sign it with `seed`, and rebuild the
/// evidence with the real signature.
fn signed_evidence_with(
    seed: &[u8; 32],
    node_id: &str,
    decision: NodeDecision,
    proposal_digest_hex: &str,
    nonce: &str,
    expires_at: i64,
) -> ZeroDecisionEvidence {
    let signing = SigningKey::from_bytes(seed);
    let unsigned = ZeroDecisionEvidence::new(
        GOLDEN_CITY_ID,
        node_id,
        GOLDEN_NODE_EPOCH,
        decision,
        proposal_digest_hex,
        GOLDEN_FRONTIER_DIGEST,
        GOLDEN_MUTATION_DIGEST,
        nonce,
        expires_at,
        &"a".repeat(128),
    )
    .expect("unsigned evidence is valid");
    let message = cross_city_signature_message(&unsigned.evidence_digest)
        .expect("signed message from canonical digest");
    let signature = signing.sign(&message);
    ZeroDecisionEvidence::new(
        GOLDEN_CITY_ID,
        node_id,
        GOLDEN_NODE_EPOCH,
        decision,
        proposal_digest_hex,
        GOLDEN_FRONTIER_DIGEST,
        GOLDEN_MUTATION_DIGEST,
        nonce,
        expires_at,
        &hex::encode(signature.to_bytes()),
    )
    .expect("signed evidence is valid")
}

fn golden_signed_evidence(
    decision: NodeDecision,
    nonce: &str,
    expires_at: i64,
) -> ZeroDecisionEvidence {
    signed_evidence_with(
        &GOLDEN_SEED,
        GOLDEN_NODE_ID,
        decision,
        &golden_proposal_digest(),
        nonce,
        expires_at,
    )
}

fn record_for(seed: &[u8; 32], identity: CrossCityNodeIdentity) -> CrossCityNodeKeyRecord {
    let public_key_hex = hex::encode(SigningKey::from_bytes(seed).verifying_key().to_bytes());
    CrossCityNodeKeyRecord::from_public_key_hex(identity, &public_key_hex)
        .expect("test public key is canonical hex")
}

fn golden_identity() -> CrossCityNodeIdentity {
    CrossCityNodeIdentity::new(GOLDEN_CITY_ID, GOLDEN_NODE_ID, GOLDEN_NODE_EPOCH)
        .expect("golden identity is valid")
}

fn golden_resolver(events: EventLog) -> FixedKeyResolver {
    FixedKeyResolver::new(events).with_record(record_for(&GOLDEN_SEED, golden_identity()))
}

fn evidence_from_golden_with_signature(signature_hex: &str) -> ZeroDecisionEvidence {
    ZeroDecisionEvidence::new(
        GOLDEN_CITY_ID,
        GOLDEN_NODE_ID,
        GOLDEN_NODE_EPOCH,
        NodeDecision::Allow,
        &golden_proposal_digest(),
        GOLDEN_FRONTIER_DIGEST,
        GOLDEN_MUTATION_DIGEST,
        GOLDEN_NONCE,
        GOLDEN_EXPIRES_AT,
        signature_hex,
    )
    .expect("golden evidence is valid")
}

#[test]
fn public_identity_constructor_enforces_strict_identity_contract() {
    assert_eq!(
        CrossCityNodeIdentity::new(GOLDEN_CITY_ID, GOLDEN_NODE_ID, 0),
        Err(CrossCitySignatureError::ContractRejected)
    );

    for poisoned_city in ["city\u{200b}alpha", "city\u{202e}alpha"] {
        assert_eq!(
            CrossCityNodeIdentity::new(poisoned_city, GOLDEN_NODE_ID, GOLDEN_NODE_EPOCH),
            Err(CrossCitySignatureError::ContractRejected),
            "invisible format characters must be rejected from public identities"
        );
    }
}

#[test]
fn public_replay_key_constructor_requires_canonical_digest_and_epoch() {
    assert_eq!(
        CrossCityEvidenceReplayKey::new(
            GOLDEN_CITY_ID,
            GOLDEN_NODE_ID,
            0,
            GOLDEN_NONCE,
            GOLDEN_EVIDENCE_DIGEST,
        ),
        Err(CrossCitySignatureError::ContractRejected)
    );

    let bidi_digest = [GOLDEN_EVIDENCE_DIGEST, "\u{202e}"].concat();
    let invalid_digests = [
        String::new(),
        "0".repeat(63),
        GOLDEN_EVIDENCE_DIGEST.to_uppercase(),
        format!(" {GOLDEN_EVIDENCE_DIGEST}"),
        bidi_digest,
    ];
    for digest in invalid_digests {
        assert_eq!(
            CrossCityEvidenceReplayKey::new(
                GOLDEN_CITY_ID,
                GOLDEN_NODE_ID,
                GOLDEN_NODE_EPOCH,
                GOLDEN_NONCE,
                &digest,
            ),
            Err(CrossCitySignatureError::ContractRejected),
            "non-canonical replay digest must be rejected: {digest:?}"
        );
    }

    assert!(CrossCityEvidenceReplayKey::new(
        GOLDEN_CITY_ID,
        GOLDEN_NODE_ID,
        GOLDEN_NODE_EPOCH,
        GOLDEN_NONCE,
        GOLDEN_EVIDENCE_DIGEST,
    )
    .is_ok());
}

// ---------------------------------------------------------------------------
// RFC 8032 known-answer test (low-level Ed25519, no cross-city framing)
// ---------------------------------------------------------------------------

#[test]
fn rfc8032_test1_known_answer_vector_verifies_strictly() {
    let seed = decode_hex32(RFC8032_TEST1_SEED_HEX).expect("RFC 8032 seed decodes");
    let signing = SigningKey::from_bytes(&seed);
    assert_eq!(
        hex::encode(signing.verifying_key().to_bytes()),
        RFC8032_TEST1_PUBLIC_KEY_HEX
    );
    let signature = signing.sign(b"");
    assert_eq!(
        hex::encode(signature.to_bytes()),
        RFC8032_TEST1_SIGNATURE_HEX
    );

    let public_key = decode_hex32(RFC8032_TEST1_PUBLIC_KEY_HEX).expect("RFC 8032 key decodes");
    let verifying = VerifyingKey::from_bytes(&public_key).expect("RFC 8032 public key is valid");
    verifying
        .verify_strict(b"", &signature)
        .expect("RFC 8032 TEST 1 must verify with strict verification");
    verifying
        .verify_strict(b"tampered", &signature)
        .expect_err("a tampered message must not verify");
}

// ---------------------------------------------------------------------------
// Golden vector
// ---------------------------------------------------------------------------

#[test]
fn golden_cross_city_allow_vector_pins_exact_bytes() {
    // The pinned proposal digest still matches the live canonical derivation.
    assert_eq!(golden_proposal_digest(), GOLDEN_PROPOSAL_DIGEST);

    let evidence = evidence_from_golden_with_signature(GOLDEN_SIGNATURE_HEX);
    assert_eq!(evidence.evidence_digest, GOLDEN_EVIDENCE_DIGEST);
    assert_eq!(
        hex::encode(golden_signing_key().verifying_key().to_bytes()),
        GOLDEN_PUBLIC_KEY_HEX
    );

    // The exact signed bytes: domain prefix + 32 raw digest bytes.
    let message =
        cross_city_signature_message(&evidence.evidence_digest).expect("golden digest decodes");
    assert_eq!(message.len(), CROSS_CITY_SIGNATURE_MESSAGE_LEN);
    assert_eq!(hex::encode(message), GOLDEN_MESSAGE_HEX);
    assert_eq!(
        &message[..CROSS_CITY_NODE_SIGNATURE_DOMAIN_PREFIX.len()],
        CROSS_CITY_NODE_SIGNATURE_DOMAIN_PREFIX
    );

    let events = event_log();
    let resolver = golden_resolver(events.clone());
    let guard = InMemoryReplayGuard::new(events.clone());
    let verified =
        verify_zero_decision_evidence(&evidence, GOLDEN_EXPIRES_AT - 1, &resolver, &guard)
            .expect("the pinned golden vector must verify");
    assert_eq!(verified.signer_identity().city_id(), GOLDEN_CITY_ID);
    assert_eq!(verified.signer_identity().node_id(), GOLDEN_NODE_ID);
    assert_eq!(verified.signer_identity().node_epoch(), GOLDEN_NODE_EPOCH);
    assert_eq!(verified.verified_at_seconds(), GOLDEN_EXPIRES_AT - 1);
    assert_eq!(verified.evidence(), &evidence);
    assert_eq!(verified.replay_key().nonce(), GOLDEN_NONCE);
    assert_eq!(
        verified.replay_key().evidence_digest(),
        GOLDEN_EVIDENCE_DIGEST
    );
    assert_eq!(events.borrow().as_slice(), &["resolver", "replay_guard"]);
    assert_eq!(guard.reserved_count(), 1);
}

// ---------------------------------------------------------------------------
// Valid ALLOW and DENY
// ---------------------------------------------------------------------------

#[test]
fn valid_allow_and_valid_deny_evidence_both_verify() {
    let events = event_log();
    let resolver = golden_resolver(events.clone());
    let guard = InMemoryReplayGuard::new(events.clone());
    let now = GOLDEN_EXPIRES_AT - 1;

    let allow = golden_signed_evidence(NodeDecision::Allow, "nonce-allow-1", now + 10);
    let verified_allow =
        verify_zero_decision_evidence(&allow, now, &resolver, &guard).expect("ALLOW verifies");
    assert_eq!(verified_allow.evidence().decision, NodeDecision::Allow);

    let deny = golden_signed_evidence(NodeDecision::Deny, "nonce-deny-1", now + 10);
    let verified_deny =
        verify_zero_decision_evidence(&deny, now, &resolver, &guard).expect("DENY verifies");
    assert_eq!(verified_deny.evidence().decision, NodeDecision::Deny);

    assert_eq!(guard.reserved_count(), 2);
}

// ---------------------------------------------------------------------------
// Ordering: verification strictly precedes replay reservation
// ---------------------------------------------------------------------------

#[test]
fn verification_precedes_replay_reservation_on_success() {
    // Evidence expires at GOLDEN_EXPIRES_AT - 10 (exclusive); any earlier
    // instant is a valid evaluation time.
    let evidence =
        golden_signed_evidence(NodeDecision::Allow, "nonce-order-1", GOLDEN_EXPIRES_AT - 10);
    let events = event_log();
    let resolver = golden_resolver(events.clone());
    let guard = InMemoryReplayGuard::new(events.clone());

    verify_zero_decision_evidence(&evidence, GOLDEN_EXPIRES_AT - 11, &resolver, &guard)
        .expect("valid evidence verifies");
    assert_eq!(
        events.borrow().as_slice(),
        &["resolver", "replay_guard"],
        "the replay guard may only run after resolver + strict verification"
    );
}

#[test]
fn contract_rejection_short_circuits_before_resolver_and_guard() {
    // Tampering with any signed field breaks the recomputed digest: rejected
    // by contract validation alone.
    let mut evidence =
        golden_signed_evidence(NodeDecision::Allow, "nonce-order-2", GOLDEN_EXPIRES_AT - 10);
    evidence.nonce = "nonce-tampered".to_owned();

    let events = event_log();
    let resolver = golden_resolver(events.clone());
    let guard = InMemoryReplayGuard::new(events.clone());

    let error = verify_zero_decision_evidence(&evidence, GOLDEN_EXPIRES_AT - 1, &resolver, &guard)
        .unwrap_err();
    assert_eq!(error, CrossCitySignatureError::ContractRejected);
    assert!(
        events.borrow().is_empty(),
        "no resolver or guard call may happen for contract-rejected evidence"
    );
}

#[test]
fn padded_signature_rejected_as_non_canonical_before_resolver_and_guard() {
    // The signature is not part of the signed digest, so padded signatures
    // pass `validate_at` - these inputs specifically exercise the strict
    // canonical-form equality gate (which runs before any decode, resolver, or
    // guard call).
    let padded_variants = [
        format!(" {} ", GOLDEN_SIGNATURE_HEX),
        format!(" {}", GOLDEN_SIGNATURE_HEX),
        format!("{}\n", GOLDEN_SIGNATURE_HEX),
    ];
    let events = event_log();
    for padded in padded_variants {
        let mut evidence = evidence_from_golden_with_signature(GOLDEN_SIGNATURE_HEX);
        evidence.signature = padded;
        evidence
            .validate_at(GOLDEN_EXPIRES_AT - 1)
            .expect("padded evidence still passes contract validation");

        let resolver = golden_resolver(events.clone());
        let guard = InMemoryReplayGuard::new(events.clone());
        let error =
            verify_zero_decision_evidence(&evidence, GOLDEN_EXPIRES_AT - 1, &resolver, &guard)
                .unwrap_err();
        assert_eq!(error, CrossCitySignatureError::ContractRejected);
    }
    assert!(events.borrow().is_empty());
}

#[test]
fn non_canonical_digest_shapes_rejected_before_resolver_and_guard() {
    // Uppercase digest: not the canonical lowercase form.
    let mut uppercase = evidence_from_golden_with_signature(GOLDEN_SIGNATURE_HEX);
    uppercase.evidence_digest = GOLDEN_EVIDENCE_DIGEST.to_uppercase();

    // Altered (but well-formed) digest: no longer matches the signed payload.
    let mut altered = evidence_from_golden_with_signature(GOLDEN_SIGNATURE_HEX);
    altered.evidence_digest = "0".repeat(64);

    let events = event_log();
    for evidence in [uppercase, altered] {
        let resolver = golden_resolver(events.clone());
        let guard = InMemoryReplayGuard::new(events.clone());
        let error =
            verify_zero_decision_evidence(&evidence, GOLDEN_EXPIRES_AT - 1, &resolver, &guard)
                .unwrap_err();
        assert_eq!(error, CrossCitySignatureError::ContractRejected);
    }
    assert!(events.borrow().is_empty());
}

// ---------------------------------------------------------------------------
// Malformed signature encodings
// ---------------------------------------------------------------------------

#[test]
fn malformed_signature_shapes_rejected_before_resolver_and_guard() {
    // NOTE: an empty signature is rejected even earlier, by contract
    // validation (normalize rejects empty fields), and is therefore covered by
    // the contract-rejection tests rather than the decode layer. Whitespace
    // around or inside the signature is likewise caught by contract/canonical
    // validation first; see the padded-signature test below.
    let cases = vec![
        "uppercase hex".to_string(),
        GOLDEN_SIGNATURE_HEX.to_uppercase(),
        "base64 padding characters".to_string(),
        format!("{}+/==", &GOLDEN_SIGNATURE_HEX[..124]),
        "one byte short".to_string(),
        GOLDEN_SIGNATURE_HEX[..127].to_string(),
        "one byte long".to_string(),
        format!("{}a", GOLDEN_SIGNATURE_HEX),
        "non-hex characters".to_string(),
        format!(
            "{}zz{}",
            &GOLDEN_SIGNATURE_HEX[..63],
            &GOLDEN_SIGNATURE_HEX[65..]
        ),
    ];

    let events = event_log();
    for chunk in cases.chunks(2) {
        let mut evidence = evidence_from_golden_with_signature(GOLDEN_SIGNATURE_HEX);
        evidence.signature = chunk[1].clone();
        let resolver = golden_resolver(events.clone());
        let guard = InMemoryReplayGuard::new(events.clone());
        let error =
            verify_zero_decision_evidence(&evidence, GOLDEN_EXPIRES_AT - 1, &resolver, &guard)
                .unwrap_err();
        assert_eq!(
            error,
            CrossCitySignatureError::MalformedSignature,
            "case {:?} must be a malformed signature",
            chunk[0]
        );
    }
    assert!(
        events.borrow().is_empty(),
        "undecodable signatures must never reach the resolver or guard"
    );
}

// ---------------------------------------------------------------------------
// Key resolution failures
// ---------------------------------------------------------------------------

#[test]
fn unknown_node_key_fails_closed_before_replay_guard() {
    let evidence = evidence_from_golden_with_signature(GOLDEN_SIGNATURE_HEX);
    let events = event_log();
    let resolver = FixedKeyResolver::new(events.clone());
    let guard = InMemoryReplayGuard::new(events.clone());

    let error = verify_zero_decision_evidence(&evidence, GOLDEN_EXPIRES_AT - 1, &resolver, &guard)
        .unwrap_err();
    assert_eq!(error, CrossCitySignatureError::UnknownNodeKey);
    assert_eq!(events.borrow().as_slice(), &["resolver"]);
    assert_eq!(guard.reserved_count(), 0);
}

#[test]
fn wrong_city_node_or_epoch_key_is_unknown() {
    let evidence = evidence_from_golden_with_signature(GOLDEN_SIGNATURE_HEX);
    let events = event_log();
    // Keys exist, but only for a different epoch, a different node, and a
    // different city: the exact identity lookup must miss every time.
    let resolver = FixedKeyResolver::new(events.clone())
        .with_record(record_for(
            &GOLDEN_SEED,
            CrossCityNodeIdentity::new(GOLDEN_CITY_ID, GOLDEN_NODE_ID, GOLDEN_NODE_EPOCH + 1)
                .expect("identity"),
        ))
        .with_record(record_for(
            &GOLDEN_SEED,
            CrossCityNodeIdentity::new(GOLDEN_CITY_ID, "node-other", GOLDEN_NODE_EPOCH)
                .expect("identity"),
        ))
        .with_record(record_for(
            &GOLDEN_SEED,
            CrossCityNodeIdentity::new("city-other", GOLDEN_NODE_ID, GOLDEN_NODE_EPOCH)
                .expect("identity"),
        ));
    let guard = InMemoryReplayGuard::new(events.clone());

    let error = verify_zero_decision_evidence(&evidence, GOLDEN_EXPIRES_AT - 1, &resolver, &guard)
        .unwrap_err();
    assert_eq!(error, CrossCitySignatureError::UnknownNodeKey);
    assert_eq!(guard.reserved_count(), 0);
}

#[test]
fn mismatched_node_key_record_fails_closed() {
    let evidence = evidence_from_golden_with_signature(GOLDEN_SIGNATURE_HEX);
    let events = event_log();
    // Simulate a misbehaving resolver: the golden identity lookup returns a
    // record bound to a different identity. The verifier must re-check and
    // fail closed.
    let wrong_identity = CrossCityNodeIdentity::new("city-beta", "node-02", 9).expect("identity");
    let resolver = FixedKeyResolver::new(events.clone()).with_record_under(
        (
            GOLDEN_CITY_ID.to_owned(),
            GOLDEN_NODE_ID.to_owned(),
            GOLDEN_NODE_EPOCH,
        ),
        record_for(&GOLDEN_SEED, wrong_identity),
    );
    let guard = InMemoryReplayGuard::new(events.clone());

    let error = verify_zero_decision_evidence(&evidence, GOLDEN_EXPIRES_AT - 1, &resolver, &guard)
        .unwrap_err();
    assert_eq!(error, CrossCitySignatureError::NodeKeyMismatch);
    assert_eq!(events.borrow().as_slice(), &["resolver"]);
    assert_eq!(guard.reserved_count(), 0);
}

#[test]
fn malformed_public_key_fails_closed() {
    let evidence = evidence_from_golden_with_signature(GOLDEN_SIGNATURE_HEX);
    let events = event_log();
    let resolver = FixedKeyResolver::new(events.clone()).with_record(CrossCityNodeKeyRecord::new(
        golden_identity(),
        NON_DECOMPRESSIBLE_PUBLIC_KEY,
    ));
    let guard = InMemoryReplayGuard::new(events.clone());

    let error = verify_zero_decision_evidence(&evidence, GOLDEN_EXPIRES_AT - 1, &resolver, &guard)
        .unwrap_err();
    assert_eq!(error, CrossCitySignatureError::MalformedPublicKey);
    assert_eq!(guard.reserved_count(), 0);
}

// ---------------------------------------------------------------------------
// Signature verification failures
// ---------------------------------------------------------------------------

#[test]
fn wrong_signing_key_produces_invalid_signature_without_reservation() {
    let evidence = evidence_from_golden_with_signature(GOLDEN_SIGNATURE_HEX);
    let events = event_log();
    // The registered key exists for the exact identity, but belongs to a
    // different node key pair than the one that signed the evidence.
    let resolver = FixedKeyResolver::new(events.clone())
        .with_record(record_for(&SECOND_SEED, golden_identity()));
    let guard = InMemoryReplayGuard::new(events.clone());

    let error = verify_zero_decision_evidence(&evidence, GOLDEN_EXPIRES_AT - 1, &resolver, &guard)
        .unwrap_err();
    assert_eq!(error, CrossCitySignatureError::InvalidSignature);
    assert_eq!(events.borrow().as_slice(), &["resolver"]);
    assert_eq!(guard.reserved_count(), 0);
}

#[test]
fn altered_signature_fails_verification_without_reservation() {
    // Flip one hex character while staying within the canonical lowercase
    // alphabet: decoding succeeds, strict verification must fail.
    let last_character = &GOLDEN_SIGNATURE_HEX[GOLDEN_SIGNATURE_HEX.len() - 1..];
    let replacement = if last_character == "0" { "1" } else { "0" };
    let tampered = format!(
        "{}{}",
        &GOLDEN_SIGNATURE_HEX[..GOLDEN_SIGNATURE_HEX.len() - 1],
        replacement
    );
    assert_ne!(tampered, GOLDEN_SIGNATURE_HEX);
    let evidence = evidence_from_golden_with_signature(&tampered);

    let events = event_log();
    let resolver = golden_resolver(events.clone());
    let guard = InMemoryReplayGuard::new(events.clone());

    let error = verify_zero_decision_evidence(&evidence, GOLDEN_EXPIRES_AT - 1, &resolver, &guard)
        .unwrap_err();
    assert_eq!(error, CrossCitySignatureError::InvalidSignature);
    assert_eq!(events.borrow().as_slice(), &["resolver"]);
    assert_eq!(guard.reserved_count(), 0);
}

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

#[test]
fn expired_evidence_rejected_fail_closed() {
    let evidence = golden_signed_evidence(NodeDecision::Allow, "nonce-exp-1", 1_000_000);
    let events = event_log();
    let resolver = golden_resolver(events.clone());
    let guard = InMemoryReplayGuard::new(events.clone());

    let error = verify_zero_decision_evidence(&evidence, 1_000_001, &resolver, &guard).unwrap_err();
    assert_eq!(
        error,
        CrossCitySignatureError::ExpiredEvidence {
            now_seconds: 1_000_001,
            expires_at: 1_000_000,
        }
    );
    assert_eq!(guard.reserved_count(), 0);
}

#[test]
fn exact_expiry_boundary_now_equals_expires_at_rejects() {
    let evidence = golden_signed_evidence(NodeDecision::Allow, "nonce-exp-2", 1_000_000);
    let events = event_log();
    let resolver = golden_resolver(events.clone());
    let guard = InMemoryReplayGuard::new(events.clone());

    // `expires_at` is an exclusive upper bound: now == expires_at is expired.
    let error = verify_zero_decision_evidence(&evidence, 1_000_000, &resolver, &guard).unwrap_err();
    assert_eq!(
        error,
        CrossCitySignatureError::ExpiredEvidence {
            now_seconds: 1_000_000,
            expires_at: 1_000_000,
        }
    );
    // One second earlier the same evidence verifies.
    verify_zero_decision_evidence(&evidence, 999_999, &resolver, &guard)
        .expect("now < expires_at must verify");
}

// ---------------------------------------------------------------------------
// Replay semantics
// ---------------------------------------------------------------------------

#[test]
fn duplicate_nonce_reservation_returns_typed_nonce_replay() {
    let evidence = golden_signed_evidence(
        NodeDecision::Allow,
        "nonce-replay-1",
        GOLDEN_EXPIRES_AT - 10,
    );
    let events = event_log();
    let resolver = golden_resolver(events.clone());
    let guard = InMemoryReplayGuard::new(events.clone());
    let now = GOLDEN_EXPIRES_AT - 11;

    let first = verify_zero_decision_evidence(&evidence, now, &resolver, &guard)
        .expect("first reservation succeeds");
    let second = verify_zero_decision_evidence(&evidence, now, &resolver, &guard).unwrap_err();
    assert_eq!(second, CrossCitySignatureError::NonceReplay);
    // The second attempt re-ran full verification (resolver + guard) and was
    // only rejected by the guard's duplicate detection.
    assert_eq!(
        events.borrow().as_slice(),
        &["resolver", "replay_guard", "resolver", "replay_guard"]
    );
    assert_eq!(guard.reserved_count(), 1);
    assert!(guard.contains(first.replay_key()));
}

#[test]
fn replay_guard_failure_fails_closed_even_with_valid_signature() {
    let evidence =
        golden_signed_evidence(NodeDecision::Allow, "nonce-guard-1", GOLDEN_EXPIRES_AT - 10);
    let events = event_log();
    let resolver = golden_resolver(events.clone());
    let guard = InMemoryReplayGuard::new(events.clone())
        .with_forced_error(CrossCitySignatureError::ReplayGuardUnavailable);

    let error = verify_zero_decision_evidence(&evidence, GOLDEN_EXPIRES_AT - 11, &resolver, &guard)
        .unwrap_err();
    assert_eq!(error, CrossCitySignatureError::ReplayGuardUnavailable);
    assert_eq!(guard.reserved_count(), 0);
}

#[test]
fn replay_guard_error_other_than_replay_is_coalesced_fail_closed() {
    let evidence =
        golden_signed_evidence(NodeDecision::Allow, "nonce-guard-2", GOLDEN_EXPIRES_AT - 10);
    let events = event_log();
    let resolver = golden_resolver(events.clone());
    // A guard that fails for any other reason (here: an unknown-key code) is
    // still coalesced into the distinct fail-closed guard error, never into a
    // pass-through and never into a success.
    let guard = InMemoryReplayGuard::new(events.clone())
        .with_forced_error(CrossCitySignatureError::UnknownNodeKey);

    let error = verify_zero_decision_evidence(&evidence, GOLDEN_EXPIRES_AT - 11, &resolver, &guard)
        .unwrap_err();
    assert_eq!(error, CrossCitySignatureError::ReplayGuardUnavailable);
}

#[test]
fn same_nonce_under_different_signer_identity_is_distinct() {
    let events = event_log();
    let resolver = FixedKeyResolver::new(events.clone())
        .with_record(record_for(&GOLDEN_SEED, golden_identity()))
        .with_record(record_for(
            &SECOND_SEED,
            CrossCityNodeIdentity::new(GOLDEN_CITY_ID, "node-02", GOLDEN_NODE_EPOCH)
                .expect("identity"),
        ));
    let guard = InMemoryReplayGuard::new(events.clone());
    let now = GOLDEN_EXPIRES_AT - 1;

    let first = signed_evidence_with(
        &GOLDEN_SEED,
        GOLDEN_NODE_ID,
        NodeDecision::Allow,
        &golden_proposal_digest(),
        "nonce-shared-1",
        now + 10,
    );
    let second = signed_evidence_with(
        &SECOND_SEED,
        "node-02",
        NodeDecision::Allow,
        &golden_proposal_digest(),
        "nonce-shared-1",
        now + 10,
    );

    let verified_first =
        verify_zero_decision_evidence(&first, now, &resolver, &guard).expect("first verifies");
    let verified_second =
        verify_zero_decision_evidence(&second, now, &resolver, &guard).expect("second verifies");
    // Same nonce, different signer identity: two distinct replay keys, both
    // reserved.
    assert_ne!(verified_first.replay_key(), verified_second.replay_key());
    assert_eq!(verified_first.replay_key().nonce(), "nonce-shared-1");
    assert_eq!(verified_second.replay_key().nonce(), "nonce-shared-1");
    assert_ne!(
        verified_first.replay_key().node_id(),
        verified_second.replay_key().node_id()
    );
    assert_eq!(guard.reserved_count(), 2);
}

#[test]
fn replay_key_binds_operation_and_proposal_through_signed_digest() {
    let events = event_log();
    let resolver = golden_resolver(events.clone());
    let guard = InMemoryReplayGuard::new(events.clone());
    let now = GOLDEN_EXPIRES_AT - 1;

    let on_golden_proposal = golden_signed_evidence(NodeDecision::Allow, "nonce-bind-1", now + 10);
    let on_other_proposal = signed_evidence_with(
        &GOLDEN_SEED,
        GOLDEN_NODE_ID,
        NodeDecision::Allow,
        &other_proposal_digest(),
        "nonce-bind-1",
        now + 10,
    );
    // The two proposals produce different signed digests: the same nonce under
    // the same identity is bound to one exact proposal context.
    assert_ne!(
        on_golden_proposal.evidence_digest,
        on_other_proposal.evidence_digest
    );

    let verified_golden =
        verify_zero_decision_evidence(&on_golden_proposal, now, &resolver, &guard)
            .expect("evidence over the golden proposal verifies");
    let verified_other = verify_zero_decision_evidence(&on_other_proposal, now, &resolver, &guard)
        .expect("evidence over the other proposal verifies");

    assert_ne!(verified_golden.replay_key(), verified_other.replay_key());
    assert_ne!(
        verified_golden.replay_key().evidence_digest(),
        verified_other.replay_key().evidence_digest()
    );
    assert_eq!(verified_golden.replay_key().nonce(), "nonce-bind-1");
    assert_eq!(verified_other.replay_key().nonce(), "nonce-bind-1");
    assert_eq!(guard.reserved_count(), 2);

    // The replay key structure itself is pinned: exact signer identity +
    // nonce + signed evidence digest.
    let expected = CrossCityEvidenceReplayKey::new(
        GOLDEN_CITY_ID,
        GOLDEN_NODE_ID,
        GOLDEN_NODE_EPOCH,
        "nonce-bind-1",
        &on_golden_proposal.evidence_digest,
    )
    .expect("expected replay key is valid");
    assert_eq!(verified_golden.replay_key(), &expected);
}

// ---------------------------------------------------------------------------
// Secret-free, bounded diagnostics; stable error codes
// ---------------------------------------------------------------------------

#[test]
fn debug_and_error_output_leak_no_signature_or_seed_material() {
    let evidence = evidence_from_golden_with_signature(GOLDEN_SIGNATURE_HEX);
    let events = event_log();
    let resolver = golden_resolver(events.clone());
    let guard = InMemoryReplayGuard::new(events);
    let verified =
        verify_zero_decision_evidence(&evidence, GOLDEN_EXPIRES_AT - 1, &resolver, &guard)
            .expect("golden verifies");

    let seed_hex = hex::encode(GOLDEN_SEED);
    let secrets = [
        GOLDEN_SIGNATURE_HEX,
        GOLDEN_PUBLIC_KEY_HEX,
        seed_hex.as_str(),
        "astral-cross-city-signature-seed",
    ];

    let wrapper_debug = format!("{:?}", verified);
    for secret in secrets {
        assert!(
            !wrapper_debug.contains(secret),
            "wrapper debug must not leak signature, key, or seed material"
        );
    }
    // Bounded debug: no long signature run may appear anywhere.
    assert!(!wrapper_debug.contains(&GOLDEN_SIGNATURE_HEX[..64]));

    let replay_debug = format!("{:?}", verified.replay_key());
    for secret in secrets {
        assert!(!replay_debug.contains(secret));
    }

    let record_debug = format!("{:?}", record_for(&GOLDEN_SEED, golden_identity()));
    for secret in secrets {
        assert!(!record_debug.contains(secret));
    }

    let all_errors = [
        CrossCitySignatureError::ContractRejected,
        CrossCitySignatureError::ExpiredEvidence {
            now_seconds: 1,
            expires_at: 2,
        },
        CrossCitySignatureError::MalformedSignature,
        CrossCitySignatureError::MalformedPublicKey,
        CrossCitySignatureError::InvalidSignature,
        CrossCitySignatureError::UnknownNodeKey,
        CrossCitySignatureError::NodeKeyMismatch,
        CrossCitySignatureError::NonceReplay,
        CrossCitySignatureError::ReplayGuardUnavailable,
    ];
    for error in all_errors {
        let rendered = format!("{:?} | {}", error, error);
        for secret in secrets {
            assert!(
                !rendered.contains(secret),
                "error output must not leak signature, key, or seed material"
            );
        }
    }
}

#[test]
fn error_codes_are_stable_and_distinct() {
    let codes = [
        CrossCitySignatureError::ContractRejected.code(),
        CrossCitySignatureError::ExpiredEvidence {
            now_seconds: 1,
            expires_at: 2,
        }
        .code(),
        CrossCitySignatureError::MalformedSignature.code(),
        CrossCitySignatureError::MalformedPublicKey.code(),
        CrossCitySignatureError::InvalidSignature.code(),
        CrossCitySignatureError::UnknownNodeKey.code(),
        CrossCitySignatureError::NodeKeyMismatch.code(),
        CrossCitySignatureError::NonceReplay.code(),
        CrossCitySignatureError::ReplayGuardUnavailable.code(),
    ];
    let mut seen = HashSet::new();
    for code in codes {
        assert!(code.starts_with("CROSS_CITY_"), "unstable code {}", code);
        assert!(seen.insert(code), "duplicated error code {}", code);
    }
}

// ---------------------------------------------------------------------------
// Source-shape pins
// ---------------------------------------------------------------------------

#[test]
fn source_shape_domain_prefix_and_strict_verification_pinned() {
    // The domain-separated prefix with its NUL terminator is pinned verbatim.
    assert!(MODULE_SOURCE.contains(r#"b"ASTRAL_CROSS_CITY_NODE_SIGNATURE_V1\0""#));
    // Only strict verification may be used.
    assert!(MODULE_SOURCE.contains("verify_strict("));
    assert!(!MODULE_SOURCE.contains(".verify("));
    // Exact 128-lowercase-hex signature encoding is pinned by the constants.
    assert!(MODULE_SOURCE.contains("ED25519_SIGNATURE_HEX_LEN: usize = 128"));
}

#[test]
fn source_shape_verification_precedes_replay_reservation_in_source() {
    let verification_position = MODULE_SOURCE
        .find("verify_strict(")
        .expect("strict verification call exists");
    let reservation_position = MODULE_SOURCE
        .find(".reserve(")
        .expect("replay reservation call exists");
    assert!(
        verification_position < reservation_position,
        "the source must verify signatures before reserving nonces"
    );
}

#[test]
fn source_shape_wrapper_constructor_and_fields_are_private() {
    let struct_start = MODULE_SOURCE
        .find("pub struct CrossCityVerifiedEvidence {")
        .expect("wrapper struct exists");
    let struct_end = struct_start
        + MODULE_SOURCE[struct_start..]
            .find("\n}")
            .expect("wrapper struct ends");
    let struct_block = &MODULE_SOURCE[struct_start..struct_end];
    assert!(
        !struct_block.contains("\n    pub "),
        "no wrapper field may be public"
    );

    let impl_start = MODULE_SOURCE
        .find("impl CrossCityVerifiedEvidence {")
        .expect("wrapper inherent impl exists");
    let impl_end = impl_start
        + MODULE_SOURCE[impl_start..]
            .find("\n}\n")
            .expect("wrapper inherent impl ends");
    let impl_block = &MODULE_SOURCE[impl_start..impl_end];
    assert!(impl_block.contains("    fn new("), "the constructor exists");
    assert!(
        !impl_block.contains("pub fn new") && !impl_block.contains("pub const fn new"),
        "the wrapper constructor must stay private"
    );
    assert!(
        !impl_block.contains("pub fn from"),
        "no public conversion constructor may exist"
    );
}

#[test]
fn source_shape_no_runtime_caller_inside_astral_common() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let source_root = std::path::Path::new(&manifest_dir).join("src");
    let module_directory = source_root.join("cross_city_signature");
    let mut stack = vec![source_root.clone()];
    let mut offenders = Vec::new();
    while let Some(directory) = stack.pop() {
        let entries = std::fs::read_dir(&directory).expect("source directory is readable");
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let file_name = path
                .file_name()
                .map(|name| name.to_string_lossy().to_string())
                .unwrap_or_default();
            // lib.rs holds the re-export; the module file and the module test
            // directory are the boundary itself. Any OTHER reference would be
            // a runtime caller, which is forbidden in this batch.
            if file_name == "lib.rs"
                || file_name == "cross_city_signature.rs"
                || path == module_directory
            {
                continue;
            }
            if path.starts_with(&module_directory) {
                continue;
            }
            let content = std::fs::read_to_string(&path).unwrap_or_default();
            if content.contains("cross_city_signature") {
                offenders.push(path.display().to_string());
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "unexpected cross_city_signature references (no runtime caller allowed): {:?}",
        offenders
    );
}

#[test]
fn source_shape_no_network_db_or_cache_primitives() {
    let banned = [
        "reqwest",
        "sqlx",
        "redis",
        "moka",
        "lapin",
        "TcpStream",
        "UdpSocket",
        "std::net",
        "tokio::",
        "mysql",
    ];
    for primitive in banned {
        assert!(
            !MODULE_SOURCE.contains(primitive),
            "the verifier module must stay pure; found banned primitive {:?}",
            primitive
        );
    }
}

#[test]
fn source_shape_lib_rs_only_declares_and_reexports_module() {
    const LIB_SOURCE: &str = include_str!("../lib.rs");
    assert!(LIB_SOURCE.contains("pub mod cross_city_signature;"));
    assert!(LIB_SOURCE.contains("pub use cross_city_signature::"));
}
