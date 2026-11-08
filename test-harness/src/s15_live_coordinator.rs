//! S15 live coordinator: bounded, read-only readiness/identity evidence over
//! the frozen TrustGraph test-control plane (`astral-trustgraph/src/api/
//! test_control.rs`), scoped to the CURRENT V6 four-server/two-half topology.
//!
//! # Scope boundary (read this before extending)
//!
//! - The offline S15 requirements/coverage contract stays in
//!   [`crate::s15_validation`]; offline and live statuses are strictly
//!   separate. This module never upgrades offline contract results and never
//!   reports the S15 live gate by itself: [`s15_live_gate_verdict`] keeps the
//!   overall gate `BLOCKED`/`UNKNOWN` unless EVERY requirement in
//!   [`CURRENT_S15_LIVE_REQUIREMENTS`] is backed by real raw evidence —
//!   deployment attestation booleans only declare environment prerequisites
//!   and are not an input to this verdict. Four successful probes yield at
//!   most the probe/identity `PASS` recorded via [`PROBE_EVIDENCE_REQUIREMENTS`].
//! - The only requestable endpoints are the frozen read-only worker identity
//!   probe and the production-owned, normal-authenticated exact-scope
//!   `/authorization-observations/s15` GET. Business authorization, source
//!   mutation, pump, probe-evaluate, and fault-injection control-plane
//!   capabilities are unreachable here; live fault injection is Exec-L3, see
//!   `e4_fault_driver_contract::LIVE_INTEGRATION_REASON`.
//! - No sockets: this crate opens no network, process or filesystem resources
//!   by design. Real I/O is supplied by the executor through the
//!   [`ProbeTransport`] port (same injected-port architecture as
//!   `node_adapter_native`). Without a transport the attempt surfaces
//!   `UNKNOWN`/`BLOCKED`, never `PASS`.
//! - Fail-closed identity: a probe response whose `nodeId` does not exactly
//!   equal the allowlisted node under test is recorded as an evidence
//!   violation and can never produce `PASS`.
//! - Finite budgets: per-attempt timeout and per-node attempt count are
//!   capped ([`MAX_PROBE_TIMEOUT_MS`], [`MAX_PROBE_ATTEMPTS_PER_NODE`]).
//!   Retries are GET-only (no durable side effects) and stop early on
//!   deterministic 4xx/parse/identity outcomes. Budget-exhausted outcomes
//!   stay `UNKNOWN`; callers must reconcile before any new attempt — this
//!   module never auto-replays UNKNOWN results.
//! - Secrets: the test-control token and the gateway signing key are held in
//!   redacted wrappers ([`S15Secret`], manual `Debug`), never logged, never
//!   serialized into evidence records. Evidence keeps the raw response body
//!   verbatim as the raw artifact; durable persistence of those records is
//!   the executor's responsibility.
//!
//! # Known shared-API gaps (reported, not worked around silently)
//!
//! 1. `node_adapter_contract::build_signed_request` cannot carry
//!    `X-Test-Control-Token` and is locked to the retired three-node
//!    `NODE_ALIASES` topology. This module composes the public `sign_headers`
//!    primitive directly for AL1–AL4 and does not widen the shared API.
//! 2. The observation route does not supply deployment approval, fault
//!    control, transport selection, half ownership, cross-tenant negative
//!    proof, or authority quorum evidence; those requirements stay unresolved.
//!    The separate authority mTLS client can observe a global frontier but not
//!    the S15 per-half ownership/fence or stale-writer scenario.
//! 3. A real transport ships only in the executor layer
//!    (`s15_probe_executor::TlsProbeTransport`, composed by the
//!    `s15-probe` CLI); the coordinator itself stays transport-agnostic and
//!    the crate still opens no sockets outside that executor boundary.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

use crate::node_adapter_contract::{sign_headers, Actor};
use crate::readiness_contract::{validate_campaign_id, ReadinessStatus};
use crate::s15_validation::{S15Half, CURRENT_S15_LIVE_REQUIREMENTS, S15_NODE_PLACEMENTS};

/// Frozen read-only test-control probe path (nest segment under
/// `/main/api/v1`; source of truth:
/// `astral-trustgraph/src/api/test_control.rs::TEST_CONTROL_ROUTE`).
pub const S15_PROBE_PATH: &str = "/internal/test-control/worker-id";
/// Frozen test-control token header (source of truth:
/// `astral-trustgraph/src/api/test_control.rs::TEST_CONTROL_TOKEN_HEADER`).
pub const TEST_CONTROL_TOKEN_HEADER: &str = "X-Test-Control-Token";

/// Upper bound for a single probe attempt; matches the harness signed-request
/// timeout convention (`NodeAdapter::signed_get` uses 30_000 ms).
pub const MAX_PROBE_TIMEOUT_MS: u64 = 30_000;

/// Hard cap on probe attempts per node: retries are GET-only, but the budget
/// stays finite and auditable.
pub const MAX_PROBE_ATTEMPTS_PER_NODE: usize = 3;

/// The exact allowlisted S15 node identities (protected node identity).
pub fn s15_probe_allowlist() -> Vec<&'static str> {
    S15_NODE_PLACEMENTS
        .iter()
        .map(|placement| placement.node_id)
        .collect()
}

fn s15_placement(node: &str) -> Option<&'static crate::s15_validation::S15NodePlacement> {
    S15_NODE_PLACEMENTS
        .iter()
        .find(|placement| placement.node_id == node)
}

/// Redacted secret wrapper for the test-control token: no `Debug`/`Display`
/// leak path, no `Serialize`, construction validates non-emptiness.
pub struct S15Secret(String);

impl S15Secret {
    pub fn new(value: String) -> Result<Self, S15LiveError> {
        if value.is_empty() {
            return Err(S15LiveError::EmptySecret);
        }
        Ok(Self(value))
    }

    /// Crate-internal re-wrap for executors composing coordinators from a
    /// shared protected config; the token bytes never leave the redacted
    /// wrapper and never enter logs or evidence.
    pub fn reproduce(&self) -> S15Secret {
        S15Secret(self.0.clone())
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for S15Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("S15Secret([redacted])")
    }
}

/// One outbound probe request after allowlist validation. Header values are
/// redacted in `Debug` so the token never enters logs.
pub struct ProbeRequest {
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub timeout_ms: u64,
}

impl fmt::Debug for ProbeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names = self.headers.keys().cloned().collect::<Vec<_>>().join(",");
        formatter
            .debug_struct("ProbeRequest")
            .field("url", &"[redacted-host]")
            .field("headers", &header_names)
            .field("timeout_ms", &self.timeout_ms)
            .finish()
    }
}

pub struct ProbeResponse {
    pub status: u16,
    pub body: String,
}

/// Transport port: the executor injects the real HTTP stack; this crate never
/// opens sockets itself.
pub trait ProbeTransport {
    fn request(&mut self, plan: &ProbeRequest) -> Result<ProbeResponse, String>;
}

/// Exact per-node base-URL allowlist. Keys must be a subset of the four S15
/// node identities; values must be a bare `http(s)://host[:port]` origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S15NodeEndpoints {
    base_urls: BTreeMap<&'static str, String>,
}

impl S15NodeEndpoints {
    pub fn from_pairs(pairs: &[(&'static str, String)]) -> Result<Self, S15LiveError> {
        let mut base_urls = BTreeMap::new();
        for (node, base_url) in pairs {
            if s15_placement(node).is_none() {
                return Err(S15LiveError::UnknownNodeAlias((*node).to_owned()));
            }
            if base_urls.contains_key(*node) {
                return Err(S15LiveError::DuplicateNodeAlias((*node).to_owned()));
            }
            if !valid_base_url(base_url) {
                return Err(S15LiveError::InvalidNodeBaseUrl((*node).to_owned()));
            }
            base_urls.insert(*node, base_url.clone());
        }
        Ok(Self { base_urls })
    }

    pub fn base_url(&self, node: &str) -> Option<&String> {
        self.base_urls.get(node)
    }

    pub fn len(&self) -> usize {
        self.base_urls.len()
    }

    pub fn is_empty(&self) -> bool {
        self.base_urls.is_empty()
    }
}

/// Origin-shape check mirroring the repo convention (`valid_url_shape` in
/// `node_adapter_contract`): http/https, no trailing slash, no query, no
/// whitespace.
fn valid_base_url(value: &str) -> bool {
    (value.starts_with("http://") || value.starts_with("https://"))
        && !value.ends_with('/')
        && !value.contains('?')
        && !value.chars().any(char::is_whitespace)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum S15LiveError {
    EmptySecret,
    InvalidCampaignId,
    InvalidTimeout(u64),
    InvalidAttemptBudget(usize),
    UnknownNodeAlias(String),
    DuplicateNodeAlias(String),
    InvalidNodeBaseUrl(String),
    NodeMissingEndpoint(String),
    NonProbePath(String),
    NonGetMethod,
    InvalidTimestamp,
    InvalidActor,
    InvalidSigningKey,
}

impl fmt::Display for S15LiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::EmptySecret => "empty_secret".to_owned(),
            Self::InvalidCampaignId => "invalid_campaign_id".to_owned(),
            Self::InvalidTimeout(value) => format!("invalid_timeout:{value}"),
            Self::InvalidAttemptBudget(value) => format!("invalid_attempt_budget:{value}"),
            Self::UnknownNodeAlias(node) => format!("unknown_node_alias:{node}"),
            Self::DuplicateNodeAlias(node) => format!("duplicate_node_alias:{node}"),
            Self::InvalidNodeBaseUrl(node) => format!("invalid_node_base_url:{node}"),
            Self::NodeMissingEndpoint(node) => format!("node_missing_endpoint:{node}"),
            Self::NonProbePath(path) => format!("non_probe_path_rejected:{path}"),
            Self::NonGetMethod => "non_get_method_rejected".to_owned(),
            Self::InvalidTimestamp => "invalid_timestamp".to_owned(),
            Self::InvalidActor => "invalid_actor".to_owned(),
            Self::InvalidSigningKey => "invalid_signing_key".to_owned(),
        };
        formatter.write_str(&text)
    }
}

/// One observed probe exchange. The raw response body is captured verbatim —
/// this is the raw artifact; transport errors carry only a short reason.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum S15ProbeOutcome {
    Http {
        status: u16,
        #[serde(rename = "rawBody")]
        raw_body: String,
    },
    TransportError {
        detail: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct S15ProbeObservation {
    pub attempt: usize,
    #[serde(rename = "requestId")]
    pub request_id: String,
    pub outcome: S15ProbeOutcome,
}

/// Identity fields of the frozen worker-id probe contract (top-level
/// camelCase JSON).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct S15ProbeIdentity {
    pub node_id: String,
    pub worker_id: String,
    pub config_fingerprint: String,
    pub jvm_start_time: String,
    pub process_identity_hash: String,
}

fn parse_probe_identity(raw_body: &str) -> Option<S15ProbeIdentity> {
    let parsed: Value = serde_json::from_str(raw_body).ok()?;
    let object = parsed.as_object()?;
    let field = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    Some(S15ProbeIdentity {
        node_id: field("nodeId")?,
        worker_id: field("workerId")?,
        config_fingerprint: field("configFingerprint")?,
        jvm_start_time: field("jvmStartTime")?,
        process_identity_hash: field("processIdentityHash")?,
    })
}

fn is_hex_digest_64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Terminal result of one node's probe sequence within a run. Topology fields
/// (half, database) are frozen metadata; the probe itself exercises no
/// transport channel and therefore claims none.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct S15NodeAttempt {
    pub node: &'static str,
    /// `"A"` or `"B"` (half membership from the frozen S15 topology).
    pub half: &'static str,
    #[serde(rename = "databaseId")]
    pub database_id: &'static str,
    #[serde(rename = "probePath")]
    pub probe_path: &'static str,
    #[serde(rename = "campaignId")]
    pub campaign_id: String,
    pub status: ReadinessStatus,
    pub reason: String,
    pub observations: Vec<S15ProbeObservation>,
    pub identity: Option<S15ProbeIdentity>,
}

fn half_label(half: S15Half) -> &'static str {
    match half {
        S15Half::A => "A",
        S15Half::B => "B",
    }
}

/// Live coordinator over the frozen read-only test-control probe.
///
/// Holds the run identity, the redacted token and the finite budgets. All
/// per-call secrets (actor, gateway key) stay call-scoped and are never
/// retained.
pub struct S15LiveCoordinator {
    campaign_id: String,
    token: S15Secret,
    attempt_timeout_ms: u64,
    max_attempts: usize,
}

impl fmt::Debug for S15LiveCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S15LiveCoordinator")
            .field("campaign_id", &self.campaign_id)
            .field("token", &"[redacted]")
            .field("attempt_timeout_ms", &self.attempt_timeout_ms)
            .field("max_attempts", &self.max_attempts)
            .finish()
    }
}

impl S15LiveCoordinator {
    pub fn new(
        campaign_id: &str,
        token: S15Secret,
        attempt_timeout_ms: u64,
        max_attempts: usize,
    ) -> Result<Self, S15LiveError> {
        validate_campaign_id(campaign_id).map_err(|_| S15LiveError::InvalidCampaignId)?;
        if attempt_timeout_ms == 0 || attempt_timeout_ms > MAX_PROBE_TIMEOUT_MS {
            return Err(S15LiveError::InvalidTimeout(attempt_timeout_ms));
        }
        if max_attempts == 0 || max_attempts > MAX_PROBE_ATTEMPTS_PER_NODE {
            return Err(S15LiveError::InvalidAttemptBudget(max_attempts));
        }
        Ok(Self {
            campaign_id: campaign_id.to_owned(),
            token,
            attempt_timeout_ms,
            max_attempts,
        })
    }

    pub fn campaign_id(&self) -> &str {
        &self.campaign_id
    }

    /// Run-scoped, deterministic, signing-safe request id:
    /// `s15-{node}-{seq}-{hash16(run_id)}` — stable for one run, distinct
    /// across nodes/sequences, within the 64-byte operation-id contract.
    fn request_id_for(&self, node: &str, sequence: usize) -> String {
        let digest = Sha256::digest(self.campaign_id.as_bytes());
        let digest_hex: String = digest[..8]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        format!("s15-{}-{sequence}-{digest_hex}", node.to_ascii_lowercase())
    }

    /// Builds the exact allowlisted probe request: GET only, frozen path only,
    /// gateway-v3 signed headers plus the test-control token header. Any
    /// other path or method is rejected before the transport exists.
    pub fn build_probe_request(
        &self,
        actor: &Actor,
        key: &[u8],
        endpoints: &S15NodeEndpoints,
        node: &'static str,
        request_id: &str,
        timestamp_ms: &str,
    ) -> Result<ProbeRequest, S15LiveError> {
        if s15_placement(node).is_none() {
            return Err(S15LiveError::UnknownNodeAlias(node.to_owned()));
        }
        let Some(base_url) = endpoints.base_url(node) else {
            return Err(S15LiveError::NodeMissingEndpoint(node.to_owned()));
        };
        if timestamp_ms.is_empty() || !timestamp_ms.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(S15LiveError::InvalidTimestamp);
        }
        if !request_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/')
        }) || request_id.is_empty()
            || request_id.len() > 64
        {
            return Err(S15LiveError::NonProbePath(request_id.to_owned()));
        }
        let headers = sign_headers(actor, "GET", S15_PROBE_PATH, request_id, timestamp_ms, key)
            .map_err(|_| S15LiveError::InvalidSigningKey)?;
        let mut header_map = headers.values;
        header_map.insert(
            TEST_CONTROL_TOKEN_HEADER.to_owned(),
            self.token.expose().to_owned(),
        );
        Ok(ProbeRequest {
            url: format!("{base_url}/main/api/v1{S15_PROBE_PATH}"),
            headers: header_map,
            timeout_ms: self.attempt_timeout_ms,
        })
    }

    /// Probes one allowlisted node with the finite retry budget and returns
    /// the terminal attempt record. Retrying applies only to transport errors
    /// and 5xx; deterministic outcomes (4xx, unparseable body, identity
    /// mismatch) stop immediately. Every exchange is recorded verbatim.
    pub fn probe_node<T: ProbeTransport>(
        &self,
        transport: &mut T,
        actor: &Actor,
        key: &[u8],
        endpoints: &S15NodeEndpoints,
        node: &'static str,
        timestamp_ms: &str,
    ) -> Result<S15NodeAttempt, S15LiveError> {
        let placement =
            s15_placement(node).ok_or_else(|| S15LiveError::UnknownNodeAlias(node.to_owned()))?;
        actor.validate().map_err(|_| S15LiveError::InvalidActor)?;
        if key.is_empty() {
            return Err(S15LiveError::InvalidSigningKey);
        }
        if timestamp_ms.is_empty() || !timestamp_ms.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(S15LiveError::InvalidTimestamp);
        }
        let mut observations = Vec::with_capacity(self.max_attempts);
        let mut status = ReadinessStatus::Unknown;
        let mut reason = String::new();
        let mut identity = None;
        for sequence in 1..=self.max_attempts {
            let request_id = self.request_id_for(node, sequence);
            let plan =
                self.build_probe_request(actor, key, endpoints, node, &request_id, timestamp_ms)?;
            match transport.request(&plan) {
                Ok(response) => {
                    let outcome = S15ProbeOutcome::Http {
                        status: response.status,
                        raw_body: response.body.clone(),
                    };
                    observations.push(S15ProbeObservation {
                        attempt: sequence,
                        request_id,
                        outcome,
                    });
                    if response.status == 200 {
                        match parse_probe_identity(&response.body) {
                            None => {
                                status = ReadinessStatus::Blocked;
                                reason = "response_not_contract_json".to_owned();
                            }
                            Some(parsed) => {
                                if parsed.node_id != node {
                                    // Fail-closed: foreign identity can never
                                    // become PASS evidence for this node.
                                    status = ReadinessStatus::Blocked;
                                    reason = "node_identity_mismatch".to_owned();
                                } else {
                                    status = ReadinessStatus::Pass;
                                    reason = "probe_identity_confirmed".to_owned();
                                    identity = Some(parsed);
                                }
                            }
                        }
                        break;
                    } else if (400..500).contains(&response.status) {
                        status = ReadinessStatus::Blocked;
                        reason = format!("http_{}", response.status);
                        break;
                    } else if (500..600).contains(&response.status) {
                        status = ReadinessStatus::Unknown;
                        reason = format!("http_{}_after_budget", response.status);
                    } else {
                        status = ReadinessStatus::Blocked;
                        reason = format!("unexpected_http_{}", response.status);
                        break;
                    }
                }
                Err(detail) => {
                    observations.push(S15ProbeObservation {
                        attempt: sequence,
                        request_id,
                        outcome: S15ProbeOutcome::TransportError { detail },
                    });
                    status = ReadinessStatus::Unknown;
                    reason = "transport_error_after_budget".to_owned();
                }
            }
        }
        Ok(S15NodeAttempt {
            node,
            half: half_label(placement.half),
            database_id: placement.database_id,
            probe_path: S15_PROBE_PATH,
            campaign_id: self.campaign_id.clone(),
            status,
            reason,
            observations,
            identity,
        })
    }
}

/// Durable postcondition over the full four-node identity evidence set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct S15IdentityPostcondition {
    pub status: ReadinessStatus,
    pub problems: Vec<String>,
}

/// Evaluates the identity postcondition: all four S15 nodes probed to PASS
/// with contract-shaped, pairwise-distinct worker/process identities. Any
/// `UNKNOWN` node keeps the whole postcondition `UNKNOWN`; deterministic
/// violations yield `BLOCKED`. Nothing here can turn partial evidence into
/// `PASS`.
pub fn evaluate_identity_postcondition(attempts: &[S15NodeAttempt]) -> S15IdentityPostcondition {
    let mut by_node: BTreeMap<&'static str, &S15NodeAttempt> = BTreeMap::new();
    for attempt in attempts {
        if by_node.insert(attempt.node, attempt).is_some() {
            return S15IdentityPostcondition {
                status: ReadinessStatus::Blocked,
                problems: vec![format!("duplicate_attempt_record:{}", attempt.node)],
            };
        }
    }
    let mut problems = Vec::new();
    for placement in S15_NODE_PLACEMENTS.iter() {
        let Some(attempt) = by_node.get(placement.node_id) else {
            problems.push(format!("missing_node_attempt:{}", placement.node_id));
            continue;
        };
        if attempt.status == ReadinessStatus::Unknown {
            problems.push(format!("unknown_node_attempt:{}", placement.node_id));
        } else if attempt.status != ReadinessStatus::Pass {
            problems.push(format!(
                "node_not_pass:{}:{}",
                placement.node_id, attempt.reason
            ));
        }
    }
    let identities: Vec<(&str, &S15ProbeIdentity)> = attempts
        .iter()
        .filter_map(|attempt| {
            attempt
                .identity
                .as_ref()
                .map(|identity| (attempt.node, identity))
        })
        .collect();
    if identities.len() != S15_NODE_PLACEMENTS.len() {
        problems.push("missing_identity_payload".to_owned());
    }
    let mut worker_ids: BTreeMap<&str, &str> = BTreeMap::new();
    let mut process_hashes: BTreeMap<&str, &str> = BTreeMap::new();
    for (node, identity) in identities {
        if worker_ids
            .insert(identity.worker_id.as_str(), node)
            .is_some()
        {
            problems.push(format!("duplicate_worker_id:{}", node));
        }
        if process_hashes
            .insert(identity.process_identity_hash.as_str(), node)
            .is_some()
        {
            problems.push(format!("duplicate_process_identity_hash:{}", node));
        }
        if !is_hex_digest_64(&identity.process_identity_hash) {
            problems.push(format!("malformed_process_identity_hash:{}", node));
        }
        if !is_hex_digest_64(&identity.config_fingerprint) {
            problems.push(format!("malformed_config_fingerprint:{}", node));
        }
        if identity
            .jvm_start_time
            .bytes()
            .any(|byte| !byte.is_ascii_digit())
        {
            problems.push(format!("malformed_jvm_start_time:{}", node));
        }
    }
    let status = if problems
        .iter()
        .any(|problem| problem.starts_with("unknown_node_attempt:"))
    {
        ReadinessStatus::Unknown
    } else if problems.is_empty() {
        ReadinessStatus::Pass
    } else {
        ReadinessStatus::Blocked
    };
    S15IdentityPostcondition { status, problems }
}

/// Requirements whose raw evidence THIS probe executor can produce: per-node
/// gateway-signed 200 responses with exactly-matched identities are captured
/// verbatim (raw body + request ids + distinct worker/process hashes) in the
/// run record, so `signed_identity` and `four_node_state` carry raw evidence,
/// hash, and identity postcondition support. `readiness` and
/// `run_scoped_provenance` are distinct gates not proven by worker-id.
///
/// Every OTHER requirement in [`CURRENT_S15_LIVE_REQUIREMENTS`] — approved
/// deployment, fault/partition controller, half/database state, the custom
/// same-database channel, cross-database RabbitMQ, current transport,
/// durable receipts, tenant isolation, audit correlation, half-authority
/// fence, split-brain fail-closed — has NO protected evidence primitive in
/// this executor. Those requirements can NEVER be closed by a deployment
/// attestation boolean; they keep the overall S15 gate `BLOCKED` until a
/// full live campaign supplies real raw evidence for each of them.
pub const PROBE_EVIDENCE_REQUIREMENTS: &[&str] = &["signed_identity", "four_node_state"];

/// A live worker-id exchange proves process liveness and identity only. It is
/// not a serving-readiness check, an authorization ALLOW, or evidence that the
/// configured database/transport is the one used by that process.
pub const S15_READINESS_PROBE_GAP: &str =
    "worker-id proves process liveness only; no production serving-readiness probe exists";

pub const MAX_S15_OWNER_EVIDENCE_BYTES: usize = 256 * 1024;
pub const MAX_S15_OWNER_EVIDENCE_AGE_MS: i64 = 30_000;
pub const MAX_S15_OWNER_EVIDENCE_TTL_MS: i64 = 300_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S15OwnerTransportProof {
    // These fields are intentionally private. A JSON caller or a test-control
    // probe cannot manufacture an authenticated owner identity; only a future
    // production owner adapter may construct this opaque proof after verifying
    // the endpoint transport and its signed response.
    owner_identity: String,
    proof_digest: String,
}

impl S15OwnerTransportProof {
    /// This constructor is intentionally private. There is currently no
    /// production owner endpoint/transport adapter in this crate; a future
    /// adapter must create the proof only after verifying the endpoint
    /// transport and its signed response.
    #[cfg(test)]
    fn synthetic_for_parser_contract_tests(owner_identity: String, proof_digest: String) -> Self {
        Self {
            owner_identity,
            proof_digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct S15OwnerEvidence {
    requirement: String,
    owner: String,
    owner_identity: String,
    run_id: String,
    scope: String,
    operation_id: String,
    event_id: String,
    observed_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    certificate_hash: String,
    frontier_digest: String,
    audit_correlation_id: String,
    postcondition: String,
    raw_sha256: String,
    #[serde(skip)]
    adapter_verified: bool,
    raw_body: String,
}

impl S15OwnerEvidence {
    pub fn requirement(&self) -> &str {
        &self.requirement
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    pub fn owner_identity(&self) -> &str {
        &self.owner_identity
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn scope(&self) -> &str {
        &self.scope
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn observed_at_unix_ms(&self) -> i64 {
        self.observed_at_unix_ms
    }

    pub fn expires_at_unix_ms(&self) -> i64 {
        self.expires_at_unix_ms
    }

    pub fn certificate_hash(&self) -> &str {
        &self.certificate_hash
    }

    pub fn frontier_digest(&self) -> &str {
        &self.frontier_digest
    }

    pub fn audit_correlation_id(&self) -> &str {
        &self.audit_correlation_id
    }

    pub fn postcondition(&self) -> &str {
        &self.postcondition
    }

    pub fn raw_sha256(&self) -> &str {
        &self.raw_sha256
    }

    pub fn raw_body(&self) -> &str {
        &self.raw_body
    }

    pub fn adapter_verified(&self) -> bool {
        self.adapter_verified
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct S15RawOwnerProbe {
    pub requirement: String,
    /// Untrusted caller metadata. It is never promoted to an owner identity.
    pub reported_owner_identity: String,
    pub transport_proof: Option<S15OwnerTransportProof>,
    pub raw_body: Option<String>,
    pub log_complete: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct S15OwnerEvidenceCollection {
    pub evidence: Vec<S15OwnerEvidence>,
    pub unknown: Vec<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct S15OwnerEvidenceWire {
    requirement: String,
    owner: String,
    run_id: String,
    observed_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    scope: String,
    operation_id: String,
    event_id: String,
    certificate_hash: String,
    frontier_digest: String,
    audit_correlation_id: String,
    postcondition: String,
    evidence: S15OwnerEvidencePayload,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct S15OwnerEvidencePayload {
    scope: String,
    operation_id: String,
    event_id: String,
    certificate_hash: String,
    frontier_digest: String,
    source_commit_digest: String,
    source_outcome_digest: String,
    audit_correlation_id: String,
    postcondition: String,
}

pub fn parse_s15_owner_evidence(
    requirement: &str,
    transport_proof: Option<&S15OwnerTransportProof>,
    expected_run_id: &str,
    expected_scope: &str,
    expected_operation_id: Option<&str>,
    now_unix_ms: i64,
    raw_body: &str,
) -> Result<S15OwnerEvidence, String> {
    let transport_proof =
        transport_proof.ok_or_else(|| "owner_transport_proof_missing".to_owned())?;
    if transport_proof.owner_identity.trim().is_empty()
        || !is_digest_64_lower(&transport_proof.proof_digest)
    {
        return Err("owner_transport_proof_invalid".to_owned());
    }
    if expected_s15_evidence_owner(requirement).is_none() {
        return Err("unknown_owner_requirement".to_owned());
    }
    validate_campaign_id(expected_run_id).map_err(|_| "cross_run_evidence".to_owned())?;
    if expected_scope.is_empty() {
        return Err("scope_mismatch".to_owned());
    }
    if raw_body.is_empty() || raw_body.len() > MAX_S15_OWNER_EVIDENCE_BYTES {
        return Err("owner_evidence_body_invalid".to_owned());
    }
    let raw_sha256 = Sha256::digest(raw_body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if transport_proof.proof_digest != raw_sha256 {
        return Err("owner_transport_proof_binding_mismatch".to_owned());
    }
    let wire: S15OwnerEvidenceWire =
        serde_json::from_str(raw_body).map_err(|_| "owner_evidence_not_strict_json".to_owned())?;
    if wire.requirement != requirement {
        return Err("owner_requirement_mismatch".to_owned());
    }
    if wire.run_id != expected_run_id {
        return Err("cross_run_evidence".to_owned());
    }
    if wire.scope != expected_scope || wire.evidence.scope != expected_scope {
        return Err("scope_mismatch".to_owned());
    }
    if wire.operation_id.is_empty()
        || wire.evidence.operation_id != wire.operation_id
        || expected_operation_id.is_some_and(|expected| wire.operation_id != expected)
    {
        return Err("operation_id_mismatch".to_owned());
    }
    if wire.event_id.is_empty()
        || wire.evidence.event_id != wire.event_id
        || wire.certificate_hash != wire.evidence.certificate_hash
        || wire.frontier_digest != wire.evidence.frontier_digest
        || wire.audit_correlation_id != wire.evidence.audit_correlation_id
        || wire.postcondition != wire.evidence.postcondition
    {
        return Err("owner_evidence_binding_mismatch".to_owned());
    }
    if wire.owner != expected_s15_evidence_owner(requirement).unwrap_or_default() {
        return Err("owner_requirement_mismatch".to_owned());
    }
    if wire.postcondition != "PASS" {
        return Err("owner_postcondition_not_pass".to_owned());
    }
    if wire.observed_at_unix_ms <= 0
        || wire.expires_at_unix_ms <= wire.observed_at_unix_ms
        || wire.observed_at_unix_ms > now_unix_ms.saturating_add(5_000)
        || now_unix_ms.saturating_sub(wire.observed_at_unix_ms) > MAX_S15_OWNER_EVIDENCE_AGE_MS
        || wire
            .expires_at_unix_ms
            .saturating_sub(wire.observed_at_unix_ms)
            > MAX_S15_OWNER_EVIDENCE_TTL_MS
        || now_unix_ms >= wire.expires_at_unix_ms
    {
        return Err("evidence_expired_or_outside_freshness_window".to_owned());
    }
    for digest in [
        wire.certificate_hash.as_str(),
        wire.frontier_digest.as_str(),
        wire.evidence.source_commit_digest.as_str(),
        wire.evidence.source_outcome_digest.as_str(),
    ] {
        if !is_digest_64_lower(digest) {
            return Err("durable_source_evidence_incomplete".to_owned());
        }
    }
    if wire.audit_correlation_id.is_empty() || wire.operation_id.is_empty() {
        return Err("durable_source_evidence_incomplete".to_owned());
    }
    let raw_sha256 = Sha256::digest(raw_body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(S15OwnerEvidence {
        requirement: requirement.to_owned(),
        owner: wire.owner,
        owner_identity: transport_proof.owner_identity.clone(),
        run_id: wire.run_id,
        scope: wire.scope,
        operation_id: wire.operation_id,
        event_id: wire.event_id,
        observed_at_unix_ms: wire.observed_at_unix_ms,
        expires_at_unix_ms: wire.expires_at_unix_ms,
        certificate_hash: wire.certificate_hash,
        frontier_digest: wire.frontier_digest,
        audit_correlation_id: wire.audit_correlation_id,
        postcondition: wire.postcondition,
        raw_sha256,
        adapter_verified: true,
        raw_body: raw_body.to_owned(),
    })
}

pub fn collect_s15_owner_evidence(
    probes: &[S15RawOwnerProbe],
    expected_run_id: &str,
    expected_scope: &str,
    expected_operation_id: Option<&str>,
    now_unix_ms: i64,
) -> S15OwnerEvidenceCollection {
    let mut collection = S15OwnerEvidenceCollection::default();
    for probe in probes {
        if !probe.log_complete {
            collection
                .unknown
                .push(format!("owner_probe_log_incomplete:{}", probe.requirement));
            continue;
        }
        let Some(raw_body) = probe.raw_body.as_deref() else {
            collection
                .unknown
                .push(format!("owner_probe_missing:{}", probe.requirement));
            continue;
        };
        match parse_s15_owner_evidence(
            &probe.requirement,
            probe.transport_proof.as_ref(),
            expected_run_id,
            expected_scope,
            expected_operation_id,
            now_unix_ms,
            raw_body,
        ) {
            Ok(evidence) => collection.evidence.push(evidence),
            Err(reason) => collection.unknown.push(format!(
                "owner_probe_invalid:{}:{reason}",
                probe.requirement
            )),
        }
    }
    collection
}

/// Requirement-to-owner binding. An adapter cannot claim another subsystem's
/// evidence merely by returning a `PASS` envelope.
pub fn expected_s15_evidence_owner(requirement: &str) -> Option<&'static str> {
    match requirement {
        "approved_deployment" => Some("deployment_authority"),
        "signed_identity" | "four_node_state" => Some("trustgraph_node"),
        "readiness" => Some("trustgraph_readiness"),
        "controller" => Some("s15_fault_controller"),
        "two_half_state" => Some("deployment_control"),
        "two_database_state" => Some("database_identity_owner"),
        "same_db_custom_channel" => Some("same_database_transport_owner"),
        "cross_db_rabbitmq" => Some("rabbitmq_transport_owner"),
        "current_transport" => Some("transport_owner"),
        "durable_evidence" => Some("source_database_owner"),
        "run_scoped_provenance" => Some("evidence_recorder"),
        "tenant_isolation" => Some("tenant_read_gate_owner"),
        "audit_correlation" => Some("audit_store_owner"),
        "half_authority_fence" | "split_brain_fail_closed" => Some("authority_quorum_owner"),
        _ => None,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct S15LiveCapabilityGap {
    pub requirement: &'static str,
    pub missing_production_contract: &'static str,
}

/// Requirements with no exact production evidence plane in the current read-only
/// adapter. The TrustGraph observations close only source/durable receipt,
/// tenant-scope, audit, per-node readiness/liveness, and configured node identity
/// projections; they do not prove deployment approval, controller/fault behavior,
/// the two-node transport paths, half ownership, or authority fencing.
pub const S15_LIVE_CAPABILITY_GAPS: &[S15LiveCapabilityGap] = &[
    S15LiveCapabilityGap { requirement: "approved_deployment", missing_production_contract: "signed deployment approval artifact bound to this run and protected topology" },
    S15LiveCapabilityGap { requirement: "controller", missing_production_contract: "read-only controller attestation plus separately approved, run-scoped fault/restore adapter; this executor performs no faults" },
    S15LiveCapabilityGap { requirement: "two_half_state", missing_production_contract: "live owner proof of both half memberships and current worker/lease ownership; local topology constants are not deployment evidence" },
    S15LiveCapabilityGap { requirement: "two_database_state", missing_production_contract: "read-only authenticated DB identity proof for isolated DB1 and DB2, bound to the expected nodes" },
    S15LiveCapabilityGap { requirement: "same_db_custom_channel", missing_production_contract: "per-message durable custom-channel evidence across each same-DB node pair; process-local LocalBus is insufficient" },
    S15LiveCapabilityGap { requirement: "cross_db_rabbitmq", missing_production_contract: "per-message RabbitMQ outbox/confirm/inbox/APPLIED evidence across DB halves" },
    S15LiveCapabilityGap { requirement: "current_transport", missing_production_contract: "production owner observation binding source/target nodes to the actual selected transport and canonical message identity" },
    S15LiveCapabilityGap { requirement: "run_scoped_provenance", missing_production_contract: "immutable recorder manifest binding every observation/artifact digest to this runId and stable operation/event identity; route runId is caller-correlation-only" },
    S15LiveCapabilityGap { requirement: "tenant_isolation", missing_production_contract: "two-tenant live read-gate evidence with an exact negative cross-tenant postcondition; this route observes only one exact tenant/card scope" },
    S15LiveCapabilityGap { requirement: "half_authority_fence", missing_production_contract: "authority quorum read proving current term/fence plus both halves' ownership and stale-writer rejection" },
    S15LiveCapabilityGap { requirement: "split_brain_fail_closed", missing_production_contract: "independently controlled partition/split-brain scenario and durable PENDING/DENY postcondition; not run without Exec-L3 approval" },
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct S15AuthorizationObservationEvidence {
    pub node: String,
    pub observation_sha256: String,
    pub raw_body: String,
    pub observed_at_unix_ms: i64,
    pub source_status: String,
    pub source_authority_commit_status: String,
    pub source_phase: String,
    pub source_owner_identity_status: String,
    pub source_database_id: Option<String>,
    pub source_reservation_id: Option<String>,
    pub source_operation_id: Option<String>,
    pub source_event_id: Option<String>,
    pub source_commit_digest: Option<String>,
    pub source_outcome_digest: Option<String>,
    pub source_request_binding_digest: Option<String>,
    pub outbox_status: String,
    pub outbox_message_id: Option<String>,
    pub outbox_operation_id: Option<String>,
    pub outbox_tenant_id: Option<i64>,
    pub inbox_status: String,
    pub inbox_message_id: Option<String>,
    pub inbox_operation_id: Option<String>,
    pub inbox_tenant_id: Option<i64>,
    pub audit_status: String,
    pub audit_receipt_count: Option<usize>,
    pub exact_audit_receipts_verified: Option<bool>,
    pub read_gate_status: String,
    pub positive_authorization_ready: Option<bool>,
    pub liveness_status: String,
    pub process_reached_handler: bool,
    pub deployment_node_identity_status: String,
    pub deployment_node_id: Option<String>,
    pub source_receipt_proven: bool,
    pub audit_correlation_proven: bool,
    pub outbox_receipt_proven: bool,
    pub inbox_receipt_proven: bool,
    pub readiness_proven: bool,
    pub liveness_proven: bool,
    pub configured_node_identity_proven: bool,
    pub tenant_scope_observed: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct S15AuthorizationObservationEvidenceSet {
    pub observations: Vec<S15AuthorizationObservationEvidence>,
    pub attempts: Vec<S15AuthorizationObservationAttempt>,
    pub evidence_backed: Vec<String>,
    pub missing_or_invalid: Vec<String>,
    pub unknown: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum S15AuthorizationObservationOutcome {
    Http {
        status: u16,
        #[serde(rename = "rawBody")]
        raw_body: String,
    },
    TransportError {
        detail: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct S15AuthorizationObservationAttempt {
    pub node: &'static str,
    pub request_id: String,
    pub outcome: S15AuthorizationObservationOutcome,
}

pub struct S15AuthorizationObservationRequest {
    pub node: &'static str,
    pub request_id: String,
    pub plan: ProbeRequest,
}

impl fmt::Debug for S15AuthorizationObservationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S15AuthorizationObservationRequest")
            .field("node", &self.node)
            .field("request_id", &self.request_id)
            .field("plan", &self.plan)
            .finish()
    }
}

pub struct S15ObservationCorrelation<'a> {
    pub run_id: &'a str,
    pub operation_id: &'a str,
    pub reservation_id: &'a str,
    pub message_id: &'a str,
    pub tenant_id: i64,
    pub card_id: i64,
}

pub struct S15ObservationSigning<'a> {
    pub request_id: &'a str,
    pub timestamp_ms: &'a str,
}

/// Build a GET plan only for the production owner observation route. Its
/// six correlation dimensions are exact, canonical ASCII values; the signature
/// binds the route path while HTTP GET semantics cover the query string.
pub fn build_s15_authorization_observation_request(
    actor: &Actor,
    key: &[u8],
    endpoints: &S15NodeEndpoints,
    timeout_ms: u64,
    node: &'static str,
    correlation: &S15ObservationCorrelation<'_>,
    signing: &S15ObservationSigning<'_>,
) -> Result<S15AuthorizationObservationRequest, String> {
    let S15ObservationCorrelation {
        run_id,
        operation_id,
        reservation_id,
        message_id,
        tenant_id,
        card_id,
    } = *correlation;
    let S15ObservationSigning {
        request_id,
        timestamp_ms,
    } = *signing;
    if s15_placement(node).is_none() {
        return Err("unknown_observation_node".to_owned());
    }
    crate::readiness_contract::validate_campaign_id(run_id)
        .map_err(|_| "observation_run_id_invalid".to_owned())?;
    for (name, value, maximum) in [
        ("operation_id", operation_id, 128),
        ("reservation_id", reservation_id, 128),
        ("message_id", message_id, 128),
    ] {
        if value.is_empty()
            || value.len() > maximum
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(format!("observation_{name}_invalid"));
        }
    }
    if tenant_id <= 0 || card_id <= 0 {
        return Err("observation_scope_invalid".to_owned());
    }
    if timeout_ms == 0 || timeout_ms > MAX_PROBE_TIMEOUT_MS {
        return Err("observation_timeout_invalid".to_owned());
    }
    let base_url = endpoints
        .base_url(node)
        .ok_or_else(|| "observation_node_missing_endpoint".to_owned())?;
    if request_id.is_empty()
        || request_id.len() > 64
        || !request_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/')
        })
        || timestamp_ms.is_empty()
        || !timestamp_ms.bytes().all(|byte| byte.is_ascii_digit())
        || key.is_empty()
    {
        return Err("observation_signing_input_invalid".to_owned());
    }
    let query = format!(
        "runId={run_id}&operationId={operation_id}&reservationId={reservation_id}&messageId={message_id}&tenantId={tenant_id}&cardId={card_id}"
    );
    let signed = sign_headers(
        actor,
        "GET",
        "/authorization-observations/s15",
        request_id,
        timestamp_ms,
        key,
    )
    .map_err(|_| "observation_signed_request_rejected".to_owned())?;
    let headers = signed.values;
    let plan = ProbeRequest {
        url: format!("{base_url}/main/api/v1/authorization-observations/s15?{query}"),
        headers,
        timeout_ms,
    };
    Ok(S15AuthorizationObservationRequest {
        node,
        request_id: request_id.to_owned(),
        plan,
    })
}

fn is_digest_64_lower(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Parse the concrete production `ApiResponse<S15AuthorizationObservation>`
/// DTO. Only independently supported requirement planes are admitted; metadata
/// on the route is not promoted to a blanket PASS for other S15 requirements.
pub fn parse_s15_authorization_observation(
    node: &'static str,
    raw_body: &str,
    now_unix_ms: i64,
    expected: &S15ObservationCorrelation<'_>,
) -> Result<S15AuthorizationObservationEvidence, String> {
    let S15ObservationCorrelation {
        run_id: expected_run_id,
        operation_id: expected_operation_id,
        reservation_id: expected_reservation_id,
        message_id: expected_message_id,
        tenant_id: expected_tenant_id,
        card_id: expected_card_id,
    } = *expected;
    if s15_placement(node).is_none() {
        return Err("unknown_observation_node".to_owned());
    }
    if raw_body.len() > MAX_S15_OWNER_EVIDENCE_BYTES {
        return Err("observation_body_too_large".to_owned());
    }
    let response: ProductionApiResponse =
        serde_json::from_str(raw_body).map_err(|_| "observation_response_invalid".to_owned())?;
    if !response.success || response.code != 200 {
        return Err("observation_http_envelope_not_success".to_owned());
    }
    let _ = (
        response.message,
        response.error_type,
        response.decision,
        response.reason_code,
        response.required_permission,
        response.request_path,
        response.request_method,
        response.timestamp,
        response.trace_id,
    );
    let observation = response
        .data
        .ok_or_else(|| "observation_data_missing".to_owned())?;
    if observation.schema != "astral.s15.authorization-observation/v1" {
        return Err("observation_schema_mismatch".to_owned());
    }
    let correlation = &observation.correlation;
    if correlation.run_id_binding != ProductionPlaneStatus::Unknown {
        return Err("run_id_binding_must_remain_unknown".to_owned());
    }
    if correlation.run_id != expected_run_id
        || correlation.operation_id != expected_operation_id
        || correlation.reservation_id != expected_reservation_id
        || correlation.message_id != expected_message_id
        || correlation.tenant_id != expected_tenant_id
        || correlation.card_id != expected_card_id
    {
        return Err("observation_correlation_mismatch".to_owned());
    }
    if observation.observed_at_unix_ms <= 0
        || observation.observed_at_unix_ms > now_unix_ms.saturating_add(5_000)
        || now_unix_ms.saturating_sub(observation.observed_at_unix_ms)
            > MAX_S15_OWNER_EVIDENCE_AGE_MS
    {
        return Err("observation_stale_or_future".to_owned());
    }
    let observation_sha256 = Sha256::digest(raw_body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let correlation = observation.correlation;
    let source = observation.source;
    let outbox = observation.outbox;
    let inbox = observation.inbox;
    let audit = observation.audit;
    let read_gate = observation.read_gate;
    let liveness = observation.liveness;
    let deployment = observation.deployment;
    let mut missing_or_invalid = Vec::new();
    let source_receipt_proven = matches!(source.status, ProductionPlaneStatus::Proven)
        && matches!(
            source.phase,
            ProductionSourcePhase::SourceCommitDurable
                | ProductionSourcePhase::AuthorityCommitted
                | ProductionSourcePhase::Published
                | ProductionSourcePhase::Completed
        )
        && matches!(source.owner_identity_status, ProductionPlaneStatus::Proven)
        && source.reservation_id.as_deref() == Some(expected_reservation_id)
        && source.operation_id.as_deref() == Some(expected_operation_id)
        && source
            .event_id
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        && source
            .source_commit_digest
            .as_deref()
            .is_some_and(is_digest_64_lower)
        && source
            .outcome_digest
            .as_deref()
            .is_some_and(is_digest_64_lower)
        && source
            .request_binding_digest
            .as_deref()
            .is_some_and(is_digest_64_lower)
        && source
            .mutation_kind
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        && source
            .service_id
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        && source
            .database_id
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        && source.source_generation.is_some_and(|value| value > 0)
        && source.revoke_fence.is_some_and(|fence| {
            source
                .source_generation
                .is_some_and(|generation| fence <= generation)
        })
        && source.lease_generation.is_some_and(|value| value > 0)
        && source
            .committed_at_unix_seconds
            .is_some_and(|value| value > 0);
    if !source_receipt_proven {
        if matches!(source.status, ProductionPlaneStatus::Pending)
            || matches!(
                source.authority_commit_status,
                ProductionPlaneStatus::Pending
            )
        {
            missing_or_invalid.push("source_receipt_pending".to_owned());
        } else {
            missing_or_invalid.push("source_receipt_incomplete".to_owned());
        }
    }
    let outbox_receipt_proven = matches!(outbox.status, ProductionPlaneStatus::Proven)
        && outbox.message_id.as_deref() == Some(expected_message_id)
        && outbox.operation_id.as_deref() == Some(expected_operation_id)
        && outbox.tenant_id == Some(expected_tenant_id)
        && outbox
            .payload_digest
            .as_deref()
            .is_some_and(is_digest_64_lower)
        && outbox.observed_at_unix_ms.is_some_and(|value| {
            value > 0
                && value <= now_unix_ms.saturating_add(5_000)
                && now_unix_ms.saturating_sub(value) <= MAX_S15_OWNER_EVIDENCE_AGE_MS
        })
        && outbox
            .durable_state
            .as_deref()
            .is_some_and(|state| matches!(state, "PROCESSED" | "APPLIED" | "COMPLETED"));
    if !outbox_receipt_proven {
        missing_or_invalid.push("outbox_receipt_incomplete".to_owned());
    }
    let inbox_receipt_proven = matches!(inbox.status, ProductionPlaneStatus::Proven)
        && inbox.message_id.as_deref() == Some(expected_message_id)
        && inbox.operation_id.as_deref() == Some(expected_operation_id)
        && inbox.tenant_id == Some(expected_tenant_id)
        && inbox
            .payload_digest
            .as_deref()
            .is_some_and(is_digest_64_lower)
        && inbox.observed_at_unix_ms.is_some_and(|value| {
            value > 0
                && value <= now_unix_ms.saturating_add(5_000)
                && now_unix_ms.saturating_sub(value) <= MAX_S15_OWNER_EVIDENCE_AGE_MS
        })
        && inbox
            .durable_state
            .as_deref()
            .is_some_and(|state| matches!(state, "PROCESSED" | "APPLIED" | "COMPLETED"));
    if !inbox_receipt_proven {
        missing_or_invalid.push("inbox_receipt_incomplete".to_owned());
    }
    let audit_correlation_proven = matches!(audit.status, ProductionPlaneStatus::Proven)
        && audit.receipt_count.is_some_and(|count| count > 0)
        && audit.exact_receipts_verified == Some(true)
        && audit.observed_at_unix_ms.is_some_and(|value| {
            value > 0
                && value <= now_unix_ms.saturating_add(5_000)
                && now_unix_ms.saturating_sub(value) <= MAX_S15_OWNER_EVIDENCE_AGE_MS
        });
    if !audit_correlation_proven {
        missing_or_invalid.push("audit_correlation_incomplete".to_owned());
    }
    let readiness_proven = matches!(read_gate.status, ProductionPlaneStatus::Proven)
        && read_gate.positive_authorization_ready == Some(true)
        && read_gate.observed_at_unix_ms > 0
        && read_gate.observed_at_unix_ms <= now_unix_ms.saturating_add(5_000)
        && now_unix_ms.saturating_sub(read_gate.observed_at_unix_ms)
            <= MAX_S15_OWNER_EVIDENCE_AGE_MS;
    if !readiness_proven {
        missing_or_invalid.push("readiness_observation_incomplete".to_owned());
    }
    let liveness_proven = matches!(liveness.status, ProductionPlaneStatus::Proven)
        && liveness.process_reached_handler
        && liveness.observed_at_unix_ms > 0
        && liveness.observed_at_unix_ms <= now_unix_ms.saturating_add(5_000)
        && now_unix_ms.saturating_sub(liveness.observed_at_unix_ms)
            <= MAX_S15_OWNER_EVIDENCE_AGE_MS;
    if !liveness_proven {
        missing_or_invalid.push("liveness_observation_incomplete".to_owned());
    }
    let configured_node_identity_proven = matches!(
        deployment.node_identity_status,
        ProductionPlaneStatus::Proven
    ) && deployment.node_id.as_deref() == Some(node)
        && deployment
            .region_id
            .as_deref()
            .is_some_and(|value| !value.is_empty());
    if !configured_node_identity_proven {
        missing_or_invalid.push("configured_node_identity_incomplete".to_owned());
    }
    let _ = (
        correlation.run_id_binding,
        source.authority_commit_status,
        source.before_image_digest,
        source.after_image_digest,
        source.admission_proof_id,
        source.reason_code,
        outbox.reason_code,
        inbox.reason_code,
        audit.reason_code,
        read_gate.hub_authority_state,
        deployment.topology_status,
        deployment.half,
        deployment.controller,
        observation.authority_frontier.status,
        observation.authority_frontier.reason_code,
    );
    let evidence = S15AuthorizationObservationEvidence {
        node: node.to_owned(),
        observation_sha256,
        raw_body: raw_body.to_owned(),
        observed_at_unix_ms: observation.observed_at_unix_ms,
        source_status: plane_status_name(&source.status).to_owned(),
        source_authority_commit_status: plane_status_name(&source.authority_commit_status)
            .to_owned(),
        source_phase: source_phase_name(&source.phase).to_owned(),
        source_owner_identity_status: plane_status_name(&source.owner_identity_status).to_owned(),
        source_database_id: source.database_id,
        source_reservation_id: source.reservation_id,
        source_operation_id: source.operation_id,
        source_event_id: source.event_id,
        source_commit_digest: source.source_commit_digest,
        source_outcome_digest: source.outcome_digest,
        source_request_binding_digest: source.request_binding_digest,
        outbox_status: plane_status_name(&outbox.status).to_owned(),
        outbox_message_id: outbox.message_id,
        outbox_operation_id: outbox.operation_id,
        outbox_tenant_id: outbox.tenant_id,
        inbox_status: plane_status_name(&inbox.status).to_owned(),
        inbox_message_id: inbox.message_id,
        inbox_operation_id: inbox.operation_id,
        inbox_tenant_id: inbox.tenant_id,
        audit_status: plane_status_name(&audit.status).to_owned(),
        audit_receipt_count: audit.receipt_count,
        exact_audit_receipts_verified: audit.exact_receipts_verified,
        read_gate_status: plane_status_name(&read_gate.status).to_owned(),
        positive_authorization_ready: read_gate.positive_authorization_ready,
        liveness_status: plane_status_name(&liveness.status).to_owned(),
        process_reached_handler: liveness.process_reached_handler,
        deployment_node_identity_status: plane_status_name(&deployment.node_identity_status)
            .to_owned(),
        deployment_node_id: deployment.node_id,
        source_receipt_proven,
        audit_correlation_proven,
        outbox_receipt_proven,
        inbox_receipt_proven,
        readiness_proven,
        liveness_proven,
        configured_node_identity_proven,
        tenant_scope_observed: correlation.tenant_id == expected_tenant_id
            && correlation.card_id == expected_card_id,
    };
    if evidence.source_receipt_proven && evidence.audit_correlation_proven {
        Ok(evidence)
    } else {
        Err("observation_durable_planes_incomplete".to_owned())
    }
}

fn plane_status_name(status: &ProductionPlaneStatus) -> &'static str {
    match status {
        ProductionPlaneStatus::Proven => "PROVEN",
        ProductionPlaneStatus::Pending => "PENDING",
        ProductionPlaneStatus::Unknown => "UNKNOWN",
    }
}

fn source_phase_name(phase: &ProductionSourcePhase) -> &'static str {
    match phase {
        ProductionSourcePhase::Staged => "STAGED",
        ProductionSourcePhase::SourceCommitDurable => "SOURCE_COMMIT_DURABLE",
        ProductionSourcePhase::AuthorityCommitted => "AUTHORITY_COMMITTED",
        ProductionSourcePhase::Published => "PUBLISHED",
        ProductionSourcePhase::Completed => "COMPLETED",
        ProductionSourcePhase::Quarantined => "QUARANTINED",
        ProductionSourcePhase::Unknown => "UNKNOWN",
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionApiResponse {
    success: bool,
    code: i32,
    message: String,
    data: Option<ProductionS15AuthorizationObservation>,
    error_type: Option<String>,
    decision: Option<String>,
    reason_code: Option<String>,
    required_permission: Option<String>,
    request_path: Option<String>,
    request_method: Option<String>,
    timestamp: i64,
    trace_id: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionS15AuthorizationObservation {
    schema: String,
    correlation: ProductionObservationCorrelation,
    observed_at_unix_ms: i64,
    source: ProductionSourceObservation,
    outbox: ProductionMessageObservation,
    inbox: ProductionMessageObservation,
    audit: ProductionAuditObservation,
    read_gate: ProductionReadGateObservation,
    liveness: ProductionLivenessObservation,
    authority_frontier: ProductionAuthorityFrontierObservation,
    deployment: ProductionDeploymentObservation,
}

#[derive(Clone)]
struct ProductionObservationCorrelation {
    run_id: String,
    run_id_binding: ProductionPlaneStatus,
    operation_id: String,
    reservation_id: String,
    message_id: String,
    tenant_id: i64,
    card_id: i64,
}

impl<'de> Deserialize<'de> for ProductionObservationCorrelation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CorrelationVisitor;

        impl<'de> serde::de::Visitor<'de> for CorrelationVisitor {
            type Value = ProductionObservationCorrelation;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a unique S15 observation correlation object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                const FIELDS: &[&str] = &[
                    "runId",
                    "runIdBinding",
                    "operationId",
                    "reservationId",
                    "messageId",
                    "tenantId",
                    "cardId",
                ];
                let mut run_id = None;
                let mut run_id_binding = None;
                let mut operation_id = None;
                let mut reservation_id = None;
                let mut message_id = None;
                let mut tenant_id = None;
                let mut card_id = None;
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "runId" => {
                            if run_id.is_some() {
                                return Err(serde::de::Error::duplicate_field("runId"));
                            }
                            run_id = Some(map.next_value()?);
                        }
                        "runIdBinding" => {
                            if run_id_binding.is_some() {
                                return Err(serde::de::Error::duplicate_field("runIdBinding"));
                            }
                            run_id_binding = Some(map.next_value()?);
                        }
                        "operationId" => {
                            if operation_id.is_some() {
                                return Err(serde::de::Error::duplicate_field("operationId"));
                            }
                            operation_id = Some(map.next_value()?);
                        }
                        "reservationId" => {
                            if reservation_id.is_some() {
                                return Err(serde::de::Error::duplicate_field("reservationId"));
                            }
                            reservation_id = Some(map.next_value()?);
                        }
                        "messageId" => {
                            if message_id.is_some() {
                                return Err(serde::de::Error::duplicate_field("messageId"));
                            }
                            message_id = Some(map.next_value()?);
                        }
                        "tenantId" => {
                            if tenant_id.is_some() {
                                return Err(serde::de::Error::duplicate_field("tenantId"));
                            }
                            tenant_id = Some(map.next_value()?);
                        }
                        "cardId" => {
                            if card_id.is_some() {
                                return Err(serde::de::Error::duplicate_field("cardId"));
                            }
                            card_id = Some(map.next_value()?);
                        }
                        _ => return Err(serde::de::Error::unknown_field(&field, FIELDS)),
                    }
                }
                Ok(Self::Value {
                    run_id: run_id.ok_or_else(|| serde::de::Error::missing_field("runId"))?,
                    run_id_binding: run_id_binding
                        .ok_or_else(|| serde::de::Error::missing_field("runIdBinding"))?,
                    operation_id: operation_id
                        .ok_or_else(|| serde::de::Error::missing_field("operationId"))?,
                    reservation_id: reservation_id
                        .ok_or_else(|| serde::de::Error::missing_field("reservationId"))?,
                    message_id: message_id
                        .ok_or_else(|| serde::de::Error::missing_field("messageId"))?,
                    tenant_id: tenant_id
                        .ok_or_else(|| serde::de::Error::missing_field("tenantId"))?,
                    card_id: card_id.ok_or_else(|| serde::de::Error::missing_field("cardId"))?,
                })
            }
        }

        deserializer.deserialize_map(CorrelationVisitor)
    }
}

#[derive(Clone, Copy, Eq, PartialEq, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ProductionPlaneStatus {
    Proven,
    Pending,
    Unknown,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ProductionSourcePhase {
    Staged,
    SourceCommitDurable,
    AuthorityCommitted,
    Published,
    Completed,
    Quarantined,
    Unknown,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionSourceObservation {
    status: ProductionPlaneStatus,
    authority_commit_status: ProductionPlaneStatus,
    phase: ProductionSourcePhase,
    owner_identity_status: ProductionPlaneStatus,
    reservation_id: Option<String>,
    operation_id: Option<String>,
    event_id: Option<String>,
    admission_proof_id: Option<String>,
    mutation_kind: Option<String>,
    service_id: Option<String>,
    database_id: Option<String>,
    request_binding_digest: Option<String>,
    source_commit_digest: Option<String>,
    before_image_digest: Option<String>,
    after_image_digest: Option<String>,
    outcome_digest: Option<String>,
    source_generation: Option<u64>,
    revoke_fence: Option<u64>,
    lease_generation: Option<u64>,
    committed_at_unix_seconds: Option<i64>,
    reason_code: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionMessageObservation {
    status: ProductionPlaneStatus,
    message_id: Option<String>,
    operation_id: Option<String>,
    tenant_id: Option<i64>,
    payload_digest: Option<String>,
    durable_state: Option<String>,
    observed_at_unix_ms: Option<i64>,
    reason_code: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionAuditObservation {
    status: ProductionPlaneStatus,
    receipt_count: Option<usize>,
    exact_receipts_verified: Option<bool>,
    observed_at_unix_ms: Option<i64>,
    reason_code: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionReadGateObservation {
    status: ProductionPlaneStatus,
    positive_authorization_ready: Option<bool>,
    hub_authority_state: Option<String>,
    observed_at_unix_ms: i64,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionLivenessObservation {
    status: ProductionPlaneStatus,
    process_reached_handler: bool,
    observed_at_unix_ms: i64,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionAuthorityFrontierObservation {
    status: ProductionPlaneStatus,
    reason_code: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionDeploymentObservation {
    node_identity_status: ProductionPlaneStatus,
    region_id: Option<String>,
    node_id: Option<String>,
    topology_status: ProductionPlaneStatus,
    half: Option<String>,
    controller: Option<String>,
}

/// Overall S15 live-gate verdict — deliberately structurally unable to reach
/// `PASS` from this probe executor alone.
///
/// Semantics (review correction 2026-11-07):
/// - The deployment attestation (17 booleans) only DECLARES environment
///   prerequisites; it is not evidence and is not an input to this verdict.
/// - `evidence_backed` lists requirements supported by raw evidence captured
///   in the run record (probe identity plane, only when the identity
///   postcondition is `PASS`).
/// - `unresolved` lists [`CURRENT_S15_LIVE_REQUIREMENTS`] members without an
///   evidence primitive here; they hold the gate at `BLOCKED`/`UNKNOWN`
///   regardless of any attestation. `unresolved` can only shrink when a
///   future executor records real raw evidence for those planes.
/// - `status` is `PASS` only when `unresolved` is empty — unreachable with
///   the worker-id evidence set (2 of 16 requirements), so four successful
///   probes yield at most an identity-plane `PASS` while the overall S15 gate
///   stays `BLOCKED`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct S15LiveGateVerdict {
    pub status: ReadinessStatus,
    #[serde(rename = "evidenceBacked")]
    pub evidence_backed: Vec<String>,
    #[serde(rename = "unresolved")]
    pub unresolved: Vec<String>,
    /// Same set as `unresolved` (kept under the dispatch-report name).
    pub blockers: Vec<String>,
    pub problems: Vec<String>,
}

pub fn s15_live_gate_verdict(identity: &S15IdentityPostcondition) -> S15LiveGateVerdict {
    s15_live_gate_verdict_with_owner_evidence(identity, &[])
}

/// Combines identity-plane proof with complete, already-authenticated
/// production-owner evidence artifacts. Any duplicate owner claim, owner
/// mismatch, non-PASS postcondition or invalid binding is ignored and remains
/// unresolved. Deployment prerequisite booleans are intentionally absent.
pub fn s15_live_gate_verdict_with_owner_evidence(
    identity: &S15IdentityPostcondition,
    owner_evidence: &[S15OwnerEvidence],
) -> S15LiveGateVerdict {
    let mut evidence_backed: Vec<String> = if identity.status == ReadinessStatus::Pass {
        PROBE_EVIDENCE_REQUIREMENTS
            .iter()
            .map(|requirement| (*requirement).to_owned())
            .collect()
    } else {
        Vec::new()
    };
    let mut seen_owner_requirements = std::collections::BTreeSet::new();
    for evidence in owner_evidence {
        let Some(expected_owner) = expected_s15_evidence_owner(evidence.requirement()) else {
            continue;
        };
        if evidence.owner() == expected_owner
            && evidence.adapter_verified()
            && !evidence.owner_identity().trim().is_empty()
            && evidence.postcondition() == "PASS"
            && !evidence.raw_sha256().is_empty()
            && !evidence.raw_body().is_empty()
            && evidence.raw_body().len() <= MAX_S15_OWNER_EVIDENCE_BYTES
            && is_digest_64_lower(evidence.raw_sha256())
            && is_digest_64_lower(evidence.certificate_hash())
            && is_digest_64_lower(evidence.frontier_digest())
            && evidence.scope().starts_with("CARD:")
            && !evidence.operation_id().is_empty()
            && !evidence.event_id().is_empty()
            && (evidence.requirement() != "run_scoped_provenance"
                || evidence.run_id().starts_with("authz-validation-")
                    && !evidence.operation_id().is_empty()
                    && !evidence.event_id().is_empty())
            && seen_owner_requirements.insert(evidence.requirement())
        {
            evidence_backed.push(evidence.requirement().to_owned());
        }
    }
    evidence_backed.sort();
    evidence_backed.dedup();
    let unresolved: Vec<String> = CURRENT_S15_LIVE_REQUIREMENTS
        .iter()
        .copied()
        .filter(|requirement| !evidence_backed.iter().any(|backed| backed == requirement))
        .map(str::to_owned)
        .collect();
    let owner_unknown = owner_evidence.iter().any(|evidence| {
        CURRENT_S15_LIVE_REQUIREMENTS.contains(&evidence.requirement())
            && evidence.postcondition() == "UNKNOWN"
    });
    let status = if unresolved.is_empty() {
        match identity.status {
            ReadinessStatus::Pass => ReadinessStatus::Pass,
            ReadinessStatus::Unknown => ReadinessStatus::Unknown,
            _ => ReadinessStatus::Blocked,
        }
    } else if identity.status == ReadinessStatus::Unknown || owner_unknown {
        ReadinessStatus::Unknown
    } else {
        ReadinessStatus::Blocked
    };
    let mut problems = identity.problems.clone();
    if owner_unknown {
        problems.push("owner_evidence_unknown_or_interrupted".to_owned());
    }
    S15LiveGateVerdict {
        status,
        evidence_backed,
        unresolved: unresolved.clone(),
        blockers: unresolved,
        problems,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_adapter_contract::{GATEWAY_AUTH_VERIFIED, GATEWAY_V3_PREFIX};
    use crate::remaining_contracts::LivePrerequisites;
    use serde_json::json;

    const RUN_ID: &str = "authz-validation-s15-live-20261107";
    const TOKEN: &str = "run-scoped-test-control-token";

    fn actor() -> Actor {
        Actor {
            user_id: "probe-actor".to_owned(),
            identity_card: "ic-1".to_owned(),
            user_card: "uc-1".to_owned(),
            domain: "domain-1".to_owned(),
            tenant: "tenant-1".to_owned(),
        }
    }

    fn key() -> Vec<u8> {
        b"gateway-hmac-key".to_vec()
    }

    fn token() -> S15Secret {
        S15Secret::new(TOKEN.to_owned()).expect("token")
    }

    fn coordinator() -> S15LiveCoordinator {
        S15LiveCoordinator::new(RUN_ID, token(), 5_000, 3).expect("coordinator")
    }

    fn all_endpoints() -> S15NodeEndpoints {
        S15NodeEndpoints::from_pairs(&[
            ("AL1", "https://al1.internal".to_owned()),
            ("AL2", "https://al2.internal".to_owned()),
            ("AL3", "https://al3.internal".to_owned()),
            ("AL4", "https://al4.internal".to_owned()),
        ])
        .expect("endpoints")
    }

    fn identity_json(node: &str, worker: &str) -> String {
        // Process identity is per-node distinct (numeric hex suffix derived
        // from the worker label); the config fingerprint legitimately repeats
        // across nodes running the same configuration.
        let suffix = worker.trim_start_matches('w');
        let process_hash = format!("{}{:0>2}", "b".repeat(62), suffix);
        json!({
            "nodeId": node,
            "workerId": worker,
            "configFingerprint": "a".repeat(64),
            "jvmStartTime": "1699000000000",
            "processIdentityHash": process_hash,
        })
        .to_string()
    }

    /// Fake transport that records observed plans and serves canned responses
    /// in order; exhausted fakes surface a transport error like a dead peer.
    struct FakeTransport {
        responses: std::collections::VecDeque<Result<ProbeResponse, String>>,
        observed: Vec<ProbeRequest>,
    }

    impl FakeTransport {
        fn serving(status: u16, body: String) -> Self {
            Self::with_responses(vec![Ok(ProbeResponse { status, body })])
        }

        fn serving_repeated(status: u16, body: String, times: usize) -> Self {
            Self::with_responses(
                (0..times)
                    .map(|_| {
                        Ok(ProbeResponse {
                            status,
                            body: body.clone(),
                        })
                    })
                    .collect(),
            )
        }

        fn failing(detail: &str, times: usize) -> Self {
            Self::with_responses(
                (0..times)
                    .map(|_| Err(detail.to_owned()) as Result<ProbeResponse, String>)
                    .collect(),
            )
        }

        fn with_responses(responses: Vec<Result<ProbeResponse, String>>) -> Self {
            Self {
                responses: responses.into(),
                observed: Vec::new(),
            }
        }
    }

    impl ProbeTransport for FakeTransport {
        fn request(&mut self, plan: &ProbeRequest) -> Result<ProbeResponse, String> {
            self.observed.push(ProbeRequest {
                url: plan.url.clone(),
                headers: plan.headers.clone(),
                timeout_ms: plan.timeout_ms,
            });
            self.responses
                .pop_front()
                .unwrap_or_else(|| Err("fake_response_exhausted".to_owned()))
        }
    }

    #[test]
    fn probe_allowlist_is_exactly_the_four_s15_nodes() {
        assert_eq!(
            s15_probe_allowlist(),
            vec!["AL1", "AL2", "AL3", "AL4"],
            "protected node identity is the frozen four-node S15 topology"
        );
    }

    #[test]
    fn build_probe_request_targets_exactly_the_frozen_probe() {
        let coordinator = coordinator();
        let endpoints = all_endpoints();
        let plan = coordinator
            .build_probe_request(
                &actor(),
                &key(),
                &endpoints,
                "AL1",
                "s15-al1-1-abcdef",
                "1700000000000",
            )
            .expect("plan");
        // The only reachable production surface is the frozen read-only probe;
        // business routes are structurally unreachable because the path is a
        // compile-time constant pinned to the production route segment.
        assert_eq!(
            plan.url,
            "https://al1.internal/main/api/v1/internal/test-control/worker-id"
        );
        assert_eq!(S15_PROBE_PATH, "/internal/test-control/worker-id");
        assert!(plan.headers.contains_key("x-gateway-signature"));
        assert_eq!(
            plan.headers
                .get(TEST_CONTROL_TOKEN_HEADER)
                .map(String::as_str),
            Some(TOKEN)
        );
        assert_ne!(S15_PROBE_PATH, "/main/api/v1/permission-rules/check");
        let error = S15LiveError::NonProbePath("/main/api/v1/user-cards".to_owned());
        assert!(error.to_string().contains("/main/api/v1/user-cards"));
    }

    #[test]
    fn build_probe_request_rejects_malformed_request_ids_nodes_and_timestamps() {
        let coordinator = coordinator();
        let endpoints = all_endpoints();
        assert!(matches!(
            coordinator.build_probe_request(
                &actor(),
                &key(),
                &endpoints,
                "AL9",
                "s15-al9-1-x",
                "1700000000000"
            ),
            Err(S15LiveError::UnknownNodeAlias(_))
        ));
        assert!(matches!(
            coordinator.build_probe_request(
                &actor(),
                &key(),
                &endpoints,
                "AL1",
                "bad id with spaces",
                "1700000000000"
            ),
            Err(S15LiveError::NonProbePath(_))
        ));
        assert!(matches!(
            coordinator.build_probe_request(
                &actor(),
                &key(),
                &endpoints,
                "AL1",
                "",
                "1700000000000"
            ),
            Err(S15LiveError::NonProbePath(_))
        ));
        assert!(matches!(
            coordinator.build_probe_request(
                &actor(),
                &key(),
                &endpoints,
                "AL1",
                "s15-al1-1-x",
                "17O000000000"
            ),
            Err(S15LiveError::InvalidTimestamp)
        ));
        let partial = S15NodeEndpoints::from_pairs(&[("AL2", "https://al2".to_owned())])
            .expect("partial endpoints");
        assert!(matches!(
            coordinator.build_probe_request(
                &actor(),
                &key(),
                &partial,
                "AL1",
                "s15-al1-1-x",
                "1700000000000"
            ),
            Err(S15LiveError::NodeMissingEndpoint(_))
        ));
    }

    #[test]
    fn node_endpoints_accept_only_s15_nodes_and_wellformed_origins() {
        let good = S15NodeEndpoints::from_pairs(&[("AL2", "http://127.0.0.1:8080".to_owned())]);
        assert!(good.is_ok());
        assert_eq!(
            S15LiveError::UnknownNodeAlias("AL9".into()).to_string(),
            "unknown_node_alias:AL9"
        );
        assert!(S15NodeEndpoints::from_pairs(&[("AL9", "https://x".to_owned())]).is_err());
        assert!(S15NodeEndpoints::from_pairs(&[("AL1", "https://x/".to_owned())]).is_err());
        assert!(S15NodeEndpoints::from_pairs(&[("AL1", "https://x/?a=b".to_owned())]).is_err());
        assert!(S15NodeEndpoints::from_pairs(&[("AL1", "ftp://x".to_owned())]).is_err());
        assert!(
            S15NodeEndpoints::from_pairs(&[("AL1", "https://x .internal".to_owned())]).is_err()
        );
        assert!(S15NodeEndpoints::from_pairs(&[
            ("AL1", "https://a".to_owned()),
            ("AL1", "https://b".to_owned()),
        ])
        .is_err());
    }

    #[test]
    fn coordinator_construction_validates_campaign_and_budgets() {
        assert!(matches!(
            S15LiveCoordinator::new("not-a-campaign-id", token(), 1_000, 1),
            Err(S15LiveError::InvalidCampaignId)
        ));
        assert!(matches!(
            S15LiveCoordinator::new(RUN_ID, token(), 0, 1),
            Err(S15LiveError::InvalidTimeout(0))
        ));
        assert!(matches!(
            S15LiveCoordinator::new(RUN_ID, token(), MAX_PROBE_TIMEOUT_MS + 1, 1),
            Err(S15LiveError::InvalidTimeout(_))
        ));
        assert!(matches!(
            S15LiveCoordinator::new(RUN_ID, token(), 1_000, 0),
            Err(S15LiveError::InvalidAttemptBudget(0))
        ));
        assert!(matches!(
            S15LiveCoordinator::new(RUN_ID, token(), 1_000, MAX_PROBE_ATTEMPTS_PER_NODE + 1),
            Err(S15LiveError::InvalidAttemptBudget(4))
        ));
        assert!(S15Secret::new(String::new()).is_err());
    }

    #[test]
    fn request_ids_are_run_scoped_deterministic_and_signing_safe() {
        let coordinator = coordinator();
        let first = coordinator.request_id_for("AL1", 1);
        let second = S15LiveCoordinator::new(RUN_ID, token(), 1_000, 1)
            .expect("coordinator")
            .request_id_for("AL1", 1);
        assert_eq!(first, second, "same run yields the same operation id");
        assert_ne!(first, coordinator.request_id_for("AL2", 1));
        assert_ne!(first, coordinator.request_id_for("AL1", 2));
        assert!(first.len() <= 64);
        assert!(first
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/')));
        assert!(first.starts_with("s15-al1-1-"));
    }

    #[test]
    fn probe_success_records_raw_body_verbatim_and_confirms_identity() {
        let coordinator = coordinator();
        let mut transport = FakeTransport::serving(200, identity_json("AL1", "worker-al1"));
        let attempt = coordinator
            .probe_node(
                &mut transport,
                &actor(),
                &key(),
                &all_endpoints(),
                "AL1",
                "1700000000000",
            )
            .expect("attempt");
        assert_eq!(attempt.status, ReadinessStatus::Pass);
        assert_eq!(attempt.node, "AL1");
        assert_eq!(attempt.half, "A");
        assert_eq!(attempt.database_id, "DB1");
        assert_eq!(attempt.campaign_id, RUN_ID);
        assert_eq!(attempt.probe_path, S15_PROBE_PATH);
        assert_eq!(attempt.observations.len(), 1);
        match &attempt.observations[0].outcome {
            S15ProbeOutcome::Http { status, raw_body } => {
                assert_eq!(*status, 200);
                assert_eq!(
                    raw_body,
                    &identity_json("AL1", "worker-al1"),
                    "raw artifact verbatim"
                );
            }
            other => panic!("expected http outcome, got {other:?}"),
        }
        let identity = attempt.identity.expect("identity");
        assert_eq!(identity.node_id, "AL1");
        assert_eq!(identity.worker_id, "worker-al1");
        assert_eq!(transport.observed.len(), 1);
        assert_eq!(transport.observed[0].timeout_ms, 5_000);
    }

    #[test]
    fn half_b_node_records_half_and_database_metadata() {
        let coordinator = coordinator();
        let mut transport = FakeTransport::serving(200, identity_json("AL3", "worker-al3"));
        let attempt = coordinator
            .probe_node(
                &mut transport,
                &actor(),
                &key(),
                &all_endpoints(),
                "AL3",
                "1700000000000",
            )
            .expect("attempt");
        assert_eq!(attempt.half, "B");
        assert_eq!(attempt.database_id, "DB2");
    }

    #[test]
    fn identity_mismatch_fails_closed_without_pass() {
        let coordinator = coordinator();
        let mut transport = FakeTransport::serving(200, identity_json("AL2", "worker-al2"));
        let attempt = coordinator
            .probe_node(
                &mut transport,
                &actor(),
                &key(),
                &all_endpoints(),
                "AL1",
                "1700000000000",
            )
            .expect("attempt");
        assert_eq!(attempt.status, ReadinessStatus::Blocked);
        assert_eq!(attempt.reason, "node_identity_mismatch");
        assert!(attempt.identity.is_none());
        assert_eq!(
            attempt.observations.len(),
            1,
            "deterministic outcome stops retry"
        );
    }

    #[test]
    fn deterministic_4xx_is_blocked_and_not_retried() {
        let coordinator = coordinator();
        for status in [403_u16, 404, 429] {
            let mut transport = FakeTransport::serving(status, "{}".to_owned());
            let attempt = coordinator
                .probe_node(
                    &mut transport,
                    &actor(),
                    &key(),
                    &all_endpoints(),
                    "AL1",
                    "1700000000000",
                )
                .expect("attempt");
            assert_eq!(attempt.status, ReadinessStatus::Blocked, "{status}");
            assert_eq!(attempt.reason, format!("http_{status}"));
            assert_eq!(attempt.observations.len(), 1);
        }
    }

    #[test]
    fn server_errors_retry_within_budget_then_stay_unknown() {
        let coordinator = coordinator();
        let mut transport = FakeTransport::serving_repeated(503, String::new(), 3);
        let attempt = coordinator
            .probe_node(
                &mut transport,
                &actor(),
                &key(),
                &all_endpoints(),
                "AL1",
                "1700000000000",
            )
            .expect("attempt");
        assert_eq!(attempt.status, ReadinessStatus::Unknown);
        assert_eq!(attempt.reason, "http_503_after_budget");
        assert_eq!(
            attempt.observations.len(),
            3,
            "budget is finite and used up"
        );
        for observation in &attempt.observations {
            assert!(matches!(
                observation.outcome,
                S15ProbeOutcome::Http { status: 503, .. }
            ));
        }
        assert!(attempt.identity.is_none());
    }

    #[test]
    fn transport_errors_exhaust_budget_then_stay_unknown() {
        let coordinator = coordinator();
        let mut transport = FakeTransport::failing("connection refused", 2);
        let attempt = coordinator
            .probe_node(
                &mut transport,
                &actor(),
                &key(),
                &all_endpoints(),
                "AL4",
                "1700000000000",
            )
            .expect("attempt");
        assert_eq!(attempt.status, ReadinessStatus::Unknown);
        assert_eq!(attempt.reason, "transport_error_after_budget");
        assert_eq!(
            attempt.observations.len(),
            3,
            "unknown never auto-replays past budget"
        );
        for (index, observation) in attempt.observations.iter().enumerate() {
            assert_eq!(observation.attempt, index + 1);
            assert!(matches!(
                observation.outcome,
                S15ProbeOutcome::TransportError { .. }
            ));
        }
    }

    #[test]
    fn unparseable_or_foreign_json_body_is_blocked() {
        let coordinator = coordinator();
        let mut transport = FakeTransport::serving(200, "not json".to_owned());
        let attempt = coordinator
            .probe_node(
                &mut transport,
                &actor(),
                &key(),
                &all_endpoints(),
                "AL1",
                "1700000000000",
            )
            .expect("attempt");
        assert_eq!(attempt.status, ReadinessStatus::Blocked);
        assert_eq!(attempt.reason, "response_not_contract_json");
    }

    #[test]
    fn postcondition_requires_all_four_nodes_with_distinct_identities() {
        let coordinator = coordinator();
        let probe = |node: &'static str, worker: &str| {
            let mut transport = FakeTransport::serving(200, identity_json(node, worker));
            coordinator
                .probe_node(
                    &mut transport,
                    &actor(),
                    &key(),
                    &all_endpoints(),
                    node,
                    "1700000000000",
                )
                .expect("attempt")
        };
        let good = [
            probe("AL1", "w1"),
            probe("AL2", "w2"),
            probe("AL3", "w3"),
            probe("AL4", "w4"),
        ];
        let pass = evaluate_identity_postcondition(&good);
        assert_eq!(pass.status, ReadinessStatus::Pass);
        assert!(pass.problems.is_empty());

        let duplicate_worker = [
            probe("AL1", "w1"),
            probe("AL2", "w1"),
            probe("AL3", "w3"),
            probe("AL4", "w4"),
        ];
        let duplicated = evaluate_identity_postcondition(&duplicate_worker);
        assert_eq!(duplicated.status, ReadinessStatus::Blocked);
        assert!(duplicated
            .problems
            .iter()
            .any(|problem| problem == "duplicate_worker_id:AL2"));

        let partial = evaluate_identity_postcondition(&good[..3]);
        assert_eq!(partial.status, ReadinessStatus::Blocked);
        assert!(partial
            .problems
            .iter()
            .any(|problem| problem == "missing_node_attempt:AL4"));
        assert!(partial
            .problems
            .iter()
            .any(|problem| problem == "missing_identity_payload"));
    }

    #[test]
    fn unknown_node_attempt_keeps_postcondition_unknown() {
        let coordinator = coordinator();
        let mut transport = FakeTransport::failing("down", 3);
        let unknown_node = coordinator
            .probe_node(
                &mut transport,
                &actor(),
                &key(),
                &all_endpoints(),
                "AL1",
                "1700000000000",
            )
            .expect("attempt");
        assert_eq!(unknown_node.status, ReadinessStatus::Unknown);
        let postcondition = evaluate_identity_postcondition(&[unknown_node]);
        assert_eq!(postcondition.status, ReadinessStatus::Unknown);
        assert!(postcondition
            .problems
            .iter()
            .any(|problem| problem == "unknown_node_attempt:AL1"));
    }

    #[test]
    fn malformed_digest_shapes_block_the_postcondition() {
        let coordinator = coordinator();
        let bad_fingerprint = json!({
            "nodeId": "AL1",
            "workerId": "w1",
            "configFingerprint": "short",
            "jvmStartTime": "1700000000000",
            "processIdentityHash": "b".repeat(64),
        })
        .to_string();
        let mut transport = FakeTransport::serving(200, bad_fingerprint);
        let attempt = coordinator
            .probe_node(
                &mut transport,
                &actor(),
                &key(),
                &all_endpoints(),
                "AL1",
                "1700000000000",
            )
            .expect("attempt");
        // Probe-level identity matches; the digest shape is a postcondition concern.
        assert_eq!(attempt.status, ReadinessStatus::Pass);
        let postcondition = evaluate_identity_postcondition(&[attempt]);
        assert_eq!(postcondition.status, ReadinessStatus::Blocked);
        assert!(postcondition
            .problems
            .iter()
            .any(|problem| problem == "malformed_config_fingerprint:AL1"));
    }

    #[test]
    fn identity_pass_yields_probe_pass_but_overall_gate_stays_blocked() {
        let pass_identity = S15IdentityPostcondition {
            status: ReadinessStatus::Pass,
            problems: Vec::new(),
        };
        let verdict = s15_live_gate_verdict(&pass_identity);
        // Worker-id only backs signed identity and the observed four-node
        // identity plane; it does not establish serving readiness or run provenance.
        assert_eq!(
            verdict.evidence_backed,
            vec!["four_node_state".to_owned(), "signed_identity".to_owned()]
        );
        assert!(!verdict.evidence_backed.contains(&"readiness".to_owned()));
        assert!(!verdict
            .evidence_backed
            .contains(&"run_scoped_provenance".to_owned()));
        // Overall gate: the 14 requirements without a distinct evidence
        // primitive stay unresolved — a successful identity probe cannot lift them.
        assert_eq!(verdict.status, ReadinessStatus::Blocked);
        assert_eq!(
            verdict.unresolved.len(),
            CURRENT_S15_LIVE_REQUIREMENTS.len() - PROBE_EVIDENCE_REQUIREMENTS.len()
        );
        assert_eq!(verdict.blockers, verdict.unresolved);
        for expected_unresolved in [
            "approved_deployment",
            "readiness",
            "run_scoped_provenance",
            "controller",
            "two_half_state",
            "two_database_state",
            "same_db_custom_channel",
            "cross_db_rabbitmq",
            "current_transport",
            "durable_evidence",
            "tenant_isolation",
            "audit_correlation",
            "half_authority_fence",
            "split_brain_fail_closed",
        ] {
            assert!(
                verdict.unresolved.contains(&expected_unresolved.to_owned()),
                "{expected_unresolved} must remain unresolved"
            );
        }
    }

    #[test]
    fn all_true_attestation_plus_four_successful_probes_cannot_pass_the_gate() {
        // Review-correction negative: even when the deployment attestation
        // declares every prerequisite true (the maximum a boolean file can
        // claim) and all four probes succeed, the overall S15 gate stays
        // BLOCKED — attestation booleans are not evidence and are not an
        // input to the verdict at all.
        let pass_identity = S15IdentityPostcondition {
            status: ReadinessStatus::Pass,
            problems: Vec::new(),
        };
        for _attestation in [LivePrerequisites::all(), LivePrerequisites::none()] {
            let verdict = s15_live_gate_verdict(&pass_identity);
            assert_ne!(
                verdict.status,
                ReadinessStatus::Pass,
                "attestation booleans must never elevate the overall gate"
            );
            assert_eq!(verdict.status, ReadinessStatus::Blocked);
            assert!(!verdict.unresolved.is_empty());
        }
    }

    #[test]
    fn probe_evidence_allowlist_is_a_strict_subset_without_fault_or_transport_planes() {
        assert!(PROBE_EVIDENCE_REQUIREMENTS
            .iter()
            .all(|requirement| CURRENT_S15_LIVE_REQUIREMENTS.contains(requirement)));
        // The probe records no evidence primitive for fault injection, the
        // custom same-database channel, cross-database RabbitMQ, transport
        // state, durable receipts or the fail-closed fences: booleans about
        // those planes can never be closed by this executor.
        let forbidden: [&str; 9] = [
            "readiness",
            "run_scoped_provenance",
            "controller",
            "same_db_custom_channel",
            "cross_db_rabbitmq",
            "current_transport",
            "durable_evidence",
            "half_authority_fence",
            "split_brain_fail_closed",
        ];
        assert!(PROBE_EVIDENCE_REQUIREMENTS
            .iter()
            .all(|requirement| !forbidden.contains(requirement)));
        assert!(PROBE_EVIDENCE_REQUIREMENTS.len() < CURRENT_S15_LIVE_REQUIREMENTS.len());
    }

    #[test]
    fn identity_unknown_keeps_gate_unknown_with_no_evidence_backed() {
        let unknown_identity = S15IdentityPostcondition {
            status: ReadinessStatus::Unknown,
            problems: vec!["unknown_node_attempt:AL1".to_owned()],
        };
        let verdict = s15_live_gate_verdict(&unknown_identity);
        assert_eq!(verdict.status, ReadinessStatus::Unknown);
        assert!(verdict.evidence_backed.is_empty());
        assert_eq!(
            verdict.unresolved.len(),
            CURRENT_S15_LIVE_REQUIREMENTS.len()
        );
        assert!(verdict
            .problems
            .contains(&"unknown_node_attempt:AL1".to_owned()));

        let blocked_identity = S15IdentityPostcondition {
            status: ReadinessStatus::Blocked,
            problems: vec!["node_not_pass:AL1:node_identity_mismatch".to_owned()],
        };
        let verdict = s15_live_gate_verdict(&blocked_identity);
        assert_eq!(verdict.status, ReadinessStatus::Blocked);
        assert!(verdict.evidence_backed.is_empty());
    }

    fn hex_digest(value: &str) -> String {
        Sha256::digest(value.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn owner_evidence_body(
        requirement: &str,
        owner: &str,
        run_id: &str,
        scope: &str,
        operation_id: &str,
        observed_at_ms: i64,
        expires_at_ms: i64,
    ) -> String {
        json!({
            "requirement": requirement,
            "owner": owner,
                "runId": run_id,
            "observedAtUnixMs": observed_at_ms,
            "expiresAtUnixMs": expires_at_ms,
            "scope": scope,
            "operationId": operation_id,
            "eventId": "event-9",
            "certificateHash": "a".repeat(64),
            "frontierDigest": "b".repeat(64),
            "auditCorrelationId": "audit-9",
            "postcondition": "PASS",
            "evidence": {
                "scope": scope,
                "operationId": operation_id,
                "eventId": "event-9",
                "certificateHash": "a".repeat(64),
                "frontierDigest": "b".repeat(64),
                "sourceCommitDigest": "c".repeat(64),
                "sourceOutcomeDigest": "d".repeat(64),
                "auditCorrelationId": "audit-9",
                "postcondition": "PASS"
            }
        })
        .to_string()
    }

    fn observation_correlation() -> S15ObservationCorrelation<'static> {
        S15ObservationCorrelation {
            run_id: RUN_ID,
            operation_id: "operation-9",
            reservation_id: "reservation-9",
            message_id: "message-9",
            tenant_id: 17,
            card_id: 29,
        }
    }

    fn typed_observation_body() -> String {
        json!({
            "success": true,
            "code": 200,
            "message": "ok",
            "data": {
                "schema": "astral.s15.authorization-observation/v1",
                "correlation": {
                    "runId": RUN_ID,
                    "runIdBinding": "UNKNOWN",
                    "operationId": "operation-9",
                    "reservationId": "reservation-9",
                    "messageId": "message-9",
                    "tenantId": 17,
                    "cardId": 29
                },
                "observedAtUnixMs": 1_700_000_001_000_i64,
                "source": {
                    "status": "PROVEN",
                    "authorityCommitStatus": "UNKNOWN",
                    "phase": "COMPLETED",
                    "ownerIdentityStatus": "PROVEN",
                    "reservationId": "reservation-9",
                    "operationId": "operation-9",
                    "eventId": "event-9",
                    "admissionProofId": "admission-9",
                    "mutationKind": "CREATE",
                    "serviceId": "trustgraph",
                    "databaseId": "DB1",
                    "requestBindingDigest": "a".repeat(64),
                    "sourceCommitDigest": "b".repeat(64),
                    "beforeImageDigest": "c".repeat(64),
                    "afterImageDigest": "d".repeat(64),
                    "outcomeDigest": "e".repeat(64),
                    "sourceGeneration": 1,
                    "revokeFence": 0,
                    "leaseGeneration": 1,
                    "committedAtUnixSeconds": 1_700_000_000_i64,
                    "reasonCode": null
                },
                "outbox": {
                    "status": "UNKNOWN",
                    "messageId": null,
                    "operationId": null,
                    "tenantId": null,
                    "payloadDigest": null,
                    "durableState": null,
                    "observedAtUnixMs": null,
                    "reasonCode": "outbox_not_observed"
                },
                "inbox": {
                    "status": "UNKNOWN",
                    "messageId": null,
                    "operationId": null,
                    "tenantId": null,
                    "payloadDigest": null,
                    "durableState": null,
                    "observedAtUnixMs": null,
                    "reasonCode": "inbox_not_observed"
                },
                "audit": {
                    "status": "PROVEN",
                    "receiptCount": 1,
                    "exactReceiptsVerified": true,
                    "observedAtUnixMs": 1_700_000_001_000_i64,
                    "reasonCode": null
                },
                "readGate": {
                    "status": "UNKNOWN",
                    "positiveAuthorizationReady": null,
                    "hubAuthorityState": null,
                    "observedAtUnixMs": 0
                },
                "liveness": {
                    "status": "UNKNOWN",
                    "processReachedHandler": false,
                    "observedAtUnixMs": 0
                },
                "authorityFrontier": {
                    "status": "UNKNOWN",
                    "reasonCode": "authority_frontier_not_verified"
                },
                "deployment": {
                    "nodeIdentityStatus": "UNKNOWN",
                    "regionId": null,
                    "nodeId": null,
                    "topologyStatus": "UNKNOWN",
                    "half": null,
                    "controller": null
                }
            },
            "timestamp": 1_700_000_001_i64,
            "traceId": "trace-9"
        })
        .to_string()
    }

    #[test]
    fn observation_request_binds_exactly_six_query_dimensions_once() {
        let correlation = observation_correlation();
        let request = build_s15_authorization_observation_request(
            &actor(),
            &key(),
            &all_endpoints(),
            5_000,
            "AL1",
            &correlation,
            &S15ObservationSigning {
                request_id: "observation-request-9",
                timestamp_ms: "1700000000000",
            },
        )
        .expect("observation request");
        let query = request.plan.url.split_once('?').expect("query").1;
        let pairs: Vec<_> = query.split('&').collect();
        assert_eq!(pairs.len(), 6);
        assert_eq!(
            query,
            "runId=authz-validation-s15-live-20261107&operationId=operation-9&reservationId=reservation-9&messageId=message-9&tenantId=17&cardId=29"
        );
        let mut counts = std::collections::BTreeMap::new();
        for pair in pairs {
            let (name, _) = pair.split_once('=').expect("query pair");
            *counts.entry(name).or_insert(0usize) += 1;
        }
        assert_eq!(
            counts,
            std::collections::BTreeMap::from([
                ("runId", 1),
                ("operationId", 1),
                ("reservationId", 1),
                ("messageId", 1),
                ("tenantId", 1),
                ("cardId", 1),
            ])
        );
    }

    #[test]
    fn observation_request_rejects_malformed_foreign_and_empty_correlation() {
        let endpoints = all_endpoints();
        let signing = S15ObservationSigning {
            request_id: "observation-request-9",
            timestamp_ms: "1700000000000",
        };
        let build = |correlation: &S15ObservationCorrelation<'_>, node: &'static str| {
            build_s15_authorization_observation_request(
                &actor(),
                &key(),
                &endpoints,
                5_000,
                node,
                correlation,
                &signing,
            )
        };

        let mut malformed = observation_correlation();
        malformed.operation_id = "operation with spaces";
        assert_eq!(
            build(&malformed, "AL1").unwrap_err(),
            "observation_operation_id_invalid"
        );

        let mut empty = observation_correlation();
        empty.reservation_id = "";
        assert_eq!(
            build(&empty, "AL1").unwrap_err(),
            "observation_reservation_id_invalid"
        );

        let mut empty_run = observation_correlation();
        empty_run.run_id = "";
        assert_eq!(
            build(&empty_run, "AL1").unwrap_err(),
            "observation_run_id_invalid"
        );

        let mut empty_message = observation_correlation();
        empty_message.message_id = "";
        assert_eq!(
            build(&empty_message, "AL1").unwrap_err(),
            "observation_message_id_invalid"
        );

        let mut invalid_scope = observation_correlation();
        invalid_scope.tenant_id = 0;
        assert_eq!(
            build(&invalid_scope, "AL1").unwrap_err(),
            "observation_scope_invalid"
        );

        assert_eq!(
            build(&observation_correlation(), "AL9").unwrap_err(),
            "unknown_observation_node"
        );
    }

    #[test]
    fn typed_observation_decoder_rejects_foreign_correlation_dimensions() {
        let expected = observation_correlation();
        for (field, value) in [
            ("runId", json!("authz-validation-foreign")),
            ("operationId", json!("foreign-operation")),
            ("reservationId", json!("foreign-reservation")),
            ("messageId", json!("foreign-message")),
            ("tenantId", json!(18)),
            ("cardId", json!(30)),
        ] {
            let mut body = serde_json::from_str::<Value>(&typed_observation_body()).unwrap();
            body["data"]["correlation"][field] = value;
            assert_eq!(
                parse_s15_authorization_observation(
                    "AL1",
                    &body.to_string(),
                    1_700_000_001_001,
                    &expected,
                )
                .unwrap_err(),
                "observation_correlation_mismatch",
                "foreign {field} must not bind"
            );
        }
    }

    #[test]
    fn typed_observation_decoder_preserves_proven_and_unknown_planes() {
        let expected = observation_correlation();
        let body = typed_observation_body();
        let evidence =
            parse_s15_authorization_observation("AL1", &body, 1_700_000_001_001, &expected)
                .expect("typed production observation");

        assert_eq!(evidence.node, "AL1");
        assert_eq!(evidence.raw_body, body);
        assert!(evidence.source_receipt_proven);
        assert!(evidence.audit_correlation_proven);
        assert!(!evidence.outbox_receipt_proven);
        assert!(!evidence.inbox_receipt_proven);
        assert!(!evidence.readiness_proven);
        assert!(!evidence.liveness_proven);
        assert!(!evidence.configured_node_identity_proven);
        assert!(evidence.tenant_scope_observed);
        assert_eq!(evidence.outbox_status, "UNKNOWN");
        assert_eq!(evidence.inbox_status, "UNKNOWN");
        assert_eq!(evidence.read_gate_status, "UNKNOWN");
        assert_eq!(evidence.liveness_status, "UNKNOWN");
        assert_eq!(evidence.deployment_node_identity_status, "UNKNOWN");

        // A typed observation is partial evidence only. It is not an
        // S15OwnerEvidence and cannot close the overall gate by itself.
        let identity = S15IdentityPostcondition {
            status: ReadinessStatus::Pass,
            problems: Vec::new(),
        };
        let verdict = s15_live_gate_verdict_with_owner_evidence(&identity, &[]);
        assert_eq!(verdict.status, ReadinessStatus::Blocked);
        assert!(!verdict
            .evidence_backed
            .contains(&"durable_evidence".to_owned()));
        assert!(!verdict
            .evidence_backed
            .contains(&"audit_correlation".to_owned()));
    }

    #[test]
    fn typed_observation_decoder_rejects_malformed_empty_and_duplicate_wire_correlation() {
        let expected = observation_correlation();
        assert_eq!(
            parse_s15_authorization_observation("AL1", "not-json", 1_700_000_001_001, &expected,)
                .unwrap_err(),
            "observation_response_invalid"
        );

        let mut empty = serde_json::from_str::<Value>(&typed_observation_body()).unwrap();
        empty["data"]["correlation"]["operationId"] = json!("");
        assert_eq!(
            parse_s15_authorization_observation(
                "AL1",
                &empty.to_string(),
                1_700_000_001_001,
                &expected,
            )
            .unwrap_err(),
            "observation_correlation_mismatch"
        );

        let body = typed_observation_body();
        let duplicate = body.replacen(
            "\"operationId\":\"operation-9\"",
            "\"operationId\":\"operation-9\",\"operationId\":\"operation-9\"",
            1,
        );
        assert_eq!(
            parse_s15_authorization_observation("AL1", &duplicate, 1_700_000_001_001, &expected,)
                .unwrap_err(),
            "observation_response_invalid"
        );
    }
    #[test]
    fn owner_evidence_parser_requires_authenticated_run_scope_operation_and_durable_bindings() {
        let valid = owner_evidence_body(
            "durable_evidence",
            "source_database_owner",
            RUN_ID,
            "CARD:tenant=17:card=29",
            "op-9",
            1_700_000_000_000,
            1_700_000_030_000,
        );
        let transport_proof = S15OwnerTransportProof::synthetic_for_parser_contract_tests(
            "mtls:sha256:owner-cert".to_owned(),
            hex_digest(&valid),
        );
        let evidence = parse_s15_owner_evidence(
            "durable_evidence",
            Some(&transport_proof),
            RUN_ID,
            "CARD:tenant=17:card=29",
            Some("op-9"),
            1_700_000_001_000,
            &valid,
        )
        .expect("valid durable owner artifact");
        assert_eq!(evidence.run_id(), RUN_ID);
        assert_eq!(evidence.operation_id(), "op-9");
        assert_eq!(evidence.event_id(), "event-9");
        assert_eq!(evidence.raw_sha256().len(), 64);
        assert_eq!(evidence.requirement(), "durable_evidence");
        assert_eq!(evidence.scope(), "CARD:tenant=17:card=29");
        assert_eq!(evidence.owner_identity(), "mtls:sha256:owner-cert");
        assert!(evidence.adapter_verified());
        let serialized_before =
            serde_json::to_string(&evidence).expect("serialize parsed evidence");
        let cloned = evidence.clone();
        assert_eq!(cloned.requirement(), evidence.requirement());
        assert_eq!(cloned.scope(), evidence.scope());
        assert_eq!(cloned.operation_id(), evidence.operation_id());
        assert_eq!(cloned.raw_body(), evidence.raw_body());
        assert!(cloned.adapter_verified());
        assert_eq!(
            serde_json::to_string(&cloned).expect("serialize cloned evidence"),
            serialized_before
        );

        let identity_bound = parse_s15_owner_evidence(
            "durable_evidence",
            Some(&transport_proof),
            RUN_ID,
            "CARD:tenant=17:card=29",
            Some("op-9"),
            1_700_000_001_000,
            &valid,
        )
        .expect("transport-authenticated identity supplied by the production adapter");
        assert_eq!(identity_bound.owner_identity, "mtls:sha256:owner-cert");
        assert_eq!(
            parse_s15_owner_evidence(
                "durable_evidence",
                None,
                RUN_ID,
                "CARD:tenant=17:card=29",
                Some("op-9"),
                1_700_000_001_000,
                &valid
            )
            .unwrap_err(),
            "owner_transport_proof_missing"
        );
        assert_eq!(
            parse_s15_owner_evidence(
                "durable_evidence",
                Some(&transport_proof),
                RUN_ID,
                "CARD:tenant=17:card=29",
                None,
                1_700_000_001_000,
                &valid
            )
            .expect("non-optional operation binding")
            .operation_id,
            "op-9"
        );
        let mut operation_mismatch = serde_json::from_str::<Value>(&valid).unwrap();
        operation_mismatch["evidence"]["operationId"] = json!("op-other");
        let operation_mismatch_body = operation_mismatch.to_string();
        let operation_mismatch_proof = S15OwnerTransportProof::synthetic_for_parser_contract_tests(
            "mtls:sha256:owner-cert".to_owned(),
            hex_digest(&operation_mismatch_body),
        );
        assert_eq!(
            parse_s15_owner_evidence(
                "durable_evidence",
                Some(&operation_mismatch_proof),
                RUN_ID,
                "CARD:tenant=17:card=29",
                None,
                1_700_000_001_000,
                &operation_mismatch_body
            )
            .unwrap_err(),
            "operation_id_mismatch"
        );
        assert_eq!(
            parse_s15_owner_evidence(
                "durable_evidence",
                Some(&transport_proof),
                RUN_ID,
                "CARD:tenant=17:card=29",
                Some("op-9"),
                1_700_000_001_000,
                &valid
            )
            .expect("transport-authenticated identity supplied by the production adapter")
            .owner_identity,
            "mtls:sha256:owner-cert"
        );
        assert_eq!(
            parse_s15_owner_evidence(
                "durable_evidence",
                Some(&transport_proof),
                RUN_ID,
                "CARD:tenant=17:card=29",
                Some("op-9"),
                1_700_000_001_000,
                &valid
            )
            .expect("transport-authenticated identity supplied by the production adapter")
            .owner_identity,
            "mtls:sha256:owner-cert"
        );

        let mut mismatched_durable = serde_json::from_str::<Value>(&valid).unwrap();
        mismatched_durable["evidence"]["sourceOutcomeDigest"] = json!("not-a-digest");
        let mismatched_durable_body = mismatched_durable.to_string();
        let mismatched_durable_proof = S15OwnerTransportProof::synthetic_for_parser_contract_tests(
            "mtls:sha256:owner-cert".to_owned(),
            hex_digest(&mismatched_durable_body),
        );
        assert_eq!(
            parse_s15_owner_evidence(
                "durable_evidence",
                Some(&mismatched_durable_proof),
                RUN_ID,
                "CARD:tenant=17:card=29",
                Some("op-9"),
                1_700_000_001_000,
                &mismatched_durable_body
            )
            .unwrap_err(),
            "durable_source_evidence_incomplete"
        );
    }

    #[test]
    fn incomplete_owner_log_is_unknown_and_cannot_lift_all_true_attestation() {
        let identity = S15IdentityPostcondition {
            status: ReadinessStatus::Pass,
            problems: Vec::new(),
        };
        let probes = CURRENT_S15_LIVE_REQUIREMENTS
            .iter()
            .map(|requirement| S15RawOwnerProbe {
                requirement: (*requirement).to_owned(),
                reported_owner_identity: "caller-claimed:mtls:sha256:owner-cert".to_owned(),
                transport_proof: None,
                raw_body: Some(owner_evidence_body(
                    requirement,
                    expected_s15_evidence_owner(requirement).unwrap(),
                    RUN_ID,
                    "CARD:tenant=17:card=29",
                    "op-9",
                    1_700_000_000_000,
                    1_700_000_030_000,
                )),
                log_complete: requirement != &"audit_correlation",
            })
            .collect::<Vec<_>>();
        let collection = collect_s15_owner_evidence(
            &probes,
            RUN_ID,
            "CARD:tenant=17:card=29",
            Some("op-9"),
            1_700_000_001_000,
        );
        assert_eq!(collection.evidence.len(), 0);
        assert_eq!(
            collection.unknown.len(),
            CURRENT_S15_LIVE_REQUIREMENTS.len()
        );
        assert!(collection
            .unknown
            .iter()
            .any(|reason| reason
                == "owner_probe_invalid:signed_identity:owner_transport_proof_missing"));
        assert!(collection
            .unknown
            .iter()
            .any(|reason| reason == "owner_probe_log_incomplete:audit_correlation"));
        // Caller-supplied identity is retained only as untrusted metadata; it
        // cannot become evidence without a production transport proof.
        let verdict = s15_live_gate_verdict_with_owner_evidence(&identity, &[]);
        assert_eq!(verdict.status, ReadinessStatus::Blocked);
        assert_eq!(verdict.evidence_backed.len(), 2);
        assert!(!verdict.evidence_backed.contains(&"readiness".to_owned()));
        assert!(!verdict
            .evidence_backed
            .contains(&"run_scoped_provenance".to_owned()));
        assert_eq!(LivePrerequisites::all(), LivePrerequisites::all());
        assert_eq!(
            verdict.unresolved.len(),
            CURRENT_S15_LIVE_REQUIREMENTS.len() - 2
        );
    }

    #[test]
    fn overall_gate_is_structurally_unreachable_pass_from_probe_evidence() {
        // The evidence set is a strict subset of the requirement contract, so
        // `unresolved` can never be empty in this executor and the overall
        // verdict can never be PASS — for any identity outcome.
        for status in [
            ReadinessStatus::Pass,
            ReadinessStatus::Unknown,
            ReadinessStatus::Blocked,
        ] {
            let identity = S15IdentityPostcondition {
                status,
                problems: Vec::new(),
            };
            assert_ne!(
                s15_live_gate_verdict(&identity).status,
                ReadinessStatus::Pass,
                "overall S15 gate must stay BLOCKED/UNKNOWN without full raw evidence"
            );
        }
    }

    #[test]
    fn evidence_records_and_debug_never_carry_secret_material() {
        let coordinator = coordinator();
        let mut transport = FakeTransport::serving(200, identity_json("AL1", "worker-al1"));
        let attempt = coordinator
            .probe_node(
                &mut transport,
                &actor(),
                &key(),
                &all_endpoints(),
                "AL1",
                "1700000000000",
            )
            .expect("attempt");
        let serialized = serde_json::to_string(&attempt).expect("serialize");
        assert!(
            !serialized.contains(TOKEN),
            "token must never enter evidence"
        );
        assert!(
            !serialized.contains("gateway-hmac-key"),
            "signing key must never enter evidence"
        );
        assert!(
            !serialized.contains("x-gateway-signature"),
            "header material stays out of evidence"
        );

        let debug_coordinator = format!("{coordinator:?}");
        assert!(!debug_coordinator.contains(TOKEN));
        assert!(debug_coordinator.contains("[redacted]"));

        let request_debug = format!(
            "{:?}",
            coordinator
                .build_probe_request(
                    &actor(),
                    &key(),
                    &all_endpoints(),
                    "AL1",
                    "s15-al1-1-x",
                    "1700000000000"
                )
                .expect("plan")
        );
        assert!(
            !request_debug.contains(TOKEN),
            "plan Debug must redact the token header"
        );
        assert!(request_debug.contains("[redacted-host]"));
    }

    #[test]
    fn probe_request_payload_carries_gateway_v3_signed_headers() {
        let coordinator = coordinator();
        let plan = coordinator
            .build_probe_request(
                &actor(),
                &key(),
                &all_endpoints(),
                "AL1",
                "s15-al1-1-x",
                "1700000000000",
            )
            .expect("plan");
        assert!(plan.headers.contains_key("x-request-id"));
        assert_eq!(
            plan.headers.get("x-gateway-auth").map(String::as_str),
            Some(GATEWAY_AUTH_VERIFIED)
        );
        assert!(plan.headers.contains_key("x-user-card-tenant-id"));
        // The gateway-v3 payload shape is the production signing contract.
        assert_eq!(GATEWAY_V3_PREFIX, "astral-gateway-v3");
    }
}
