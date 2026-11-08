//! S15 probe executor: real TLS transport, protected configuration loading,
//! stable run artifacts and the orchestration entry behind the `s15-probe`
//! CLI (`bin/s15-probe.rs`).
//!
//! # Ownership of layers (test-control stays out of business routes)
//!
//! - The live coordinator contract (`crate::s15_live_coordinator`) stays
//!   transport-agnostic: it defines the exact frozen probe path allowlist,
//!   the AL1–AL4 node allowlist, finite budgets and the fail-closed verdict
//!   gate. This module supplies the real I/O layer underneath it.
//! - The only production surface this executor can ever touch is the frozen
//!   read-only test-control probe (`GET /main/api/v1/internal/test-control/
//!   worker-id`). There is no business-route code path here: the probe path
//!   is a compile-time constant owned by the coordinator, and this module
//!   adds no route configuration of its own.
//! - Fault injection and quorum control are NOT implemented: production
//!   exposes no protected primitive for them (see
//!   `e4_fault_driver_contract::LIVE_INTEGRATION_REASON`). The executor
//!   never fabricates those prerequisites, and the deployment attestation
//!   ([`LivePrerequisites`] booleans) only DECLARES environment
//!   prerequisites — it is recorded for audit correlation and is never an
//!   input to the verdict. A successful probe run yields at most the
//!   probe/identity `PASS`; the overall S15 gate stays `BLOCKED` until every
//!   requirement carries real raw evidence/hash/postcondition.
//!
//! # Protected configuration
//!
//! All protected inputs arrive from the environment (values never logged;
//! only variable names are recorded, matching the run-CS evidence
//! convention). Missing or invalid values fail closed with the variable
//! NAME and a reason kind — never the value. The gateway HMAC key is read
//! from a protected file (unix: mode 0600 enforced). Server addresses exist
//! only in protected configuration and are redacted from `Debug`.
//!
//! # Stable run artifacts
//!
//! Each executed run writes `{artifact_root}/{run_id}/s15-live-probe/
//! record.json` plus a SHA-256 checksum sidecar (reusing the readiness
//! checksum manifest contract). The run directory is created exclusively:
//! an existing directory for the same run id is refused, so a fresh run can
//! never overwrite prior evidence — pick a new run id instead.
//!
//! # Network boundary
//!
//! `TlsProbeTransport` is the only network-capable type in this module. It
//! performs GET-only requests built exclusively from coordinator-validated
//! plans, refuses redirects, and maps every transport failure to a short
//! reason label (never embedding URLs, tokens or key material). Unit tests
//! here open no sockets; the `--execute` path additionally requires an
//! explicit confirmation variable so the probe can never be triggered by
//! accident.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::node_adapter_contract::Actor;
use crate::readiness_contract::{checksum_manifest, validate_artifact_path};
use crate::remaining_contracts::LivePrerequisites;
use crate::s15_live_coordinator::{
    evaluate_identity_postcondition, s15_live_gate_verdict_with_owner_evidence, ProbeRequest,
    ProbeResponse, ProbeTransport, S15IdentityPostcondition, S15LiveCoordinator,
    S15LiveGateVerdict, S15NodeAttempt, S15NodeEndpoints, S15Secret, MAX_PROBE_ATTEMPTS_PER_NODE,
    MAX_PROBE_TIMEOUT_MS,
};
use crate::s15_validation::CURRENT_S15_LIVE_REQUIREMENTS;

// ===== Protected environment variable names (names only; never values) =====

/// Run id (must satisfy the `authz-validation-` campaign id contract).
pub const ENV_RUN_ID: &str = "ASTRAL_S15_RUN_ID";
/// Test-control token (same secret the production control plane compares).
pub const ENV_TOKEN: &str = "ASTRAL_TEST_CONTROL_TOKEN";
/// Path to the protected gateway HMAC key file (unix: 0600 enforced).
pub const ENV_GATEWAY_HMAC_FILE: &str = "ASTRAL_S15_GATEWAY_HMAC_FILE";
pub const ENV_ACTOR_USER_ID: &str = "ASTRAL_S15_ACTOR_USER_ID";
pub const ENV_ACTOR_IDENTITY_CARD: &str = "ASTRAL_S15_ACTOR_IDENTITY_CARD";
pub const ENV_ACTOR_USER_CARD: &str = "ASTRAL_S15_ACTOR_USER_CARD";
pub const ENV_ACTOR_DOMAIN: &str = "ASTRAL_S15_ACTOR_DOMAIN";
pub const ENV_ACTOR_TENANT: &str = "ASTRAL_S15_ACTOR_TENANT";
pub const ENV_NODE_AL1: &str = "ASTRAL_S15_NODE_AL1";
pub const ENV_NODE_AL2: &str = "ASTRAL_S15_NODE_AL2";
pub const ENV_NODE_AL3: &str = "ASTRAL_S15_NODE_AL3";
pub const ENV_NODE_AL4: &str = "ASTRAL_S15_NODE_AL4";
pub const ENV_ARTIFACT_ROOT: &str = "ASTRAL_S15_ARTIFACT_ROOT";
/// Optional per-attempt timeout override (ms, capped by
/// [`MAX_PROBE_TIMEOUT_MS`]).
pub const ENV_ATTEMPT_TIMEOUT_MS: &str = "ASTRAL_S15_ATTEMPT_TIMEOUT_MS";
/// Optional per-node attempt count override (capped by
/// [`MAX_PROBE_ATTEMPTS_PER_NODE`]).
pub const ENV_MAX_ATTEMPTS: &str = "ASTRAL_S15_MAX_ATTEMPTS";
/// Explicit execution confirmation; any other value (or absence) keeps the
/// executor network-inert.
pub const ENV_CONFIRM: &str = "ASTRAL_S15_PROBE_CONFIRM";
/// The only accepted confirmation value.
pub const CONFIRM_VALUE: &str = "approved-run";
/// Optional prerequisites attestation file (written by the deployment
/// authority). Absent = fail-closed `LivePrerequisites::none()`.
pub const ENV_PREREQUISITES_FILE: &str = "ASTRAL_S15_PREREQUISITES_FILE";
const S15_NODE_ALIASES: [&str; 4] = ["AL1", "AL2", "AL3", "AL4"];
const DEFAULT_ATTEMPT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_MAX_ATTEMPTS: usize = 2;
const MAX_KEY_BYTES: usize = 256;
const NODE_ENVS: [&str; 4] = [ENV_NODE_AL1, ENV_NODE_AL2, ENV_NODE_AL3, ENV_NODE_AL4];

/// Maps a node alias to its protected environment variable name (for
/// operators scripting the protected deployment).
pub fn node_env_name(alias: &str) -> &'static str {
    match alias {
        "AL1" => ENV_NODE_AL1,
        "AL2" => ENV_NODE_AL2,
        "AL3" => ENV_NODE_AL3,
        "AL4" => ENV_NODE_AL4,
        _ => "ASTRAL_S15_NODE_UNKNOWN",
    }
}

/// Configuration error report: environment variable NAMES and reason kinds
/// only — values are withheld by construction.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct S15ConfigReport {
    pub missing: Vec<String>,
    pub invalid: Vec<String>,
}

impl S15ConfigReport {
    fn push_missing(&mut self, name: &str) {
        self.missing.push(name.to_owned());
    }

    fn push_invalid(&mut self, entry: String) {
        self.invalid.push(entry);
    }

    pub fn is_empty(&self) -> bool {
        self.missing.is_empty() && self.invalid.is_empty()
    }
}

impl fmt::Display for S15ConfigReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let missing = if self.missing.is_empty() {
            "-".to_owned()
        } else {
            self.missing.join(",")
        };
        let invalid = if self.invalid.is_empty() {
            "-".to_owned()
        } else {
            self.invalid.join(",")
        };
        write!(formatter, "missing={missing}; invalid={invalid}")
    }
}

/// Protected probe configuration. `Debug` prints only non-sensitive counts —
/// never token, key file path, actor fields or node origins.
pub struct S15ProtectedProbeConfig {
    pub campaign_id: String,
    token: S15Secret,
    pub gateway_hmac_file: PathBuf,
    pub actor: Actor,
    pub endpoints: S15NodeEndpoints,
    pub artifact_root: PathBuf,
    pub attempt_timeout_ms: u64,
    pub max_attempts: usize,
}

impl fmt::Debug for S15ProtectedProbeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("S15ProtectedProbeConfig")
            .field("campaign_id", &self.campaign_id)
            .field("token", &"[redacted]")
            .field("gateway_hmac_file", &"[protected-path]")
            .field("actor", &"[redacted]")
            .field("endpoint_count", &self.endpoints.len())
            .field("artifact_root", &"[protected-path]")
            .field("attempt_timeout_ms", &self.attempt_timeout_ms)
            .field("max_attempts", &self.max_attempts)
            .finish()
    }
}

impl S15ProtectedProbeConfig {
    /// Pure core: builds the config from a name→value map so tests never
    /// touch process environment state. Values are trimmed; secrets keep
    /// their interior bytes. The missing inventory is complete: every
    /// required variable is reported before any value validation runs.
    pub fn from_settings(map: &BTreeMap<String, String>) -> Result<Self, S15ConfigReport> {
        const REQUIRED: [&str; 13] = [
            ENV_RUN_ID,
            ENV_TOKEN,
            ENV_GATEWAY_HMAC_FILE,
            ENV_ACTOR_USER_ID,
            ENV_ACTOR_IDENTITY_CARD,
            ENV_ACTOR_USER_CARD,
            ENV_ACTOR_DOMAIN,
            ENV_ACTOR_TENANT,
            ENV_NODE_AL1,
            ENV_NODE_AL2,
            ENV_NODE_AL3,
            ENV_NODE_AL4,
            ENV_ARTIFACT_ROOT,
        ];
        let mut report = S15ConfigReport::default();
        let mut values: BTreeMap<&'static str, String> = BTreeMap::new();
        for name in REQUIRED {
            match map.get(name) {
                Some(value) if !value.trim().is_empty() => {
                    values.insert(name, value.trim().to_owned());
                }
                Some(_) => report.push_invalid(format!("{name}:blank")),
                None => report.push_missing(name),
            }
        }
        if !report.is_empty() {
            return Err(report);
        }
        let campaign_id = values.get(ENV_RUN_ID).expect("required value").clone();
        if crate::readiness_contract::validate_campaign_id(&campaign_id).is_err() {
            report.push_invalid(format!("{ENV_RUN_ID}:invalid_campaign_id"));
            return Err(report);
        }
        let token = match S15Secret::new(values.get(ENV_TOKEN).expect("required value").clone()) {
            Ok(token) => token,
            Err(_) => {
                report.push_invalid(format!("{ENV_TOKEN}:blank"));
                return Err(report);
            }
        };
        let hmac_file = values.get(ENV_GATEWAY_HMAC_FILE).expect("required value");
        if hmac_file.is_empty() || Path::new(hmac_file).file_name().is_none() {
            report.push_invalid(format!("{ENV_GATEWAY_HMAC_FILE}:unsafe_path"));
            return Err(report);
        }
        let actor = Actor {
            user_id: values
                .get(ENV_ACTOR_USER_ID)
                .expect("required value")
                .clone(),
            identity_card: values
                .get(ENV_ACTOR_IDENTITY_CARD)
                .expect("required value")
                .clone(),
            user_card: values
                .get(ENV_ACTOR_USER_CARD)
                .expect("required value")
                .clone(),
            domain: values
                .get(ENV_ACTOR_DOMAIN)
                .expect("required value")
                .clone(),
            tenant: values
                .get(ENV_ACTOR_TENANT)
                .expect("required value")
                .clone(),
        };
        if actor.validate().is_err() {
            report.push_invalid(format!("{ENV_ACTOR_USER_ID}:invalid_actor_shape"));
            return Err(report);
        }
        let mut pairs = Vec::with_capacity(NODE_ENVS.len());
        for (alias, env_name) in S15_NODE_ALIASES.iter().zip(NODE_ENVS.iter()) {
            pairs.push((
                *alias,
                values.get(*env_name).expect("required value").clone(),
            ));
        }
        let endpoints = match S15NodeEndpoints::from_pairs(&pairs) {
            Ok(endpoints) => endpoints,
            Err(error) => {
                report.push_invalid(format!("{ENV_NODE_AL1}:{}", error));
                return Err(report);
            }
        };
        let artifact_root = values.get(ENV_ARTIFACT_ROOT).expect("required value");
        if !safe_artifact_root(artifact_root) {
            report.push_invalid(format!("{ENV_ARTIFACT_ROOT}:unsafe_path"));
            return Err(report);
        }
        let attempt_timeout_ms = match optional_number(
            map.get(ENV_ATTEMPT_TIMEOUT_MS).map(String::as_str),
            DEFAULT_ATTEMPT_TIMEOUT_MS as i64,
            1,
            MAX_PROBE_TIMEOUT_MS as i64,
        ) {
            Ok(value) => value as u64,
            Err(reason) => {
                report.push_invalid(format!("{ENV_ATTEMPT_TIMEOUT_MS}:{reason}"));
                return Err(report);
            }
        };
        let max_attempts = match optional_number(
            map.get(ENV_MAX_ATTEMPTS).map(String::as_str),
            DEFAULT_MAX_ATTEMPTS as i64,
            1,
            MAX_PROBE_ATTEMPTS_PER_NODE as i64,
        ) {
            Ok(value) => value as usize,
            Err(reason) => {
                report.push_invalid(format!("{ENV_MAX_ATTEMPTS}:{reason}"));
                return Err(report);
            }
        };
        Ok(Self {
            campaign_id,
            token,
            gateway_hmac_file: PathBuf::from(hmac_file),
            actor,
            endpoints,
            artifact_root: PathBuf::from(artifact_root),
            attempt_timeout_ms,
            max_attempts,
        })
    }

    /// Thin environment adapter: reads the documented variable names into the
    /// pure core. Only names travel into errors.
    pub fn from_env() -> Result<Self, S15ConfigReport> {
        let mut map = BTreeMap::new();
        for name in protected_env_names() {
            if let Ok(value) = std::env::var(name) {
                map.insert(name.to_owned(), value);
            }
        }
        Self::from_settings(&map)
    }

    /// Environment variable NAMES consumed by this configuration (for the
    /// evidence record; values are never recorded).
    pub fn env_names(&self) -> Vec<&'static str> {
        protected_env_names()
    }

    pub fn token(&self) -> &S15Secret {
        &self.token
    }
}

fn protected_env_names() -> Vec<&'static str> {
    let names = vec![
        ENV_RUN_ID,
        ENV_TOKEN,
        ENV_GATEWAY_HMAC_FILE,
        ENV_ACTOR_USER_ID,
        ENV_ACTOR_IDENTITY_CARD,
        ENV_ACTOR_USER_CARD,
        ENV_ACTOR_DOMAIN,
        ENV_ACTOR_TENANT,
        ENV_NODE_AL1,
        ENV_NODE_AL2,
        ENV_NODE_AL3,
        ENV_NODE_AL4,
        ENV_ARTIFACT_ROOT,
        ENV_ATTEMPT_TIMEOUT_MS,
        ENV_MAX_ATTEMPTS,
        ENV_PREREQUISITES_FILE,
        ENV_CONFIRM,
    ];
    names
}

/// Artifact root safety: non-empty, no `..` segments, no backslashes or NULs
/// (path-traversal and injection hygiene for a value that becomes a path).
fn safe_artifact_root(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('\\')
        && !value.contains('\0')
        && value.split('/').all(|segment| segment != "..")
}

fn optional_number(
    raw: Option<&str>,
    default: i64,
    minimum: i64,
    maximum: i64,
) -> Result<i64, &'static str> {
    let Some(raw) = raw else {
        return Ok(default);
    };
    if raw.trim().is_empty() {
        return Ok(default);
    }
    let value: i64 = raw.trim().parse().map_err(|_| "not_a_number")?;
    if value < minimum || value > maximum {
        return Err("out_of_range");
    }
    Ok(value)
}

/// Loads the protected gateway HMAC key. Unix deployments enforce mode 0600;
/// the key is non-empty, size-capped, and trailing ASCII newlines written by
/// editors are trimmed. Failures name the reason kind, never the content.
pub fn load_gateway_key(path: &Path) -> Result<Vec<u8>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path).map_err(|_| "key_file_unreadable".to_owned())?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(format!("key_file_mode_insecure:{mode:o}"));
        }
    }
    let mut bytes = fs::read(path).map_err(|_| "key_file_unreadable".to_owned())?;
    if bytes.len() > MAX_KEY_BYTES {
        return Err("key_file_too_large".to_owned());
    }
    while matches!(bytes.last(), Some(b'\n') | Some(b'\r')) {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err("key_file_empty".to_owned());
    }
    Ok(bytes)
}

/// Parses the deployment authority's prerequisites attestation file. All 17
/// known fields must be present booleans; unknown keys are rejected so an
/// attestation cannot silently omit requirements.
pub fn parse_live_prerequisites(raw: &str) -> Result<LivePrerequisites, String> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|_| "prerequisites_not_json".to_owned())?;
    let object = value
        .as_object()
        .ok_or_else(|| "prerequisites_not_object".to_owned())?;
    const FIELDS: [&str; 17] = [
        "approved_deployment",
        "signed_identity",
        "readiness",
        "controller",
        "three_node_state",
        "four_node_state",
        "two_half_state",
        "two_database_state",
        "same_db_custom_channel",
        "cross_db_rabbitmq",
        "current_transport",
        "durable_evidence",
        "run_scoped_provenance",
        "tenant_isolation",
        "audit_correlation",
        "half_authority_fence",
        "split_brain_fail_closed",
    ];
    let mut parsed = LivePrerequisites::none();
    for field in FIELDS {
        match object.get(field) {
            Some(serde_json::Value::Bool(flag)) => {
                set_prerequisite(&mut parsed, field, *flag);
            }
            Some(_) => return Err(format!("prerequisite_not_bool:{field}")),
            None => return Err(format!("prerequisite_missing:{field}")),
        }
    }
    if object.len() != FIELDS.len() {
        return Err("prerequisites_unknown_keys".to_owned());
    }
    Ok(parsed)
}

fn set_prerequisite(prerequisites: &mut LivePrerequisites, field: &str, flag: bool) {
    match field {
        "approved_deployment" => prerequisites.approved_deployment = flag,
        "signed_identity" => prerequisites.signed_identity = flag,
        "readiness" => prerequisites.readiness = flag,
        "controller" => prerequisites.controller = flag,
        "three_node_state" => prerequisites.three_node_state = flag,
        "four_node_state" => prerequisites.four_node_state = flag,
        "two_half_state" => prerequisites.two_half_state = flag,
        "two_database_state" => prerequisites.two_database_state = flag,
        "same_db_custom_channel" => prerequisites.same_db_custom_channel = flag,
        "cross_db_rabbitmq" => prerequisites.cross_db_rabbitmq = flag,
        "current_transport" => prerequisites.current_transport = flag,
        "durable_evidence" => prerequisites.durable_evidence = flag,
        "run_scoped_provenance" => prerequisites.run_scoped_provenance = flag,
        "tenant_isolation" => prerequisites.tenant_isolation = flag,
        "audit_correlation" => prerequisites.audit_correlation = flag,
        "half_authority_fence" => prerequisites.half_authority_fence = flag,
        "split_brain_fail_closed" => prerequisites.split_brain_fail_closed = flag,
        _ => {}
    }
}

/// Reads and parses the attestation file when the variable is set; absent
/// variable = `None` (fail-closed none()).
pub fn load_prerequisites_from_env() -> Result<Option<LivePrerequisites>, String> {
    let Some(path) = std::env::var(ENV_PREREQUISITES_FILE)
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(None);
    };
    let raw = fs::read_to_string(Path::new(path.trim()))
        .map_err(|_| "prerequisites_file_unreadable".to_owned())?;
    parse_live_prerequisites(&raw).map(Some)
}

/// The explicit-execution gate: the probe runs network I/O only when the
/// confirmation variable equals [`CONFIRM_VALUE`] exactly.
pub fn execution_confirmed(confirm_raw: Option<&str>) -> bool {
    confirm_raw == Some(CONFIRM_VALUE)
}

// ===== Real TLS transport =====

/// Real HTTPS transport over the workspace rustls stack. GET-only plans come
/// exclusively from the coordinator; redirects are refused so the effective
/// URL can never drift beyond the validated origin.
pub struct TlsProbeTransport {
    client: reqwest::blocking::Client,
}

impl fmt::Debug for TlsProbeTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsProbeTransport")
            .field("client", &"[configured]")
            .finish()
    }
}

impl TlsProbeTransport {
    pub fn new() -> Result<Self, String> {
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_millis(MAX_PROBE_TIMEOUT_MS))
            .build()
            .map_err(|_| "tls_client_build_failed".to_owned())?;
        Ok(Self { client })
    }

    /// Builds the outgoing request without sending it (offline inspection
    /// seam used by tests to pin method/url/headers/timeout).
    fn build_outgoing(&self, plan: &ProbeRequest) -> Result<reqwest::blocking::Request, String> {
        let mut builder = self
            .client
            .get(&plan.url)
            .timeout(Duration::from_millis(plan.timeout_ms));
        for (name, value) in &plan.headers {
            builder = builder.header(name, value);
        }
        builder
            .build()
            .map_err(|_| "outgoing_request_build_failed".to_owned())
    }
}

/// Transport failure classification: short reason labels only — never URLs,
/// headers, tokens or key material.
fn transport_reason(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "timeout".to_owned()
    } else if error.is_connect() {
        "connect_error".to_owned()
    } else if error.is_request() {
        "request_error".to_owned()
    } else {
        "transport_error".to_owned()
    }
}

impl ProbeTransport for TlsProbeTransport {
    fn request(&mut self, plan: &ProbeRequest) -> Result<ProbeResponse, String> {
        let request = self.build_outgoing(plan)?;
        let response = self
            .client
            .execute(request)
            .map_err(|error| transport_reason(&error))?;
        let status = response.status().as_u16();
        let body = response.text().map_err(|_| "body_read_error".to_owned())?;
        Ok(ProbeResponse { status, body })
    }
}

// ===== Run record and stable artifacts =====

/// Immutable evidence record of one executed probe run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct S15ProbeRunRecord {
    pub schema: &'static str,
    #[serde(rename = "campaignId")]
    pub campaign_id: String,
    #[serde(rename = "startedUnixMs")]
    pub started_unix_ms: i64,
    #[serde(rename = "finishedUnixMs")]
    pub finished_unix_ms: i64,
    pub attempts: Vec<S15NodeAttempt>,
    pub identity: S15IdentityPostcondition,
    pub verdict: S15LiveGateVerdict,
    /// Actual requirements proved by strict owner evidence, separate from
    /// declaration-only prerequisite booleans.
    #[serde(rename = "evidenceBacked")]
    pub evidence_backed: Vec<String>,
    /// Evidence planes with no production-owner observation path in this build.
    #[serde(rename = "capabilityGaps")]
    pub capability_gaps: Vec<crate::s15_live_coordinator::S15LiveCapabilityGap>,
    /// `"declaration_file"` (an attestation was loaded — declaration only,
    /// never evidence) or `"none_fail_closed"`.
    #[serde(rename = "prerequisitesSource")]
    pub prerequisites_source: &'static str,
    /// Requirement NAMES the deployment attestation declares true. This is a
    /// declaration for audit correlation only: these names are NOT evidence
    /// and never enter the verdict (see `s15_live_gate_verdict_with_owner_evidence`).
    #[serde(rename = "declaredPrerequisites")]
    pub declared_prerequisites: Vec<String>,
    /// Protected variable NAMES consumed (values never recorded).
    #[serde(rename = "envVarNames")]
    pub env_var_names: Vec<String>,
}

pub const RUN_RECORD_SCHEMA: &str = "astral.s15.live-probe-record/v1";

/// Orchestration input. The gateway key is pre-loaded by the caller (CLI)
/// via [`load_gateway_key`]; the coordinator contract stays I/O-free.
pub struct S15ProbeRunInput<'a> {
    pub config: &'a S15ProtectedProbeConfig,
    pub key: Vec<u8>,
    /// `None` = no attestation available: fail-closed
    /// [`LivePrerequisites::none()`].
    pub prerequisites: Option<LivePrerequisites>,
    pub now_unix_ms: i64,
}

/// Executes the four-node identity probe run and computes the fail-closed
/// verdict. Network I/O happens only through the injected transport; this
/// function itself opens nothing.
pub fn execute_s15_probe_run<T: ProbeTransport>(
    transport: &mut T,
    input: &S15ProbeRunInput<'_>,
) -> Result<S15ProbeRunRecord, String> {
    execute_s15_probe_run_with_owner_evidence(transport, input, Vec::new())
}

/// Compose node identity with strict, authenticated owner DTOs. Only distinct
/// exact owner records can close corresponding requirements; caller boolean
/// declarations and incomplete logs never do. No requirement is synthesized.
pub fn execute_s15_probe_run_with_owner_evidence<T: ProbeTransport>(
    transport: &mut T,
    input: &S15ProbeRunInput<'_>,
    owner_evidence: Vec<crate::s15_live_coordinator::S15OwnerEvidence>,
) -> Result<S15ProbeRunRecord, String> {
    let coordinator = S15LiveCoordinator::new(
        &input.config.campaign_id,
        input.config.token.reproduce(),
        input.config.attempt_timeout_ms,
        input.config.max_attempts,
    )
    .map_err(|error| format!("coordinator_rejected_config:{error}"))?;
    let mut attempts = Vec::with_capacity(S15_NODE_ALIASES.len());
    for alias in S15_NODE_ALIASES {
        let node: &'static str = match alias {
            "AL1" => "AL1",
            "AL2" => "AL2",
            "AL3" => "AL3",
            "AL4" => "AL4",
            _ => unreachable!("fixed alias table"),
        };
        let attempt = coordinator
            .probe_node(
                transport,
                &input.config.actor,
                &input.key,
                &input.config.endpoints,
                node,
                &input.now_unix_ms.to_string(),
            )
            .map_err(|error| format!("node_probe_failed:{error}"))?;
        attempts.push(attempt);
    }
    let identity = evaluate_identity_postcondition(&attempts);
    // The real authority adapter can establish signed global frontier,
    // scope-certificate and read-gate observations, but it does not prove the
    // authority half ownership/fence or any DB/channel/audit behavior. Only
    // individually validated owner evidence can close additional requirements.
    let verdict = s15_live_gate_verdict_with_owner_evidence(&identity, &owner_evidence);
    let evidence_backed = verdict.evidence_backed.clone();
    let capability_gaps = crate::s15_live_coordinator::S15_LIVE_CAPABILITY_GAPS
        .iter()
        .filter(|gap| {
            !verdict
                .evidence_backed
                .iter()
                .any(|name| name == gap.requirement)
        })
        .cloned()
        .collect();
    let (prerequisites_source, declared_prerequisites) = match &input.prerequisites {
        Some(attested) => ("declaration_file", declared_prerequisite_names(attested)),
        None => ("none_fail_closed", Vec::new()),
    };
    Ok(S15ProbeRunRecord {
        schema: RUN_RECORD_SCHEMA,
        campaign_id: input.config.campaign_id.clone(),
        started_unix_ms: input.now_unix_ms,
        finished_unix_ms: input.now_unix_ms,
        attempts,
        identity,
        verdict,
        evidence_backed,
        capability_gaps,
        prerequisites_source,
        declared_prerequisites,
        env_var_names: input
            .config
            .env_names()
            .into_iter()
            .map(str::to_owned)
            .collect(),
    })
}

/// Enumerates the requirement names a deployment attestation declares true —
/// for audit records only; never a verdict input.
pub fn declared_prerequisite_names(attested: &LivePrerequisites) -> Vec<String> {
    CURRENT_S15_LIVE_REQUIREMENTS
        .iter()
        .copied()
        .filter(|requirement| match *requirement {
            "approved_deployment" => attested.approved_deployment,
            "signed_identity" => attested.signed_identity,
            "readiness" => attested.readiness,
            "controller" => attested.controller,
            "three_node_state" => attested.three_node_state,
            "four_node_state" => attested.four_node_state,
            "two_half_state" => attested.two_half_state,
            "two_database_state" => attested.two_database_state,
            "same_db_custom_channel" => attested.same_db_custom_channel,
            "cross_db_rabbitmq" => attested.cross_db_rabbitmq,
            "current_transport" => attested.current_transport,
            "durable_evidence" => attested.durable_evidence,
            "run_scoped_provenance" => attested.run_scoped_provenance,
            "tenant_isolation" => attested.tenant_isolation,
            "audit_correlation" => attested.audit_correlation,
            "half_authority_fence" => attested.half_authority_fence,
            "split_brain_fail_closed" => attested.split_brain_fail_closed,
            _ => false,
        })
        .map(str::to_owned)
        .collect()
}

/// Stable artifact layout for one executed run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeArtifactPaths {
    pub run_dir: PathBuf,
    pub record_json: PathBuf,
    pub checksum: PathBuf,
}

/// Writes the run record as stable artifacts:
/// `{root}/{run_id}/s15-live-probe/record.json` + `record.json.sha256`
/// (readiness checksum manifest contract). The run directory is created
/// exclusively — existing evidence for the same run id is never overwritten.
pub fn write_probe_artifacts(
    root: &Path,
    record: &S15ProbeRunRecord,
) -> Result<ProbeArtifactPaths, String> {
    validate_artifact_path(&format!("{}/s15-live-probe", record.campaign_id))
        .map_err(|error| format!("artifact_scope_invalid:{error:?}"))?;
    let run_dir = root.join(record.campaign_id.clone()).join("s15-live-probe");
    let parent = run_dir
        .parent()
        .ok_or_else(|| "artifact_root_invalid".to_owned())?;
    fs::create_dir_all(parent).map_err(|_| "artifact_root_unwritable".to_owned())?;
    fs::create_dir(&run_dir).map_err(|_| {
        "run_artifact_dir_exists:refusing_to_overwrite_existing_evidence".to_owned()
    })?;
    let record_json = run_dir.join("record.json");
    let serialized =
        serde_json::to_string_pretty(record).map_err(|_| "record_not_serializable".to_owned())?;
    fs::write(&record_json, serialized.as_bytes()).map_err(|_| "record_write_failed".to_owned())?;
    let manifest = checksum_manifest(&BTreeMap::from([(
        "record.json".to_owned(),
        serialized.as_bytes().to_vec(),
    )]))
    .map_err(|error| format!("checksum_manifest_failed:{error:?}"))?;
    let checksum = run_dir.join("record.json.sha256");
    fs::write(&checksum, manifest.as_bytes()).map_err(|_| "checksum_write_failed".to_owned())?;
    Ok(ProbeArtifactPaths {
        run_dir,
        record_json,
        checksum,
    })
}

/// UTC unix milliseconds from the system clock (CLI-side only; library
/// functions take explicit timestamps for determinism).
pub fn unix_ms_now() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => duration.as_millis() as i64,
        Err(_) => 0,
    }
}

/// SHA-256 hex helper reused by the CLI for artifact self-description.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::readiness_contract::{verify_checksum_manifest, ReadinessStatus};
    use serde_json::json;

    const RUN_ID: &str = "authz-validation-s15-exec-20261107";

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "s15-probe-executor-test-{label}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn valid_settings() -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        map.insert(ENV_RUN_ID.to_owned(), RUN_ID.to_owned());
        map.insert(ENV_TOKEN.to_owned(), "probe-token".to_owned());
        map.insert(
            ENV_GATEWAY_HMAC_FILE.to_owned(),
            "/protected/hmac.txt".to_owned(),
        );
        map.insert(ENV_ACTOR_USER_ID.to_owned(), "probe-actor".to_owned());
        map.insert(ENV_ACTOR_IDENTITY_CARD.to_owned(), "ic-1".to_owned());
        map.insert(ENV_ACTOR_USER_CARD.to_owned(), "uc-1".to_owned());
        map.insert(ENV_ACTOR_DOMAIN.to_owned(), "domain-1".to_owned());
        map.insert(ENV_ACTOR_TENANT.to_owned(), "tenant-1".to_owned());
        map.insert(ENV_NODE_AL1.to_owned(), "https://al1.internal".to_owned());
        map.insert(ENV_NODE_AL2.to_owned(), "https://al2.internal".to_owned());
        map.insert(ENV_NODE_AL3.to_owned(), "https://al3.internal".to_owned());
        map.insert(ENV_NODE_AL4.to_owned(), "https://al4.internal".to_owned());
        map.insert(
            ENV_ARTIFACT_ROOT.to_owned(),
            "/tmp/s15-probe-artifacts".to_owned(),
        );
        map
    }

    #[test]
    fn config_loads_from_complete_settings_and_defaults_budgets() {
        let config =
            S15ProtectedProbeConfig::from_settings(&valid_settings()).expect("config must load");
        assert_eq!(config.campaign_id, RUN_ID);
        assert_eq!(config.attempt_timeout_ms, DEFAULT_ATTEMPT_TIMEOUT_MS);
        assert_eq!(config.max_attempts, DEFAULT_MAX_ATTEMPTS);
        assert_eq!(config.endpoints.len(), 4);
        let debug = format!("{config:?}");
        assert!(!debug.contains("probe-token"));
        assert!(!debug.contains("al1.internal"));
        assert!(!debug.contains("probe-actor"));
        assert!(!debug.contains("/protected/hmac.txt"));
        assert!(!debug.contains("/tmp/s15-probe-artifacts"));
    }

    #[test]
    fn config_fails_closed_naming_missing_variables_without_values() {
        let report = S15ProtectedProbeConfig::from_settings(&BTreeMap::new()).unwrap_err();
        for name in [
            ENV_RUN_ID,
            ENV_TOKEN,
            ENV_GATEWAY_HMAC_FILE,
            ENV_ACTOR_USER_ID,
            ENV_ACTOR_USER_CARD,
            ENV_ACTOR_TENANT,
            ENV_NODE_AL1,
            ENV_NODE_AL2,
            ENV_NODE_AL3,
            ENV_NODE_AL4,
            ENV_ARTIFACT_ROOT,
        ] {
            assert!(report.missing.contains(&name.to_owned()), "{name}");
        }
        assert_eq!(report.missing.len(), 13);
        let rendered = report.to_string();
        assert!(!rendered.contains("probe-token"));
        assert!(!rendered.contains("https://"));
    }

    #[test]
    fn config_rejects_invalid_and_unsafe_values_by_name() {
        let mut map = valid_settings();
        map.insert(ENV_RUN_ID.to_owned(), "not-a-campaign-id".to_owned());
        let report = S15ProtectedProbeConfig::from_settings(&map).unwrap_err();
        assert!(report
            .invalid
            .contains(&format!("{ENV_RUN_ID}:invalid_campaign_id")));

        let mut map = valid_settings();
        map.insert(ENV_ATTEMPT_TIMEOUT_MS.to_owned(), "999999".to_owned());
        let report = S15ProtectedProbeConfig::from_settings(&map).unwrap_err();
        assert!(report
            .invalid
            .contains(&format!("{ENV_ATTEMPT_TIMEOUT_MS}:out_of_range")));

        let mut map = valid_settings();
        map.insert(ENV_MAX_ATTEMPTS.to_owned(), "9".to_owned());
        let report = S15ProtectedProbeConfig::from_settings(&map).unwrap_err();
        assert!(report
            .invalid
            .contains(&format!("{ENV_MAX_ATTEMPTS}:out_of_range")));

        let mut map = valid_settings();
        map.insert(ENV_ARTIFACT_ROOT.to_owned(), "/tmp/../escape".to_owned());
        let report = S15ProtectedProbeConfig::from_settings(&map).unwrap_err();
        assert!(report
            .invalid
            .contains(&format!("{ENV_ARTIFACT_ROOT}:unsafe_path")));

        let mut map = valid_settings();
        map.insert(ENV_NODE_AL1.to_owned(), "https://al1.internal/".to_owned());
        let report = S15ProtectedProbeConfig::from_settings(&map).unwrap_err();
        assert!(report
            .invalid
            .iter()
            .any(|entry| entry.starts_with(&format!("{ENV_NODE_AL1}:"))));

        let mut map = valid_settings();
        map.insert(ENV_ACTOR_USER_ID.to_owned(), String::new());
        let report = S15ProtectedProbeConfig::from_settings(&map).unwrap_err();
        assert!(report
            .invalid
            .contains(&format!("{ENV_ACTOR_USER_ID}:blank")));
    }

    #[test]
    fn optional_budget_overrides_apply_within_caps() {
        let mut map = valid_settings();
        map.insert(ENV_ATTEMPT_TIMEOUT_MS.to_owned(), "1234".to_owned());
        map.insert(ENV_MAX_ATTEMPTS.to_owned(), "3".to_owned());
        let config = S15ProtectedProbeConfig::from_settings(&map).expect("config");
        assert_eq!(config.attempt_timeout_ms, 1234);
        assert_eq!(config.max_attempts, 3);
    }

    #[cfg(unix)]
    #[test]
    fn gateway_key_enforces_unix_mode_0600_and_trims_trailing_newline() {
        use std::os::unix::fs::PermissionsExt;
        let directory = TestDirectory::new("key");
        let secure = directory.path().join("hmac-secure.txt");
        fs::write(&secure, b"gateway-key\n").unwrap();
        fs::set_permissions(&secure, fs::Permissions::from_mode(0o600)).unwrap();
        let key = load_gateway_key(&secure).expect("secure key loads");
        assert_eq!(key, b"gateway-key".to_vec());

        let loose = directory.path().join("hmac-loose.txt");
        fs::write(&loose, b"gateway-key").unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).unwrap();
        let error = load_gateway_key(&loose).unwrap_err();
        assert!(error.starts_with("key_file_mode_insecure:644"), "{error}");

        let missing = directory.path().join("absent.txt");
        assert_eq!(
            load_gateway_key(&missing).unwrap_err(),
            "key_file_unreadable"
        );

        let empty = directory.path().join("hmac-empty.txt");
        fs::write(&empty, b"\n").unwrap();
        fs::set_permissions(&empty, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(load_gateway_key(&empty).unwrap_err(), "key_file_empty");
    }

    #[test]
    fn prerequisites_attestation_requires_all_fields_as_bools_and_rejects_unknowns() {
        let mut object = serde_json::Map::new();
        for field in [
            "approved_deployment",
            "signed_identity",
            "readiness",
            "controller",
            "three_node_state",
            "four_node_state",
            "two_half_state",
            "two_database_state",
            "same_db_custom_channel",
            "cross_db_rabbitmq",
            "current_transport",
            "durable_evidence",
            "run_scoped_provenance",
            "tenant_isolation",
            "audit_correlation",
            "half_authority_fence",
            "split_brain_fail_closed",
        ] {
            object.insert(field.to_owned(), json!(true));
        }
        let parsed =
            parse_live_prerequisites(&serde_json::Value::Object(object.clone()).to_string())
                .expect("full attestation parses");
        assert_eq!(parsed, LivePrerequisites::all());

        object.remove("controller");
        assert_eq!(
            parse_live_prerequisites(&serde_json::Value::Object(object.clone()).to_string())
                .unwrap_err(),
            "prerequisite_missing:controller"
        );
        object.insert("controller".to_owned(), json!("yes"));
        assert_eq!(
            parse_live_prerequisites(&serde_json::Value::Object(object.clone()).to_string())
                .unwrap_err(),
            "prerequisite_not_bool:controller"
        );
        object.insert("controller".to_owned(), json!(true));
        object.insert("extra_key".to_owned(), json!(true));
        assert_eq!(
            parse_live_prerequisites(&serde_json::Value::Object(object).to_string()).unwrap_err(),
            "prerequisites_unknown_keys"
        );
        assert_eq!(
            parse_live_prerequisites("not json").unwrap_err(),
            "prerequisites_not_json"
        );
        assert_eq!(
            parse_live_prerequisites("[]").unwrap_err(),
            "prerequisites_not_object"
        );
    }

    #[test]
    fn execution_confirmation_requires_the_exact_approval_value() {
        assert!(!execution_confirmed(None));
        assert!(!execution_confirmed(Some("")));
        assert!(!execution_confirmed(Some("yes")));
        assert!(!execution_confirmed(Some("approved-run ")));
        assert!(execution_confirmed(Some(CONFIRM_VALUE)));
    }

    #[test]
    fn tls_transport_builds_offline_requests_with_exact_mapping() {
        let transport = TlsProbeTransport::new().expect("client builds offline");
        let plan = ProbeRequest {
            url: "https://al1.internal/main/api/v1/internal/test-control/worker-id".to_owned(),
            headers: BTreeMap::from([
                ("x-request-id".to_owned(), "s15-al1-1-x".to_owned()),
                ("X-Test-Control-Token".to_owned(), "secret-token".to_owned()),
            ]),
            timeout_ms: 5_000,
        };
        let request = transport.build_outgoing(&plan).expect("request builds");
        assert_eq!(request.method(), reqwest::Method::GET);
        assert_eq!(
            request.url().as_str(),
            "https://al1.internal/main/api/v1/internal/test-control/worker-id"
        );
        assert_eq!(
            request.headers().get("X-Test-Control-Token"),
            Some(&reqwest::header::HeaderValue::from_static("secret-token"))
        );
        assert_eq!(request.timeout(), Some(&Duration::from_millis(5_000)));
    }

    struct FakeTransport {
        responses: std::collections::VecDeque<Result<ProbeResponse, String>>,
    }

    impl FakeTransport {
        fn identities() -> Self {
            let body = |node: &str, worker: &str| {
                let suffix = worker.trim_start_matches('w');
                json!({
                    "nodeId": node,
                    "workerId": worker,
                    "configFingerprint": "a".repeat(64),
                    "jvmStartTime": "1699000000000",
                    "processIdentityHash": format!("{}{:0>2}", "b".repeat(62), suffix),
                })
                .to_string()
            };
            Self {
                responses: [("AL1", "w1"), ("AL2", "w2"), ("AL3", "w3"), ("AL4", "w4")]
                    .into_iter()
                    .map(|(node, worker)| {
                        Ok(ProbeResponse {
                            status: 200,
                            body: body(node, worker),
                        })
                    })
                    .collect(),
            }
        }
    }

    impl ProbeTransport for FakeTransport {
        fn request(&mut self, _plan: &ProbeRequest) -> Result<ProbeResponse, String> {
            self.responses
                .pop_front()
                .unwrap_or_else(|| Err("fake_exhausted".to_owned()))
        }
    }

    fn run_config(directory: &TestDirectory) -> S15ProtectedProbeConfig {
        let mut map = valid_settings();
        map.insert(
            ENV_ARTIFACT_ROOT.to_owned(),
            directory.path().to_string_lossy().to_string(),
        );
        S15ProtectedProbeConfig::from_settings(&map).expect("config")
    }

    #[test]
    fn probe_run_records_blockers_without_declaration_and_pass_is_impossible_without_it() {
        let directory = TestDirectory::new("run-no-attest");
        let config = run_config(&directory);
        let mut transport = FakeTransport::identities();
        let record = execute_s15_probe_run(
            &mut transport,
            &S15ProbeRunInput {
                config: &config,
                key: b"gateway-key".to_vec(),
                prerequisites: None,
                now_unix_ms: 1_700_000_000_000,
            },
        )
        .expect("run completes");
        assert_eq!(record.schema, RUN_RECORD_SCHEMA);
        assert_eq!(record.prerequisites_source, "none_fail_closed");
        assert!(record.declared_prerequisites.is_empty());
        // Probe plane: identity evidence is complete — the probe itself PASSes.
        assert_eq!(
            record.identity.status,
            ReadinessStatus::Pass,
            "identity evidence is complete"
        );
        assert_eq!(record.attempts.len(), 4);
        // Overall gate: no declaration exists, so nothing is evidenced beyond
        // the probe plane and the gate stays BLOCKED.
        assert_eq!(record.verdict.status, ReadinessStatus::Blocked);
        assert!(!record.verdict.evidence_backed.is_empty());
        assert!(record
            .verdict
            .unresolved
            .contains(&"approved_deployment".to_owned()));
        assert!(!record.env_var_names.is_empty());
        let serialized = serde_json::to_string(&record).unwrap();
        assert!(!serialized.contains("probe-token"));
        assert!(!serialized.contains("gateway-key"));

        let paths = write_probe_artifacts(directory.path(), &record).expect("artifacts");
        assert!(paths.record_json.exists());
        assert!(paths.checksum.exists());
        let checksum = fs::read_to_string(&paths.checksum).unwrap();
        let record_bytes = serde_json::to_vec_pretty(&record).unwrap();
        assert!(checksum.starts_with(&format!("{}  record.json\n", sha256_hex(&record_bytes))));
        assert!(verify_checksum_manifest(
            &BTreeMap::from([("record.json".to_owned(), record_bytes)]),
            &checksum
        )
        .is_ok());
    }

    #[test]
    fn all_true_attestation_plus_four_successful_probes_cannot_pass_the_overall_gate() {
        // Review-correction negative: the deployment attestation declares
        // EVERY prerequisite true and all four probes succeed with matched
        // identities — the overall S15 gate still stays BLOCKED. Booleans
        // declare environment prerequisites; they are not evidence for the
        // fault/quorum/transport/durable planes and never enter the verdict.
        let directory = TestDirectory::new("run-attest-cannot-lift");
        let config = run_config(&directory);
        let mut transport = FakeTransport::identities();
        let record = execute_s15_probe_run(
            &mut transport,
            &S15ProbeRunInput {
                config: &config,
                key: b"gateway-key".to_vec(),
                prerequisites: Some(LivePrerequisites::all()),
                now_unix_ms: 1_700_000_000_000,
            },
        )
        .expect("run completes");
        // Declaration is recorded verbatim for audit — as a declaration.
        assert_eq!(record.prerequisites_source, "declaration_file");
        assert_eq!(record.declared_prerequisites.len(), 16);
        assert!(record
            .declared_prerequisites
            .contains(&"controller".to_owned()));
        assert!(record
            .declared_prerequisites
            .contains(&"split_brain_fail_closed".to_owned()));
        // Probe plane: full identity PASS.
        assert_eq!(record.identity.status, ReadinessStatus::Pass);
        // Overall gate: still BLOCKED; the fault/quorum/transport planes
        // remain unresolved because no raw evidence primitive exists here.
        assert_ne!(
            record.verdict.status,
            ReadinessStatus::Pass,
            "attestation booleans plus probe success must never lift the overall gate"
        );
        assert_eq!(record.verdict.status, ReadinessStatus::Blocked);
        assert!(record.verdict.unresolved.contains(&"controller".to_owned()));
        assert!(record
            .verdict
            .unresolved
            .contains(&"same_db_custom_channel".to_owned()));
        assert!(record
            .verdict
            .unresolved
            .contains(&"cross_db_rabbitmq".to_owned()));
        assert!(record
            .verdict
            .unresolved
            .contains(&"split_brain_fail_closed".to_owned()));
        // Worker-id proves identity/liveness only; serving readiness and
        // run-scoped provenance require separate production-owner evidence.
        assert_eq!(record.verdict.evidence_backed.len(), 2);
        assert!(record
            .verdict
            .evidence_backed
            .contains(&"signed_identity".to_owned()));
        assert!(record
            .verdict
            .evidence_backed
            .contains(&"four_node_state".to_owned()));
        assert!(!record
            .verdict
            .evidence_backed
            .contains(&"readiness".to_owned()));
        assert!(!record
            .verdict
            .evidence_backed
            .contains(&"run_scoped_provenance".to_owned()));
    }

    #[test]
    fn artifacts_refuse_to_overwrite_an_existing_run_directory() {
        let directory = TestDirectory::new("no-clobber");
        let config = run_config(&directory);
        let mut transport = FakeTransport::identities();
        let record = execute_s15_probe_run(
            &mut transport,
            &S15ProbeRunInput {
                config: &config,
                key: b"gateway-key".to_vec(),
                prerequisites: None,
                now_unix_ms: 1_700_000_000_000,
            },
        )
        .expect("run completes");
        write_probe_artifacts(directory.path(), &record).expect("first write");
        let error = write_probe_artifacts(directory.path(), &record).unwrap_err();
        assert!(
            error.contains("refusing_to_overwrite_existing_evidence"),
            "{error}"
        );
    }

    #[test]
    fn env_name_inventory_covers_the_documented_protected_surface() {
        let names = protected_env_names();
        for expected in [
            ENV_RUN_ID,
            ENV_TOKEN,
            ENV_GATEWAY_HMAC_FILE,
            ENV_ARTIFACT_ROOT,
            ENV_CONFIRM,
            ENV_PREREQUISITES_FILE,
            ENV_NODE_AL1,
            ENV_NODE_AL2,
            ENV_NODE_AL3,
            ENV_NODE_AL4,
        ] {
            assert!(names.contains(&expected), "missing env name {expected}");
        }
        // node_env_name maps each alias to its own variable name.
        for alias in S15_NODE_ALIASES {
            assert_eq!(node_env_name(alias), format!("ASTRAL_S15_NODE_{alias}"));
        }
    }
}
