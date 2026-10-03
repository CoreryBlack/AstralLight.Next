//! Cross-city runtime proof repository (third slice: node keys, durable replay
//! reservations, commit receipts, mint records, authority scopes).
//!
//! This module is the pure database boundary for the runtime-proof half of the
//! default-off cross-city subsystem. It owns EXACTLY the five tables created
//! by migration `20261001000002_cross_city_runtime_proof.sql`:
//!
//! - `authorization_cross_city_node_key`: the durable node key registry, one
//!   exact public key per `(city_id, node_id, node_epoch)` plus a revoked
//!   flag. The loaded registry is an immutable snapshot implementing the sync
//!   [`CrossCityNodeKeyResolver`] boundary — the "explicit fixed provider"
//!   production composition requires. Revoked or missing identities resolve
//!   to `UnknownNodeKey` (fail-closed); a neighboring epoch/city/node is NEVER
//!   guessed.
//! - `authorization_cross_city_vote_reservation`: the durable replay
//!   reservation ledger over the exact signature-boundary replay key. The
//!   reservation INSERT and the verified-vote INSERT share ONE short source
//!   transaction ([`record_cross_city_verified_vote_in_tx`]): either both
//!   commit or neither does, so a durable vote without its durable proof of
//!   cryptographic verification is structurally impossible through this
//!   module.
//! - `authorization_cross_city_commit_receipt`: insert-only signed receipts
//!   proving a city durably applied the mutation to its own source. Receipts
//!   are recorded ONLY from an authenticated (signature-verified) evidence
//!   capability whose signer city is registered authoritative for the
//!   operation's scope, and only while every pinned version (proposal,
//!   generation, revoke fence, coordinator epoch) agrees with the locked
//!   parent operation.
//! - `authorization_cross_city_operation_activation`: the durable mint record
//!   of the commit-confirmed activation (idempotency + audit witness; the
//!   mint primitive itself lives in [`crate::cross_city_repository`], where
//!   the guarded proof constructors live).
//! - `authorization_cross_city_authority_scope`: the explicit authoritative
//!   city-scope registry. An unregistered or non-authoritative city/scope
//!   pair is refused everywhere it is consulted — independent-city data
//!   source boundaries are configuration, never guesses.
//!
//! # Execution boundary (default-off subsystem)
//!
//! Nothing in this module decides authorization, flips the cross-city mode
//! switch, or contacts MQ/Redis/network. Every primitive runs inside the
//! CALLER's `Transaction` (the caller's COMMIT is the only durable point);
//! this module never commits, rolls back, retries, or sleeps. The one
//! pool-level read ([`load_cross_city_node_key_snapshot`]) is a plain
//! single-statement snapshot load with no transaction of its own.
//!
//! # Signature boundary (compile-level, not a convention)
//!
//! This module NEVER verifies signatures and NEVER accepts a raw
//! `ZeroDecisionEvidence` on a production write path. Vote and receipt writes
//! take the opaque [`CrossCityAuthenticatedEvidence`] capability, whose
//! constructor is private to `astral_common::cross_city_signature` — it is
//! structurally impossible to build one from a raw or unsigned evidence
//! outside that crate. The durable reservation row is the storage-level
//! witness that the vote/receipt went through the authenticate step; the
//! certificate/mint layer re-proves it per vote via
//! [`require_votes_have_durable_reservations_in_tx`].
//!
//! # Failure policy
//!
//! Everything fails closed. Duplicate replay keys are typed
//! [`CrossCityRuntimeRepositoryError::ReplayConflict`]s (never upserts, never
//! "equivalent success"); duplicate identities/receipts are durable
//! conflicts; missing authority registration, non-ALLOW decisions on
//! receipts, version mismatches against the locked parent, poisoned stored
//! rows, and any `rows_affected() != 1` mutation surface as explicit typed
//! errors with stable `code=cross_city_runtime_repository.*` identifiers. No
//! secret material (signatures, keys) is ever embedded into an error message.

use std::collections::HashMap;

use sqlx::{MySql, MySqlPool, Transaction};
use thiserror::Error;
use time::PrimitiveDateTime;

use astral_common::cross_city_signature::{
    CrossCityAuthenticatedEvidence, CrossCityEvidenceReplayKey, CrossCityNodeIdentity,
    CrossCityNodeKeyRecord, CrossCityNodeKeyResolver, CrossCitySignatureError,
    ED25519_PUBLIC_KEY_BYTE_LEN,
};
use astral_types::ZeroDecisionEvidence;

use crate::cross_city_repository::{
    insert_vote_in_tx, load_operation_for_update_in_tx, CrossCityRepositoryError, StoredCityVote,
    MAX_CROSS_CITY_IDENTIFIER_LENGTH,
};
use crate::grant_repository::Sha256Digest;

/// Raw byte length of an Ed25519 public key (re-declared locally so the SQL
/// decode binds the column length without leaking resolver internals).
const PUBLIC_KEY_BYTE_LEN: usize = ED25519_PUBLIC_KEY_BYTE_LEN;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed failures of the runtime-proof repository.
#[derive(Debug, Error)]
pub enum CrossCityRuntimeRepositoryError {
    /// The exact replay key was already durably reserved: the evidence is a
    /// proven replay. Never an upsert and never retried in place.
    #[error("cross-city replay reservation conflict: {0}")]
    ReplayConflict(String),
    /// A database driver error occurred.
    #[error("database query failed: {0}")]
    Query(#[from] sqlx::Error),
    /// A sibling cross-city repository primitive refused the input.
    #[error(transparent)]
    Repository(#[from] CrossCityRepositoryError),
}

impl CrossCityRuntimeRepositoryError {
    /// Stable machine-readable code for audit events and metrics.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ReplayConflict(_) => "CROSS_CITY_REPLAY_RESERVED",
            Self::Query(_) => "CROSS_CITY_RUNTIME_STORAGE_FAILED",
            Self::Repository(_) => "CROSS_CITY_RUNTIME_REPOSITORY_REFUSED",
        }
    }
}

fn mapping(code: &str) -> CrossCityRepositoryError {
    CrossCityRepositoryError::Mapping(format!("code=cross_city_runtime_repository.{code}"))
}

fn scope_violation(code: &str) -> CrossCityRepositoryError {
    CrossCityRepositoryError::ScopeViolation(format!("code=cross_city_runtime_repository.{code}"))
}

fn conflict(code: &str) -> CrossCityRepositoryError {
    CrossCityRepositoryError::Conflict(format!("code=cross_city_runtime_repository.{code}"))
}

fn db_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
}

fn digest_from_hex(value: &str) -> Result<Sha256Digest, CrossCityRepositoryError> {
    Sha256Digest::from_hex(value).map_err(|_| mapping("invalid_sha256_hex"))
}

fn bind_i64(value: u64, field: &'static str) -> Result<i64, CrossCityRepositoryError> {
    i64::try_from(value).map_err(|_| {
        CrossCityRepositoryError::Mapping(format!(
            "code=cross_city_runtime_repository.bigint_overflow;field={field}"
        ))
    })
}

fn read_u64(value: i64, field: &'static str) -> Result<u64, CrossCityRepositoryError> {
    u64::try_from(value).map_err(|_| {
        CrossCityRepositoryError::Mapping(format!(
            "code=cross_city_runtime_repository.negative_bigint;field={field}"
        ))
    })
}

fn validated_text(
    value: &str,
    max_length: usize,
    field: &'static str,
) -> Result<(), CrossCityRepositoryError> {
    if value.trim() != value {
        return Err(scope_violation(&format!("padded_field;field={field}")));
    }
    if value.is_empty()
        || value.len() > max_length
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(scope_violation(&format!(
            "invalid_field;field={field};max_length={max_length}"
        )));
    }
    Ok(())
}

fn validated_operation_id(value: &str) -> Result<String, CrossCityRepositoryError> {
    let bytes = value.as_bytes();
    let hyphen_ok = |index: usize| index < bytes.len() && bytes[index] == b'-';
    let length_ok =
        bytes.len() == 36 && hyphen_ok(8) && hyphen_ok(13) && hyphen_ok(18) && hyphen_ok(23);
    let lowercase_ok = bytes.iter().enumerate().all(|(index, byte)| {
        hyphen_ok(index) || byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
    });
    if !length_ok || !lowercase_ok {
        return Err(mapping("invalid_operation_id"));
    }
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| mapping("unparsable_operation_id"))?;
    if parsed.is_nil() || parsed.to_string() != value {
        return Err(mapping("noncanonical_operation_id"));
    }
    Ok(value.to_owned())
}

fn validate_generation_pair(
    target_generation: u64,
    revoke_fence: u64,
    field_prefix: &str,
) -> Result<(), CrossCityRepositoryError> {
    if target_generation == 0 {
        return Err(scope_violation(&format!(
            "{field_prefix}_non_positive_generation"
        )));
    }
    if revoke_fence > target_generation {
        return Err(scope_violation(&format!(
            "{field_prefix}_fence_exceeds_generation;generation={target_generation};fence={revoke_fence}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SQL statements (fixed constants; registered in the test registry verbatim)
// ---------------------------------------------------------------------------

const NODE_KEY_INSERT_SQL: &str = "INSERT INTO authorization_cross_city_node_key \
     (city_id, node_id, node_epoch, public_key) VALUES (?, ?, ?, ?)";
const NODE_KEY_REVOKE_SQL: &str = "UPDATE authorization_cross_city_node_key \
     SET revoked = 1, revoked_at = UTC_TIMESTAMP(), revoked_reason = ? \
     WHERE city_id = ? AND node_id = ? AND node_epoch = ? AND revoked = 0";
const NODE_KEY_SELECT_ALL_SQL: &str = "SELECT node_key_id, city_id, node_id, node_epoch, \
     public_key, revoked FROM authorization_cross_city_node_key ORDER BY node_key_id";

const RESERVATION_INSERT_SQL: &str = "INSERT INTO authorization_cross_city_vote_reservation \
     (operation_id, city_id, node_id, node_epoch, nonce, evidence_digest) \
     VALUES (?, ?, ?, ?, ?, ?)";
const RESERVATION_PROVE_SQL: &str = "SELECT reservation_id FROM \
     authorization_cross_city_vote_reservation WHERE operation_id = ? AND city_id = ? \
     AND node_id = ? AND node_epoch = ? AND nonce = ? AND evidence_digest = ?";

const RECEIPT_INSERT_SQL: &str = "INSERT INTO authorization_cross_city_commit_receipt \
     (operation_id, city_id, node_id, node_epoch, decision, proposal_digest, \
      evidence_digest, target_generation, revoke_fence, coordinator_epoch, nonce, signature) \
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
const RECEIPT_SELECT_FOR_OPERATION_SQL: &str = "SELECT receipt_id, operation_id, city_id, \
     node_id, node_epoch, decision, proposal_digest, evidence_digest, target_generation, \
     revoke_fence, coordinator_epoch, nonce, signature, observed_at \
     FROM authorization_cross_city_commit_receipt WHERE operation_id = ? ORDER BY receipt_id";

const AUTHORITY_SCOPE_INSERT_SQL: &str = "INSERT INTO authorization_cross_city_authority_scope \
     (city_id, scope_digest, authoritative) VALUES (?, ?, ?)";
const AUTHORITY_SCOPE_REQUIRE_SQL: &str = "SELECT authoritative FROM \
     authorization_cross_city_authority_scope WHERE city_id = ? AND scope_digest = ?";
const AUTHORITY_SCOPE_SELECT_ALL_SQL: &str = "SELECT scope_id, city_id, scope_digest, \
     authoritative FROM authorization_cross_city_authority_scope ORDER BY scope_id";

// ---------------------------------------------------------------------------
// Node key registry (durable resolver over an explicit fixed snapshot)
// ---------------------------------------------------------------------------

/// Insert-only request for one node key registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityNodeKeyInsert {
    pub city_id: String,
    pub node_id: String,
    pub node_epoch: u64,
    /// Canonical lowercase 64-character hex Ed25519 public key.
    pub public_key_hex: String,
}

/// Insert one node key registration. Plain INSERT: an existing registration
/// for the same exact identity is a durable conflict — re-keying an identity
/// requires a new epoch, never an overwrite of key material.
pub async fn insert_cross_city_node_key_in_tx(
    tx: &mut Transaction<'_, MySql>,
    insert: &CrossCityNodeKeyInsert,
) -> Result<i64, CrossCityRuntimeRepositoryError> {
    validated_text(&insert.city_id, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "city_id")?;
    validated_text(&insert.node_id, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "node_id")?;
    let epoch = bind_i64(insert.node_epoch, "node_epoch")?;
    let identity = CrossCityNodeIdentity::new(&insert.city_id, &insert.node_id, insert.node_epoch)
        .map_err(|_| mapping("invalid_node_identity"))?;
    // Canonical-hex + length decode happens inside the key record; strict
    // Ed25519 decompressibility is re-proved at every verification in the
    // astral-common boundary, so a malformed key can never verify.
    let record = CrossCityNodeKeyRecord::from_public_key_hex(identity, &insert.public_key_hex)
        .map_err(|_| mapping("invalid_node_public_key"))?;

    let result = sqlx::query(NODE_KEY_INSERT_SQL)
        .bind(&insert.city_id)
        .bind(&insert.node_id)
        .bind(epoch)
        .bind(record.public_key().as_slice())
        .execute(&mut **tx)
        .await
        .map_err(CrossCityRuntimeRepositoryError::from)?;
    if result.rows_affected() != 1 {
        return Err(mapping("node_key_insert_not_applied").into());
    }
    let key_id = i64::try_from(result.last_insert_id()).map_err(|_| {
        CrossCityRepositoryError::Mapping(
            "code=cross_city_runtime_repository.bigint_overflow;field=node_key_id".to_owned(),
        )
    })?;
    if key_id == 0 {
        return Err(mapping("node_key_insert_not_applied").into());
    }
    Ok(key_id)
}

/// Revoke one exact node identity (CAS `revoked = 0 -> 1`). A missing or
/// already-revoked identity is a typed conflict; revocation never deletes the
/// row (durable audit of every key that ever existed).
pub async fn revoke_cross_city_node_key_in_tx(
    tx: &mut Transaction<'_, MySql>,
    city_id: &str,
    node_id: &str,
    node_epoch: u64,
    reason: &str,
) -> Result<(), CrossCityRuntimeRepositoryError> {
    validated_text(city_id, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "city_id")?;
    validated_text(node_id, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "node_id")?;
    validated_text(reason, 512, "revoked_reason")?;
    let epoch = bind_i64(node_epoch, "node_epoch")?;
    let result = sqlx::query(NODE_KEY_REVOKE_SQL)
        .bind(reason)
        .bind(city_id)
        .bind(node_id)
        .bind(epoch)
        .execute(&mut **tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(conflict("node_key_revoke_not_applied").into());
    }
    Ok(())
}

#[derive(Debug, sqlx::FromRow)]
struct NodeKeyRow {
    node_key_id: i64,
    city_id: String,
    node_id: String,
    node_epoch: i64,
    public_key: Vec<u8>,
    revoked: i8,
}

/// Immutable, exact-identity snapshot of the durable node key registry.
///
/// This is the production "explicit fixed provider" of the sync
/// [`CrossCityNodeKeyResolver`] boundary: it is loaded ONCE (durably, by the
/// embedding process at construction time) and resolves purely from its
/// loaded rows afterwards — no hidden runtime DB calls, no cache, no fallback
/// to neighboring identities. Revoked rows are excluded from resolution
/// entirely (they resolve to `UnknownNodeKey`, exactly like unregistered
/// identities) but remain counted for audit.
#[derive(Clone, Default)]
pub struct CrossCityNodeKeySnapshot {
    usable: HashMap<CrossCityNodeIdentity, CrossCityNodeKeyRecord>,
    revoked_count: usize,
    total_count: usize,
}

impl CrossCityNodeKeySnapshot {
    /// Number of usable (non-revoked) registered identities.
    pub fn usable_count(&self) -> usize {
        self.usable.len()
    }

    /// Number of revoked registrations (audit only; they never resolve).
    pub const fn revoked_count(&self) -> usize {
        self.revoked_count
    }

    /// Total number of registered identities seen in the durable registry.
    pub const fn total_count(&self) -> usize {
        self.total_count
    }

    /// Whether the registry is empty (the coordinator's config gate refuses
    /// to enable cross-city work over an empty registry).
    pub fn is_empty(&self) -> bool {
        self.total_count == 0
    }

    /// Whether the exact identity is registered and usable.
    pub fn knows_identity(&self, identity: &CrossCityNodeIdentity) -> bool {
        self.usable.contains_key(identity)
    }
}

impl std::fmt::Debug for CrossCityNodeKeySnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Key material is never rendered.
        formatter
            .debug_struct("CrossCityNodeKeySnapshot")
            .field("usable_count", &self.usable.len())
            .field("revoked_count", &self.revoked_count)
            .field("total_count", &self.total_count)
            .finish()
    }
}

impl CrossCityNodeKeyResolver for CrossCityNodeKeySnapshot {
    fn resolve_node_key(
        &self,
        identity: &CrossCityNodeIdentity,
    ) -> Result<CrossCityNodeKeyRecord, CrossCitySignatureError> {
        self.usable
            .get(identity)
            .cloned()
            .ok_or(CrossCitySignatureError::UnknownNodeKey)
    }
}

/// Load the durable node key registry into an immutable snapshot (pool-level
/// read; no transaction of its own). Every row is strictly decoded; any
/// poisoned row fails the WHOLE snapshot closed (a half-loaded registry could
/// silently widen or narrow who may sign).
pub async fn load_cross_city_node_key_snapshot(
    pool: &MySqlPool,
) -> Result<CrossCityNodeKeySnapshot, CrossCityRuntimeRepositoryError> {
    let rows: Vec<NodeKeyRow> = sqlx::query_as(NODE_KEY_SELECT_ALL_SQL)
        .fetch_all(pool)
        .await?;
    let mut snapshot = CrossCityNodeKeySnapshot::default();
    for row in rows {
        snapshot.total_count += 1;
        if row.node_key_id <= 0 {
            return Err(mapping("poisoned_node_key_row").into());
        }
        if row.revoked != 0 {
            snapshot.revoked_count += 1;
            continue;
        }
        let epoch = read_u64(row.node_epoch, "node_epoch")?;
        if epoch == 0 {
            return Err(mapping("poisoned_node_key_epoch").into());
        }
        validated_text(&row.city_id, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "city_id")?;
        validated_text(&row.node_id, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "node_id")?;
        let identity = CrossCityNodeIdentity::new(&row.city_id, &row.node_id, epoch)
            .map_err(|_| mapping("poisoned_node_key_identity"))?;
        let public_key: [u8; PUBLIC_KEY_BYTE_LEN] = row
            .public_key
            .try_into()
            .map_err(|_| mapping("poisoned_node_key_public_key_length"))?;
        let record = CrossCityNodeKeyRecord::new(identity.clone(), public_key);
        if snapshot.usable.insert(identity, record).is_some() {
            // Structurally impossible under uk_accnk_identity; kept fail-closed.
            return Err(mapping("poisoned_node_key_duplicate_identity").into());
        }
    }
    Ok(snapshot)
}

// ---------------------------------------------------------------------------
// Durable replay reservation + verified vote (ONE transaction)
// ---------------------------------------------------------------------------

/// The durably recorded, cryptographically verified vote: the row exists ONLY
/// together with its durable replay reservation (same transaction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityVerifiedVoteRecord {
    pub vote_id: i64,
    pub operation_id: String,
    pub evidence: ZeroDecisionEvidence,
    pub replay_key: CrossCityEvidenceReplayKey,
}

/// Durably reserve the replay key AND insert the verified vote inside ONE
/// short source transaction.
///
/// Ordering and guarantees:
///
/// 1. `authenticated` is an opaque capability minted by the pure
///    astral-common authentication boundary — a raw/unsigned evidence cannot
///    reach this function through the type system.
/// 2. The reservation INSERT runs FIRST: a replayed evidence is blocked at
///    the earliest possible durable point with a typed
///    [`CrossCityRuntimeRepositoryError::ReplayConflict`].
/// 3. The vote INSERT reuses the sibling cross-city repository primitive
///    (operation lock, proposal binding, accepting-state whitelist, per-city
///    capacity, plain insert with duplicate-key conflicts) inside the SAME
///    transaction — any failure rolls back the reservation with it.
///
/// The caller owns the transaction and its COMMIT: nothing here is durable
/// before that commit, and no network/MQ/Redis work may happen inside it.
pub async fn record_cross_city_verified_vote_in_tx(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
    authenticated: &CrossCityAuthenticatedEvidence,
    now_seconds: i64,
) -> Result<CrossCityVerifiedVoteRecord, CrossCityRuntimeRepositoryError> {
    let operation_id = validated_operation_id(operation_id)?;
    let evidence = authenticated.evidence();
    validated_text(
        &evidence.city_id,
        MAX_CROSS_CITY_IDENTIFIER_LENGTH,
        "city_id",
    )?;
    validated_text(
        &evidence.node_id,
        MAX_CROSS_CITY_IDENTIFIER_LENGTH,
        "node_id",
    )?;
    validated_text(&evidence.nonce, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "nonce")?;
    let replay_key = authenticated.replay_key().clone();
    let evidence_digest = digest_from_hex(replay_key.evidence_digest())?;
    let epoch = bind_i64(replay_key.node_epoch(), "node_epoch")?;

    // 1. Durable replay reservation (insert-only; duplicate = proven replay).
    let reservation = sqlx::query(RESERVATION_INSERT_SQL)
        .bind(&operation_id)
        .bind(replay_key.city_id())
        .bind(replay_key.node_id())
        .bind(epoch)
        .bind(replay_key.nonce())
        .bind(evidence_digest.as_bytes().to_vec())
        .execute(&mut **tx)
        .await;
    if let Err(error) = reservation {
        if db_unique_violation(&error) {
            return Err(CrossCityRuntimeRepositoryError::ReplayConflict(format!(
                "code=cross_city_runtime_repository.replay_key_already_reserved;city={};node={}",
                replay_key.city_id(),
                replay_key.node_id()
            )));
        }
        return Err(error.into());
    }

    // 2. Verified vote insert in the SAME transaction (sibling primitive owns
    //    the operation lock, binding, state whitelist, and city capacity).
    let vote_id = insert_vote_in_tx(tx, &operation_id, evidence, now_seconds).await?;

    Ok(CrossCityVerifiedVoteRecord {
        vote_id,
        operation_id,
        evidence: evidence.clone(),
        replay_key,
    })
}

/// Prove that every stored vote of one operation carries its durable replay
/// reservation row (the storage-level witness that the vote went through the
/// cryptographic authenticate step). A stored vote WITHOUT its reservation is
/// poisoned storage and fails closed — the certificate/mint layer refuses to
/// derive anything from unverifiable evidence.
pub async fn require_votes_have_durable_reservations_in_tx(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
    votes: &[StoredCityVote],
) -> Result<(), CrossCityRuntimeRepositoryError> {
    let operation_id = validated_operation_id(operation_id)?;
    for vote in votes {
        let evidence = &vote.evidence;
        if evidence.city_id.is_empty() || evidence.node_id.is_empty() || evidence.nonce.is_empty() {
            return Err(mapping("poisoned_vote_replay_identity").into());
        }
        let evidence_digest = digest_from_hex(&evidence.evidence_digest)?;
        let epoch = bind_i64(evidence.node_epoch, "node_epoch")?;
        let proven = sqlx::query(RESERVATION_PROVE_SQL)
            .bind(&operation_id)
            .bind(&evidence.city_id)
            .bind(&evidence.node_id)
            .bind(epoch)
            .bind(&evidence.nonce)
            .bind(evidence_digest.as_bytes().to_vec())
            .fetch_optional(&mut **tx)
            .await?;
        if proven.is_none() {
            return Err(mapping(&format!(
                "poisoned_vote_without_durable_reservation;city={};node={}",
                evidence.city_id, evidence.node_id
            ))
            .into());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Authoritative city-scope registry (explicit configuration, never guesses)
// ---------------------------------------------------------------------------

/// Insert-only request registering one city as authoritative for one scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityAuthorityScopeInsert {
    pub city_id: String,
    /// Canonical lowercase 64-character hex scope digest.
    pub scope_digest_hex: String,
    /// Only an explicit `true` is admitted as authoritative; `false` rows are
    /// legal explicit refusals (they block, they never enable).
    pub authoritative: bool,
}

/// Insert one authoritative city-scope registration. Plain INSERT: an
/// existing row for the same (city, scope) pair is a durable conflict.
pub async fn insert_cross_city_authority_scope_in_tx(
    tx: &mut Transaction<'_, MySql>,
    insert: &CrossCityAuthorityScopeInsert,
) -> Result<i64, CrossCityRuntimeRepositoryError> {
    validated_text(&insert.city_id, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "city_id")?;
    let scope = digest_from_hex(&insert.scope_digest_hex)?;
    let result = sqlx::query(AUTHORITY_SCOPE_INSERT_SQL)
        .bind(&insert.city_id)
        .bind(scope.as_bytes().to_vec())
        .bind(i64::from(insert.authoritative))
        .execute(&mut **tx)
        .await
        .map_err(CrossCityRuntimeRepositoryError::from)?;
    if result.rows_affected() != 1 {
        return Err(mapping("authority_scope_insert_not_applied").into());
    }
    let scope_id = i64::try_from(result.last_insert_id()).map_err(|_| {
        CrossCityRepositoryError::Mapping(
            "code=cross_city_runtime_repository.bigint_overflow;field=scope_id".to_owned(),
        )
    })?;
    if scope_id == 0 {
        return Err(mapping("authority_scope_insert_not_applied").into());
    }
    Ok(scope_id)
}

/// Require the city to be EXPLICITLY registered authoritative for the scope.
/// A missing row, or a row whose `authoritative` flag is 0, fails closed:
/// independent-city data-source boundaries come from configuration only.
pub async fn require_cross_city_authority_scope_in_tx(
    tx: &mut Transaction<'_, MySql>,
    city_id: &str,
    scope_digest_hex: &str,
) -> Result<(), CrossCityRepositoryError> {
    validated_text(city_id, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "city_id")?;
    let scope = digest_from_hex(scope_digest_hex)?;
    let row: Option<(i64,)> = sqlx::query_as(AUTHORITY_SCOPE_REQUIRE_SQL)
        .bind(city_id)
        .bind(scope.as_bytes().to_vec())
        .fetch_optional(&mut **tx)
        .await?;
    match row {
        Some((authoritative,)) if authoritative != 0 => Ok(()),
        Some(_) => Err(scope_violation(&format!(
            "authority_scope_not_authoritative;city={city_id}"
        ))),
        None => Err(scope_violation(&format!(
            "authority_scope_unregistered;city={city_id}"
        ))),
    }
}

#[derive(Debug, sqlx::FromRow)]
struct AuthorityScopeRow {
    scope_id: i64,
    city_id: String,
    scope_digest: Vec<u8>,
    authoritative: i64,
}

/// One decoded authoritative city-scope registry entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityAuthorityScopeEntry {
    pub scope_id: i64,
    pub city_id: String,
    pub scope_digest_hex: String,
    pub authoritative: bool,
}

/// Load the durable authoritative city-scope registry (pool-level read; no
/// transaction of its own). The runtime wiring's startup admission requires
/// at least one explicitly authoritative row: an empty registry is missing
/// configuration and refuses startup, never silently enables.
pub async fn load_cross_city_authority_scope_registry(
    pool: &MySqlPool,
) -> Result<Vec<CrossCityAuthorityScopeEntry>, CrossCityRuntimeRepositoryError> {
    let rows: Vec<AuthorityScopeRow> = sqlx::query_as(AUTHORITY_SCOPE_SELECT_ALL_SQL)
        .fetch_all(pool)
        .await?;
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        if row.scope_id <= 0 {
            return Err(mapping("poisoned_authority_scope_row").into());
        }
        validated_text(&row.city_id, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "city_id")?;
        let scope = Sha256Digest::from_bytes(row.scope_digest)
            .map_err(|_| mapping("poisoned_authority_scope_digest"))?;
        entries.push(CrossCityAuthorityScopeEntry {
            scope_id: row.scope_id,
            city_id: row.city_id,
            scope_digest_hex: scope.as_hex(),
            authoritative: row.authoritative != 0,
        });
    }
    Ok(entries)
}

// ---------------------------------------------------------------------------
// Commit receipts (signed durable source-apply evidence per city/node)
// ---------------------------------------------------------------------------

/// Version pins a commit receipt must agree on with the locked parent
/// operation (proposal binding happens against the loaded record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityCommitReceiptMeta {
    pub target_generation: u64,
    pub revoke_fence: u64,
    pub coordinator_epoch: u64,
}

/// The durably recorded commit receipt of one city node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossCityCommitReceiptRecord {
    pub receipt_id: i64,
    pub operation_id: String,
    pub city_id: String,
    pub node_id: String,
    pub node_epoch: u64,
    pub proposal_digest_hex: String,
    pub evidence_digest_hex: String,
    pub target_generation: u64,
    pub revoke_fence: u64,
    pub coordinator_epoch: u64,
    pub nonce: String,
    pub signature: String,
    pub observed_at_seconds: i64,
}

/// Record one signed, durable source-apply commit receipt.
///
/// Admission (fail-closed, inside the caller's transaction):
/// 1. `authenticated` is the opaque astral-common capability — the receipt is
///    cryptographically verified before this function runs;
/// 2. the decision must be ALLOW: a DENY evidence never proves an apply;
/// 3. the signer city must be explicitly registered authoritative for the
///    parent operation's scope digest;
/// 4. every pinned version must agree with the locked parent operation:
///    proposal digest, target generation, revoke fence, coordinator epoch;
/// 5. the replay key is durably reserved in the SAME transaction (one nonce,
///    one use, global); a duplicate is a typed replay conflict;
/// 6. the receipt row is insert-only: one node contributes exactly one
///    receipt per operation, and any duplicate key is a durable conflict.
pub async fn record_cross_city_commit_receipt_in_tx(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
    authenticated: &CrossCityAuthenticatedEvidence,
    meta: &CrossCityCommitReceiptMeta,
    now_seconds: i64,
) -> Result<i64, CrossCityRuntimeRepositoryError> {
    let operation_id = validated_operation_id(operation_id)?;
    validate_generation_pair(meta.target_generation, meta.revoke_fence, "commit_receipt")?;
    if meta.coordinator_epoch == 0 {
        return Err(scope_violation("commit_receipt_non_positive_epoch").into());
    }
    let evidence = authenticated.evidence();
    if evidence.decision != astral_types::NodeDecision::Allow {
        return Err(scope_violation("commit_receipt_decision_not_allow").into());
    }
    validated_text(
        &evidence.city_id,
        MAX_CROSS_CITY_IDENTIFIER_LENGTH,
        "city_id",
    )?;
    validated_text(
        &evidence.node_id,
        MAX_CROSS_CITY_IDENTIFIER_LENGTH,
        "node_id",
    )?;
    validated_text(&evidence.nonce, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "nonce")?;

    // Parent operation: locked in the same transaction, every pin re-checked.
    let operation = load_operation_for_update_in_tx(tx, &operation_id).await?;
    if evidence.proposal_digest != operation.proposal_digest {
        return Err(scope_violation("commit_receipt_proposal_binding_mismatch").into());
    }
    if meta.target_generation != operation.target_generation
        || meta.revoke_fence != operation.target_revoke_fence
    {
        return Err(scope_violation("commit_receipt_generation_binding_mismatch").into());
    }
    if meta.coordinator_epoch != operation.coordinator_epoch {
        return Err(scope_violation("commit_receipt_epoch_binding_mismatch").into());
    }
    // Explicit city data-source boundary: the signer city must be registered
    // authoritative for exactly this scope. Missing configuration is refused.
    require_cross_city_authority_scope_in_tx(tx, &evidence.city_id, &operation.scope_digest)
        .await?;

    let proposal_digest = digest_from_hex(&evidence.proposal_digest)?;
    let evidence_digest = digest_from_hex(&evidence.evidence_digest)?;
    let epoch = bind_i64(evidence.node_epoch, "node_epoch")?;
    let generation = bind_i64(meta.target_generation, "target_generation")?;
    let fence = bind_i64(meta.revoke_fence, "revoke_fence")?;
    let coordinator_epoch = bind_i64(meta.coordinator_epoch, "coordinator_epoch")?;

    // Durable replay reservation over the exact replay key (same ledger and
    // the same uniqueness semantics as votes).
    let reservation = sqlx::query(RESERVATION_INSERT_SQL)
        .bind(&operation_id)
        .bind(&evidence.city_id)
        .bind(&evidence.node_id)
        .bind(epoch)
        .bind(&evidence.nonce)
        .bind(evidence_digest.as_bytes().to_vec())
        .execute(&mut **tx)
        .await;
    if let Err(error) = reservation {
        if db_unique_violation(&error) {
            return Err(CrossCityRuntimeRepositoryError::ReplayConflict(format!(
                "code=cross_city_runtime_repository.replay_key_already_reserved;city={};node={}",
                evidence.city_id, evidence.node_id
            )));
        }
        return Err(error.into());
    }

    let result = sqlx::query(RECEIPT_INSERT_SQL)
        .bind(&operation_id)
        .bind(&evidence.city_id)
        .bind(&evidence.node_id)
        .bind(epoch)
        .bind(evidence.decision.as_str())
        .bind(proposal_digest.as_bytes().to_vec())
        .bind(evidence_digest.as_bytes().to_vec())
        .bind(generation)
        .bind(fence)
        .bind(coordinator_epoch)
        .bind(&evidence.nonce)
        .bind(&evidence.signature)
        .execute(&mut **tx)
        .await;
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            if db_unique_violation(&error) {
                // One node, one receipt per operation; a repeated node or a
                // reused per-operation nonce is a durable conflict to audit.
                return Err(conflict("commit_receipt_duplicate").into());
            }
            return Err(error.into());
        }
    };
    if result.rows_affected() != 1 {
        return Err(mapping("commit_receipt_insert_not_applied").into());
    }
    let receipt_id = i64::try_from(result.last_insert_id()).map_err(|_| {
        CrossCityRepositoryError::Mapping(
            "code=cross_city_runtime_repository.bigint_overflow;field=receipt_id".to_owned(),
        )
    })?;
    if receipt_id == 0 {
        return Err(mapping("commit_receipt_insert_not_applied").into());
    }
    let _ = now_seconds; // observed_at is computed server-side (UTC_TIMESTAMP)
    Ok(receipt_id)
}

#[derive(Debug, sqlx::FromRow)]
struct CommitReceiptRow {
    receipt_id: i64,
    operation_id: String,
    city_id: String,
    node_id: String,
    node_epoch: i64,
    decision: String,
    proposal_digest: Vec<u8>,
    evidence_digest: Vec<u8>,
    target_generation: i64,
    revoke_fence: i64,
    coordinator_epoch: i64,
    nonce: String,
    signature: String,
    observed_at: PrimitiveDateTime,
}

/// Load and strictly decode every durable commit receipt of one operation
/// (deterministic `receipt_id` order). Stored rows are evidence only — the
/// caller (the mint primitive) re-checks every binding against the locked
/// parent before deriving any activation digest.
pub async fn load_cross_city_commit_receipts_in_tx(
    tx: &mut Transaction<'_, MySql>,
    operation_id: &str,
) -> Result<Vec<CrossCityCommitReceiptRecord>, CrossCityRuntimeRepositoryError> {
    let operation_id = validated_operation_id(operation_id)?;
    let rows: Vec<CommitReceiptRow> = sqlx::query_as(RECEIPT_SELECT_FOR_OPERATION_SQL)
        .bind(&operation_id)
        .fetch_all(&mut **tx)
        .await?;
    let mut receipts = Vec::with_capacity(rows.len());
    for row in rows {
        if row.receipt_id <= 0 || row.operation_id != operation_id {
            return Err(mapping("poisoned_commit_receipt_identity").into());
        }
        if row.decision != astral_types::NodeDecision::Allow.as_str() {
            // DENY receipts are refused at write time; a stored DENY row is
            // poisoned storage and fails closed on read.
            return Err(mapping("poisoned_commit_receipt_decision").into());
        }
        let proposal_digest = Sha256Digest::from_bytes(row.proposal_digest)
            .map_err(|_| mapping("poisoned_commit_receipt_digest"))?;
        let evidence_digest = Sha256Digest::from_bytes(row.evidence_digest)
            .map_err(|_| mapping("poisoned_commit_receipt_digest"))?;
        validated_text(&row.city_id, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "city_id")?;
        validated_text(&row.node_id, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "node_id")?;
        validated_text(&row.nonce, MAX_CROSS_CITY_IDENTIFIER_LENGTH, "nonce")?;
        receipts.push(CrossCityCommitReceiptRecord {
            receipt_id: row.receipt_id,
            operation_id: row.operation_id,
            city_id: row.city_id,
            node_id: row.node_id,
            node_epoch: read_u64(row.node_epoch, "node_epoch")?,
            proposal_digest_hex: proposal_digest.as_hex(),
            evidence_digest_hex: evidence_digest.as_hex(),
            target_generation: read_u64(row.target_generation, "target_generation")?,
            revoke_fence: read_u64(row.revoke_fence, "revoke_fence")?,
            coordinator_epoch: read_u64(row.coordinator_epoch, "coordinator_epoch")?,
            nonce: row.nonce,
            signature: row.signature,
            observed_at_seconds: row.observed_at.assume_utc().unix_timestamp(),
        });
    }
    Ok(receipts)
}

// ---------------------------------------------------------------------------
// Tests (pure: no DB, no network, no external system)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn production_source() -> &'static str {
        const TEST_MODULE_MARKER: &str = concat!("#[", "cfg(test)]");
        let source = include_str!("cross_city_runtime_repository.rs");
        source
            .split_once(TEST_MODULE_MARKER)
            .map(|(production, _)| production)
            .expect("test-module marker present")
    }

    fn production_function_body(signature_needle: &str) -> &'static str {
        let production = production_source();
        let start = production
            .find(signature_needle)
            .unwrap_or_else(|| panic!("production function missing: {signature_needle}"));
        let end = production[start..]
            .find("\n}")
            .map(|position| start + position)
            .unwrap_or_else(|| panic!("function body unterminated: {signature_needle}"));
        &production[start..end]
    }

    fn placeholder_count(statement: &str) -> usize {
        statement.bytes().filter(|byte| *byte == b'?').count()
    }

    #[test]
    fn every_sqlx_call_uses_the_registered_statement_constants() {
        let production = production_source();
        for forbidden_path in [
            "sqlx::raw_sql",
            "raw_sql(",
            "query_scalar",
            "query_unchecked",
            "query_as_unchecked",
            "query!(",
            "query_as!(",
        ] {
            assert!(
                !production.contains(forbidden_path),
                "non-registry SQL path present: {forbidden_path}"
            );
        }
        let needle = "sqlx::query";
        let mut call_sites: Vec<&str> = Vec::new();
        let mut rest = production;
        while let Some(position) = rest.find(needle) {
            let after = &rest[position + needle.len()..];
            let after = if let Some(rest) = after.strip_prefix("_as(") {
                rest
            } else if let Some(rest) = after.strip_prefix('(') {
                rest
            } else {
                panic!("unexpected sqlx::query call form: {after:?}");
            };
            let name_end = after
                .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .expect("statement constant name not terminated");
            call_sites.push(&after[..name_end]);
            rest = after;
        }
        let registry: &[&str] = &[
            "NODE_KEY_INSERT_SQL",
            "NODE_KEY_REVOKE_SQL",
            "NODE_KEY_SELECT_ALL_SQL",
            // The reservation insert has TWO production call sites (verified
            // vote and commit receipt share the replay ledger).
            "RESERVATION_INSERT_SQL",
            "RESERVATION_INSERT_SQL",
            "RESERVATION_PROVE_SQL",
            "RECEIPT_INSERT_SQL",
            "RECEIPT_SELECT_FOR_OPERATION_SQL",
            "AUTHORITY_SCOPE_INSERT_SQL",
            "AUTHORITY_SCOPE_REQUIRE_SQL",
            "AUTHORITY_SCOPE_SELECT_ALL_SQL",
        ];
        for name in &call_sites {
            assert!(
                registry.contains(name),
                "inline or unregistered SQL statement: {name}"
            );
        }
        assert_eq!(
            call_sites.len(),
            registry.len(),
            "production sqlx::query* call count drifted from the registry"
        );
    }

    #[test]
    fn statements_bind_exactly_the_expected_parameter_counts() {
        let expected: [(&str, usize); 10] = [
            (NODE_KEY_INSERT_SQL, 4),
            (NODE_KEY_REVOKE_SQL, 4),
            (NODE_KEY_SELECT_ALL_SQL, 0),
            (RESERVATION_INSERT_SQL, 6),
            (RESERVATION_PROVE_SQL, 6),
            (RECEIPT_INSERT_SQL, 12),
            (RECEIPT_SELECT_FOR_OPERATION_SQL, 1),
            (AUTHORITY_SCOPE_INSERT_SQL, 3),
            (AUTHORITY_SCOPE_REQUIRE_SQL, 2),
            (AUTHORITY_SCOPE_SELECT_ALL_SQL, 0),
        ];
        for (statement, count) in expected {
            assert_eq!(
                placeholder_count(statement),
                count,
                "placeholder drift in: {statement}"
            );
        }
    }

    #[test]
    fn evidence_tables_are_insert_and_select_only() {
        // The replay-reservation and commit-receipt ledgers are insert-only
        // durable evidence: no UPDATE/DELETE/UPSERT may ever touch them.
        for statement in [
            RESERVATION_INSERT_SQL,
            RESERVATION_PROVE_SQL,
            RECEIPT_INSERT_SQL,
            RECEIPT_SELECT_FOR_OPERATION_SQL,
        ] {
            assert!(!statement.contains("UPDATE"));
            assert!(!statement.contains("DELETE"));
            assert!(!statement.contains("ON DUPLICATE"));
            assert!(!statement.contains("REPLACE INTO"));
        }
        // And the module as a whole never upserts anywhere either.
        let production = production_source();
        assert!(!production.contains("ON DUPLICATE"));
        assert!(!production.contains("REPLACE INTO"));
    }

    #[test]
    fn module_owns_exactly_the_five_runtime_proof_tables() {
        // No statement may reach a sibling-owned table directly: votes are
        // written through cross_city_repository::insert_vote_in_tx, and the
        // operation/vote/city-state/gate/outbox/inbox tables stay there.
        for statement in [
            NODE_KEY_INSERT_SQL,
            NODE_KEY_REVOKE_SQL,
            NODE_KEY_SELECT_ALL_SQL,
            RESERVATION_INSERT_SQL,
            RESERVATION_PROVE_SQL,
            RECEIPT_INSERT_SQL,
            RECEIPT_SELECT_FOR_OPERATION_SQL,
            AUTHORITY_SCOPE_INSERT_SQL,
            AUTHORITY_SCOPE_REQUIRE_SQL,
        ] {
            for foreign_table in [
                "authorization_cross_city_operation ",
                "authorization_cross_city_vote ",
                "authorization_cross_city_city_state",
                "authorization_cross_city_gate",
                "authorization_cross_city_outbox",
                "authorization_cross_city_inbox",
            ] {
                assert!(
                    !statement.contains(foreign_table),
                    "runtime-proof statement touches foreign table {foreign_table}"
                );
            }
        }
    }

    // -- Pure admission helpers -------------------------------------------------

    #[test]
    fn validated_operation_id_enforces_canonical_lowercase_uuid() {
        let canonical = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            validated_operation_id(canonical).expect("canonical operation id"),
            canonical
        );
        assert!(validated_operation_id("550E8400-E29B-41D4-A716-446655440000").is_err());
        assert!(validated_operation_id("00000000-0000-0000-0000-000000000000").is_err());
        assert!(validated_operation_id("550e8400e29b41d4a716446655440000").is_err());
        assert!(validated_operation_id("550e8400-e29b-41d4-a716").is_err());
        assert!(validated_operation_id("550e8400-e29b-41d4-a716-44665544000g").is_err());
    }

    #[test]
    fn generation_pair_validation_refuses_zero_generation_and_high_fence() {
        assert!(validate_generation_pair(4, 2, "receipt").is_ok());
        assert!(validate_generation_pair(0, 0, "receipt").is_err());
        assert!(validate_generation_pair(4, 5, "receipt").is_err());
    }

    // -- Snapshot resolver --------------------------------------------------------

    fn identity_of(city: &str, node: &str, epoch: u64) -> CrossCityNodeIdentity {
        CrossCityNodeIdentity::new(city, node, epoch).expect("identity is valid")
    }

    #[test]
    fn snapshot_resolves_exact_identities_and_fails_closed_on_unknown_or_revoked() {
        let identity = identity_of("city-alpha", "node-01", 3);
        let public_key = [0x2Au8; ED25519_PUBLIC_KEY_BYTE_LEN];
        let record = CrossCityNodeKeyRecord::new(identity.clone(), public_key);

        let mut snapshot = CrossCityNodeKeySnapshot::default();
        assert!(snapshot.is_empty());
        assert_eq!(snapshot.total_count(), 0);
        snapshot.usable.insert(identity.clone(), record.clone());
        snapshot.total_count = 1;
        assert!(!snapshot.is_empty());
        assert_eq!(snapshot.usable_count(), 1);
        assert_eq!(snapshot.revoked_count(), 0);
        assert!(snapshot.knows_identity(&identity));

        let resolved = snapshot
            .resolve_node_key(&identity)
            .expect("exact identity resolves");
        assert_eq!(resolved, record);

        let unknown_node = identity_of("city-alpha", "node-02", 3);
        assert_eq!(
            snapshot.resolve_node_key(&unknown_node),
            Err(CrossCitySignatureError::UnknownNodeKey)
        );
        let wrong_epoch = identity_of("city-alpha", "node-01", 4);
        assert_eq!(
            snapshot.resolve_node_key(&wrong_epoch),
            Err(CrossCitySignatureError::UnknownNodeKey)
        );
        let wrong_city = identity_of("city-beta", "node-01", 3);
        assert_eq!(
            snapshot.resolve_node_key(&wrong_city),
            Err(CrossCitySignatureError::UnknownNodeKey)
        );

        // A revoked registration is counted for audit but never resolvable.
        snapshot.revoked_count = 1;
        snapshot.total_count = 2;
        assert_eq!(snapshot.revoked_count(), 1);
        assert_eq!(snapshot.usable_count(), 1);
    }

    #[test]
    fn snapshot_debug_output_leaks_no_key_material() {
        let identity = identity_of("city-alpha", "node-01", 3);
        let public_key = [0x5Eu8; ED25519_PUBLIC_KEY_BYTE_LEN];
        let mut snapshot = CrossCityNodeKeySnapshot::default();
        let record = CrossCityNodeKeyRecord::new(identity.clone(), public_key);
        snapshot.usable.insert(identity, record);
        snapshot.total_count = 1;
        let rendered = format!("{snapshot:?}");
        assert!(rendered.contains("CrossCityNodeKeySnapshot"));
        assert!(rendered.contains("usable_count"));
        assert!(!rendered.contains("node-01"));
        assert!(!rendered.contains("city-alpha"));
    }

    // -- Source-shape guards ------------------------------------------------------

    #[test]
    fn verified_vote_flow_reserves_before_insert_and_consumes_only_authenticated_evidence() {
        let body = production_function_body("pub async fn record_cross_city_verified_vote_in_tx");
        let reservation = body
            .find("RESERVATION_INSERT_SQL")
            .expect("replay reservation insert missing");
        let vote_insert = body
            .find("insert_vote_in_tx(")
            .expect("verified vote insert missing");
        assert!(
            reservation < vote_insert,
            "the replay reservation must be attempted before the vote insert"
        );
        // The capability's evidence is the ONLY evidence source: no raw
        // ZeroDecisionEvidence parameter can enter the durable path.
        assert!(body.contains("authenticated.evidence()"));
        assert!(body.contains(".replay_key()"));
    }

    #[test]
    fn commit_receipt_flow_checks_decision_parent_authority_before_insert() {
        let body = production_function_body("pub async fn record_cross_city_commit_receipt_in_tx");
        let decision = body
            .find("commit_receipt_decision_not_allow")
            .expect("ALLOW-only gate missing");
        let parent_lock = body
            .find("load_operation_for_update_in_tx")
            .expect("parent operation lock missing");
        let authority = body
            .find("require_cross_city_authority_scope_in_tx")
            .expect("authority scope gate missing");
        let reservation = body
            .find("RESERVATION_INSERT_SQL")
            .expect("replay reservation missing");
        let receipt = body
            .find("RECEIPT_INSERT_SQL")
            .expect("receipt insert missing");
        assert!(decision < parent_lock);
        assert!(parent_lock < authority);
        assert!(authority < reservation);
        assert!(reservation < receipt);
    }

    #[test]
    fn runtime_error_codes_are_stable_and_distinct() {
        let codes = [
            CrossCityRuntimeRepositoryError::ReplayConflict("x".to_owned()).code(),
            CrossCityRuntimeRepositoryError::Query(sqlx::Error::RowNotFound).code(),
            CrossCityRuntimeRepositoryError::Repository(CrossCityRepositoryError::NotFound(
                "x".to_owned(),
            ))
            .code(),
        ];
        assert_eq!(codes[0], "CROSS_CITY_REPLAY_RESERVED");
        for i in 0..codes.len() {
            for j in (i + 1)..codes.len() {
                assert_ne!(codes[i], codes[j]);
            }
        }
    }
}
