//! Cross-city node signature verification (Ed25519, default-off).
//!
//! This module is the *signature-verification boundary* for cross-city
//! [`ZeroDecisionEvidence`] values. It is pure: no network, no database, no
//! cache, no configuration, no runtime caller. Cross-city mode stays
//! default-off (`astral_types::CROSS_CITY_MODE_DEFAULT_ENABLED == false`); this
//! module never flips that switch and never contacts a writer, coordinator, or
//! key registry. Key material enters through the [`CrossCityNodeKeyResolver`]
//! trait, whose production implementation is intentionally absent in this
//! batch.
//!
//! # What the verifier guarantees
//!
//! [`verify_zero_decision_evidence`] returns an opaque
//! [`CrossCityVerifiedEvidence`] capability only when ALL of the following hold:
//!
//! 1. The evidence passes strict contract validation
//!    (`ZeroDecisionEvidence::validate_at(now_seconds)`, including the
//!    exclusive expiry bound `now < expires_at`), for both `ALLOW` and `DENY`
//!    decisions. Certificate policy is intentionally out of scope here.
//! 2. The evidence equals its own canonical form
//!    (`canonicalized() == evidence`): no padded identifiers, no padded
//!    signature, no non-canonical encoding. This check runs before any
//!    resolver or replay-guard call.
//! 3. The exact node identity `(city_id, node_id, node_epoch)` resolves to a
//!    registered Ed25519 public key through the resolver, and the resolved
//!    record carries byte-identical identity fields (`NodeKeyMismatch`
//!    otherwise). IP, PID, hostname, or any other machine metadata is never
//!    part of the identity.
//! 4. The signature is exactly 128 lowercase hex characters (64 raw bytes),
//!    and strict Ed25519 verification (`VerifyingKey::verify_strict`) succeeds
//!    over the domain-separated message pinned by
//!    [`cross_city_signature_message`]: the ASCII prefix
//!    `ASTRAL_CROSS_CITY_NODE_SIGNATURE_V1\0` followed by the 32 raw bytes
//!    decoded from the canonical `evidence_digest`. There is deliberately no
//!    JSON/hex signing ambiguity: the signed bytes are fixed-length and
//!    pinned by a public constant.
//! 5. Replay reservation succeeds *after* signature verification: the
//!    [`CrossCityReplayGuard`] atomically reserves the
//!    [`CrossCityEvidenceReplayKey`] (exact signer identity + nonce + signed
//!    `evidence_digest`). A duplicate is a typed [`CrossCitySignatureError::NonceReplay`];
//!    any guard/storage failure is a distinct fail-closed error.
//!
//! # Attack model and blocking points
//!
//! An attacker controlling evidence transport (but not the node private keys)
//! can: tamper with any evidence field or the signature; replay a previously
//! valid evidence/nonce against the same or a different operation, proposal,
//! or epoch; present a key registered for a different city/node/epoch; or race
//! the nonce reservation between concurrent verifications. The blocking points
//! map one-to-one: canonical contract validation (1, 2) rejects every field
//! tampering including the digest itself; exact key-identity resolution plus
//! the mismatch re-check (3) rejects wrong-city/wrong-node/wrong-epoch keys;
//! strict Ed25519 verification over the pinned domain-separated message (4)
//! rejects every signature forgery; the signed `evidence_digest` inside the
//! message binds the full proposal, decision, and expiry, so replay across
//! operations or epochs changes the signed message; the atomic
//! [`CrossCityReplayGuard::reserve`] call (5) rejects nonce reuse - provided
//! the reservation is durable.
//!
//! False `ALLOW` is unacceptable; a false `DENY`/defer is the safe cost of
//! every ambiguous input (unknown key, guard outage, expired evidence). The
//! verifier therefore fails closed on every error path and never falls back to
//! raw/source reads or stale state.
//!
//! This module is NOT an authorization decision and cannot replace
//! `PolicyEngine.evaluate()`. Signature verification is only a mandatory
//! precondition for the durable writer: evidence DB insertion, city vote
//! certificate derivation, and activation minting must consume only
//! cryptographically authenticated evidence.
//!
//! # Production admission seam (authenticate first, then durable reservation)
//!
//! The replay-reservation half of this boundary is deliberately split in two
//! so production can be durable:
//!
//! 1. [`authenticate_zero_decision_evidence`] performs every purely
//!    cryptographic step (steps 1-6 above) WITHOUT reserving anything and
//!    returns the opaque [`CrossCityAuthenticatedEvidence`] capability;
//! 2. the production repository (astral-db) then durably reserves the
//!    [`CrossCityEvidenceReplayKey`] and inserts the verified vote inside ONE
//!    short source transaction.
//!
//! The synchronous [`verify_zero_decision_evidence`] +
//! [`CrossCityReplayGuard`] composition stays public for in-process
//! composition and tests. An in-memory guard is NOT durable proof: process
//! restart loses it and concurrent replicas never share it, so it must never
//! be presented as production replay protection.
//!
//! # Replay-guard durability caveat
//!
//! Authentication ([`authenticate_zero_decision_evidence`]) and verification
//! ([`verify_zero_decision_evidence`]) are pure: neither one is durable proof.
//! The [`CrossCityReplayGuard`] trait is the contract the production writer
//! implements *in the same durable transaction as the evidence/vote insert*.
//! An in-memory `HashSet` (as used by the tests below) proves nothing about
//! production durability and must never be presented as replay proof: process
//! restart loses it, and concurrent replicas do not share it. The production
//! durable reservation seam lives in the astral-db cross-city runtime
//! repository, which durably reserves the nonce and inserts the verified vote
//! in one transaction.

use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;

use astral_types::{CrossCityContractError, ZeroDecisionEvidence};

// ---------------------------------------------------------------------------
// Pinned wire format constants
// ---------------------------------------------------------------------------

/// Domain-separated prefix of the exact Ed25519-signed message.
///
/// The trailing NUL byte terminates the ASCII domain label so the prefix can
/// never be confused with evidence-derived bytes.
pub const CROSS_CITY_NODE_SIGNATURE_DOMAIN_PREFIX: &[u8] = b"ASTRAL_CROSS_CITY_NODE_SIGNATURE_V1\0";

/// Raw byte length of the SHA-256 `evidence_digest` carried inside the signed
/// message.
pub const EVIDENCE_DIGEST_BYTE_LEN: usize = 32;

/// Canonical hex length of the `evidence_digest` field (lowercase SHA-256 hex).
pub const EVIDENCE_DIGEST_HEX_LEN: usize = 64;

/// Total length of the exact signed message:
/// [`CROSS_CITY_NODE_SIGNATURE_DOMAIN_PREFIX`] plus 32 raw digest bytes.
pub const CROSS_CITY_SIGNATURE_MESSAGE_LEN: usize =
    CROSS_CITY_NODE_SIGNATURE_DOMAIN_PREFIX.len() + EVIDENCE_DIGEST_BYTE_LEN;

/// Required raw byte length of an Ed25519 signature.
pub const ED25519_SIGNATURE_BYTE_LEN: usize = 64;

/// Required hex length of an Ed25519 signature: exactly 128 lowercase hex
/// characters. Uppercase, base64, whitespace, and every other encoding is
/// rejected.
pub const ED25519_SIGNATURE_HEX_LEN: usize = 128;

/// Raw byte length of an Ed25519 public key.
pub const ED25519_PUBLIC_KEY_BYTE_LEN: usize = 32;

/// Canonical hex length of an Ed25519 public key (lowercase hex).
pub const ED25519_PUBLIC_KEY_HEX_LEN: usize = 64;

/// The exact bytes covered by the node's Ed25519 signature: the
/// domain-separated prefix followed by the 32 raw bytes decoded from the
/// canonical (64 lowercase hex character) `evidence_digest`.
///
/// Signers (future key holders) and verifiers must both use this helper so the
/// signed byte string is pinned in exactly one place. The digest is
/// fixed-length raw bytes - not JSON, not hex text - so no serialization
/// ambiguity can split the domain label from the payload.
pub fn cross_city_signature_message(
    evidence_digest: &str,
) -> Result<[u8; CROSS_CITY_SIGNATURE_MESSAGE_LEN], CrossCitySignatureError> {
    let digest_bytes = decode_canonical_hex_array::<EVIDENCE_DIGEST_BYTE_LEN>(evidence_digest)
        .ok_or(CrossCitySignatureError::ContractRejected)?;
    let mut message = [0u8; CROSS_CITY_SIGNATURE_MESSAGE_LEN];
    message[..CROSS_CITY_NODE_SIGNATURE_DOMAIN_PREFIX.len()]
        .copy_from_slice(CROSS_CITY_NODE_SIGNATURE_DOMAIN_PREFIX);
    message[CROSS_CITY_NODE_SIGNATURE_DOMAIN_PREFIX.len()..].copy_from_slice(&digest_bytes);
    Ok(message)
}

// ---------------------------------------------------------------------------
// Typed, stable, secret-free errors
// ---------------------------------------------------------------------------

/// Verification failures of the cross-city signature boundary.
///
/// Every variant is stable, secret-free, and free of caller-controlled raw
/// strings; bounded numeric fields are the only payloads. Stable machine codes
/// are exposed through [`CrossCitySignatureError::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CrossCitySignatureError {
    /// The evidence violated the strict cross-city contract: failed
    /// `validate_at` field/digest validation, is not in canonical form, or the
    /// `evidence_digest` could not be decoded for message construction.
    #[error("cross-city evidence rejected by strict contract or canonical-form validation")]
    ContractRejected,
    /// The evidence is expired: `now_seconds >= expires_at` (exclusive bound).
    #[error("cross-city evidence expired at Unix second {expires_at} (now {now_seconds})")]
    ExpiredEvidence {
        /// Evaluation instant in UTC Unix seconds.
        now_seconds: i64,
        /// Exclusive expiry bound of the evidence.
        expires_at: i64,
    },
    /// The signature is not exactly 128 lowercase hex characters (64 raw
    /// bytes), or is otherwise undecodable. Uppercase, base64, whitespace, and
    /// wrong lengths all land here.
    #[error("cross-city node signature must be exactly 128 lowercase hex characters")]
    MalformedSignature,
    /// The resolved public key bytes are not a valid Ed25519 verifying key.
    #[error("cross-city node public key is not a valid Ed25519 verifying key")]
    MalformedPublicKey,
    /// Strict Ed25519 verification failed: the signature does not match the
    /// pinned message under the resolved key.
    #[error("cross-city node signature verification failed")]
    InvalidSignature,
    /// No node key is registered for the exact `(city_id, node_id, node_epoch)`.
    #[error("no cross-city node key registered for the exact node identity")]
    UnknownNodeKey,
    /// The resolver returned a key record whose identity differs from the
    /// requested `(city_id, node_id, node_epoch)`.
    #[error("resolved cross-city node key record belongs to a different node identity")]
    NodeKeyMismatch,
    /// The exact signer identity + nonce + evidence tuple was already
    /// reserved: the evidence is a replay.
    #[error("cross-city evidence nonce already reserved (replay rejected)")]
    NonceReplay,
    /// The replay guard could not prove a durable reservation (storage
    /// failure, timeout, unknown state). Verification fails closed.
    #[error("cross-city replay guard could not prove reservation (fail closed)")]
    ReplayGuardUnavailable,
}

impl CrossCitySignatureError {
    /// Stable machine-readable code, suitable for audit events and metrics.
    /// Codes never change meaning and never embed runtime data.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ContractRejected => "CROSS_CITY_CONTRACT_REJECTED",
            Self::ExpiredEvidence { .. } => "CROSS_CITY_EVIDENCE_EXPIRED",
            Self::MalformedSignature => "CROSS_CITY_SIGNATURE_MALFORMED",
            Self::MalformedPublicKey => "CROSS_CITY_NODE_KEY_MALFORMED",
            Self::InvalidSignature => "CROSS_CITY_SIGNATURE_INVALID",
            Self::UnknownNodeKey => "CROSS_CITY_NODE_KEY_UNKNOWN",
            Self::NodeKeyMismatch => "CROSS_CITY_NODE_KEY_MISMATCH",
            Self::NonceReplay => "CROSS_CITY_NONCE_REPLAY",
            Self::ReplayGuardUnavailable => "CROSS_CITY_REPLAY_GUARD_UNAVAILABLE",
        }
    }
}

// ---------------------------------------------------------------------------
// Node identity and key records
// ---------------------------------------------------------------------------

/// Maximum byte length of one identity field (mirrors the cross-city contract
/// identifier bound).
const IDENTITY_FIELD_MAX_LEN: usize = 512;

/// Validated identity of one cross-city signing node: canonical `city_id`,
/// canonical `node_id`, and a positive `node_epoch`.
///
/// Identity is carried by explicit contract fields only - never by IP, PID,
/// hostname, or any other machine-local metadata. Fields are validated to be
/// canonical (no surrounding whitespace, non-empty, bounded, no
/// whitespace/control characters); the verifier additionally requires
/// byte-equality with the evidence fields, and the evidence contract itself
/// rejects invisible Unicode format characters upstream.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CrossCityNodeIdentity {
    city_id: String,
    node_id: String,
    node_epoch: u64,
}

impl CrossCityNodeIdentity {
    /// Construct a validated node identity.
    pub fn new(
        city_id: &str,
        node_id: &str,
        node_epoch: u64,
    ) -> Result<Self, CrossCitySignatureError> {
        validate_node_epoch(node_epoch)?;
        Ok(Self {
            city_id: validate_identity_field(city_id)?,
            node_id: validate_identity_field(node_id)?,
            node_epoch,
        })
    }

    /// Derive the identity from an already contract-validated evidence. The
    /// checks run again fail-closed; for a validated evidence they cannot
    /// fail.
    fn from_evidence(evidence: &ZeroDecisionEvidence) -> Result<Self, CrossCitySignatureError> {
        Self::new(&evidence.city_id, &evidence.node_id, evidence.node_epoch)
    }

    /// Canonical city identifier.
    pub fn city_id(&self) -> &str {
        &self.city_id
    }

    /// Canonical node identifier.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Positive epoch of the node software/state.
    pub const fn node_epoch(&self) -> u64 {
        self.node_epoch
    }
}

/// Unicode General_Category=Cf (format) ranges treated as invisible poison in
/// direct constructor inputs as well as evidence-derived inputs. The upstream
/// cross-city contract applies the same rule; keeping it here closes the public
/// helper boundary independently.
const FORMAT_CHARACTER_RANGES: [(u32, u32); 21] = [
    (0x00AD, 0x00AD),
    (0x0600, 0x0605),
    (0x061C, 0x061C),
    (0x06DD, 0x06DD),
    (0x070F, 0x070F),
    (0x0890, 0x0891),
    (0x08E2, 0x08E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

fn is_unicode_format_character(character: char) -> bool {
    let code_point = character as u32;
    FORMAT_CHARACTER_RANGES
        .iter()
        .any(|(low, high)| code_point >= *low && code_point <= *high)
}

/// Validate one identity field: canonical (no trim needed), non-empty,
/// bounded, no whitespace/control characters, and no invisible Unicode format
/// characters.
fn validate_identity_field(value: &str) -> Result<String, CrossCitySignatureError> {
    if value.is_empty()
        || value.len() > IDENTITY_FIELD_MAX_LEN
        || value.trim() != value
        || value.chars().any(|character| {
            character.is_whitespace()
                || character.is_control()
                || is_unicode_format_character(character)
        })
    {
        return Err(CrossCitySignatureError::ContractRejected);
    }
    Ok(value.to_owned())
}

fn validate_canonical_evidence_digest(value: &str) -> Result<(), CrossCitySignatureError> {
    if decode_canonical_hex_array::<EVIDENCE_DIGEST_BYTE_LEN>(value).is_some() {
        Ok(())
    } else {
        Err(CrossCitySignatureError::ContractRejected)
    }
}

fn validate_node_epoch(node_epoch: u64) -> Result<(), CrossCitySignatureError> {
    if node_epoch == 0 {
        return Err(CrossCitySignatureError::ContractRejected);
    }
    Ok(())
}

/// The registered Ed25519 public key of one exact node identity.
///
/// This is what a production key registry (absent in this batch) hands to the
/// verifier through [`CrossCityNodeKeyResolver`].
#[derive(Clone, PartialEq, Eq)]
pub struct CrossCityNodeKeyRecord {
    identity: CrossCityNodeIdentity,
    public_key: [u8; ED25519_PUBLIC_KEY_BYTE_LEN],
}

impl CrossCityNodeKeyRecord {
    /// Build a key record from a validated identity and raw Ed25519 public key
    /// bytes. The bytes are re-validated during verification
    /// ([`CrossCitySignatureError::MalformedPublicKey`]) so a malformed key can
    /// never verify.
    pub const fn new(
        identity: CrossCityNodeIdentity,
        public_key: [u8; ED25519_PUBLIC_KEY_BYTE_LEN],
    ) -> Self {
        Self {
            identity,
            public_key,
        }
    }

    /// Build a key record from a canonical lowercase-hex public key.
    pub fn from_public_key_hex(
        identity: CrossCityNodeIdentity,
        public_key_hex: &str,
    ) -> Result<Self, CrossCitySignatureError> {
        let public_key = decode_canonical_hex_array::<ED25519_PUBLIC_KEY_BYTE_LEN>(public_key_hex)
            .ok_or(CrossCitySignatureError::MalformedPublicKey)?;
        Ok(Self::new(identity, public_key))
    }

    /// The exact identity this key belongs to.
    pub const fn identity(&self) -> &CrossCityNodeIdentity {
        &self.identity
    }

    /// The raw 32-byte Ed25519 public key.
    pub const fn public_key(&self) -> &[u8; ED25519_PUBLIC_KEY_BYTE_LEN] {
        &self.public_key
    }
}

impl std::fmt::Debug for CrossCityNodeKeyRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CrossCityNodeKeyRecord")
            .field("identity", &self.identity)
            .field("public_key", &"<ed25519 public key omitted>")
            .finish()
    }
}

/// Synchronous resolver from an exact node identity to its registered public
/// key record.
///
/// Contract for implementations (the production key registry does not exist in
/// this batch):
///
/// - Return `Err(CrossCitySignatureError::UnknownNodeKey)` when no key exists
///   for the exact `(city_id, node_id, node_epoch)`.
/// - Never guess, never fall back to a different epoch/city/node, never use
///   machine metadata as a key.
/// - Any returned error fails the whole verification closed before signature
///   checking and before replay reservation.
pub trait CrossCityNodeKeyResolver {
    /// Resolve the exact identity to its registered key record.
    fn resolve_node_key(
        &self,
        identity: &CrossCityNodeIdentity,
    ) -> Result<CrossCityNodeKeyRecord, CrossCitySignatureError>;
}

// ---------------------------------------------------------------------------
// Replay semantics
// ---------------------------------------------------------------------------

/// The replay identity of one evidence: the exact signer identity plus the
/// nonce, bound to the signed `evidence_digest`.
///
/// Because `evidence_digest` commits to the full signed payload (city, node,
/// epoch, decision, `proposal_digest`, frontier, mutation, nonce, expiry), this
/// key binds a nonce to one exact operation/proposal context: the same nonce
/// under a different signer identity, or under a different proposal, is a
/// *different* replay key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CrossCityEvidenceReplayKey {
    city_id: String,
    node_id: String,
    node_epoch: u64,
    nonce: String,
    evidence_digest: String,
}

impl CrossCityEvidenceReplayKey {
    /// Construct a validated replay key from canonical parts.
    pub fn new(
        city_id: &str,
        node_id: &str,
        node_epoch: u64,
        nonce: &str,
        evidence_digest: &str,
    ) -> Result<Self, CrossCitySignatureError> {
        validate_node_epoch(node_epoch)?;
        validate_canonical_evidence_digest(evidence_digest)?;
        Ok(Self {
            city_id: validate_identity_field(city_id)?,
            node_id: validate_identity_field(node_id)?,
            node_epoch,
            nonce: validate_identity_field(nonce)?,
            evidence_digest: evidence_digest.to_owned(),
        })
    }

    /// Canonical city identifier of the signer.
    pub fn city_id(&self) -> &str {
        &self.city_id
    }

    /// Canonical node identifier of the signer.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Node epoch of the signer.
    pub const fn node_epoch(&self) -> u64 {
        self.node_epoch
    }

    /// The per-evidence nonce.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// The signed evidence digest binding this nonce to one proposal context.
    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }
}

/// Durable replay reservation contract.
///
/// The future repository writer must implement `reserve` **in the same durable
/// transaction as the evidence/vote insert** so that either both the nonce
/// reservation and the insert commit, or neither does. The verifier calls
/// `reserve` only AFTER cryptographic verification succeeded.
///
/// Implementation contract:
///
/// - Duplicate reservation (the key was already reserved) must return
///   `Err(CrossCitySignatureError::NonceReplay)`.
/// - Any storage failure, timeout, or unknown outcome must return
///   `Err(CrossCitySignatureError::ReplayGuardUnavailable)` - never `Ok`. The
///   verifier treats every non-replay error as fail-closed
///   ([`CrossCitySignatureError::ReplayGuardUnavailable`]).
/// - An in-memory cache/`HashSet` does NOT satisfy this contract in production:
///   it is neither durable nor shared across replicas, and must never be
///   presented as replay proof.
pub trait CrossCityReplayGuard {
    /// Atomically reserve the replay key. `Ok(())` means "proven reserved".
    fn reserve(&self, key: &CrossCityEvidenceReplayKey) -> Result<(), CrossCitySignatureError>;
}

// ---------------------------------------------------------------------------
// Authentication seam (pure, reservation-free)
// ---------------------------------------------------------------------------

/// Opaque capability proving that one [`ZeroDecisionEvidence`] passed the full
/// cryptographic authentication boundary (strict contract + canonical form +
/// exact key identity + strict Ed25519 verification) WITHOUT any replay
/// reservation.
///
/// This is the pure first half of the production admission flow. The original
/// synchronous [`CrossCityReplayGuard`] trait cannot express a DURABLE
/// reservation (its `reserve` is sync and an in-process guard proves nothing
/// about production durability), so the production path is deliberately split:
///
/// 1. `authenticate_zero_decision_evidence` (THIS seam) performs every purely
///    cryptographic step - no I/O, no reservation, no capability minted for
///    the replay half;
/// 2. the production repository (astral-db) then performs the DURABLE replay
///    reservation and the verified-vote INSERT inside ONE short source
///    transaction, so either both commit or neither does. An in-memory guard
///    must never be presented as that durable reservation.
///
/// The constructor and all fields are private: the only way to obtain an
/// instance is `authenticate_zero_decision_evidence`, so no raw or unsigned
/// evidence can be smuggled into the durable writer behind this type.
#[derive(Clone, PartialEq, Eq)]
pub struct CrossCityAuthenticatedEvidence {
    evidence: ZeroDecisionEvidence,
    signer: CrossCityNodeIdentity,
    replay_key: CrossCityEvidenceReplayKey,
    authenticated_at_seconds: i64,
}

impl CrossCityAuthenticatedEvidence {
    /// Private constructor - the only producer is
    /// `authenticate_zero_decision_evidence`.
    fn new(
        evidence: ZeroDecisionEvidence,
        signer: CrossCityNodeIdentity,
        replay_key: CrossCityEvidenceReplayKey,
        authenticated_at_seconds: i64,
    ) -> Self {
        Self {
            evidence,
            signer,
            replay_key,
            authenticated_at_seconds,
        }
    }

    /// Read access to the authenticated evidence (signature cryptographically
    /// verified; nonce not yet durably reserved).
    pub fn evidence(&self) -> &ZeroDecisionEvidence {
        &self.evidence
    }

    /// Consume the capability into the authenticated evidence.
    pub fn into_evidence(self) -> ZeroDecisionEvidence {
        self.evidence
    }

    /// The exact signer identity the signature was verified against.
    pub const fn signer_identity(&self) -> &CrossCityNodeIdentity {
        &self.signer
    }

    /// The replay key the production repository must durably reserve (in the
    /// same transaction as the verified-vote insert) before the vote counts.
    pub const fn replay_key(&self) -> &CrossCityEvidenceReplayKey {
        &self.replay_key
    }

    /// The `now_seconds` the authentication was performed at.
    pub const fn authenticated_at_seconds(&self) -> i64 {
        self.authenticated_at_seconds
    }
}

impl std::fmt::Debug for CrossCityAuthenticatedEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Bounded, secret-free debug: identity, decision, public digest, and
        // authentication metadata only. The signature bytes and every other
        // evidence field are deliberately omitted (`..`).
        formatter
            .debug_struct("CrossCityAuthenticatedEvidence")
            .field("signer", &self.signer)
            .field("decision", &self.evidence.decision)
            .field("evidence_digest", &self.evidence.evidence_digest)
            .field("authenticated_at_seconds", &self.authenticated_at_seconds)
            .finish_non_exhaustive()
    }
}

/// Authenticate one [`ZeroDecisionEvidence`] against every purely
/// cryptographic rule of the cross-city boundary, WITHOUT reserving the
/// replay nonce.
///
/// This is steps 1-6 of `verify_zero_decision_evidence` with the reservation
/// step deliberately removed:
///
/// 1. strict contract validation including the exclusive expiry bound;
/// 2. strict canonical-form equality (no padded/normalizable input);
/// 3. exact signer identity derivation;
/// 4. strict signature decoding (exactly 128 lowercase hex characters);
/// 5. exact key-identity resolution plus mismatch re-check;
/// 6. strict Ed25519 verification over the pinned, domain-separated message.
///
/// The replay reservation is NOT performed here: it is the production
/// repository's job, executed DURABLY (one SQL transaction together with the
/// verified-vote insert). The synchronous
/// [`verify_zero_decision_evidence`] + [`CrossCityReplayGuard`] composition
/// stays available for in-process composition and tests; it must never be
/// presented as production replay proof (process restart loses an in-memory
/// guard, and concurrent replicas never share one).
///
/// Every failure is fail-closed and typed ([`CrossCitySignatureError`]); no
/// error variant of this function implies anything about the nonce - the
/// reservation simply never happens on any failure path.
pub fn authenticate_zero_decision_evidence<R>(
    evidence: &ZeroDecisionEvidence,
    now_seconds: i64,
    resolver: &R,
) -> Result<CrossCityAuthenticatedEvidence, CrossCitySignatureError>
where
    R: CrossCityNodeKeyResolver,
{
    // Step 1: strict contract validation including the exclusive expiry bound.
    match evidence.validate_at(now_seconds) {
        Ok(()) => {}
        Err(CrossCityContractError::Expired {
            now_seconds,
            expires_at,
            ..
        }) => {
            return Err(CrossCitySignatureError::ExpiredEvidence {
                now_seconds,
                expires_at,
            });
        }
        Err(_) => return Err(CrossCitySignatureError::ContractRejected),
    }

    // Step 2: strict canonical-form equality. `validate_at` tolerates padded
    // inputs in a few places (it normalizes before checking); byte equality
    // with the canonical re-derivation rejects every non-canonical encoding
    // (padded identifiers, padded signature) before any resolver call.
    match evidence.canonicalized() {
        Ok(canonical) if canonical == *evidence => {}
        _ => return Err(CrossCitySignatureError::ContractRejected),
    }

    // Step 3: exact signer identity derived from the validated fields.
    let signer = CrossCityNodeIdentity::from_evidence(evidence)?;

    // Step 4: strict signature decoding - exactly 128 lowercase hex characters.
    let signature = decode_signature(&evidence.signature)?;

    // Step 5: exact key-identity resolution plus mismatch re-check.
    let record = resolver.resolve_node_key(&signer)?;
    if record.identity() != &signer {
        return Err(CrossCitySignatureError::NodeKeyMismatch);
    }

    // Step 6: strict Ed25519 verification over the pinned, domain-separated
    // message. `verify_strict` rejects weak keys and malleable encodings.
    let verifying_key = VerifyingKey::from_bytes(record.public_key())
        .map_err(|_| CrossCitySignatureError::MalformedPublicKey)?;
    let message = cross_city_signature_message(&evidence.evidence_digest)?;
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| CrossCitySignatureError::InvalidSignature)?;

    // The replay key is derived but NOT reserved: the durable reservation is
    // the production repository's responsibility, in the same transaction as
    // the verified-vote insert.
    let replay_key = CrossCityEvidenceReplayKey::new(
        signer.city_id(),
        signer.node_id(),
        signer.node_epoch(),
        &evidence.nonce,
        &evidence.evidence_digest,
    )?;

    Ok(CrossCityAuthenticatedEvidence::new(
        evidence.clone(),
        signer,
        replay_key,
        now_seconds,
    ))
}

// ---------------------------------------------------------------------------
// Verified-evidence capability
// ---------------------------------------------------------------------------

/// Opaque capability proving that one [`ZeroDecisionEvidence`] passed the full
/// cross-city signature boundary (contract + canonical form + exact key
/// identity + strict Ed25519 + atomic replay reservation).
///
/// The constructor and all fields are private: external callers can only
/// *receive* an instance from [`verify_zero_decision_evidence`] - it is
/// impossible to forge one with a bool, a string, or any other runtime value:
///
/// ```compile_fail
/// use astral_common::cross_city_signature::CrossCityVerifiedEvidence;
///
/// // No `From<bool>` (or any other conversion) exists for the capability.
/// let forged: CrossCityVerifiedEvidence = true.into();
/// ```
///
/// ```compile_fail
/// use astral_common::cross_city_signature::CrossCityVerifiedEvidence;
///
/// // The constructor is private; external crates cannot call it.
/// let forged = CrossCityVerifiedEvidence::new(unimplemented!(), unimplemented!(), unimplemented!(), 0);
/// ```
///
/// The type itself is nameable from outside - only construction is restricted
/// (this doctest must compile, so the `compile_fail` examples above fail
/// because of the private construction, not because of a wrong path):
///
/// ```
/// use astral_common::cross_city_signature::CrossCityVerifiedEvidence;
///
/// fn consume_verified(evidence: &CrossCityVerifiedEvidence) -> &str {
///     evidence.signer_identity().city_id()
/// }
/// ```
///
/// A future durable writer must consume only this type for evidence insertion,
/// certificate derivation, and activation minting (that writer is absent in
/// this batch).
#[derive(Clone, PartialEq, Eq)]
pub struct CrossCityVerifiedEvidence {
    evidence: ZeroDecisionEvidence,
    signer: CrossCityNodeIdentity,
    replay_key: CrossCityEvidenceReplayKey,
    verified_at_seconds: i64,
}

impl CrossCityVerifiedEvidence {
    /// Private constructor - the only way to obtain this capability is
    /// [`verify_zero_decision_evidence`].
    fn new(
        evidence: ZeroDecisionEvidence,
        signer: CrossCityNodeIdentity,
        replay_key: CrossCityEvidenceReplayKey,
        verified_at_seconds: i64,
    ) -> Self {
        Self {
            evidence,
            signer,
            replay_key,
            verified_at_seconds,
        }
    }

    /// Read access to the validated evidence.
    pub fn evidence(&self) -> &ZeroDecisionEvidence {
        &self.evidence
    }

    /// Consume the capability into the validated evidence (for the future
    /// writer that persists only verified evidence).
    pub fn into_evidence(self) -> ZeroDecisionEvidence {
        self.evidence
    }

    /// The exact signer identity the signature was verified against.
    pub const fn signer_identity(&self) -> &CrossCityNodeIdentity {
        &self.signer
    }

    /// The replay key that was durably reserved for this evidence.
    pub const fn replay_key(&self) -> &CrossCityEvidenceReplayKey {
        &self.replay_key
    }

    /// The `now_seconds` the verification was performed at.
    pub const fn verified_at_seconds(&self) -> i64 {
        self.verified_at_seconds
    }
}

impl std::fmt::Debug for CrossCityVerifiedEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Bounded, secret-free debug: identity, decision, public digest, and
        // verification metadata only. The signature bytes and every other
        // evidence field are deliberately omitted (`..`).
        formatter
            .debug_struct("CrossCityVerifiedEvidence")
            .field("signer", &self.signer)
            .field("decision", &self.evidence.decision)
            .field("evidence_digest", &self.evidence.evidence_digest)
            .field("verified_at_seconds", &self.verified_at_seconds)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Verify one [`ZeroDecisionEvidence`] against the full signature boundary.
///
/// Ordering is part of the contract: strict contract validation, canonical
/// form, signature decoding, exact key resolution, and strict Ed25519
/// verification ALL happen before the replay guard is invoked; the guard is
/// never reached by unverifiable input. On success the caller receives the
/// [`CrossCityVerifiedEvidence`] capability; every failure is fail-closed and
/// typed ([`CrossCitySignatureError`]).
///
/// Certificate policy (how many evidences make a city vote, which decisions
/// count) is intentionally outside this module.
pub fn verify_zero_decision_evidence<R, G>(
    evidence: &ZeroDecisionEvidence,
    now_seconds: i64,
    resolver: &R,
    replay_guard: &G,
) -> Result<CrossCityVerifiedEvidence, CrossCitySignatureError>
where
    R: CrossCityNodeKeyResolver,
    G: CrossCityReplayGuard,
{
    // Steps 1-6 (contract, canonical form, identity, signature decoding, key
    // resolution, strict verification) are delegated to the pure
    // authentication seam; the reservation step below stays AFTER them, so
    // unverifiable input never reaches the guard.
    let authenticated = authenticate_zero_decision_evidence(evidence, now_seconds, resolver)?;

    // Step 7: atomic replay reservation - only AFTER cryptographic success.
    // A duplicate nonce is a typed replay; every other guard outcome fails
    // closed without ever producing the capability.
    let replay_key = authenticated.replay_key.clone();
    match replay_guard.reserve(&replay_key) {
        Ok(()) => {}
        Err(CrossCitySignatureError::NonceReplay) => {
            return Err(CrossCitySignatureError::NonceReplay);
        }
        Err(_) => return Err(CrossCitySignatureError::ReplayGuardUnavailable),
    }

    let CrossCityAuthenticatedEvidence {
        evidence,
        signer,
        replay_key,
        authenticated_at_seconds: verified_at_seconds,
    } = authenticated;

    Ok(CrossCityVerifiedEvidence::new(
        evidence,
        signer,
        replay_key,
        verified_at_seconds,
    ))
}

// ---------------------------------------------------------------------------
// Strict decoding helpers
// ---------------------------------------------------------------------------

/// Whether `value` is exactly `expected_len` characters of lowercase hex.
fn is_canonical_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Decode a canonical lowercase-hex string into a fixed-size byte array.
/// Rejects uppercase, non-hex characters, whitespace, and wrong lengths.
fn decode_canonical_hex_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    if !is_canonical_hex(value, N * 2) {
        return None;
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(value, &mut out).ok()?;
    Some(out)
}

/// Decode an Ed25519 signature from its canonical 128 lowercase hex character
/// form into exactly 64 raw bytes.
fn decode_signature(signature: &str) -> Result<Signature, CrossCitySignatureError> {
    let bytes = decode_canonical_hex_array::<ED25519_SIGNATURE_BYTE_LEN>(signature)
        .ok_or(CrossCitySignatureError::MalformedSignature)?;
    Signature::from_slice(&bytes).map_err(|_| CrossCitySignatureError::MalformedSignature)
}

// ---------------------------------------------------------------------------
// Tests (pure: no network, no database, no cache, no external services)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
