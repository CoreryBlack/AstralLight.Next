//! Additive wire/value contract for the global authority control plane (V7+).
//!
//! This module is the pure contract layer between the source-side DB/commit
//! owners and the external global authority service (`astral-authority`). It
//! contains only serde-friendly value types, deterministic canonical digests,
//! and fail-closed validation logic. It performs no I/O and never makes an
//! authorization decision by itself.
//!
//! Design rules honored by this module:
//! - Existing contracts are reused, not duplicated: read responses carry the
//!   existing [`AuthorizationFenceProof`], [`AuthorizationAuthorityScope`] and
//!   related types unchanged. [`GlobalAuthorityFrontier`] is a separate
//!   global frontier whose `global_chain_digest` is deliberately NOT a scope
//!   snapshot hash; global and per-scope content identity never collapse into
//!   one value.
//! - Every signed structure uses the existing Ed25519 canonical semantics:
//!   domain-separated header, u32 big-endian length-prefixed fields, lowercase
//!   hex signatures, `verify_strict` verification, and explicit time windows.
//! - Deserialization is not trust: every structure revalidates on use, and a
//!   digest is recomputed from validated fields instead of trusting a wire copy.
//! - Unknown, pending and quarantined source-operation states fail closed:
//!   [`AuthorityReadGate`] reports blocking reservations, and callers must
//!   treat any pending/unknown state as "positive reads blocked".
//! - The protocol carries no signing capability for business processes: the
//!   client library built on these types only verifies; signing lives solely
//!   inside the authority's protected signer owner.

mod abort;
mod bootstrap;
mod certificate;
mod config_completion;
mod eligibility_completion;
mod frontier;
mod reservation;
mod source_bootstrap;
mod wire;

pub use abort::*;
pub use bootstrap::*;
pub use certificate::*;
pub use config_completion::*;
pub use eligibility_completion::*;
pub use frontier::*;
pub use reservation::*;
pub use source_bootstrap::*;
pub use wire::*;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::AuthorizationAuthorityError;

/// Wire protocol version of this contract set.
pub const AUTHORITY_PROTOCOL_VERSION: u16 = 1;

/// Maximum accepted JSON body size for authority control-plane requests.
pub const AUTHORITY_MAX_BODY_BYTES: usize = 256 * 1024;

const AUTHORITY_PROTOCOL_MAX_TEXT: usize = 128;
const SHA256_HEX_LEN: usize = 64;
const ED25519_SIGNATURE_HEX_LEN: usize = 128;

/// Errors of the authority control-plane protocol.
///
/// This is a closed, fail-closed taxonomy: callers must treat unknown
/// (`UnknownOutcome`) and pending states as "not provable" and reconcile by
/// stable identity instead of retrying.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthorityProtocolError {
    #[error("authorization edition is not current")]
    WrongEdition,
    #[error("{field} must be a positive identifier")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} is empty, too long, or non-canonical")]
    InvalidText { field: &'static str },
    #[error("{field} must be a lowercase SHA-256 hex digest")]
    InvalidDigest { field: &'static str },
    #[error("{field} must be a positive monotonic value")]
    InvalidCounter { field: &'static str },
    #[error("time window is invalid")]
    InvalidTimeWindow,
    #[error("value is not currently valid at the supplied time")]
    NotCurrentlyValid,
    #[error("signature must be exactly 128 lowercase hex characters")]
    InvalidSignatureEncoding,
    #[error("authority protocol signature is invalid")]
    InvalidSignature,
    #[error("revoke watermark cannot exceed scope generation")]
    RevokeWatermarkAhead,
    #[error("reservation coverage is empty or invalid")]
    InvalidCoverage,
    #[error("requested scope does not match the bound scope")]
    ScopeMismatch,
    #[error("digest does not match the recomputed canonical value")]
    DigestMismatch { field: &'static str },
    #[error("referenced authority record was not found")]
    NotFound { record: &'static str },
    #[error("record exists and must not be created again")]
    AlreadyExists { record: &'static str },
    #[error("record state does not permit this operation")]
    StateConflict { record: &'static str, state: String },
    #[error("the authorization lease has expired; source replay is refused")]
    LeaseExpired,
    #[error("positive reads are blocked by a pending source operation")]
    ReadsBlocked { reservation_id: String },
    #[error("key epoch is not strictly increasing")]
    KeyEpochNonMonotonic,
    #[error("trust root does not match the protected pin")]
    TrustRootMismatch,
    #[error("caller identity does not match the authenticated transport identity")]
    CallerIdentityMismatch,
    #[error("requested frontier or certificate does not match current authority state")]
    FrontierDiverged,
    #[error("operation outcome is unknown; reconcile by stable identity before any new attempt")]
    UnknownOutcome { operation_hint: String },
    #[error("authority instance is not the quorum leader for mutations")]
    NotLeader,
    #[error("authority quorum is unavailable; state was not proven")]
    QuorumUnavailable,
    #[error("value could not be canonically encoded")]
    CanonicalSerialization,
}

/// Domain-separated signing/derivation header for one structure.
pub(crate) fn authority_field(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

/// Encode one optional i64 the same way the existing authority contracts do.
pub(crate) fn authority_optional_i64(value: Option<i64>) -> String {
    value.map_or_else(|| "-".to_owned(), |value| value.to_string())
}

/// Validate shared text rules: non-empty, bounded, no leading/trailing space,
/// no whitespace or control characters (canonical, injective encoding).
pub(crate) fn authority_text(
    value: &str,
    field: &'static str,
) -> Result<(), AuthorityProtocolError> {
    if value.is_empty()
        || value.len() > AUTHORITY_PROTOCOL_MAX_TEXT
        || value.trim() != value
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(AuthorityProtocolError::InvalidText { field });
    }
    Ok(())
}

pub(crate) fn authority_counter(
    value: u64,
    field: &'static str,
) -> Result<(), AuthorityProtocolError> {
    (value > 0)
        .then_some(())
        .ok_or(AuthorityProtocolError::InvalidCounter { field })
}

/// Validate a positive i64 timestamp/counter (Unix seconds or sequence values
/// stored as i64 across the wire).
pub(crate) fn authority_timestamp(
    value: i64,
    field: &'static str,
) -> Result<(), AuthorityProtocolError> {
    (value > 0)
        .then_some(())
        .ok_or(AuthorityProtocolError::InvalidCounter { field })
}

pub(crate) fn authority_positive_id(
    value: i64,
    field: &'static str,
) -> Result<(), AuthorityProtocolError> {
    (value > 0)
        .then_some(())
        .ok_or(AuthorityProtocolError::InvalidIdentifier { field })
}

pub(crate) fn authority_digest(
    value: &str,
    field: &'static str,
) -> Result<(), AuthorityProtocolError> {
    if value.len() != SHA256_HEX_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AuthorityProtocolError::InvalidDigest { field });
    }
    Ok(())
}

pub(crate) fn authority_signature_encoding(value: &str) -> Result<(), AuthorityProtocolError> {
    if value.len() != ED25519_SIGNATURE_HEX_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AuthorityProtocolError::InvalidSignatureEncoding);
    }
    Ok(())
}

pub(crate) fn authority_time_window(
    not_before: i64,
    issued_at: i64,
    expires_at: i64,
) -> Result<(), AuthorityProtocolError> {
    if not_before > issued_at || issued_at >= expires_at {
        return Err(AuthorityProtocolError::InvalidTimeWindow);
    }
    Ok(())
}

/// Verify one lowercase-hex Ed25519 signature over the exact bytes.
pub(crate) fn authority_verify_strict(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature_hex: &str,
) -> Result<(), AuthorityProtocolError> {
    if signature_hex.len() != ED25519_SIGNATURE_HEX_LEN {
        return Err(AuthorityProtocolError::InvalidSignatureEncoding);
    }
    let mut raw = [0u8; 64];
    for (index, pair) in signature_hex.as_bytes().chunks(2).enumerate() {
        let high = hex_nibble(
            *pair
                .first()
                .ok_or(AuthorityProtocolError::InvalidSignatureEncoding)?,
        )?;
        let low = hex_nibble(
            *pair
                .get(1)
                .ok_or(AuthorityProtocolError::InvalidSignatureEncoding)?,
        )?;
        raw[index] = (high << 4) | low;
    }
    verifying_key
        .verify_strict(message, &Signature::from_bytes(&raw))
        .map_err(|_| AuthorityProtocolError::InvalidSignature)
}

/// SHA-256 over the given bytes, rendered as 64 lowercase hex characters.
pub(crate) fn authority_sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Whether the value is a syntactically valid 64-character lowercase SHA-256
/// hex digest. Useful for configuration pins before any record exists.
pub fn authority_protocol_digest_shape(value: &str) -> bool {
    authority_digest(value, "value").is_ok()
}

fn hex_nibble(value: u8) -> Result<u8, AuthorityProtocolError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(AuthorityProtocolError::InvalidSignatureEncoding),
    }
}

/// Conversion from the existing authority error taxonomy so protocol code can
/// propagate shared proof validation with `?` directly.
impl From<AuthorizationAuthorityError> for AuthorityProtocolError {
    fn from(value: AuthorizationAuthorityError) -> Self {
        match value {
            AuthorizationAuthorityError::WrongEdition => Self::WrongEdition,
            AuthorizationAuthorityError::InvalidIdentifier { field } => {
                Self::InvalidIdentifier { field }
            }
            AuthorizationAuthorityError::InvalidText { field } => Self::InvalidText { field },
            AuthorizationAuthorityError::InvalidDigest { field } => Self::InvalidDigest { field },
            AuthorizationAuthorityError::InvalidCounter { field } => Self::InvalidCounter { field },
            AuthorizationAuthorityError::RevokeWatermarkAhead => Self::RevokeWatermarkAhead,
            AuthorizationAuthorityError::InvalidTimeWindow => Self::InvalidTimeWindow,
            AuthorizationAuthorityError::NotCurrentlyValid => Self::NotCurrentlyValid,
            AuthorizationAuthorityError::InvalidSignatureEncoding => Self::InvalidSignatureEncoding,
            AuthorizationAuthorityError::InvalidSignature => Self::InvalidSignature,
            AuthorizationAuthorityError::NonMonotonicIdentity => Self::FrontierDiverged,
            AuthorizationAuthorityError::ScopeMismatch => Self::ScopeMismatch,
            AuthorizationAuthorityError::AdmissionConsumed => Self::StateConflict {
                record: "admission",
                state: "CONSUMED".to_owned(),
            },
            AuthorizationAuthorityError::EvidenceContentHashMismatch
            | AuthorizationAuthorityError::EvidenceFrontierMismatch
            | AuthorizationAuthorityError::EvidenceScopeMismatch
            | AuthorizationAuthorityError::EvidenceInvalid => {
                Self::DigestMismatch { field: "evidence" }
            }
            AuthorizationAuthorityError::EvidenceNotCurrentlyUsable => Self::NotCurrentlyValid,
            AuthorizationAuthorityError::CanonicalSerialization => Self::CanonicalSerialization,
            AuthorizationAuthorityError::NonceReplay => Self::AlreadyExists { record: "nonce" },
        }
    }
}

/// Project the shared error type where the two taxonomies overlap, so callers
/// that already handle [`AuthorizationAuthorityError`] can map uniformly.
pub fn as_authorization_error(
    error: &AuthorityProtocolError,
) -> Option<AuthorizationAuthorityError> {
    match error {
        AuthorityProtocolError::WrongEdition => Some(AuthorizationAuthorityError::WrongEdition),
        AuthorityProtocolError::InvalidIdentifier { field } => {
            Some(AuthorizationAuthorityError::InvalidIdentifier { field })
        }
        AuthorityProtocolError::InvalidText { field } => {
            Some(AuthorizationAuthorityError::InvalidText { field })
        }
        AuthorityProtocolError::InvalidDigest { field } => {
            Some(AuthorizationAuthorityError::InvalidDigest { field })
        }
        AuthorityProtocolError::InvalidCounter { field } => {
            Some(AuthorizationAuthorityError::InvalidCounter { field })
        }
        AuthorityProtocolError::InvalidTimeWindow => {
            Some(AuthorizationAuthorityError::InvalidTimeWindow)
        }
        AuthorityProtocolError::NotCurrentlyValid => {
            Some(AuthorizationAuthorityError::NotCurrentlyValid)
        }
        AuthorityProtocolError::InvalidSignatureEncoding => {
            Some(AuthorizationAuthorityError::InvalidSignatureEncoding)
        }
        AuthorityProtocolError::InvalidSignature => {
            Some(AuthorizationAuthorityError::InvalidSignature)
        }
        AuthorityProtocolError::RevokeWatermarkAhead => {
            Some(AuthorizationAuthorityError::RevokeWatermarkAhead)
        }
        AuthorityProtocolError::ScopeMismatch => Some(AuthorizationAuthorityError::ScopeMismatch),
        AuthorityProtocolError::CanonicalSerialization => {
            Some(AuthorizationAuthorityError::CanonicalSerialization)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn strict_verification_rejects_tampered_messages() {
        let key = signing_key(9);
        let message = b"ASTRAL_TEST_MESSAGE";
        let signature = hex::encode(ed25519_dalek::Signer::sign(&key, message).to_bytes());
        authority_verify_strict(&key.verifying_key(), message, &signature).unwrap();

        let tampered = b"ASTRAL_TEST_MESSAG0";
        assert!(matches!(
            authority_verify_strict(&key.verifying_key(), tampered, &signature),
            Err(AuthorityProtocolError::InvalidSignature)
        ));
        assert!(matches!(
            authority_verify_strict(&key.verifying_key(), message, &"zz".repeat(64)),
            Err(AuthorityProtocolError::InvalidSignatureEncoding)
        ));
    }

    #[test]
    fn text_and_digest_helpers_fail_closed() {
        assert!(authority_text("ok-value", "field").is_ok());
        assert!(matches!(
            authority_text(" leading", "field"),
            Err(AuthorityProtocolError::InvalidText { .. })
        ));
        assert!(matches!(
            authority_text("", "field"),
            Err(AuthorityProtocolError::InvalidText { .. })
        ));
        assert!(authority_digest(&"ab".repeat(32), "field").is_ok());
        assert!(matches!(
            authority_digest(&"AB".repeat(32), "field"),
            Err(AuthorityProtocolError::InvalidDigest { .. })
        ));
        assert!(matches!(
            authority_counter(0, "field"),
            Err(AuthorityProtocolError::InvalidCounter { .. })
        ));
    }

    #[test]
    fn shared_error_projection_covers_common_cases() {
        assert_eq!(
            as_authorization_error(&AuthorityProtocolError::WrongEdition),
            Some(AuthorizationAuthorityError::WrongEdition)
        );
        assert_eq!(
            as_authorization_error(&AuthorityProtocolError::NotLeader),
            None
        );
    }
}
