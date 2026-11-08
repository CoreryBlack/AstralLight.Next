//! Explicit reservation abort contract (V7): the ONLY protocol path from a
//! `Reserved` reservation to the terminal `Aborted` state.
//!
//! Fail-closed rules honored by this contract:
//! - The abort is an owner-only transition: the request must carry the EXACT
//!   source identity of the reserved intent (service, database, operation and
//!   approved request digest). Operators use the separate close contract; no
//!   operator, and no unregistered caller, may assert an abort.
//! - Every abort request must present a `source_tombstone_digest`: the
//!   canonical digest of the durable local tombstone row (the source's own
//!   reservation record binding plus the abort identity). A lease expiry, a
//!   transport error, or the mere absence of an outcome row is never a proof
//!   of rollback and never substitutes for this digest.
//! - An unknown source commit is reconciled by stable identity first and is
//!   NEVER aborted: the authority accepts the transition only from the
//!   `Reserved` state; `Committed`, `Published`, `Certified` and
//!   `Quarantined` reservations are terminal for the abort path.
//! - The abort receipt is immutable: the EXACT same request (stable abort id,
//!   binding, reason and tombstone digest) replays by reading the receipt
//!   back with its recorded post-abort frontier — the frontier never
//!   re-advances. Any different binding is a genuine conflict.

use serde::{Deserialize, Serialize};

use super::{
    authority_digest, authority_field, authority_sha256_hex, authority_text, authority_timestamp,
    AuthorityCallerIdentity, AuthorityProtocolError, AuthorityReadGate,
    AuthorityReservationDisposition, AuthorityReservationState, AuthorityScopeReservation,
    GlobalAuthorityFrontier,
};
use crate::AUTHORIZATION_EDITION;

/// Wire path of the reservation abort endpoint (authenticated mTLS internal
/// control plane; plural kebab-case like the existing reservation paths).
pub const AUTHORITY_PATH_RESERVATION_ABORTS: &str = "/main/api/v1/authority-reservations/aborts";

/// Canonical domain header of the durable source tombstone digest.
const SOURCE_TOMBSTONE_DOMAIN: &[u8] = b"ASTRAL_AUTHORITY_SOURCE_TOMBSTONE_V1\0";

/// The durable source-side tombstone whose canonical digest every abort
/// request must present.
///
/// This is the exact binding of the source's local reservation row after the
/// tombstone transaction committed: the stable reservation/operation/proof
/// identity, the intent digest, the digest over the row's stored reservation
/// record bytes, the `ABORTED` disposition and the abort identity. The
/// authority cannot read the source database, so it never verifies the row
/// itself — it verifies that a REGISTERED source asserts exactly one
/// immutable tombstone identity and records it in the receipt, making every
/// abort traceable to one durable local closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySourceTombstone {
    pub reservation_id: String,
    pub operation_id: String,
    pub admission_proof_id: String,
    /// SHA-256 of the approved, immutable target request content.
    pub request_digest: String,
    pub service_id: String,
    pub database_id: String,
    /// Digest of the accepted intent the reservation was created from.
    pub intent_digest: String,
    /// SHA-256 over the EXACT durable reservation-record bytes of the local
    /// row (the stored prepare acceptance evidence), lowercase hex.
    pub reservation_record_digest: String,
    /// Disposition stored on the tombstoned row; must be `ABORTED`.
    pub disposition: String,
    pub tombstoned_at: i64,
    pub abort_id: String,
    pub reason: String,
}

impl AuthoritySourceTombstone {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        authority_text(&self.admission_proof_id, "admission_proof_id")?;
        authority_digest(&self.request_digest, "request_digest")?;
        authority_text(&self.service_id, "service_id")?;
        authority_text(&self.database_id, "database_id")?;
        authority_digest(&self.intent_digest, "intent_digest")?;
        authority_digest(&self.reservation_record_digest, "reservation_record_digest")?;
        if self.disposition != "ABORTED" {
            return Err(AuthorityProtocolError::InvalidText {
                field: "tombstone_disposition",
            });
        }
        authority_timestamp(self.tombstoned_at, "tombstoned_at")?;
        authority_text(&self.abort_id, "abort_id")?;
        let reason = self.reason.trim();
        if reason.is_empty()
            || reason.len() > 256
            || reason.chars().any(|character| character.is_control())
        {
            return Err(AuthorityProtocolError::InvalidText { field: "reason" });
        }
        Ok(())
    }

    /// Canonical tombstone digest: the stable identity of one durable local
    /// closure. The same tombstone always produces the same digest; any
    /// binding change produces a different one.
    pub fn digest(&self) -> Result<String, AuthorityProtocolError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(512);
        bytes.extend_from_slice(SOURCE_TOMBSTONE_DOMAIN);
        authority_field(&mut bytes, &self.reservation_id);
        authority_field(&mut bytes, &self.operation_id);
        authority_field(&mut bytes, &self.admission_proof_id);
        authority_field(&mut bytes, &self.request_digest);
        authority_field(&mut bytes, &self.service_id);
        authority_field(&mut bytes, &self.database_id);
        authority_field(&mut bytes, &self.intent_digest);
        authority_field(&mut bytes, &self.reservation_record_digest);
        authority_field(&mut bytes, &self.disposition);
        authority_field(&mut bytes, &self.tombstoned_at.to_string());
        authority_field(&mut bytes, &self.abort_id);
        authority_field(&mut bytes, self.reason.trim());
        Ok(authority_sha256_hex(&bytes))
    }
}

/// Abort: the owner-only explicit transition of one `Reserved` reservation to
/// the terminal `Aborted` state after a PROVEN local rollback (durable
/// tombstone) or a proven never-begun transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityAbortRequest {
    pub caller: AuthorityCallerIdentity,
    pub reservation_id: String,
    /// Exact operation identity of the reserved intent.
    pub operation_id: String,
    /// Registered database identity of the reserved intent.
    pub database_id: String,
    /// Exact approved request digest of the reserved intent.
    pub request_digest: String,
    /// Stable, immutable abort identity. The SAME identity (with the same
    /// binding, reason and tombstone digest) replays idempotently by reading
    /// the receipt back; a different identity on an already-aborted
    /// reservation is a genuine conflict.
    pub abort_id: String,
    /// Canonical digest of the durable local tombstone row (see
    /// [`AuthoritySourceTombstone`]). Mandatory: no tombstone, no abort.
    pub source_tombstone_digest: String,
    /// Bounded owner audit note recorded immutably in the receipt.
    pub reason: String,
}

impl AuthorityAbortRequest {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.caller.validate()?;
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        authority_text(&self.database_id, "database_id")?;
        authority_digest(&self.request_digest, "request_digest")?;
        authority_text(&self.abort_id, "abort_id")?;
        authority_digest(&self.source_tombstone_digest, "source_tombstone_digest")?;
        let reason = self.reason.trim();
        if reason.is_empty()
            || reason.len() > 256
            || reason.chars().any(|character| character.is_control())
        {
            return Err(AuthorityProtocolError::InvalidText { field: "reason" });
        }
        Ok(())
    }

    /// The deterministic stable abort identity of one reservation: the exact
    /// same abort replays under this id, and the receipt of a prior abort is
    /// always found by it.
    pub fn stable_abort_id(reservation_id: &str) -> Result<String, AuthorityProtocolError> {
        authority_text(reservation_id, "reservation_id")?;
        let abort_id = format!("abort-{reservation_id}");
        authority_text(&abort_id, "abort_id")?;
        Ok(abort_id)
    }
}

/// The immutable, durable abort receipt. Written put-if-absent in the SAME
/// quorum transaction that flips the reservation to `Aborted`; the exact same
/// abort replays by reading this receipt back and serving the recorded
/// post-abort frontier — nothing is ever re-advanced or rewritten.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityAbortReceipt {
    pub authorization_edition: u16,
    pub reservation_id: String,
    pub abort_id: String,
    pub operation_id: String,
    pub event_id: String,
    pub admission_proof_id: String,
    pub request_digest: String,
    pub service_id: String,
    pub database_id: String,
    pub intent_digest: String,
    pub reason: String,
    /// The exact tombstone digest the abort was asserted with.
    pub source_tombstone_digest: String,
    pub aborted_at: i64,
    /// The COMPLETE post-abort frontier; replays serve this value verbatim.
    pub global_frontier: GlobalAuthorityFrontier,
}

impl AuthorityAbortReceipt {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        if self.authorization_edition != AUTHORIZATION_EDITION {
            return Err(AuthorityProtocolError::WrongEdition);
        }
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_text(&self.abort_id, "abort_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        authority_text(&self.event_id, "event_id")?;
        authority_text(&self.admission_proof_id, "admission_proof_id")?;
        authority_digest(&self.request_digest, "request_digest")?;
        authority_text(&self.service_id, "service_id")?;
        authority_text(&self.database_id, "database_id")?;
        authority_digest(&self.intent_digest, "intent_digest")?;
        authority_text(&self.service_id, "service_id")?;
        let reason = self.reason.trim();
        if reason.is_empty()
            || reason.len() > 256
            || reason.chars().any(|character| character.is_control())
        {
            return Err(AuthorityProtocolError::InvalidText { field: "reason" });
        }
        authority_digest(&self.source_tombstone_digest, "source_tombstone_digest")?;
        authority_timestamp(self.aborted_at, "aborted_at")?;
        self.global_frontier.validate()
    }

    /// Whether this receipt is the recorded abort of EXACTLY this request
    /// against EXACTLY this reservation: stable abort identity, exact source
    /// binding, exact reason and exact tombstone digest. Used by the
    /// authority for idempotent read-back and by the client to verify the
    /// echoed receipt.
    pub fn matches_abort(
        &self,
        request: &AuthorityAbortRequest,
        reservation: &AuthorityScopeReservation,
    ) -> bool {
        self.reservation_id == request.reservation_id
            && self.abort_id == request.abort_id
            && self.operation_id == request.operation_id
            && self.database_id == request.database_id
            && self.request_digest == request.request_digest
            && self.source_tombstone_digest == request.source_tombstone_digest
            && self.service_id == request.caller.service_id
            && self.reason == request.reason.trim()
            && self.intent_digest == reservation.intent_digest
            && self.event_id == reservation.intent.event_id
            && self.admission_proof_id == reservation.intent.admission_proof_id
    }
}

/// Abort response: the terminal receipt of one owner abort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityAbortResponse {
    pub disposition: AuthorityReservationDisposition,
    pub reservation: AuthorityScopeReservation,
    pub receipt: AuthorityAbortReceipt,
    pub global_frontier: GlobalAuthorityFrontier,
    pub read_gate: AuthorityReadGate,
}

impl AuthorityAbortResponse {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.reservation.validate()?;
        self.receipt.validate()?;
        self.global_frontier.validate()?;
        self.read_gate.validate()?;
        if self.disposition != AuthorityReservationDisposition::Aborted
            || self.reservation.state != AuthorityReservationState::Aborted
            || self.global_frontier != self.receipt.global_frontier
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        // The receipt must bind exactly this reservation's durable identity.
        if self.receipt.reservation_id != self.reservation.reservation_id
            || self.receipt.intent_digest != self.reservation.intent_digest
            || self.receipt.operation_id != self.reservation.intent.operation_id
            || self.receipt.event_id != self.reservation.intent.event_id
            || self.receipt.admission_proof_id != self.reservation.intent.admission_proof_id
            || self.receipt.request_digest != self.reservation.intent.request_digest
            || self.receipt.service_id != self.reservation.intent.service_id
            || self.receipt.database_id != self.reservation.intent.database_id
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        Ok(())
    }
}

/// Build the tombstone binding of one aborted reservation from the durable
/// local record. Shared so the source producer and any verifier agree on the
/// canonical bytes.
pub fn source_tombstone_for_reservation(
    reservation: &AuthorityScopeReservation,
    reservation_record_digest: String,
    tombstoned_at: i64,
    abort_id: String,
    reason: String,
) -> Result<AuthoritySourceTombstone, AuthorityProtocolError> {
    let tombstone = AuthoritySourceTombstone {
        reservation_id: reservation.reservation_id.clone(),
        operation_id: reservation.intent.operation_id.clone(),
        admission_proof_id: reservation.intent.admission_proof_id.clone(),
        request_digest: reservation.intent.request_digest.clone(),
        service_id: reservation.intent.service_id.clone(),
        database_id: reservation.intent.database_id.clone(),
        intent_digest: reservation.intent_digest.clone(),
        reservation_record_digest,
        disposition: "ABORTED".to_owned(),
        tombstoned_at,
        abort_id,
        reason,
    };
    tombstone.validate()?;
    Ok(tombstone)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_protocol::AuthorityReservationCoverage;
    use crate::AuthoritySourceIntent;

    fn caller() -> AuthorityCallerIdentity {
        AuthorityCallerIdentity {
            service_id: "source-svc".to_owned(),
            request_nonce: "nonce-1".to_owned(),
            issued_at: 1_700,
        }
    }

    fn reservation() -> AuthorityScopeReservation {
        AuthorityScopeReservation {
            reservation_id: "res-abc123".to_owned(),
            intent_digest: "ab".repeat(32),
            intent: AuthoritySourceIntent {
                authorization_edition: AUTHORIZATION_EDITION,
                mutation_kind: crate::AuthorityMutationKind::AuthorizationSource,
                operation_id: "operation-1".to_owned(),
                event_id: "event-1".to_owned(),
                admission_proof_id: "proof-1".to_owned(),
                request_digest: "cd".repeat(32),
                service_id: "source-svc".to_owned(),
                database_id: "db-1".to_owned(),
                coverage: AuthorityReservationCoverage::Global,
                before_image_digest: None,
                lease_not_before: 1_000,
                lease_expires_at: 2_000,
                intent_nonce: "intent-nonce-1".to_owned(),
            },
            state: AuthorityReservationState::Reserved,
            authority_term: 1,
            fence_sequence_at_prepare: 1,
            created_at: 1_000,
            updated_at: 1_000,
            committed_at: None,
            source_commit_digest: None,
            after_image_digest: None,
            certificate_id: None,
            certified_scopes: Vec::new(),
            source_outcome_digest: None,
        }
    }

    fn tombstone() -> AuthoritySourceTombstone {
        source_tombstone_for_reservation(
            &reservation(),
            "ef".repeat(32),
            5_000,
            AuthorityAbortRequest::stable_abort_id("res-abc123").unwrap(),
            "local rollback proven".to_owned(),
        )
        .unwrap()
    }

    fn request(digest: &str) -> AuthorityAbortRequest {
        AuthorityAbortRequest {
            caller: caller(),
            reservation_id: "res-abc123".to_owned(),
            operation_id: "operation-1".to_owned(),
            database_id: "db-1".to_owned(),
            request_digest: "cd".repeat(32),
            abort_id: AuthorityAbortRequest::stable_abort_id("res-abc123").unwrap(),
            source_tombstone_digest: digest.to_owned(),
            reason: "local rollback proven".to_owned(),
        }
    }

    fn receipt(frontier: GlobalAuthorityFrontier) -> AuthorityAbortReceipt {
        AuthorityAbortReceipt {
            authorization_edition: AUTHORIZATION_EDITION,
            reservation_id: "res-abc123".to_owned(),
            abort_id: AuthorityAbortRequest::stable_abort_id("res-abc123").unwrap(),
            operation_id: "operation-1".to_owned(),
            event_id: "event-1".to_owned(),
            admission_proof_id: "proof-1".to_owned(),
            request_digest: "cd".repeat(32),
            service_id: "source-svc".to_owned(),
            database_id: "db-1".to_owned(),
            intent_digest: "ab".repeat(32),
            reason: "local rollback proven".to_owned(),
            source_tombstone_digest: tombstone().digest().unwrap(),
            aborted_at: 5_000,
            global_frontier: frontier,
        }
    }

    fn frontier() -> GlobalAuthorityFrontier {
        GlobalAuthorityFrontier {
            authorization_edition: AUTHORIZATION_EDITION,
            authority_id: "authority-1".to_owned(),
            authority_term: 1,
            global_fence_sequence: 2,
            key_id: "signer-1".to_owned(),
            key_epoch: 1,
            root_id: "root-1".to_owned(),
            trust_root_digest: "aa".repeat(32),
            global_chain_digest: "bb".repeat(32),
            updated_at: 5_000,
        }
    }

    #[test]
    fn stable_abort_id_is_deterministic_and_validated() {
        assert_eq!(
            AuthorityAbortRequest::stable_abort_id("res-abc123").unwrap(),
            "abort-res-abc123"
        );
        assert_eq!(
            AuthorityAbortRequest::stable_abort_id("res-abc123").unwrap(),
            AuthorityAbortRequest::stable_abort_id("res-abc123").unwrap()
        );
        assert!(AuthorityAbortRequest::stable_abort_id("").is_err());
    }

    #[test]
    fn tombstone_digest_binds_every_field_and_rejects_tampering() {
        let base = tombstone();
        let digest = base.digest().unwrap();
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, base.digest().unwrap(), "digest must be stable");

        let mut other = base.clone();
        other.reservation_record_digest = "01".repeat(32);
        assert_ne!(digest, other.digest().unwrap(), "row digest is bound");
        let mut other = base.clone();
        other.disposition = "RESERVED".to_owned();
        assert!(
            other.digest().is_err(),
            "non-ABORTED disposition is invalid"
        );
        let mut other = base.clone();
        other.reason = "different reason".to_owned();
        assert_ne!(digest, other.digest().unwrap(), "reason is bound");
        let mut other = base.clone();
        other.tombstoned_at = 5_001;
        assert_ne!(digest, other.digest().unwrap(), "tombstone time is bound");
        let mut other = base.clone();
        other.abort_id = "abort-other".to_owned();
        assert_ne!(digest, other.digest().unwrap(), "abort id is bound");
    }

    #[test]
    fn request_validation_rejects_bad_shapes_and_reasons() {
        assert!(request(&tombstone().digest().unwrap()).validate().is_ok());
        assert!(request("nothex").validate().is_err());
        assert!(request(&"AB".repeat(32)).validate().is_err());
        let mut empty_reason = request(&tombstone().digest().unwrap());
        empty_reason.reason = "   ".to_owned();
        assert!(empty_reason.validate().is_err());
        let mut control_reason = request(&tombstone().digest().unwrap());
        control_reason.reason = "bad\u{0007}reason".to_owned();
        assert!(control_reason.validate().is_err());
    }

    #[test]
    fn response_validation_binds_receipt_to_reservation() {
        let frontier = frontier();
        let receipt = receipt(frontier.clone());
        let mut aborted_reservation = reservation();
        aborted_reservation.state = AuthorityReservationState::Aborted;
        let response = AuthorityAbortResponse {
            disposition: AuthorityReservationDisposition::Aborted,
            reservation: aborted_reservation.clone(),
            receipt: receipt.clone(),
            global_frontier: frontier.clone(),
            read_gate: AuthorityReadGate::blocked(),
        };
        assert!(response.validate().is_ok());

        let mut tampered = response.clone();
        tampered.receipt.intent_digest = "ff".repeat(32);
        assert!(tampered.validate().is_err());
        let mut wrong_state = response.clone();
        wrong_state.reservation.state = AuthorityReservationState::Committed;
        assert!(wrong_state.validate().is_err());
        let mut wrong_disposition = response.clone();
        wrong_disposition.disposition = AuthorityReservationDisposition::Committed;
        assert!(wrong_disposition.validate().is_err());
        let mut wrong_frontier = response.clone();
        wrong_frontier.global_frontier.global_fence_sequence = 9;
        assert!(wrong_frontier.validate().is_err());
    }

    #[test]
    fn matches_abort_requires_every_immutable_binding() {
        let frontier = frontier();
        let receipt = receipt(frontier);
        let request = request(&receipt.source_tombstone_digest);
        let reservation = reservation();
        assert!(receipt.matches_abort(&request, &reservation));

        let mut wrong_reason = request.clone();
        wrong_reason.reason = "other".to_owned();
        assert!(!receipt.matches_abort(&wrong_reason, &reservation));
        let mut wrong_digest = request.clone();
        wrong_digest.source_tombstone_digest = "12".repeat(32);
        assert!(!receipt.matches_abort(&wrong_digest, &reservation));
        let mut wrong_abort_id = request.clone();
        wrong_abort_id.abort_id = "abort-other".to_owned();
        assert!(!receipt.matches_abort(&wrong_abort_id, &reservation));
        let mut foreign_service = request.clone();
        foreign_service.caller.service_id = "other-svc".to_owned();
        assert!(!receipt.matches_abort(&foreign_service, &reservation));
    }
}
