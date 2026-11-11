//! Authority-owned receipt for one certified-memory family completion.
//!
//! The source owner supplies a complete, already durable family completion. The
//! authority assigns the receipt identity and binds it to the committed source
//! reservation and the authority frontier. A caller-provided receipt id is never
//! trusted as proof.

use serde::{Deserialize, Serialize};

use super::{
    authority_digest, authority_text, authority_timestamp, AuthorityCallerIdentity,
    AuthorityCertifiedMemoryFamily, AuthorityFamilyCompletion, AuthorityFamilyCompletionCandidate,
    AuthorityMutationKind, AuthorityProtocolError, AuthorityReadGate,
    AuthorityReservationDisposition, AuthorityReservationState, AuthorityScopeReservation,
    GlobalAuthorityFrontier,
};

pub const AUTHORITY_PATH_FAMILY_COMPLETIONS: &str = "/main/api/v1/authority-family-completions";
pub const AUTHORITY_PATH_FAMILY_COMPLETION_RECONCILE: &str =
    "/main/api/v1/authority-family-completions/reconcile";
pub const AUTHORITY_OPERATION_FAMILY_COMPLETION: &str = "family_completion";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityFamilyCompletionRequest {
    pub caller: AuthorityCallerIdentity,
    pub database_id: String,
    pub completion: AuthorityFamilyCompletionCandidate,
}

impl AuthorityFamilyCompletionRequest {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.caller.validate()?;
        authority_text(&self.database_id, "database_id")?;
        self.completion.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityFamilyCompletionReconcileRequest {
    pub caller: AuthorityCallerIdentity,
    pub database_id: String,
    pub reservation_id: String,
    pub operation_id: String,
    pub family: AuthorityCertifiedMemoryFamily,
}

impl AuthorityFamilyCompletionReconcileRequest {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.caller.validate()?;
        authority_text(&self.database_id, "database_id")?;
        authority_text(&self.reservation_id, "reservation_id")?;
        authority_text(&self.operation_id, "operation_id")?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityFamilyCompletionReconcileResponse {
    pub reservation: AuthorityScopeReservation,
    pub receipt: Option<AuthorityFamilyCompletionReceipt>,
    pub global_frontier: GlobalAuthorityFrontier,
    pub read_gate: AuthorityReadGate,
}

impl AuthorityFamilyCompletionReconcileResponse {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.reservation.validate()?;
        self.global_frontier.validate()?;
        self.read_gate.validate()?;
        if let Some(receipt) = &self.receipt {
            receipt.validate()?;
            if receipt.completion.reservation_id != self.reservation.reservation_id
                || receipt.completion.operation_id != self.reservation.intent.operation_id
                || receipt.global_frontier != self.global_frontier
            {
                return Err(AuthorityProtocolError::ScopeMismatch);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityFamilyCompletionReceipt {
    pub receipt_id: String,
    pub completion: AuthorityFamilyCompletion,
    pub completed_at: i64,
    pub global_frontier: GlobalAuthorityFrontier,
}

impl AuthorityFamilyCompletionReceipt {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        authority_text(&self.receipt_id, "receipt_id")?;
        self.completion.validate()?;
        authority_timestamp(self.completed_at, "completed_at")?;
        self.global_frontier.validate()?;
        if self.completion.authority_completion_receipt_id != self.receipt_id
            || self.global_frontier.authorization_edition != crate::AUTHORIZATION_EDITION
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        Ok(())
    }

    pub fn completion_digest(&self) -> Result<String, AuthorityProtocolError> {
        authority_digest(&self.completion.completion_digest()?, "completion_digest")?;
        self.completion.completion_digest()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityFamilyCompletionResponse {
    pub disposition: AuthorityReservationDisposition,
    pub reservation: AuthorityScopeReservation,
    pub receipt: AuthorityFamilyCompletionReceipt,
    pub global_frontier: GlobalAuthorityFrontier,
    pub read_gate: AuthorityReadGate,
}

impl AuthorityFamilyCompletionResponse {
    pub fn validate(&self) -> Result<(), AuthorityProtocolError> {
        self.reservation.validate()?;
        self.receipt.validate()?;
        self.global_frontier.validate()?;
        self.read_gate.validate()?;
        if self.disposition != AuthorityReservationDisposition::from_reservation(&self.reservation)
            || self.reservation.intent.mutation_kind != AuthorityMutationKind::AuthorizationSource
            || !matches!(
                self.reservation.state,
                AuthorityReservationState::Committed
                    | AuthorityReservationState::Certified
                    | AuthorityReservationState::Completed
            )
            || self.global_frontier != self.receipt.global_frontier
        {
            return Err(AuthorityProtocolError::ScopeMismatch);
        }
        Ok(())
    }
}

impl AuthorityFamilyCompletion {
    /// Kept only as a compatibility shim for callers that still hold the old
    /// receipt-bearing value. New authority requests use
    /// [`AuthorityFamilyCompletionCandidate`] and cannot carry this field.
    pub fn validate_for_authority_submission(&self) -> Result<(), AuthorityProtocolError> {
        Err(AuthorityProtocolError::StateConflict {
            record: "family_completion",
            state: "RECEIPT_BEARING_REQUEST".to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority_protocol::{
        AuthorityCertifiedMemoryFamily, AuthorityFamilyCompletionState,
        AuthorityFamilyDependencyFrontier, AuthorityFamilyInventoryItem, AuthorityFamilyScope,
    };

    fn candidate() -> AuthorityFamilyCompletionCandidate {
        AuthorityFamilyCompletionCandidate {
            family: AuthorityCertifiedMemoryFamily::CardContext,
            state: AuthorityFamilyCompletionState::CompleteEmpty,
            scope: AuthorityFamilyScope {
                tenant_id: Some(7),
                scope: "tenant:7".into(),
            },
            reservation_id: "reservation".into(),
            operation_id: "operation".into(),
            event_id: "event".into(),
            message_id: None,
            source_commit_digest: "11".repeat(32),
            source_outcome_digest: "22".repeat(32),
            before_content_digest: None,
            after_content_digest: None,
            complete_content_digest: Some("33".repeat(32)),
            audit_correlation_id: "audit".into(),
            inventory: Vec::<AuthorityFamilyInventoryItem>::new(),
            scope_generation: 3,
            revoke_watermark: 1,
            dependency_frontier: AuthorityFamilyDependencyFrontier {
                authority_term: 1,
                global_fence_sequence: 2,
                dependency_generation: 3,
            },
        }
    }

    #[test]
    fn candidate_has_no_caller_receipt_field_and_requires_terminal_state() {
        assert!(candidate().validate().is_ok());
        for state in [
            AuthorityFamilyCompletionState::Pending,
            AuthorityFamilyCompletionState::Unknown,
            AuthorityFamilyCompletionState::Quarantined,
        ] {
            let invalid = AuthorityFamilyCompletionCandidate {
                state,
                ..candidate()
            };
            assert_eq!(
                invalid.validate(),
                Err(AuthorityProtocolError::InvalidCoverage)
            );
        }
    }

    #[test]
    fn authority_assigns_receipt_identity_after_candidate_validation() {
        let completion = candidate()
            .into_receipted_completion("authority-receipt".into())
            .expect("authority receipt binding");
        assert_eq!(
            completion.authority_completion_receipt_id,
            "authority-receipt"
        );
        assert!(completion.validate().is_ok());
    }

    #[test]
    fn receipt_bearing_values_cannot_be_reused_as_submission_candidates() {
        let completion = candidate()
            .into_receipted_completion("authority-receipt".into())
            .expect("authority receipt binding");
        assert!(matches!(
            completion.validate_for_authority_submission(),
            Err(AuthorityProtocolError::StateConflict { .. })
        ));
    }
}
