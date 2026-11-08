//! Error types of the authority control plane.
//!
//! [`AuthorityServiceError`] mirrors the protocol taxonomy plus the internal
//! failure modes. `UnknownOutcome` is terminal for the current attempt: the
//! service and the client library never retry an unknown operation.

use astral_types::AuthorityProtocolError;
use thiserror::Error;

#[cfg(feature = "service")]
/// Errors of the durable store layer.
#[derive(Debug, Error)]
pub enum AuthorityStoreError {
    #[error("quorum store is unavailable: {0}")]
    Unavailable(String),
    #[error("quorum store configuration is invalid: {0}")]
    Configuration(String),
    #[error("stored record is invalid: {0}")]
    Corrupt(String),
    #[error("compare-and-swap precondition failed on {key}")]
    PreconditionFailed { key: String },
}

#[cfg(feature = "service")]
/// Errors of the authority service.
#[derive(Debug, Error)]
pub enum AuthorityServiceError {
    #[error(transparent)]
    Protocol(#[from] AuthorityProtocolError),
    #[error(transparent)]
    Store(#[from] AuthorityStoreError),
    #[error("authority instance is not the quorum leader; mutations are refused")]
    NotLeader,
    #[error("protected signer is not available for this operation")]
    SignerUnavailable,
    #[error("operation outcome is unknown (hint: {operation_hint}); reconcile by stable identity")]
    UnknownOutcome { operation_hint: String },
    #[error("caller {caller} is not authorized for operation {operation}")]
    NotAuthorized {
        caller: String,
        operation: &'static str,
    },
}

/// Errors of the internal client library.
#[derive(Debug, Error)]
pub enum AuthorityClientError {
    #[error("authority endpoint must use https")]
    InsecureEndpoint,
    #[error("startup attestation failed: {0}")]
    Attestation(String),
    #[error("authority rejected the request: {code}: {message}")]
    Rejected { code: String, message: String },
    #[error("operation outcome is unknown (hint: {operation_hint}); reconcile by stable identity")]
    UnknownOutcome { operation_hint: String },
    #[error("transport failure: {0}")]
    Transport(String),
    #[error("protocol violation in response: {0}")]
    Protocol(String),
    #[error(transparent)]
    ProtocolError(#[from] AuthorityProtocolError),
}
