//! Strict public wire contracts and Ed25519 signatures for AstralLight SDKs.
//!
//! The SDK authorization endpoint is fixed to `POST AUTHORIZATION_PATH`. The
//! signed request additionally binds the app's business method/path and the
//! entire actor/resource-facts body. Unknown fields are rejected on all wire
//! contract structs.

mod manifest;
mod signing;
mod types;
mod validation;

pub use manifest::{ApplicationManifest, ManifestRoute, ResourceResolver};
pub use signing::{sign_decision, verify_decision, verify_request};
pub use types::{
    ApiResponseEnvelope, AuthorizationDecision, AuthorizationRequest, ContractError,
    DecisionOutcome, DecisionScope, ExternalSubject, ResourceFacts, ResourceOperation,
    SignedAuthorizationDecision, SignedAuthorizationRequest, VerifiedAuthorizationDecision,
};
pub use validation::{identifier, opaque_identifier};

pub const AUTHORIZATION_PATH: &str = "/main/api/v1/integrations/authorization-decisions";
pub const AUTHORIZATION_DECISIONS_PATH: &str = AUTHORIZATION_PATH;
pub const AUTHORIZATION_HTTP_METHOD: &str = "POST";
pub const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024;
pub const MAX_WIRE_BYTES: usize = MAX_REQUEST_BODY_BYTES;
pub const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 32 * 1024;
pub const MAX_MANIFEST_ROUTES: usize = 128;
pub const MAX_DECISION_REASON_BYTES: usize = 512;
pub const MAX_DECISION_TTL_MS: u64 = 5_000;
pub const MAX_CLOCK_SKEW_MS: u64 = 30_000;
pub const MAX_REQUEST_CLOCK_SKEW_MS: u64 = MAX_CLOCK_SKEW_MS;

#[cfg(test)]
mod tests;
