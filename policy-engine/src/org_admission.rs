//! ORG authority read outcome shared with `RuleRepository` implementations.
//!
//! memory—v1: The legacy ORG_SCOPE admission execution chain (published
//! administrative-authority evaluation, contribution matching, and its ALLOW
//! path) has been physically retired per `memory-v1-retire-legacy-read-20261112`
//! (Rust 规范 §15.10). What remains is the read-outcome type that repository
//! owners and the fail-closed engine still share; it never authorizes by itself.

use astral_types::org_scope::OrgAdmissionEvidence;

#[derive(Debug, Clone)]
pub enum OrgAuthorityRead {
    /// The tenant is outside durable ORG_SCOPE management. memory—v1: with the
    /// legacy card-evidence path retired this outcome no longer enables any
    /// fall-through; the formal entry remains fail-closed.
    Unmanaged,
    /// The tenant is durably managed but the startup-frozen feature is disabled.
    Disabled,
    /// A completed ORG read established a deterministic business pending state
    /// (for example stale publication, membership mismatch, or missing proof).
    /// This remains fail-closed but is not an infrastructure dependency failure.
    Pending {
        code: String,
    },
    /// The ORG gate or authoritative evidence reader was unavailable. The engine
    /// must fail closed and record a dependency failure so outages remain visible
    /// to the circuit breaker instead of being laundered into business pending.
    Unavailable {
        code: String,
    },
    Ready(Box<OrgAdmissionEvidence>),
}
