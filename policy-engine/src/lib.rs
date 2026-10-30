//! AstralLight authorization policy engine.
//!
//! `PolicyEngine::evaluate()` is the only formal authorization entry point. It
//! applies identity and target-ownership gates, then requires CURRENT V6 published
//! ORG_SCOPE or CARD evidence; missing, stale, malformed, or unavailable proof
//! fails closed. This crate contains no database, cache, or message transport
//! implementation; authoritative reads are injected through `RuleRepository`.
//!
//! The crate also exposes Rust-native authorization compiler kernels. Their
//! candidate and rebuild APIs are separate from the formal authorization read path.

mod authorization_compiler;
mod circuit_breaker;
mod client;
mod condition;
mod cross_city_conflict;
mod data_scope;
#[cfg(any(feature = "e1-observability", test))]
pub mod e1_observation;
mod engine;
mod hit_stats;
/// ORG_SCOPE admission contract and evidence validation.
pub mod org_admission;
/// ORG_SCOPE pure compiler kernel.
mod org_compiler;

pub use authorization_compiler::*;
pub use circuit_breaker::*;
pub use client::*;
pub use condition::*;
pub use cross_city_conflict::*;
pub use data_scope::*;
pub use engine::*;
pub use hit_stats::*;
pub use org_admission::OrgAuthorityRead;
pub use org_compiler::*;
