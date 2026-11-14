//! AstralLight authorization policy engine.
//!
//! `PolicyEngine::evaluate()` is the only formal authorization entry point.
//! memory—v1: the legacy CURRENT V6/V7 published-evidence execution chain has
//! been physically retired (`memory-v1-retire-legacy-read-20261112`, Rust 规范
//! §15.10); until the memory-v1 shared root completes adoption, every formal
//! evaluation fails closed to `AUTHORIZATION_PENDING` and no repository state,
//! published evidence, or authorization fence can produce an ALLOW. This crate
//! contains no database, cache, or message transport implementation;
//! authoritative reads for the future positive path stay injected through
//! `RuleRepository`.
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
/// Experimental memory-v1 candidate inspection; never an authorization decision.
#[cfg(feature = "memory-v1-candidate")]
pub mod memory_v1_candidate;
/// Typed memory-v1 evaluator, isolated from the legacy formal path.
#[cfg(feature = "memory-v1-candidate")]
pub mod memory_v1_formal;
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
