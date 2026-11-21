//! Single-node composition support and memory-v1 durable journal contracts.
//!
//! The binary remains the runtime entry point; this library target exposes the
//! narrow durable owner so composition and contract tests share one module path.

#![forbid(unsafe_code)]

pub mod memory_v1_cold_install;
pub mod memory_v1_durable_journal;
pub mod memory_v1_governance_owner;
pub mod memory_v1_recovery_owner;
pub mod memory_v1_root_writer;

// memory—v1: The in-memory reservation of one governed mutation's complete
// immutable journal payload; internal to the commit owner.
mod memory_v1_governance_payload;

#[cfg(test)]
mod memory_v1_governance_owner_tests;

// memory—v1: Paper evidence at owner, writer and recovery level (C&S sections 4 and 5).
#[cfg(test)]
mod memory_v1_paper_evidence_tests;

// memory—v1: Large-scale production-shape simulation (sharded fixtures, random
// rule-set mixing, request distribution and service-period context loads).
#[cfg(test)]
mod memory_v1_scale_tests;
