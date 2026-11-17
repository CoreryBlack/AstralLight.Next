//! Single-node composition support and memory-v1 durable journal contracts.
//!
//! The binary remains the runtime entry point; this library target exposes the
//! narrow durable owner so composition and contract tests share one module path.

#![forbid(unsafe_code)]

pub mod memory_v1_durable_journal;
pub mod memory_v1_governance_owner;
pub mod memory_v1_recovery_owner;
pub mod memory_v1_root_writer;

#[cfg(test)]
mod memory_v1_governance_owner_tests;
