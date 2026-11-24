//! Process-local candidate models and snapshot infrastructure.
//!
//! This crate does not verify publication, coverage, source commits, V7
//! authority, or request proofs. Its candidate data and local synchronization
//! must never be used as authorization evidence or to admit a business mutation.

#![forbid(unsafe_code)]

pub mod memory_v1_adoption;
/// Untrusted local candidate codec for one change and its audit value.
pub mod memory_v1_change_audit_wire;
mod memory_v1_confirmation_index;
pub mod memory_v1_db_rows;
pub mod memory_v1_digest;
pub mod memory_v1_fence;
pub mod memory_v1_hamt;
pub mod memory_v1_hamt_runtime;
pub mod memory_v1_mutation_digest;
pub mod memory_v1_mutation_wire;
pub mod memory_v1_policy_time;
pub mod memory_v1_registry;
pub mod memory_v1_request;
pub mod memory_v1_root;
mod memory_v1_root_digest;
pub mod memory_v1_rules;
pub mod memory_v1_session;
pub mod memory_v1_session_authority;
pub mod memory_v1_version;
pub mod model;
