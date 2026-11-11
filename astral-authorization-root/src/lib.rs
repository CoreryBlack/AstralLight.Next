//! Process-local candidate models and snapshot infrastructure.
//!
//! This crate does not verify publication, coverage, source commits, V7
//! authority, or request proofs. Its candidate data and local synchronization
//! must never be used as authorization evidence or to admit a business mutation.

#![forbid(unsafe_code)]

use std::sync::atomic::AtomicBool;

static OWNER_REGISTERED: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
static TEST_OWNER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub mod atomic_state;
pub mod candidate_scope;
pub mod evidence;
pub mod experimental;
pub mod manager;
pub mod memory_v1_db_rows;
pub mod memory_v1_digest;
pub mod memory_v1_facts;
pub mod memory_v1_hamt;
pub mod memory_v1_hamt_runtime;
pub mod memory_v1_kernel;
pub mod memory_v1_model;
pub mod memory_v1_rules;
pub mod memory_v1_structured;
pub mod memory_v1_version;
pub mod model;
pub mod protocol;
pub mod shared_snapshot;
