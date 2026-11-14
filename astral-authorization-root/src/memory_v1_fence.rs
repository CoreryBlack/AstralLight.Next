//! memory—v1 §4.6: The generation fence over BASE/OVERLAY modification windows.
//!
//! While a rule set is being modified, the fence holds the declared premises
//! (observed rule-set version, root version and digest). A second modification
//! of the same object is rejected for the whole window, and reads that depend
//! on the object are refused immediately (§4.6 "立即 PENDING") instead of
//! queueing. Publication happens only when the declared premises still match
//! the actual snapshot; otherwise the window closes with zero side effects.
//! Correctness is carried by the atomic snapshot, the CAS publication and the
//! §4.7 dependency recheck — the fence adds explicit mutual exclusion and the
//! fail-closed refusal, never a request/writer shared gate.

use std::collections::HashMap;
use std::sync::Mutex;
use thiserror::Error;

use crate::memory_v1_db_rows::BinaryId;
use crate::memory_v1_digest::ContentDigest;

/// The declaration captured when a modification window opens (§4.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FenceDeclaration {
    /// The rule-set version the modifier observed.
    pub rule_set_version: Vec<u8>,
    /// The root global version the modifier observed.
    pub root_version: u64,
    /// The root digest the modifier observed.
    pub digest: ContentDigest,
}

/// An active fence with its declared premises.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModificationFence {
    pub declaration: FenceDeclaration,
}

/// Fence operation failures; every one is deterministic.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FenceError {
    #[error("rule set {0:?} already has an active modification fence")]
    AlreadyFenced(BinaryId),
    #[error("rule set {0:?} has no active modification fence")]
    NotFenced(BinaryId),
    #[error("declared rule-set version does not match the current selection")]
    RuleSetVersionMismatch {
        declared: Vec<u8>,
        actual: Option<Vec<u8>>,
    },
    #[error("declared root version/digest does not match the current snapshot")]
    RootMismatch {
        declared_root_version: u64,
        actual_root_version: u64,
    },
    #[error("candidate lookup failed while checking fence premises: {0:?}")]
    Candidate(crate::memory_v1_hamt::CandidateError),
}

/// The actual snapshot premise a declaration is checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FencePremise {
    pub root_version: u64,
    pub digest: ContentDigest,
    pub selected_version: Option<Vec<u8>>,
}

/// The active modification fences keyed by rule set (§4.6).
#[derive(Default)]
pub struct FenceRegistry {
    fences: Mutex<HashMap<BinaryId, ModificationFence>>,
}

impl FenceRegistry {
    /// Open the modification window (§4.6).
    ///
    /// Fails when the object is already fenced or any declared premise does
    /// not match the actual snapshot state (concurrent抢先、重放、替换).
    pub fn begin(
        &self,
        rule_set_id: BinaryId,
        declaration: &FenceDeclaration,
        premise: &FencePremise,
    ) -> Result<(), FenceError> {
        let mut fences = self.fences.lock().expect("fence lock");
        if fences.contains_key(&rule_set_id) {
            return Err(FenceError::AlreadyFenced(rule_set_id));
        }
        if premise.root_version != declaration.root_version || premise.digest != declaration.digest
        {
            return Err(FenceError::RootMismatch {
                declared_root_version: declaration.root_version,
                actual_root_version: premise.root_version,
            });
        }
        if premise.selected_version.as_deref() != Some(declaration.rule_set_version.as_slice()) {
            return Err(FenceError::RuleSetVersionMismatch {
                declared: declaration.rule_set_version.clone(),
                actual: premise.selected_version.clone(),
            });
        }
        fences.insert(
            rule_set_id,
            ModificationFence {
                declaration: declaration.clone(),
            },
        );
        Ok(())
    }

    /// §4.6: whether reads depending on this object must be refused.
    pub fn is_active(&self, rule_set_id: BinaryId) -> bool {
        self.fences
            .lock()
            .expect("fence lock")
            .contains_key(&rule_set_id)
    }

    /// Close the window without publishing (abort/reinitiate path).
    pub fn abort(&self, rule_set_id: BinaryId) -> Result<(), FenceError> {
        self.fences
            .lock()
            .expect("fence lock")
            .remove(&rule_set_id)
            .map(|_| ())
            .ok_or(FenceError::NotFenced(rule_set_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration(version: &[u8]) -> FenceDeclaration {
        FenceDeclaration {
            rule_set_version: version.to_vec(),
            root_version: 7,
            digest: ContentDigest::default(),
        }
    }

    fn premise(version: &[u8]) -> FencePremise {
        FencePremise {
            root_version: 7,
            digest: ContentDigest::default(),
            selected_version: Some(version.to_vec()),
        }
    }

    // memory—v1 §4.6: one fence per object; a second modifier is rejected.
    #[test]
    fn same_object_fencing_is_mutually_exclusive() {
        let fences = FenceRegistry::default();
        fences
            .begin([1; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        assert!(fences.is_active([1; 16]));
        assert_eq!(
            fences.begin([1; 16], &declaration(b"v1"), &premise(b"v1")),
            Err(FenceError::AlreadyFenced([1; 16]))
        );
        // A different object fences independently.
        fences
            .begin([2; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        assert!(fences.is_active([2; 16]));
    }

    // memory—v1 §4.6: declared premises must match the actual snapshot.
    #[test]
    fn declared_premises_are_checked_against_the_snapshot() {
        let fences = FenceRegistry::default();
        let stale_root = FenceDeclaration {
            rule_set_version: b"v1".to_vec(),
            root_version: 6,
            digest: ContentDigest::default(),
        };
        assert_eq!(
            fences.begin([1; 16], &stale_root, &premise(b"v1")),
            Err(FenceError::RootMismatch {
                declared_root_version: 6,
                actual_root_version: 7,
            })
        );
        assert_eq!(
            fences.begin([1; 16], &declaration(b"v0"), &premise(b"v1")),
            Err(FenceError::RuleSetVersionMismatch {
                declared: b"v0".to_vec(),
                actual: Some(b"v1".to_vec()),
            })
        );
        assert!(!fences.is_active([1; 16]));
    }

    // memory—v1 §4.6: abort releases the window; double abort is an error.
    #[test]
    fn abort_releases_and_is_strict() {
        let fences = FenceRegistry::default();
        fences
            .begin([1; 16], &declaration(b"v1"), &premise(b"v1"))
            .unwrap();
        fences.abort([1; 16]).unwrap();
        assert!(!fences.is_active([1; 16]));
        assert_eq!(fences.abort([1; 16]), Err(FenceError::NotFenced([1; 16])));
    }
}
