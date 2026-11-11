//! Structural checks for a batch of single-node CARD publication candidates.
//!
//! This module performs no reads, installation, authorization or publication.
//! The caller supplies both the expected scope and the already collected state;
//! matching those inputs does not establish where either was read. Successful
//! validation proves only the checked structures, not snapshot consistency,
//! complete enumeration (including an empty set), freshness, dependency
//! frontier closure, mutation fencing, or permission to serve.

use std::collections::{HashMap, HashSet};
use std::io::{self, Write};

use astral_types::PublishedEvidenceAggregate;
use thiserror::Error;

use crate::authorization_projection_repository::{
    AuthorizationPublishedState, ProjectionAggregateIdentity,
    MAX_PUBLISHED_CARD_AGGREGATES_PER_READ, MAX_SEGMENT_PAYLOAD_BYTES,
};
use crate::authorization_snapshot::{
    validate_published_state_snapshot, ProjectionSnapshotError, MAX_CAPTURE_PUBLISHED_STATES,
};

/// Batch-wide limits on already collected typed input. These limits do not bound
/// input collection, allocation overhead, or total process memory. The actual
/// serialized grants are measured before the snapshot validator allocates a payload.
pub const MAX_CANDIDATE_SEGMENTS: usize = 100_000;
pub const MAX_CANDIDATE_GRANTS: usize = 1_000_000;
pub const MAX_CANDIDATE_PAYLOAD_BYTES: u64 = 256 * 1024 * 1024;

/// Expected database identity for one CARD-scoped published aggregate.
/// The expected values are comparison inputs, not proof of coverage or origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateCardScope {
    pub tenant_id: i64,
    pub card_id: i64,
    pub aggregate_type: PublishedEvidenceAggregate,
    pub aggregate_id: i64,
}

/// A borrowed state and the exact identity the caller expects it to have.
pub struct CandidatePublication<'a> {
    pub expected: CandidateCardScope,
    pub state: &'a AuthorizationPublishedState,
}

/// Explicitly records that no complete-set or absence proof was supplied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateCoverage {
    Unproven,
}

/// Diagnostic counts for structurally checked input, not a serving capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateBatchSummary {
    pub state_count: usize,
    pub segment_count: usize,
    pub grant_count: usize,
    pub payload_bytes: u64,
    pub coverage: CandidateCoverage,
}

#[derive(Debug, Error)]
pub enum CandidateValidationError {
    #[error("candidate scope is invalid or does not match the published pointer at index {index}")]
    ScopeMismatch { index: usize },
    #[error("candidate publication has an invalid {kind} at index {index}")]
    InvalidIdentity { kind: &'static str, index: usize },
    #[error("candidate batch contains a duplicate {kind} at index {index}")]
    Duplicate { kind: &'static str, index: usize },
    #[error("candidate batch exceeds {resource} limit {limit}")]
    LimitExceeded { resource: &'static str, limit: u64 },
    #[error("candidate published state failed structural validation at index {index}: {source}")]
    InvalidState {
        index: usize,
        #[source]
        source: ProjectionSnapshotError,
    },
}

fn scope_matches(
    expected: &CandidateCardScope,
    actual: &ProjectionAggregateIdentity,
    actual_card_id: Option<i64>,
) -> bool {
    expected.tenant_id > 0
        && expected.card_id > 0
        && expected.aggregate_id > 0
        && (expected.aggregate_type != PublishedEvidenceAggregate::UserCard
            || expected.aggregate_id == expected.card_id)
        && actual.tenant_id == expected.tenant_id
        && actual.aggregate_type == expected.aggregate_type.as_str()
        && actual.aggregate_id == expected.aggregate_id
        && actual_card_id == Some(expected.card_id)
}

#[derive(Default)]
struct BatchBudget {
    segments: usize,
    grants: usize,
    payload_bytes: u64,
}

impl BatchBudget {
    fn add(
        &mut self,
        segments: usize,
        grants: usize,
        bytes: u64,
    ) -> Result<(), CandidateValidationError> {
        self.segments = bounded_add(self.segments, segments, MAX_CANDIDATE_SEGMENTS, "segments")?;
        self.grants = bounded_add(self.grants, grants, MAX_CANDIDATE_GRANTS, "grants")?;
        self.payload_bytes = self
            .payload_bytes
            .checked_add(bytes)
            .filter(|sum| *sum <= MAX_CANDIDATE_PAYLOAD_BYTES)
            .ok_or(CandidateValidationError::LimitExceeded {
                resource: "payload bytes",
                limit: MAX_CANDIDATE_PAYLOAD_BYTES,
            })?;
        Ok(())
    }
}

struct LimitedCounter {
    count: u64,
    limit: u64,
    exceeded: bool,
}

impl Write for LimitedCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.count.checked_add(bytes.len() as u64) else {
            self.exceeded = true;
            return Err(io::Error::other("candidate byte limit"));
        };
        if next > self.limit {
            self.exceeded = true;
            return Err(io::Error::other("candidate byte limit"));
        }
        self.count = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn actual_grant_bytes<T: serde::Serialize>(
    value: &T,
    remaining: u64,
    index: usize,
) -> Result<u64, CandidateValidationError> {
    let mut counter = LimitedCounter {
        count: 0,
        limit: remaining,
        exceeded: false,
    };
    let result = serde_json::to_writer(&mut counter, value);
    if counter.exceeded {
        return Err(CandidateValidationError::LimitExceeded {
            resource: "actual grant bytes",
            limit: MAX_CANDIDATE_PAYLOAD_BYTES,
        });
    }
    result.map_err(|_| CandidateValidationError::InvalidIdentity {
        kind: "grant encoding",
        index,
    })?;
    Ok(counter.count)
}

fn bounded_add(
    current: usize,
    additional: usize,
    limit: usize,
    resource: &'static str,
) -> Result<usize, CandidateValidationError> {
    current
        .checked_add(additional)
        .filter(|sum| *sum <= limit)
        .ok_or(CandidateValidationError::LimitExceeded {
            resource,
            limit: limit as u64,
        })
}

/// Check every supplied CARD-scoped chain as a single all-or-error batch.
///
/// Reuses the existing snapshot validator for each whole state, including its
/// manifest/reference/segment pairing and canonical payload seals. The caller
/// must independently bound enumeration before allocating these inputs. Empty
/// input is accepted only as a structurally valid batch with coverage unproven;
/// it does not establish an empty durable scope or a negative authorization.
pub fn validate_candidate_publications(
    publications: &[CandidatePublication<'_>],
) -> Result<CandidateBatchSummary, CandidateValidationError> {
    bounded_add(
        0,
        publications.len(),
        MAX_CAPTURE_PUBLISHED_STATES,
        "states",
    )?;
    let mut scopes = HashSet::new();
    let mut pointer_ids = HashSet::new();
    let mut manifest_ids = HashSet::new();
    let mut reference_ids = HashSet::new();
    let mut segment_ids = HashSet::new();
    let mut grant_revisions = HashSet::new();
    let mut per_card = HashMap::new();
    let mut budget = BatchBudget::default();
    let mut actual_bytes = 0u64;

    for (index, publication) in publications.iter().enumerate() {
        let state = publication.state;
        let pointer = &state.pointer;
        if !scope_matches(&publication.expected, &pointer.identity, pointer.card_id) {
            return Err(CandidateValidationError::ScopeMismatch { index });
        }
        if pointer.pointer_id <= 0 || state.manifest_id <= 0 {
            return Err(CandidateValidationError::InvalidIdentity {
                kind: "pointer or manifest id",
                index,
            });
        }
        if !scopes.insert(&pointer.identity) {
            return Err(CandidateValidationError::Duplicate {
                kind: "aggregate identity",
                index,
            });
        }
        if !pointer_ids.insert(pointer.pointer_id) {
            return Err(CandidateValidationError::Duplicate {
                kind: "pointer id",
                index,
            });
        }
        if !manifest_ids.insert(state.manifest_id) {
            return Err(CandidateValidationError::Duplicate {
                kind: "manifest id",
                index,
            });
        }
        let card_count = per_card
            .entry((publication.expected.tenant_id, publication.expected.card_id))
            .or_insert(0);
        *card_count = bounded_add(
            *card_count,
            1,
            MAX_PUBLISHED_CARD_AGGREGATES_PER_READ,
            "aggregates per card",
        )?;

        // Check counts before invoking the validator, which re-encodes payloads.
        budget.add(state.segments.len(), 0, 0)?;
        for segment in &state.segments {
            budget.add(0, segment.grants.len(), segment.byte_size)?;
            actual_bytes += actual_grant_bytes(
                &segment.grants,
                (MAX_CANDIDATE_PAYLOAD_BYTES - actual_bytes).min(MAX_SEGMENT_PAYLOAD_BYTES as u64),
                index,
            )?;
            if segment.segment_id <= 0 {
                return Err(CandidateValidationError::InvalidIdentity {
                    kind: "segment id",
                    index,
                });
            }
            for grant in &segment.grants {
                if grant.tenant.tenant_id != publication.expected.tenant_id
                    || grant.card_id != publication.expected.card_id
                {
                    return Err(CandidateValidationError::ScopeMismatch { index });
                }
                // Conservative candidate rule: do not collapse even equivalent
                // duplicates; the formal reader has a separate provenance contract.
                if !grant_revisions.insert((grant.grant_id, grant.revision)) {
                    return Err(CandidateValidationError::Duplicate {
                        kind: "grant revision",
                        index,
                    });
                }
            }
            if !segment_ids.insert(segment.segment_id) {
                return Err(CandidateValidationError::Duplicate {
                    kind: "segment id",
                    index,
                });
            }
        }
        // Bound references independently: corrupt input need not have matching
        // reference and segment lengths, and must not grow this set unbounded.
        if state.references.len() != state.segments.len() {
            return Err(CandidateValidationError::InvalidIdentity {
                kind: "reference/segment count",
                index,
            });
        }
        for reference in &state.references {
            if reference.reference_id <= 0 {
                return Err(CandidateValidationError::InvalidIdentity {
                    kind: "reference id",
                    index,
                });
            }
            if !reference_ids.insert(reference.reference_id) {
                return Err(CandidateValidationError::Duplicate {
                    kind: "reference id",
                    index,
                });
            }
        }
        validate_published_state_snapshot(state)
            .map_err(|source| CandidateValidationError::InvalidState { index, source })?;
    }

    Ok(CandidateBatchSummary {
        state_count: publications.len(),
        segment_count: budget.segments,
        grant_count: budget.grants,
        payload_bytes: budget.payload_bytes,
        coverage: CandidateCoverage::Unproven,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_never_claims_complete_or_proven_absence() {
        let summary = validate_candidate_publications(&[]).unwrap();
        assert_eq!(summary.state_count, 0);
        assert_eq!(summary.coverage, CandidateCoverage::Unproven);
    }

    #[test]
    fn scope_is_exact_and_user_card_aggregate_is_the_card() {
        let expected = CandidateCardScope {
            tenant_id: 7,
            card_id: 11,
            aggregate_type: PublishedEvidenceAggregate::UserCard,
            aggregate_id: 11,
        };
        let identity = ProjectionAggregateIdentity::new(7, "USER_CARD", 11).unwrap();
        assert!(scope_matches(&expected, &identity, Some(11)));
        assert!(!scope_matches(&expected, &identity, Some(12)));
        assert!(!scope_matches(&expected, &identity, None));
        let foreign = ProjectionAggregateIdentity::new(8, "USER_CARD", 11).unwrap();
        assert!(!scope_matches(&expected, &foreign, Some(11)));
        let wrong_type = ProjectionAggregateIdentity::new(7, "RULE_SET", 11).unwrap();
        assert!(!scope_matches(&expected, &wrong_type, Some(11)));
        let mut wrong_card_aggregate = expected.clone();
        wrong_card_aggregate.aggregate_id = 12;
        let identity = ProjectionAggregateIdentity::new(7, "USER_CARD", 12).unwrap();
        assert!(!scope_matches(&wrong_card_aggregate, &identity, Some(11)));
        let ruleset = CandidateCardScope {
            aggregate_type: PublishedEvidenceAggregate::RuleSet,
            aggregate_id: 12,
            ..expected
        };
        let identity = ProjectionAggregateIdentity::new(7, "RULE_SET", 12).unwrap();
        assert!(scope_matches(&ruleset, &identity, Some(11)));
    }

    #[test]
    fn actual_encoding_is_bounded_independently_of_declared_size() {
        let value = vec!["payload"];
        assert!(matches!(
            actual_grant_bytes(&value, 2, 0),
            Err(CandidateValidationError::LimitExceeded { .. })
        ));
        assert_eq!(actual_grant_bytes(&value, 11, 0).unwrap(), 11);
    }

    #[test]
    fn budgets_reject_overflow_and_never_truncate() {
        assert_eq!(
            bounded_add(
                0,
                MAX_CAPTURE_PUBLISHED_STATES,
                MAX_CAPTURE_PUBLISHED_STATES,
                "states"
            )
            .unwrap(),
            MAX_CAPTURE_PUBLISHED_STATES
        );
        assert!(bounded_add(
            0,
            MAX_CAPTURE_PUBLISHED_STATES + 1,
            MAX_CAPTURE_PUBLISHED_STATES,
            "states"
        )
        .is_err());
        assert!(bounded_add(usize::MAX, 1, usize::MAX, "states").is_err());
        let mut budget = BatchBudget::default();
        budget
            .add(
                MAX_CANDIDATE_SEGMENTS,
                MAX_CANDIDATE_GRANTS,
                MAX_CANDIDATE_PAYLOAD_BYTES,
            )
            .unwrap();
        assert!(budget.add(1, 0, 0).is_err());
        let mut budget = BatchBudget::default();
        assert!(budget.add(0, MAX_CANDIDATE_GRANTS + 1, 0).is_err());
        let mut budget = BatchBudget::default();
        assert!(budget.add(0, 0, MAX_CANDIDATE_PAYLOAD_BYTES + 1).is_err());
    }
}
