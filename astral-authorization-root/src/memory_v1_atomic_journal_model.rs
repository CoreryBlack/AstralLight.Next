//! memory—v1 isolated atomic journal candidate; this file is not wired into a root.
//!
//! This is an in-memory state-transition model, not authorization, a durable
//! journal, a persistence confirmation, or a recovery protocol. Its opaque facts,
//! operation keys, digests, and payloads are caller-supplied; in particular it
//! does not verify that a digest binds the complete change and audit payload.
//!
//! The model intentionally never removes a record or a seen operation. A full
//! journal permanently applies backpressure, so it is not a long-running design.
//! There is no simulated or real durable-prefix advancement API.
//!
//! One mutex owns fixed-size inline arrays for facts and all records. A read
//! guard borrows that state and prevents publication until dropped; no `Arc`
//! snapshots, reference-counted payloads, or internal queues are created.
//! Writers attempt the mutex once and construct the sole new record while
//! holding it, so competing writers do not construct model-owned copies. The
//! caller chooses the compile-time bounds and must budget the inline object,
//! initialization/move and one writer's stack temporaries, thread stacks, and
//! caller-owned input or copies separately. Neither the number of callers nor
//! their memory is bounded here. A retained reader can indefinitely block writes;
//! this deliberately trades availability for a small, auditable memory model.
//! Allocation failure, process abort, and arbitrary caller code are outside this
//! model; no successful result establishes persistence or permission to serve.

use std::sync::{Mutex, MutexGuard, TryLockError};

/// Candidate outcome of one in-memory publication or its idempotent replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateResult {
    /// Candidate root generation after the original publication.
    pub generation: u64,
    /// Independent, process-local mutation sequence of the original publication.
    pub sequence: u64,
}

/// Candidate failure; no variant asserts anything about a durable operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateError {
    /// A compile-time size or capacity is zero.
    InvalidBounds,
    /// The operation key is zero or the payload is empty or exceeds its bound.
    InvalidInput,
    /// Another reader or writer currently holds the candidate state.
    Busy,
    /// A previous holder panicked; the candidate is unavailable.
    Poisoned,
    /// This operation key was previously used with a different digest.
    OperationConflict,
    /// The caller's expected generation is no longer current.
    StaleGeneration,
    /// The no-release record and deduplication capacity has been exhausted.
    Full,
    /// A generation or mutation sequence has no representable successor.
    Exhausted,
}

/// Candidate record containing the exact bytes supplied by the caller.
///
/// It is not evidence that the payload is complete, valid, or persisted.
pub struct CandidateRecord<const PAYLOAD: usize> {
    operation: [u8; 16],
    digest: [u8; 32],
    payload: [u8; PAYLOAD],
    payload_len: usize,
    result: CandidateResult,
}

impl<const PAYLOAD: usize> CandidateRecord<PAYLOAD> {
    /// memory—v1: Return this candidate record's operation key.
    pub fn operation(&self) -> &[u8; 16] {
        &self.operation
    }

    /// memory—v1: Return the opaque caller-supplied candidate digest.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// memory—v1: Borrow exactly the candidate payload bytes supplied on commit.
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len]
    }

    /// memory—v1: Return the original candidate publication result.
    pub fn result(&self) -> CandidateResult {
        self.result
    }
}

struct CandidateState<const FACTS: usize, const PAYLOAD: usize, const RECORDS: usize> {
    facts: [u8; FACTS],
    generation: u64,
    sequence: u64,
    records: [Option<CandidateRecord<PAYLOAD>>; RECORDS],
    len: usize,
}

/// A fixed-capacity, no-release, process-local atomic publication candidate.
///
/// `FACTS`, `PAYLOAD`, and `RECORDS` are inline byte/entry bounds, not an OS
/// memory reservation. All construction, readers and publications must remain
/// inside the same process; this candidate has no external or durable effects.
pub struct CandidateAtomicJournal<const FACTS: usize, const PAYLOAD: usize, const RECORDS: usize> {
    state: Mutex<CandidateState<FACTS, PAYLOAD, RECORDS>>,
}

/// A stable borrowed candidate view; keeping it alive prevents all publication.
pub struct CandidateReadGuard<'a, const FACTS: usize, const PAYLOAD: usize, const RECORDS: usize> {
    state: MutexGuard<'a, CandidateState<FACTS, PAYLOAD, RECORDS>>,
}

impl<const FACTS: usize, const PAYLOAD: usize, const RECORDS: usize>
    CandidateAtomicJournal<FACTS, PAYLOAD, RECORDS>
{
    /// memory—v1: Create an empty candidate journal with opaque initial facts.
    ///
    /// The initial generation and mutation sequence are independent local
    /// counters. They have no meaning outside this candidate instance.
    pub fn new(facts: [u8; FACTS], generation: u64) -> Result<Self, CandidateError> {
        if FACTS == 0 || PAYLOAD == 0 || RECORDS == 0 {
            return Err(CandidateError::InvalidBounds);
        }
        Ok(Self {
            state: Mutex::new(CandidateState {
                facts,
                generation,
                sequence: 0,
                records: std::array::from_fn(|_| None),
                len: 0,
            }),
        })
    }

    /// memory—v1: Try once to borrow a consistent candidate state.
    ///
    /// A held guard blocks even other readers. Callers must bound its lifetime.
    pub fn try_read(
        &self,
    ) -> Result<CandidateReadGuard<'_, FACTS, PAYLOAD, RECORDS>, CandidateError> {
        match self.state.try_lock() {
            Ok(state) => Ok(CandidateReadGuard { state }),
            Err(TryLockError::WouldBlock) => Err(CandidateError::Busy),
            Err(TryLockError::Poisoned(_)) => Err(CandidateError::Poisoned),
        }
    }

    /// memory—v1: Try once to atomically publish facts and one prepared record.
    ///
    /// The caller prepares the full payload and must bind the key and digest to
    /// all semantically relevant input. This model treats the digest as opaque,
    /// does not recompute it, and is not a security boundary. Equal key/digest
    /// returns the original result even if the supplied generation is stale or
    /// the journal is full; different digest rejects the key. A replay does not
    /// compare or apply its newly supplied facts or payload. Inputs are validated
    /// before replay lookup, and lock contention can return `Busy` for any call.
    pub fn try_publish(
        &self,
        expected_generation: u64,
        operation: [u8; 16],
        digest: [u8; 32],
        facts: [u8; FACTS],
        payload: &[u8],
    ) -> Result<CandidateResult, CandidateError> {
        if operation == [0; 16] || payload.is_empty() || payload.len() > PAYLOAD {
            return Err(CandidateError::InvalidInput);
        }
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Err(CandidateError::Busy),
            Err(TryLockError::Poisoned(_)) => return Err(CandidateError::Poisoned),
        };

        for record in state.records[..state.len].iter().flatten() {
            if record.operation == operation {
                return if record.digest == digest {
                    Ok(record.result)
                } else {
                    Err(CandidateError::OperationConflict)
                };
            }
        }
        if state.generation != expected_generation {
            return Err(CandidateError::StaleGeneration);
        }
        if state.len == RECORDS {
            return Err(CandidateError::Full);
        }
        let result = CandidateResult {
            generation: state
                .generation
                .checked_add(1)
                .ok_or(CandidateError::Exhausted)?,
            sequence: state
                .sequence
                .checked_add(1)
                .ok_or(CandidateError::Exhausted)?,
        };
        let mut stored_payload = [0; PAYLOAD];
        stored_payload[..payload.len()].copy_from_slice(payload);
        let record = CandidateRecord {
            operation,
            digest,
            payload: stored_payload,
            payload_len: payload.len(),
            result,
        };

        // No fallible work remains; the mutex is the single publication boundary.
        let index = state.len;
        state.records[index] = Some(record);
        state.facts = facts;
        state.generation = result.generation;
        state.sequence = result.sequence;
        state.len = index + 1;
        Ok(result)
    }
}

impl<const FACTS: usize, const PAYLOAD: usize, const RECORDS: usize>
    CandidateReadGuard<'_, FACTS, PAYLOAD, RECORDS>
{
    /// memory—v1: Borrow the facts of this consistent candidate view.
    pub fn facts(&self) -> &[u8; FACTS] {
        &self.state.facts
    }

    /// memory—v1: Return this candidate view's root generation.
    pub fn generation(&self) -> u64 {
        self.state.generation
    }

    /// memory—v1: Return this candidate view's mutation sequence.
    pub fn sequence(&self) -> u64 {
        self.state.sequence
    }

    /// memory—v1: Return the number of retained candidate records.
    pub fn len(&self) -> usize {
        self.state.len
    }

    /// memory—v1: Report whether this candidate view contains no records.
    pub fn is_empty(&self) -> bool {
        self.state.len == 0
    }

    /// memory—v1: Borrow a retained candidate record in mutation order.
    pub fn record(&self, index: usize) -> Option<&CandidateRecord<PAYLOAD>> {
        self.state.records.get(index).and_then(Option::as_ref)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    type Model = CandidateAtomicJournal<1, 8, 2>;

    // memory—v1: Tests have a bounded contention retry budget.
    fn publish_retry(
        model: &Model,
        generation: u64,
        key: u8,
        digest: u8,
        facts: u8,
        payload: &[u8],
    ) -> Result<CandidateResult, CandidateError> {
        for _ in 0..10_000 {
            match model.try_publish(generation, [key; 16], [digest; 32], [facts], payload) {
                Err(CandidateError::Busy) => thread::yield_now(),
                outcome => return outcome,
            }
        }
        Err(CandidateError::Busy)
    }

    #[test]
    // memory—v1: Publish full payload and retain idempotency even at capacity.
    fn capacity_replay_conflict_and_exact_payload() {
        let model = Model::new([0], 40).unwrap();
        let first = model
            .try_publish(40, [1; 16], [7; 32], [1], b"one\0two")
            .unwrap();
        assert_eq!(
            first,
            CandidateResult {
                generation: 41,
                sequence: 1
            }
        );
        let second = model
            .try_publish(41, [2; 16], [8; 32], [2], b"12345678")
            .unwrap();
        assert_eq!(
            second,
            CandidateResult {
                generation: 42,
                sequence: 2
            }
        );
        assert_eq!(
            model.try_publish(0, [1; 16], [7; 32], [9], b"different".get(..8).unwrap()),
            Ok(first)
        );
        assert_eq!(
            model.try_publish(42, [1; 16], [9; 32], [9], b"x"),
            Err(CandidateError::OperationConflict)
        );
        assert_eq!(
            model.try_publish(42, [3; 16], [9; 32], [9], b"x"),
            Err(CandidateError::Full)
        );
        let view = model.try_read().unwrap();
        assert_eq!(
            (view.facts(), view.generation(), view.sequence(), view.len()),
            (&[2], 42, 2, 2)
        );
        assert_eq!(view.record(0).unwrap().payload(), b"one\0two");
        assert_eq!(view.record(1).unwrap().payload(), b"12345678");
        assert_eq!(view.record(0).unwrap().result(), first);
        assert_eq!(view.record(0).unwrap().operation(), &[1; 16]);
        assert_eq!(view.record(0).unwrap().digest(), &[7; 32]);
        assert!(view.record(2).is_none());
    }

    #[test]
    // memory—v1: Invalid and stale attempts do not leave facts, records or holes.
    fn failed_preparation_and_stale_are_inert() {
        assert!(matches!(
            CandidateAtomicJournal::<0, 8, 2>::new([], 0),
            Err(CandidateError::InvalidBounds)
        ));
        assert!(matches!(
            CandidateAtomicJournal::<1, 0, 2>::new([0], 0),
            Err(CandidateError::InvalidBounds)
        ));
        assert!(matches!(
            CandidateAtomicJournal::<1, 8, 0>::new([0], 0),
            Err(CandidateError::InvalidBounds)
        ));
        let model = Model::new([4], 10).unwrap();
        assert_eq!(
            model.try_publish(10, [0; 16], [1; 32], [5], b"x"),
            Err(CandidateError::InvalidInput)
        );
        assert_eq!(
            model.try_publish(10, [1; 16], [1; 32], [5], b""),
            Err(CandidateError::InvalidInput)
        );
        assert_eq!(
            model.try_publish(10, [1; 16], [1; 32], [5], b"123456789"),
            Err(CandidateError::InvalidInput)
        );
        assert_eq!(
            model.try_publish(9, [1; 16], [1; 32], [5], b"x"),
            Err(CandidateError::StaleGeneration)
        );
        {
            let view = model.try_read().unwrap();
            assert_eq!(
                (view.facts(), view.generation(), view.sequence(), view.len()),
                (&[4], 10, 0, 0)
            );
            assert!(view.record(0).is_none());
        }
        assert_eq!(
            model
                .try_publish(10, [1; 16], [1; 32], [5], b"x")
                .unwrap()
                .sequence,
            1
        );
    }

    #[test]
    // memory—v1: A borrowed old view stays stable and blocks new publication.
    fn old_reader_is_stable_without_retained_snapshots() {
        let model = Model::new([3], 20).unwrap();
        let old = model.try_read().unwrap();
        assert_eq!(
            model.try_publish(20, [1; 16], [1; 32], [4], b"x"),
            Err(CandidateError::Busy)
        );
        assert_eq!(
            (old.facts(), old.generation(), old.sequence(), old.len()),
            (&[3], 20, 0, 0)
        );
        drop(old);
        model.try_publish(20, [1; 16], [1; 32], [4], b"x").unwrap();
        assert_eq!(model.try_read().unwrap().facts(), &[4]);
    }

    #[test]
    // memory—v1: Competing stale generations admit exactly one complete record.
    fn concurrent_distinct_operations_have_one_winner() {
        let model = Arc::new(Model::new([0], 5).unwrap());
        let barrier = Arc::new(Barrier::new(3));
        let handles: Vec<_> = (1..=2)
            .map(|key| {
                let model = Arc::clone(&model);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    (key, publish_retry(&model, 5, key, key, key, &[key]))
                })
            })
            .collect();
        barrier.wait();
        let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(
            outcomes.iter().filter(|(_, result)| result.is_ok()).count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|(_, result)| *result == Err(CandidateError::StaleGeneration))
                .count(),
            1
        );
        let winner = outcomes
            .iter()
            .find(|(_, result)| result.is_ok())
            .unwrap()
            .0;
        let view = model.try_read().unwrap();
        assert_eq!(
            (view.facts(), view.generation(), view.sequence(), view.len()),
            (&[winner], 6, 1, 1)
        );
        let record = view.record(0).unwrap();
        assert_eq!(record.operation(), &[winner; 16]);
        assert_eq!(record.payload(), &[winner]);
        assert_eq!(
            record.result(),
            CandidateResult {
                generation: 6,
                sequence: 1
            }
        );
    }

    #[test]
    // memory—v1: Racing equal keys deduplicate; conflicting content is rejected.
    fn concurrent_replay_and_conflict() {
        let model = Arc::new(Model::new([0], 0).unwrap());
        let barrier = Arc::new(Barrier::new(4));
        let handles: Vec<_> = [4, 4, 5]
            .into_iter()
            .map(|digest| {
                let model = Arc::clone(&model);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    (
                        digest,
                        publish_retry(&model, 0, 1, digest, digest, &[digest]),
                    )
                })
            })
            .collect();
        barrier.wait();
        let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let view = model.try_read().unwrap();
        let record = view.record(0).unwrap();
        let winning_digest = record.digest()[0];
        for (digest, result) in outcomes {
            if digest == winning_digest {
                assert_eq!(
                    result,
                    Ok(CandidateResult {
                        generation: 1,
                        sequence: 1
                    })
                );
            } else {
                assert_eq!(result, Err(CandidateError::OperationConflict));
            }
        }
        assert_eq!(
            (view.facts(), view.sequence(), view.len(), record.payload()),
            (&[winning_digest], 1, 1, &[winning_digest][..])
        );
    }

    #[test]
    // memory—v1: A racing reader sees either the entire old or new state.
    fn racing_reader_never_observes_partial_publication() {
        for _ in 0..64 {
            let model = Arc::new(Model::new([0], 10).unwrap());
            let barrier = Arc::new(Barrier::new(3));
            let reader_model = Arc::clone(&model);
            let reader_barrier = Arc::clone(&barrier);
            let reader = thread::spawn(move || {
                reader_barrier.wait();
                for _ in 0..10_000 {
                    match reader_model.try_read() {
                        Ok(view) => {
                            match view.sequence() {
                                0 => {
                                    assert_eq!(
                                        (view.facts(), view.generation(), view.len()),
                                        (&[0], 10, 0)
                                    );
                                    assert!(view.record(0).is_none());
                                }
                                1 => {
                                    assert_eq!(
                                        (view.facts(), view.generation(), view.len()),
                                        (&[9], 11, 1)
                                    );
                                    let record = view.record(0).unwrap();
                                    assert_eq!(record.operation(), &[1; 16]);
                                    assert_eq!(record.payload(), b"payload");
                                    assert_eq!(
                                        record.result(),
                                        CandidateResult {
                                            generation: 11,
                                            sequence: 1
                                        }
                                    );
                                }
                                _ => panic!("unexpected sequence"),
                            }
                            return;
                        }
                        Err(CandidateError::Busy) => thread::yield_now(),
                        Err(error) => panic!("unexpected read failure: {error:?}"),
                    }
                }
                panic!("reader contention budget exhausted");
            });
            let writer_model = Arc::clone(&model);
            let writer_barrier = Arc::clone(&barrier);
            let writer = thread::spawn(move || {
                writer_barrier.wait();
                publish_retry(&writer_model, 10, 1, 1, 9, b"payload").unwrap();
            });
            barrier.wait();
            reader.join().unwrap();
            writer.join().unwrap();
            let view = model.try_read().unwrap();
            assert_eq!(
                (view.facts(), view.generation(), view.sequence(), view.len()),
                (&[9], 11, 1, 1)
            );
        }
    }

    #[test]
    // memory—v1: A poisoned lock fails closed instead of exposing its state.
    fn poisoned_candidate_is_unavailable() {
        let model = Arc::new(Model::new([0], 0).unwrap());
        let holder = Arc::clone(&model);
        assert!(thread::spawn(move || {
            let _guard = holder.state.lock().unwrap();
            panic!("poison candidate for test");
        })
        .join()
        .is_err());
        assert!(matches!(model.try_read(), Err(CandidateError::Poisoned)));
        assert_eq!(
            model.try_publish(0, [1; 16], [1; 32], [1], b"x"),
            Err(CandidateError::Poisoned)
        );
    }

    #[test]
    // memory—v1: Counter exhaustion never leaves a record or changes facts.
    fn exhausted_counters_are_inert() {
        let model = Model::new([4], u64::MAX).unwrap();
        assert_eq!(
            model.try_publish(u64::MAX, [1; 16], [1; 32], [5], b"x"),
            Err(CandidateError::Exhausted)
        );
        let view = model.try_read().unwrap();
        assert_eq!(
            (view.facts(), view.generation(), view.sequence(), view.len()),
            (&[4], u64::MAX, 0, 0)
        );
        drop(view);
        let model = Model::new([6], 7).unwrap();
        model.state.lock().unwrap().sequence = u64::MAX;
        assert_eq!(
            model.try_publish(7, [1; 16], [1; 32], [8], b"x"),
            Err(CandidateError::Exhausted)
        );
        let view = model.try_read().unwrap();
        assert_eq!(
            (view.facts(), view.generation(), view.sequence(), view.len()),
            (&[6], 7, u64::MAX, 0)
        );
    }
}
