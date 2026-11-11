use super::*;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Barrier};
use std::thread;
use std::time::Duration;

fn owner() -> AtomicStateOwner {
    AtomicStateOwner::new(
        vec![Some(vec![0]), Some(vec![9])],
        [0; 32],
        Limits {
            max_slots: 2,
            max_value_bytes: 8,
            max_capture_slots: 3,
            max_change_slots: 2,
        },
    )
    .unwrap()
}

fn update(owner: &mut AtomicStateOwner, value: u8) -> Metadata {
    owner
        .transact(&[0], |capture| {
            assert_eq!(capture.entries().next().unwrap().0, 0);
            Ok::<_, ()>(Change {
                slots: vec![SlotChange {
                    slot: 0,
                    value: Some(vec![value]),
                }],
                digest: [value; 32],
            })
        })
        .unwrap()
}

#[test]
fn capture_is_coherent_and_aba_never_reuses_version() {
    let mut state = owner();
    let handle = state.handle();
    let initial = handle.capture(&[0, 1, 0]).unwrap();
    assert_eq!(
        initial.entries().collect::<Vec<_>>(),
        vec![
            (0, Some(&[0][..])),
            (1, Some(&[9][..])),
            (0, Some(&[0][..]))
        ]
    );
    assert_eq!(update(&mut state, 1).version, 1);
    assert_eq!(update(&mut state, 0).version, 2);
    let again = handle.capture(&[0]).unwrap();
    assert_eq!(again.entries().next().unwrap().1, Some(&[0][..]));
    assert_eq!(again.metadata().digest, initial.metadata().digest);
    assert!(!handle.is_current(&initial).unwrap());
    assert!(handle.is_current(&again).unwrap());
    let other = owner();
    assert!(!other.handle().is_current(&initial).unwrap());
    drop(state);
    assert!(matches!(
        handle.capture(&[1]),
        Err(StateError::OwnerDropped)
    ));
    assert_eq!(handle.is_current(&again), Err(StateError::OwnerDropped));
    assert_eq!(again.entries().next().unwrap().1, Some(&[0][..]));
}

#[test]
fn failed_or_panicking_preparation_and_invalid_changes_leave_state_unchanged() {
    let mut state = owner();
    let handle = state.handle();
    let before = handle.capture(&[0, 1]).unwrap();
    let result = state.transact(&[0], |_| Err::<Change, _>("rejected"));
    assert_eq!(result, Err(TransactionError::Prepare("rejected")));
    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = state.transact::<()>(&[0], |_| panic!("preparation failed"));
    }));
    assert!(panic.is_err());
    assert_eq!(
        state.transact(&[], |_| Ok::<_, ()>(Change {
            slots: vec![SlotChange {
                slot: 2,
                value: None
            }],
            digest: [1; 32]
        })),
        Err(TransactionError::State(StateError::InvalidSlot))
    );
    assert_eq!(
        state.transact(&[], |_| Ok::<_, ()>(Change {
            slots: vec![SlotChange {
                slot: 0,
                value: Some(vec![1; 9])
            }],
            digest: [1; 32]
        })),
        Err(TransactionError::State(StateError::ValueTooLarge))
    );
    assert_eq!(
        state.transact::<()>(&[2], |_| panic!("must not run")),
        Err(TransactionError::State(StateError::InvalidSlot))
    );
    let after = handle.capture(&[0, 1]).unwrap();
    assert_eq!(before.metadata(), after.metadata());
    assert_eq!(
        before.entries().collect::<Vec<_>>(),
        after.entries().collect::<Vec<_>>()
    );
    assert!(handle.is_current(&before).unwrap());
    assert_eq!(update(&mut state, 1).version, 1);
}

#[test]
fn version_exhaustion_does_not_mutate_facts_or_metadata() {
    let mut state = owner();
    {
        let mut inner = state.shared.state.lock().unwrap();
        inner.metadata.version = u64::MAX;
    }
    let handle = state.handle();
    let before = handle.capture(&[0]).unwrap();
    assert_eq!(
        state.transact(&[], |_| Ok::<_, ()>(Change {
            slots: vec![SlotChange {
                slot: 0,
                value: None
            }],
            digest: [7; 32]
        })),
        Err(TransactionError::State(StateError::VersionExhausted))
    );
    assert!(matches!(
        handle.capture(&[0]),
        Err(StateError::OwnerDropped)
    ));
    assert_eq!(handle.is_current(&before), Err(StateError::OwnerDropped));
    assert_eq!(before.entries().next().unwrap().1, Some(&[0][..]));
}

#[test]
fn preparation_does_not_hold_reader_lock() {
    let mut state = owner();
    let handle = state.handle();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (continue_tx, continue_rx) = mpsc::channel();
    let writer = thread::spawn(move || {
        state
            .transact(&[0], |_| {
                entered_tx.send(()).unwrap();
                continue_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                Ok::<_, ()>(Change {
                    slots: vec![SlotChange {
                        slot: 0,
                        value: Some(vec![1]),
                    }],
                    digest: [1; 32],
                })
            })
            .unwrap();
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let (read_tx, read_rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        read_tx
            .send(handle.capture(&[0]).unwrap().metadata())
            .unwrap()
    });
    let read = read_rx.recv_timeout(Duration::from_secs(5));
    continue_tx.send(()).unwrap();
    writer.join().unwrap();
    reader.join().unwrap();
    assert_eq!(read.unwrap().version, 0);
}

#[test]
fn concurrent_captures_never_observe_partial_commit() {
    const WRITES: u64 = 4_000;
    let mut state = owner();
    let handle = state.handle();
    let done = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(5));
    let mut readers = Vec::new();
    for _ in 0..4 {
        let handle = handle.clone();
        let done = Arc::clone(&done);
        let barrier = Arc::clone(&barrier);
        readers.push(thread::spawn(move || {
            barrier.wait();
            loop {
                let capture = handle.capture(&[0, 1]).unwrap();
                let entries = capture.entries().collect::<Vec<_>>();
                let value = entries[0].1.unwrap()[0];
                assert_eq!(entries[1].1.unwrap()[0], value ^ 9);
                assert_eq!(value, (capture.metadata().version % 2) as u8);
                assert_eq!(capture.metadata().digest, [value; 32]);
                if done.load(Ordering::Acquire) {
                    break;
                }
            }
        }));
    }
    barrier.wait();
    for version in 1..=WRITES {
        let value = (version % 2) as u8;
        let metadata = state
            .transact(&[0, 1], |_| {
                Ok::<_, ()>(Change {
                    slots: vec![
                        SlotChange {
                            slot: 0,
                            value: Some(vec![value]),
                        },
                        SlotChange {
                            slot: 1,
                            value: Some(vec![value ^ 9]),
                        },
                    ],
                    digest: [value; 32],
                })
            })
            .unwrap();
        assert_eq!(metadata.version, version);
    }
    done.store(true, Ordering::Release);
    for reader in readers {
        reader.join().unwrap();
    }
    assert_eq!(handle.capture(&[0]).unwrap().metadata().version, WRITES);
}

#[test]
fn invalid_batch_never_commits_a_valid_prefix() {
    let mut state = owner();
    let handle = state.handle();
    let before = handle.capture(&[0, 1]).unwrap();
    let batches = [
        (
            vec![
                SlotChange {
                    slot: 0,
                    value: Some(vec![3]),
                },
                SlotChange {
                    slot: 1,
                    value: Some(vec![4; 9]),
                },
            ],
            StateError::ValueTooLarge,
        ),
        (
            vec![
                SlotChange {
                    slot: 0,
                    value: Some(vec![3]),
                },
                SlotChange {
                    slot: 2,
                    value: None,
                },
            ],
            StateError::InvalidSlot,
        ),
        (
            vec![
                SlotChange {
                    slot: 0,
                    value: Some(vec![3]),
                },
                SlotChange {
                    slot: 0,
                    value: None,
                },
            ],
            StateError::DuplicateSlot,
        ),
        (
            vec![
                SlotChange {
                    slot: 0,
                    value: None,
                },
                SlotChange {
                    slot: 1,
                    value: None,
                },
                SlotChange {
                    slot: 0,
                    value: None,
                },
            ],
            StateError::TooManyChangeSlots,
        ),
        (vec![], StateError::EmptyChange),
    ];
    for (slots, expected) in batches {
        assert_eq!(
            state.transact(&[0, 1], |_| Ok::<_, ()>(Change {
                slots,
                digest: [3; 32]
            })),
            Err(TransactionError::State(expected))
        );
        let after = handle.capture(&[0, 1]).unwrap();
        assert_eq!(after.metadata(), before.metadata());
        assert_eq!(
            after.entries().collect::<Vec<_>>(),
            before.entries().collect::<Vec<_>>()
        );
        assert!(handle.is_current(&before).unwrap());
    }
}

#[test]
fn owner_drop_closes_clones_and_foreign_current_checks() {
    let state = owner();
    let first = state.handle();
    let second = first.clone();
    let captured = first.capture(&[0]).unwrap();
    let other = owner();
    let foreign = other.handle().capture(&[0]).unwrap();
    drop(state);
    assert!(matches!(first.capture(&[]), Err(StateError::OwnerDropped)));
    assert!(matches!(
        second.capture(&[0]),
        Err(StateError::OwnerDropped)
    ));
    assert_eq!(second.is_current(&captured), Err(StateError::OwnerDropped));
    assert_eq!(first.is_current(&foreign), Err(StateError::OwnerDropped));
    assert_eq!(captured.entries().next().unwrap().1, Some(&[0][..]));
    assert!(other.handle().is_current(&foreign).unwrap());
}

#[test]
fn limits_and_clearing_are_enforced() {
    let mut state = owner();
    let handle = state.handle();
    assert!(matches!(
        handle.capture(&[0, 0, 0, 0]),
        Err(StateError::TooManyCaptureSlots)
    ));
    assert!(matches!(handle.capture(&[2]), Err(StateError::InvalidSlot)));
    state
        .transact(&[], |_| {
            Ok::<_, ()>(Change {
                slots: vec![SlotChange {
                    slot: 1,
                    value: None,
                }],
                digest: [8; 32],
            })
        })
        .unwrap();
    let capture = handle.capture(&[1]).unwrap();
    assert_eq!(capture.entries().next().unwrap().1, None);
    assert_eq!(
        capture.metadata(),
        Metadata {
            version: 1,
            digest: [8; 32]
        }
    );
    assert!(matches!(
        AtomicStateOwner::new(
            vec![Some(vec![0; 9])],
            [0; 32],
            Limits {
                max_slots: 1,
                max_value_bytes: 8,
                max_capture_slots: 1,
                max_change_slots: 1
            }
        ),
        Err(StateError::ValueTooLarge)
    ));
}
