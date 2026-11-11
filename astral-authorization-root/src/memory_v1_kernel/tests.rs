use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

// memory—v1: Use small, explicit bounds for the experimental kernel tests.
fn limits() -> Limits {
    Limits {
        max_slots: 8,
        max_value_bytes: 8,
        max_capture_slots: 8,
        max_change_slots: 4,
    }
}

// memory—v1: Create an owned slot replacement for a batch.
fn change(slot: usize, value: Option<&[u8]>) -> MemoryRootChange {
    MemoryRootChange {
        slot,
        value: value.map(<[u8]>::to_vec),
    }
}

// memory—v1: Rebuild the tree from all current values as the incremental oracle.
fn rebuilt_digest(values: &[Option<Vec<u8>>]) -> Digest {
    HashTree::new(values).unwrap().digest()
}

#[test]
// memory—v1: Compare incremental paths with full rebuilds across ordering and ABA.
fn incremental_hash_matches_full_rebuild() {
    for slot_count in 1..=8 {
        let mut values = vec![None; slot_count];
        let mut owner = MemoryRootOwner::new(values.clone(), limits()).unwrap();
        let handle = owner.handle();
        let initial = handle.capture(&[]).unwrap();
        assert_eq!(initial.metadata().digest, rebuilt_digest(&values));

        for slot in (0..slot_count).rev() {
            let value = vec![slot as u8, 0, 255];
            let metadata = owner.apply(vec![change(slot, Some(&value))]).unwrap();
            values[slot] = Some(value);
            assert_eq!(metadata.digest, rebuilt_digest(&values));
        }
        for slot in 0..slot_count {
            let metadata = owner.apply(vec![change(slot, Some(&[]))]).unwrap();
            values[slot] = Some(Vec::new());
            assert_eq!(metadata.digest, rebuilt_digest(&values));
            let metadata = owner.apply(vec![change(slot, None)]).unwrap();
            values[slot] = None;
            assert_eq!(metadata.digest, rebuilt_digest(&values));
        }
        let restored = handle.capture(&[]).unwrap();
        assert_eq!(restored.metadata().digest, initial.metadata().digest);
        assert!(restored.metadata().version > initial.metadata().version);
        assert!(!handle.is_current(&initial).unwrap());
    }

    let mut forward = MemoryRootOwner::new(vec![None; 3], limits()).unwrap();
    let mut reverse = MemoryRootOwner::new(vec![None; 3], limits()).unwrap();
    let first = forward
        .apply(vec![change(0, Some(b"a")), change(2, Some(b"b"))])
        .unwrap();
    let second = reverse
        .apply(vec![change(2, Some(b"b")), change(0, Some(b"a"))])
        .unwrap();
    let expected = vec![Some(b"a".to_vec()), None, Some(b"b".to_vec())];
    assert_eq!(first.digest, rebuilt_digest(&expected));
    assert_eq!(first.digest, second.digest);

    let none = rebuilt_digest(&[None]);
    let empty = rebuilt_digest(&[Some(Vec::new())]);
    assert_ne!(none, empty);
    assert_ne!(rebuilt_digest(&[]), none);
    assert_ne!(
        rebuilt_digest(&[Some(b"x".to_vec()), None]),
        rebuilt_digest(&[None, Some(b"x".to_vec())])
    );
}

#[test]
// memory—v1: Verify readers see matching slot bytes, version and internal digest.
fn concurrent_captures_observe_complete_batches() {
    const WRITES: u64 = 1_000;
    const READERS: usize = 4;
    let initial = vec![Some(vec![0]), Some(vec![9]), None];
    let mut owner = MemoryRootOwner::new(initial, limits()).unwrap();
    let handle = owner.handle();
    let done = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(Barrier::new(READERS + 1));
    let mut readers = Vec::new();
    for _ in 0..READERS {
        let handle = handle.clone();
        let done = Arc::clone(&done);
        let ready = Arc::clone(&ready);
        readers.push(thread::spawn(move || {
            ready.wait();
            loop {
                let capture = handle.capture(&[0, 1, 2]).unwrap();
                let entries = capture.entries().collect::<Vec<_>>();
                let value = (capture.metadata().version % 2) as u8;
                assert_eq!(entries[0].1, Some(&[value][..]));
                assert_eq!(entries[1].1, Some(&[value ^ 9][..]));
                let expected_third = if value == 0 { None } else { Some(&[][..]) };
                assert_eq!(entries[2].1, expected_third);
                let values = entries
                    .iter()
                    .map(|(_, bytes)| bytes.map(<[u8]>::to_vec))
                    .collect::<Vec<_>>();
                assert_eq!(capture.metadata().digest, rebuilt_digest(&values));
                if done.load(Ordering::Acquire) {
                    break;
                }
            }
        }));
    }
    ready.wait();
    for version in 1..=WRITES {
        let value = (version % 2) as u8;
        let third = if value == 0 { None } else { Some(&[][..]) };
        let metadata = owner
            .apply(vec![
                change(0, Some(&[value])),
                change(1, Some(&[value ^ 9])),
                change(2, third),
            ])
            .unwrap();
        assert_eq!(metadata.version, version);
    }
    done.store(true, Ordering::Release);
    for reader in readers {
        reader.join().unwrap();
    }
    assert_eq!(handle.capture(&[]).unwrap().metadata().version, WRITES);
}

#[test]
// memory—v1: Force readers to observe each complete commit before the next one.
fn readers_observe_every_coordinated_commit() {
    let mut owner = MemoryRootOwner::new(vec![Some(vec![0]), Some(vec![0])], limits()).unwrap();
    let handle = owner.handle();
    let (committed, receives_commit) = std::sync::mpsc::sync_channel(0);
    let (acknowledges, received_ack) = std::sync::mpsc::sync_channel(0);
    let writer = thread::spawn(move || {
        for value in 1..=32_u8 {
            owner
                .apply(vec![change(0, Some(&[value])), change(1, Some(&[value]))])
                .unwrap();
            committed.send(value).unwrap();
            received_ack.recv().unwrap();
        }
        owner
    });
    for expected in 1..=32_u8 {
        assert_eq!(receives_commit.recv().unwrap(), expected);
        let capture = handle.capture(&[0, 1]).unwrap();
        assert_eq!(capture.metadata().version, u64::from(expected));
        for (_, value) in capture.entries() {
            assert_eq!(value, Some(&[expected][..]));
        }
        acknowledges.send(()).unwrap();
    }
    let owner = writer.join().unwrap();
    assert_eq!(owner.handle().capture(&[]).unwrap().metadata().version, 32);
}

#[test]
// memory—v1: Reject invalid batches without changing facts, digest or version.
fn invalid_batches_leave_state_and_hash_tree_unchanged() {
    let initial = vec![Some(b"a".to_vec()), Some(b"b".to_vec()), None];
    let mut owner = MemoryRootOwner::new(initial.clone(), limits()).unwrap();
    let handle = owner.handle();
    let before = handle.capture(&[0, 1, 2]).unwrap();
    let batches = [
        (vec![], StateError::EmptyChange),
        (
            vec![change(0, Some(b"changed")), change(3, None)],
            StateError::InvalidSlot,
        ),
        (
            vec![change(0, Some(b"changed")), change(0, None)],
            StateError::DuplicateSlot,
        ),
        (
            vec![change(0, Some(b"changed")), change(1, Some(&[0; 9]))],
            StateError::ValueTooLarge,
        ),
        (
            vec![
                change(0, None),
                change(1, None),
                change(2, None),
                change(0, None),
                change(1, None),
            ],
            StateError::TooManyChangeSlots,
        ),
    ];
    for (batch, error) in batches {
        assert_eq!(owner.apply(batch), Err(error));
        let after = handle.capture(&[0, 1, 2]).unwrap();
        assert_eq!(after.metadata(), before.metadata());
        assert_eq!(
            after.entries().collect::<Vec<_>>(),
            before.entries().collect::<Vec<_>>()
        );
        assert!(handle.is_current(&before).unwrap());
    }
    let metadata = owner.apply(vec![change(2, Some(b"ok"))]).unwrap();
    let mut expected = initial;
    expected[2] = Some(b"ok".to_vec());
    assert_eq!(metadata.version, before.metadata().version + 1);
    assert_eq!(metadata.digest, rebuilt_digest(&expected));
}

#[test]
// memory—v1: Enforce owner identity and invalidate all handles when the owner exits.
fn captures_are_owner_bound_and_handles_close_on_drop() {
    let owner = MemoryRootOwner::new(vec![Some(b"a".to_vec())], limits()).unwrap();
    let first = owner.handle();
    let clone = first.clone();
    let captured = first.capture(&[0]).unwrap();
    let other = MemoryRootOwner::new(vec![Some(b"a".to_vec())], limits()).unwrap();
    let foreign = other.handle().capture(&[0]).unwrap();
    assert_eq!(captured.metadata(), foreign.metadata());
    assert!(!first.is_current(&foreign).unwrap());
    assert!(!other.handle().is_current(&captured).unwrap());
    drop(owner);
    assert!(matches!(first.capture(&[]), Err(StateError::OwnerDropped)));
    assert!(matches!(clone.capture(&[0]), Err(StateError::OwnerDropped)));
    assert_eq!(first.is_current(&captured), Err(StateError::OwnerDropped));
    assert_eq!(clone.is_current(&foreign), Err(StateError::OwnerDropped));
    assert_eq!(captured.entries().next().unwrap().1, Some(&b"a"[..]));
    assert!(other.handle().is_current(&foreign).unwrap());
}
