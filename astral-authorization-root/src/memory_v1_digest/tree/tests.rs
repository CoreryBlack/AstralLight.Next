use sha2::{Digest as _, Sha256};

use super::*;
use crate::memory_v1_digest::{Table, BRANCH_DOMAIN, EMPTY_DOMAIN};

// memory—v1: Reference full-depth branches without compressed shapes or checkpoints.
fn reference(leaves: &[Leaf], depth: usize) -> ContentDigest {
    fn branch(depth: usize, left: ContentDigest, right: ContentDigest) -> ContentDigest {
        let mut hash = Sha256::new();
        hash.update(BRANCH_DOMAIN);
        hash.update((depth as u16).to_be_bytes());
        hash.update(left);
        hash.update(right);
        hash.finalize().into()
    }

    let mut empty = [[0; 32]; DEPTH + 1];
    empty[DEPTH] = Sha256::digest(EMPTY_DOMAIN).into();
    for level in (0..DEPTH).rev() {
        empty[level] = branch(level, empty[level + 1], empty[level + 1]);
    }
    fn recurse(leaves: &[Leaf], depth: usize, empty: &[ContentDigest]) -> ContentDigest {
        match (leaves.first(), depth) {
            (None, _) => empty[depth],
            (Some(leaf), DEPTH) => {
                assert_eq!(leaves.len(), 1);
                leaf.2
            }
            _ => {
                let mid = leaves.partition_point(|entry| !bit(&entry.0, depth));
                branch(
                    depth,
                    recurse(&leaves[..mid], depth + 1, empty),
                    recurse(&leaves[mid..], depth + 1, empty),
                )
            }
        }
    }
    recurse(leaves, depth, &empty)
}

fn leaf_with_bit(level: Option<usize>, id: u8) -> Leaf {
    let mut path = [0; 32];
    if let Some(level) = level {
        path[level / 8] = 0x80 >> (level % 8);
    }
    (path, Key::row(Table::User, [id; 16]), [id; 32])
}

#[test]
fn split_collapse_and_restore_match_full_depth_at_checkpoint_edges() {
    let levels = [255, 248, 241, 240, 239, 129, 128, 127, 17, 16, 15, 7, 0];
    let first = leaf_with_bit(None, 1);
    let old = build(std::slice::from_ref(&first), 0);
    let old_hash = root_hash(&old);
    let mut tree = old.clone();
    let mut expected = vec![first];
    for (i, level) in levels.into_iter().enumerate() {
        let leaf = leaf_with_bit(Some(level), 2 + i as u8);
        tree = add(&tree, std::slice::from_ref(&leaf)).unwrap();
        expected.push(leaf);
        assert_eq!(
            root_hash(&tree),
            reference(&expected, 0),
            "split at {level}"
        );
    }
    // Conflicts and rewrites are evaluated against the exact immutable leaf.
    let (path, key, hash) = &expected[1];
    let collision = Key::row(Table::Tenant, [42; 16]);
    assert!(matches!(
        update(&tree, path, &collision, Some(*hash)),
        Err(DigestError::PathCollision)
    ));
    assert!(matches!(
        add(&tree, &[(*path, collision, *hash)]),
        Err(DigestError::PathCollision)
    ));
    let changed = update(&tree, path, key, Some([99; 32])).unwrap();
    let restored = update(&changed, path, key, Some(*hash)).unwrap();
    assert_eq!(root_hash(&restored), root_hash(&tree));
    for level in levels.into_iter().rev() {
        let (path, key, _) = expected.pop().unwrap();
        tree = update(&tree, &path, &key, None).unwrap();
        assert_eq!(
            root_hash(&tree),
            reference(&expected, 0),
            "collapse at {level}"
        );
    }
    assert_eq!(root_hash(&tree), old_hash);
    assert_eq!(root_hash(&old), old_hash);
}

#[test]
fn sorted_batch_splits_both_sides_without_replacing_existing_leaves() {
    let leaves = [
        leaf_with_bit(None, 1),
        leaf_with_bit(Some(255), 2),
        leaf_with_bit(Some(65), 3),
        leaf_with_bit(Some(0), 4),
    ];
    let before = build(&leaves[1..2], 0);
    let batch = vec![leaves[0].clone(), leaves[2].clone(), leaves[3].clone()];
    let after = add(&before, &batch).unwrap();
    assert_eq!(root_hash(&after), reference(&leaves, 0));
    assert_eq!(root_hash(&before), reference(&leaves[1..2], 0));
}
