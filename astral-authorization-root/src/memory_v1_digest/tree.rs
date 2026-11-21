//! memory—v1: Path-compressed storage of the same full-depth SHA-256 tree.
//!
//! A node represents a unary path followed by either a fork or a leaf. The
//! missing siblings still contribute the depth-specific empty hashes. Sparse
//! checkpoints on the unary path bound the hashing needed to split it without
//! copying its terminal or traversing an unchanged subtree.

use std::sync::Arc;

use super::{bit, empties, hash_branch, ContentDigest, DigestError, Key, DEPTH};

const CHECKPOINT_INTERVAL: usize = 16;

pub(super) type Tree = Option<Arc<Node>>;
pub(super) type Leaf = (ContentDigest, Key, ContentDigest);

pub(super) struct Node {
    hash: ContentDigest,
    // Ordered from the terminal toward the root, aligned to the terminal's depth.
    checkpoints: Option<Arc<[ContentDigest]>>,
    terminal: Arc<Terminal>,
}

struct Terminal {
    path: ContentDigest,
    depth: usize,
    hash: ContentDigest,
    kind: Kind,
}

enum Kind {
    Leaf(Key),
    Fork { left: Arc<Node>, right: Arc<Node> },
}

impl Node {
    fn leaf(depth: usize, path: ContentDigest, key: Key, hash: ContentDigest) -> Arc<Self> {
        Self::attach(
            depth,
            Arc::new(Terminal {
                path,
                depth: DEPTH,
                hash,
                kind: Kind::Leaf(key),
            }),
        )
    }

    fn fork(depth: usize, split: usize, left: Arc<Self>, right: Arc<Self>) -> Arc<Self> {
        Self::attach(
            depth,
            Arc::new(Terminal {
                path: left.terminal.path,
                depth: split,
                hash: hash_branch(split, left.hash, right.hash),
                kind: Kind::Fork { left, right },
            }),
        )
    }

    fn attach(depth: usize, terminal: Arc<Terminal>) -> Arc<Self> {
        let mut checkpoints = Vec::with_capacity((terminal.depth - depth) / CHECKPOINT_INTERVAL);
        let hash = terminal.fold(depth, terminal.depth, terminal.hash, |hash| {
            checkpoints.push(hash);
        });
        Arc::new(Self {
            hash,
            checkpoints: (!checkpoints.is_empty()).then(|| checkpoints.into()),
            terminal,
        })
    }

    // memory—v1: Re-root an immutable unary path after a fork splits or collapses.
    // Reuse only checkpoints of the exact same terminal and representative path.
    fn at_depth(&self, depth: usize) -> Arc<Self> {
        let terminal = &self.terminal;
        let checkpoints = self.checkpoints.as_deref().unwrap_or_default();
        let wanted = (terminal.depth - depth) / CHECKPOINT_INTERVAL;
        let held = checkpoints.len().min(wanted);
        let start = terminal.depth - held * CHECKPOINT_INTERVAL;
        let hash = if held == 0 {
            terminal.hash
        } else {
            checkpoints[held - 1]
        };
        let (hash, checkpoints) = if wanted > held {
            let mut extended = Vec::with_capacity(wanted);
            extended.extend_from_slice(checkpoints);
            let hash = terminal.fold(depth, start, hash, |hash| extended.push(hash));
            (hash, Some(extended.into()))
        } else {
            (
                terminal.fold(depth, start, hash, |_| {}),
                self.checkpoints.clone(),
            )
        };
        Arc::new(Self {
            hash,
            checkpoints,
            terminal: terminal.clone(),
        })
    }

    #[cfg(test)]
    pub(super) fn root_children(&self) -> (&Arc<Self>, &Arc<Self>) {
        assert_eq!(self.terminal.depth, 0);
        match &self.terminal.kind {
            Kind::Fork { left, right } => (left, right),
            Kind::Leaf(_) => unreachable!(),
        }
    }
}

impl Terminal {
    // memory—v1: Fold as many real SHA-256 branches as the sparse tree defines.
    fn fold(
        &self,
        depth: usize,
        start: usize,
        mut hash: ContentDigest,
        mut save: impl FnMut(ContentDigest),
    ) -> ContentDigest {
        let empty = empties();
        for level in (depth..start).rev() {
            let sibling = empty[level + 1];
            hash = if bit(&self.path, level) {
                hash_branch(level, sibling, hash)
            } else {
                hash_branch(level, hash, sibling)
            };
            if (self.depth - level).is_multiple_of(CHECKPOINT_INTERVAL) {
                save(hash);
            }
        }
        hash
    }
}

pub(super) fn root_hash(tree: &Tree) -> ContentDigest {
    tree.as_ref().map_or_else(|| empties()[0], |node| node.hash)
}

// memory—v1: Find the first non-shared bit. A sorted range shares every bit
// common to its endpoints; the third path optionally represents an old subtree.
fn common_depth(
    first: &ContentDigest,
    last: &ContentDigest,
    other: &ContentDigest,
    depth: usize,
) -> usize {
    for byte in depth / 8..first.len() {
        let different = (first[byte] ^ last[byte]) | (first[byte] ^ other[byte]);
        if different != 0 {
            let split = byte * 8 + different.leading_zeros() as usize;
            debug_assert!(split >= depth, "paths share their caller's prefix");
            return split;
        }
    }
    DEPTH
}

// memory—v1: Paths are sorted and distinct before construction.
pub(super) fn build(leaves: &[Leaf], depth: usize) -> Tree {
    let first = leaves.first()?;
    if leaves.len() == 1 {
        return Some(Node::leaf(depth, first.0, first.1.clone(), first.2));
    }
    let split = common_depth(&first.0, &leaves.last().unwrap().0, &first.0, depth);
    let mid = leaves.partition_point(|entry| !bit(&entry.0, split));
    Some(Node::fork(
        depth,
        split,
        build(&leaves[..mid], split + 1).expect("split has a left path"),
        build(&leaves[mid..], split + 1).expect("split has a right path"),
    ))
}

// memory—v1: At most one scoped helper, and only for two substantial root arms.
fn parallel_split(leaves: &[Leaf]) -> Option<usize> {
    const MIN_ARM: usize = 64;
    if leaves.len() < 2 * MIN_ARM {
        return None;
    }
    let mid = leaves.partition_point(|entry| !bit(&entry.0, 0));
    (mid.min(leaves.len() - mid) >= MIN_ARM
        && std::thread::available_parallelism().is_ok_and(|n| n.get() >= 2))
    .then_some(mid)
}

// memory—v1: Cold construction and additions use the same left/right ordering and
// join discipline. A failed spawn falls back to the caller, not to a partial tree.
fn joined_halves<T: Send>(
    left: impl FnOnce() -> T + Send + Copy,
    right: impl FnOnce() -> T,
) -> (T, T) {
    std::thread::scope(|scope| {
        match std::thread::Builder::new()
            .name("digest-half".into())
            .spawn_scoped(scope, left)
        {
            Ok(worker) => {
                let right = right();
                (
                    worker
                        .join()
                        .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
                    right,
                )
            }
            Err(_) => (left(), right()),
        }
    })
}

// memory—v1: Split only at the root. All recursive calls use the serial builder.
pub(super) fn build_root(leaves: &[Leaf]) -> Tree {
    let Some(mid) = parallel_split(leaves) else {
        return build(leaves, 0);
    };
    let (left, right) = joined_halves(|| build(&leaves[..mid], 1), || build(&leaves[mid..], 1));
    Some(Node::fork(
        0,
        0,
        left.expect("nonempty left arm"),
        right.expect("nonempty right arm"),
    ))
}
fn add_root_halves(
    left: &Arc<Node>,
    right: &Arc<Node>,
    a: &[Leaf],
    b: &[Leaf],
) -> Result<Tree, DigestError> {
    let (left, right) = joined_halves(|| add_at(Some(left), a, 1), || add_at(Some(right), b, 1));
    Ok(Some(Node::fork(
        0,
        0,
        left?.expect("existing left arm"),
        right?.expect("existing right arm"),
    )))
}

// memory—v1: Reuse untouched branches and reject a path already in the tree.
pub(super) fn add(tree: &Tree, leaves: &[Leaf]) -> Result<Tree, DigestError> {
    if let Some(node) = tree.as_ref().filter(|n| n.terminal.depth == 0) {
        if let (Kind::Fork { left, right }, Some(mid)) =
            (&node.terminal.kind, parallel_split(leaves))
        {
            return add_root_halves(left, right, &leaves[..mid], &leaves[mid..]);
        }
    }
    add_at(tree.as_ref(), leaves, 0)
}

fn add_at(old: Option<&Arc<Node>>, leaves: &[Leaf], depth: usize) -> Result<Tree, DigestError> {
    let Some(first) = leaves.first() else {
        return Ok(old.cloned());
    };
    let Some(old) = old else {
        return Ok(build(leaves, depth));
    };
    let terminal = &old.terminal;
    let split = common_depth(&first.0, &leaves.last().unwrap().0, &terminal.path, depth)
        .min(terminal.depth);
    if split == DEPTH {
        return Err(DigestError::PathCollision);
    }
    let mid = leaves.partition_point(|entry| !bit(&entry.0, split));
    let (left, right) = if split == terminal.depth {
        let Kind::Fork { left, right } = &terminal.kind else {
            unreachable!("only leaves are at full depth");
        };
        (
            add_at(Some(left), &leaves[..mid], split + 1)?,
            add_at(Some(right), &leaves[mid..], split + 1)?,
        )
    } else {
        let retained = old.at_depth(split + 1);
        if bit(&terminal.path, split) {
            (
                build(&leaves[..mid], split + 1),
                add_at(Some(&retained), &leaves[mid..], split + 1)?,
            )
        } else {
            (
                add_at(Some(&retained), &leaves[..mid], split + 1)?,
                build(&leaves[mid..], split + 1),
            )
        }
    };
    Ok(Some(Node::fork(
        depth,
        split,
        left.expect("left branch is nonempty"),
        right.expect("right branch is nonempty"),
    )))
}

// memory—v1: Copy a single changed path, with exact-key collision checks.
pub(super) fn update(
    tree: &Tree,
    path: &ContentDigest,
    key: &Key,
    hash: Option<ContentDigest>,
) -> Result<Tree, DigestError> {
    update_at(tree.as_ref(), 0, path, key, hash)
}

fn update_at(
    old: Option<&Arc<Node>>,
    depth: usize,
    path: &ContentDigest,
    key: &Key,
    hash: Option<ContentDigest>,
) -> Result<Tree, DigestError> {
    let leaf = |start| hash.map(|hash| Node::leaf(start, *path, key.clone(), hash));
    let Some(old) = old else {
        return Ok(leaf(depth));
    };
    let terminal = &old.terminal;
    let split = common_depth(path, path, &terminal.path, depth);
    if split < terminal.depth {
        let Some(added) = leaf(split + 1) else {
            return Ok(Some(old.clone()));
        };
        let retained = old.at_depth(split + 1);
        let (left, right) = if bit(path, split) {
            (retained, added)
        } else {
            (added, retained)
        };
        return Ok(Some(Node::fork(depth, split, left, right)));
    }
    match &terminal.kind {
        Kind::Leaf(existing_key) => {
            if existing_key != key {
                return Err(DigestError::PathCollision);
            }
            Ok(leaf(depth))
        }
        Kind::Fork { left, right } => {
            let split = terminal.depth;
            let next = if bit(path, split) {
                match update_at(Some(right), split + 1, path, key, hash)? {
                    Some(updated) => Node::fork(depth, split, left.clone(), updated),
                    None => left.at_depth(depth),
                }
            } else {
                match update_at(Some(left), split + 1, path, key, hash)? {
                    Some(updated) => Node::fork(depth, split, updated, right.clone()),
                    None => right.at_depth(depth),
                }
            };
            Ok(Some(next))
        }
    }
}

#[cfg(test)]
mod tests;
