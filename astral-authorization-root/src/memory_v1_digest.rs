//! Experimental, process-local memory—v1 content digest candidate.
//!
//! This SHA-256 tree is not the database rule-set hash, a persistence format,
//! a completeness or provenance proof, or authorization evidence. It covers
//! exactly the caller-supplied keys, fields, and explicit current selections.
//! Callers must define and consistently supply every relevant field and NULL;
//! omitted rows or fields are not detected. No database, source, relationship,
//! currentness, or trust validation is performed here.
//!
//! Preparing a batch creates a separate persistent snapshot; it does not publish
//! it. A shared-root owner must atomically publish the matching facts, digest,
//! instance and monotonic version, with its own concurrency fence. Equal content
//! deliberately has equal hashes, including after ABA, so the hash alone is not
//! a freshness token. Fixed per-snapshot and per-batch limits bound this index,
//! but retained snapshots and already allocated input need caller-owned budgets.
//!
//! Keys are table tag + exact 16-byte ID + (for versions) length-framed version
//! bytes. A distinct tag represents the caller's explicit current selection.
//! SHA-256 of the framed key determines a 256-bit sparse binary trie path; an
//! actual path collision between distinct keys is rejected. Leaves include the
//! full key and a count-and-length-framed sequence of nullable byte fields.
//! Empty nodes, paths, leaves and branches use distinct domains. Branches include
//! their depth; left and right order is fixed. All lengths are big-endian u64.
//! Nodes and the `im` row index are persistent, so a change copies only its trie
//! path and affected map nodes. This is an experiment, not a stable protocol.

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};

use im::OrdMap;
use sha2::{Digest as _, Sha256};

const PATH_DOMAIN: &[u8] = b"astrallight/memory-v1/digest-candidate/path/1\0";
const LEAF_DOMAIN: &[u8] = b"astrallight/memory-v1/digest-candidate/leaf/1\0";
const BRANCH_DOMAIN: &[u8] = b"astrallight/memory-v1/digest-candidate/branch/1\0";
const EMPTY_DOMAIN: &[u8] = b"astrallight/memory-v1/digest-candidate/empty/1\0";
const DEPTH: usize = 256;
// Experimental resource ceilings, not database or business limits.
const MAX_VERSION_BYTES: usize = 255;
const MAX_FIELD_BYTES: usize = 16 * 1024 * 1024;
const MAX_FIELDS: usize = 32;
const MAX_ROW_BYTES: usize = 16 * 1024 * 1024;
const MAX_BATCH: usize = 128;
const MAX_ROWS: usize = 4096;
const MAX_TOTAL_BYTES: usize = 128 * 1024 * 1024;

/// This candidate digest, not a database rule-set hash or authorization proof.
pub type ContentDigest = [u8; 32];
/// One explicitly supplied row: `None` is NULL and `Some(vec![])` is empty.
pub type Fields = Vec<Option<Vec<u8>>>;

/// The nine candidate tables. Tags are local to this experiment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Table {
    /// `memory_user`.
    User = 1,
    /// `memory_identity_card`.
    IdentityCard = 2,
    /// `memory_tenant`.
    Tenant = 3,
    /// `memory_user_card`.
    UserCard = 4,
    /// `memory_rule_set`.
    RuleSet = 5,
    /// `memory_card_rule_set_binding`.
    Binding = 7,
    /// `memory_binding_confirmation`.
    BindingConfirmation = 8,
    /// `memory_rule_set_change_confirmation`.
    RuleSetChangeConfirmation = 9,
}

/// Exact candidate identity. Version and selection keys have dedicated constructors.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    tag: u8,
    id: [u8; 16],
    version: Option<Vec<u8>>,
}

impl Key {
    /// memory—v1: Identify a row from one of the eight single-ID tables.
    pub fn row(table: Table, id: [u8; 16]) -> Self {
        Self {
            tag: table as u8,
            id,
            version: None,
        }
    }

    /// memory—v1: Identify a version by its exact composite key, including empty bytes.
    pub fn rule_set_version(rule_set_id: [u8; 16], version: Vec<u8>) -> Self {
        Self {
            tag: 6,
            id: rule_set_id,
            version: Some(version),
        }
    }

    /// memory—v1: Identify the caller's explicit current selection for a rule set.
    ///
    /// A missing key means no selection; a present key containing empty bytes
    /// means that the empty version was selected, whether or not its row exists.
    pub fn current_selection(rule_set_id: [u8; 16]) -> Self {
        Self {
            tag: 10,
            id: rule_set_id,
            version: None,
        }
    }
}

/// A batch operation; selections use one present field containing version bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// Insert or replace the supplied complete field sequence.
    Put { key: Key, fields: Fields },
    /// Remove a key; deleting an absent key is a no-op.
    Delete { key: Key },
}

impl Change {
    /// memory—v1: Set the explicit current selection to exact version bytes.
    pub fn select_current(rule_set_id: [u8; 16], version: Vec<u8>) -> Self {
        Self::Put {
            key: Key::current_selection(rule_set_id),
            fields: vec![Some(version)],
        }
    }

    /// memory—v1: Remove the explicit current selection.
    pub fn clear_current(rule_set_id: [u8; 16]) -> Self {
        Self::Delete {
            key: Key::current_selection(rule_set_id),
        }
    }

    // memory—v1: Borrow the operation key for batch validation.
    fn key(&self) -> &Key {
        match self {
            Self::Put { key, .. } | Self::Delete { key } => key,
        }
    }
}

/// Rejected preparation; the original snapshot remains unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigestError {
    /// A batch mentions the same key more than once.
    DuplicateKey,
    /// A key, field or field count cannot be encoded in a u64 length.
    LengthOverflow,
    /// An input, batch, or snapshot exceeds this experiment's resource ceilings.
    LimitExceeded,
    /// A current selection must have exactly one non-NULL version field.
    InvalidSelection,
    /// Two distinct exact keys have the same SHA-256 trie path.
    PathCollision,
}

#[derive(Clone)]
enum Node {
    Branch {
        hash: ContentDigest,
        left: Option<Arc<Node>>,
        right: Option<Arc<Node>>,
    },
    Leaf {
        hash: ContentDigest,
        key: Key,
    },
}

impl Node {
    // memory—v1: Return the immutable node's precomputed digest.
    fn hash(&self) -> ContentDigest {
        match self {
            Self::Branch { hash, .. } | Self::Leaf { hash, .. } => *hash,
        }
    }
}

/// Immutable candidate snapshot; cloning shares unchanged data and trie nodes.
#[derive(Clone)]
pub struct DigestIndex {
    rows: OrdMap<Key, Arc<Fields>>,
    tree: Option<Arc<Node>>,
    total_bytes: usize,
}

impl DigestIndex {
    /// memory—v1: Create the digest of an explicitly empty supplied set.
    pub fn new() -> Self {
        Self {
            rows: OrdMap::new(),
            tree: None,
            total_bytes: 0,
        }
    }

    /// memory—v1: Return the experimental digest for this supplied set.
    pub fn digest(&self) -> ContentDigest {
        node_hash(&self.tree, 0)
    }

    /// memory—v1: Look up supplied fields, distinguishing absent from empty.
    pub fn get(&self, key: &Key) -> Option<&Fields> {
        self.rows.get(key).map(Arc::as_ref)
    }

    /// memory—v1: Prepare a new snapshot without changing or publishing `self`.
    ///
    /// Duplicate keys are rejected rather than giving batch order semantics.
    /// The owner must serialize or fence publication against the exact source
    /// snapshot; this method does not implement a commit, version, or CAS.
    pub fn prepare(&self, changes: impl IntoIterator<Item = Change>) -> Result<Self, DigestError> {
        let mut next = self.clone();
        let mut seen = BTreeSet::new();
        for (position, change) in changes.into_iter().enumerate() {
            if position >= MAX_BATCH {
                return Err(DigestError::LimitExceeded);
            }
            validate_key(change.key())?;
            if !seen.insert(change.key().clone()) {
                return Err(DigestError::DuplicateKey);
            }
            match change {
                Change::Put { key, fields } => {
                    if key.tag == 10 {
                        if fields.len() != 1 || fields[0].is_none() {
                            return Err(DigestError::InvalidSelection);
                        }
                        if fields[0]
                            .as_ref()
                            .is_some_and(|version| version.len() > MAX_VERSION_BYTES)
                        {
                            return Err(DigestError::LimitExceeded);
                        }
                    }
                    let row_bytes = row_size(&fields)?;
                    let old = next.rows.get(&key);
                    if old.is_some_and(|old| old.as_ref() == &fields) {
                        continue;
                    }
                    if old.is_none() && next.rows.len() >= MAX_ROWS {
                        return Err(DigestError::LimitExceeded);
                    }
                    let previous_size =
                        old.map_or(0, |old| row_size(old).expect("stored rows are bounded"));
                    let total_bytes = next.total_bytes - previous_size + row_bytes;
                    if total_bytes > MAX_TOTAL_BYTES {
                        return Err(DigestError::LimitExceeded);
                    }
                    let key_bytes = encode_key(&key)?;
                    let leaf = hash_leaf(&key_bytes, &fields)?;
                    let path = hash_path(&key_bytes);
                    next.tree = update(&next.tree, 0, &path, &key, Some(leaf))?;
                    next.rows.insert(key, Arc::new(fields));
                    next.total_bytes = total_bytes;
                }
                Change::Delete { key } => {
                    let Some(old) = next.rows.get(&key) else {
                        continue;
                    };
                    let old_size = row_size(old).expect("stored rows are bounded");
                    let key_bytes = encode_key(&key)?;
                    let path = hash_path(&key_bytes);
                    next.tree = update(&next.tree, 0, &path, &key, None)?;
                    next.rows.remove(&key);
                    next.total_bytes -= old_size;
                }
            }
        }
        Ok(next)
    }
}

impl Default for DigestIndex {
    /// memory—v1: Create an explicitly empty candidate snapshot.
    fn default() -> Self {
        Self::new()
    }
}

// memory—v1: Bound version bytes before framing or cloning the key.
fn validate_key(key: &Key) -> Result<(), DigestError> {
    if key
        .version
        .as_ref()
        .is_some_and(|version| version.len() > MAX_VERSION_BYTES)
    {
        return Err(DigestError::LimitExceeded);
    }
    Ok(())
}

// memory—v1: Bound field count and bytes before retaining or hashing a row.
fn row_size(fields: &Fields) -> Result<usize, DigestError> {
    if fields.len() > MAX_FIELDS {
        return Err(DigestError::LimitExceeded);
    }
    let mut total = 0usize;
    for value in fields.iter().flatten() {
        if value.len() > MAX_FIELD_BYTES {
            return Err(DigestError::LimitExceeded);
        }
        total = total
            .checked_add(value.len())
            .ok_or(DigestError::LimitExceeded)?;
        if total > MAX_ROW_BYTES {
            return Err(DigestError::LimitExceeded);
        }
    }
    Ok(total)
}

// memory—v1: Encode a length without truncation.
fn length(len: usize) -> Result<[u8; 8], DigestError> {
    Ok(u64::try_from(len)
        .map_err(|_| DigestError::LengthOverflow)?
        .to_be_bytes())
}

// memory—v1: Encode exact key identity; only version keys carry version bytes.
fn encode_key(key: &Key) -> Result<Vec<u8>, DigestError> {
    let mut out = Vec::new();
    out.push(key.tag);
    out.extend_from_slice(&key.id);
    if let Some(version) = &key.version {
        out.extend_from_slice(&length(version.len())?);
        out.extend_from_slice(version);
    }
    Ok(out)
}

// memory—v1: Hash a key in the independent path namespace.
fn hash_path(key: &[u8]) -> ContentDigest {
    let mut hash = Sha256::new();
    hash.update(PATH_DOMAIN);
    hash.update(key);
    hash.finalize().into()
}

// memory—v1: Hash the key and fully framed nullable fields in the leaf namespace.
fn hash_leaf(key: &[u8], fields: &Fields) -> Result<ContentDigest, DigestError> {
    let mut hash = Sha256::new();
    hash.update(LEAF_DOMAIN);
    hash.update(length(key.len())?);
    hash.update(key);
    hash.update(length(fields.len())?);
    for field in fields {
        match field {
            None => hash.update([0]),
            Some(bytes) => {
                hash.update([1]);
                hash.update(length(bytes.len())?);
                hash.update(bytes);
            }
        }
    }
    Ok(hash.finalize().into())
}

// memory—v1: Bind branch depth and the ordered pair of child hashes.
fn hash_branch(depth: usize, left: ContentDigest, right: ContentDigest) -> ContentDigest {
    let mut hash = Sha256::new();
    hash.update(BRANCH_DOMAIN);
    hash.update((depth as u16).to_be_bytes());
    hash.update(left);
    hash.update(right);
    hash.finalize().into()
}

// memory—v1: Calculate depth-specific empty subtrees once in a separate namespace.
fn empties() -> &'static [ContentDigest; DEPTH + 1] {
    static EMPTY: OnceLock<[ContentDigest; DEPTH + 1]> = OnceLock::new();
    EMPTY.get_or_init(|| {
        let mut result = [[0; 32]; DEPTH + 1];
        result[DEPTH] = Sha256::digest(EMPTY_DOMAIN).into();
        for depth in (0..DEPTH).rev() {
            result[depth] = hash_branch(depth, result[depth + 1], result[depth + 1]);
        }
        result
    })
}

// memory—v1: Return a stored digest or the empty digest at this depth.
fn node_hash(node: &Option<Arc<Node>>, depth: usize) -> ContentDigest {
    node.as_ref().map_or(empties()[depth], |node| node.hash())
}

// memory—v1: Read a path bit in big-endian order.
fn bit(path: &ContentDigest, depth: usize) -> bool {
    path[depth / 8] & (0x80 >> (depth % 8)) != 0
}

// memory—v1: Copy only one root-to-leaf path, rejecting distinct-key collisions.
fn update(
    node: &Option<Arc<Node>>,
    depth: usize,
    path: &ContentDigest,
    key: &Key,
    leaf: Option<ContentDigest>,
) -> Result<Option<Arc<Node>>, DigestError> {
    if depth == DEPTH {
        if let Some(existing) = node {
            match existing.as_ref() {
                Node::Leaf {
                    key: existing_key, ..
                } if existing_key != key => return Err(DigestError::PathCollision),
                Node::Leaf { .. } => {}
                Node::Branch { .. } => unreachable!("branch below trie depth"),
            }
        }
        return Ok(leaf.map(|hash| {
            Arc::new(Node::Leaf {
                hash,
                key: key.clone(),
            })
        }));
    }
    let (mut left, mut right) = match node.as_deref() {
        Some(Node::Branch { left, right, .. }) => (left.clone(), right.clone()),
        None => (None, None),
        Some(Node::Leaf { .. }) => unreachable!("leaf above trie depth"),
    };
    if bit(path, depth) {
        right = update(&right, depth + 1, path, key, leaf)?;
    } else {
        left = update(&left, depth + 1, path, key, leaf)?;
    }
    if left.is_none() && right.is_none() {
        return Ok(None);
    }
    let hash = hash_branch(
        depth,
        node_hash(&left, depth + 1),
        node_hash(&right, depth + 1),
    );
    Ok(Some(Arc::new(Node::Branch { hash, left, right })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    // memory—v1: Independently frame and hash all input rows and rebuild the trie.
    fn rebuild(rows: &BTreeMap<Key, Fields>) -> ContentDigest {
        let mut leaves = Vec::new();
        for (key, fields) in rows {
            let mut kb = vec![key.tag];
            kb.extend_from_slice(&key.id);
            if let Some(version) = &key.version {
                kb.extend_from_slice(&(version.len() as u64).to_be_bytes());
                kb.extend_from_slice(version);
            }
            let mut path_frame = PATH_DOMAIN.to_vec();
            path_frame.extend_from_slice(&kb);
            let path: ContentDigest = Sha256::digest(&path_frame).into();
            let mut frame = LEAF_DOMAIN.to_vec();
            frame.extend_from_slice(&(kb.len() as u64).to_be_bytes());
            frame.extend_from_slice(&kb);
            frame.extend_from_slice(&(fields.len() as u64).to_be_bytes());
            for field in fields {
                if let Some(value) = field {
                    frame.push(1);
                    frame.extend_from_slice(&(value.len() as u64).to_be_bytes());
                    frame.extend_from_slice(value);
                } else {
                    frame.push(0);
                }
            }
            leaves.push((path, ContentDigest::from(Sha256::digest(&frame))));
        }
        leaves.sort_by_key(|entry| entry.0);
        // memory—v1: Rebuild a subtree from sorted full leaves, not stored nodes.
        fn subtree(leaves: &[(ContentDigest, ContentDigest)], depth: usize) -> ContentDigest {
            if depth == DEPTH {
                assert!(leaves.len() <= 1, "reference path collision");
                return leaves
                    .first()
                    .map_or_else(|| Sha256::digest(EMPTY_DOMAIN).into(), |entry| entry.1);
            }
            let split =
                leaves.partition_point(|entry| (entry.0[depth / 8] & (0x80 >> (depth % 8))) == 0);
            let left = subtree(&leaves[..split], depth + 1);
            let right = subtree(&leaves[split..], depth + 1);
            let mut frame = BRANCH_DOMAIN.to_vec();
            frame.extend_from_slice(&(depth as u16).to_be_bytes());
            frame.extend_from_slice(&left);
            frame.extend_from_slice(&right);
            Sha256::digest(frame).into()
        }
        // Empty subtrees can be calculated directly; avoid exponential recursion.
        // memory—v1: Rebuild populated paths, calculating empty subtrees linearly.
        fn sparse(leaves: &[(ContentDigest, ContentDigest)], depth: usize) -> ContentDigest {
            if leaves.is_empty() {
                let mut hash: ContentDigest = Sha256::digest(EMPTY_DOMAIN).into();
                for level in (depth..DEPTH).rev() {
                    let mut frame = BRANCH_DOMAIN.to_vec();
                    frame.extend_from_slice(&(level as u16).to_be_bytes());
                    frame.extend_from_slice(&hash);
                    frame.extend_from_slice(&hash);
                    hash = Sha256::digest(frame).into();
                }
                return hash;
            }
            if depth == DEPTH {
                return subtree(leaves, depth);
            }
            let split =
                leaves.partition_point(|entry| (entry.0[depth / 8] & (0x80 >> (depth % 8))) == 0);
            let mut frame = BRANCH_DOMAIN.to_vec();
            frame.extend_from_slice(&(depth as u16).to_be_bytes());
            frame.extend_from_slice(&sparse(&leaves[..split], depth + 1));
            frame.extend_from_slice(&sparse(&leaves[split..], depth + 1));
            Sha256::digest(frame).into()
        }
        sparse(&leaves, 0)
    }

    // memory—v1: Build one input operation.
    fn put(key: Key, value: &[u8]) -> Change {
        Change::Put {
            key,
            fields: vec![Some(value.to_vec())],
        }
    }

    // memory—v1: Compare every incremental step with an independent complete rebuild.
    fn apply(index: &DigestIndex, rows: &mut BTreeMap<Key, Fields>, change: Change) -> DigestIndex {
        match &change {
            Change::Put { key, fields } => {
                rows.insert(key.clone(), fields.clone());
            }
            Change::Delete { key } => {
                rows.remove(key);
            }
        }
        let result = index.prepare([change]).unwrap();
        assert_eq!(result.digest(), rebuild(rows));
        result
    }

    #[test]
    // memory—v1: All nine tables and explicit current are order independent.
    fn insertion_order_and_rebuild_cover_nine_tables() {
        let id = [0; 16];
        let keys = vec![
            Key::row(Table::User, id),
            Key::row(Table::IdentityCard, id),
            Key::row(Table::Tenant, id),
            Key::row(Table::UserCard, id),
            Key::row(Table::RuleSet, id),
            Key::rule_set_version(id, b"v\0".to_vec()),
            Key::row(Table::Binding, id),
            Key::row(Table::BindingConfirmation, id),
            Key::row(Table::RuleSetChangeConfirmation, id),
            Key::current_selection(id),
            Key::rule_set_version(id, b"v".to_vec()),
        ];
        let mut rows = BTreeMap::new();
        let mut forward = DigestIndex::new();
        assert_eq!(forward.digest(), rebuild(&rows));
        for key in &keys {
            forward = apply(&forward, &mut rows, put(key.clone(), b"v"));
        }
        let mut reverse = DigestIndex::new();
        let mut reverse_rows = BTreeMap::new();
        for key in keys.iter().rev() {
            reverse = apply(&reverse, &mut reverse_rows, put(key.clone(), b"v"));
        }
        assert_eq!(forward.digest(), reverse.digest());
        assert_eq!(rows, reverse_rows);
    }

    #[test]
    // memory—v1: Updates, deletes, no-ops and ABA match a fresh full rebuild.
    fn update_delete_aba_and_snapshot_isolation() {
        let key = Key::row(Table::User, [1; 16]);
        let mut rows = BTreeMap::new();
        let empty = DigestIndex::new();
        let first = apply(&empty, &mut rows, put(key.clone(), b"a"));
        let changed = apply(&first, &mut rows, put(key.clone(), b"b"));
        let restored = apply(&changed, &mut rows, put(key.clone(), b"a"));
        assert_ne!(first.digest(), changed.digest());
        assert_eq!(first.digest(), restored.digest());
        assert_eq!(first.get(&key), Some(&vec![Some(b"a".to_vec())]));
        assert_eq!(empty.get(&key), None);
        let removed = apply(&restored, &mut rows, Change::Delete { key: key.clone() });
        assert_eq!(removed.digest(), empty.digest());
        let again = apply(&removed, &mut rows, Change::Delete { key });
        assert_eq!(again.digest(), removed.digest());
    }

    #[test]
    // memory—v1: NULL, empty field, no fields, absent row and selection differ.
    fn empty_null_absent_and_selection_are_distinct() {
        let id = [3; 16];
        let key = Key::row(Table::Tenant, id);
        let base = DigestIndex::new();
        let null = base
            .prepare([Change::Put {
                key: key.clone(),
                fields: vec![None],
            }])
            .unwrap();
        let empty = base.prepare([put(key.clone(), b"")]).unwrap();
        let no_fields = base
            .prepare([Change::Put {
                key,
                fields: vec![],
            }])
            .unwrap();
        let selected = base.prepare([Change::select_current(id, vec![])]).unwrap();
        let values = [
            base.digest(),
            null.digest(),
            empty.digest(),
            no_fields.digest(),
            selected.digest(),
        ];
        assert_eq!(
            values.into_iter().collect::<BTreeSet<_>>().len(),
            values.len()
        );
        assert_eq!(
            selected.get(&Key::current_selection(id)),
            Some(&vec![Some(vec![])])
        );
        assert_eq!(
            selected
                .prepare([Change::clear_current(id)])
                .unwrap()
                .digest(),
            base.digest()
        );
    }

    #[test]
    // memory—v1: Framing separates concatenation ambiguities, tables and version keys.
    fn framing_and_domains_are_unambiguous() {
        let id = [4; 16];
        let key = Key::row(Table::User, id);
        let index = DigestIndex::new();
        let a = index
            .prepare([Change::Put {
                key: key.clone(),
                fields: vec![Some(b"a".to_vec()), Some(b"bc".to_vec())],
            }])
            .unwrap();
        let b = index
            .prepare([Change::Put {
                key,
                fields: vec![Some(b"ab".to_vec()), Some(b"c".to_vec())],
            }])
            .unwrap();
        assert_ne!(a.digest(), b.digest());
        let c = index
            .prepare([put(Key::row(Table::Tenant, id), b"x")])
            .unwrap();
        let d = index
            .prepare([put(Key::row(Table::User, id), b"x")])
            .unwrap();
        assert_ne!(c.digest(), d.digest());
        let e = index
            .prepare([put(Key::rule_set_version(id, vec![]), b"x")])
            .unwrap();
        let f = index
            .prepare([put(Key::current_selection(id), b"x")])
            .unwrap();
        assert_ne!(e.digest(), f.digest());
        let g = index
            .prepare([put(Key::rule_set_version(id, vec![0]), b"x")])
            .unwrap();
        assert_ne!(e.digest(), g.digest());
    }

    #[test]
    // memory—v1: Enforce bounded keys, rows, batches and snapshot input atomically.
    fn resource_limits_reject_without_changing_the_snapshot() {
        let index = DigestIndex::new();
        let id = [5; 16];
        let too_long = Key::rule_set_version(id, vec![0; MAX_VERSION_BYTES + 1]);
        assert!(matches!(
            index.prepare([put(too_long, b"x")]),
            Err(DigestError::LimitExceeded)
        ));
        let valid = Key::rule_set_version(id, vec![0; MAX_VERSION_BYTES]);
        assert!(index.prepare([put(valid, b"x")]).is_ok());
        assert!(matches!(
            index.prepare([Change::select_current(id, vec![0; MAX_VERSION_BYTES + 1])]),
            Err(DigestError::LimitExceeded)
        ));
        assert!(index
            .prepare([Change::select_current(id, vec![0; MAX_VERSION_BYTES])])
            .is_ok());
        let key = Key::row(Table::User, id);
        assert!(matches!(
            index.prepare([Change::Put {
                key,
                fields: vec![None; MAX_FIELDS + 1]
            }]),
            Err(DigestError::LimitExceeded)
        ));
        let changes = (0..=MAX_BATCH).map(|n| {
            let mut key_id = [0; 16];
            key_id[..8].copy_from_slice(&(n as u64).to_be_bytes());
            put(Key::row(Table::User, key_id), b"x")
        });
        assert!(matches!(
            index.prepare(changes),
            Err(DigestError::LimitExceeded)
        ));
        assert_eq!(index.digest(), rebuild(&BTreeMap::new()));
    }

    #[test]
    // memory—v1: Reject a forced path collision without replacing the old leaf.
    fn collision_rejects_distinct_keys() {
        let path = [0; 32];
        let first = Key::row(Table::User, [1; 16]);
        let second = Key::row(Table::User, [2; 16]);
        let tree = update(&None, 0, &path, &first, Some([1; 32])).unwrap();
        assert!(matches!(
            update(&tree, 0, &path, &second, Some([2; 32])),
            Err(DigestError::PathCollision)
        ));
        assert!(tree.is_some());
    }

    #[test]
    // memory—v1: A successful batch matches a rebuild and preserves untouched branches.
    fn batch_rebuild_and_structural_sharing() {
        let first = Key::row(Table::User, [11; 16]);
        let second = (12u8..=255)
            .map(|id| Key::row(Table::User, [id; 16]))
            .find(|key| {
                bit(&hash_path(&encode_key(key).unwrap()), 0)
                    != bit(&hash_path(&encode_key(&first).unwrap()), 0)
            })
            .unwrap();
        let initial = DigestIndex::new()
            .prepare([put(first.clone(), b"one"), put(second.clone(), b"two")])
            .unwrap();
        let next = initial.prepare([put(first.clone(), b"changed")]).unwrap();
        let mut rows = BTreeMap::new();
        rows.insert(first.clone(), vec![Some(b"changed".to_vec())]);
        rows.insert(second.clone(), vec![Some(b"two".to_vec())]);
        assert_eq!(next.digest(), rebuild(&rows));
        let (old_left, old_right) = match initial.tree.as_deref().unwrap() {
            Node::Branch { left, right, .. } => (left.as_ref().unwrap(), right.as_ref().unwrap()),
            Node::Leaf { .. } => unreachable!(),
        };
        let (new_left, new_right) = match next.tree.as_deref().unwrap() {
            Node::Branch { left, right, .. } => (left.as_ref().unwrap(), right.as_ref().unwrap()),
            Node::Leaf { .. } => unreachable!(),
        };
        if bit(&hash_path(&encode_key(&first).unwrap()), 0) {
            assert!(Arc::ptr_eq(old_left, new_left));
            assert!(!Arc::ptr_eq(old_right, new_right));
        } else {
            assert!(Arc::ptr_eq(old_right, new_right));
            assert!(!Arc::ptr_eq(old_left, new_left));
        }
        let final_index = next
            .prepare([
                Change::Delete { key: first.clone() },
                put(second.clone(), b"three"),
                Change::select_current([7; 16], vec![]),
            ])
            .unwrap();
        rows.remove(&first);
        rows.insert(second, vec![Some(b"three".to_vec())]);
        rows.insert(Key::current_selection([7; 16]), vec![Some(vec![])]);
        assert_eq!(final_index.digest(), rebuild(&rows));
    }

    #[test]
    // memory—v1: Failed multi-operation preparation leaves the original unchanged.
    fn invalid_batches_are_atomic() {
        let original = DigestIndex::new();
        let key = Key::row(Table::User, [1; 16]);
        assert!(matches!(
            original.prepare([put(key.clone(), b"x"), put(key.clone(), b"y")]),
            Err(DigestError::DuplicateKey)
        ));
        assert!(matches!(
            original.prepare([
                put(key.clone(), b"x"),
                Change::Put {
                    key: Key::current_selection([2; 16]),
                    fields: vec![None]
                }
            ]),
            Err(DigestError::InvalidSelection)
        ));
        assert_eq!(original.get(&key), None);
        assert_eq!(original.digest(), rebuild(&BTreeMap::new()));
    }
}
