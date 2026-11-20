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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

use im::OrdMap;
use sha2::{Digest as _, Sha256};

mod tree;

const PATH_DOMAIN: &[u8] = b"astrallight/memory-v1/digest-candidate/path/1\0";
const LEAF_DOMAIN: &[u8] = b"astrallight/memory-v1/digest-candidate/leaf/1\0";
const BRANCH_DOMAIN: &[u8] = b"astrallight/memory-v1/digest-candidate/branch/1\0";
const EMPTY_DOMAIN: &[u8] = b"astrallight/memory-v1/digest-candidate/empty/1\0";
const DEPTH: usize = 256;
// Experimental resource ceilings, not database or business limits.
pub(crate) const MAX_VERSION_BYTES: usize = 255;
const MAX_FIELD_BYTES: usize = 16 * 1024 * 1024;
const MAX_FIELDS: usize = 32;
pub(crate) const MAX_ROW_BYTES: usize = 16 * 1024 * 1024;
const MAX_BATCH: usize = 128;
/// Maximum distinct row and current-selection keys in one candidate digest.
/// memory—v1: This local resource limit is not a database or business limit.
pub const MAX_ROOT_DIGEST_KEYS: usize = 4096;
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

/// Immutable candidate snapshot; cloning shares unchanged data and trie nodes.
#[derive(Clone)]
pub struct DigestIndex {
    rows: OrdMap<Key, Arc<Fields>>,
    tree: tree::Tree,
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
        tree::root_hash(&self.tree)
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
                    validate_put(&key, &fields)?;
                    let row_bytes = row_size(&fields)?;
                    let old = next.rows.get(&key);
                    if old.is_some_and(|old| old.as_ref() == &fields) {
                        continue;
                    }
                    if old.is_none() && next.rows.len() >= MAX_ROOT_DIGEST_KEYS {
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
                    next.tree = tree::update(&next.tree, &path, &key, Some(leaf))?;
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
                    next.tree = tree::update(&next.tree, &path, &key, None)?;
                    next.rows.remove(&key);
                    next.total_bytes -= old_size;
                }
            }
        }
        Ok(next)
    }

    // memory—v1: A bounded additive load hashes the changed paths in one pass.
    // Reuse all unaffected branches, including their precomputed digests.
    pub(crate) fn remaining_bytes(&self) -> usize {
        MAX_TOTAL_BYTES.saturating_sub(self.total_bytes)
    }
}

pub(crate) struct DigestAdditions<'a> {
    before: &'a DigestIndex,
    next: DigestIndex,
    leaves: Vec<tree::Leaf>,
}

impl<'a> DigestAdditions<'a> {
    // memory—v1: Stage bounded additions without an intermediate copy of the batch.
    pub(crate) fn new(before: &'a DigestIndex) -> Self {
        Self {
            before,
            next: before.clone(),
            leaves: Vec::new(),
        }
    }

    pub(crate) fn push(&mut self, change: Change) -> Result<(), DigestError> {
        let Change::Put { key, fields } = change else {
            return Err(DigestError::DuplicateKey);
        };
        validate_key(&key)?;
        validate_put(&key, &fields)?;
        if self.next.rows.contains_key(&key) {
            return Err(DigestError::DuplicateKey);
        }
        if self.next.rows.len() >= MAX_ROOT_DIGEST_KEYS {
            return Err(DigestError::LimitExceeded);
        }
        self.next.total_bytes = self
            .next
            .total_bytes
            .checked_add(row_size(&fields)?)
            .filter(|total| *total <= MAX_TOTAL_BYTES)
            .ok_or(DigestError::LimitExceeded)?;
        let key_bytes = encode_key(&key)?;
        self.leaves.push((
            hash_path(&key_bytes),
            key.clone(),
            hash_leaf(&key_bytes, &fields)?,
        ));
        self.next.rows.insert(key, Arc::new(fields));
        Ok(())
    }

    // memory—v1: Reuse all unaffected branches and their precomputed digests.
    pub(crate) fn finish(mut self) -> Result<DigestIndex, DigestError> {
        self.leaves.sort_unstable_by_key(|entry| entry.0);
        if self.leaves.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(DigestError::PathCollision);
        }
        self.next.tree = tree::add(&self.before.tree, &self.leaves)?;
        Ok(self.next)
    }
}

// memory—v1: Stage a cold build in input order, retaining prepare's 128-change
// duplicate and replacement semantics without allocating persistent trie paths.
// This private builder accepts puts only and cannot modify an existing snapshot.
pub(crate) struct ColdDigestBuilder {
    rows: BTreeMap<Key, Arc<Fields>>,
    paths: BTreeMap<ContentDigest, (Key, ContentDigest)>,
    seen: BTreeSet<Key>,
    position: usize,
    total_bytes: usize,
    error: Option<DigestError>,
}

impl ColdDigestBuilder {
    // memory—v1: Start an unpublished empty cold-build staging area.
    pub(crate) fn new() -> Self {
        Self {
            rows: BTreeMap::new(),
            paths: BTreeMap::new(),
            seen: BTreeSet::new(),
            position: 0,
            total_bytes: 0,
            error: None,
        }
    }

    // memory—v1: Reject a failed staging area even if a caller ignores an error.
    pub(crate) fn push(&mut self, key: Key, fields: Fields) -> Result<(), DigestError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let result = self.push_inner(key, fields);
        if let Err(error) = result {
            self.error = Some(error);
        }
        result
    }

    // memory—v1: Validate each put in the same order as chunked prepare.
    fn push_inner(&mut self, key: Key, fields: Fields) -> Result<(), DigestError> {
        if self.position == MAX_BATCH {
            self.seen.clear();
            self.position = 0;
        }
        self.position += 1;
        validate_key(&key)?;
        if !self.seen.insert(key.clone()) {
            return Err(DigestError::DuplicateKey);
        }
        validate_put(&key, &fields)?;
        let row_bytes = row_size(&fields)?;
        let old = self.rows.get(&key);
        if old.is_some_and(|old| old.as_ref() == &fields) {
            return Ok(());
        }
        if old.is_none() && self.rows.len() >= MAX_ROOT_DIGEST_KEYS {
            return Err(DigestError::LimitExceeded);
        }
        let previous_size = old.map_or(0, |old| row_size(old).expect("stored rows are bounded"));
        let total_bytes = self.total_bytes - previous_size + row_bytes;
        if total_bytes > MAX_TOTAL_BYTES {
            return Err(DigestError::LimitExceeded);
        }
        let key_bytes = encode_key(&key)?;
        // Match prepare's framing validation before checking the path collision.
        let leaf = hash_leaf(&key_bytes, &fields)?;
        let path = hash_path(&key_bytes);
        if self
            .paths
            .get(&path)
            .is_some_and(|(other, _)| other != &key)
        {
            return Err(DigestError::PathCollision);
        }
        self.paths.insert(path, (key.clone(), leaf));
        self.rows.insert(key, Arc::new(fields));
        self.total_bytes = total_bytes;
        Ok(())
    }

    // memory—v1: Construct every occupied branch once, after complete validation.
    pub(crate) fn finish(self) -> Result<DigestIndex, DigestError> {
        self.finish_with(|leaves| tree::build(leaves, 0))
    }

    fn finish_with(
        self,
        build: impl FnOnce(&[tree::Leaf]) -> tree::Tree,
    ) -> Result<DigestIndex, DigestError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let leaves: Vec<_> = self
            .paths
            .into_iter()
            .map(|(path, (key, hash))| (path, key, hash))
            .collect();
        let tree = build(&leaves);
        let mut rows = OrdMap::new();
        for (key, fields) in self.rows {
            rows.insert(key, fields);
        }
        Ok(DigestIndex {
            rows,
            tree,
            total_bytes: self.total_bytes,
        })
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

// memory—v1: A selection has exactly one present and bounded version field.
fn validate_put(key: &Key, fields: &Fields) -> Result<(), DigestError> {
    if key.tag == 10 {
        let [Some(version)] = fields.as_slice() else {
            return Err(DigestError::InvalidSelection);
        };
        if version.len() > MAX_VERSION_BYTES {
            return Err(DigestError::LimitExceeded);
        }
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
    const DEPTH_END: usize = BRANCH_DOMAIN.len() + 2;
    const LEFT_END: usize = DEPTH_END + 32;
    let mut frame = [0; LEFT_END + 32];
    frame[..BRANCH_DOMAIN.len()].copy_from_slice(BRANCH_DOMAIN);
    frame[BRANCH_DOMAIN.len()..DEPTH_END].copy_from_slice(&(depth as u16).to_be_bytes());
    frame[DEPTH_END..LEFT_END].copy_from_slice(&left);
    frame[LEFT_END..].copy_from_slice(&right);
    ring::digest::digest(&ring::digest::SHA256, &frame)
        .as_ref()
        .try_into()
        .expect("SHA-256 has 32 output bytes")
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

// memory—v1: Read a path bit in big-endian order.
fn bit(path: &ContentDigest, depth: usize) -> bool {
    path[depth / 8] & (0x80 >> (depth % 8)) != 0
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

    // memory—v1: Independently exercise the cold path against chunked preparation.
    fn cold(changes: &[Change]) -> Result<DigestIndex, DigestError> {
        let mut builder = ColdDigestBuilder::new();
        for change in changes {
            match change {
                Change::Put { key, fields } => builder.push(key.clone(), fields.clone())?,
                Change::Delete { .. } => panic!("cold inputs must be puts"),
            }
        }
        builder.finish()
    }

    // memory—v1: Reproduce the former cold loader's bounded prepare batches.
    fn chunked(changes: &[Change]) -> Result<DigestIndex, DigestError> {
        let mut index = DigestIndex::new();
        for batch in changes.chunks(MAX_BATCH) {
            index = index.prepare(batch.iter().cloned())?;
        }
        Ok(index)
    }

    #[test]
    // memory—v1: Cold construction matches independent framing and later updates.
    fn cold_build_matches_reference_incremental_and_snapshot_updates() {
        let id = [42; 16];
        let empty = cold(&[]).unwrap();
        assert_eq!(empty.digest(), rebuild(&BTreeMap::new()));
        let keys = vec![
            Key::row(Table::BindingConfirmation, id),
            Key::rule_set_version(id, vec![]),
            Key::row(Table::Tenant, id),
            Key::current_selection(id),
            Key::row(Table::RuleSetChangeConfirmation, id),
            Key::row(Table::User, id),
            Key::row(Table::IdentityCard, id),
            Key::row(Table::UserCard, id),
            Key::row(Table::RuleSet, id),
            Key::row(Table::Binding, id),
            Key::rule_set_version(id, vec![0, 1]),
        ];
        let changes: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(n, key)| Change::Put {
                key: key.clone(),
                fields: if key.tag == 10 {
                    vec![Some(vec![])]
                } else {
                    vec![None, Some(vec![]), Some(vec![n as u8])]
                },
            })
            .collect();
        let mut reference = BTreeMap::new();
        for change in &changes {
            if let Change::Put { key, fields } = change {
                reference.insert(key.clone(), fields.clone());
            }
        }
        let initial = cold(&changes).unwrap();
        let mut reversed = changes.clone();
        reversed.reverse();
        let incremental = chunked(&changes).unwrap();
        assert_eq!(initial.digest(), rebuild(&reference));
        assert_eq!(initial.digest(), incremental.digest());
        assert_eq!(initial.digest(), cold(&reversed).unwrap().digest());
        for (key, fields) in &reference {
            assert_eq!(initial.get(key), Some(fields));
        }
        let old_digest = initial.digest();
        let added = Key::row(Table::User, [77; 16]);
        let updates = [
            put(keys[0].clone(), b"modified"),
            Change::Delete {
                key: keys[1].clone(),
            },
            put(added.clone(), b"added"),
            Change::select_current(id, vec![0, 1]),
        ];
        let next = initial.prepare(updates.clone()).unwrap();
        let next_incremental = incremental.prepare(updates).unwrap();
        reference.insert(keys[0].clone(), vec![Some(b"modified".to_vec())]);
        reference.remove(&keys[1]);
        reference.insert(added.clone(), vec![Some(b"added".to_vec())]);
        reference.insert(Key::current_selection(id), vec![Some(vec![0, 1])]);
        assert_eq!(next.digest(), rebuild(&reference));
        assert_eq!(next.digest(), next_incremental.digest());
        assert_eq!(initial.digest(), old_digest);
        assert_eq!(initial.get(&added), None);
        assert_eq!(
            initial.get(&keys[1]),
            Some(&vec![None, Some(vec![]), Some(vec![1])])
        );
    }

    #[test]
    #[ignore = "opt-in comparison at the exact digest key capacity"]
    // memory—v1: Compare both complete 4096-key construction paths without holding both trees.
    fn cold_build_near_capacity_matches_chunked_and_preserves_snapshots() {
        use std::time::Instant;

        // The odd multiplier permutes all 4096 IDs and makes input order non-sorted.
        let changes: Vec<_> = (0..MAX_ROOT_DIGEST_KEYS)
            .map(|position| {
                let n = (position * 4051) % MAX_ROOT_DIGEST_KEYS;
                let mut id = [0; 16];
                id[8..].copy_from_slice(&(n as u64).to_be_bytes());
                let key = match n % 10 {
                    0 => Key::row(Table::User, id),
                    1 => Key::row(Table::IdentityCard, id),
                    2 => Key::row(Table::Tenant, id),
                    3 => Key::row(Table::UserCard, id),
                    4 => Key::row(Table::RuleSet, id),
                    5 => Key::rule_set_version(id, vec![0, (n % 251) as u8]),
                    6 => Key::row(Table::Binding, id),
                    7 => Key::row(Table::BindingConfirmation, id),
                    8 => Key::row(Table::RuleSetChangeConfirmation, id),
                    _ => Key::current_selection(id),
                };
                let fields = if key.tag == 10 {
                    vec![Some(vec![(n % 251) as u8])]
                } else {
                    vec![None, Some(vec![]), Some((n as u64).to_be_bytes().to_vec())]
                };
                Change::Put { key, fields }
            })
            .collect();
        assert_eq!(changes.len(), MAX_ROOT_DIGEST_KEYS);
        let Change::Put {
            key: update_key, ..
        } = &changes[0]
        else {
            unreachable!();
        };
        let update_key = update_key.clone();
        let updated_fields = vec![Some(b"updated at capacity".to_vec()), None];
        let first_bit = bit(&hash_path(&encode_key(&update_key).unwrap()), 0);
        let delete_key = changes
            .iter()
            .skip(1)
            .find_map(|change| match change {
                Change::Put { key, .. }
                    if bit(&hash_path(&encode_key(key).unwrap()), 0) == first_bit =>
                {
                    Some(key.clone())
                }
                _ => None,
            })
            .expect("sample has two keys in the same root branch");

        // Only one complete tree is live at a time. The updated snapshots below
        // share all unchanged nodes with that tree and copy at most two paths.
        let started = Instant::now();
        let legacy = chunked(&changes).unwrap();
        let legacy_elapsed = started.elapsed();
        assert_eq!(legacy.rows.len(), MAX_ROOT_DIGEST_KEYS);
        for change in &changes {
            let Change::Put { key, fields } = change else {
                unreachable!();
            };
            assert_eq!(legacy.get(key), Some(fields));
        }
        let legacy_digest = legacy.digest();
        let legacy_updated = legacy
            .prepare([Change::Put {
                key: update_key.clone(),
                fields: updated_fields.clone(),
            }])
            .unwrap();
        let legacy_deleted = legacy_updated
            .prepare([Change::Delete {
                key: delete_key.clone(),
            }])
            .unwrap();
        let legacy_updated_digest = legacy_updated.digest();
        let legacy_deleted_digest = legacy_deleted.digest();
        drop(legacy_deleted);
        drop(legacy_updated);
        drop(legacy);

        let started = Instant::now();
        let bulk = cold(&changes).unwrap();
        let bulk_elapsed = started.elapsed();
        assert_eq!(bulk.rows.len(), MAX_ROOT_DIGEST_KEYS);
        assert_eq!(bulk.digest(), legacy_digest);
        for change in &changes {
            let Change::Put { key, fields } = change else {
                unreachable!();
            };
            assert_eq!(bulk.get(key), Some(fields));
        }
        let updated = bulk
            .prepare([Change::Put {
                key: update_key.clone(),
                fields: updated_fields.clone(),
            }])
            .unwrap();
        let deleted = updated
            .prepare([Change::Delete {
                key: delete_key.clone(),
            }])
            .unwrap();
        assert_eq!(updated.digest(), legacy_updated_digest);
        assert_eq!(deleted.digest(), legacy_deleted_digest);
        assert_eq!(deleted.rows.len(), MAX_ROOT_DIGEST_KEYS - 1);
        for change in &changes {
            let Change::Put { key, fields } = change else {
                unreachable!();
            };
            assert_eq!(bulk.get(key), Some(fields));
            let expected = if key == &delete_key {
                None
            } else if key == &update_key {
                Some(&updated_fields)
            } else {
                Some(fields)
            };
            assert_eq!(deleted.get(key), expected);
        }
        assert_eq!(bulk.digest(), legacy_digest);
        assert_eq!(updated.get(&update_key), Some(&updated_fields));
        assert!(updated.get(&delete_key).is_some());
        // memory—v1: Borrow the root branch that neither change traverses.
        fn untouched(index: &DigestIndex, first_bit: bool) -> &Arc<tree::Node> {
            let (left, right) = index.tree.as_ref().unwrap().root_children();
            if first_bit {
                left
            } else {
                right
            }
        }
        assert!(Arc::ptr_eq(
            untouched(&bulk, first_bit),
            untouched(&updated, first_bit)
        ));
        assert!(Arc::ptr_eq(
            untouched(&bulk, first_bit),
            untouched(&deleted, first_bit)
        ));
        eprintln!(
            "near-capacity digest build: keys={}, chunked={legacy_elapsed:?}, cold={bulk_elapsed:?}; sequential full trees",
            changes.len()
        );
    }

    #[test]
    #[ignore = "local digest scheduler comparison; run explicitly in release"]
    // memory—v1: Compare bounded cold staging with and without one extra worker.
    fn cold_build_two_worker_profile() {
        use std::hint::black_box;
        use std::time::Instant;

        fn build(count: usize, parallel: bool) -> DigestIndex {
            let mut cold = ColdDigestBuilder::new();
            for n in 0..count {
                let mut id = [0; 16];
                id[8..].copy_from_slice(&(n as u64).to_be_bytes());
                cold.push(
                    Key::row(Table::UserCard, id),
                    vec![Some(id.to_vec()), None, Some(vec![0; 64])],
                )
                .unwrap();
            }
            if parallel {
                cold.finish_with(tree::build_with_two_workers).unwrap()
            } else {
                cold.finish().unwrap()
            }
        }

        for count in [32, 500, 3_018, MAX_ROOT_DIGEST_KEYS] {
            let expected = build(count, false).digest();
            let mut samples = [Vec::new(), Vec::new()];
            for round in 0..40 {
                // Alternate order so both arms encounter the same warm-up and drift.
                for arm in [round % 2, 1 - round % 2] {
                    let started = Instant::now();
                    let digest = build(count, arm == 1);
                    let elapsed = started.elapsed().as_nanos();
                    assert_eq!(black_box(&digest).digest(), expected);
                    samples[arm].push(elapsed);
                }
            }
            for (arm, values) in samples.iter_mut().enumerate() {
                values.sort_unstable();
                println!(
                    "digest-profile: keys={count} threads={} n={} p50_ns={} p95_ns={}",
                    arm + 1,
                    values.len(),
                    values[19],
                    values[37],
                );
            }
        }
    }

    #[test]
    // memory—v1: Preserve within-batch duplicate errors and cross-batch replacement.
    fn cold_build_preserves_chunk_duplicate_semantics() {
        let key = Key::row(Table::User, [1; 16]);
        let duplicate = vec![put(key.clone(), b"old"), put(key.clone(), b"new")];
        assert!(matches!(cold(&duplicate), Err(DigestError::DuplicateKey)));
        assert!(matches!(
            chunked(&duplicate),
            Err(DigestError::DuplicateKey)
        ));
        let mut changes = vec![put(key.clone(), b"old")];
        for n in 1..MAX_BATCH {
            let mut id = [0; 16];
            id[8..].copy_from_slice(&(n as u64).to_be_bytes());
            changes.push(put(Key::row(Table::Tenant, id), b"x"));
        }
        changes.push(put(key.clone(), b"new"));
        let bulk = cold(&changes).unwrap();
        let original = chunked(&changes).unwrap();
        assert_eq!(bulk.digest(), original.digest());
        assert_eq!(bulk.get(&key), Some(&vec![Some(b"new".to_vec())]));
        changes.push(put(key, b"again"));
        assert!(matches!(cold(&changes), Err(DigestError::DuplicateKey)));
        assert!(matches!(chunked(&changes), Err(DigestError::DuplicateKey)));
    }

    #[test]
    // memory—v1: Validate limits in order and poison every failed cold staging area.
    fn cold_build_limits_and_failure_are_atomic() {
        let key = Key::row(Table::User, [9; 16]);
        let mut builder = ColdDigestBuilder::new();
        builder.push(key.clone(), vec![Some(vec![])]).unwrap();
        assert_eq!(
            builder.push(Key::current_selection([1; 16]), vec![None]),
            Err(DigestError::InvalidSelection)
        );
        assert_eq!(
            builder.push(Key::row(Table::User, [10; 16]), vec![]),
            Err(DigestError::InvalidSelection)
        );
        assert!(matches!(
            builder.finish(),
            Err(DigestError::InvalidSelection)
        ));
        let mut builder = ColdDigestBuilder::new();
        assert_eq!(
            builder.push(
                Key::rule_set_version([0; 16], vec![0; MAX_VERSION_BYTES + 1]),
                vec![]
            ),
            Err(DigestError::LimitExceeded)
        );
        assert!(matches!(builder.finish(), Err(DigestError::LimitExceeded)));
        let mut builder = ColdDigestBuilder::new();
        assert_eq!(
            builder.push(key.clone(), vec![None; MAX_FIELDS + 1]),
            Err(DigestError::LimitExceeded)
        );
        assert!(matches!(builder.finish(), Err(DigestError::LimitExceeded)));
        let mut builder = ColdDigestBuilder::new();
        builder.total_bytes = MAX_TOTAL_BYTES - 1;
        builder.push(key.clone(), vec![Some(vec![0])]).unwrap();
        assert_eq!(builder.total_bytes, MAX_TOTAL_BYTES);
        assert_eq!(
            builder.push(Key::row(Table::User, [10; 16]), vec![Some(vec![0])]),
            Err(DigestError::LimitExceeded)
        );
        assert!(matches!(builder.finish(), Err(DigestError::LimitExceeded)));
        let mut builder = ColdDigestBuilder::new();
        for n in 0..MAX_ROOT_DIGEST_KEYS {
            let mut id = [0; 16];
            id[8..].copy_from_slice(&(n as u64).to_be_bytes());
            builder.push(Key::row(Table::User, id), vec![]).unwrap();
        }
        assert_eq!(builder.rows.len(), MAX_ROOT_DIGEST_KEYS);
        assert_eq!(
            builder.push(Key::row(Table::Tenant, [0; 16]), vec![]),
            Err(DigestError::LimitExceeded)
        );
        assert!(matches!(builder.finish(), Err(DigestError::LimitExceeded)));
    }

    #[test]
    // memory—v1: A simulated digest collision fails closed before tree creation.
    fn cold_build_forced_path_collision_is_atomic() {
        let first = Key::row(Table::User, [1; 16]);
        let second = Key::row(Table::User, [2; 16]);
        let mut builder = ColdDigestBuilder::new();
        builder.push(first.clone(), vec![]).unwrap();
        let second_path = hash_path(&encode_key(&second).unwrap());
        builder.paths.insert(second_path, (first, [0; 32]));
        assert_eq!(
            builder.push(second, vec![]),
            Err(DigestError::PathCollision)
        );
        assert!(matches!(builder.finish(), Err(DigestError::PathCollision)));
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
        let tree = tree::update(&None, &path, &first, Some([1; 32])).unwrap();
        assert!(matches!(
            tree::update(&tree, &path, &second, Some([2; 32])),
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
        let (old_left, old_right) = initial.tree.as_ref().unwrap().root_children();
        let (new_left, new_right) = next.tree.as_ref().unwrap().root_children();
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
