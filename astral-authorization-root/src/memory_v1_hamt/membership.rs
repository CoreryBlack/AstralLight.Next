//! memory—v1: Private binding and confirmation indexes store a lone ID inline.

use super::{BinaryId, HashMap, HashSet};

pub(super) type Membership = HashMap<BinaryId, Members>;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) enum Members {
    #[default]
    Empty,
    One(BinaryId),
    Many(HashSet<BinaryId>),
}

impl Members {
    // memory—v1: Cardinality includes all exact identities, not only active rows.
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::One(_) => 1,
            Self::Many(ids) => ids.len(),
        }
    }

    // memory—v1: Empty buckets must be removed before publication.
    pub(super) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // memory—v1: Use the full binary ID for both representations.
    pub(super) fn contains(&self, id: &BinaryId) -> bool {
        match self {
            Self::Empty => false,
            Self::One(existing) => existing == id,
            Self::Many(ids) => ids.contains(id),
        }
    }

    // memory—v1: A singleton read neither allocates nor constructs a hash iterator.
    pub(super) fn iter(&self) -> impl Iterator<Item = &BinaryId> {
        let (one, many) = match self {
            Self::Empty => (None, None),
            Self::One(id) => (Some(id), None),
            Self::Many(ids) => (None, Some(ids)),
        };
        one.into_iter()
            .chain(many.into_iter().flat_map(HashSet::iter))
    }

    // memory—v1: Promote only on a second distinct ID; large buckets stay persistent.
    fn insert(&mut self, id: BinaryId) {
        match self {
            Self::Empty => *self = Self::One(id),
            Self::One(existing) if existing == &id => {}
            Self::One(existing) => *self = Self::Many([*existing, id].into_iter().collect()),
            Self::Many(ids) => {
                ids.insert(id);
            }
        }
    }

    // memory—v1: A missing ID is not a successful removal. Demote only after removal.
    pub(super) fn remove(&mut self, id: &BinaryId) -> Option<BinaryId> {
        match self {
            Self::One(existing) if existing == id => {
                *self = Self::Empty;
                Some(*id)
            }
            Self::Many(ids) => {
                let removed = ids.remove(id)?;
                if ids.len() == 1 {
                    *self = Self::One(*ids.iter().next().expect("one remaining member"));
                }
                Some(removed)
            }
            _ => None,
        }
    }
}

// memory—v1: Mutate only the successor map's bucket through the HAMT's COW path.
pub(super) fn add_member(index: &mut Membership, key: BinaryId, id: BinaryId) {
    index.entry(key).or_default().insert(id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn exact_set_and_pinned_predecessors_survive_promotion_and_demotion() {
        let key = [0; 16];
        let mut index = Membership::new();
        let mut expected = BTreeSet::new();
        // Same prefix, including the all-zero ID: no shortened IDs or sentinel values.
        let id = |n: u8| {
            let mut id = [0; 16];
            id[15] = n;
            id
        };
        let mut pinned = Vec::new();
        for n in 0..=200 {
            if matches!(n, 1 | 2 | 100) {
                pinned.push((index.clone(), expected.clone()));
            }
            for _ in 0..2 {
                add_member(&mut index, key, id(n));
            }
            expected.insert(id(n));
            let bucket = &index[&key];
            assert_eq!(bucket.len(), expected.len());
            assert!(bucket.contains(&id(n)));
            assert!(matches!(bucket, Members::One(_)) == (n == 0));
        }
        pinned.push((index.clone(), expected.clone()));
        for n in (0..=200).rev() {
            let bucket = index.get_mut(&key).unwrap();
            assert_eq!(bucket.remove(&id(n)), Some(id(n)));
            assert_eq!(bucket.remove(&id(n)), None);
            expected.remove(&id(n));
            assert_eq!(bucket.iter().copied().collect::<BTreeSet<_>>(), expected);
            assert_eq!(matches!(bucket, Members::One(_)), expected.len() == 1);
        }
        assert!(index[&key].is_empty());
        for (snapshot, ids) in pinned {
            assert_eq!(snapshot[&key].iter().copied().collect::<BTreeSet<_>>(), ids);
        }
    }
}
