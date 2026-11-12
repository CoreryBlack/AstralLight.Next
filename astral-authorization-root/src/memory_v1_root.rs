//! memory—v1: One process-local root over the prebuilt object relationships.
//!
//! The registry installs at most one root for its composition scope. The process
//! entry point uses the process registry; isolated registries exist for tests and
//! explicitly isolated compositions. A root snapshot owns the supplied objects
//! and the HAMT-derived relationship indexes. Readers load one immutable snapshot
//! and do not take a root `RwLock` while traversing it.
//!
//! This module does not establish database provenance, complete coverage,
//! confirmation validity, rule semantics, or formal authorization. The current
//! installer creates a candidate root; it does not mark it as production-serving.

use std::sync::{Arc, OnceLock, Weak};

use arc_swap::ArcSwap;
use thiserror::Error;
use uuid::Uuid;

use crate::memory_v1_db_rows::{BinaryId, CandidateRows, CurrentSelection};
use crate::memory_v1_digest::ContentDigest;
use crate::memory_v1_hamt::{
    CandidateBudget, CandidateError, HamtCandidate, RuleSetImpactCandidate,
};
use crate::memory_v1_hamt_runtime::{digest_candidate, RuntimeCardContext, RuntimeError};

/// Process-local identity of one installed root instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RootInstanceId(Uuid);

impl RootInstanceId {
    /// memory—v1: Expose the UUID representation for diagnostics and correlation.
    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// Lifecycle state carried by the current root snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootStatus {
    /// The object graph is installed as an experimental candidate.
    Candidate,
    /// The root has passed a separately implemented adoption gate.
    Serving,
    /// Positive authorization is unavailable until controlled recovery.
    Invalid,
    /// The owner is no longer accepting reads.
    Stopped,
}

/// Metadata captured atomically with one root snapshot load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootMetadata {
    /// Process-local instance identity; a restart creates a new value.
    pub instance_id: RootInstanceId,
    /// Monotonic root update sequence within this instance.
    pub version: u64,
    /// Digest of the explicitly supplied candidate fields and selections.
    pub digest: ContentDigest,
    /// Candidate limits used to build the object graph.
    pub budget: CandidateBudget,
    /// Number of rows in the nine supplied tables.
    pub row_count: usize,
    /// Current lifecycle state.
    pub status: RootStatus,
}

/// A root observation bound to one exact root instance and snapshot metadata.
#[derive(Clone)]
pub struct RootObservation {
    owner: Weak<RootRuntime>,
    metadata: RootMetadata,
}

impl RootObservation {
    /// memory—v1: Return the metadata captured with a root read.
    pub fn metadata(self) -> RootMetadata {
        self.metadata
    }
}

/// A value produced from one coherent immutable root snapshot.
pub struct RootRead<T> {
    /// The callback result derived from one snapshot.
    pub value: T,
    /// The metadata observation to recheck before a positive decision.
    pub observation: RootObservation,
}

struct RootSnapshot {
    metadata: RootMetadata,
    objects: HamtCandidate,
}

struct RootRuntime {
    current: ArcSwap<RootSnapshot>,
}

/// A cloneable read capability for the one installed root.
///
/// The weak reference prevents a consumer handle from extending the owner
/// lifetime. It points at the same runtime; it never contains an independent
/// object graph and exposes no mutation operation.
#[derive(Clone)]
pub struct RootHandle {
    runtime: Weak<RootRuntime>,
}

/// The non-cloneable lifetime owner of one installed root.
///
/// The composition root must retain this value until every consumer has
/// stopped. Dropping it invalidates weak consumer handles; the registry keeps
/// only the one-time installation marker and does not keep a second strong root.
pub struct RootOwner {
    runtime: Arc<RootRuntime>,
}

/// Installation and lifetime owner for one root in one composition scope.
///
/// The process-wide installer is the only production entry point. This registry
/// type remains private so another crate cannot create a second process root;
/// unit tests use it to isolate their own composition scopes.
struct RootRegistry {
    slot: OnceLock<Weak<RootRuntime>>,
}

/// The process-wide installation slot used by the single-node composition root.
static PROCESS_ROOT: RootRegistry = RootRegistry::new();

/// Errors from root installation or immutable root reads.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RootError {
    /// A registry already has a root installed.
    #[error("memory-v1 root is already installed")]
    AlreadyInstalled,
    /// The registry has no installed root.
    #[error("memory-v1 root is not installed")]
    NotInstalled,
    /// The owner was dropped before the consumer read.
    #[error("memory-v1 root owner is gone")]
    OwnerGone,
    /// The root status does not permit the requested read.
    #[error("memory-v1 root status is not readable: {0:?}")]
    Unavailable(RootStatus),
    /// Candidate row validation failed.
    #[error("memory-v1 candidate validation failed: {0:?}")]
    Candidate(CandidateError),
    /// Candidate digest construction failed.
    #[error("memory-v1 candidate digest failed: {0:?}")]
    Runtime(RuntimeError),
    /// Candidate row relationships were not closed.
    #[error("memory-v1 candidate relationships are incomplete")]
    InconsistentCandidate,
    /// A root observation belongs to a different installed root.
    #[error("memory-v1 root observation belongs to another owner")]
    ForeignOwner,
}

impl RootRegistry {
    /// memory—v1: Create an empty installation scope.
    pub const fn new() -> Self {
        Self {
            slot: OnceLock::new(),
        }
    }

    /// memory—v1: Install one candidate object graph and return its read handle.
    ///
    /// Construction validates the supplied references and builds all indexes
    /// before publication. The candidate remains non-authorizing; a future
    /// adoption gate must explicitly prove completeness before `Serving`.
    pub fn install_candidate(
        &self,
        rows: CandidateRows,
        selections: Vec<CurrentSelection>,
        budget: CandidateBudget,
    ) -> Result<RootOwner, RootError> {
        let digest = digest_candidate(&rows, &selections).map_err(RootError::Runtime)?;
        let objects =
            HamtCandidate::build(rows, selections, budget).map_err(RootError::Candidate)?;
        let (actual_budget, row_count) = objects.budget_and_row_count();
        let metadata = RootMetadata {
            instance_id: RootInstanceId(Uuid::new_v4()),
            version: 0,
            digest,
            budget: actual_budget,
            row_count,
            status: RootStatus::Candidate,
        };
        let runtime = Arc::new(RootRuntime {
            current: ArcSwap::from_pointee(RootSnapshot { metadata, objects }),
        });
        self.slot
            .set(Arc::downgrade(&runtime))
            .map_err(|_| RootError::AlreadyInstalled)?;
        Ok(RootOwner { runtime })
    }

    /// memory—v1: Return a read handle for the already installed root.
    pub fn handle(&self) -> Result<RootHandle, RootError> {
        let runtime = self
            .slot
            .get()
            .ok_or(RootError::NotInstalled)?
            .upgrade()
            .ok_or(RootError::OwnerGone)?;
        Ok(RootHandle {
            runtime: Arc::downgrade(&runtime),
        })
    }
}

impl Default for RootRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// memory—v1: Install the one process-wide candidate root.
pub fn install_process_root(
    rows: CandidateRows,
    selections: Vec<CurrentSelection>,
    budget: CandidateBudget,
) -> Result<RootOwner, RootError> {
    PROCESS_ROOT.install_candidate(rows, selections, budget)
}

/// memory—v1: Obtain a handle to the process-wide root after installation.
pub fn process_root_handle() -> Result<RootHandle, RootError> {
    PROCESS_ROOT.handle()
}

impl RootOwner {
    /// memory—v1: Create the read capability distributed to consumers.
    pub fn handle(&self) -> RootHandle {
        RootHandle {
            runtime: Arc::downgrade(&self.runtime),
        }
    }
}

impl Drop for RootOwner {
    // memory—v1: Consumer handles become unavailable before a replacement root can exist.
    fn drop(&mut self) {
        let current = self.runtime.current.load_full();
        let mut metadata = current.metadata;
        metadata.status = RootStatus::Stopped;
        self.runtime.current.store(Arc::new(RootSnapshot {
            metadata,
            objects: current.objects.clone(),
        }));
    }
}

impl RootHandle {
    fn runtime(&self) -> Result<Arc<RootRuntime>, RootError> {
        self.runtime.upgrade().ok_or(RootError::OwnerGone)
    }

    fn snapshot(&self) -> Result<Arc<RootSnapshot>, RootError> {
        let runtime = self.runtime()?;
        let snapshot = runtime.current.load_full();
        match snapshot.metadata.status {
            RootStatus::Candidate | RootStatus::Serving => Ok(snapshot),
            status => Err(RootError::Unavailable(status)),
        }
    }

    /// memory—v1: Load metadata from the current immutable root snapshot.
    pub fn metadata(&self) -> Result<RootMetadata, RootError> {
        Ok(self.snapshot()?.metadata)
    }

    /// memory—v1: Read one pre-indexed card relationship from one root snapshot.
    ///
    /// The callback runs after the atomic snapshot pointer is loaded; no root
    /// lock is held during relationship traversal or rule matching. Borrowed
    /// rows cannot escape the callback, while the returned value is owned.
    pub fn read_card<T>(
        &self,
        card_id: BinaryId,
        f: impl for<'a> FnOnce(RuntimeCardContext<'a>) -> T,
    ) -> Result<RootRead<T>, RootError> {
        let runtime = self.runtime()?;
        let snapshot = self.snapshot()?;
        let card = snapshot
            .objects
            .card_candidate(card_id)
            .map_err(RootError::Candidate)?;
        let user = snapshot
            .objects
            .user(card.card.user_id)
            .ok_or(RootError::InconsistentCandidate)?;
        let identity = snapshot
            .objects
            .identity_for_user(card.card.user_id)
            .ok_or(RootError::InconsistentCandidate)?;
        let tenant = snapshot
            .objects
            .tenant(card.card.tenant_id)
            .ok_or(RootError::InconsistentCandidate)?;
        let mut bindings = Vec::with_capacity(card.bindings.len());
        for binding in card.bindings {
            bindings.push(crate::memory_v1_hamt_runtime::RuntimeBindingContext {
                binding,
                rule_set: snapshot
                    .objects
                    .rule_set(binding.rule_set_id)
                    .ok_or(RootError::InconsistentCandidate)?,
                selected: snapshot
                    .objects
                    .selected_version(binding.rule_set_id)
                    .map_err(RootError::Candidate)?,
                confirmations: snapshot
                    .objects
                    .binding_confirmations(binding.binding_id)
                    .map_err(RootError::Candidate)?,
                change_confirmations: snapshot
                    .objects
                    .change_confirmations(binding.rule_set_id)
                    .map_err(RootError::Candidate)?,
            });
        }
        let value = f(RuntimeCardContext {
            user,
            identity,
            card: card.card,
            tenant,
            bindings,
        });
        Ok(RootRead {
            value,
            observation: RootObservation {
                owner: Arc::downgrade(&runtime),
                metadata: snapshot.metadata,
            },
        })
    }

    /// memory—v1: Read direct reverse relationships from the same root snapshot.
    pub fn read_impact(
        &self,
        rule_set_id: BinaryId,
    ) -> Result<RootRead<RuleSetImpactCandidate>, RootError> {
        let runtime = self.runtime()?;
        let snapshot = self.snapshot()?;
        let value = snapshot
            .objects
            .rule_set_impact(rule_set_id)
            .map_err(RootError::Candidate)?;
        Ok(RootRead {
            value,
            observation: RootObservation {
                owner: Arc::downgrade(&runtime),
                metadata: snapshot.metadata,
            },
        })
    }

    /// memory—v1: Recheck the same root instance and snapshot metadata.
    pub fn is_current(&self, observation: &RootObservation) -> Result<bool, RootError> {
        if !Weak::ptr_eq(&self.runtime, &observation.owner) {
            return Err(RootError::ForeignOwner);
        }
        let runtime = self.runtime()?;
        let current = runtime.current.load_full();
        Ok(current.metadata == observation.metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_v1_db_rows::{
        BindingLayer, BindingRow, IdentityCardRow, RuleSetRow, RuleSetVersionRow, TenantRow,
        UserCardRow, UserRow,
    };

    fn id(value: u8) -> BinaryId {
        [value; 16]
    }

    fn rows() -> CandidateRows {
        CandidateRows {
            users: vec![UserRow { user_id: id(1) }],
            identity_cards: vec![IdentityCardRow {
                identity_card_id: id(2),
                user_id: id(1),
            }],
            tenants: vec![TenantRow {
                tenant_id: id(3),
                parent_tenant_id: None,
            }],
            user_cards: vec![UserCardRow {
                user_card_id: id(4),
                user_id: id(1),
                tenant_id: id(3),
            }],
            rule_sets: vec![RuleSetRow {
                rule_set_id: id(5),
                owner_tenant_id: id(3),
            }],
            rule_set_versions: vec![RuleSetVersionRow {
                rule_set_id: id(5),
                version_bytes: vec![1],
                content_bytes: vec![1],
                timestamp_bytes: vec![1],
                hash_input_bytes: vec![1],
                hash_bytes: vec![1],
            }],
            bindings: vec![BindingRow {
                binding_id: id(6),
                user_card_id: id(4),
                rule_set_id: id(5),
                binding_layer: BindingLayer::Base,
            }],
            ..CandidateRows::default()
        }
    }

    fn budget() -> CandidateBudget {
        CandidateBudget {
            max_table_rows: 32,
            max_bindings_per_read: 4,
        }
    }

    #[test]
    // memory—v1: One registry publishes one root and all handles read its graph.
    fn one_registry_shares_one_prebuilt_relationship_database() {
        let registry = RootRegistry::new();
        let owner = registry
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let first = owner.handle();
        let second = registry.handle().unwrap();
        let first_metadata = first.metadata().unwrap();
        assert_eq!(first_metadata.status, RootStatus::Candidate);
        assert_eq!(first_metadata.row_count, 7);
        let read = second
            .read_card(id(4), |context| {
                (
                    context.user.user_id,
                    context.identity.identity_card_id,
                    context.card.user_card_id,
                    context.tenant.tenant_id,
                    context.bindings.len(),
                )
            })
            .unwrap();
        assert_eq!(read.value, (id(1), id(2), id(4), id(3), 1));
        assert!(first.is_current(&read.observation).unwrap());
        assert_eq!(first.metadata().unwrap(), second.metadata().unwrap());
    }

    #[test]
    // memory—v1: A second installation is rejected before another root is visible.
    fn duplicate_installation_is_rejected() {
        let registry = RootRegistry::new();
        registry
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        assert!(matches!(
            registry.install_candidate(rows(), vec![], budget()),
            Err(RootError::AlreadyInstalled)
        ));
    }

    #[test]
    // memory—v1: A consumer handle cannot keep a dropped composition owner alive.
    fn handle_does_not_extend_registry_lifetime() {
        let handle = {
            let registry = RootRegistry::new();
            let owner = registry
                .install_candidate(rows(), vec![], budget())
                .unwrap();
            owner.handle()
        };
        assert_eq!(handle.metadata(), Err(RootError::OwnerGone));
    }

    #[test]
    // memory—v1: Shared BASE stays shared while one card has an isolated OVERLAY.
    fn shared_base_and_card_overlay_are_indexed_in_one_root() {
        let rows = CandidateRows {
            users: vec![
                UserRow { user_id: id(1) },
                UserRow { user_id: id(2) },
                UserRow { user_id: id(3) },
            ],
            identity_cards: vec![
                IdentityCardRow {
                    identity_card_id: id(11),
                    user_id: id(1),
                },
                IdentityCardRow {
                    identity_card_id: id(12),
                    user_id: id(2),
                },
                IdentityCardRow {
                    identity_card_id: id(13),
                    user_id: id(3),
                },
            ],
            tenants: vec![TenantRow {
                tenant_id: id(20),
                parent_tenant_id: None,
            }],
            user_cards: vec![
                UserCardRow {
                    user_card_id: id(21),
                    user_id: id(1),
                    tenant_id: id(20),
                },
                UserCardRow {
                    user_card_id: id(22),
                    user_id: id(2),
                    tenant_id: id(20),
                },
                UserCardRow {
                    user_card_id: id(23),
                    user_id: id(3),
                    tenant_id: id(20),
                },
            ],
            rule_sets: vec![
                RuleSetRow {
                    rule_set_id: id(30),
                    owner_tenant_id: id(20),
                },
                RuleSetRow {
                    rule_set_id: id(31),
                    owner_tenant_id: id(20),
                },
            ],
            rule_set_versions: vec![
                RuleSetVersionRow {
                    rule_set_id: id(30),
                    version_bytes: vec![1],
                    content_bytes: vec![30],
                    timestamp_bytes: vec![1],
                    hash_input_bytes: vec![30],
                    hash_bytes: vec![30],
                },
                RuleSetVersionRow {
                    rule_set_id: id(31),
                    version_bytes: vec![1],
                    content_bytes: vec![31],
                    timestamp_bytes: vec![1],
                    hash_input_bytes: vec![31],
                    hash_bytes: vec![31],
                },
            ],
            bindings: vec![
                BindingRow {
                    binding_id: id(40),
                    user_card_id: id(21),
                    rule_set_id: id(30),
                    binding_layer: BindingLayer::Base,
                },
                BindingRow {
                    binding_id: id(41),
                    user_card_id: id(22),
                    rule_set_id: id(30),
                    binding_layer: BindingLayer::Base,
                },
                BindingRow {
                    binding_id: id(42),
                    user_card_id: id(23),
                    rule_set_id: id(30),
                    binding_layer: BindingLayer::Base,
                },
                BindingRow {
                    binding_id: id(43),
                    user_card_id: id(23),
                    rule_set_id: id(31),
                    binding_layer: BindingLayer::Overlay,
                },
            ],
            ..CandidateRows::default()
        };
        let owner = RootRegistry::new()
            .install_candidate(
                rows,
                vec![
                    CurrentSelection {
                        rule_set_id: id(30),
                        version_bytes: vec![1],
                    },
                    CurrentSelection {
                        rule_set_id: id(31),
                        version_bytes: vec![1],
                    },
                ],
                CandidateBudget {
                    max_table_rows: 64,
                    max_bindings_per_read: 4,
                },
            )
            .unwrap();
        let handle = owner.handle();

        let layers_for = |card_id| {
            handle
                .read_card(card_id, |context| {
                    context
                        .bindings
                        .iter()
                        .map(|binding| (binding.binding.rule_set_id, binding.binding.binding_layer))
                        .collect::<Vec<_>>()
                })
                .unwrap()
                .value
        };
        assert_eq!(layers_for(id(21)), vec![(id(30), BindingLayer::Base)]);
        assert_eq!(layers_for(id(22)), vec![(id(30), BindingLayer::Base)]);
        let mut special_layers = layers_for(id(23));
        special_layers.sort_by_key(|(rule_set_id, layer)| {
            (*rule_set_id, matches!(layer, BindingLayer::Overlay))
        });
        assert_eq!(
            special_layers,
            vec![
                (id(30), BindingLayer::Base),
                (id(31), BindingLayer::Overlay),
            ]
        );
    }

    #[test]
    // memory—v1: Different registries are isolated test scopes, not shared consumers.
    fn foreign_observation_is_rejected() {
        let first_registry = RootRegistry::new();
        let second_registry = RootRegistry::new();
        let first_owner = first_registry
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let first = first_owner.handle();
        let second_owner = second_registry
            .install_candidate(rows(), vec![], budget())
            .unwrap();
        let second = second_owner.handle();
        let observation = first
            .read_card(id(4), |context| context.card.user_card_id)
            .unwrap()
            .observation;
        assert_eq!(
            second.is_current(&observation),
            Err(RootError::ForeignOwner)
        );
    }
}
