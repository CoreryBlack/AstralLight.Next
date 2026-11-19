//! memory—v1 §4.9: The resource/action registry and its registration state machine.
//!
//! The registry is the single fact source for which resources and actions exist
//! (§4.9 A-3.7: no parallel catalogs). Its content comes from route-metadata
//! aggregation plus explicit custom declarations, and its lifecycle has exactly
//! three states. Every transition is an atomic swap under the state's write lock
//! and bumps the version counter that participates in the §4.7 dependency set.
//! The registry never grants authorization: it only defines what may be judged.

use crate::memory_v1_rules::{MemoryV1RuleSetContent, PreparedRuleSet};
use astral_types::{
    MAX_ACTION_NAME_BYTES, MAX_CUSTOM_RESOURCE_ACTIONS, MAX_RESOURCE_TYPE_NAME_BYTES,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{RwLock, RwLockReadGuard};
use thiserror::Error;

/// Registration lifecycle states (§4.9 A-3.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryStatus {
    /// Usable by rule entries and route mappings.
    Active,
    /// A retirement request passed the engine; preconditions are pending.
    RetireRequested,
    /// Removed from every authorization surface.
    Retired,
}

/// One registered resource: its registered actions and lifecycle state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryEntry {
    pub actions: BTreeSet<String>,
    pub status: RegistryStatus,
}

/// A stable, owned view of one resource in the root registry.
///
/// This value deliberately contains no lock guard or mutation capability. It is
/// copied while the registry read lock is held and can therefore be consumed by
/// a request without keeping the registry locked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryEntryView {
    pub resource: String,
    pub actions: Vec<String>,
    pub status: RegistryStatus,
}

/// One consistent registry observation for a request or diagnostic reader.
///
/// `version` is copied under the same read lock as `entries`; callers must not
/// combine separately read versions and entries to claim one observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrySnapshot {
    pub version: u64,
    pub entries: Vec<RegistryEntryView>,
}

/// A code-declared resource/action set aggregated from route metadata (§4.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryDeclaration {
    pub resource: String,
    pub actions: Vec<String>,
}

/// Registry operation failures. An unavailable registry cannot establish a
/// deterministic membership decision.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RegistryError {
    #[error("memory-v1 registry is already installed")]
    AlreadyInstalled,
    #[error("memory-v1 registry is not installed")]
    NotInstalled,
    #[error("resource \"{0}\" is not registered")]
    Unregistered(String),
    #[error("resource \"{0}\" is registered but not active: {1:?}")]
    Inactive(String, RegistryStatus),
    #[error("action \"{1}\" is not registered for resource \"{0}\"")]
    UnknownAction(String, String),
    #[error("duplicate registry declaration for \"{0}\"")]
    DuplicateDeclaration(String),
    #[error("registry identifier \"{0}\" is invalid")]
    InvalidIdentifier(String),
    #[error("registry retirement preconditions are not met for \"{0}\"")]
    RetirementPreconditions(String),
}

/// Identifier rules inherited from the main baseline (§4.9 A-3.5): the first
/// byte must be a lowercase ASCII letter and the rest may only be lowercase
/// letters, digits, `_` or `-`. Values are rejected, never normalized.
pub fn valid_registry_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    match bytes.first() {
        Some(first) if first.is_ascii_lowercase() => {}
        _ => return false,
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_' || *b == b'-')
}

struct RegistryInner {
    installed: bool,
    exhausted: bool,
    version: u64,
    entries: BTreeMap<String, RegistryEntry>,
}

/// The registry state owned by the root runtime (§4.9).
pub struct RegistryState {
    inner: RwLock<RegistryInner>,
}

/// A stable registry observation held across root validation and publication.
/// It never escapes the root crate and cannot modify the registry.
pub(crate) struct RegistryReadGuard<'a> {
    inner: RwLockReadGuard<'a, RegistryInner>,
}

impl RegistryReadGuard<'_> {
    // memory—v1 §4.9: every entry must refer to an active registered pair.
    pub(crate) fn validate_rules(
        &self,
        content: &MemoryV1RuleSetContent,
    ) -> Result<(), RegistryError> {
        for rule in &content.rules {
            self.inner.validate(&rule.resource, &rule.action)?;
        }
        Ok(())
    }
}

impl RegistryInner {
    // memory—v1: Reserve MAX as an unavailable version in the same locked observation.
    fn is_available(&self) -> bool {
        self.installed && !self.exhausted && self.version != u64::MAX
    }

    // memory—v1: Check a pair against the registry version held by the caller.
    fn validate(&self, resource: &str, action: &str) -> Result<(), RegistryError> {
        if !self.is_available() {
            return Err(RegistryError::NotInstalled);
        }
        let Some(entry) = self.entries.get(resource) else {
            return Err(RegistryError::Unregistered(resource.to_owned()));
        };
        if entry.status != RegistryStatus::Active {
            return Err(RegistryError::Inactive(resource.to_owned(), entry.status));
        }
        if !entry.actions.contains(action) {
            return Err(RegistryError::UnknownAction(
                resource.to_owned(),
                action.to_owned(),
            ));
        }
        Ok(())
    }
}

impl Default for RegistryState {
    fn default() -> Self {
        Self {
            inner: RwLock::new(RegistryInner {
                installed: false,
                exhausted: false,
                version: 0,
                entries: BTreeMap::new(),
            }),
        }
    }
}

impl RegistryState {
    /// memory—v1 §4.9: Install the aggregated declarations exactly once.
    ///
    /// Declarations arrive from startup route-metadata aggregation; duplicates,
    /// invalid identifiers, exceeded limits and empty action sets fail the whole
    /// installation. A poisoned state is unavailable and is never recovered.
    pub fn install(&self, declarations: &[RegistryDeclaration]) -> Result<(), RegistryError> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| RegistryError::NotInstalled)?;
        if inner.installed {
            return Err(RegistryError::AlreadyInstalled);
        }
        let mut entries = BTreeMap::new();
        for declaration in declarations {
            if !valid_registry_identifier(&declaration.resource)
                || declaration.resource.len() > MAX_RESOURCE_TYPE_NAME_BYTES
            {
                return Err(RegistryError::InvalidIdentifier(
                    declaration.resource.clone(),
                ));
            }
            if entries.contains_key(&declaration.resource) {
                return Err(RegistryError::DuplicateDeclaration(
                    declaration.resource.clone(),
                ));
            }
            if declaration.actions.is_empty()
                || declaration.actions.len() > MAX_CUSTOM_RESOURCE_ACTIONS
            {
                return Err(RegistryError::InvalidIdentifier(
                    declaration.resource.clone(),
                ));
            }
            let mut actions = BTreeSet::new();
            for action in &declaration.actions {
                if !valid_registry_identifier(action) || action.len() > MAX_ACTION_NAME_BYTES {
                    return Err(RegistryError::InvalidIdentifier(action.clone()));
                }
                if !actions.insert(action.clone()) {
                    return Err(RegistryError::DuplicateDeclaration(
                        declaration.resource.clone(),
                    ));
                }
            }
            entries.insert(
                declaration.resource.clone(),
                RegistryEntry {
                    actions,
                    status: RegistryStatus::Active,
                },
            );
        }
        inner.entries = entries;
        inner.installed = true;
        // Installation is the only transition from the default, empty registry.
        inner.version = 1;
        Ok(())
    }

    /// §4.9 A-3.4: every evaluated (resource, action) pair must be registered
    /// and active. An unavailable registry cannot prove membership.
    pub fn validate(&self, resource: &str, action: &str) -> Result<(), RegistryError> {
        self.validate_with_version(resource, action).map(|_| ())
    }

    /// memory—v1 §4.7: Capture the version under the same read lock that
    /// validates the resource and action, so retirement cannot be paired with
    /// an earlier Active decision and a later version.
    pub fn validate_with_version(
        &self,
        resource: &str,
        action: &str,
    ) -> Result<u64, RegistryError> {
        let inner = self
            .inner
            .try_read()
            .map_err(|_| RegistryError::NotInstalled)?;
        inner.validate(resource, action)?;
        Ok(inner.version)
    }

    /// memory—v1 §4.9: Validate an entire parsed version under one observation.
    /// The returned version must be rechecked before an authorization ALLOW.
    pub(crate) fn validate_rules_with_version(
        &self,
        content: &MemoryV1RuleSetContent,
    ) -> Result<u64, RegistryError> {
        let inner = self
            .inner
            .try_read()
            .map_err(|_| RegistryError::NotInstalled)?;
        if !inner.is_available() {
            return Err(RegistryError::NotInstalled);
        }
        let guard = RegistryReadGuard { inner };
        guard.validate_rules(content)?;
        Ok(guard.inner.version)
    }

    // memory—v1: Validate all distinct pairs of a prepared version against the
    // current live registry. No earlier successful registry observation is reused.
    pub(crate) fn validate_prepared_with_version(
        &self,
        plan: &PreparedRuleSet,
    ) -> Result<u64, RegistryError> {
        let inner = self
            .inner
            .try_read()
            .map_err(|_| RegistryError::NotInstalled)?;
        if !inner.is_available() {
            return Err(RegistryError::NotInstalled);
        }
        for (resource, action) in plan.registry_pairs() {
            inner.validate(resource, action)?;
        }
        Ok(inner.version)
    }

    // memory—v1: Keep the active registry stable while a root snapshot is published.
    pub(crate) fn read_for_publication(&self) -> Result<RegistryReadGuard<'_>, RegistryError> {
        let inner = self.inner.read().map_err(|_| RegistryError::NotInstalled)?;
        if !inner.is_available() {
            return Err(RegistryError::NotInstalled);
        }
        Ok(RegistryReadGuard { inner })
    }

    /// memory—v1 §4.9: Active → RetireRequested.
    pub fn request_retire(&self, resource: &str) -> Result<(), RegistryError> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| RegistryError::NotInstalled)?;
        let Some(entry) = inner.entries.get(resource) else {
            return Err(RegistryError::Unregistered(resource.to_owned()));
        };
        if entry.status != RegistryStatus::Active {
            return Err(RegistryError::Inactive(resource.to_owned(), entry.status));
        }
        if inner.exhausted {
            return Err(RegistryError::NotInstalled);
        }
        let Some(next_version) = inner.version.checked_add(1) else {
            inner.exhausted = true;
            return Err(RegistryError::NotInstalled);
        };
        inner
            .entries
            .get_mut(resource)
            .expect("entry checked")
            .status = RegistryStatus::RetireRequested;
        inner.version = next_version;
        Ok(())
    }

    /// memory—v1 §4.9: RetireRequested → Retired. The caller must have verified the
    /// retirement preconditions (revocation published, zero active references);
    /// a reported reference keeps the request pending instead of retiring.
    pub fn confirm_retire(&self, resource: &str, referenced: bool) -> Result<(), RegistryError> {
        let mut inner = self
            .inner
            .write()
            .map_err(|_| RegistryError::NotInstalled)?;
        let Some(entry) = inner.entries.get(resource) else {
            return Err(RegistryError::Unregistered(resource.to_owned()));
        };
        if entry.status != RegistryStatus::RetireRequested {
            return Err(RegistryError::Inactive(resource.to_owned(), entry.status));
        }
        if referenced {
            return Err(RegistryError::RetirementPreconditions(resource.to_owned()));
        }
        if inner.exhausted {
            return Err(RegistryError::NotInstalled);
        }
        let Some(next_version) = inner.version.checked_add(1) else {
            inner.exhausted = true;
            return Err(RegistryError::NotInstalled);
        };
        inner
            .entries
            .get_mut(resource)
            .expect("entry checked")
            .status = RegistryStatus::Retired;
        inner.version = next_version;
        Ok(())
    }

    /// §4.9: the registry version participates in the §4.7 dependency set.
    pub fn version(&self) -> u64 {
        self.inner.read().map_or(u64::MAX, |inner| inner.version)
    }

    /// memory—v1: Probe registry writer availability in isolated tests.
    #[cfg(feature = "test-support")]
    pub(crate) fn write_available_for_test(&self) -> bool {
        self.inner.try_write().is_ok()
    }

    /// memory—v1: Hold a registry writer only for isolated contention tests.
    #[cfg(feature = "test-support")]
    pub(crate) fn with_write_lock_for_test<T>(&self, f: impl FnOnce() -> T) -> T {
        let _guard = self.inner.write().expect("test registry lock poisoned");
        f()
    }

    /// memory—v1: Hold an active version stable during a nonblocking final check.
    /// Contention, poisoning, exhaustion and a stale version all fail closed.
    pub(crate) fn try_with_active_version<T>(
        &self,
        version: u64,
        f: impl FnOnce() -> T,
    ) -> Option<T> {
        let inner = self.inner.try_read().ok()?;
        if !inner.is_available() || inner.version != version {
            return None;
        }
        let result = f();
        drop(inner);
        Some(result)
    }

    /// memory—v1: Check the version and availability in one observation for in-flight reads.
    #[cfg(test)]
    pub(crate) fn matches_active_version(&self, version: u64) -> bool {
        let Ok(inner) = self.inner.read() else {
            return false;
        };
        inner.is_available() && inner.version == version
    }

    /// memory—v1 §4.9: Copy the complete registry state in one nonblocking
    /// read-lock observation. Contention is unavailable and fails closed; the
    /// returned value owns all strings and never retains the registry lock.
    pub fn snapshot(&self) -> Result<RegistrySnapshot, RegistryError> {
        let inner = self
            .inner
            .try_read()
            .map_err(|_| RegistryError::NotInstalled)?;
        if !inner.is_available() {
            return Err(RegistryError::NotInstalled);
        }
        let entries = inner
            .entries
            .iter()
            .map(|(resource, entry)| RegistryEntryView {
                resource: resource.clone(),
                actions: entry.actions.iter().cloned().collect(),
                status: entry.status,
            })
            .collect();
        Ok(RegistrySnapshot {
            version: inner.version,
            entries,
        })
    }

    /// memory—v1: Diagnostic status of one resource; a poisoned state is unavailable.
    pub fn status(&self, resource: &str) -> Result<RegistryStatus, RegistryError> {
        let inner = self.inner.read().map_err(|_| RegistryError::NotInstalled)?;
        let Some(entry) = inner.entries.get(resource) else {
            return Err(RegistryError::Unregistered(resource.to_owned()));
        };
        Ok(entry.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration(resource: &str, actions: &[&str]) -> RegistryDeclaration {
        RegistryDeclaration {
            resource: resource.to_owned(),
            actions: actions.iter().map(|action| (*action).to_owned()).collect(),
        }
    }

    // memory—v1 §4.9: declaration is once-only and self-consistent.
    #[test]
    fn install_is_once_only_and_validates_declarations() {
        let registry = RegistryState::default();
        assert_eq!(
            registry.validate("permission_rule", "read"),
            Err(RegistryError::NotInstalled)
        );
        registry
            .install(&[declaration("permission_rule", &["read", "registry-read"])])
            .unwrap();
        assert_eq!(registry.install(&[]), Err(RegistryError::AlreadyInstalled));
        registry.validate("permission_rule", "read").unwrap();
        assert_eq!(
            registry.validate("permission_rule", "create"),
            Err(RegistryError::UnknownAction(
                "permission_rule".to_owned(),
                "create".to_owned()
            ))
        );
        assert_eq!(
            registry.validate("unknown", "read"),
            Err(RegistryError::Unregistered("unknown".to_owned()))
        );
    }

    // memory—v1 §4.9: Duplicate actions reject the entire installation.
    #[test]
    fn duplicate_actions_leave_registry_uninstalled_and_allow_valid_install() {
        let registry = RegistryState::default();
        assert_eq!(
            registry.install(&[
                declaration("valid", &["read"]),
                declaration("document", &["read", "write", "read"]),
            ]),
            Err(RegistryError::DuplicateDeclaration("document".to_owned()))
        );
        {
            let inner = registry.inner.read().unwrap();
            assert!(!inner.installed);
            assert!(!inner.exhausted);
            assert_eq!(inner.version, 0);
            assert!(inner.entries.is_empty());
        }
        assert_eq!(registry.snapshot(), Err(RegistryError::NotInstalled));

        registry
            .install(&[
                declaration("valid", &["read"]),
                declaration("document", &["read", "write"]),
            ])
            .unwrap();
        let snapshot = registry.snapshot().unwrap();
        assert_eq!(snapshot.version, 1);
        assert_eq!(snapshot.entries.len(), 2);
        assert_eq!(registry.validate("valid", "read"), Ok(()));
        assert_eq!(registry.validate("document", "read"), Ok(()));
        assert_eq!(registry.validate("document", "write"), Ok(()));
    }

    // memory—v1: Request checks do not wait for a registry writer.
    #[test]
    fn request_checks_fail_closed_while_registry_writer_is_active() {
        use std::sync::mpsc;
        use std::time::Duration;

        let registry = RegistryState::default();
        registry
            .install(&[declaration("document", &["read"])])
            .unwrap();
        let content = MemoryV1RuleSetContent::parse(
            br#"{"rules":[{"ruleId":"r","resource":"document","action":"read","effect":"ALLOW"}]}"#,
        )
        .unwrap();
        std::thread::scope(|scope| {
            let (held_tx, held_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let (result_tx, result_rx) = mpsc::channel();
            let registry_ref = &registry;
            let holder = scope.spawn(move || {
                let _guard = registry_ref.inner.write().unwrap();
                held_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            });
            held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let registry_ref = &registry;
            let content_ref = &content;
            let worker = scope.spawn(move || {
                result_tx
                    .send((
                        registry_ref.validate_with_version("document", "read"),
                        registry_ref.validate_rules_with_version(content_ref),
                    ))
                    .unwrap();
            });
            let observed = result_rx.recv_timeout(Duration::from_secs(2));
            release_tx.send(()).unwrap();
            holder.join().unwrap();
            worker.join().unwrap();
            assert_eq!(
                observed.unwrap(),
                (
                    Err(RegistryError::NotInstalled),
                    Err(RegistryError::NotInstalled)
                )
            );
        });
        assert!(registry.validate_with_version("document", "read").is_ok());
    }

    // memory—v1 §4.9 A-3.7: The public view is one stable, sorted copy and
    // carries the exact version that was observed with its entries.
    #[test]
    fn snapshot_copies_entries_and_version_under_one_observation() {
        let registry = RegistryState::default();
        registry
            .install(&[
                declaration("z_resource", &["write", "read"]),
                declaration("a_resource", &["scan", "read"]),
            ])
            .unwrap();

        let snapshot = registry.snapshot().unwrap();
        assert_eq!(snapshot.version, 1);
        assert_eq!(
            snapshot
                .entries
                .iter()
                .map(|entry| entry.resource.as_str())
                .collect::<Vec<_>>(),
            ["a_resource", "z_resource"]
        );
        assert_eq!(snapshot.entries[0].actions, ["read", "scan"]);
        assert_eq!(snapshot.entries[1].actions, ["read", "write"]);
        assert!(snapshot
            .entries
            .iter()
            .all(|entry| entry.status == RegistryStatus::Active));

        registry.request_retire("z_resource").unwrap();
        assert_eq!(snapshot.version, 1);
        assert_eq!(snapshot.entries[1].status, RegistryStatus::Active);
        let current = registry.snapshot().unwrap();
        assert_eq!(current.version, 2);
        assert_eq!(current.entries[1].status, RegistryStatus::RetireRequested);
    }

    // memory—v1: An uninstalled or exhausted registry cannot produce a
    // directory that could be mistaken for an authoritative empty set.
    #[test]
    fn snapshot_fails_closed_when_registry_is_unavailable() {
        let registry = RegistryState::default();
        assert_eq!(registry.snapshot(), Err(RegistryError::NotInstalled));

        registry
            .install(&[declaration("document", &["read"])])
            .unwrap();
        registry.inner.write().unwrap().exhausted = true;
        assert_eq!(registry.snapshot(), Err(RegistryError::NotInstalled));
    }

    // memory—v1 §4.9: A lifecycle transition is visible in the copied view;
    // callers cannot continue serving a retired resource from an old global list.
    #[test]
    fn snapshot_reports_retirement_state_and_version() {
        let registry = RegistryState::default();
        registry
            .install(&[declaration("document", &["read"])])
            .unwrap();
        registry.request_retire("document").unwrap();
        let requested = registry.snapshot().unwrap();
        assert_eq!(requested.version, 2);
        assert_eq!(requested.entries[0].status, RegistryStatus::RetireRequested);
        assert_eq!(requested.entries[0].actions, ["read"]);
        registry.confirm_retire("document", false).unwrap();
        let retired = registry.snapshot().unwrap();
        assert_eq!(retired.version, 3);
        assert_eq!(retired.entries[0].status, RegistryStatus::Retired);
    }

    // memory—v1: A directory read never waits behind a registry writer;
    // contention is PENDING/Unavailable instead of a stale or partial view.
    #[test]
    fn snapshot_fails_closed_while_registry_writer_is_active() {
        use std::sync::mpsc;
        use std::time::Duration;

        let registry = RegistryState::default();
        registry
            .install(&[declaration("document", &["read"])])
            .unwrap();
        std::thread::scope(|scope| {
            let (held_tx, held_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let registry_ref = &registry;
            let holder = scope.spawn(move || {
                let _guard = registry_ref.inner.write().unwrap();
                held_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            });
            held_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(registry.snapshot(), Err(RegistryError::NotInstalled));
            assert_eq!(registry.try_with_active_version(1, || ()), None);
            release_tx.send(()).unwrap();
            holder.join().unwrap();
        });
        assert_eq!(registry.snapshot().unwrap().version, 1);
    }

    // memory—v1 §4.7: Membership and its version must be one observation.
    #[test]
    fn validation_returns_the_version_of_the_validated_state() {
        let registry = RegistryState::default();
        registry
            .install(&[declaration("document", &["read"])])
            .unwrap();
        let observed = registry.validate_with_version("document", "read").unwrap();
        assert_eq!(observed, registry.version());

        registry.request_retire("document").unwrap();
        assert_ne!(observed, registry.version());
        assert_eq!(
            registry.validate_with_version("document", "read"),
            Err(RegistryError::Inactive(
                "document".to_owned(),
                RegistryStatus::RetireRequested
            ))
        );
    }

    // memory—v1 §4.7: exhaustion never reuses a version or admits in-flight reads.
    #[test]
    fn version_exhaustion_stops_new_and_inflight_authorization() {
        for requested_first in [false, true] {
            let registry = RegistryState::default();
            registry
                .install(&[declaration("document", &["read"])])
                .unwrap();
            if requested_first {
                registry.request_retire("document").unwrap();
            }
            registry.inner.write().unwrap().version = u64::MAX;
            assert!(!registry.matches_active_version(u64::MAX));
            assert_eq!(
                registry.validate_with_version("document", "read"),
                Err(RegistryError::NotInstalled)
            );
            assert!(matches!(
                registry.read_for_publication(),
                Err(RegistryError::NotInstalled)
            ));
            assert_eq!(registry.snapshot(), Err(RegistryError::NotInstalled));
            assert_eq!(registry.try_with_active_version(u64::MAX, || ()), None);
            let result = if requested_first {
                registry.confirm_retire("document", false)
            } else {
                registry.request_retire("document")
            };
            assert_eq!(result, Err(RegistryError::NotInstalled));
            assert_eq!(registry.version(), u64::MAX);
            assert!(!registry.matches_active_version(u64::MAX));
            assert_eq!(
                registry.validate("document", "read"),
                Err(RegistryError::NotInstalled)
            );
            assert_eq!(
                registry.status("document"),
                Ok(if requested_first {
                    RegistryStatus::RetireRequested
                } else {
                    RegistryStatus::Active
                })
            );
            assert_eq!(registry.install(&[]), Err(RegistryError::AlreadyInstalled));
        }
    }

    // memory—v1: A successful last increment immediately closes every read gate.
    #[test]
    fn reaching_max_invalidates_prior_reads_and_blocks_publication() {
        for confirm in [false, true] {
            let registry = RegistryState::default();
            registry
                .install(&[
                    declaration("document", &["read"]),
                    declaration("other", &["read"]),
                ])
                .unwrap();
            if confirm {
                registry.request_retire("other").unwrap();
            }
            registry.inner.write().unwrap().version = u64::MAX - 1;
            let observed = registry.validate_with_version("document", "read").unwrap();
            assert_eq!(observed, u64::MAX - 1);
            assert_eq!(registry.try_with_active_version(observed, || 7), Some(7));
            assert!(registry.read_for_publication().is_ok());
            let empty = MemoryV1RuleSetContent::parse(br#"{"rules":[]}"#).unwrap();
            assert_eq!(registry.validate_rules_with_version(&empty), Ok(observed));

            if confirm {
                registry.confirm_retire("other", false).unwrap();
            } else {
                registry.request_retire("other").unwrap();
            }
            assert_eq!(registry.version(), u64::MAX);
            assert!(!registry.inner.read().unwrap().exhausted);
            assert_eq!(registry.try_with_active_version(observed, || 7), None);
            assert_eq!(registry.try_with_active_version(u64::MAX, || 7), None);
            assert_eq!(
                registry.validate("document", "read"),
                Err(RegistryError::NotInstalled)
            );
            assert_eq!(
                registry.validate_rules_with_version(&empty),
                Err(RegistryError::NotInstalled)
            );
            assert!(matches!(
                registry.read_for_publication(),
                Err(RegistryError::NotInstalled)
            ));
            assert_eq!(registry.snapshot(), Err(RegistryError::NotInstalled));
        }
    }

    // memory—v1: A poisoned registry cannot validate a request or its observation.
    #[test]
    fn poisoned_registry_fails_closed_without_reusing_a_version() {
        let registry = RegistryState::default();
        registry
            .install(&[declaration("document", &["read"])])
            .unwrap();
        let observed = registry.version();
        std::thread::scope(|scope| {
            let result = scope
                .spawn(|| {
                    let _guard = registry.inner.write().unwrap();
                    panic!("poison registry for test");
                })
                .join();
            assert!(result.is_err());
        });
        assert_eq!(
            registry.validate("document", "read"),
            Err(RegistryError::NotInstalled)
        );
        assert!(!registry.matches_active_version(observed));
        assert_eq!(registry.try_with_active_version(observed, || ()), None);
        assert!(matches!(
            registry.read_for_publication(),
            Err(RegistryError::NotInstalled)
        ));
        assert_eq!(registry.snapshot(), Err(RegistryError::NotInstalled));
        assert_eq!(registry.version(), u64::MAX);
        assert_eq!(
            registry.status("document"),
            Err(RegistryError::NotInstalled)
        );
        assert_eq!(
            registry.request_retire("document"),
            Err(RegistryError::NotInstalled)
        );
        assert_eq!(
            registry.confirm_retire("document", false),
            Err(RegistryError::NotInstalled)
        );
        assert_eq!(registry.install(&[]), Err(RegistryError::NotInstalled));
    }

    // memory—v1 §4.9 A-3.5: identifiers are rejected, never normalized.
    #[test]
    fn invalid_identifiers_are_rejected() {
        let registry = RegistryState::default();
        for bad in ["Permission", "1resource", "has space", "under.dot"] {
            assert_eq!(
                registry.install(&[declaration(bad, &["read"])]),
                Err(RegistryError::InvalidIdentifier(bad.to_owned()))
            );
        }
    }

    // memory—v1 §4.9: Boundary-sized declarations install together; one
    // oversized declaration leaves the registry empty and available to retry.
    #[test]
    fn declaration_limits_are_enforced_atomically() {
        let max_resource = "r".repeat(MAX_RESOURCE_TYPE_NAME_BYTES);
        let max_action = "a".repeat(MAX_ACTION_NAME_BYTES);
        let actions: Vec<String> = (0..MAX_CUSTOM_RESOURCE_ACTIONS)
            .map(|index| format!("action-{index}"))
            .collect();
        let bounded = RegistryDeclaration {
            resource: max_resource.clone(),
            actions: std::iter::once(max_action.clone())
                .chain(
                    actions
                        .iter()
                        .take(MAX_CUSTOM_RESOURCE_ACTIONS - 1)
                        .cloned(),
                )
                .collect(),
        };
        let registry = RegistryState::default();
        registry.install(std::slice::from_ref(&bounded)).unwrap();
        assert_eq!(registry.validate(&max_resource, &max_action), Ok(()));
        assert_eq!(
            registry.validate(&max_resource, &actions[MAX_CUSTOM_RESOURCE_ACTIONS - 2]),
            Ok(())
        );

        let oversized_resource = format!("{max_resource}x");
        let oversized_action = format!("{max_action}x");
        let invalid = [
            RegistryDeclaration {
                resource: oversized_resource.clone(),
                actions: vec!["read".to_owned()],
            },
            RegistryDeclaration {
                resource: "document".to_owned(),
                actions: vec![oversized_action.clone()],
            },
            RegistryDeclaration {
                resource: "document".to_owned(),
                actions: (0..=MAX_CUSTOM_RESOURCE_ACTIONS)
                    .map(|index| format!("action-{index}"))
                    .collect(),
            },
        ];
        for (invalid_declaration, expected) in
            invalid
                .into_iter()
                .zip([oversized_resource, oversized_action, "document".to_owned()])
        {
            let registry = RegistryState::default();
            assert_eq!(
                registry.install(&[declaration("valid", &["read"]), invalid_declaration]),
                Err(RegistryError::InvalidIdentifier(expected))
            );
            assert_eq!(registry.version(), 0);
            assert_eq!(
                registry.validate("valid", "read"),
                Err(RegistryError::NotInstalled)
            );
            registry.install(std::slice::from_ref(&bounded)).unwrap();
            assert_eq!(registry.validate(&max_resource, &max_action), Ok(()));
        }
    }

    // memory—v1 §4.9 A-3.9: the three-state lifecycle with preconditions.
    #[test]
    fn retirement_state_machine_requires_preconditions() {
        let registry = RegistryState::default();
        registry
            .install(&[declaration("legacy", &["read"])])
            .unwrap();
        let before = registry.version();
        registry.request_retire("legacy").unwrap();
        assert_eq!(registry.version(), before.wrapping_add(1));
        assert_eq!(
            registry.status("legacy"),
            Ok(RegistryStatus::RetireRequested)
        );
        // A referenced resource keeps the request pending.
        assert_eq!(
            registry.confirm_retire("legacy", true),
            Err(RegistryError::RetirementPreconditions("legacy".to_owned()))
        );
        assert_eq!(
            registry.status("legacy"),
            Ok(RegistryStatus::RetireRequested)
        );
        registry.confirm_retire("legacy", false).unwrap();
        assert_eq!(registry.status("legacy"), Ok(RegistryStatus::Retired));
        assert_eq!(registry.version(), before.wrapping_add(2));
    }
}
