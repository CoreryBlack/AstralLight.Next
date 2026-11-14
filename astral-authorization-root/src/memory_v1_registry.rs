//! memory—v1 §4.9: The resource/action registry and its registration state machine.
//!
//! The registry is the single fact source for which resources and actions exist
//! (§4.9 A-3.7: no parallel catalogs). Its content comes from route-metadata
//! aggregation plus explicit custom declarations, and its lifecycle has exactly
//! three states. Every transition is an atomic swap under the state's write lock
//! and bumps the version counter that participates in the §4.7 dependency set.
//! The registry never grants authorization: it only defines what may be judged.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;
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

/// A code-declared resource/action set aggregated from route metadata (§4.9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryDeclaration {
    pub resource: String,
    pub actions: Vec<String>,
}

/// Registry operation failures; every one is a deterministic structural refusal.
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
    version: u64,
    entries: BTreeMap<String, RegistryEntry>,
}

/// The registry state owned by the root runtime (§4.9).
pub struct RegistryState {
    inner: RwLock<RegistryInner>,
}

impl Default for RegistryState {
    fn default() -> Self {
        Self {
            inner: RwLock::new(RegistryInner {
                installed: false,
                version: 0,
                entries: BTreeMap::new(),
            }),
        }
    }
}

impl RegistryState {
    /// Install the aggregated declarations exactly once (§4.9 A-3.8).
    ///
    /// Declarations arrive from startup route-metadata aggregation; duplicates,
    /// invalid identifiers and empty action sets fail the whole installation.
    pub fn install(&self, declarations: &[RegistryDeclaration]) -> Result<(), RegistryError> {
        let mut inner = self.inner.write().expect("registry lock");
        if inner.installed {
            return Err(RegistryError::AlreadyInstalled);
        }
        let mut entries = BTreeMap::new();
        for declaration in declarations {
            if !valid_registry_identifier(&declaration.resource) {
                return Err(RegistryError::InvalidIdentifier(
                    declaration.resource.clone(),
                ));
            }
            if entries.contains_key(&declaration.resource) {
                return Err(RegistryError::DuplicateDeclaration(
                    declaration.resource.clone(),
                ));
            }
            let mut actions = BTreeSet::new();
            for action in &declaration.actions {
                if !valid_registry_identifier(action) {
                    return Err(RegistryError::InvalidIdentifier(action.clone()));
                }
                actions.insert(action.clone());
            }
            if actions.is_empty() {
                return Err(RegistryError::InvalidIdentifier(
                    declaration.resource.clone(),
                ));
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
        inner.version = inner.version.wrapping_add(1);
        Ok(())
    }

    /// §4.9 A-3.4: every evaluated (resource, action) pair must be registered
    /// and active. Not installed, unregistered, inactive and unknown-action
    /// cases are all deterministic structural refusals.
    pub fn validate(&self, resource: &str, action: &str) -> Result<(), RegistryError> {
        let inner = self.inner.read().expect("registry lock");
        if !inner.installed {
            return Err(RegistryError::NotInstalled);
        }
        let Some(entry) = inner.entries.get(resource) else {
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

    /// §4.9: Active → RetireRequested.
    pub fn request_retire(&self, resource: &str) -> Result<(), RegistryError> {
        let mut inner = self.inner.write().expect("registry lock");
        let Some(entry) = inner.entries.get_mut(resource) else {
            return Err(RegistryError::Unregistered(resource.to_owned()));
        };
        if entry.status != RegistryStatus::Active {
            return Err(RegistryError::Inactive(resource.to_owned(), entry.status));
        }
        entry.status = RegistryStatus::RetireRequested;
        inner.version = inner.version.wrapping_add(1);
        Ok(())
    }

    /// §4.9: RetireRequested → Retired. The caller must have verified the
    /// retirement preconditions (revocation published, zero active references);
    /// a reported reference keeps the request pending instead of retiring.
    pub fn confirm_retire(&self, resource: &str, referenced: bool) -> Result<(), RegistryError> {
        let mut inner = self.inner.write().expect("registry lock");
        let Some(entry) = inner.entries.get_mut(resource) else {
            return Err(RegistryError::Unregistered(resource.to_owned()));
        };
        if entry.status != RegistryStatus::RetireRequested {
            return Err(RegistryError::Inactive(resource.to_owned(), entry.status));
        }
        if referenced {
            return Err(RegistryError::RetirementPreconditions(resource.to_owned()));
        }
        entry.status = RegistryStatus::Retired;
        inner.version = inner.version.wrapping_add(1);
        Ok(())
    }

    /// §4.9: the registry version participates in the §4.7 dependency set.
    pub fn version(&self) -> u64 {
        self.inner.read().expect("registry lock").version
    }

    /// Diagnostics: the current status of one resource.
    pub fn status(&self, resource: &str) -> Result<RegistryStatus, RegistryError> {
        let inner = self.inner.read().expect("registry lock");
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
