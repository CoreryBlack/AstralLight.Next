//! memory—v1: Candidate evaluation of an ordered batch of binding confirmations.
//!
//! Each target is resolved from one request root and uses the same card evaluator
//! as ordinary authorization. The result is not a commit authorization: ordered
//! mutation binding, replay control and persistent audit remain separate duties.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use astral_authorization_root::memory_v1_db_rows::BinaryId;
use astral_authorization_root::memory_v1_request::RequestRootExtension;
use astral_authorization_root::memory_v1_root::{
    DependencyRecord, RootError, RootMetadata, RootStatus,
};
use astral_authorization_root::memory_v1_session::{
    FinalCheckTimeConstraints, FinalCheckWindow, RequestSessionExtension, SessionFinalCheck,
};
use astral_types::memory_v1::CandidateIdentity;

use crate::memory_v1_formal::{
    capture_deny_observation, evaluate_card_candidate, CardOutcome, MemoryV1Decision,
    MemoryV1DenyObservation, MemoryV1DenySource, MemoryV1PendingSource, MemoryV1Request,
};

/// Hard resource bound; the governance owner may apply a lower operational limit.
pub const MAX_MEMORY_V1_BINDING_CONFIRMATION_BATCH: usize = 64;
const MAX_OPERATION_ID_BYTES: usize = 64;
const HTTP_FINGERPRINT_BYTES: usize = 64;

/// One ordered target. Ownership and tenant attribution are always read from the root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryV1BatchItem {
    pub sequence: u32,
    pub binding_id: BinaryId,
    pub confirmation_id: BinaryId,
}

/// The complete ordered request and its caller-supplied correlation fields.
#[derive(Clone, Copy, Debug)]
pub struct MemoryV1BatchRequest<'a> {
    pub operation_id: &'a [u8],
    pub operation_fingerprint: &'a [u8],
    pub items: &'a [MemoryV1BatchItem],
}

/// One target derived from the request root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryV1BatchTarget {
    pub item: MemoryV1BatchItem,
    pub user_card_id: BinaryId,
    pub rule_set_id: BinaryId,
    pub beneficiary_user_id: BinaryId,
    pub tenant_id: BinaryId,
}

/// A read-side batch observation; it is not a mutation capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryV1BatchAdmission {
    root: RootMetadata,
    identity: CandidateIdentity,
    operation_id: Vec<u8>,
    operation_fingerprint: Vec<u8>,
    trusted_time_unix_seconds: i64,
    targets: Vec<MemoryV1BatchTarget>,
}

impl MemoryV1BatchAdmission {
    /// memory—v1: Return the observed root metadata.
    pub fn root(&self) -> RootMetadata {
        self.root
    }

    /// memory—v1: Return the session identity used during evaluation.
    pub fn identity(&self) -> CandidateIdentity {
        self.identity
    }

    /// memory—v1: Return the supplied operation identifier.
    pub fn operation_id(&self) -> &[u8] {
        &self.operation_id
    }

    /// memory—v1: Return the supplied request fingerprint.
    pub fn operation_fingerprint(&self) -> &[u8] {
        &self.operation_fingerprint
    }

    /// memory—v1: Return the final trusted-time observation.
    pub fn trusted_time_unix_seconds(&self) -> i64 {
        self.trusted_time_unix_seconds
    }

    /// memory—v1: Return the ordered targets resolved in this read phase.
    pub fn targets(&self) -> &[MemoryV1BatchTarget] {
        &self.targets
    }
}

/// Result of the common batch evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryV1BatchEvaluation {
    pub decision: MemoryV1Decision,
    pub deny_source: Option<MemoryV1DenySource>,
    pub pending_source: Option<MemoryV1PendingSource>,
    pub admission: Option<MemoryV1BatchAdmission>,
    /// Read-phase facts for the selected resolved DENY item, when available.
    pub deny_observation: Option<Box<MemoryV1DenyObservation>>,
}

// memory—v1: Preserve the reason without manufacturing an admission.
fn non_allow(
    decision: MemoryV1Decision,
    deny_source: Option<MemoryV1DenySource>,
    pending_source: Option<MemoryV1PendingSource>,
) -> MemoryV1BatchEvaluation {
    MemoryV1BatchEvaluation {
        decision,
        deny_source,
        pending_source,
        admission: None,
        deny_observation: None,
    }
}

// memory—v1: Use a single start time and the root-owned common final check.
fn evaluate_with(
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    request: &MemoryV1BatchRequest<'_>,
    clock: impl FnOnce() -> Option<i64>,
    after_read: impl FnOnce(),
    final_time: impl FnOnce(
        &SessionFinalCheck<'_>,
        &DependencyRecord,
        &FinalCheckTimeConstraints<'_>,
        RootMetadata,
        &[BinaryId],
    ) -> Option<i64>,
) -> MemoryV1BatchEvaluation {
    let pending = || {
        non_allow(
            MemoryV1Decision::Pending,
            None,
            Some(MemoryV1PendingSource::ContextInvalid),
        )
    };
    if request.operation_id.is_empty()
        || request.operation_id.len() > MAX_OPERATION_ID_BYTES
        || !request
            .operation_id
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/".contains(byte))
        || request.operation_fingerprint.len() != HTTP_FINGERPRINT_BYTES
        || !request
            .operation_fingerprint
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        || request.items.is_empty()
        || request.items.len() > MAX_MEMORY_V1_BINDING_CONFIRMATION_BATCH
    {
        return pending();
    }
    let mut bindings = HashSet::with_capacity(request.items.len());
    let mut confirmations = HashSet::with_capacity(request.items.len());
    for (position, item) in request.items.iter().enumerate() {
        if item.sequence as usize != position
            || item.binding_id == [0; 16]
            || item.confirmation_id == [0; 16]
            || !bindings.insert(item.binding_id)
            || !confirmations.insert(item.confirmation_id)
        {
            return pending();
        }
    }

    session
        .with_authoritative_context(root, |facts, reader, check| {
            let Some(check) = check else { return pending() };
            let Some(start) = clock() else {
                return pending();
            };
            let metadata = reader.metadata();
            if metadata.status != RootStatus::Serving || !facts.valid_at(start) {
                return pending();
            }
            let mut targets = Vec::with_capacity(request.items.len());
            let mut target_rule_sets = Vec::with_capacity(request.items.len());
            let mut unresolved_target = false;
            for item in request.items {
                let target = match reader.binding_target(item.binding_id) {
                    Ok(target) => target,
                    // An absent binding is an unresolved target, not a reason to
                    // stop inspecting the other targets. A later proven
                    // self-beneficiary still deterministically denies the batch.
                    Err(RootError::InconsistentCandidate) => {
                        unresolved_target = true;
                        continue;
                    }
                    Err(_) => {
                        return non_allow(
                            MemoryV1Decision::Pending,
                            None,
                            Some(MemoryV1PendingSource::RootUnavailable),
                        );
                    }
                };
                if target.user_card_id == [0; 16]
                    || target.rule_set_id == [0; 16]
                    || target.owner_user_id == [0; 16]
                    || target.tenant_id == [0; 16]
                {
                    return non_allow(
                        MemoryV1Decision::Pending,
                        None,
                        Some(MemoryV1PendingSource::ContextInvalid),
                    );
                }
                match reader.is_fenced(target.rule_set_id) {
                    Ok(false) => {}
                    // §4.7 requires an immediate conservative PENDING for any
                    // resolved target in an active modification window. In
                    // particular, do not use this target's attribution for SoD.
                    Ok(true) => {
                        return non_allow(
                            MemoryV1Decision::Pending,
                            None,
                            Some(MemoryV1PendingSource::FenceActive),
                        )
                    }
                    Err(_) => {
                        return non_allow(
                            MemoryV1Decision::Pending,
                            None,
                            Some(MemoryV1PendingSource::RootUnavailable),
                        )
                    }
                }
                target_rule_sets.push(target.rule_set_id);
                targets.push(MemoryV1BatchTarget {
                    item: *item,
                    user_card_id: target.user_card_id,
                    rule_set_id: target.rule_set_id,
                    beneficiary_user_id: target.owner_user_id,
                    tenant_id: target.tenant_id,
                });
            }

            let mut invalid_target = false;
            for target in &targets {
                match reader.confirmation_target_is_available(
                    target.item.binding_id,
                    target.item.confirmation_id,
                ) {
                    Ok(true) => {}
                    Ok(false) => invalid_target = true,
                    Err(_) => {
                        return non_allow(
                            MemoryV1Decision::Pending,
                            None,
                            Some(MemoryV1PendingSource::RootUnavailable),
                        );
                    }
                }
            }
            if let Some(target) = targets.iter().find(|target| {
                target.beneficiary_user_id == facts.candidate_identity().user_id.into_bytes()
            }) {
                let source = MemoryV1DenySource::SelfConfirmation;
                let single = MemoryV1Request {
                    resource: "binding",
                    action: "confirm",
                    target: Some(&target.item.binding_id),
                    target_tenant: Some(&target.tenant_id),
                    target_owner: Some(&target.beneficiary_user_id),
                    operation_id: request.operation_id,
                    operation_fingerprint: request.operation_fingerprint,
                };
                let mut result = non_allow(MemoryV1Decision::Deny, Some(source), None);
                result.deny_observation = Some(capture_deny_observation(
                    metadata,
                    facts,
                    start,
                    &single,
                    source,
                    Some(target.item.sequence),
                ));
                return result;
            }
            let mut record = None;
            let mut windows = Vec::new();
            let mut boundaries = Vec::new();
            // A resolved structural conflict cannot hide a deterministic denial,
            // but it must still prevent admission when no target is denied.
            let mut pending_source = if unresolved_target {
                Some(MemoryV1PendingSource::ContextInvalid)
            } else {
                invalid_target.then_some(MemoryV1PendingSource::ContextInvalid)
            };
            let mut deny_source = None;
            for target in &targets {
                let single = MemoryV1Request {
                    resource: "binding",
                    action: "confirm",
                    target: Some(&target.item.binding_id),
                    target_tenant: Some(&target.tenant_id),
                    target_owner: Some(&target.beneficiary_user_id),
                    operation_id: request.operation_id,
                    operation_fingerprint: request.operation_fingerprint,
                };
                match evaluate_card_candidate(facts, reader, &single, start, false) {
                    CardOutcome::Deny(source) => {
                        deny_source.get_or_insert((source, target));
                    }
                    CardOutcome::Pending(source) => {
                        pending_source.get_or_insert(source);
                    }
                    CardOutcome::Allow {
                        dependencies,
                        winning_allows,
                        future_boundaries,
                        tree_version,
                        registry_version,
                        ..
                    } => {
                        let dependency = DependencyRecord {
                            card_id: facts.candidate_identity().user_card_id.into_bytes(),
                            instance_id: metadata.instance_id,
                            bindings: dependencies,
                            tenant_tree_version: tree_version,
                            registry_version,
                        };
                        if record
                            .as_ref()
                            .is_some_and(|previous| previous != &dependency)
                        {
                            pending_source.get_or_insert(MemoryV1PendingSource::ContextInvalid);
                        } else {
                            record = Some(dependency);
                        }
                        boundaries.extend(future_boundaries);
                        windows.extend(winning_allows.into_iter().map(|winning| {
                            FinalCheckWindow {
                                entry_validity: winning.entry_validity,
                                binding_from: winning.binding_from,
                                binding_until: winning.binding_until,
                            }
                        }));
                    }
                }
            }
            if let Some((source, target)) = deny_source {
                let single = MemoryV1Request {
                    resource: "binding",
                    action: "confirm",
                    target: Some(&target.item.binding_id),
                    target_tenant: Some(&target.tenant_id),
                    target_owner: Some(&target.beneficiary_user_id),
                    operation_id: request.operation_id,
                    operation_fingerprint: request.operation_fingerprint,
                };
                let mut result = non_allow(MemoryV1Decision::Deny, Some(source), None);
                result.deny_observation = Some(capture_deny_observation(
                    metadata,
                    facts,
                    start,
                    &single,
                    source,
                    Some(target.item.sequence),
                ));
                return result;
            }
            if let Some(source) = pending_source {
                return non_allow(MemoryV1Decision::Pending, None, Some(source));
            }
            let Some(record) = record else {
                return pending();
            };
            after_read();
            let constraints = FinalCheckTimeConstraints {
                start_time: start,
                future_boundaries: &boundaries,
                winning_windows: &windows,
            };
            let Some(now) = final_time(&check, &record, &constraints, metadata, &target_rule_sets)
            else {
                return pending();
            };
            MemoryV1BatchEvaluation {
                decision: MemoryV1Decision::Allow,
                deny_source: None,
                pending_source: None,
                deny_observation: None,
                admission: Some(MemoryV1BatchAdmission {
                    root: metadata,
                    identity: facts.candidate_identity(),
                    operation_id: request.operation_id.to_vec(),
                    operation_fingerprint: request.operation_fingerprint.to_vec(),
                    trusted_time_unix_seconds: now,
                    targets,
                }),
            }
        })
        .unwrap_or_else(|_| {
            non_allow(
                MemoryV1Decision::Pending,
                None,
                Some(MemoryV1PendingSource::RootUnavailable),
            )
        })
}

/// memory—v1: Evaluate one batch; this observation does not authorize a later commit.
pub(crate) fn evaluate_memory_v1_batch(
    root: &RequestRootExtension,
    session: &RequestSessionExtension,
    request: &MemoryV1BatchRequest<'_>,
) -> MemoryV1BatchEvaluation {
    evaluate_with(
        root,
        session,
        request,
        || {
            let seconds = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
            i64::try_from(seconds).ok()
        },
        || {},
        |check, record, constraints, metadata, targets| {
            check.try_final_time_exact_batch(record, constraints, metadata, targets)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use astral_authorization_root::memory_v1_db_rows::{
        BindingConfirmationRow, BindingLayer, BindingRow, CandidateRows, CurrentSelection,
        IdentityCardRow, RuleSetChangeConfirmationRow, RuleSetRow, RuleSetVersionRow, TenantRow,
        UserCardRow, UserCardStatus, UserRow,
    };
    use astral_authorization_root::memory_v1_fence::FenceDeclaration;
    use astral_authorization_root::memory_v1_hamt::CandidateBudget;
    use astral_authorization_root::memory_v1_registry::RegistryDeclaration;
    use astral_authorization_root::memory_v1_request::RequestRootScope;
    use astral_authorization_root::memory_v1_root::{install_process_root, RootOwner};
    use astral_authorization_root::memory_v1_rules::{
        canonical_version_bytes, version_digest, MemoryV1OwnerScope, MemoryV1TenantScope,
    };
    use astral_authorization_root::memory_v1_session_authority::MemoryV1SessionAuthority;
    use astral_types::memory_v1::MemoryId;

    // memory—v1: Build three confirmed rule sets and two withdrawn targets.
    fn batch_owner(experimental: bool) -> RootOwner {
        let mut rows = CandidateRows {
            users: (1..=3).map(|id| UserRow { user_id: [id; 16] }).collect(),
            identity_cards: (1..=3)
                .map(|id| IdentityCardRow {
                    identity_card_id: [id + 10; 16],
                    user_id: [id; 16],
                })
                .collect(),
            tenants: vec![TenantRow {
                tenant_id: [4; 16],
                parent_tenant_id: None,
            }],
            user_cards: (1..=3)
                .map(|id| UserCardRow {
                    user_card_id: [id + 20; 16],
                    user_id: [id; 16],
                    tenant_id: [4; 16],
                    status: UserCardStatus::Active,
                })
                .collect(),
            ..CandidateRows::default()
        };
        let mut selections = Vec::new();
        for id in 1..=4 {
            let rule_set_id = [id + 30; 16];
            let content: &[u8] = if id == 1 {
                br#"{"rules":[{"ruleId":"confirm","resource":"binding","action":"confirm","effect":"ALLOW","ownerScope":"all","tenantScope":"self"}]}"#
            } else {
                br#"{"rules":[]}"#
            };
            let version = vec![1];
            let timestamp = vec![1];
            let hash_input = canonical_version_bytes(&version, content, &timestamp);
            rows.rule_sets.push(RuleSetRow {
                status: astral_authorization_root::memory_v1_db_rows::RuleSetStatus::Active,
                rule_set_id,
                owner_tenant_id: [4; 16],
                current_version_bytes: version.clone(),
            });
            rows.rule_set_versions.push(RuleSetVersionRow {
                rule_set_id,
                version_bytes: version.clone(),
                content_bytes: content.to_vec(),
                timestamp_bytes: timestamp,
                hash_bytes: version_digest(&hash_input),
                hash_input_bytes: hash_input,
            });
            if id <= 3 {
                let binding_id = [id + 40; 16];
                rows.bindings.push(BindingRow {
                    binding_id,
                    user_card_id: [id + 20; 16],
                    rule_set_id,
                    binding_layer: BindingLayer::Base,
                    valid_from: None,
                    valid_until: None,
                    owner_scope: MemoryV1OwnerScope::AllUsers,
                    tenant_scope: MemoryV1TenantScope::SelfTenant,
                    removed_at: None,
                    removed_by: None,
                });
                rows.binding_confirmations.push(BindingConfirmationRow {
                    confirmation_id: [id + 50; 16],
                    binding_id,
                    rule_set_id,
                    version_bytes: version.clone(),
                    confirmer_user_id: [1; 16],
                    scope_bytes: vec![1],
                    operation_id: vec![1],
                    confirmed_at_bytes: vec![1],
                    revoked_at: (id != 1).then_some(100),
                    revoked_by: (id != 1).then_some([1; 16]),
                });
            }
            rows.rule_set_change_confirmations
                .push(RuleSetChangeConfirmationRow {
                    confirmation_id: [id + 60; 16],
                    rule_set_id,
                    version_bytes: version.clone(),
                    confirmer_user_id: [1; 16],
                    affected_scope_bytes: vec![1],
                    operation_id: vec![1],
                    confirmed_at_bytes: vec![1],
                    revoked_at: None,
                    revoked_by: None,
                });
            selections.push(CurrentSelection {
                rule_set_id,
                version_bytes: version,
            });
        }
        let counts = rows.table_counts();
        let owner = install_process_root(
            rows,
            selections,
            CandidateBudget {
                max_table_rows: 64,
                max_bindings_per_read: 4,
            },
        )
        .unwrap();
        owner
            .install_registry(&[
                RegistryDeclaration {
                    resource: "binding".to_owned(),
                    actions: vec!["confirm".to_owned()],
                },
                RegistryDeclaration {
                    resource: "unrelated".to_owned(),
                    actions: vec!["read".to_owned()],
                },
            ])
            .unwrap();
        if experimental {
            use astral_authorization_root::memory_v1_adoption::{
                AdoptionLimit, ColdLoadFacts, MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
            };
            owner
                .adopt_experimental(
                    &ColdLoadFacts {
                        schema_contract_version: MEMORY_V1_CANDIDATE_SCHEMA_VERSION,
                        schema_fingerprint: [1; 32],
                        snapshot_counts: counts,
                        scanned_counts: counts,
                        captured_at_unix_seconds: 100,
                    },
                    &AdoptionLimit::EXPERIMENTAL,
                )
                .unwrap();
        } else {
            owner.adopt_serving_for_isolated_tests().unwrap();
        }
        owner
    }

    // memory—v1: Acknowledging unverified confirmation authority cannot make a
    // fully resolved, otherwise authorized batch a positive decision.
    #[test]
    fn experimental_unproven_confirmation_batch_stays_pending() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_BATCH_UNPROVEN_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_batch::tests::experimental_unproven_confirmation_batch_stays_pending",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }
        let owner = batch_owner(true);
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let identity = CandidateIdentity {
            user_id: MemoryId::from_bytes([1; 16]),
            identity_card_id: MemoryId::from_bytes([11; 16]),
            user_card_id: MemoryId::from_bytes([21; 16]),
            tenant_id: MemoryId::from_bytes([4; 16]),
        };
        let issued = authority
            .identity_session_adapter()
            .issue_unchecked_for_test(identity, 100, 100)
            .unwrap();
        let session = authority
            .verifier()
            .verify_and_bind(issued.credential(), 100, &root)
            .unwrap();
        let items = [
            MemoryV1BatchItem {
                sequence: 0,
                binding_id: [42; 16],
                confirmation_id: [71; 16],
            },
            MemoryV1BatchItem {
                sequence: 1,
                binding_id: [43; 16],
                confirmation_id: [72; 16],
            },
        ];
        let result = evaluate_with(
            &root,
            &session,
            &MemoryV1BatchRequest {
                operation_id: b"unproven-confirmation-batch",
                operation_fingerprint:
                    b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                items: &items,
            },
            || Some(110),
            || panic!("unproven confirmation must not reach the final check"),
            |_, _, _, _, _| panic!("unproven confirmation must not issue admission"),
        );
        assert_eq!(result.decision, MemoryV1Decision::Pending);
        assert_eq!(
            result.pending_source,
            Some(MemoryV1PendingSource::ContextInvalid)
        );
        assert!(result.admission.is_none());
        assert!(result.deny_observation.is_none());
        let self_item = MemoryV1BatchItem {
            sequence: 0,
            binding_id: [41; 16],
            confirmation_id: [73; 16],
        };
        for mixed in [
            [
                items[0],
                MemoryV1BatchItem {
                    sequence: 1,
                    ..self_item
                },
            ],
            [
                self_item,
                MemoryV1BatchItem {
                    sequence: 1,
                    ..items[0]
                },
            ],
            [
                MemoryV1BatchItem {
                    sequence: 0,
                    binding_id: [99; 16],
                    confirmation_id: [74; 16],
                },
                MemoryV1BatchItem {
                    sequence: 1,
                    ..self_item
                },
            ],
        ] {
            let denial = evaluate_with(
                &root,
                &session,
                &MemoryV1BatchRequest {
                    operation_id: b"unproven-mixed-self",
                    operation_fingerprint:
                        b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    items: &mixed,
                },
                || Some(110),
                || panic!("self-confirmation must not reach the final check"),
                |_, _, _, _, _| panic!("self-confirmation must not issue admission"),
            );
            assert_eq!(denial.decision, MemoryV1Decision::Deny);
            assert_eq!(
                denial.deny_source,
                Some(MemoryV1DenySource::SelfConfirmation)
            );
            assert!(denial.admission.is_none());
            let observation = denial
                .deny_observation
                .as_deref()
                .expect("resolved self target");
            assert_eq!(
                observation.root(),
                root.with_reader(|reader| reader.metadata()).unwrap()
            );
            assert_eq!(observation.identity(), identity);
            assert_eq!(observation.read_started_at_unix_seconds(), 110);
            assert_eq!(observation.source(), MemoryV1DenySource::SelfConfirmation);
            assert_eq!(
                observation.batch_sequence(),
                Some(
                    mixed
                        .iter()
                        .find(|item| item.binding_id == [41; 16])
                        .unwrap()
                        .sequence
                )
            );
            assert_eq!(observation.target(), Some([41; 16].as_slice()));
            assert_eq!(observation.target_tenant(), Some([4; 16].as_slice()));
            assert_eq!(observation.target_owner(), Some([1; 16].as_slice()));
            assert_eq!(
                (observation.resource(), observation.action()),
                ("binding", "confirm")
            );
            assert_eq!(observation.operation_id(), b"unproven-mixed-self");
        }
    }

    // memory—v1: The batch final check sees changes made after every target was
    // evaluated; a live fence, root update, session revoke or bad time fails closed.
    #[test]
    fn batch_final_check_rejects_post_read_drift() {
        const CHILD: &str = "ASTRAL_MEMORY_V1_BATCH_FINAL_DRIFT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "memory_v1_batch::tests::batch_final_check_rejects_post_read_drift",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "stdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }
        let owner = batch_owner(false);
        let authority = MemoryV1SessionAuthority::new();
        authority.bind_to_root(&owner).unwrap();
        let adapter = authority.identity_session_adapter();
        let identity = CandidateIdentity {
            user_id: MemoryId::from_bytes([1; 16]),
            identity_card_id: MemoryId::from_bytes([11; 16]),
            user_card_id: MemoryId::from_bytes([21; 16]),
            tenant_id: MemoryId::from_bytes([4; 16]),
        };
        let items = [
            MemoryV1BatchItem {
                sequence: 0,
                binding_id: [42; 16],
                confirmation_id: [71; 16],
            },
            MemoryV1BatchItem {
                sequence: 1,
                binding_id: [43; 16],
                confirmation_id: [72; 16],
            },
        ];
        let request = MemoryV1BatchRequest {
            operation_id: b"batch-final-drift",
            operation_fingerprint:
                b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            items: &items,
        };
        let run = |after_read: &mut dyn FnMut(), final_clock: Option<i64>| {
            let scope = RequestRootScope::new(owner.handle(), Default::default());
            let root = scope.extension();
            let issued = adapter
                .issue_unchecked_for_test(identity, 100, 100)
                .unwrap();
            let session = authority
                .verifier()
                .verify_and_bind(issued.credential(), 100, &root)
                .unwrap();
            let result = evaluate_with(
                &root,
                &session,
                &request,
                || Some(110),
                after_read,
                |check, record, constraints, metadata, targets| {
                    assert_eq!(targets, &[[32; 16], [33; 16]]);
                    check.try_final_time_exact_batch_for_test(
                        record,
                        constraints,
                        metadata,
                        targets,
                        || final_clock,
                    )
                },
            );
            (result, issued)
        };
        assert_eq!(
            run(&mut || {}, Some(111)).0.decision,
            MemoryV1Decision::Allow
        );
        let unrelated_fence = run(
            &mut || {
                let metadata = owner.handle().metadata().unwrap();
                owner
                    .begin_modification_fence(
                        [34; 16],
                        &FenceDeclaration {
                            rule_set_version: vec![1],
                            root_version: metadata.version,
                            digest: metadata.digest,
                        },
                    )
                    .unwrap();
            },
            Some(111),
        )
        .0;
        assert_eq!(unrelated_fence.decision, MemoryV1Decision::Allow);
        owner.abort_modification_fence([34; 16]).unwrap();
        for clock in [None, Some(109), Some(200)] {
            let result = run(&mut || {}, clock).0;
            assert_eq!(result.decision, MemoryV1Decision::Pending);
            assert!(result.admission.is_none());
        }
        let result = run(
            &mut || {
                let metadata = owner.handle().metadata().unwrap();
                owner
                    .begin_modification_fence(
                        [33; 16],
                        &FenceDeclaration {
                            rule_set_version: vec![1],
                            root_version: metadata.version,
                            digest: metadata.digest,
                        },
                    )
                    .unwrap();
            },
            Some(111),
        )
        .0;
        assert_eq!(result.decision, MemoryV1Decision::Pending);
        assert!(result.admission.is_none());
        owner.abort_modification_fence([33; 16]).unwrap();

        let result = run(
            &mut || {
                owner
                    .request_registry_retirement_for_test("unrelated")
                    .unwrap();
            },
            Some(111),
        )
        .0;
        assert_eq!(result.decision, MemoryV1Decision::Pending);
        assert!(result.admission.is_none());

        let scope = RequestRootScope::new(owner.handle(), Default::default());
        let root = scope.extension();
        let issued = adapter
            .issue_unchecked_for_test(identity, 100, 100)
            .unwrap();
        let session = authority
            .verifier()
            .verify_and_bind(issued.credential(), 100, &root)
            .unwrap();
        let result = evaluate_with(
            &root,
            &session,
            &request,
            || Some(110),
            || {
                adapter.revoke(issued.credential()).unwrap();
            },
            |check, record, constraints, metadata, targets| {
                check.try_final_time_exact_batch_for_test(
                    record,
                    constraints,
                    metadata,
                    targets,
                    || Some(111),
                )
            },
        );
        assert_eq!(result.decision, MemoryV1Decision::Pending);
        assert!(result.admission.is_none());

        let result = run(
            &mut || {
                let metadata = owner.handle().metadata().unwrap();
                authority
                    .disable_card_with_sessions_for_isolated_tests(
                        &owner.mutation_executor(),
                        MemoryId::from_bytes([22; 16]),
                        metadata,
                    )
                    .unwrap();
            },
            Some(111),
        )
        .0;
        assert_eq!(result.decision, MemoryV1Decision::Pending);
        assert!(result.admission.is_none());
    }
}
