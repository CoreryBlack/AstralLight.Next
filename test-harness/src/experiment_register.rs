use crate::dependency_profiles;
use std::collections::{BTreeMap, BTreeSet};

pub const REGISTER_VERSION: &str = "1.0.0";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stimulus {
    pub id: &'static str,
    pub source_form: &'static str,
    pub revocation_class: bool,
    pub note: &'static str,
}

pub const STIMULI: [Stimulus; 6] = [
    Stimulus {
        id: "rule_set_unbinding",
        source_form: "RULE_SET unbind",
        revocation_class: true,
        note: "advances the fence on all nodes; rebind recovers (S4/I7)",
    },
    Stimulus {
        id: "winning_entry_removal",
        source_form: "RULE_SET entry REMOVE",
        revocation_class: true,
        note: "the diagnostic race's stimulus; kept for comparability",
    },
    Stimulus {
        id: "direct_rule_removal",
        source_form: "DIRECT rule REMOVE",
        revocation_class: true,
        note: "untested end to end before this register",
    },
    Stimulus {
        id: "approval_or_delegation_withdrawal",
        source_form: "APPROVAL/DELEGATION withdrawal",
        revocation_class: true,
        note: "provenance-level narrowing; fan-out per affected card",
    },
    Stimulus {
        id: "card_disablement",
        source_form: "card disablement",
        revocation_class: true,
        note: "carrier-level narrowing; must fan out to every scope",
    },
    Stimulus {
        id: "aggregate_wide_narrowing",
        source_form: "aggregate-wide narrowing (card = NULL)",
        revocation_class: true,
        note: "enters every affected probe and evidence chain (M1)",
    },
];

pub const STIMULUS_CLASSES: [&str; 6] = [
    "rule_set_unbinding",
    "winning_entry_removal",
    "direct_rule_removal",
    "approval_or_delegation_withdrawal",
    "card_disablement",
    "aggregate_wide_narrowing",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanaryExpectation {
    pub id: &'static str,
    pub injection: &'static str,
    pub expected_detection_rate_basis_points: u16,
    pub expected_false_block_rate_basis_points: u16,
    pub note: &'static str,
}

pub const CANARY_EXPECTATIONS: [CanaryExpectation; 2] = [
    CanaryExpectation {
        id: "suppressed_revocation_delta",
        injection:
            "a revocation-class delta is durably committed but its publication is suppressed",
        expected_detection_rate_basis_points: 10_000,
        expected_false_block_rate_basis_points: 0,
        note: "the gate must block until the suppressed delta publishes",
    },
    CanaryExpectation {
        id: "revision_confused_grant",
        injection: "a successor revision is served for the original candidate identity",
        expected_detection_rate_basis_points: 10_000,
        expected_false_block_rate_basis_points: 0,
        note: "exact identity binding must reject the substitute",
    },
];
pub const E2_RUNTIME_PREMISES: [&str; 5] = [
    "pending_probe",
    "post_recheck",
    "final_reload",
    "exact_identity",
    "generation_revoke_fence",
];
pub const MODEL_ONLY_PREMISES: [&str; 1] = ["host_mediation"];
pub const CANARY_SCENARIOS: [&str; 2] = ["suppressed_revocation_delta", "revision_confused_grant"];
pub const CAPTURE_EXPERIMENTS: [&str; 4] = ["E1", "E2", "E3", "E4"];
pub const ACCEPTANCE_EXPERIMENTS: [&str; 6] = ["E1", "E2", "E3", "E4", "E7", "E8"];
pub const DEPENDENCY_PROFILES: [&str; 8] = dependency_profiles::PROFILE_IDS;
pub const FAULT_TIMINGS: [&str; 2] = dependency_profiles::FAULT_TIMINGS;
pub const LEGACY_REDIS_COMPAT_FAULTS: [&str; 6] = [
    "redis_unavailable",
    "stale_hmac",
    "pointer_movement",
    "worker_restart",
    "lease_expiry",
    "unknown_ack",
];
pub const PROFILE_SERVICE_DEPENDENCIES: [(&str, &[&str]); 8] = [
    ("native-kernel", &[]),
    ("offline-validation", &[]),
    ("native-single-node", &["mysql"]),
    ("standalone-rabbit", &["mysql", "rabbitmq"]),
    ("distributed", &["mysql", "rabbitmq"]),
    ("redis-compat", &["mysql", "redis"]),
    ("performance-kernel", &[]),
    ("performance-native", &["mysql"]),
];
pub const NATIVE_SINGLE_NODE_DEPENDENCIES: [&str; 9] = [
    "cache",
    "publication_worker",
    "authoritative_database",
    "memory_projection_hub",
    "local_bus",
    "local_projection_bus",
    "identity_mapping",
    "gateway_integrity",
    "single_writer_lease",
];
pub const PROFILE_DEPENDENCY_CLASSES: [(&str, &[&str]); 8] = [
    ("native-kernel", &[]),
    ("offline-validation", &[]),
    ("native-single-node", &NATIVE_SINGLE_NODE_DEPENDENCIES),
    (
        "standalone-rabbit",
        &[
            "cache",
            "publication_worker_or_mq",
            "authoritative_database",
            "rabbitmq",
            "identity_mapping",
            "gateway_integrity",
        ],
    ),
    (
        "distributed",
        &[
            "cache",
            "publication_worker_or_mq",
            "authoritative_database",
            "rabbitmq",
            "identity_mapping",
            "gateway_integrity",
        ],
    ),
    (
        "redis-compat",
        &[
            "cache",
            "redis",
            "publication_worker_or_mq",
            "authoritative_database",
            "identity_mapping",
            "gateway_integrity",
        ],
    ),
    ("performance-kernel", &[]),
    (
        "performance-native",
        &["cache", "authoritative_database", "gateway_integrity"],
    ),
];
pub const PROFILE_FAULTS: [(&str, &[&str]); 8] = [
    ("native-kernel", &[]),
    ("offline-validation", &[]),
    (
        "native-single-node",
        &[
            "memory_channel_suspect",
            "memory_invalidation_omission",
            "local_bus_owner_loss",
            "local_bus_overflow",
            "local_bus_unknown_completion",
            "source_commit_unknown",
            "worker_death_sticky",
            "writer_lease_loss",
            "current_pointer_movement",
            "hmac_failure",
            "mysql_unavailable",
        ],
    ),
    (
        "standalone-rabbit",
        &[
            "source_commit_unknown",
            "rabbit_transport_unavailable",
            "worker_death_sticky",
            "current_pointer_movement",
            "hmac_failure",
            "mysql_unavailable",
        ],
    ),
    (
        "distributed",
        &[
            "source_commit_unknown",
            "rabbit_transport_unavailable",
            "worker_death_sticky",
            "current_pointer_movement",
            "hmac_failure",
            "mysql_unavailable",
        ],
    ),
    ("redis-compat", &LEGACY_REDIS_COMPAT_FAULTS),
    ("performance-kernel", &[]),
    (
        "performance-native",
        &[
            "source_commit_unknown",
            "current_pointer_movement",
            "hmac_failure",
            "mysql_unavailable",
        ],
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct E2Control {
    pub premise: &'static str,
    pub crate_name: &'static str,
    pub rust_test: &'static str,
    pub hazard: &'static str,
    pub expected_finding: &'static str,
}

pub const E2_CONTROLS: [E2Control; 5] = [
    E2Control {
        premise: "pending_probe",
        crate_name: "astral-db",
        rust_test: "evidence_cache::tests::e2_pending_probe_omission_accepts_stale_candidate_while_full_contract_reloads",
        hazard: "source narrowing unpublished while old evidence is accepted",
        expected_finding: "counterexample_found",
    },
    E2Control {
        premise: "post_recheck",
        crate_name: "astral-db",
        rust_test: "evidence_cache::tests::e2_post_recheck_omission_accepts_interleaving_while_full_contract_reloads",
        hazard: "publication interleaving accepted across the two observations",
        expected_finding: "counterexample_found",
    },
    E2Control {
        premise: "final_reload",
        crate_name: "policy-engine",
        rust_test: "engine::tests::e2_final_reload_omission_accepts_removed_candidate_while_full_contract_reloads",
        hazard: "pre-observation fallback admits the removed candidate",
        expected_finding: "counterexample_found",
    },
    E2Control {
        premise: "exact_identity",
        crate_name: "policy-engine",
        rust_test: "engine::tests::test_strict_successor_revision_cannot_replace_original_candidate",
        hazard: "successor revision replaces the original candidate",
        expected_finding: "counterexample_found",
    },
    E2Control {
        premise: "generation_revoke_fence",
        crate_name: "astral-db",
        rust_test: "evidence_cache::tests::e2_generation_revoke_fence_omission_accepts_stale_candidate",
        hazard: "stale generation or pointer rollback accepted",
        expected_finding: "counterexample_found",
    },
];

pub const E2_RUST_TESTS: [(&str, &str); 5] = [
    (E2_CONTROLS[0].premise, E2_CONTROLS[0].rust_test),
    (E2_CONTROLS[1].premise, E2_CONTROLS[1].rust_test),
    (E2_CONTROLS[2].premise, E2_CONTROLS[2].rust_test),
    (E2_CONTROLS[3].premise, E2_CONTROLS[3].rust_test),
    (E2_CONTROLS[4].premise, E2_CONTROLS[4].rust_test),
];

pub const CAPTURE_REQUIREMENTS: [(&str, &[&str]); 4] = [
    (
        "E1",
        &[
            "per-request commit/final-observation/stable-check/admission boundaries",
            "cache-or-strict branch",
            "decision reason code",
            "per-mutation hazard attribution",
            "revocation stimulus class id",
        ],
    ),
    (
        "E2",
        &[
            "disabled premise id",
            "full-contract control run",
            "expected hazard family",
            "repeatability within the registered repetition budget",
        ],
    ),
    (
        "E3",
        &[
            "per-event enqueue/claim/attempt/backoff/parking timestamps",
            "queue-depth time series",
            "target/unrelated/cold-start card decision series",
            "publication drain decomposition",
        ],
    ),
    (
        "E4",
        &[
            "per-connection transaction isolation",
            "primary-routing confirmation",
            "UTC/clock-offset observations",
            "cache-generation initialization/rotation events",
            "readiness and liveness recorded separately",
        ],
    ),
];

pub const ACCEPTANCE_CRITERIA: [(&str, &[&str]); 6] = [
    (
        "E1",
        &[
            "zero stale ALLOW among strictly-ordered pre-observation samples",
            "every ALLOW carries a complete ordering record",
            "overlap-window outcomes reported separately",
            "every registered stimulus class executed",
        ],
    ),
    (
        "E2",
        &[
            "each ablated control reproduces its hazard family",
            "full-contract control yields zero violations under identical workload",
            "a control that cannot be made to fail weakens its necessity claim",
        ],
    ),
    (
        "E3",
        &[
            "zero stale ALLOW throughout the drain",
            "target-card PENDING/DENY separated from unrelated-card availability",
            "drain decomposition reported as distributions",
        ],
    ),
    (
        "E4",
        &[
            "every fault window terminates in PENDING/DENY with a reason code",
            "recovery judged at readiness, not liveness",
            "unarchivable preconditions downgrade the claim",
        ],
    ),
    (
        "E7",
        &[
            "canary detection rate one",
            "zero false blocks on fresh evidence",
        ],
    ),
    (
        "E8",
        &[
            "bounded tail latency at the registered maximum",
            "zero stale ALLOW and zero errors",
        ],
    ),
];

pub fn dependency_fault_matrices(
) -> Result<BTreeMap<String, BTreeMap<String, dependency_profiles::FaultMatrixEntry>>, String> {
    DEPENDENCY_PROFILES
        .iter()
        .map(|profile| {
            dependency_profiles::dependency_fault_matrix(profile)
                .map(|matrix| ((*profile).to_owned(), matrix))
        })
        .collect()
}

pub fn dependency_fault_matrix(
) -> Result<BTreeMap<String, dependency_profiles::FaultMatrixEntry>, String> {
    dependency_profiles::dependency_fault_matrix("native-single-node")
}

pub fn validate_register() -> Result<(), Vec<String>> {
    let mut problems = Vec::new();
    let stimuli = STIMULUS_CLASSES.into_iter().collect::<BTreeSet<_>>();
    let stimulus_ids = STIMULI.iter().map(|item| item.id).collect::<BTreeSet<_>>();
    if stimuli.len() != STIMULUS_CLASSES.len()
        || stimulus_ids != stimuli
        || STIMULI.len() != STIMULUS_CLASSES.len()
    {
        problems.push("duplicate_or_incomplete_stimulus_class".to_owned());
    }
    if STIMULI
        .iter()
        .any(|item| !item.revocation_class || item.source_form.is_empty() || item.note.is_empty())
    {
        problems.push("invalid_stimulus_declaration".to_owned());
    }
    let canary_ids = CANARY_EXPECTATIONS
        .iter()
        .map(|item| item.id)
        .collect::<BTreeSet<_>>();
    if canary_ids != CANARY_SCENARIOS.into_iter().collect()
        || CANARY_EXPECTATIONS.iter().any(|item| {
            item.expected_detection_rate_basis_points != 10_000
                || item.expected_false_block_rate_basis_points != 0
                || item.injection.is_empty()
                || item.note.is_empty()
        })
    {
        problems.push("invalid_canary_expectation".to_owned());
    }
    let expected_services = PROFILE_SERVICE_DEPENDENCIES
        .iter()
        .map(|(id, services)| (*id, *services))
        .collect::<BTreeMap<_, _>>();
    let expected_dependencies = PROFILE_DEPENDENCY_CLASSES
        .iter()
        .map(|(id, dependencies)| (*id, *dependencies))
        .collect::<BTreeMap<_, _>>();
    let expected_faults = PROFILE_FAULTS
        .iter()
        .map(|(id, faults)| (*id, *faults))
        .collect::<BTreeMap<_, _>>();
    if expected_services.len() != DEPENDENCY_PROFILES.len()
        || expected_dependencies.len() != DEPENDENCY_PROFILES.len()
        || expected_faults.len() != DEPENDENCY_PROFILES.len()
        || DEPENDENCY_PROFILES.iter().copied().collect::<BTreeSet<_>>()
            != expected_services.keys().copied().collect()
        || DEPENDENCY_PROFILES.iter().any(|profile| {
            dependency_profiles::profile_services(profile)
                != expected_services.get(profile).copied()
                || dependency_profiles::profile_dependencies(profile)
                    != expected_dependencies.get(profile).copied()
                || dependency_profiles::profile_faults(profile)
                    != expected_faults.get(profile).copied()
        })
    {
        problems.push("profile_registry_mismatch".to_owned());
    }
    let native_dependencies = dependency_profiles::profile_dependencies("native-single-node")
        .map(|items| items.iter().copied().collect::<BTreeSet<_>>());
    if native_dependencies != Some(NATIVE_SINGLE_NODE_DEPENDENCIES.into_iter().collect()) {
        problems.push("native_dependency_registry_mismatch".to_owned());
    }
    if dependency_profiles::fault_dependencies_for("native-kernel", "unknown_ack")
        .is_ok_and(|dependencies| !dependencies.is_empty())
        || LEGACY_REDIS_COMPAT_FAULTS.iter().any(|fault| {
            !dependency_profiles::profile_faults("redis-compat")
                .is_some_and(|faults| faults.contains(fault))
                || dependency_profiles::profile_faults("native-single-node")
                    .is_some_and(|faults| faults.contains(fault))
                || dependency_profiles::profile_faults("standalone-rabbit")
                    .is_some_and(|faults| faults.contains(fault))
        })
    {
        problems.push("legacy_fault_profile_boundary_mismatch".to_owned());
    }
    let matrices = dependency_fault_matrices();
    match matrices {
        Ok(matrices) => {
            for profile in DEPENDENCY_PROFILES {
                let dependencies =
                    dependency_profiles::profile_dependencies(profile).unwrap_or_default();
                let expected = dependencies
                    .iter()
                    .flat_map(|dependency| {
                        FAULT_TIMINGS
                            .iter()
                            .map(move |timing| format!("{dependency}:{timing}"))
                    })
                    .collect::<BTreeSet<_>>();
                if matrices
                    .get(profile)
                    .map(|matrix| matrix.keys().cloned().collect::<BTreeSet<_>>())
                    != Some(expected)
                    || matrices.get(profile).is_some_and(|matrix| {
                        matrix.iter().any(|(key, entry)| {
                            let Some((dependency, timing)) = key.split_once(':') else {
                                return true;
                            };
                            entry.profile != profile
                                || entry.dependency != dependency
                                || entry.timing != timing
                                || entry.acceptance != "fail_closed"
                        })
                    })
                {
                    problems.push(format!("{profile}:invalid_fault_matrix"));
                }
            }
            if matrices.get("native-single-node") != dependency_fault_matrix().ok().as_ref()
                || matrices.get("redis-compat").map(BTreeMap::len) != Some(12)
            {
                problems.push("default_or_redis_fault_matrix_mismatch".to_owned());
            }
        }
        Err(_) => problems.push("dependency_fault_matrix_generation_failed".to_owned()),
    }
    let runtime = E2_RUST_TESTS
        .iter()
        .map(|(premise, test)| {
            if test.is_empty() {
                problems.push(format!("missing_e2_rust_test:{premise}"));
            }
            *premise
        })
        .collect::<BTreeSet<_>>();
    let mut all = runtime;
    all.extend(MODEL_ONLY_PREMISES);
    if all
        != [
            "exact_identity",
            "final_reload",
            "generation_revoke_fence",
            "host_mediation",
            "pending_probe",
            "post_recheck",
        ]
        .into_iter()
        .collect()
    {
        problems.push("e2_controls_and_model_only_premises_do_not_cover_registry".to_owned());
    }
    if dependency_profiles::validate_profiles().is_err() {
        problems.push("dependency_profile_contract_invalid".to_owned());
    }
    let capture_ids = CAPTURE_REQUIREMENTS
        .iter()
        .map(|(experiment, _)| *experiment)
        .collect::<BTreeSet<_>>();
    if capture_ids.len() != CAPTURE_REQUIREMENTS.len()
        || capture_ids != CAPTURE_EXPERIMENTS.into_iter().collect()
    {
        problems.push("capture_experiment_registry_mismatch".to_owned());
    }
    for (experiment, fields) in CAPTURE_REQUIREMENTS {
        if fields.len() < 3 {
            problems.push(format!("invalid_capture_requirements:{experiment}"));
        }
    }
    let acceptance_ids = ACCEPTANCE_CRITERIA
        .iter()
        .map(|(experiment, _)| *experiment)
        .collect::<BTreeSet<_>>();
    if acceptance_ids.len() != ACCEPTANCE_CRITERIA.len()
        || acceptance_ids != ACCEPTANCE_EXPERIMENTS.into_iter().collect()
    {
        problems.push("acceptance_experiment_registry_mismatch".to_owned());
    }
    for (experiment, criteria) in ACCEPTANCE_CRITERIA {
        if criteria.len() < 2 {
            problems.push(format!("invalid_acceptance_criteria:{experiment}"));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_links_every_runtime_e2_premise_to_a_readiness_test() {
        assert_eq!(E2_RUST_TESTS.len(), E2_RUNTIME_PREMISES.len());
        for (control, expected) in E2_CONTROLS.iter().zip(E2_RUNTIME_PREMISES) {
            assert_eq!(control.premise, expected);
            assert!(["astral-db", "policy-engine"].contains(&control.crate_name));
            assert!(
                control.rust_test.starts_with("evidence_cache::tests::")
                    || control.rust_test.starts_with("engine::tests::")
            );
            assert!(!control.hazard.is_empty());
            assert_eq!(control.expected_finding, "counterexample_found");
            assert!(include_str!(
                "../../Docs/authorization-validation/tools/run_single_node_campaign.py"
            )
            .contains(control.rust_test));
        }
        assert!(validate_register().is_ok());

        let mut premises = E2_RUNTIME_PREMISES.to_vec();
        premises.extend(MODEL_ONLY_PREMISES);
        premises.sort_unstable();
        let mut model_premises = crate::e5_model::PREMISES.to_vec();
        model_premises.sort_unstable();
        assert_eq!(premises, model_premises);
        let mut premise_ids = E2_RUST_TESTS
            .iter()
            .map(|(premise, _)| *premise)
            .collect::<Vec<_>>();
        premise_ids.sort_unstable();
        premise_ids.dedup();
        assert_eq!(premise_ids.len(), E2_RUNTIME_PREMISES.len());
        let mut test_ids = E2_RUST_TESTS
            .iter()
            .map(|(_, test)| *test)
            .collect::<Vec<_>>();
        test_ids.sort_unstable();
        test_ids.dedup();
        assert_eq!(test_ids.len(), E2_RUNTIME_PREMISES.len());
        assert!(E2_RUST_TESTS
            .iter()
            .all(|(premise, test)| !premise.contains("host") && !test.contains("host")));

        let rust_sources = [
            include_str!("../../astral-db/src/evidence_cache.rs"),
            include_str!("../../policy-engine/src/engine/tests.rs"),
        ];
        for control in E2_CONTROLS {
            let test_name = control.rust_test.rsplit("::").next().unwrap();
            assert!(
                rust_sources
                    .iter()
                    .any(|source| source.contains(&format!("fn {test_name}"))),
                "{} does not resolve to a Rust test",
                control.rust_test
            );
        }
    }

    #[test]
    fn required_registry_symbols_are_importable() {
        let _: fn() -> Result<(), Vec<String>> = validate_register;
        let _: fn(
            &[crate::e1_validation::Event],
            &[crate::e1_validation::Event],
        ) -> Result<crate::e1_validation::Classification, String> =
            crate::e1_validation::classify_e1_allow;
    }

    #[test]
    fn registry_pins_stimulus_canary_capture_and_acceptance_surfaces() {
        assert_eq!(STIMULUS_CLASSES.len(), 6);
        assert_eq!(STIMULI.len(), 6);
        assert!(STIMULI
            .iter()
            .all(|item| item.revocation_class && !item.note.is_empty()));
        assert_eq!(
            CANARY_SCENARIOS,
            ["suppressed_revocation_delta", "revision_confused_grant"]
        );
        assert_eq!(CANARY_EXPECTATIONS.len(), 2);
        assert!(CANARY_EXPECTATIONS.iter().all(|item| {
            item.expected_detection_rate_basis_points == 10_000
                && item.expected_false_block_rate_basis_points == 0
        }));
        assert_eq!(DEPENDENCY_PROFILES.len(), 8);
        assert_eq!(NATIVE_SINGLE_NODE_DEPENDENCIES.len(), 9);
        assert_eq!(FAULT_TIMINGS, ["steady_state", "in_flight_revocation"]);
        let matrices = dependency_fault_matrices().unwrap();
        assert_eq!(matrices["native-single-node"].len(), 18);
        assert_eq!(matrices["redis-compat"].len(), 12);
        assert_eq!(
            matrices["native-single-node"],
            dependency_fault_matrix().unwrap()
        );
        assert_eq!(CAPTURE_REQUIREMENTS.len(), 4);
        assert_eq!(ACCEPTANCE_CRITERIA.len(), 6);
        assert!(CAPTURE_REQUIREMENTS
            .iter()
            .find(|(name, _)| *name == "E1")
            .unwrap()
            .1
            .iter()
            .any(|value| value.contains("per-mutation")));
        assert!(ACCEPTANCE_CRITERIA
            .iter()
            .all(|(_, values)| values.len() >= 2));
    }
}
