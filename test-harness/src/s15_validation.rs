use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub const SCENARIO_NAMES: [&str; 15] = [
    "S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10", "S11", "S12", "S13", "S14", "S15",
];
pub const MIN_FULL_ROUNDS: usize = 3;

pub const REQUIRED_CASES: &[(&str, &[&str])] = &[
    (
        "S1",
        &[
            "S1_both_concurrent_writes_200",
            "S1_all_nodes_allow_after_projection",
            "S1_unique_head_contiguous_generations",
        ],
    ),
    (
        "S2",
        &[
            "S2_revoke_commit_200",
            "S2_no_stale_allow_window",
            "S2_all_nodes_deny",
            "S2_deltas_succeeded_after_projection",
        ],
    ),
    (
        "S3",
        &[
            "S3_stale_replay_structurally_rejected",
            "S3_stale_replay_no_resurrect",
            "S3_pointer_unchanged_by_stale_replay",
            "S3_replayed_row_absent",
        ],
    ),
    (
        "S4",
        &[
            "S4_unbind_200",
            "S4_unbind_propagates_deny",
            "S4_revoke_fence_advanced",
            "S4_rebind_restores_allow",
        ],
    ),
    (
        "S5",
        &[
            "S5_baseline_written",
            "S5_baseline_drained",
            "S5_lease_claimed",
            "S5_reclaimed_by_other_node",
            "S5_single_terminal_transition",
            "S5_obsolete_owner_no_second_terminal",
            "S5_pointer_and_decisions_unchanged",
            "S5_outbox_all_terminal_after_reclaim",
            "S5_unbound_has_no_target_delta",
            "S5_drain_clean",
        ],
    ),
    (
        "S6",
        &[
            "S6_alternating_convergence",
            "S6_generation_strictly_increasing",
            "S6_outbox_integrity",
        ],
    ),
    ("S7", &["S7_epoch_present", "S7_stale_residue_not_served"]),
    ("S8", &["S8_abac_attribute_change"]),
    (
        "S9",
        &[
            "S9_storm_no_stale_allow",
            "S9_storm_converge_deny",
            "S9_generation_no_loss",
        ],
    ),
    (
        "S10",
        &[
            "S10_baseline_written",
            "S10_baseline_drained",
            "S10_lease_observed",
            "S10_second_projector_blocked",
            "S10_owner_completes_unique_terminal",
            "S10_obsolete_owner_no_second_terminal",
            "S10_pointer_and_decisions_unchanged",
            "S10_outbox_all_terminal_after_reclaim",
            "S10_unbound_has_no_target_delta",
            "S10_drain_clean",
        ],
    ),
    (
        "S11",
        &[
            "S11_grant_evidence_self_consistent",
            "S11_revoke_evidence_self_consistent",
        ],
    ),
    ("S12", &["S12_arbiter_r1_fence_deny"]),
    (
        "S13",
        &[
            "S13_arbiter_unprovable_defers",
            "S13_arbiter_empty_evidence_rejected",
            "S13_entry_gate_denies_after_cleanup",
        ],
    ),
    (
        "S14",
        &[
            "S14_process_restarted",
            "S14_no_stale_allow_during_down",
            "S14_node_c_ready_after_restart",
            "S14_all_nodes_deny_after_restart",
        ],
    ),
    (
        "S15",
        &[
            "S15_redis_stopped",
            "S15_redis_recovered",
            "S15_no_stale_allow_during_redis_down",
            "S15_no_stale_allow_after_restart",
            "S15_all_nodes_deny_final",
        ],
    ),
];

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Coverage {
    pub scope: &'static str,
    pub complete: bool,
    #[serde(rename = "roundsRequested")]
    pub rounds_requested: usize,
    #[serde(rename = "roundsDone")]
    pub rounds_done: usize,
    #[serde(rename = "minimumFullRounds")]
    pub minimum_full_rounds: usize,
    #[serde(rename = "selectedScenarios")]
    pub selected_scenarios: Vec<String>,
    pub partial: bool,
    #[serde(rename = "requiredCasePasses")]
    pub required_case_passes: bool,
    #[serde(rename = "missingCasesByRound")]
    pub missing_cases_by_round: Vec<BTreeMap<String, Vec<String>>>,
}

#[cfg(test)]
fn known_scenario(value: &str) -> bool {
    SCENARIO_NAMES.contains(&value)
}

fn required_cases(scenario: &str) -> Option<&'static [&'static str]> {
    REQUIRED_CASES
        .iter()
        .find(|(name, _)| *name == scenario)
        .map(|(_, cases)| *cases)
}

pub fn validate_run_selection(rounds: i64, only: Option<&[String]>) -> Vec<String> {
    validate_run_selection_value(&serde_json::json!(rounds), only)
}

pub fn validate_run_selection_value(
    rounds: &serde_json::Value,
    only: Option<&[String]>,
) -> Vec<String> {
    let mut errors = Vec::new();
    if rounds.as_i64().is_none_or(|value| value <= 0) {
        errors.push("rounds_must_be_positive".to_owned());
    }
    if let Some(selected) = only {
        let selected = selected.iter().map(String::as_str).collect::<BTreeSet<_>>();
        let unknown = selected
            .difference(&SCENARIO_NAMES.into_iter().collect())
            .copied()
            .collect::<Vec<_>>();
        if !unknown.is_empty() {
            errors.push(format!("unknown_only:{}", unknown.join(",")));
        }
        if selected.is_empty() {
            errors.push("only_must_select_at_least_one_scenario".to_owned());
        }
    }
    errors
}

pub fn normalize_scenarios(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

pub fn missing_required_cases(
    selected: &[String],
    recorded_names: &BTreeSet<String>,
) -> BTreeMap<String, Vec<String>> {
    selected
        .iter()
        .filter_map(|scenario| {
            let missing = required_cases(scenario)?
                .iter()
                .filter(|case| !recorded_names.contains(**case))
                .map(|case| (*case).to_owned())
                .collect::<Vec<_>>();
            (!missing.is_empty()).then(|| (scenario.clone(), missing))
        })
        .collect()
}

pub fn missing_nonpass_cases(
    selected: &[String],
    round_verdicts: &BTreeMap<String, String>,
) -> BTreeMap<String, Vec<String>> {
    selected
        .iter()
        .filter_map(|scenario| {
            let cases = required_cases(scenario)?
                .iter()
                .filter(|case| round_verdicts.get(**case).map(String::as_str) != Some("PASS"))
                .map(|case| (*case).to_owned())
                .collect::<Vec<_>>();
            (!cases.is_empty()).then(|| (scenario.clone(), cases))
        })
        .collect()
}

pub fn campaign_coverage(
    rounds: usize,
    rounds_done: usize,
    only: Option<&[String]>,
    round_missing_cases: &[BTreeMap<String, Vec<String>>],
    round_case_verdicts: Option<&[BTreeMap<String, String>]>,
) -> Coverage {
    let partial_scope = only.is_some();
    let sufficient_repeats = rounds >= MIN_FULL_ROUNDS && rounds_done == rounds;
    let all_cases = round_missing_cases.len() == rounds_done
        && round_missing_cases.iter().all(BTreeMap::is_empty);
    let selected_scenarios = only.map(|scenarios| scenarios.to_vec()).unwrap_or_else(|| {
        SCENARIO_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect()
    });
    let required_case_passes = round_case_verdicts.is_some_and(|rounds| {
        rounds.len() == rounds_done
            && rounds.iter().all(|verdicts| {
                selected_scenarios.iter().all(|scenario| {
                    required_cases(scenario).is_some_and(|cases| {
                        cases
                            .iter()
                            .all(|case| verdicts.get(*case).map(String::as_str) == Some("PASS"))
                    })
                })
            })
    });
    let complete = !partial_scope && sufficient_repeats && all_cases && required_case_passes;
    let partial = partial_scope || !sufficient_repeats || !all_cases || !required_case_passes;
    Coverage {
        scope: if partial_scope || !sufficient_repeats {
            "partial"
        } else {
            "full"
        },
        complete,
        rounds_requested: rounds,
        rounds_done,
        minimum_full_rounds: MIN_FULL_ROUNDS,
        selected_scenarios,
        partial,
        required_case_passes,
        missing_cases_by_round: round_missing_cases.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_verdicts() -> BTreeMap<String, String> {
        REQUIRED_CASES
            .iter()
            .flat_map(|(_, cases)| cases.iter())
            .map(|case| ((*case).to_owned(), "PASS".to_owned()))
            .collect()
    }

    fn empty_missing_rounds(count: usize) -> Vec<BTreeMap<String, Vec<String>>> {
        vec![BTreeMap::new(); count]
    }

    #[test]
    fn test_rejects_nonpositive_rounds_before_run_setup() {
        for rounds in [0, -1] {
            assert!(
                validate_run_selection(rounds, None).contains(&"rounds_must_be_positive".into())
            );
        }
        for rounds in [
            serde_json::json!(0),
            serde_json::json!(-1),
            serde_json::json!(true),
        ] {
            assert!(validate_run_selection_value(&rounds, None)
                .contains(&"rounds_must_be_positive".into()));
        }
    }

    #[test]
    fn test_rejects_unknown_empty_and_whitespace_only_scenarios() {
        assert_eq!(
            validate_run_selection(3, Some(&["S2".into(), "S99".into()])),
            vec!["unknown_only:S99"]
        );
        assert_eq!(
            validate_run_selection(3, Some(&[])),
            vec!["only_must_select_at_least_one_scenario"]
        );
        assert_eq!(normalize_scenarios("S2, ,S4"), vec!["S2", "S4"]);
    }

    #[test]
    fn test_required_case_coverage_and_nonpass_are_distinct() {
        let selected = vec!["S1".to_owned()];
        let required = required_cases("S1").unwrap();
        let recorded = required[..required.len() - 1]
            .iter()
            .map(|case| (*case).to_owned())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            missing_required_cases(&selected, &recorded)["S1"],
            vec![required[2]]
        );
        let mut verdicts = required
            .iter()
            .map(|case| ((*case).to_owned(), "PASS".to_owned()))
            .collect::<BTreeMap<_, _>>();
        verdicts.insert(required[0].to_owned(), "N/A".into());
        assert!(missing_required_cases(
            &selected,
            &required.iter().map(|case| (*case).to_owned()).collect()
        )
        .is_empty());
        assert_eq!(
            missing_nonpass_cases(&selected, &verdicts)["S1"],
            vec![required[0]]
        );
    }

    #[test]
    fn test_scoped_or_incomplete_runs_are_partial_not_complete() {
        let required = required_cases("S1").unwrap();
        let s1_only = vec!["S1".to_owned()];
        let verdicts: BTreeMap<String, String> = required
            .iter()
            .map(|case| ((*case).to_owned(), "PASS".to_owned()))
            .collect();
        let partial = campaign_coverage(
            3,
            3,
            Some(&s1_only),
            &empty_missing_rounds(3),
            Some(&vec![verdicts.clone(); 3]),
        );
        assert!(!partial.complete);
        assert_eq!(partial.scope, "partial");
        let mut missing = empty_missing_rounds(3);
        missing[0].insert("S1".into(), vec![required[0].into()]);
        let incomplete = campaign_coverage(3, 3, None, &missing, Some(&vec![full_verdicts(); 3]));
        assert!(!incomplete.complete);
    }

    #[test]
    fn test_full_scope_requires_three_rounds_and_positive_cases() {
        let full = campaign_coverage(
            3,
            3,
            None,
            &empty_missing_rounds(3),
            Some(&vec![full_verdicts(); 3]),
        );
        assert!(full.complete);
        assert_eq!(full.scope, "full");
        let one_round = campaign_coverage(
            2,
            2,
            None,
            &empty_missing_rounds(2),
            Some(&vec![full_verdicts(); 2]),
        );
        assert!(!one_round.complete);
        let mut failed = full_verdicts();
        failed.insert("S1_both_concurrent_writes_200".into(), "FAIL".into());
        let failed =
            campaign_coverage(3, 3, None, &empty_missing_rounds(3), Some(&vec![failed; 3]));
        assert!(!failed.complete);
        assert!(!failed.required_case_passes);
    }

    #[test]
    fn test_required_case_inventory_is_exactly_fifteen_named_scenarios() {
        assert_eq!(REQUIRED_CASES.len(), 15);
        assert_eq!(
            REQUIRED_CASES
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>(),
            SCENARIO_NAMES
        );
        assert!(SCENARIO_NAMES.iter().all(|name| known_scenario(name)));
        assert!(!known_scenario("S99"));
    }
}
