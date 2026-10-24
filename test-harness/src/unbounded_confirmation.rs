use crate::e5_model::{self, Mode, Premises, DEFAULT_BOUND, MAX_BOUND};
use serde_json::{json, Value};
use std::collections::BTreeSet;

const EVENT_NAMES: [&str; 19] = [
    "INIT",
    "COMMIT_BEGIN",
    "COMMIT_DURABLE",
    "PUBLISH",
    "EVIDENCE_BODY_ADVANCE",
    "ROLLBACK",
    "PRE_OBS_BEGIN",
    "PRE_OBS_END",
    "RELOAD_M0",
    "RELOAD_P0",
    "RELOAD_M1",
    "RELOAD_P1",
    "STRICT_LOAD",
    "MATCH",
    "POST_OBS_BEGIN",
    "POST_OBS_END",
    "STRICT_OBS",
    "ADMIT",
    "BYPASS",
];

fn event_space_closed(premises: Premises, mode: Mode) -> bool {
    let chains = e5_model::build_chains(premises, mode);
    let chain_groups = [
        chains.checklist,
        chains.pre,
        chains.mutation,
        chains.body,
        chains.bypass,
    ];
    for chain in &chain_groups {
        let mut local = BTreeSet::new();
        if chain
            .iter()
            .any(|event| !EVENT_NAMES.contains(event) || !local.insert(*event))
        {
            return false;
        }
    }
    true
}

fn two_mutation_event_space_closed(premises: Premises, mode: Mode) -> bool {
    let chains = crate::two_mutation_model::build_chains(premises, mode);
    let chain_groups = [
        chains.checklist,
        chains.pre,
        chains.mutation_a,
        chains.mutation_b,
        chains.rollback,
        chains.bypass,
        chains.recheck,
    ];
    chain_groups.iter().all(|chain| {
        let mut local = BTreeSet::new();
        chain.iter().all(|event| local.insert(event))
    })
}

fn run_summary(premises: Premises, mode: Mode, bound: usize) -> Result<Value, String> {
    e5_model::run_model(premises, mode, bound)
}

fn invariant_fields(baseline: &Value, stressed: &Value) -> bool {
    [
        "status",
        "violations",
        "admittedTraces",
        "deniedTraces",
        "explorationComplete",
        "exploredTraces",
    ]
    .iter()
    .all(|key| baseline.get(*key) == stressed.get(*key))
}

pub fn confirmation_report() -> Result<Value, String> {
    let default = Premises::default();
    let mut all_premises_disabled = default;
    for premise in e5_model::PREMISES {
        all_premises_disabled = all_premises_disabled.without(premise)?;
    }
    let mut c1_single_model = true;
    let mut c1_two_mutation_model = true;
    for premises in [default, all_premises_disabled] {
        for mode in [Mode::Bracket, Mode::Strict] {
            c1_single_model &= event_space_closed(premises, mode);
            c1_two_mutation_model &= two_mutation_event_space_closed(premises, mode);
        }
    }

    let mut evidence = serde_json::Map::new();
    let mut c2 = true;
    for mode in [Mode::Bracket, Mode::Strict] {
        let baseline = run_summary(default, mode, DEFAULT_BOUND)?;
        let stressed = run_summary(default, mode, MAX_BOUND)?;
        let invariant = invariant_fields(&baseline, &stressed)
            && baseline["explorationComplete"] == true
            && stressed["explorationComplete"] == true;
        c2 &= invariant;
        evidence.insert(
            format!("single/{}", mode.as_str()),
            json!({
                "boundInvariant": invariant,
                "status": baseline["status"],
                "exploredTraces": baseline["exploredTraces"],
                "maxBoundExploredTraces": stressed["exploredTraces"],
            }),
        );
    }

    let c1_status = if c1_single_model && c1_two_mutation_model {
        "PASS"
    } else {
        "FAIL"
    };
    let hypotheses = vec![
        json!({
            "id": "C1",
            "status": c1_status,
            "evidence": {
                "singleModelStatus": if c1_single_model { "PASS" } else { "FAIL" },
                "singleModelProblems": if c1_single_model { Vec::<String>::new() } else { vec!["single-mutation event-chain closure failed".to_owned()] },
                "twoMutationModelStatus": if c1_two_mutation_model { "PASS" } else { "FAIL" },
                "twoMutationModelProblems": if c1_two_mutation_model { Vec::<String>::new() } else { vec!["two-mutation event-chain closure failed".to_owned()] },
            },
        }),
        json!({
            "id": "C2",
            "status": if c2 { "PASS" } else { "FAIL" },
            "evidence": evidence,
        }),
        json!({
            "id": "C3",
            "status": "UNKNOWN",
            "statement": "reduction lemma to at most two mutations remains unproven",
            "evidence": {
                "familyComparison": "no new violating family appears at N=2 is not evaluated by the single-mutation Rust model; the reduction lemma remains unproven",
            },
        }),
        json!({
            "id": "C4",
            "status": "UNKNOWN",
            "evidence": {
                "tlaStatus": "BLOCKED (no pinned checksum-verified TLC/TLAPS)",
            },
        }),
    ];
    let overall = if c1_single_model && c1_two_mutation_model && c2 {
        "PASS"
    } else {
        "FAIL"
    };
    Ok(json!({
        "checker": "unbounded-confirmation-check",
        "checkerVersion": "rust-partial-v2",
        "status": overall,
        "statusMeaning": "PASS means every mechanically decidable confirmation check represented here passed; C3 and C4 remain UNKNOWN obligations and are not proven by this status",
        "hypotheses": hypotheses,
        "scopeBoundary": "single-mutation bounded-model enumeration for C2; C1 event-chain closure covers the single- and two-mutation models; C3/C4 remain UNKNOWN; no deployment proof is implied",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::two_mutation_model;

    #[test]
    fn event_chains_are_closed_without_duplicate_events() {
        assert_eq!(EVENT_NAMES.len(), 19);
        let mut all_premises_disabled = Premises::default();
        for premise in e5_model::PREMISES {
            all_premises_disabled = all_premises_disabled.without(premise).unwrap();
        }
        for premises in [Premises::default(), all_premises_disabled] {
            for mode in [Mode::Bracket, Mode::Strict] {
                assert!(event_space_closed(premises, mode));
            }
        }
    }

    #[test]
    fn two_mutation_event_chains_are_closed_without_duplicate_events() {
        let mut all_premises_disabled = Premises::default();
        for premise in e5_model::PREMISES {
            all_premises_disabled = all_premises_disabled.without(premise).unwrap();
        }
        for premises in [Premises::default(), all_premises_disabled] {
            for mode in [Mode::Bracket, Mode::Strict] {
                let chains = two_mutation_model::build_chains(premises, mode);
                for chain in [
                    &chains.checklist,
                    &chains.pre,
                    &chains.mutation_a,
                    &chains.mutation_b,
                    &chains.rollback,
                    &chains.bypass,
                    &chains.recheck,
                ] {
                    let unique = chain.iter().collect::<BTreeSet<_>>();
                    assert_eq!(unique.len(), chain.len(), "{}", mode.as_str());
                }
            }
        }
    }

    #[test]
    fn finite_bound_does_not_change_single_model_full_contract() {
        for mode in [Mode::Bracket, Mode::Strict] {
            let baseline = run_summary(Premises::default(), mode, DEFAULT_BOUND).unwrap();
            let stressed = run_summary(Premises::default(), mode, MAX_BOUND).unwrap();
            assert_eq!(baseline["explorationComplete"], true);
            assert_eq!(stressed["explorationComplete"], true);
            assert!(invariant_fields(&baseline, &stressed));
        }
    }

    #[test]
    fn c3_c4_remain_explicit_unknown_obligations() {
        let report = confirmation_report().unwrap();
        assert_eq!(report["status"], "PASS");
        assert!(report["statusMeaning"]
            .as_str()
            .unwrap()
            .contains("C3 and C4 remain UNKNOWN obligations"));
        assert_eq!(report["hypotheses"][0]["status"], "PASS");
        assert_eq!(
            report["hypotheses"][0]["evidence"]["singleModelStatus"],
            "PASS"
        );
        assert_eq!(
            report["hypotheses"][0]["evidence"]["twoMutationModelStatus"],
            "PASS"
        );
        assert_eq!(
            report["hypotheses"][0]["evidence"]["singleModelProblems"],
            json!([])
        );
        assert_eq!(
            report["hypotheses"][0]["evidence"]["twoMutationModelProblems"],
            json!([])
        );
        assert_eq!(report["hypotheses"][1]["status"], "PASS");
        let c2_evidence = report["hypotheses"][1]["evidence"].as_object().unwrap();
        assert_eq!(
            c2_evidence
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["single/bracket", "single/strict"])
        );
        for item in c2_evidence.values() {
            assert_eq!(item["boundInvariant"], true);
            assert_eq!(item["status"], "PASS");
            assert_eq!(item["exploredTraces"], item["maxBoundExploredTraces"]);
        }
        let scope = report["scopeBoundary"].as_str().unwrap();
        assert!(scope.contains("C1 event-chain closure covers the single- and two-mutation models"));
        assert!(scope.contains("C3/C4 remain UNKNOWN"));
        assert!(!scope.contains("unimplemented Rust two-mutation model"));
        assert_eq!(report["hypotheses"][2]["status"], "UNKNOWN");
        assert_eq!(
            report["hypotheses"][2]["evidence"]["familyComparison"],
            "no new violating family appears at N=2 is not evaluated by the single-mutation Rust model; the reduction lemma remains unproven"
        );
        assert_eq!(report["hypotheses"][3]["status"], "UNKNOWN");
        assert_eq!(
            report["hypotheses"][3]["evidence"]["tlaStatus"],
            "BLOCKED (no pinned checksum-verified TLC/TLAPS)"
        );
        assert!(report["hypotheses"][2]["statement"]
            .as_str()
            .unwrap()
            .contains("reduction lemma"));
        assert_eq!(
            report["hypotheses"][1]["evidence"]
                .as_object()
                .unwrap()
                .len(),
            2
        );
    }
}
