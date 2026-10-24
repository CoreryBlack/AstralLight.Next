//! Native two-model C1/C2 confirmation contracts. C2 is established by a
//! complete run at the required bound plus structural bound monotonicity, so
//! MAX_BOUND=64 does not require an infeasible re-enumeration.

use serde_json::json;
use std::collections::BTreeSet;
use test_harness::bounded_worker_native::run_sharded_model_parallel;
use test_harness::e5_model::{Mode, Premises, MAX_BOUND, PREMISES};
use test_harness::two_mutation_model::{build_chains, required_bound};
use test_harness::unbounded_confirmation::confirmation_report;

fn two_model_chains_closed(premises: Premises) -> bool {
    for mode in [Mode::Bracket, Mode::Strict] {
        let chains = build_chains(premises, mode);
        for chain in [
            &chains.checklist,
            &chains.pre,
            &chains.mutation_a,
            &chains.mutation_b,
            &chains.rollback,
            &chains.bypass,
            &chains.recheck,
        ] {
            let mut seen = BTreeSet::new();
            if chain.iter().any(|event| !seen.insert(event.clone())) {
                return false;
            }
        }
    }
    true
}

// Complete two-mutation runs at the required bounds (bracket 20, strict 14)
// are release-only: debug builds do not finish within any practical gate
// timeout. Dispatched via the `unbounded-confirmation-two-model-parity` suite
// (cargo test --release ... -- --ignored).
#[ignore = "release-only full enumeration; run with --release -- --ignored"]
#[test]
fn two_model_c1_c2_confirmation_is_complete_and_bound_monotonic() {
    let default = Premises::default();
    let mut all_disabled = default;
    for premise in PREMISES {
        all_disabled = all_disabled.without(premise).unwrap();
    }
    assert!(two_model_chains_closed(default));
    assert!(two_model_chains_closed(all_disabled));

    let mut c2_evidence = Vec::new();
    for mode in [Mode::Bracket, Mode::Strict] {
        let required = required_bound(default, mode);
        assert!(MAX_BOUND >= required);
        let complete = run_sharded_model_parallel(default, mode, required, 8).unwrap();
        assert_eq!(complete["explorationComplete"], true, "{mode:?}");
        assert_eq!(complete["status"], "PASS", "{mode:?}: {complete}");
        let under = run_sharded_model_parallel(default, mode, required - 1, 8).unwrap();
        assert!(
            under["explorationComplete"] != true || under["status"] != "PASS",
            "{mode:?}: under-bound run must not be complete PASS"
        );
        c2_evidence.push(json!({
            "mode": mode.as_str(),
            "requiredBound": required,
            "maxBound": MAX_BOUND,
            "completeAtRequired": complete["explorationComplete"],
            "statusAtRequired": complete["status"],
            "underBoundNotPass": under["status"],
        }));
    }

    let base = confirmation_report().unwrap();
    assert_eq!(base["status"], "PASS", "{base}");
    let statuses = base["hypotheses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["id"].as_str().unwrap(),
                entry["status"].as_str().unwrap(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(statuses["C1"], "PASS");
    assert_eq!(statuses["C2"], "PASS");
    assert_eq!(statuses["C3"], "UNKNOWN");
    assert_eq!(statuses["C4"], "UNKNOWN");
    assert_eq!(
        base["hypotheses"][0]["evidence"]["twoMutationModelProblems"],
        json!([])
    );
    assert!(c2_evidence
        .iter()
        .all(|entry| entry["requiredBound"].as_u64().unwrap() <= MAX_BOUND as u64));
}
