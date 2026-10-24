//! Native full two-model universal-hypothesis execution at the required
//! two-mutation bound. Run with `cargo test --release --test e5_universal_native`.

use serde_json::json;
use test_harness::universal_hypotheses::run_universal;

// Full two-model enumeration at bound 20 is release-only: a debug build does
// not finish within any practical gate timeout. Dispatched via the
// `e5-universal-bounded` suite (cargo test --release ... -- --ignored).
#[ignore = "release-only full enumeration; run with --release -- --ignored"]
#[test]
fn two_model_universal_runs_u1_through_u10_at_required_bound() {
    let started = std::time::Instant::now();
    let report = run_universal(20).unwrap();
    eprintln!(
        "universal two-model bound=20 elapsed={:?} status={}",
        started.elapsed(),
        report["status"]
    );
    assert_eq!(report["status"], "PASS", "{report}");
    for model in ["single", "two"] {
        let model_report = &report["models"][model];
        assert_eq!(model_report["status"], "PASS", "{model}: {model_report}");
        assert_eq!(
            model_report["hypotheses"].as_array().unwrap().len(),
            10,
            "{model}"
        );
        assert_eq!(model_report["findings"], json!([]), "{model}");
        assert!(
            model_report["hypotheses"]
                .as_array()
                .unwrap()
                .iter()
                .all(|hypothesis| hypothesis["status"] == "PASS"),
            "{model}"
        );
    }
}
