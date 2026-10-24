use serde_json::Value;
use std::process::{Command, Output};

fn run_cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_e5-model-check"))
        .args(args)
        .output()
        .expect("run local E5 model-check binary")
}

#[test]
fn json_cli_emits_parseable_report_at_requested_bound() {
    let output = run_cli(&["--max-steps", "17", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["bound"], 17);
    assert_eq!(report["fullContract"]["status"], "PASS");
}

#[test]
fn text_cli_reports_incomplete_exploration_honestly() {
    let output = run_cli(&["--max-steps", "8"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("fullContract status: UNKNOWN"));
    assert!(text.contains("abstract bounded-model evidence ONLY"));
    assert!(text.contains("Status scope"));
}

#[test]
fn default_bound_flag_is_used() {
    let output = run_cli(&["--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["bound"], 28);
}

#[test]
fn invalid_bound_cli_exits_with_code_two_before_emitting_a_report() {
    for args in [
        ["--max-steps", "0"],
        ["--max-steps", "999"],
        ["--max-steps", "abc"],
    ] {
        let output = run_cli(&args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(!output.stderr.is_empty(), "{args:?}");
    }
}
