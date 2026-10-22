use std::process::ExitCode;
use test_harness::e5_model::{
    build_report, format_text_report, DEFAULT_BOUND, MAX_BOUND, MIN_BOUND,
};

fn main() -> ExitCode {
    match run(std::env::args().skip(1)) {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

fn run(args: impl IntoIterator<Item = String>) -> Result<String, String> {
    let mut bound = DEFAULT_BOUND;
    let mut json_output = false;
    let mut args = args.into_iter();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--max-steps" => {
                let raw = args.next().ok_or_else(usage)?;
                bound = raw
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --max-steps value: {raw}\n{}", usage()))?;
                if !(MIN_BOUND..=MAX_BOUND).contains(&bound) {
                    return Err(format!(
                        "max-steps must be a finite bound in [{MIN_BOUND}, {MAX_BOUND}], got {bound}\n{}",
                        usage()
                    ));
                }
            }
            "--json" => json_output = true,
            "--help" | "-h" => return Ok(usage()),
            other => return Err(format!("unknown argument: {other}\n{}", usage())),
        }
    }
    let report = build_report(bound)?;
    if json_output {
        serde_json::to_string_pretty(&report).map_err(|error| error.to_string())
    } else {
        Ok(format_text_report(&report))
    }
}

fn usage() -> String {
    format!(
        "Usage: e5-model-check [--max-steps N] [--json] (N in [{MIN_BOUND}, {MAX_BOUND}], default {DEFAULT_BOUND})"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn json_cli_emits_parseable_report_at_requested_bound() {
        let output = run(args(&["--max-steps", "17", "--json"])).unwrap();
        let report: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(report["bound"], 17);
        assert_eq!(report["fullContract"]["status"], "PASS");
    }

    #[test]
    fn text_cli_reports_incomplete_exploration_honestly() {
        let output = run(args(&["--max-steps", "8"])).unwrap();
        assert!(output.contains("fullContract status: UNKNOWN"));
        assert!(output.contains("abstract bounded-model evidence ONLY"));
        assert!(output.contains("Status scope"));
    }

    #[test]
    fn default_bound_and_invalid_arguments_match_the_cli_contract() {
        let report: Value = serde_json::from_str(&run(args(&["--json"])).unwrap()).unwrap();
        assert_eq!(report["bound"], DEFAULT_BOUND);
        for values in [
            vec!["--max-steps", "0"],
            vec!["--max-steps", "999"],
            vec!["--max-steps", "abc"],
            vec!["--unknown"],
        ] {
            assert!(run(args(&values)).is_err(), "{values:?}");
        }
    }
}
