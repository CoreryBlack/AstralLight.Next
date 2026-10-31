use regex::Regex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn verdict(status: &str, reason: &str) -> Value {
    json!({"status": status, "reason": reason})
}

fn time_to_ns(value: &str, unit: &str) -> Option<f64> {
    let number: f64 = value.parse().ok()?;
    if !number.is_finite() || number <= 0.0 {
        return None;
    }
    let factor = match unit {
        "ps" => 0.001,
        "ns" => 1.0,
        "us" | "µs" | "μs" => 1_000.0,
        "ms" => 1_000_000.0,
        "s" => 1_000_000_000.0,
        _ => return None,
    };
    let result = number * factor;
    result.is_finite().then_some(result)
}

fn ansi_free(input: &str) -> String {
    Regex::new(r"\x1b\[[0-?]*[ -/]*[@-~]")
        .expect("constant regex")
        .replace_all(input, "")
        .into_owned()
}

pub fn check_criterion(cases: &[String], output: &str, smoke: bool) -> Value {
    let expected: BTreeSet<&str> = cases.iter().map(String::as_str).collect();
    let mut seen = BTreeMap::<String, Value>::new();
    let mut current: Option<String> = None;
    let line_re =
        Regex::new(r"([0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\s*(ps|ns|us|µs|μs|ms|s)")
            .expect("constant regex");
    for line in ansi_free(output).lines() {
        let mut stripped = line.trim();
        if let Some(value) = stripped.strip_prefix("Testing ") {
            stripped = value;
        }
        if let Some(name) = expected
            .iter()
            .find(|name| stripped == **name || stripped.starts_with(&format!("{} ", name)))
        {
            current = Some((*name).to_owned());
        }
        if smoke && stripped == "Success" {
            let Some(name) = current.take() else {
                return verdict("FAIL", "duplicate or unbound benchmark smoke result");
            };
            if seen
                .insert(name, json!({"fixture": "executed; not measured"}))
                .is_some()
            {
                return verdict("FAIL", "duplicate or unbound benchmark smoke result");
            }
        } else if !smoke && line.contains("time:") {
            let Some(name) = current.take() else {
                return verdict("FAIL", "duplicate or unbound Criterion measurement");
            };
            if seen.contains_key(&name) {
                return verdict("FAIL", "duplicate or unbound Criterion measurement");
            }
            let rest = line.split_once("time:").map(|(_, rest)| rest).unwrap_or("");
            let values = line_re
                .captures_iter(rest)
                .filter_map(|captures| time_to_ns(&captures[1], &captures[2]))
                .collect::<Vec<_>>();
            if values.len() != 3 || values.windows(2).any(|pair| pair[0] > pair[1]) {
                return verdict("FAIL", "invalid or incomplete Criterion timing interval");
            }
            seen.insert(
                name,
                json!({"lower_ns": values[0], "estimate_ns": values[1], "upper_ns": values[2]}),
            );
        }
    }
    if seen.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return verdict(
            "FAIL",
            "benchmark output lacks the complete expected case set",
        );
    }
    json!({
        "status": "PASS",
        "reason": if smoke { "complete benchmark fixture smoke" } else { "complete measured CPU Criterion cases; no HTTP/DB claim" },
        "performance": {
            "scope": if smoke { "fixture smoke only" } else { "CPU component only" },
            "cases": seen.len(),
            "measurements": seen
        }
    })
}

fn parse_time_ns(value: &str) -> Option<f64> {
    let captures = Regex::new(
        r"^((?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)\s*(ps|ns|us|µs|μs|ms|s)$",
    )
    .expect("constant regex")
    .captures(value.trim())?;
    time_to_ns(&captures[1], &captures[2])
}

fn parse_finite_number(value: &str) -> Option<f64> {
    let number: f64 = value.trim().parse().ok()?;
    number.is_finite().then_some(number)
}

fn valid_allocation_stat(value: &str, require_unit: bool) -> bool {
    // 必须从最长单位开始匹配："B" 排在前会把 "KB"/"MiB" 截成 "…K" 导致拒绝。
    let units = ["GiB", "MiB", "KiB", "TB", "GB", "MB", "KB", "B"];
    let trimmed = value.trim();
    if require_unit {
        let Some((number, unit)) = units.iter().find_map(|unit| {
            trimmed
                .strip_suffix(unit)
                .map(|number| (number.trim(), *unit))
        }) else {
            return false;
        };
        !unit.is_empty() && parse_finite_number(number).is_some_and(|value| value >= 0.0)
    } else {
        parse_finite_number(trimmed).is_some_and(|value| value >= 0.0)
    }
}

pub fn check_divan(cases: &[String], allocation_cases: &[String], output: &str) -> Value {
    let expected = cases.iter().map(String::as_str).collect::<BTreeSet<_>>();
    let allocating = allocation_cases
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if expected.len() != cases.len()
        || allocating.len() != allocation_cases.len()
        || !allocating.is_subset(&expected)
    {
        return verdict("FAIL", "Divan benchmark inventory is invalid");
    }
    let mut seen = BTreeMap::<String, Value>::new();
    let mut allocations = BTreeMap::<String, Value>::new();
    let mut current: Option<String> = None;
    let mut pending: Option<Vec<Vec<String>>> = None;
    for raw_line in ansi_free(output).lines() {
        let line = raw_line.trim_start_matches(|character: char| {
            character.is_whitespace() || matches!(character, '├' | '└' | '╰' | '─' | '│')
        });
        let mut cells = line
            .split('│')
            .map(str::trim)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut label = cells.first().map(String::as_str).unwrap_or("").to_owned();
        if let Some(rows) = pending.as_mut() {
            let Some(values) = cells.get(..4) else {
                return verdict("FAIL", "missing or invalid Divan allocation statistics");
            };
            let require_unit = !rows.is_empty();
            if values
                .iter()
                .any(|value| !valid_allocation_stat(value, require_unit))
            {
                return verdict("FAIL", "missing or invalid Divan allocation statistics");
            }
            rows.push(values.to_vec());
            if rows.len() == 2 {
                let rows = pending.take().expect("allocation rows exist");
                let name = current.as_ref().expect("allocation case exists").clone();
                allocations.insert(
                    name,
                    json!({"counts_per_iteration":rows[0],"bytes_per_iteration":rows[1]}),
                );
            }
            continue;
        }
        if !expected.contains(label.as_str()) {
            for name in &expected {
                let Some(rest) = label.strip_prefix(name) else {
                    continue;
                };
                if !rest.starts_with(char::is_whitespace) {
                    continue;
                }
                let time = rest.trim();
                if parse_time_ns(time).is_some() {
                    let remainder = cells.into_iter().skip(1).collect::<Vec<_>>();
                    cells = vec![(*name).to_owned(), time.to_owned()];
                    cells.extend(remainder);
                    label = (*name).to_owned();
                    break;
                }
            }
        }
        if expected.contains(label.as_str()) {
            if seen.contains_key(&label) || cells.len() < 7 {
                return verdict("FAIL", "duplicate or malformed Divan case");
            }
            let values = cells[1..5]
                .iter()
                .map(|value| parse_time_ns(value))
                .collect::<Option<Vec<_>>>();
            let Some(values) = values else {
                return verdict("FAIL", "missing Divan timing/sample evidence");
            };
            let Some(samples) = cells[5].parse::<usize>().ok() else {
                return verdict("FAIL", "missing Divan timing/sample evidence");
            };
            let Some(iterations) = cells[6].parse::<usize>().ok() else {
                return verdict("FAIL", "missing Divan timing/sample evidence");
            };
            if values
                .iter()
                .any(|value| !value.is_finite() || *value <= 0.0)
                || samples < 15
                || iterations < 1
            {
                return verdict("FAIL", "invalid Divan samples");
            }
            seen.insert(label.clone(), json!({"fastest_ns":values[0],"slowest_ns":values[1],"median_ns":values[2],"mean_ns":values[3],"samples":samples,"iterations":iterations}));
            current = Some(label);
        } else if current.is_some() && label == "alloc:" {
            let name = current.as_ref().expect("current case exists");
            if allocations.contains_key(name) {
                return verdict("FAIL", "duplicate Divan allocation section");
            }
            pending = Some(Vec::new());
        }
    }
    let seen_names = seen.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let allocated_names = allocations
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if pending.is_some() || seen_names != expected || !allocating.is_subset(&allocated_names) {
        return verdict("FAIL", "Divan timing or allocation cases are incomplete");
    }
    json!({"status":"PASS","reason":"complete CPU allocation benchmark; no service-capacity claim","performance":{"scope":"CPU/allocation component only; instrumented timing","cases":seen.len(),"measurements":seen,"allocations":allocations}})
}

pub fn check_performance_matrix(expected_cases: usize, stdout: &str) -> Value {
    let rows_re = Regex::new(r"PERF_MATRIX (\{[^\n]+\})").expect("constant regex");
    let mut rows = Vec::new();
    let mut cases = BTreeSet::new();
    for captures in rows_re.captures_iter(stdout) {
        let Ok(row) = serde_json::from_str::<Value>(&captures[1]) else {
            return verdict("FAIL", "performance matrix row is malformed");
        };
        let Some(case) = row.get("case").and_then(Value::as_str) else {
            return verdict("FAIL", "performance matrix case name is missing");
        };
        if !cases.insert(case.to_owned()) {
            return verdict("FAIL", "performance matrix has duplicate cases");
        }
        let sample_fields: Vec<&str> = if row.get("current").is_some() {
            vec!["legacy", "current"]
        } else {
            vec!["samples"]
        };
        for field in sample_fields {
            let Some(samples) = row.get(field).and_then(Value::as_array) else {
                return verdict("FAIL", "performance matrix samples are missing");
            };
            if samples.len() < 15 || samples.iter().any(|value| !valid_sample(value)) {
                return verdict(
                    "FAIL",
                    "performance matrix contains invalid or insufficient samples",
                );
            }
        }
        rows.push(row);
    }
    if rows.len() != expected_cases {
        return verdict("FAIL", "performance matrix is incomplete");
    }
    json!({"status":"PASS", "reason":"complete CPU performance matrix measured; no HTTP/DB claim", "performance":{"scope":"CPU component only", "cases":rows.len(), "measurements":rows}})
}

pub fn check_rust_output(
    expected_tests: Option<usize>,
    minimum_tests: usize,
    performance_cases: Option<usize>,
    stdout: &str,
    stderr: &str,
    exit_code: i32,
    interrupted: bool,
) -> Value {
    check_rust_output_with_policy(RustOutputPolicy {
        expected_tests,
        minimum_tests,
        performance_cases,
        stdout,
        stderr,
        exit_code,
        interrupted,
        allow_outside_selection_ignored: false,
    })
}

pub struct RustOutputPolicy<'a> {
    pub expected_tests: Option<usize>,
    pub minimum_tests: usize,
    pub performance_cases: Option<usize>,
    pub stdout: &'a str,
    pub stderr: &'a str,
    pub exit_code: i32,
    pub interrupted: bool,
    pub allow_outside_selection_ignored: bool,
}

pub fn check_rust_output_with_policy(policy: RustOutputPolicy<'_>) -> Value {
    let RustOutputPolicy {
        expected_tests,
        minimum_tests,
        performance_cases,
        stdout,
        stderr,
        exit_code,
        interrupted,
        allow_outside_selection_ignored,
    } = policy;
    let combined = format!("{stdout}\n{stderr}");
    if interrupted
        || matches!(exit_code, 124 | 130 | 137 | 143)
        || exit_code < 0
        || contains_status(&combined, "UNKNOWN")
    {
        return verdict(
            "UNKNOWN",
            "runner interrupted, deadline exceeded or durable outcome unproven",
        );
    }
    if exit_code != 0 {
        return json!({"status":"FAIL", "reason":format!("required command exited {exit_code}")});
    }
    for status in ["PENDING", "BLOCKED", "FAIL"] {
        if contains_status(&combined, status) {
            return json!({"status":status, "reason":format!("command reported explicit [{status}] state")});
        }
    }
    let result_re = Regex::new(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out")
        .expect("constant regex");
    let mut counts = [0usize; 5];
    let mut found = false;
    for captures in result_re.captures_iter(&combined) {
        found = true;
        for (slot, idx) in counts.iter_mut().zip(2..7) {
            *slot += captures[idx].parse::<usize>().unwrap_or(0);
        }
        if &captures[1] == "FAILED" {
            counts[1] = counts[1].max(1);
        }
    }
    let labels = ["passed", "failed", "ignored", "measured", "filtered"];
    let test_counts = labels.into_iter().zip(counts).collect::<BTreeMap<_, _>>();
    if contains_status(&combined, "SKIP") {
        return json!({"status":"SKIP", "reason":"a required check returned an internal skip", "tests":test_counts});
    }
    if counts[1] != 0 || !found || counts[0] < minimum_tests {
        return json!({"status":"FAIL", "reason":"missing, empty, or failing Rust assertion summary", "tests":test_counts});
    }
    if let Some(expected) = expected_tests {
        if counts[0] != expected {
            return json!({"status":"FAIL", "reason":"exact Rust target executed an unexpected assertion count", "tests":test_counts});
        }
    }
    if counts[2] != 0 && !allow_outside_selection_ignored {
        return json!({"status":"SKIP", "reason":"selected Rust target contains unexecuted ignored checks", "tests":test_counts});
    }
    if let Some(expected_cases) = performance_cases {
        let mut performance = check_performance_matrix(expected_cases, stdout);
        if let Some(object) = performance.as_object_mut() {
            object.insert("tests".into(), json!(test_counts));
        }
        return performance;
    }
    json!({"status":"PASS", "reason":"scoped Rust assertions executed", "tests":test_counts, "unexecuted_ignored":counts[2]})
}

fn valid_sample(value: &Value) -> bool {
    match value {
        Value::Number(number) => number
            .as_f64()
            .is_some_and(|value| value.is_finite() && value >= 0.0),
        Value::Array(items) => items.iter().all(|item| {
            item.as_f64()
                .is_some_and(|value| value.is_finite() && value >= 0.0)
        }),
        _ => false,
    }
}

fn contains_status(input: &str, status: &str) -> bool {
    let lowercase = status.to_ascii_lowercase();
    let pattern = format!(r"(?:\[{status}\]|\[{lowercase}\])");
    Regex::new(&pattern)
        .expect("constant regex")
        .is_match(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(passed: usize, failed: usize, ignored: usize, filtered: usize) -> String {
        format!("test result: ok. {passed} passed; {failed} failed; {ignored} ignored; 0 measured; {filtered} filtered out; finished in 0.00s\n")
    }

    #[test]
    fn criterion_requires_complete_measured_cases_and_unit_conversion() {
        let cases = vec!["engine/allow".to_owned(), "engine/deny".to_owned()];
        let output = "engine/allow\n time: [1 ns 2 ns 3 ns]\nengine/deny time: [2 us 3 us 4 us]\n";
        let accepted = check_criterion(&cases, output, false);
        assert_eq!(accepted["status"], "PASS");
        assert_eq!(
            accepted["performance"]["measurements"]["engine/deny"]["estimate_ns"],
            3000.0
        );
        assert_eq!(
            check_criterion(
                &cases,
                "Testing engine/allow\\nSuccess\\nTesting engine/deny\\nSuccess\\n",
                true
            )["status"],
            "FAIL"
        );
        assert_eq!(
            check_criterion(
                &cases,
                "Testing engine/allow\nSuccess\nTesting engine/deny\nSuccess\n",
                true
            )["status"],
            "PASS"
        );
        assert_eq!(
            check_criterion(&cases, "engine/allow time: [5 ns 2 ns 3 ns]\n", false)["status"],
            "FAIL"
        );
    }

    #[test]
    fn python_test_smoke_is_not_measured_criterion_acceptance() {
        let cases = vec!["engine/allow".to_owned(), "engine/deny".to_owned()];
        let smoke = "Testing engine/allow\nSuccess\nTesting engine/deny\nSuccess\n";
        assert_eq!(check_criterion(&cases, smoke, true)["status"], "PASS");
        assert_eq!(check_criterion(&cases, smoke, false)["status"], "FAIL");
    }

    #[test]
    fn python_test_partial_empty_and_duplicate_criterion_measurements_fail() {
        let cases = vec!["engine/allow".to_owned(), "engine/deny".to_owned()];
        let complete = "engine/allow time: [1 ns 2 ns 3 ns]\nengine/deny time: [2 ns 3 ns 4 ns]\n";
        for output in [
            "",
            "Success",
            "engine/allow time: [1 ns 2 ns 3 ns]\n",
            &format!("{complete}{complete}"),
        ] {
            assert_eq!(check_criterion(&cases, output, false)["status"], "FAIL");
        }
    }

    #[test]
    fn python_test_criterion_rejects_nonpositive_reversed_and_unbound_intervals() {
        let cases = vec!["engine/allow".to_owned()];
        for output in [
            "engine/allow time: [0 ns 2 ns 3 ns]",
            "engine/allow time: [5 ns 2 ns 3 ns]",
            "time: [1 ns 2 ns 3 ns]",
        ] {
            assert_eq!(check_criterion(&cases, output, false)["status"], "FAIL");
        }
    }

    #[test]
    fn divan_requires_complete_measured_cases_and_declared_allocation_evidence() {
        let cases = vec!["shared_build".to_owned(), "private_build".to_owned()];
        let allocation_cases = cases.clone();
        let output = [
            "├─ shared_build │ 1 ns │ 4 ns │ 2 ns │ 3 ns │ 100 │ 200",
            "  │ alloc: │ │ │ │ │",
            "  │ 1 │ 2 │ 1.5 │ 1.6 │ │",
            "  │ 8 B │ 16 B │ 12 B │ 12.8 B │ │",
            "└─ private_build 1 ns │ 4 ns │ 2 ns │ 3 ns │ 100 │ 200",
            "  │ alloc: │ │ │ │ │",
            "  │ 1 │ 2 │ 1.5 │ 1.6 │ │",
            "  │ 8 B │ 16 B │ 12 B │ 12.8 B │ │",
        ]
        .join("\n");
        let result = check_divan(&cases, &allocation_cases, &output);
        assert_eq!(result["status"], "PASS", "{}", result["reason"]);
        assert_eq!(
            result["performance"]["measurements"]["shared_build"]["samples"],
            100
        );
        assert_eq!(
            result["performance"]["allocations"]["private_build"]["counts_per_iteration"][0],
            "1"
        );
        assert_eq!(
            check_divan(
                &cases,
                &allocation_cases,
                &output.replace("alloc:", "dealloc:")
            )["status"],
            "FAIL"
        );
        assert_eq!(
            check_divan(&cases, &allocation_cases, &output.replace("100", "0"))["status"],
            "FAIL"
        );
        assert_eq!(
            check_divan(&cases, &allocation_cases, &output.replace("8 B", "8"))["status"],
            "FAIL"
        );
        assert_eq!(
            check_divan(&cases, &allocation_cases, &format!("{output}\n{output}"))["status"],
            "FAIL"
        );
    }

    #[test]
    fn rust_summary_requires_nonempty_exact_and_unskipped_assertions() {
        assert_eq!(
            check_rust_output(None, 1, None, &row(0, 0, 0, 200), "", 0, false)["status"],
            "FAIL"
        );
        assert_eq!(
            check_rust_output(Some(1), 1, None, &row(2, 0, 0, 0), "", 0, false)["status"],
            "FAIL"
        );
        assert_eq!(
            check_rust_output(None, 1, None, &row(12, 0, 3, 0), "", 0, false)["status"],
            "SKIP"
        );
        let internal_skip = check_rust_output(
            None,
            1,
            None,
            "[SKIP] missing check\n",
            &row(1, 0, 0, 0),
            0,
            false,
        );
        assert_eq!(internal_skip["status"], "SKIP");
        assert_eq!(internal_skip["tests"]["passed"], 1);
        assert_eq!(
            check_rust_output(None, 1, None, &row(1, 0, 0, 0), "", 124, false)["status"],
            "UNKNOWN"
        );
    }

    #[test]
    fn python_test_divan_parser_covers_native_table_and_all_allocation_edges() {
        let cases = vec!["shared_build".to_owned(), "private_build".to_owned()];
        let allocation_cases = cases.clone();
        let complete = [
            "├─ shared_build │ 1 ns │ 4 ns │ 2 ns │ 3 ns │ 100 │ 200",
            "  │ alloc: │ │ │ │ │",
            "  │ 1 │ 2 │ 1.5 │ 1.6 │ │",
            "  │ 8 B │ 16 B │ 12 B │ 12.8 B │ │",
            "└─ private_build 1 ns │ 4 ns │ 2 ns │ 3 ns │ 100 │ 200",
            "  │ alloc: │ │ │ │ │",
            "  │ 1 │ 2 │ 1.5 │ 1.6 │ │",
            "  │ 8 B │ 16 B │ 12 B │ 12.8 B │ │",
        ]
        .join("\n");
        let fastest_in_name_column = complete.replace(" │ 1 ns", "  1 ns");
        assert_eq!(
            check_divan(&cases, &allocation_cases, &fastest_in_name_column),
            check_divan(&cases, &allocation_cases, &complete)
        );
        let rounded_terminal_branch = complete.replace("└─ private_build", "╰─ private_build");
        assert_eq!(
            check_divan(&cases, &allocation_cases, &rounded_terminal_branch)["status"],
            "PASS"
        );
        assert_eq!(check_divan(&cases, &allocation_cases, "")["status"], "FAIL");
        for malformed in [
            complete.replace("private_build 1 ns", "private_build nope"),
            complete.replace("private_build 1 ns", "private_build 0 ns"),
            complete.replace("100", "0"),
            complete.lines().take(4).collect::<Vec<_>>().join("\n"),
            rounded_terminal_branch.replace("alloc:", "max alloc:"),
            rounded_terminal_branch.replace("8 B", "8"),
            format!("{complete}\n{complete}"),
        ] {
            assert_eq!(
                check_divan(&cases, &allocation_cases, &malformed)["status"],
                "FAIL"
            );
        }
    }

    #[test]
    fn matrix_requires_unique_complete_finite_samples() {
        let good = format!(
            "PERF_MATRIX {{\"case\":\"one\",\"samples\":{}}}\n{}",
            serde_json::to_string(&vec![10; 15]).unwrap(),
            row(1, 0, 0, 0)
        );
        assert_eq!(
            check_rust_output(None, 1, Some(1), &good, "", 0, false)["status"],
            "PASS"
        );
        let bad = format!("PERF_MATRIX {{\"case\":\"one\",\"samples\":{}}}\nPERF_MATRIX {{\"case\":\"one\",\"samples\":{}}}\n{}", serde_json::to_string(&vec![10; 15]).unwrap(), serde_json::to_string(&vec![10; 15]).unwrap(), row(1,0,0,0));
        assert_eq!(
            check_rust_output(None, 1, Some(2), &bad, "", 0, false)["status"],
            "FAIL"
        );
        assert_eq!(
            check_rust_output(None, 1, None, &row(1, 0, 0, 0), "[PENDING] wait", 0, false)
                ["status"],
            "PENDING"
        );
    }
}
