use serde_json::Value;
use std::collections::BTreeSet;

pub const MIN_INTERVAL_S: f64 = 0.01;
pub const MAX_INTERVAL_S: f64 = 600.0;
pub const MAX_WINDOW_S: f64 = 3600.0;
pub const MAX_SAMPLES_PER_WINDOW: usize = 10_000;
pub const MAX_ATTEMPTS: u64 = 64;
pub const MIN_CONTROLLER_TIMEOUT_S: f64 = 0.05;
pub const MAX_CONTROLLER_TIMEOUT_S: f64 = 600.0;
pub const DEFAULT_CONTROLLER_TIMEOUT_S: f64 = 30.0;
pub const MAX_NODES: usize = 4;

#[derive(Clone, Debug, PartialEq)]
pub struct E3Settings {
    pub run_id: String,
    pub target_card: String,
    pub unrelated_card: String,
    pub cold_card: String,
    pub isolated_fixture: bool,
    pub sampling_interval_s: f64,
    pub injection_window_s: f64,
    pub drain_window_s: f64,
    pub max_attempts: u64,
    pub controller_timeout_s: f64,
    pub nodes: Vec<String>,
    pub decision_node: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigError {
    pub problems: Vec<&'static str>,
}

fn safe_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(byte))
}

fn safe_card(value: &str) -> bool {
    safe_id(value)
}

fn finite_number(value: Option<&Value>) -> Option<f64> {
    value
        .and_then(Value::as_number)
        .and_then(|number| number.as_f64())
        .filter(|number| number.is_finite())
}

fn scheduled_samples(window_s: f64, interval_s: f64) -> usize {
    if window_s <= 0.0 {
        return 0;
    }
    (window_s / interval_s - 1e-9).ceil() as usize
}

fn sorted_problems(mut problems: Vec<&'static str>) -> Vec<&'static str> {
    problems.sort_unstable();
    problems.dedup();
    problems
}

pub fn load_e3_config(raw: &Value) -> Result<E3Settings, ConfigError> {
    let Some(root) = raw.as_object() else {
        return Err(ConfigError {
            problems: vec!["config_not_a_mapping"],
        });
    };
    let run_id = root.get("run_id").and_then(Value::as_str);
    let Some(run_id) = run_id.filter(|value| safe_id(value)) else {
        return Err(ConfigError {
            problems: vec!["invalid:run_id"],
        });
    };
    let Some(e3) = root.get("e3").and_then(Value::as_object) else {
        return Err(ConfigError {
            problems: vec!["missing:e3"],
        });
    };
    let Some(allowlist) = e3.get("allowlist").and_then(Value::as_object) else {
        return Err(ConfigError {
            problems: vec!["missing:e3.allowlist"],
        });
    };

    let mut problems = Vec::new();
    let mut cards = Vec::new();
    for (field, problem) in [
        ("target_card", "invalid:e3.allowlist.target_card"),
        ("unrelated_card", "invalid:e3.allowlist.unrelated_card"),
        ("cold_card", "invalid:e3.allowlist.cold_card"),
    ] {
        match allowlist.get(field).and_then(Value::as_str) {
            Some(value) if safe_card(value) => cards.push(value.to_owned()),
            _ => problems.push(problem),
        }
    }
    if cards.len() == 3 && cards.iter().collect::<BTreeSet<_>>().len() != 3 {
        problems.push("invalid:e3.allowlist.cards_not_distinct");
    }
    let isolated_fixture = match allowlist.get("isolated_fixture") {
        Some(Value::Bool(value)) => Some(*value),
        _ => {
            problems.push("invalid:e3.allowlist.isolated_fixture");
            None
        }
    };

    let (sampling_interval_s, injection_window_s, drain_window_s) = match e3
        .get("windows")
        .and_then(Value::as_object)
    {
        None => {
            problems.push("missing:e3.windows");
            (None, None, None)
        }
        Some(windows) => {
            let interval = finite_number(windows.get("sampling_interval_s"));
            let interval =
                interval.filter(|value| (MIN_INTERVAL_S..=MAX_INTERVAL_S).contains(value));
            if interval.is_none() {
                problems.push("invalid:e3.windows.sampling_interval_s");
            }

            let parse_window =
                |name: &'static str, problem: &'static str, problems: &mut Vec<&'static str>| {
                    let value = finite_number(windows.get(name))
                        .filter(|value| (0.0..=MAX_WINDOW_S).contains(value));
                    if value.is_none() {
                        problems.push(problem);
                    }
                    value
                };
            let injection = parse_window(
                "injection_window_s",
                "invalid:e3.windows.injection_window_s",
                &mut problems,
            );
            let drain = parse_window(
                "drain_window_s",
                "invalid:e3.windows.drain_window_s",
                &mut problems,
            );
            if let (Some(interval), Some(injection)) = (interval, injection) {
                if scheduled_samples(injection, interval) > MAX_SAMPLES_PER_WINDOW {
                    problems.push("invalid:e3.windows.injection_window_sample_bound");
                }
            }
            if let (Some(interval), Some(drain)) = (interval, drain) {
                if scheduled_samples(drain, interval) > MAX_SAMPLES_PER_WINDOW {
                    problems.push("invalid:e3.windows.drain_window_sample_bound");
                }
            }
            (interval, injection, drain)
        }
    };

    let max_attempts = match e3.get("bounds").and_then(Value::as_object) {
        None => {
            problems.push("missing:e3.bounds");
            None
        }
        Some(bounds) => match bounds.get("max_attempts").and_then(Value::as_u64) {
            Some(value) if (1..=MAX_ATTEMPTS).contains(&value) => Some(value),
            _ => {
                problems.push("invalid:e3.bounds.max_attempts");
                None
            }
        },
    };

    let nodes = match e3.get("nodes").and_then(Value::as_array) {
        Some(nodes)
            if (1..=MAX_NODES).contains(&nodes.len())
                && nodes
                    .iter()
                    .all(|node| node.as_str().is_some_and(|s| !s.is_empty())) =>
        {
            let parsed = nodes
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if parsed.iter().collect::<BTreeSet<_>>().len() == parsed.len() {
                Some(parsed)
            } else {
                problems.push("invalid:e3.nodes");
                None
            }
        }
        _ => {
            problems.push("invalid:e3.nodes");
            None
        }
    };

    let decision_node = match e3.get("decision_node") {
        None => Some("gateway".to_owned()),
        Some(Value::String(value)) if !value.is_empty() && value.chars().count() <= 64 => {
            Some(value.clone())
        }
        _ => {
            problems.push("invalid:e3.decision_node");
            None
        }
    };

    let controller_timeout_s = match e3.get("controller_timeout_s") {
        None => Some(DEFAULT_CONTROLLER_TIMEOUT_S),
        Some(value) => finite_number(Some(value)).filter(|timeout| {
            (MIN_CONTROLLER_TIMEOUT_S..=MAX_CONTROLLER_TIMEOUT_S).contains(timeout)
        }),
    };
    if controller_timeout_s.is_none() {
        problems.push("invalid:e3.controller_timeout_s");
    }

    let problems = sorted_problems(problems);
    if !problems.is_empty() {
        return Err(ConfigError { problems });
    }

    Ok(E3Settings {
        run_id: run_id.to_owned(),
        target_card: cards[0].clone(),
        unrelated_card: cards[1].clone(),
        cold_card: cards[2].clone(),
        isolated_fixture: isolated_fixture.expect("validated isolated_fixture"),
        sampling_interval_s: sampling_interval_s.expect("validated sampling interval"),
        injection_window_s: injection_window_s.expect("validated injection window"),
        drain_window_s: drain_window_s.expect("validated drain window"),
        max_attempts: max_attempts.expect("validated max attempts"),
        controller_timeout_s: controller_timeout_s.expect("validated controller timeout"),
        nodes: nodes.expect("validated nodes"),
        decision_node: decision_node.expect("validated decision node"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_config() -> Value {
        json!({
            "run_id": "authz-validation-e3-test",
            "e3": {
                "allowlist": {
                    "target_card": "card-target-1",
                    "unrelated_card": "card-unrelated-1",
                    "cold_card": "card-cold-1",
                    "isolated_fixture": true
                },
                "windows": {
                    "sampling_interval_s": 0.02,
                    "injection_window_s": 0.05,
                    "drain_window_s": 0.05
                },
                "bounds": {"max_attempts": 8},
                "nodes": ["node-a"],
                "decision_node": "gateway"
            }
        })
    }

    fn assert_problem(config: &Value, expected: &str) {
        let error = load_e3_config(config).expect_err("configuration must be rejected");
        assert!(error.problems.contains(&expected), "{:?}", error.problems);
    }

    #[test]
    fn valid_config_loads_with_safe_defaults() {
        let settings = load_e3_config(&valid_config()).unwrap();
        assert_eq!(settings.run_id, "authz-validation-e3-test");
        assert!(settings.isolated_fixture);
        assert_eq!(
            (
                settings.target_card.as_str(),
                settings.unrelated_card.as_str(),
                settings.cold_card.as_str()
            ),
            ("card-target-1", "card-unrelated-1", "card-cold-1")
        );
        assert_eq!(settings.sampling_interval_s, 0.02);
        assert_eq!(settings.injection_window_s, 0.05);
        assert_eq!(settings.drain_window_s, 0.05);
        assert_eq!(settings.max_attempts, 8);
        assert_eq!(settings.controller_timeout_s, DEFAULT_CONTROLLER_TIMEOUT_S);
        assert_eq!(settings.nodes, ["node-a"]);
        assert_eq!(settings.decision_node, "gateway");
    }

    #[test]
    fn missing_sections_and_invalid_run_id_are_reported_before_nested_fields() {
        assert_problem(&json!({}), "invalid:run_id");
        assert_problem(&json!({"run_id": "authz-validation-e3-test"}), "missing:e3");
        assert_problem(
            &json!({"run_id": "authz-validation-e3-test", "e3": {}}),
            "missing:e3.allowlist",
        );
        assert_problem(&json!([]), "config_not_a_mapping");
    }

    #[test]
    fn cards_must_be_distinct_and_safe() {
        let mut duplicate = valid_config();
        duplicate["e3"]["allowlist"]["unrelated_card"] = json!("card-target-1");
        assert_problem(&duplicate, "invalid:e3.allowlist.cards_not_distinct");

        let mut unsafe_card = valid_config();
        unsafe_card["e3"]["allowlist"]["cold_card"] = json!("bad card");
        assert_problem(&unsafe_card, "invalid:e3.allowlist.cold_card");
    }

    #[test]
    fn isolated_fixture_must_be_a_boolean() {
        let mut missing = valid_config();
        missing["e3"]["allowlist"]
            .as_object_mut()
            .unwrap()
            .remove("isolated_fixture");
        assert_problem(&missing, "invalid:e3.allowlist.isolated_fixture");

        let mut wrong_type = valid_config();
        wrong_type["e3"]["allowlist"]["isolated_fixture"] = json!("true");
        assert_problem(&wrong_type, "invalid:e3.allowlist.isolated_fixture");
    }

    #[test]
    fn sampling_bounds_reject_out_of_range_and_boolean_values() {
        for (field, value, problem) in [
            (
                "sampling_interval_s",
                json!(0.005),
                "invalid:e3.windows.sampling_interval_s",
            ),
            (
                "sampling_interval_s",
                json!(601.0),
                "invalid:e3.windows.sampling_interval_s",
            ),
            (
                "injection_window_s",
                json!(-1.0),
                "invalid:e3.windows.injection_window_s",
            ),
            (
                "injection_window_s",
                json!(3601.0),
                "invalid:e3.windows.injection_window_s",
            ),
            (
                "injection_window_s",
                json!(true),
                "invalid:e3.windows.injection_window_s",
            ),
        ] {
            let mut config = valid_config();
            config["e3"]["windows"][field] = value;
            assert_problem(&config, problem);
        }

        let mut boundary = valid_config();
        boundary["e3"]["windows"]["sampling_interval_s"] = json!(600.0);
        boundary["e3"]["windows"]["injection_window_s"] = json!(3600.0);
        boundary["e3"]["windows"]["drain_window_s"] = json!(0.0);
        assert!(load_e3_config(&boundary).is_ok());
    }

    #[test]
    fn sample_count_bound_is_checked_per_window() {
        let mut config = valid_config();
        config["e3"]["windows"]["sampling_interval_s"] = json!(0.01);
        config["e3"]["windows"]["drain_window_s"] = json!(3600.0);
        assert_problem(&config, "invalid:e3.windows.drain_window_sample_bound");
    }

    #[test]
    fn attempt_count_bound_rejects_zero_excess_boolean_and_string() {
        for value in [json!(0), json!(MAX_ATTEMPTS + 1), json!(true), json!("4")] {
            let mut config = valid_config();
            config["e3"]["bounds"]["max_attempts"] = value;
            assert_problem(&config, "invalid:e3.bounds.max_attempts");
        }
        let mut boundary = valid_config();
        boundary["e3"]["bounds"]["max_attempts"] = json!(MAX_ATTEMPTS);
        assert!(load_e3_config(&boundary).is_ok());
    }

    #[test]
    fn node_and_decision_node_bounds_are_enforced() {
        let mut empty_nodes = valid_config();
        empty_nodes["e3"]["nodes"] = json!([]);
        assert_problem(&empty_nodes, "invalid:e3.nodes");

        let mut duplicate_nodes = valid_config();
        duplicate_nodes["e3"]["nodes"] = json!(["node-a", "node-a"]);
        assert_problem(&duplicate_nodes, "invalid:e3.nodes");

        let mut bad_decision_node = valid_config();
        bad_decision_node["e3"]["decision_node"] = json!("");
        assert_problem(&bad_decision_node, "invalid:e3.decision_node");
    }
}
