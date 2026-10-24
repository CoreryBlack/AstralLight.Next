use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const MODEL_MODULES: [&str; 2] = ["e5_model_check", "e5_model_check_two_mutations"];
pub const MAX_WORKERS: u64 = 12;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContractError {
    InvalidWorkerBudget,
    UnregisteredModel(String),
    InvalidConfiguration(String),
    EmptyShardSet,
    ShardSetMismatch,
    ConfigurationDrift,
    InvalidCounter(String),
    CounterOverflow,
    InvalidCounterexample,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Configuration {
    pub premises: BTreeMap<String, bool>,
    pub mode: String,
    pub bound: u64,
    pub required_bound: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum BoundIdentity {
    Complete,
    Exact(u64),
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ConfigurationKey {
    premises: Vec<(String, bool)>,
    mode: String,
    bound: BoundIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Shard {
    pub prefix: Vec<String>,
    pub configuration: Configuration,
    pub explored_states: u64,
    pub counters: Value,
    pub exploration_complete: bool,
    pub counterexample: Option<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergedShards {
    pub configuration: Configuration,
    pub explored_states: u64,
    pub counters: Value,
    pub exploration_complete: bool,
    pub counterexample: Option<Value>,
    pub status: &'static str,
}

pub fn validate_workers(value: &Value) -> Result<u64, ContractError> {
    value
        .as_u64()
        .filter(|workers| (1..=MAX_WORKERS).contains(workers))
        .ok_or(ContractError::InvalidWorkerBudget)
}

pub fn validate_model_module(module: &str) -> Result<(), ContractError> {
    if MODEL_MODULES.contains(&module) {
        Ok(())
    } else {
        Err(ContractError::UnregisteredModel(module.to_owned()))
    }
}

fn key_for(configuration: &Configuration) -> Result<ConfigurationKey, ContractError> {
    if configuration.mode != "strict" && configuration.mode != "bracket" {
        return Err(ContractError::InvalidConfiguration(
            "unknown observation mode".to_owned(),
        ));
    }
    if configuration.bound == 0 || configuration.required_bound == 0 {
        return Err(ContractError::InvalidConfiguration(
            "bounds must be positive finite integers".to_owned(),
        ));
    }
    Ok(ConfigurationKey {
        premises: configuration
            .premises
            .iter()
            .map(|(name, enabled)| (name.clone(), *enabled))
            .collect(),
        mode: configuration.mode.clone(),
        bound: if configuration.bound >= configuration.required_bound {
            BoundIdentity::Complete
        } else {
            BoundIdentity::Exact(configuration.bound)
        },
    })
}

pub fn configuration_key(configuration: &Configuration) -> Result<ConfigurationKey, ContractError> {
    key_for(configuration)
}

pub fn deduplicate_configurations(
    configurations: &[Configuration],
) -> Result<Vec<Configuration>, ContractError> {
    let mut seen = BTreeSet::new();
    let mut ordered = Vec::new();
    for configuration in configurations {
        let key = key_for(configuration)?;
        if seen.insert(key) {
            ordered.push(configuration.clone());
        }
    }
    Ok(ordered)
}

pub fn merge_shards(
    configuration: &Configuration,
    expected_prefixes: &[Vec<String>],
    shards: &[Shard],
) -> Result<MergedShards, ContractError> {
    key_for(configuration)?;
    if shards.is_empty() {
        return Err(ContractError::EmptyShardSet);
    }
    let actual_prefixes = shards
        .iter()
        .map(|shard| shard.prefix.clone())
        .collect::<Vec<_>>();
    if actual_prefixes != expected_prefixes {
        return Err(ContractError::ShardSetMismatch);
    }
    if shards
        .iter()
        .any(|shard| &shard.configuration != configuration)
    {
        return Err(ContractError::ConfigurationDrift);
    }
    let mut explored_states = shards.iter().try_fold(0_u64, |total, shard| {
        total
            .checked_add(shard.explored_states)
            .ok_or(ContractError::CounterOverflow)
    })?;
    let ancestors = expected_prefixes
        .iter()
        .flat_map(|prefix| (0..prefix.len()).map(move |length| prefix[..length].to_vec()))
        .collect::<BTreeSet<_>>();
    explored_states = explored_states
        .checked_add(ancestors.len() as u64)
        .ok_or(ContractError::CounterOverflow)?;

    let counters = add_json_values(
        &shards
            .iter()
            .map(|shard| &shard.counters)
            .collect::<Vec<_>>(),
        "counters",
    )?;
    let complete = shards.iter().all(|shard| shard.exploration_complete);
    let violations = counters
        .get("violations")
        .and_then(Value::as_u64)
        .ok_or_else(|| ContractError::InvalidCounter("violations".to_owned()))?;
    let mut best_example: Option<((u64, Vec<String>), &Value)> = None;
    for example in shards
        .iter()
        .filter_map(|shard| shard.counterexample.as_ref())
    {
        let key = counterexample_key(example)?;
        if best_example
            .as_ref()
            .is_none_or(|(best_key, _)| key < *best_key)
        {
            best_example = Some((key, example));
        }
    }
    let counterexample = best_example.map(|(_, example)| example.clone());
    let status = if violations > 0 {
        "FAIL"
    } else if complete {
        "PASS"
    } else {
        "UNKNOWN"
    };
    Ok(MergedShards {
        configuration: configuration.clone(),
        explored_states,
        counters,
        exploration_complete: complete,
        counterexample,
        status,
    })
}

fn add_json_values(values: &[&Value], path: &str) -> Result<Value, ContractError> {
    if values.is_empty() {
        return Ok(Value::from(0_u64));
    }
    if values.iter().all(|value| value.is_object()) {
        let keys = values
            .iter()
            .filter_map(|value| value.as_object())
            .flat_map(Map::keys)
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut sum = Map::new();
        for key in keys {
            let zero = Value::from(0_u64);
            let children = values
                .iter()
                .map(|value| value.get(&key).unwrap_or(&zero))
                .collect::<Vec<_>>();
            sum.insert(
                key.clone(),
                add_json_values(&children, &format!("{path}.{key}"))?,
            );
        }
        return Ok(Value::Object(sum));
    }
    if values.iter().any(|value| value.as_u64().is_none()) {
        return Err(ContractError::InvalidCounter(path.to_owned()));
    }
    let total = values.iter().try_fold(0_u64, |sum, value| {
        sum.checked_add(value.as_u64().expect("validated unsigned integer"))
            .ok_or(ContractError::CounterOverflow)
    })?;
    Ok(Value::from(total))
}

fn counterexample_key(value: &Value) -> Result<(u64, Vec<String>), ContractError> {
    let count = value
        .get("eventCount")
        .and_then(Value::as_u64)
        .ok_or(ContractError::InvalidCounterexample)?;
    let trace = value
        .get("trace")
        .and_then(Value::as_array)
        .ok_or(ContractError::InvalidCounterexample)?;
    let events = trace
        .iter()
        .map(|event| {
            event
                .get("event")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(ContractError::InvalidCounterexample)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((count, events))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::e5_model::{self, Mode, Premises, PREMISES};
    use serde_json::json;

    fn config(mode: &str, bound: u64) -> Configuration {
        Configuration {
            premises: BTreeMap::from([
                ("pending_probe".to_owned(), true),
                ("host_mediation".to_owned(), true),
            ]),
            mode: mode.to_owned(),
            bound,
            required_bound: 14,
        }
    }

    fn shard(prefix: &[&str], configuration: Configuration, states: u64, violations: u64) -> Shard {
        Shard {
            prefix: prefix.iter().map(|item| (*item).to_owned()).collect(),
            configuration,
            explored_states: states,
            counters: json!({
                "exploredTraces": 2,
                "violations": violations,
                "admittedDomainCounts": {"notStale": 1, "strictlyBefore": 0}
            }),
            exploration_complete: true,
            counterexample: None,
        }
    }

    #[test]
    fn worker_budget_is_integer_and_bounded() {
        for value in [
            json!(0),
            json!(13),
            json!(true),
            json!(1.0),
            json!("2"),
            Value::Null,
        ] {
            assert_eq!(
                validate_workers(&value),
                Err(ContractError::InvalidWorkerBudget)
            );
        }
        for value in [1, 4, 8, 12] {
            assert_eq!(validate_workers(&json!(value)).unwrap(), value);
        }
        assert_eq!(MAX_WORKERS, 12);
    }

    #[test]
    fn only_registered_offline_models_are_accepted() {
        assert!(validate_model_module("e5_model_check").is_ok());
        assert!(validate_model_module("e5_model_check_two_mutations").is_ok());
        assert_eq!(
            validate_model_module("std::process"),
            Err(ContractError::UnregisteredModel("std::process".to_owned()))
        );
    }

    #[test]
    fn configuration_deduplication_is_ordered_and_call_scoped() {
        let complete = config("strict", 28);
        let required = config("strict", 14);
        let under_two = config("strict", 2);
        let under_three = config("strict", 3);
        let bracket = config("bracket", 28);
        assert_eq!(
            deduplicate_configurations(&[
                complete.clone(),
                required.clone(),
                under_two.clone(),
                under_three.clone(),
                bracket.clone()
            ])
            .unwrap(),
            vec![complete.clone(), under_two, under_three, bracket]
        );
        assert_eq!(
            deduplicate_configurations(std::slice::from_ref(&required)).unwrap(),
            vec![required]
        );
    }

    #[test]
    fn complete_bound_key_collapses_above_required_but_underbounds_stay_distinct() {
        assert_eq!(
            configuration_key(&config("strict", 28)).unwrap(),
            configuration_key(&config("strict", 14)).unwrap()
        );
        assert_ne!(
            configuration_key(&config("strict", 2)).unwrap(),
            configuration_key(&config("strict", 3)).unwrap()
        );
        assert_ne!(
            configuration_key(&config("strict", 28)).unwrap(),
            configuration_key(&config("bracket", 28)).unwrap()
        );
        assert!(matches!(
            configuration_key(&config("unknown", 28)),
            Err(ContractError::InvalidConfiguration(_))
        ));
    }

    #[test]
    fn shard_merge_requires_complete_unique_order_and_matching_configuration() {
        let configuration = config("strict", 3);
        let prefixes = vec![
            vec!["INIT".to_owned()],
            vec!["INIT".to_owned(), "PROBE".to_owned()],
        ];
        let shards = vec![
            shard(&["INIT"], configuration.clone(), 5, 0),
            shard(&["INIT", "PROBE"], configuration.clone(), 7, 0),
        ];
        let merged = merge_shards(&configuration, &prefixes, &shards).unwrap();
        assert_eq!(merged.status, "PASS");
        assert!(merged.exploration_complete);
        assert_eq!(merged.explored_states, 14);
        assert_eq!(merged.counters["exploredTraces"], 4);
        assert_eq!(merged.counters["admittedDomainCounts"]["notStale"], 2);
        assert_eq!(
            merge_shards(&configuration, &prefixes, &shards[..1]),
            Err(ContractError::ShardSetMismatch)
        );
        let mut duplicate = shards.clone();
        duplicate.push(shards[0].clone());
        assert_eq!(
            merge_shards(&configuration, &prefixes, &duplicate),
            Err(ContractError::ShardSetMismatch)
        );
        let reversed = vec![shards[1].clone(), shards[0].clone()];
        assert_eq!(
            merge_shards(&configuration, &prefixes, &reversed),
            Err(ContractError::ShardSetMismatch)
        );
        assert_eq!(
            merge_shards(&configuration, &[], &[]),
            Err(ContractError::EmptyShardSet)
        );
        let mut drifted = shards.clone();
        drifted[1].configuration.mode = "bracket".to_owned();
        assert_eq!(
            merge_shards(&configuration, &prefixes, &drifted),
            Err(ContractError::ConfigurationDrift)
        );
    }

    #[test]
    fn nested_counts_sum_recursively_and_reject_invalid_values() {
        let left = json!({"counts":{"a":2,"b":1},"violations":0});
        let right = json!({"counts":{"a":3,"c":4},"violations":1});
        let merged = add_json_values(&[&left, &right], "counts").unwrap();
        assert_eq!(merged, json!({"counts":{"a":5,"b":1,"c":4},"violations":1}));
        assert!(matches!(
            add_json_values(&[&json!({"count":true})], "counts"),
            Err(ContractError::InvalidCounter(_))
        ));
        assert_eq!(
            add_json_values(&[&json!(u64::MAX), &json!(1)], "count"),
            Err(ContractError::CounterOverflow)
        );
    }

    #[test]
    fn merged_verdict_is_fail_closed_and_keeps_shortest_counterexample() {
        let configuration = config("strict", 14);
        let prefixes = vec![vec!["A".to_owned()], vec!["B".to_owned()]];
        let mut first = shard(&["A"], configuration.clone(), 4, 1);
        first.counterexample = Some(
            json!({"eventCount":3,"trace":[{"event":"INIT"},{"event":"B"},{"event":"ADMIT"}]}),
        );
        let mut second = shard(&["B"], configuration.clone(), 6, 0);
        second.exploration_complete = false;
        second.counterexample =
            Some(json!({"eventCount":2,"trace":[{"event":"INIT"},{"event":"ADMIT"}]}));
        let merged = merge_shards(&configuration, &prefixes, &[first, second]).unwrap();
        assert_eq!(merged.status, "FAIL");
        assert!(!merged.exploration_complete);
        assert_eq!(merged.counters["violations"], 1);
        assert_eq!(merged.counterexample.unwrap()["eventCount"], 2);
        let no_violations = vec![shard(&["A"], configuration.clone(), 1, 0), {
            let mut item = shard(&["B"], configuration.clone(), 1, 0);
            item.exploration_complete = false;
            item
        }];
        assert_eq!(
            merge_shards(&configuration, &prefixes, &no_violations)
                .unwrap()
                .status,
            "UNKNOWN"
        );
    }

    #[test]
    fn malformed_counterexamples_are_rejected_instead_of_tie_breaking_arbitrarily() {
        let configuration = config("strict", 14);
        let prefixes = vec![vec!["A".to_owned()]];
        let mut item = shard(&["A"], configuration.clone(), 1, 1);
        item.counterexample = Some(json!({"eventCount":1,"trace":[{"notEvent":"x"}]}));
        assert_eq!(
            merge_shards(&configuration, &prefixes, &[item]),
            Err(ContractError::InvalidCounterexample)
        );
    }

    fn single_configurations() -> Vec<(Premises, Mode, usize)> {
        let full = Premises::default();
        let mut configurations = vec![(full, Mode::Bracket, 28), (full, Mode::Strict, 28)];
        configurations.extend(
            PREMISES
                .iter()
                .map(|premise| (full.without(premise).unwrap(), Mode::Bracket, 28)),
        );
        configurations
    }

    fn run_single_configurations(configurations: &[(Premises, Mode, usize)]) -> Vec<Value> {
        configurations
            .iter()
            .map(|(premises, mode, bound)| e5_model::run_model(*premises, *mode, *bound).unwrap())
            .collect()
    }

    #[test]
    fn concurrent_configuration_runs_preserve_reports_and_input_order() {
        let configurations = single_configurations();
        let serial = run_single_configurations(&configurations);
        let split = configurations.len() / 2;
        let parallel = std::thread::scope(|scope| {
            let left = scope.spawn(|| run_single_configurations(&configurations[..split]));
            let right = scope.spawn(|| run_single_configurations(&configurations[split..]));
            let mut merged = left.join().unwrap();
            merged.extend(right.join().unwrap());
            merged
        });
        assert_eq!(parallel, serial);
    }
}
