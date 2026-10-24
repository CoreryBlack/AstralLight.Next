//! Native bounded-model worker-shard execution using scoped Rust threads.
//! The shard set and merge contract is the same deterministic prefix set used by
//! the serial model; only the dispatch mechanism differs.

use crate::e5_model::{Mode, Premises};
use crate::two_mutation_model;
use serde_json::{json, Value};

pub fn run_sharded_model_parallel(
    premises: Premises,
    mode: Mode,
    bound: usize,
    workers: usize,
) -> Result<Value, String> {
    if !(1..=12).contains(&workers) {
        return Err("worker count must be in [1, 12]".to_owned());
    }
    let prefixes = two_mutation_model::shard_prefixes(premises, mode, bound)?;
    if prefixes.is_empty() {
        return Err("model shard prefix set is empty".to_owned());
    }
    let workers = workers.min(prefixes.len()).max(1);
    let chunk_size = prefixes.len().div_ceil(workers);
    let shards = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for chunk in prefixes.chunks(chunk_size) {
            handles.push(scope.spawn(move || {
                chunk
                    .iter()
                    .map(|prefix| {
                        two_mutation_model::run_model_shard(premises, mode, bound, prefix)
                    })
                    .collect::<Result<Vec<_>, String>>()
            }));
        }
        handles
            .into_iter()
            .map(|handle| handle.join().expect("shard worker panicked"))
            .collect::<Result<Vec<_>, String>>()
            .map(|groups| groups.into_iter().flatten().collect::<Vec<_>>())
    })?;
    let configuration = shards
        .first()
        .ok_or("model shard set is empty")?
        .configuration
        .clone();
    let merged =
        crate::bounded_execution_contract::merge_shards(&configuration, &prefixes, &shards)
            .map_err(|error| format!("failed to merge model shards: {error:?}"))?;
    let mut report = json!({
        "premises": {
            "pending_probe": premises.pending_probe,
            "post_recheck": premises.post_recheck,
            "final_reload": premises.final_reload,
            "exact_identity": premises.exact_identity,
            "generation_revoke_fence": premises.generation_revoke_fence,
            "host_mediation": premises.host_mediation,
        },
        "mode": mode.as_str(),
        "bound": bound,
        "requiredBound": two_mutation_model::required_bound(premises, mode),
    });
    let object = report
        .as_object_mut()
        .ok_or("parallel report is not an object")?;
    for (key, value) in merged
        .counters
        .as_object()
        .ok_or("merged counters not object")?
    {
        object.insert(key.clone(), value.clone());
    }
    object.insert("exploredStates".to_owned(), json!(merged.explored_states));
    object.insert(
        "explorationComplete".to_owned(),
        json!(merged.exploration_complete),
    );
    object.insert(
        "counterexample".to_owned(),
        merged.counterexample.unwrap_or(Value::Null),
    );
    object.insert("status".to_owned(), json!(merged.status));
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parallel_worker_shards_match_serial_reports() {
        for premises in [
            Premises::default(),
            Premises::default().without("host_mediation").unwrap(),
        ] {
            for mode in [Mode::Strict, Mode::Bracket] {
                let bound = 3;
                let serial = two_mutation_model::run_sharded_model(premises, mode, bound).unwrap();
                for workers in [1, 2, 4] {
                    let parallel =
                        run_sharded_model_parallel(premises, mode, bound, workers).unwrap();
                    assert_eq!(parallel, serial, "{mode:?} workers={workers}");
                }
            }
        }
    }

    #[test]
    fn worker_count_is_bounded_and_dispatch_order_is_stable() {
        let premises = Premises::default();
        assert!(run_sharded_model_parallel(premises, Mode::Strict, 3, 0).is_err());
        assert!(run_sharded_model_parallel(premises, Mode::Strict, 3, 13).is_err());
        let first = run_sharded_model_parallel(premises, Mode::Strict, 3, 4).unwrap();
        let second = run_sharded_model_parallel(premises, Mode::Strict, 3, 4).unwrap();
        assert_eq!(first, second);
    }
}
