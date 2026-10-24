use crate::e5_model::{self, Mode, Premises, MAX_BOUND, MIN_BOUND, PREMISES};
use crate::two_mutation_model;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const CHECKER_NAME: &str = "universal-hypotheses-check";
pub const CHECKER_VERSION: &str = "rust-offline-v1";

const MODES: [Mode; 2] = [Mode::Bracket, Mode::Strict];
#[cfg(test)]
const HYPOTHESES: [&str; 10] = ["U1", "U2", "U3", "U4", "U5", "U6", "U7", "U8", "U9", "U10"];
const SINGLE_OMISSION_CLASSES: [&str; 6] = [
    "source_pending_commit_without_publication",
    "mutation_published_between_evidence_read_and_last_read",
    "source_pending_commit_without_publication",
    "successor_revision_identity_confusion",
    "stale_generation_pointer_rollback",
    "bypass_unmediated_admission",
];
const TWO_OMISSION_CLASSES: [Option<&str>; 6] = [
    Some("source_pending_commit_without_publication"),
    Some("mutation_published_between_evidence_read_and_last_read"),
    Some("source_pending_commit_without_publication"),
    Some("candidate_removal_identity_confusion"),
    None,
    Some("bypass_unmediated_admission"),
];
const SINGLE_EXPECTED_SAFE_SUBSETS: [&[usize]; 0] = [];
const TWO_EXPECTED_SAFE_SUBSETS: [&[usize]; 1] = [&[4]];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Lattice {
    Full,
    Singles,
}

impl Lattice {
    fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Singles => "singles",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelKind {
    Single,
    Two,
}

impl ModelKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Single => "single",
            Self::Two => "two",
        }
    }

    fn underlying(self) -> &'static str {
        match self {
            Self::Single => e5_model::MODEL_NAME,
            Self::Two => two_mutation_model::MODEL_NAME,
        }
    }

    fn required_bound(self, premises: Premises, mode: Mode) -> usize {
        match self {
            Self::Single => e5_model::required_bound(premises, mode),
            Self::Two => two_mutation_model::required_bound(premises, mode),
        }
    }

    fn minimum_bound(self) -> usize {
        MIN_BOUND
    }

    fn maximum_bound(self) -> usize {
        MAX_BOUND
    }

    fn run(self, premises: Premises, mode: Mode, bound: usize) -> Result<Value, String> {
        match self {
            Self::Single => e5_model::run_model(premises, mode, bound),
            Self::Two => {
                let workers = std::thread::available_parallelism()
                    .map(|value| value.get())
                    .unwrap_or(1)
                    .min(12);
                crate::bounded_worker_native::run_sharded_model_parallel(
                    premises, mode, bound, workers,
                )
            }
        }
    }

    fn omission_schedule(self, premise_index: usize) -> Option<&'static str> {
        match self {
            Self::Single => Some(SINGLE_OMISSION_CLASSES[premise_index]),
            Self::Two => TWO_OMISSION_CLASSES[premise_index],
        }
    }

    fn lattice(self) -> Lattice {
        match self {
            Self::Single => Lattice::Full,
            Self::Two => Lattice::Singles,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ConfigKey {
    model: String,
    premises: [bool; 6],
    mode: String,
    bound_key: String,
}

trait RunProvider {
    fn execute(
        &mut self,
        model: ModelKind,
        premises: Premises,
        mode: Mode,
        bound: usize,
    ) -> Result<Value, String>;
}

#[derive(Default)]
struct RunCache {
    runs: BTreeMap<ConfigKey, Value>,
}

impl RunProvider for RunCache {
    fn execute(
        &mut self,
        model: ModelKind,
        premises: Premises,
        mode: Mode,
        bound: usize,
    ) -> Result<Value, String> {
        let required = model.required_bound(premises, mode);
        let key = ConfigKey {
            model: model.as_str().to_owned(),
            premises: premise_bits(premises),
            mode: mode.as_str().to_owned(),
            bound_key: if bound >= required {
                "complete".to_owned()
            } else {
                bound.to_string()
            },
        };
        if let Some(report) = self.runs.get(&key) {
            return Ok(report.clone());
        }
        let report = model.run(premises, mode, bound)?;
        self.runs.insert(key, report.clone());
        Ok(report)
    }
}

fn premise_bits(premises: Premises) -> [bool; 6] {
    [
        premises.pending_probe,
        premises.post_recheck,
        premises.final_reload,
        premises.exact_identity,
        premises.generation_revoke_fence,
        premises.host_mediation,
    ]
}

fn proper_subsets(lattice: Lattice) -> Vec<Vec<usize>> {
    if lattice == Lattice::Singles {
        return (0..PREMISES.len()).map(|index| vec![index]).collect();
    }
    let count = 1usize << PREMISES.len();
    (1..count - 1)
        .map(|mask| {
            (0..PREMISES.len())
                .filter(|index| mask & (1 << index) != 0)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn without_indices(indices: &[usize]) -> Result<Premises, String> {
    let mut result = Premises::default();
    for index in indices {
        result = result.without(PREMISES[*index])?;
    }
    Ok(result)
}

fn omitted_premises(indices: &[usize]) -> Vec<String> {
    indices
        .iter()
        .map(|index| PREMISES[*index].to_owned())
        .collect()
}

fn expected_safe(model: ModelKind) -> BTreeSet<Vec<usize>> {
    match model {
        ModelKind::Single => SINGLE_EXPECTED_SAFE_SUBSETS
            .iter()
            .map(|subset| subset.to_vec())
            .collect(),
        ModelKind::Two => TWO_EXPECTED_SAFE_SUBSETS
            .iter()
            .map(|subset| subset.to_vec())
            .collect(),
    }
}

fn status(run: &Value) -> &str {
    run.get("status")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN")
}

fn is_complete(run: &Value) -> bool {
    run.get("explorationComplete").and_then(Value::as_bool) == Some(true)
}

fn number(run: &Value, path: &[&str]) -> Option<u64> {
    path.iter()
        .try_fold(run, |value, key| value.get(*key))
        .and_then(Value::as_u64)
}

fn map_sum(value: &Value) -> Option<u64> {
    let object = value.as_object()?;
    object
        .values()
        .try_fold(0u64, |total, item| total.checked_add(item.as_u64()?))
}

fn map_sum_prefix(map: &Map<String, Value>, prefix: &str) -> Option<u64> {
    map.iter()
        .filter(|(key, _)| key.starts_with(prefix))
        .try_fold(0u64, |total, (_, value)| total.checked_add(value.as_u64()?))
}

struct CoreHypothesisResults {
    u1_ok: bool,
    u3_ok: bool,
    u4_ok: bool,
    u5_ok: bool,
    u9_ok: bool,
    evidence: Value,
    conservation: Vec<Value>,
}

fn u1_u3_u4_u5_u9(
    model: ModelKind,
    bound: usize,
    cache: &mut dyn RunProvider,
) -> Result<CoreHypothesisResults, String> {
    let premises = Premises::default();
    let mut runs = BTreeMap::<String, Value>::new();
    for mode in MODES {
        runs.insert(
            mode.as_str().to_owned(),
            cache.execute(model, premises, mode, bound)?,
        );
    }
    let mut u1_ok = true;
    let mut u3_ok = true;
    let mut u4_ok = true;
    let mut u5_ok = true;
    let mut conservation = Vec::new();
    let mut u1_evidence = Map::new();
    let mut u3_evidence = Map::new();
    let mut u4_evidence = Map::new();
    let mut u5_evidence = Map::new();

    for mode in MODES {
        let key = mode.as_str();
        let run = &runs[key];
        let domains = &run["admittedDomainCounts"];
        let admitted = number(run, &["admittedTraces"]);
        let classified = map_sum(domains);
        let strictly_before = number(run, &["admittedDomainCounts", "strictlyBefore"]);
        let window = &run["admissionWindow"];
        let torn = &run["mixedManifestBody"];
        let denial_reasons = run["denialReasons"].as_object();
        let latch_denials = denial_reasons
            .map(|reasons| {
                reasons
                    .iter()
                    .filter(|(reason, _)| reason.starts_with("pending_probe_latched_unsafe_delta"))
                    .map(|(reason, count)| (reason.clone(), count.clone()))
                    .collect::<Map<_, _>>()
            })
            .unwrap_or_default();
        let stale_window = number(window, &["staleCommitPublishAfterLastReadTraces"]);
        let admitted_stale = number(window, &["admittedStaleCommitPublishAfterLastRead"]);
        let torn_traces = number(torn, &["tornReadTraces"]);
        let admitted_torn = number(torn, &["admittedTornReadTraces"]);
        let admitted_torn_domains = &torn["admittedTornReadTracesByDomain"];
        let publish_window = number(
            window,
            &["publishAfterFinalObservationBeforeAdmissionTraces"],
        );
        let admitted_publish = number(window, &["admittedPublishAfterFinalObservation"]);
        let outside_theorem = admitted
            .zip(strictly_before)
            .map(|(all, in_domain)| all.saturating_sub(in_domain));
        let latch_denial_count =
            map_sum_prefix(&latch_denials, "pending_probe_latched_unsafe_delta");

        u1_ok &= status(run) == "PASS" && is_complete(run) && strictly_before == Some(0);
        u3_ok &= stale_window.is_some_and(|count| count > 0)
            && admitted_stale == Some(0)
            && !latch_denials.is_empty()
            && latch_denial_count.is_some_and(|count| count > 0);
        u4_ok &= torn_traces.is_some_and(|count| count > 0)
            && admitted_torn == Some(0)
            && admitted_torn_domains.as_object().is_some_and(Map::is_empty);
        u5_ok &= publish_window.is_some_and(|count| count > 0)
            && admitted_publish
                .zip(outside_theorem)
                .is_some_and(|(inside, total)| inside <= total);

        if let (Some(admitted), Some(classified)) = (admitted, classified) {
            conservation.push(json!({
                "modelName": model.as_str(),
                "mode": key,
                "bound": run["bound"],
                "admittedTraces": admitted,
                "classifiedSum": classified,
            }));
        } else {
            conservation.push(json!({
                "modelName": model.as_str(),
                "mode": key,
                "admittedTraces": run["admittedTraces"],
                "classifiedSum": Value::Null,
            }));
        }

        u1_evidence.insert(
            key.to_owned(),
            json!({
                "status": status(run),
                "explorationComplete": is_complete(run),
                "admittedStrictlyBefore": strictly_before,
                "admittedTraces": admitted,
                "deniedTraces": run["deniedTraces"],
            }),
        );
        u3_evidence.insert(
            key.to_owned(),
            json!({
                "staleCommitPublishAfterLastReadTraces": stale_window,
                "admittedStaleCommitPublishAfterLastRead": admitted_stale,
                "pendingProbeLatchDenials": latch_denials,
            }),
        );
        u4_evidence.insert(
            key.to_owned(),
            json!({
                "tornReadTraces": torn_traces,
                "admittedTornReadTraces": admitted_torn,
                "admittedTornReadTracesByDomain": admitted_torn_domains,
            }),
        );
        u5_evidence.insert(
            key.to_owned(),
            json!({
                "publishAfterFinalObservationBeforeAdmissionTraces": publish_window,
                "admittedPublishAfterFinalObservation": admitted_publish,
                "admittedOutsideTheoremDomain": outside_theorem,
            }),
        );
    }
    let mode_statuses = runs.values().map(status).collect::<BTreeSet<_>>();
    let u9_ok = mode_statuses.len() == 1
        && mode_statuses.contains("PASS")
        && runs.values().all(is_complete);
    Ok(CoreHypothesisResults {
        u1_ok,
        u3_ok,
        u4_ok,
        u5_ok,
        u9_ok,
        evidence: json!({
            "U1": Value::Object(u1_evidence),
            "U3": Value::Object(u3_evidence),
            "U4": Value::Object(u4_evidence),
            "U5": Value::Object(u5_evidence),
            "U9": runs,
        }),
        conservation,
    })
}

fn run_u6(
    model: ModelKind,
    bound: usize,
    lattice: Lattice,
    cache: &mut dyn RunProvider,
    ledger: &mut Vec<Value>,
) -> Result<(bool, Value), String> {
    let expected_safe = expected_safe(model);
    let mut entries = Vec::new();
    let mut sufficient = Vec::new();
    let mut ok = true;
    let subsets = proper_subsets(lattice);
    for removed in subsets {
        let premises = without_indices(&removed)?;
        let run = cache.execute(model, premises, Mode::Bracket, bound)?;
        let violations = number(&run, &["violations"]);
        let explored_traces = number(&run, &["exploredTraces"]);
        let admitted = number(&run, &["admittedTraces"]);
        let domains = map_sum(&run["admittedDomainCounts"]);
        ledger.push(json!({
            "modelName": model.as_str(),
            "mode": "bracket",
            "bound": run["bound"],
            "admittedTraces": admitted,
            "classifiedSum": domains,
        }));
        let violating = violations.is_some_and(|count| count > 0);
        let expected_safe_here = expected_safe.contains(&removed);
        if !violating && !expected_safe_here {
            ok = false;
            sufficient.push(omitted_premises(&removed));
        }
        entries.push(json!({
            "removed": omitted_premises(&removed),
            "status": status(&run),
            "violations": violations,
            "exploredTraces": explored_traces,
        }));
    }
    let expected_safe_names = expected_safe
        .iter()
        .map(|subset| omitted_premises(subset))
        .collect::<Vec<_>>();
    let violation_count = entries
        .iter()
        .filter(|entry| entry["violations"].as_u64().is_some_and(|count| count > 0))
        .count();
    Ok((
        ok,
        json!({
            "latticePolicy": lattice.as_str(),
            "subsetsChecked": entries.len(),
            "violatingSubsets": violation_count,
            "candidateSufficientSubsets": sufficient,
            "expectedSafeSubsets": expected_safe_names,
            "lattice": entries,
        }),
    ))
}

fn run_u7(
    model: ModelKind,
    bound: usize,
    cache: &mut dyn RunProvider,
    ledger: &mut Vec<Value>,
) -> Result<(bool, Value), String> {
    let mut ok = true;
    let mut evidence = Map::new();
    for (index, premise) in PREMISES.iter().enumerate() {
        let premises = Premises::default().without(premise)?;
        let run = cache.execute(model, premises, Mode::Bracket, bound)?;
        ledger.push(json!({
            "modelName": model.as_str(),
            "mode": "bracket",
            "bound": run["bound"],
            "admittedTraces": number(&run, &["admittedTraces"]),
            "classifiedSum": map_sum(&run["admittedDomainCounts"]),
        }));
        let counterexample = &run["counterexample"];
        let observed = counterexample.get("scheduleClass").and_then(Value::as_str);
        let expected = model.omission_schedule(index);
        let sharp = match expected {
            Some(class) => status(&run) == "FAIL" && observed == Some(class),
            None => {
                status(&run) == "PASS"
                    && is_complete(&run)
                    && number(&run, &["violations"]) == Some(0)
            }
        };
        ok &= sharp;
        evidence.insert(
            (*premise).to_owned(),
            json!({
                "status": status(&run),
                "intendedScheduleClass": expected,
                "observedScheduleClass": observed,
                "counterexampleEvents": counterexample.get("eventCount"),
            }),
        );
    }
    Ok((ok, Value::Object(evidence)))
}

fn run_u8(
    model: ModelKind,
    cache: &mut dyn RunProvider,
    ledger: &mut Vec<Value>,
) -> Result<(bool, Value), String> {
    let mut ok = true;
    let mut evidence = Map::new();
    let mut configurations = vec![
        (
            "full-bracket".to_owned(),
            Premises::default(),
            Mode::Bracket,
        ),
        ("full-strict".to_owned(), Premises::default(), Mode::Strict),
    ];
    configurations.extend(PREMISES.iter().map(|premise| {
        (
            format!("without-{premise}"),
            Premises::default()
                .without(premise)
                .expect("registered premise"),
            Mode::Bracket,
        )
    }));
    let below_bound_keys = if model == ModelKind::Two {
        ["full-bracket", "full-strict"]
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
    } else {
        configurations
            .iter()
            .map(|(name, _, _)| name.clone())
            .collect()
    };
    for (name, premises, mode) in configurations {
        let required = model.required_bound(premises, mode);
        let at_required = cache.execute(model, premises, mode, required)?;
        ledger.push(json!({
            "modelName": model.as_str(),
            "mode": mode.as_str(),
            "bound": at_required["bound"],
            "admittedTraces": number(&at_required, &["admittedTraces"]),
            "classifiedSum": map_sum(&at_required["admittedDomainCounts"]),
        }));
        let complete = is_complete(&at_required);
        let mut entry = json!({
            "requiredBound": required,
            "completeAtRequired": complete,
        });
        if below_bound_keys.contains(&name) && required > model.minimum_bound() {
            let below = cache.execute(model, premises, mode, required - 1)?;
            ledger.push(json!({
                "modelName": model.as_str(),
                "mode": mode.as_str(),
                "bound": below["bound"],
                "admittedTraces": number(&below, &["admittedTraces"]),
                "classifiedSum": map_sum(&below["admittedDomainCounts"]),
            }));
            let never_pass = status(&below) != "PASS";
            entry["statusOneStepBelow"] = json!(status(&below));
            entry["incompleteTracesOneStepBelow"] = below["incompleteTraces"].clone();
            entry["neverPassBelowRequired"] = json!(never_pass);
            ok &= never_pass;
        }
        ok &= complete;
        evidence.insert(name, entry);
    }
    Ok((ok, Value::Object(evidence)))
}

fn build_aggregate_report(
    model: ModelKind,
    bound: usize,
    cache: &mut dyn RunProvider,
) -> Result<Value, String> {
    let full_premises = Premises::default();
    let bracket = cache.execute(model, full_premises, Mode::Bracket, bound)?;
    let strict = cache.execute(model, full_premises, Mode::Strict, bound)?;
    let modes = json!({"bracket": bracket, "strict": strict});
    let full_status = combine_status([status(&modes["bracket"]), status(&modes["strict"])]);
    let mut omissions = Vec::new();
    let mut states = number(&modes["bracket"], &["exploredStates"]).unwrap_or(0)
        + number(&modes["strict"], &["exploredStates"]).unwrap_or(0);
    let mut traces = number(&modes["bracket"], &["exploredTraces"]).unwrap_or(0)
        + number(&modes["strict"], &["exploredTraces"]).unwrap_or(0);
    for (index, premise) in PREMISES.iter().enumerate() {
        let run = cache.execute(model, full_premises.without(premise)?, Mode::Bracket, bound)?;
        states += number(&run, &["exploredStates"]).unwrap_or(0);
        traces += number(&run, &["exploredTraces"]).unwrap_or(0);
        let violations = number(&run, &["violations"]).unwrap_or(0);
        let complete = is_complete(&run);
        let (omission_status, finding) = if violations > 0 {
            ("FAIL", "counterexample_found")
        } else if complete {
            ("PASS", "not_independently_falsifiable")
        } else {
            ("UNKNOWN", "not_determined_incomplete_exploration")
        };
        omissions.push(json!({
            "premise": premise,
            "premiseRemoved": premise,
            "status": omission_status,
            "finding": finding,
            "counterexample": run["counterexample"],
            "run": run,
            "omissionIndex": index,
        }));
    }
    Ok(json!({
        "model": model.underlying(),
        "modelName": model.as_str(),
        "modelVersion": match model { ModelKind::Single => e5_model::MODEL_VERSION, ModelKind::Two => two_mutation_model::MODEL_VERSION },
        "bound": bound,
        "exploredStates": states,
        "exploredTraces": traces,
        "fullContract": {
            "status": full_status,
            "modes": modes,
        },
        "omissions": omissions,
        "status": full_status,
    }))
}

fn combine_status(statuses: [&str; 2]) -> &'static str {
    if statuses.contains(&"FAIL") {
        "FAIL"
    } else if statuses.contains(&"UNKNOWN") {
        "UNKNOWN"
    } else {
        "PASS"
    }
}

fn run_u10(
    model: ModelKind,
    bound: usize,
    cache: &mut dyn RunProvider,
) -> Result<(bool, Value), String> {
    let report = build_aggregate_report(model, bound, cache)?;
    let member_states = number(
        &report["fullContract"]["modes"]["bracket"],
        &["exploredStates"],
    )
    .unwrap_or(0)
        + number(
            &report["fullContract"]["modes"]["strict"],
            &["exploredStates"],
        )
        .unwrap_or(0)
        + report["omissions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| number(entry, &["run", "exploredStates"]).unwrap_or(0))
            .sum::<u64>();
    let member_traces = number(
        &report["fullContract"]["modes"]["bracket"],
        &["exploredTraces"],
    )
    .unwrap_or(0)
        + number(
            &report["fullContract"]["modes"]["strict"],
            &["exploredTraces"],
        )
        .unwrap_or(0)
        + report["omissions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| number(entry, &["run", "exploredTraces"]).unwrap_or(0))
            .sum::<u64>();
    let expected = combine_status([
        status(&report["fullContract"]["modes"]["bracket"]),
        status(&report["fullContract"]["modes"]["strict"]),
    ]);
    let ok = number(&report, &["exploredStates"]) == Some(member_states)
        && number(&report, &["exploredTraces"]) == Some(member_traces)
        && status(&report) == expected
        && status(&report["fullContract"]) == expected;
    Ok((
        ok,
        json!({
            "exploredStates": report["exploredStates"],
            "memberStateSum": member_states,
            "exploredTraces": report["exploredTraces"],
            "memberTraceSum": member_traces,
            "topLevelStatus": report["status"],
            "fullContractStatus": report["fullContract"]["status"],
            "expectedTopLevelStatus": expected,
        }),
    ))
}

fn evaluate_model_with_provider(
    model: ModelKind,
    bound: usize,
    cache: &mut dyn RunProvider,
) -> Result<Value, String> {
    if !(model.minimum_bound()..=model.maximum_bound()).contains(&bound) {
        return Err(format!(
            "bound must be a finite value in [{}, {}]",
            model.minimum_bound(),
            model.maximum_bound()
        ));
    }
    let lattice = model.lattice();
    let mut ledger = Vec::new();
    let core = u1_u3_u4_u5_u9(model, bound, cache)?;
    ledger.extend(core.conservation);
    let (u6_ok, u6_evidence) = run_u6(model, bound, lattice, cache, &mut ledger)?;
    let (u7_ok, u7_evidence) = run_u7(model, bound, cache, &mut ledger)?;
    let (u8_ok, u8_evidence) = run_u8(model, cache, &mut ledger)?;
    let (u10_ok, u10_evidence) = run_u10(model, bound, cache)?;
    let u2_ok = ledger.iter().all(|entry| {
        entry["admittedTraces"].as_u64().is_some()
            && entry["classifiedSum"].as_u64().is_some()
            && entry["admittedTraces"] == entry["classifiedSum"]
    });
    let u2_evidence = json!({"runsAudited": ledger.len()});

    let hypothesis_specs = [
        ("U1", core.u1_ok, core.evidence["U1"].clone()),
        ("U2", u2_ok, u2_evidence),
        ("U3", core.u3_ok, core.evidence["U3"].clone()),
        ("U4", core.u4_ok, core.evidence["U4"].clone()),
        ("U5", core.u5_ok, core.evidence["U5"].clone()),
        ("U6", u6_ok, u6_evidence),
        ("U7", u7_ok, u7_evidence),
        ("U8", u8_ok, u8_evidence),
        ("U9", core.u9_ok, core.evidence["U9"].clone()),
        ("U10", u10_ok, u10_evidence),
    ];
    let hypotheses = hypothesis_specs
        .iter()
        .map(|(id, ok, evidence)| {
            json!({
                "id": id,
                "status": if *ok { "PASS" } else { "FAIL" },
                "evidence": evidence,
            })
        })
        .collect::<Vec<_>>();
    let overall = if hypothesis_specs.iter().all(|(_, ok, _)| *ok) {
        "PASS"
    } else {
        "FAIL"
    };
    Ok(json!({
        "modelName": model.as_str(),
        "underlyingModel": model.underlying(),
        "status": overall,
        "hypotheses": hypotheses,
        "findings": [],
        "scopeBoundary": "abstract bounded-model evidence only; not implementation, deployment, runtime, or unbounded proof",
    }))
}

fn run_universal_with_provider(
    bound: usize,
    provider: &mut dyn RunProvider,
) -> Result<Value, String> {
    if !(MIN_BOUND..=MAX_BOUND).contains(&bound) {
        return Err(format!("bound must be in [{MIN_BOUND}, {MAX_BOUND}]"));
    }
    let single = evaluate_model_with_provider(ModelKind::Single, bound, provider)?;
    let two = evaluate_model_with_provider(ModelKind::Two, bound, provider)?;
    let status = if single["status"] == "PASS" && two["status"] == "PASS" {
        "PASS"
    } else if single["status"] == "FAIL" || two["status"] == "FAIL" {
        "FAIL"
    } else {
        "UNKNOWN"
    };
    Ok(json!({
        "checker": CHECKER_NAME,
        "checkerVersion": CHECKER_VERSION,
        "models": {"single": single, "two": two},
        "status": status,
        "scopeBoundary": "offline bounded-model evaluator output; full universal pass requires complete configuration coverage and is not implementation, deployment, runtime, or unbounded proof",
    }))
}

pub fn run_universal(bound: usize) -> Result<Value, String> {
    let mut provider = RunCache::default();
    run_universal_with_provider(bound, &mut provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureProvider {
        force_incomplete: bool,
    }

    impl RunProvider for FixtureProvider {
        fn execute(
            &mut self,
            model: ModelKind,
            premises: Premises,
            mode: Mode,
            bound: usize,
        ) -> Result<Value, String> {
            let required = model.required_bound(premises, mode);
            let complete = !self.force_incomplete && bound >= required;
            let bits = premise_bits(premises);
            let violations = match model {
                ModelKind::Single => u64::from(bits.iter().any(|enabled| !enabled)),
                ModelKind::Two if bits == [true, true, true, true, false, true] => 0,
                ModelKind::Two => u64::from(bits.iter().any(|enabled| !enabled)),
            };
            let run_status = if violations > 0 {
                "FAIL"
            } else if complete {
                "PASS"
            } else {
                "UNKNOWN"
            };
            let mut domains = Map::new();
            domains.insert("notStale".to_owned(), json!(2 - violations));
            domains.insert("strictlyBefore".to_owned(), json!(violations));
            if model == ModelKind::Two {
                domains.insert("strictlyBeforeRepresented".to_owned(), json!(0));
                domains.insert("identitySubstitution".to_owned(), json!(0));
            }
            domains.insert("overlapUnknown".to_owned(), json!(0));
            domains.insert("afterFinalObservation".to_owned(), json!(0));
            domains.insert("unknownDomain".to_owned(), json!(0));
            let schedule = if model == ModelKind::Single {
                SINGLE_OMISSION_CLASSES
                    .iter()
                    .enumerate()
                    .find_map(|(index, schedule)| (!bits[index]).then_some(*schedule))
            } else {
                TWO_OMISSION_CLASSES
                    .iter()
                    .enumerate()
                    .find_map(|(index, schedule)| (!bits[index]).then_some(*schedule).flatten())
            };
            let counterexample = if violations > 0 {
                json!({
                    "scheduleClass": schedule.unwrap_or("abstract-fixture-counterexample"),
                    "eventCount": 5,
                    "trace": ["fixture-witness"],
                })
            } else {
                Value::Null
            };
            Ok(json!({
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
                "requiredBound": required,
                "status": run_status,
                "explorationComplete": complete,
                "exploredStates": 12,
                "exploredTraces": 20,
                "incompleteTraces": if complete { 0 } else { 1 },
                "admittedTraces": 2,
                "deniedTraces": 5,
                "admittedDomainCounts": Value::Object(domains),
                "violations": violations,
                "counterexample": counterexample,
                "admissionWindow": {
                    "staleCommitPublishAfterLastReadTraces": 3,
                    "admittedStaleCommitPublishAfterLastRead": 0,
                    "publishAfterFinalObservationBeforeAdmissionTraces": 4,
                    "admittedPublishAfterFinalObservation": 1,
                },
                "mixedManifestBody": {
                    "tornReadTraces": 6,
                    "admittedTornReadTraces": 0,
                    "admittedTornReadTracesByDomain": {},
                },
                "denialReasons": {"pending_probe_latched_unsafe_delta:probe": 1},
            }))
        }
    }

    fn accepted_fixture() -> Value {
        fn model_fixture(name: &str, underlying: &str, lattice: &str, count: u64) -> Value {
            let modes = json!({
                "bracket": {"status":"PASS","explorationComplete":true,"admittedStrictlyBefore":0,"violations":0},
                "strict": {"status":"PASS","explorationComplete":true,"admittedStrictlyBefore":0,"violations":0}
            });
            let hypotheses = HYPOTHESES
                .iter()
                .map(|id| {
                    let evidence = match *id {
                        "U1" => modes.clone(),
                        "U6" => json!({"latticePolicy":lattice,"subsetsChecked":count}),
                        "U8" => {
                            let bounds = [
                                "full-bracket".to_owned(),
                                "full-strict".to_owned(),
                                "without-pending_probe".to_owned(),
                                "without-post_recheck".to_owned(),
                                "without-final_reload".to_owned(),
                                "without-exact_identity".to_owned(),
                                "without-generation_revoke_fence".to_owned(),
                                "without-host_mediation".to_owned(),
                            ];
                            bounds
                                .into_iter()
                                .map(|name| (name, json!({"completeAtRequired":true})))
                                .collect::<Map<_, _>>()
                                .into()
                        }
                        "U9" => modes.clone(),
                        _ => json!({}),
                    };
                    json!({"id":id,"status":"PASS","evidence":evidence})
                })
                .collect::<Vec<_>>();
            json!({
                "modelName": name,
                "underlyingModel": underlying,
                "status": "PASS",
                "hypotheses": hypotheses,
            })
        }
        json!({
            "checker": CHECKER_NAME,
            "status": "PASS",
            "models": {
                "single": model_fixture("single", e5_model::MODEL_NAME, "full", 62),
                "two": model_fixture("two", two_mutation_model::MODEL_NAME, "singles", 6),
            },
        })
    }

    #[test]
    fn single_model_evaluator_runs_u1_through_u10_over_the_actual_bounded_model() {
        let bound = e5_model::required_bound(Premises::default(), Mode::Bracket);
        assert_eq!(bound, 16);
        let report =
            evaluate_model_with_provider(ModelKind::Single, bound, &mut RunCache::default())
                .unwrap();
        assert_eq!(report["status"], "PASS", "{report}");
        assert_eq!(report["modelName"], "single");
        assert_eq!(report["hypotheses"].as_array().unwrap().len(), 10);
        assert_eq!(report["findings"], json!([]));
        for hypothesis in report["hypotheses"].as_array().unwrap() {
            assert_eq!(hypothesis["status"], "PASS", "{hypothesis}");
        }

        let u1 = &report["hypotheses"][0]["evidence"];
        for mode in ["bracket", "strict"] {
            assert_eq!(u1[mode]["status"], "PASS", "{mode}");
            assert_eq!(u1[mode]["explorationComplete"], true, "{mode}");
            assert_eq!(u1[mode]["admittedStrictlyBefore"], 0, "{mode}");
        }
        let u3 = &report["hypotheses"][2]["evidence"];
        for mode in ["bracket", "strict"] {
            assert!(
                u3[mode]["staleCommitPublishAfterLastReadTraces"]
                    .as_u64()
                    .is_some_and(|count| count > 0),
                "{mode}"
            );
            assert_eq!(
                u3[mode]["admittedStaleCommitPublishAfterLastRead"], 0,
                "{mode}"
            );
            assert!(
                u3[mode]["pendingProbeLatchDenials"]
                    .as_object()
                    .is_some_and(|items| !items.is_empty()),
                "{mode}"
            );
        }
        let u6 = &report["hypotheses"][5]["evidence"];
        assert_eq!(u6["subsetsChecked"], 62);
        assert_eq!(u6["violatingSubsets"], 62);
        assert_eq!(u6["candidateSufficientSubsets"], json!([]));
        let u7 = &report["hypotheses"][6]["evidence"];
        assert_eq!(u7.as_object().unwrap().len(), PREMISES.len());
        for (premise, expected_class) in PREMISES.iter().zip(SINGLE_OMISSION_CLASSES) {
            assert_eq!(u7[premise]["status"], "FAIL", "{premise}");
            assert_eq!(
                u7[premise]["observedScheduleClass"], expected_class,
                "{premise}"
            );
        }
        let u8 = &report["hypotheses"][7]["evidence"];
        assert_eq!(u8.as_object().unwrap().len(), 8);
        for (name, evidence) in u8.as_object().unwrap() {
            assert_eq!(evidence["completeAtRequired"], true, "{name}");
            if let Some(status) = evidence.get("statusOneStepBelow") {
                assert_ne!(status, "PASS", "{name}: {evidence}");
                assert_eq!(evidence["neverPassBelowRequired"], true, "{name}");
            }
        }
        let u9 = &report["hypotheses"][8]["evidence"];
        assert_eq!(
            u9.as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["bracket", "strict"])
        );
        assert!(u9
            .as_object()
            .unwrap()
            .values()
            .all(|run| status(run) == "PASS" && is_complete(run)));
        assert!(report["scopeBoundary"]
            .as_str()
            .unwrap()
            .contains("not implementation, deployment, runtime, or unbounded proof"));
    }

    #[test]
    fn single_model_bound_discipline_and_incomplete_counterexample_match_python_checks() {
        let premises = Premises::default();
        for mode in MODES {
            let required = e5_model::required_bound(premises, mode);
            let complete = e5_model::run_model(premises, mode, required).unwrap();
            assert_eq!(complete["explorationComplete"], true, "{}", mode.as_str());
            assert_eq!(complete["violations"], 0, "{}", mode.as_str());
        }

        let bracket_required = e5_model::required_bound(premises, Mode::Bracket);
        let underbound =
            e5_model::run_model(premises, Mode::Bracket, bracket_required - 1).unwrap();
        assert_ne!(underbound["status"], "PASS");
        if underbound["explorationComplete"] == false {
            assert_eq!(underbound["status"], "UNKNOWN");
            assert_eq!(underbound["violations"], 0);
            assert!(underbound["incompleteTraces"]
                .as_u64()
                .is_some_and(|count| count > 0));
        }
        assert!(
            underbound["bound"].as_u64().unwrap() < underbound["requiredBound"].as_u64().unwrap()
        );

        let omitted_host = premises.without("host_mediation").unwrap();
        let omission_required = e5_model::required_bound(omitted_host, Mode::Bracket);
        let decisive =
            e5_model::run_model(omitted_host, Mode::Bracket, omission_required - 1).unwrap();
        assert_eq!(decisive["status"], "FAIL");
        assert!(decisive["violations"]
            .as_u64()
            .is_some_and(|count| count > 0));
        assert_eq!(decisive["bound"], json!(omission_required - 1));
    }

    #[test]
    fn evaluator_runs_u1_through_u10_over_injected_bounded_run_records() {
        let mut provider = FixtureProvider {
            force_incomplete: false,
        };
        let report = run_universal_with_provider(28, &mut provider).unwrap();
        assert_eq!(report["status"], "PASS", "{report}");
        for model in ["single", "two"] {
            let item = &report["models"][model];
            assert_eq!(item["status"], "PASS");
            assert_eq!(item["hypotheses"].as_array().unwrap().len(), 10);
            assert_eq!(item["hypotheses"][0]["id"], "U1");
            assert_eq!(item["hypotheses"][9]["id"], "U10");
            assert!(item["scopeBoundary"].as_str().unwrap().contains("bounded"));
        }
    }

    #[test]
    fn evaluator_uses_six_singleton_two_model_lattice_and_all_62_single_model_subsets() {
        let mut provider = FixtureProvider {
            force_incomplete: false,
        };
        let report = run_universal_with_provider(28, &mut provider).unwrap();
        let single_u6 = &report["models"]["single"]["hypotheses"][5]["evidence"];
        let two_u6 = &report["models"]["two"]["hypotheses"][5]["evidence"];
        assert_eq!(single_u6["latticePolicy"], "full");
        assert_eq!(single_u6["subsetsChecked"], 62);
        assert_eq!(two_u6["latticePolicy"], "singles");
        assert_eq!(two_u6["subsetsChecked"], 6);
        assert_eq!(
            two_u6["expectedSafeSubsets"],
            json!([["generation_revoke_fence"]])
        );
    }

    #[test]
    fn universal_report_acceptance_requires_both_models_all_hypotheses_and_evidence() {
        let report = accepted_fixture();
        let verdict = crate::model_acceptance::check_universal(&report);
        assert_eq!(verdict["status"], "PASS", "{verdict}");
        let mut missing_model = report.clone();
        missing_model["models"]
            .as_object_mut()
            .unwrap()
            .remove("two");
        assert_eq!(
            crate::model_acceptance::check_universal(&missing_model)["status"],
            "UNKNOWN"
        );
        let mut missing_hypothesis = report.clone();
        missing_hypothesis["models"]["single"]["hypotheses"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert_eq!(
            crate::model_acceptance::check_universal(&missing_hypothesis)["status"],
            "UNKNOWN"
        );
        let mut failed = report.clone();
        failed["models"]["two"]["hypotheses"][3]["status"] = json!("FAIL");
        assert_eq!(
            crate::model_acceptance::check_universal(&failed)["status"],
            "FAIL"
        );
    }

    #[test]
    fn incomplete_model_evidence_never_mints_universal_pass() {
        let mut provider = FixtureProvider {
            force_incomplete: true,
        };
        let report = run_universal_with_provider(28, &mut provider).unwrap();
        assert_eq!(report["status"], "FAIL");
        for model in ["single", "two"] {
            assert_eq!(report["models"][model]["hypotheses"][0]["status"], "FAIL");
            assert_eq!(report["models"][model]["hypotheses"][7]["status"], "FAIL");
            assert_eq!(report["models"][model]["hypotheses"][8]["status"], "FAIL");
        }
    }

    #[test]
    fn concurrent_single_model_evaluations_preserve_every_hypothesis_and_report_field() {
        let bound = e5_model::required_bound(Premises::default(), Mode::Bracket);
        let expected =
            evaluate_model_with_provider(ModelKind::Single, bound, &mut RunCache::default())
                .unwrap();
        let (left, right) = std::thread::scope(|scope| {
            let left = scope.spawn(|| {
                evaluate_model_with_provider(ModelKind::Single, bound, &mut RunCache::default())
                    .unwrap()
            });
            let right = scope.spawn(|| {
                evaluate_model_with_provider(ModelKind::Single, bound, &mut RunCache::default())
                    .unwrap()
            });
            (left.join().unwrap(), right.join().unwrap())
        });
        assert_eq!(left, expected);
        assert_eq!(right, expected);
        assert_eq!(left["hypotheses"].as_array().unwrap().len(), 10);
    }
}
