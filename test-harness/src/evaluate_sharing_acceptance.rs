use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Map, Value};
use std::fmt;

const SCHEMA: &str = "policy-evaluate-sharing-experimental-v1";
const SCOPE: &str = "policy-engine-evaluate-cpu-owner-sharing";
const SAMPLES_PER_CASE: usize = 15;
const CASES: usize = 72;
const ARMS: [&str; 2] = ["cached-fixed-second", "forced-assembly"];
const GRANT_SIZES: [u64; 3] = [128, 1001, 2048];
const THREAD_COUNTS: [u64; 3] = [1, 4, 8];
const OUTCOMES: [&str; 2] = ["allow-first", "deny"];
const CACHE_SCOPES: [&str; 2] = ["shared-measurement", "private-worker"];
const ENGINE_SCOPES: [&str; 2] = ["shared-workers", "private-worker"];
const CONTROL_NAMES: [&str; 7] = [
    "decisionParity",
    "allowTwoReads",
    "denyOneRead",
    "noLegacyReads",
    "workersJoined",
    "warmupExcluded",
    "freshOwnersPerArm",
];
const PREMISE_NAMES: [&str; 9] = [
    "entry",
    "evidencePort",
    "assemblyCache",
    "policyEngine",
    "matcher",
    "warmup",
    "cached",
    "forced",
    "scopeExclusions",
];
const MEASUREMENT_FIELDS: [&str; 26] = [
    "decisions",
    "wallNs",
    "latencyNs",
    "cardChecks",
    "orgReads",
    "evidenceReads",
    "scopedReads",
    "evidenceGrants",
    "initialEvidenceNs",
    "finalEvidenceNs",
    "cacheHits",
    "cacheMisses",
    "arcClones",
    "getLockWaitNs",
    "insertLockWaitNs",
    "allowed",
    "denied",
    "pending",
    "mismatches",
    "legacyReads",
    "engineInstanceCount",
    "cacheInstanceCount",
    "assemblyCacheScope",
    "policyEngineScope",
    "warmupExcluded",
    "workersJoined",
];

#[derive(Debug)]
struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueVisitor;

        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value with no duplicate object keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(|number| UniqueValue(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(value)))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                UniqueValue::deserialize(deserializer)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(UniqueValue(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(UniqueValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = Map::new();
                while let Some((key, UniqueValue(value))) =
                    object.next_entry::<String, UniqueValue>()?
                {
                    if values.insert(key.clone(), value).is_some() {
                        return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
                    }
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(UniqueVisitor)
    }
}

fn decode_json(input: &str) -> Result<Value, String> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let value = UniqueValue::deserialize(&mut deserializer)
        .map_err(|error| error.to_string())?
        .0;
    deserializer.end().map_err(|error| error.to_string())?;
    Ok(value)
}

fn keys_exact(value: &Value, expected: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn uint(value: &Value, name: &str) -> Result<u64, String> {
    value
        .as_u64()
        .ok_or_else(|| format!("invalid non-negative integer field: {name}"))
}

fn nonempty_string(value: &Value) -> bool {
    value.as_str().is_some_and(|text| !text.trim().is_empty())
}

fn fail(reason: impl Into<String>) -> Value {
    json!({
        "status": "FAIL",
        "reason": reason.into(),
        "performance": null,
        "verified_postcondition": {"complete": false}
    })
}

fn expected_cases() -> Vec<(String, u64, u64, &'static str, &'static str, &'static str)> {
    let mut cases = Vec::with_capacity(CASES);
    for grants in GRANT_SIZES {
        for threads in THREAD_COUNTS {
            for outcome in OUTCOMES {
                for cache_scope in CACHE_SCOPES {
                    for engine_scope in ENGINE_SCOPES {
                        cases.push((
                            format!(
                                "evaluate-sharing/{grants}/threads-{threads}/{outcome}/cache-{cache_scope}/engine-{engine_scope}"
                            ),
                            grants,
                            threads,
                            outcome,
                            cache_scope,
                            engine_scope,
                        ));
                    }
                }
            }
        }
    }
    cases
}

fn decisions_per_thread(grants: u64) -> Option<u64> {
    match grants {
        128 => Some(64),
        1001 => Some(32),
        2048 => Some(16),
        _ => None,
    }
}

fn owner_count(scope: &str, threads: u64, shared_scope: &str) -> u64 {
    if scope == shared_scope {
        1
    } else {
        threads
    }
}

fn validate_meta(meta: &Value) -> Result<(), String> {
    if !keys_exact(
        meta,
        &[
            "schema",
            "scope",
            "cases",
            "samplesPerCase",
            "arms",
            "grantSizes",
            "threads",
            "outcomes",
            "assemblyCacheScopes",
            "policyEngineScopes",
            "controls",
            "premises",
        ],
    ) {
        return Err("experiment meta fields differ from the exact protocol".into());
    }
    if meta["schema"].as_str() != Some(SCHEMA)
        || meta["scope"].as_str() != Some(SCOPE)
        || uint(&meta["cases"], "cases")? != CASES as u64
        || uint(&meta["samplesPerCase"], "samplesPerCase")? != SAMPLES_PER_CASE as u64
        || meta["arms"] != json!(ARMS)
        || meta["grantSizes"] != json!(GRANT_SIZES)
        || meta["threads"] != json!(THREAD_COUNTS)
        || meta["outcomes"] != json!(OUTCOMES)
        || meta["assemblyCacheScopes"] != json!(CACHE_SCOPES)
        || meta["policyEngineScopes"] != json!(ENGINE_SCOPES)
    {
        return Err("experiment meta differs from the exact topology".into());
    }
    if !keys_exact(&meta["controls"], &CONTROL_NAMES)
        || CONTROL_NAMES
            .iter()
            .any(|name| meta["controls"][*name].as_bool() != Some(true))
    {
        return Err("experiment controls are missing or not all asserted true".into());
    }
    if !keys_exact(&meta["premises"], &PREMISE_NAMES)
        || PREMISE_NAMES
            .iter()
            .any(|name| !nonempty_string(&meta["premises"][*name]))
    {
        return Err("experiment explanatory premises are incomplete".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_measurement(
    measurement: &Value,
    arm: &str,
    grants: u64,
    threads: u64,
    outcome: &str,
    cache_scope: &str,
    engine_scope: &str,
    decisions: u64,
) -> Result<(), String> {
    if !keys_exact(measurement, &MEASUREMENT_FIELDS) {
        return Err("measurement fields differ from the exact protocol".into());
    }
    let wall = uint(&measurement["wallNs"], "wallNs")?;
    let latency = measurement["latencyNs"]
        .as_array()
        .ok_or("latencyNs must be a non-empty array")?;
    if latency.is_empty() || latency.len() as u64 != decisions {
        return Err("latencyNs must contain one non-negative value per decision".into());
    }
    let mut max_latency = 0;
    for value in latency {
        let value = uint(value, "latencyNs")?;
        max_latency = max_latency.max(value);
    }
    if wall < max_latency {
        return Err("wallNs is shorter than an individual evaluate latency".into());
    }

    let values = [
        ("decisions", uint(&measurement["decisions"], "decisions")?),
        (
            "cardChecks",
            uint(&measurement["cardChecks"], "cardChecks")?,
        ),
        ("orgReads", uint(&measurement["orgReads"], "orgReads")?),
        (
            "evidenceReads",
            uint(&measurement["evidenceReads"], "evidenceReads")?,
        ),
        (
            "scopedReads",
            uint(&measurement["scopedReads"], "scopedReads")?,
        ),
        (
            "evidenceGrants",
            uint(&measurement["evidenceGrants"], "evidenceGrants")?,
        ),
        (
            "initialEvidenceNs",
            uint(&measurement["initialEvidenceNs"], "initialEvidenceNs")?,
        ),
        (
            "finalEvidenceNs",
            uint(&measurement["finalEvidenceNs"], "finalEvidenceNs")?,
        ),
        ("cacheHits", uint(&measurement["cacheHits"], "cacheHits")?),
        (
            "cacheMisses",
            uint(&measurement["cacheMisses"], "cacheMisses")?,
        ),
        ("arcClones", uint(&measurement["arcClones"], "arcClones")?),
        (
            "getLockWaitNs",
            uint(&measurement["getLockWaitNs"], "getLockWaitNs")?,
        ),
        (
            "insertLockWaitNs",
            uint(&measurement["insertLockWaitNs"], "insertLockWaitNs")?,
        ),
        ("allowed", uint(&measurement["allowed"], "allowed")?),
        ("denied", uint(&measurement["denied"], "denied")?),
        ("pending", uint(&measurement["pending"], "pending")?),
        (
            "mismatches",
            uint(&measurement["mismatches"], "mismatches")?,
        ),
        (
            "legacyReads",
            uint(&measurement["legacyReads"], "legacyReads")?,
        ),
        (
            "engineInstanceCount",
            uint(&measurement["engineInstanceCount"], "engineInstanceCount")?,
        ),
        (
            "cacheInstanceCount",
            uint(&measurement["cacheInstanceCount"], "cacheInstanceCount")?,
        ),
    ];
    let value = |name: &str| {
        values
            .iter()
            .find_map(|(field, value)| (*field == name).then_some(*value))
            .expect("measurement field was checked above")
    };
    let allow = outcome == "allow-first";
    let reads = decisions
        .checked_mul(if allow { 2 } else { 1 })
        .ok_or("evidence read count overflow")?;
    let evidence_grants = reads
        .checked_mul(grants)
        .ok_or("evidence grant count overflow")?;
    let expected = [
        ("decisions", decisions),
        ("cardChecks", decisions),
        ("orgReads", decisions),
        ("evidenceReads", reads),
        ("scopedReads", reads),
        ("evidenceGrants", evidence_grants),
        ("allowed", if allow { decisions } else { 0 }),
        ("denied", if allow { 0 } else { decisions }),
        ("pending", 0),
        ("mismatches", 0),
        ("legacyReads", 0),
        (
            "engineInstanceCount",
            owner_count(engine_scope, threads, "shared-workers"),
        ),
        (
            "cacheInstanceCount",
            owner_count(cache_scope, threads, "shared-measurement"),
        ),
    ];
    if expected
        .iter()
        .any(|(field, expected)| value(field) != *expected)
    {
        return Err("measurement decision, read, or owner counts violate the contract".into());
    }
    if measurement["assemblyCacheScope"].as_str() != Some(cache_scope)
        || measurement["policyEngineScope"].as_str() != Some(engine_scope)
    {
        return Err("measurement owner scopes differ from the case topology".into());
    }
    if measurement["warmupExcluded"].as_bool() != Some(true)
        || measurement["workersJoined"].as_bool() != Some(true)
    {
        return Err("measurement warmup or worker-join postconditions are not proven".into());
    }

    let hits = value("cacheHits");
    let misses = value("cacheMisses");
    if hits
        .checked_add(misses)
        .ok_or("cache reconciliation count overflow")?
        != reads
        || value("arcClones") != hits
    {
        return Err("cache counters do not reconcile with evidence reads".into());
    }
    let _initial_evidence_ns = uint(&measurement["initialEvidenceNs"], "initialEvidenceNs")?;
    let _final_evidence_ns = uint(&measurement["finalEvidenceNs"], "finalEvidenceNs")?;
    match arm {
        "cached-fixed-second" if hits != reads || misses != 0 => {
            return Err("cached arm must hit every evidence read and never miss".into());
        }
        "forced-assembly" if hits != 0 || misses != reads => {
            return Err("forced arm must miss every evidence read and never hit".into());
        }
        _ => {}
    }
    Ok(())
}

fn validate_case(
    row: &Value,
    expected: &(String, u64, u64, &'static str, &'static str, &'static str),
) -> Result<(), String> {
    if !keys_exact(
        row,
        &[
            "case",
            "grants",
            "threads",
            "outcome",
            "decisionsPerThread",
            "assemblyCacheScope",
            "policyEngineScope",
            "samples",
        ],
    ) {
        return Err("case fields differ from the exact protocol".into());
    }
    let grants = uint(&row["grants"], "grants")?;
    let threads = uint(&row["threads"], "threads")?;
    let decisions_per_thread = decisions_per_thread(grants).ok_or("unknown grant workload")?;
    if row["case"].as_str() != Some(expected.0.as_str())
        || grants != expected.1
        || threads != expected.2
        || row["outcome"].as_str() != Some(expected.3)
        || row["assemblyCacheScope"].as_str() != Some(expected.4)
        || row["policyEngineScope"].as_str() != Some(expected.5)
        || uint(&row["decisionsPerThread"], "decisionsPerThread")? != decisions_per_thread
    {
        return Err("case differs from the exact Cartesian topology".into());
    }
    let decisions = threads
        .checked_mul(decisions_per_thread)
        .ok_or("decision count overflow")?;
    let samples = row["samples"]
        .as_array()
        .ok_or("case samples are missing")?;
    if samples.len() != SAMPLES_PER_CASE {
        return Err("case must contain exactly 15 samples".into());
    }
    for (index, sample) in samples.iter().enumerate() {
        if !keys_exact(sample, &["index", "measurements"])
            || uint(&sample["index"], "sample.index")? != index as u64
        {
            return Err("sample fields or contiguous indices differ from the protocol".into());
        }
        let measurements = sample["measurements"]
            .as_object()
            .ok_or("sample measurements are missing")?;
        if measurements.len() != ARMS.len()
            || ARMS.iter().any(|arm| !measurements.contains_key(*arm))
        {
            return Err("sample must contain exactly the two benchmark arms".into());
        }
        for arm in ARMS {
            validate_measurement(
                &measurements[arm],
                arm,
                grants,
                threads,
                expected.3,
                expected.4,
                expected.5,
                decisions,
            )?;
        }
    }
    Ok(())
}

fn validate_end(end: &Value) -> Result<(), String> {
    if !keys_exact(
        end,
        &[
            "schema",
            "status",
            "cases",
            "samples",
            "measurements",
            "postconditions",
        ],
    ) {
        return Err("experiment end fields differ from the exact protocol".into());
    }
    if end["schema"].as_str() != Some(SCHEMA)
        || end["status"].as_str() != Some("PASS")
        || uint(&end["cases"], "cases")? != CASES as u64
        || uint(&end["samples"], "samples")? != (CASES * SAMPLES_PER_CASE) as u64
        || uint(&end["measurements"], "measurements")?
            != (CASES * SAMPLES_PER_CASE * ARMS.len()) as u64
    {
        return Err("experiment end counts or status are incomplete".into());
    }
    let postconditions = [
        "workersJoined",
        "allDecisionsChecked",
        "allReadCountsChecked",
        "ownerTopologyChecked",
        "cacheReconciliationChecked",
        "warmupExcluded",
    ];
    if !keys_exact(&end["postconditions"], &postconditions)
        || postconditions
            .iter()
            .any(|field| end["postconditions"][*field].as_bool() != Some(true))
    {
        return Err("experiment postconditions are not all proven".into());
    }
    Ok(())
}

fn check_evaluate_sharing_inner(stdout: &str) -> Result<Value, String> {
    let prefixes = [
        "EVALUATE_EXPERIMENT_META",
        "EVALUATE_EXPERIMENT_CASE",
        "EVALUATE_EXPERIMENT_END",
    ];
    let mut sequence = Vec::new();
    let mut meta = None;
    let mut cases = Vec::new();
    let mut end = None;
    let mut footer_seen = false;
    let footer_re = regex::Regex::new(
        r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in \d+(?:\.\d+)?s$",
    )
    .expect("constant Rust footer regex");

    for line in stdout.lines() {
        if footer_seen {
            if !line.trim().is_empty() {
                return Err("output follows the terminal Rust result".into());
            }
            continue;
        }
        let matching = prefixes
            .iter()
            .copied()
            .find(|prefix| line.starts_with(prefix));
        if let Some(prefix) = matching {
            if !line.starts_with(&format!("{prefix} ")) {
                return Err("malformed experiment protocol line prefix".into());
            }
            let payload = line[prefix.len() + 1..].trim();
            if payload.is_empty() {
                return Err("empty experiment protocol record".into());
            }
            let value = decode_json(payload)?;
            match prefix {
                "EVALUATE_EXPERIMENT_META" => {
                    if meta.is_some() {
                        return Err("duplicate experiment meta record".into());
                    }
                    meta = Some(value);
                }
                "EVALUATE_EXPERIMENT_CASE" => cases.push(value),
                "EVALUATE_EXPERIMENT_END" => {
                    if end.is_some() {
                        return Err("duplicate experiment end record".into());
                    }
                    end = Some(value);
                }
                _ => unreachable!(),
            }
            sequence.push(prefix);
            continue;
        }
        if line.contains("EVALUATE_EXPERIMENT_") {
            return Err("experiment protocol marker is not at the start of its line".into());
        }
        if line.to_ascii_lowercase().contains("filtered out") {
            if footer_re.is_match(line)
                && sequence.last().copied() == Some("EVALUATE_EXPERIMENT_END")
            {
                footer_seen = true;
                continue;
            }
            return Err("invalid or misplaced Rust result footer".into());
        }
        if line.starts_with("test result: ") {
            return Err("invalid or misplaced Rust result footer".into());
        }
    }

    let mut expected_sequence = Vec::with_capacity(CASES + 2);
    expected_sequence.push("EVALUATE_EXPERIMENT_META");
    expected_sequence.extend(std::iter::repeat_n("EVALUATE_EXPERIMENT_CASE", CASES));
    expected_sequence.push("EVALUATE_EXPERIMENT_END");
    if sequence != expected_sequence {
        return Err("experiment records are incomplete or outside meta/cases/end order".into());
    }
    if !footer_seen {
        return Err("complete Rust result footer is missing".into());
    }
    if cases.len() != CASES || meta.is_none() || end.is_none() {
        return Err("experiment meta/end or case records are incomplete".into());
    }

    let meta = meta.as_ref().expect("checked above");
    let end = end.as_ref().expect("checked above");
    validate_meta(meta)?;
    let expected = expected_cases();
    for (row, expected_case) in cases.iter().zip(expected.iter()) {
        validate_case(row, expected_case)?;
    }
    validate_end(end)?;

    Ok(json!({
        "status": "PASS",
        "reason": "complete strict PolicyEngine owner-sharing experiment protocol",
        "performance": {
            "schema": SCHEMA,
            "scope": SCOPE,
            "cases": CASES,
            "samples": CASES * SAMPLES_PER_CASE,
            "measurements": CASES * SAMPLES_PER_CASE * ARMS.len(),
            "raw": {"meta": meta, "cases": cases, "end": end},
        },
        "verified_postcondition": {
            "complete": true,
            "schema": SCHEMA,
            "cases": CASES,
            "samples": CASES * SAMPLES_PER_CASE,
            "measurements": CASES * SAMPLES_PER_CASE * ARMS.len(),
            "workersJoined": true,
            "warmupExcluded": true,
            "allDecisionsChecked": true,
            "allReadCountsChecked": true,
            "ownerTopologyChecked": true,
            "cacheReconciliationChecked": true,
        }
    }))
}

pub fn check_evaluate_sharing(stdout: &str) -> Value {
    match check_evaluate_sharing_inner(stdout) {
        Ok(value) => value,
        Err(reason) => fail(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> Value {
        let controls = CONTROL_NAMES
            .iter()
            .map(|name| ((*name).to_owned(), json!(true)))
            .collect::<Map<_, _>>();
        let premises = PREMISE_NAMES
            .iter()
            .map(|name| ((*name).to_owned(), json!("fixture premise")))
            .collect::<Map<_, _>>();
        json!({
            "schema": SCHEMA,
            "scope": SCOPE,
            "cases": CASES,
            "samplesPerCase": SAMPLES_PER_CASE,
            "arms": ARMS,
            "grantSizes": GRANT_SIZES,
            "threads": THREAD_COUNTS,
            "outcomes": OUTCOMES,
            "assemblyCacheScopes": CACHE_SCOPES,
            "policyEngineScopes": ENGINE_SCOPES,
            "controls": controls,
            "premises": premises,
        })
    }

    fn measurement(
        arm: &str,
        grants: u64,
        threads: u64,
        outcome: &str,
        cache_scope: &str,
        engine_scope: &str,
    ) -> Value {
        let decisions = threads * decisions_per_thread(grants).unwrap();
        let allow = outcome == "allow-first";
        let reads = decisions * if allow { 2 } else { 1 };
        let cached = arm == "cached-fixed-second";
        let hits = if cached { reads } else { 0 };
        let misses = if cached { 0 } else { reads };
        json!({
            "decisions": decisions,
            "wallNs": decisions,
            "latencyNs": vec![1; decisions as usize],
            "cardChecks": decisions,
            "orgReads": decisions,
            "evidenceReads": reads,
            "scopedReads": reads,
            "evidenceGrants": reads * grants,
            "initialEvidenceNs": 1,
            "finalEvidenceNs": if allow { 1 } else { 0 },
            "cacheHits": hits,
            "cacheMisses": misses,
            "arcClones": hits,
            "getLockWaitNs": 0,
            "insertLockWaitNs": 0,
            "allowed": if allow { decisions } else { 0 },
            "denied": if allow { 0 } else { decisions },
            "pending": 0,
            "mismatches": 0,
            "legacyReads": 0,
            "engineInstanceCount": owner_count(engine_scope, threads, "shared-workers"),
            "cacheInstanceCount": owner_count(cache_scope, threads, "shared-measurement"),
            "assemblyCacheScope": cache_scope,
            "policyEngineScope": engine_scope,
            "warmupExcluded": true,
            "workersJoined": true,
        })
    }

    fn row(expected: &(String, u64, u64, &'static str, &'static str, &'static str)) -> Value {
        let samples = (0..SAMPLES_PER_CASE)
            .map(|index| {
                let measurements = ARMS
                    .iter()
                    .map(|arm| {
                        (
                            (*arm).to_owned(),
                            measurement(
                                arm, expected.1, expected.2, expected.3, expected.4, expected.5,
                            ),
                        )
                    })
                    .collect::<Map<_, _>>();
                json!({"index": index, "measurements": measurements})
            })
            .collect::<Vec<_>>();
        json!({
            "case": expected.0,
            "grants": expected.1,
            "threads": expected.2,
            "outcome": expected.3,
            "decisionsPerThread": decisions_per_thread(expected.1).unwrap(),
            "assemblyCacheScope": expected.4,
            "policyEngineScope": expected.5,
            "samples": samples,
        })
    }

    fn end() -> Value {
        json!({
            "schema": SCHEMA,
            "status": "PASS",
            "cases": CASES,
            "samples": CASES * SAMPLES_PER_CASE,
            "measurements": CASES * SAMPLES_PER_CASE * ARMS.len(),
            "postconditions": {
                "workersJoined": true,
                "allDecisionsChecked": true,
                "allReadCountsChecked": true,
                "ownerTopologyChecked": true,
                "cacheReconciliationChecked": true,
                "warmupExcluded": true,
            },
        })
    }

    fn valid_stdout() -> String {
        let expected = expected_cases();
        let mut lines = vec![format!("EVALUATE_EXPERIMENT_META {}", meta())];
        lines.extend(
            expected
                .iter()
                .map(|case| format!("EVALUATE_EXPERIMENT_CASE {}", row(case))),
        );
        lines.push(format!("EVALUATE_EXPERIMENT_END {}", end()));
        lines.push(
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 12.34s"
                .to_owned(),
        );
        lines.join("\n") + "\n"
    }

    fn mutate_first_case(output: &str, mutate: impl FnOnce(&mut Value)) -> String {
        let prefix = "EVALUATE_EXPERIMENT_CASE ";
        let mut mutate = Some(mutate);
        let mut changed = false;
        let lines = output
            .lines()
            .map(|line| {
                let Some(payload) = line.strip_prefix(prefix) else {
                    return line.to_owned();
                };
                if changed {
                    return line.to_owned();
                }
                changed = true;
                let mut value: Value = serde_json::from_str(payload).unwrap();
                mutate.take().unwrap()(&mut value);
                format!("{prefix}{}", serde_json::to_string(&value).unwrap())
            })
            .collect::<Vec<_>>();
        assert!(changed);
        lines.join("\n") + "\n"
    }

    #[test]
    fn complete_owner_sharing_protocol_is_accepted() {
        let accepted = check_evaluate_sharing(&valid_stdout());
        assert_eq!(accepted["status"], "PASS", "{}", accepted["reason"]);
        assert_eq!(accepted["verified_postcondition"]["cases"], CASES);
        assert_eq!(accepted["verified_postcondition"]["samples"], 1080);
        assert_eq!(accepted["verified_postcondition"]["measurements"], 2160);
    }

    #[test]
    fn duplicate_keys_order_and_footer_fail_closed() {
        let good = valid_stdout();
        assert_eq!(
            check_evaluate_sharing(
                "EVALUATE_EXPERIMENT_META {\"schema\":\"x\",\"schema\":\"y\"}\n"
            )["status"],
            "FAIL"
        );
        let mut reordered = good.lines().map(str::to_owned).collect::<Vec<_>>();
        reordered.swap(0, 1);
        assert_eq!(
            check_evaluate_sharing(&reordered.join("\n"))["status"],
            "FAIL"
        );
        assert_eq!(
            check_evaluate_sharing(
                &good.replace("test result: ok. 1 passed", "test result: ok. 1 failed")
            )["status"],
            "FAIL"
        );
        assert_eq!(
            check_evaluate_sharing(
                &good.replace("EVALUATE_EXPERIMENT_END", "EVALUATE_EXPERIMENT_CASE")
            )["status"],
            "FAIL"
        );

        let case_lines = good
            .lines()
            .filter(|line| line.starts_with("EVALUATE_EXPERIMENT_CASE "))
            .collect::<Vec<_>>();
        assert_eq!(case_lines.len(), CASES);
        let duplicate_case = good
            .lines()
            .map(|line| {
                if line == case_lines[1] {
                    case_lines[0]
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        assert_eq!(check_evaluate_sharing(&duplicate_case)["status"], "FAIL");

        let mut removed = false;
        let missing_case = good
            .lines()
            .filter(|line| {
                if !removed && line.starts_with("EVALUATE_EXPERIMENT_CASE ") {
                    removed = true;
                    false
                } else {
                    true
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        assert_eq!(check_evaluate_sharing(&missing_case)["status"], "FAIL");
    }

    #[test]
    fn owner_cache_and_measurement_mutations_fail_closed() {
        let good = valid_stdout();
        for invalid in [
            mutate_first_case(&good, |row| {
                row["samples"][0]["measurements"]["cached-fixed-second"]["cacheHits"] = json!(0);
            }),
            mutate_first_case(&good, |row| {
                row["samples"][0]["measurements"]["forced-assembly"]["cacheMisses"] = json!(0);
            }),
            mutate_first_case(&good, |row| {
                row["samples"][0]["measurements"]["cached-fixed-second"]["arcClones"] = json!(0);
            }),
            mutate_first_case(&good, |row| {
                row["samples"][0]["measurements"]["cached-fixed-second"]["warmupExcluded"] =
                    json!(false);
            }),
            mutate_first_case(&good, |row| {
                row["samples"][0]["measurements"]["cached-fixed-second"]["latencyNs"] = json!([]);
            }),
        ] {
            assert_eq!(check_evaluate_sharing(&invalid)["status"], "FAIL");
        }
    }
}
