use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Map, Value};
use std::fmt;

const SCHEMA: &str = "policy-evaluate-sharing-experimental-v2";
const SCOPE: &str = "policy-engine-evaluate-cpu-owner-sharing-attribution";
const SAMPLES_PER_CASE: usize = 15;
const CASES: usize = 72;
const ARMS: [&str; 2] = ["cached-fixed-second", "forced-assembly"];
const GRANT_SIZES: [u64; 3] = [128, 1001, 2048];
const THREAD_COUNTS: [u64; 3] = [1, 4, 8];
const OUTCOMES: [&str; 2] = ["allow-first", "deny"];
const CACHE_SCOPES: [&str; 2] = ["shared-measurement", "private-worker"];
const ENGINE_SCOPES: [&str; 2] = ["shared-workers", "private-worker"];
const CONTROL_NAMES: [&str; 10] = [
    "decisionParity",
    "allowTwoReads",
    "denyOneRead",
    "noLegacyReads",
    "workersJoined",
    "warmupExcluded",
    "freshOwnersPerArm",
    "atomicStatsReconciled",
    "breakerClosed",
    "cacheCriticalSectionCaptured",
];
const PREMISE_NAMES: [&str; 5] = ["entry", "stats", "cache", "breaker", "scopeExclusions"];
const MEASUREMENT_FIELDS: [&str; 30] = [
    "decisions",
    "cacheHits",
    "cacheMisses",
    "arcClones",
    "getLockWaitNs",
    "insertLockWaitNs",
    "getLockHoldNs",
    "insertLockHoldNs",
    "gcRemoved",
    "evictions",
    "engineEvaluationCount",
    "engineAllowCount",
    "engineDenyCount",
    "engineCardContextCheckNs",
    "engineInitialEvidenceLoadNs",
    "engineFinalEvidenceReloadNs",
    "engineEvidenceMatchNs",
    "engineTotalNs",
    "statsAndBreakerNs",
    "attributionTotalNs",
    "breakerMapWaitNs",
    "breakerStateWaitNs",
    "breakerClosed",
    "engineOwnerStats",
    "engineInstanceCount",
    "cacheInstanceCount",
    "assemblyCacheScope",
    "policyEngineScope",
    "warmupExcluded",
    "workersJoined",
];
const OWNER_FIELDS: [&str; 8] = [
    "evaluationCount",
    "allowCount",
    "denyCount",
    "cardContextCheckNs",
    "initialEvidenceLoadNs",
    "finalEvidenceReloadNs",
    "evidenceMatchNs",
    "totalNs",
];
const NUMERIC_MEASUREMENT_FIELDS: [&str; 24] = [
    "decisions",
    "cacheHits",
    "cacheMisses",
    "arcClones",
    "getLockWaitNs",
    "insertLockWaitNs",
    "getLockHoldNs",
    "insertLockHoldNs",
    "gcRemoved",
    "evictions",
    "engineEvaluationCount",
    "engineAllowCount",
    "engineDenyCount",
    "engineCardContextCheckNs",
    "engineInitialEvidenceLoadNs",
    "engineFinalEvidenceReloadNs",
    "engineEvidenceMatchNs",
    "engineTotalNs",
    "statsAndBreakerNs",
    "attributionTotalNs",
    "breakerMapWaitNs",
    "breakerStateWaitNs",
    "engineInstanceCount",
    "cacheInstanceCount",
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
        return Err("v2 meta fields differ from the exact protocol".into());
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
        return Err("v2 meta differs from the exact topology".into());
    }
    if !keys_exact(&meta["controls"], &CONTROL_NAMES)
        || CONTROL_NAMES
            .iter()
            .any(|name| meta["controls"][*name].as_bool() != Some(true))
    {
        return Err("v2 controls are missing or not all asserted true".into());
    }
    if !keys_exact(&meta["premises"], &PREMISE_NAMES)
        || PREMISE_NAMES
            .iter()
            .any(|name| !nonempty_string(&meta["premises"][*name]))
    {
        return Err("v2 premises are incomplete".into());
    }
    Ok(())
}

fn validate_owner_stats(
    owners: &Value,
    expected_count: u64,
    decisions: u64,
    allow: bool,
) -> Result<[u64; 8], String> {
    let owners = owners
        .as_array()
        .ok_or("engineOwnerStats must be an array")?;
    if owners.len() as u64 != expected_count {
        return Err("engineOwnerStats count differs from owner topology".into());
    }
    let mut totals = [0_u64; 8];
    for owner in owners {
        if !keys_exact(owner, &OWNER_FIELDS) {
            return Err("engineOwnerStats fields differ from the exact protocol".into());
        }
        let values = [
            uint(&owner["evaluationCount"], "evaluationCount")?,
            uint(&owner["allowCount"], "allowCount")?,
            uint(&owner["denyCount"], "denyCount")?,
            uint(&owner["cardContextCheckNs"], "cardContextCheckNs")?,
            uint(&owner["initialEvidenceLoadNs"], "initialEvidenceLoadNs")?,
            uint(&owner["finalEvidenceReloadNs"], "finalEvidenceReloadNs")?,
            uint(&owner["evidenceMatchNs"], "evidenceMatchNs")?,
            uint(&owner["totalNs"], "totalNs")?,
        ];
        let outcome_total = values[1]
            .checked_add(values[2])
            .ok_or("engine owner outcome count overflow")?;
        if values[0] == 0 || outcome_total != values[0] {
            return Err("an engine owner has inconsistent evaluation outcome counts".into());
        }
        for (total, value) in totals.iter_mut().zip(values) {
            *total = total
                .checked_add(value)
                .ok_or("engine owner attribution total overflow")?;
        }
    }
    if totals[0] != decisions
        || totals[1] != if allow { decisions } else { 0 }
        || totals[2] != if allow { 0 } else { decisions }
    {
        return Err("engine owner stats do not reconcile with decisions/outcome".into());
    }
    Ok(totals)
}

#[allow(clippy::too_many_arguments)]
fn validate_measurement(
    measurement: &Value,
    arm: &str,
    _grants: u64,
    threads: u64,
    outcome: &str,
    cache_scope: &str,
    engine_scope: &str,
    decisions: u64,
) -> Result<(), String> {
    if !keys_exact(measurement, &MEASUREMENT_FIELDS) {
        return Err("v2 measurement fields differ from the exact protocol".into());
    }
    for field in NUMERIC_MEASUREMENT_FIELDS {
        uint(&measurement[field], field)?;
    }
    let allow = outcome == "allow-first";
    let reads = decisions
        .checked_mul(if allow { 2 } else { 1 })
        .ok_or("evidence read count overflow")?;
    let expected_cache_owners = owner_count(cache_scope, threads, "shared-measurement");
    let expected_engine_owners = owner_count(engine_scope, threads, "shared-workers");
    let values = [
        ("decisions", uint(&measurement["decisions"], "decisions")?),
        ("cacheHits", uint(&measurement["cacheHits"], "cacheHits")?),
        (
            "cacheMisses",
            uint(&measurement["cacheMisses"], "cacheMisses")?,
        ),
        ("arcClones", uint(&measurement["arcClones"], "arcClones")?),
        (
            "engineEvaluationCount",
            uint(
                &measurement["engineEvaluationCount"],
                "engineEvaluationCount",
            )?,
        ),
        (
            "engineAllowCount",
            uint(&measurement["engineAllowCount"], "engineAllowCount")?,
        ),
        (
            "engineDenyCount",
            uint(&measurement["engineDenyCount"], "engineDenyCount")?,
        ),
        (
            "engineTotalNs",
            uint(&measurement["engineTotalNs"], "engineTotalNs")?,
        ),
        (
            "statsAndBreakerNs",
            uint(&measurement["statsAndBreakerNs"], "statsAndBreakerNs")?,
        ),
        (
            "attributionTotalNs",
            uint(&measurement["attributionTotalNs"], "attributionTotalNs")?,
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
    if values.iter().any(|(_, value)| *value > u64::MAX / 2) {
        return Err("v2 numeric attribution field exceeds bounded range".into());
    }
    if values[0].1 != decisions
        || values[1].1 + values[2].1 != reads
        || values[3].1 != values[1].1
        || values[4].1 != decisions
        || values[5].1 != if allow { decisions } else { 0 }
        || values[6].1 != if allow { 0 } else { decisions }
        || values[10].1 != expected_engine_owners
        || values[11].1 != expected_cache_owners
    {
        return Err("v2 decision, cache, engine, or owner counts violate the contract".into());
    }
    if measurement["assemblyCacheScope"].as_str() != Some(cache_scope)
        || measurement["policyEngineScope"].as_str() != Some(engine_scope)
        || measurement["warmupExcluded"].as_bool() != Some(true)
        || measurement["workersJoined"].as_bool() != Some(true)
        || measurement["breakerClosed"].as_bool() != Some(true)
    {
        return Err("v2 scope or safety postconditions are not proven".into());
    }
    let owners = validate_owner_stats(
        &measurement["engineOwnerStats"],
        expected_engine_owners,
        decisions,
        allow,
    )?;
    if owners[3]
        != uint(
            &measurement["engineCardContextCheckNs"],
            "engineCardContextCheckNs",
        )?
        || owners[4]
            != uint(
                &measurement["engineInitialEvidenceLoadNs"],
                "engineInitialEvidenceLoadNs",
            )?
        || owners[5]
            != uint(
                &measurement["engineFinalEvidenceReloadNs"],
                "engineFinalEvidenceReloadNs",
            )?
        || owners[6]
            != uint(
                &measurement["engineEvidenceMatchNs"],
                "engineEvidenceMatchNs",
            )?
        || owners[7] != uint(&measurement["engineTotalNs"], "engineTotalNs")?
    {
        return Err("engine owner phase totals do not reconcile with aggregate stats".into());
    }
    if measurement["attributionTotalNs"].as_u64().unwrap_or(0)
        < measurement["statsAndBreakerNs"].as_u64().unwrap_or(0)
    {
        return Err("attribution total is shorter than stats/breaker attribution".into());
    }
    match arm {
        "cached-fixed-second" if values[1].1 != reads || values[2].1 != 0 => {
            return Err("v2 cached arm must hit every evidence read".into())
        }
        "forced-assembly" if values[1].1 != 0 || values[2].1 != reads => {
            return Err("v2 forced arm must miss every evidence read".into())
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
        return Err("v2 case fields differ from the exact protocol".into());
    }
    let grants = uint(&row["grants"], "grants")?;
    let threads = uint(&row["threads"], "threads")?;
    let per_thread = decisions_per_thread(grants).ok_or("unknown grant workload")?;
    if row["case"].as_str() != Some(expected.0.as_str())
        || grants != expected.1
        || threads != expected.2
        || row["outcome"].as_str() != Some(expected.3)
        || row["assemblyCacheScope"].as_str() != Some(expected.4)
        || row["policyEngineScope"].as_str() != Some(expected.5)
        || uint(&row["decisionsPerThread"], "decisionsPerThread")? != per_thread
    {
        return Err("v2 case differs from the exact Cartesian topology".into());
    }
    let decisions = threads
        .checked_mul(per_thread)
        .ok_or("decision count overflow")?;
    let samples = row["samples"]
        .as_array()
        .ok_or("v2 case samples are missing")?;
    if samples.len() != SAMPLES_PER_CASE {
        return Err("v2 case must contain exactly 15 samples".into());
    }
    for (index, sample) in samples.iter().enumerate() {
        if !keys_exact(sample, &["index", "measurements"])
            || uint(&sample["index"], "sample.index")? != index as u64
        {
            return Err("v2 sample fields or indices differ from the protocol".into());
        }
        let measurements = sample["measurements"]
            .as_object()
            .ok_or("v2 sample measurements are missing")?;
        if measurements.len() != ARMS.len()
            || ARMS.iter().any(|arm| !measurements.contains_key(*arm))
        {
            return Err("v2 sample must contain exactly two benchmark arms".into());
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
        return Err("v2 end fields differ from the exact protocol".into());
    }
    if end["schema"].as_str() != Some(SCHEMA)
        || end["status"].as_str() != Some("PASS")
        || uint(&end["cases"], "cases")? != CASES as u64
        || uint(&end["samples"], "samples")? != (CASES * SAMPLES_PER_CASE) as u64
        || uint(&end["measurements"], "measurements")?
            != (CASES * SAMPLES_PER_CASE * ARMS.len()) as u64
    {
        return Err("v2 end counts or status are incomplete".into());
    }
    let postconditions = [
        "workersJoined",
        "allDecisionsChecked",
        "ownerTopologyChecked",
        "cacheReconciliationChecked",
        "atomicStatsReconciled",
        "breakerClosed",
        "warmupExcluded",
    ];
    if !keys_exact(&end["postconditions"], &postconditions)
        || postconditions
            .iter()
            .any(|field| end["postconditions"][*field].as_bool() != Some(true))
    {
        return Err("v2 end postconditions are not all proven".into());
    }
    Ok(())
}

fn check_inner(stdout: &str) -> Result<Value, String> {
    let prefixes = [
        "EVALUATE_SHARING_V2_META",
        "EVALUATE_SHARING_V2_CASE",
        "EVALUATE_SHARING_V2_END",
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
                return Err("malformed v2 marker prefix".into());
            }
            let payload = line[prefix.len() + 1..].trim();
            if payload.is_empty() {
                return Err("empty v2 protocol record".into());
            }
            let value = decode_json(payload)?;
            match prefix {
                "EVALUATE_SHARING_V2_META" => {
                    if meta.replace(value).is_some() {
                        return Err("duplicate v2 meta record".into());
                    }
                }
                "EVALUATE_SHARING_V2_CASE" => cases.push(value),
                "EVALUATE_SHARING_V2_END" => {
                    if end.replace(value).is_some() {
                        return Err("duplicate v2 end record".into());
                    }
                }
                _ => unreachable!(),
            }
            sequence.push(prefix);
            continue;
        }
        if line.contains("EVALUATE_SHARING_V2_") {
            return Err("v2 marker is not at the start of its line".into());
        }
        if line.to_ascii_lowercase().contains("filtered out") {
            if footer_re.is_match(line)
                && sequence.last().copied() == Some("EVALUATE_SHARING_V2_END")
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
    expected_sequence.push("EVALUATE_SHARING_V2_META");
    expected_sequence.extend(std::iter::repeat_n("EVALUATE_SHARING_V2_CASE", CASES));
    expected_sequence.push("EVALUATE_SHARING_V2_END");
    if sequence != expected_sequence {
        return Err("v2 records are incomplete or outside meta/cases/end order".into());
    }
    if !footer_seen {
        return Err("complete Rust result footer is missing".into());
    }

    let meta = meta.as_ref().ok_or("v2 meta is missing")?;
    let end = end.as_ref().ok_or("v2 end is missing")?;
    validate_meta(meta)?;
    let expected = expected_cases();
    if cases.len() != expected.len() {
        return Err("v2 case count is incomplete".into());
    }
    for (row, expected_case) in cases.iter().zip(expected.iter()) {
        validate_case(row, expected_case)?;
    }
    validate_end(end)?;

    Ok(json!({
        "status": "PASS",
        "reason": "complete strict PolicyEngine owner-sharing attribution protocol",
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
            "ownerTopologyChecked": true,
            "cacheReconciliationChecked": true,
            "atomicStatsReconciled": true,
            "breakerClosed": true,
        }
    }))
}

pub fn check_evaluate_sharing_v2(stdout: &str) -> Value {
    match check_inner(stdout) {
        Ok(value) => value,
        Err(reason) => fail(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controls() -> Map<String, Value> {
        CONTROL_NAMES
            .iter()
            .map(|name| ((*name).to_owned(), json!(true)))
            .collect()
    }

    fn meta() -> Value {
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
            "controls": controls(),
            "premises": {
                "entry": "fixture",
                "stats": "fixture",
                "cache": "fixture",
                "breaker": "fixture",
                "scopeExclusions": "fixture",
            },
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
        let hits = if arm == "cached-fixed-second" {
            reads
        } else {
            0
        };
        let misses = if arm == "cached-fixed-second" {
            0
        } else {
            reads
        };
        let engine_count = owner_count(engine_scope, threads, "shared-workers");
        let owner = json!({
            "evaluationCount": decisions / engine_count,
            "allowCount": if allow { decisions / engine_count } else { 0 },
            "denyCount": if allow { 0 } else { decisions / engine_count },
            "cardContextCheckNs": 1,
            "initialEvidenceLoadNs": 1,
            "finalEvidenceReloadNs": if allow { 1 } else { 0 },
            "evidenceMatchNs": 1,
            "totalNs": 4,
        });
        json!({
            "decisions": decisions,
            "cacheHits": hits,
            "cacheMisses": misses,
            "arcClones": hits,
            "getLockWaitNs": 0,
            "insertLockWaitNs": 0,
            "getLockHoldNs": reads,
            "insertLockHoldNs": 0,
            "gcRemoved": 0,
            "evictions": 0,
            "engineEvaluationCount": decisions,
            "engineAllowCount": if allow { decisions } else { 0 },
            "engineDenyCount": if allow { 0 } else { decisions },
            "engineCardContextCheckNs": engine_count,
            "engineInitialEvidenceLoadNs": engine_count,
            "engineFinalEvidenceReloadNs": if allow { engine_count } else { 0 },
            "engineEvidenceMatchNs": engine_count,
            "engineTotalNs": engine_count * 4,
            "statsAndBreakerNs": 1,
            "attributionTotalNs": 5,
            "breakerMapWaitNs": 0,
            "breakerStateWaitNs": 0,
            "breakerClosed": true,
            "engineOwnerStats": vec![owner; engine_count as usize],
            "engineInstanceCount": engine_count,
            "cacheInstanceCount": owner_count(cache_scope, threads, "shared-measurement"),
            "assemblyCacheScope": cache_scope,
            "policyEngineScope": engine_scope,
            "warmupExcluded": true,
            "workersJoined": true,
        })
    }

    fn valid_stdout() -> String {
        let mut lines = vec![format!("EVALUATE_SHARING_V2_META {}", meta())];
        for expected in expected_cases() {
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
            lines.push(format!(
                "EVALUATE_SHARING_V2_CASE {}",
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
            ));
        }
        lines.push(format!(
            "EVALUATE_SHARING_V2_END {}",
            json!({
                "schema": SCHEMA,
                "status": "PASS",
                "cases": CASES,
                "samples": CASES * SAMPLES_PER_CASE,
                "measurements": CASES * SAMPLES_PER_CASE * ARMS.len(),
                "postconditions": {
                    "workersJoined": true,
                    "allDecisionsChecked": true,
                    "ownerTopologyChecked": true,
                    "cacheReconciliationChecked": true,
                    "atomicStatsReconciled": true,
                    "breakerClosed": true,
                    "warmupExcluded": true,
                },
            })
        ));
        lines.push(
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.00s"
                .to_owned(),
        );
        lines.join("\n") + "\n"
    }

    #[test]
    fn complete_v2_protocol_is_accepted() {
        let accepted = check_evaluate_sharing_v2(&valid_stdout());
        assert_eq!(accepted["status"], "PASS", "{}", accepted["reason"]);
        assert_eq!(accepted["verified_postcondition"]["cases"], CASES);
    }

    #[test]
    fn duplicate_reordered_and_mutated_v2_records_fail_closed() {
        let good = valid_stdout();
        assert_eq!(
            check_evaluate_sharing_v2(
                &good.replace("EVALUATE_SHARING_V2_END", "EVALUATE_SHARING_V2_CASE")
            )["status"],
            "FAIL"
        );
        assert_eq!(
            check_evaluate_sharing_v2(
                &good.replace("test result: ok. 1 passed", "test result: ok. 1 failed")
            )["status"],
            "FAIL"
        );
        let first_case = good
            .lines()
            .find(|line| line.starts_with("EVALUATE_SHARING_V2_CASE "))
            .unwrap()
            .to_owned();
        let duplicate = good
            .lines()
            .map(|line| {
                if line == first_case {
                    format!("{line}\n{line}")
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(check_evaluate_sharing_v2(&duplicate)["status"], "FAIL");
        assert_eq!(
            check_evaluate_sharing_v2(
                &good.replace("\"breakerClosed\":true", "\"breakerClosed\":false")
            )["status"],
            "FAIL"
        );
        assert_eq!(
            check_evaluate_sharing_v2(&good.replace("\"getLockWaitNs\":0", "\"getLockWaitNs\":-1"))
                ["status"],
            "FAIL"
        );
        assert_eq!(
            check_evaluate_sharing_v2(&good.replace("\"engineTotalNs\":4", "\"engineTotalNs\":3"))
                ["status"],
            "FAIL"
        );
    }
}
