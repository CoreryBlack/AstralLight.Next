use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const SCHEMA: &str = "policy-evaluate-benefit-v1";
const SCOPE: &str = "policy-engine-evaluate-cpu";
const SAMPLES_PER_CASE: usize = 18;
const GRANT_SIZES: [u64; 5] = [1, 8, 128, 512, 2048];
const THREAD_COUNTS: [u64; 3] = [1, 4, 8];
const OUTCOMES: [&str; 3] = ["allow-first", "allow-last", "deny"];
const ARMS: [&str; 3] = ["cached-fixed-second", "forced-assembly", "production-clock"];
const ORDERS: [[usize; 3]; 6] = [
    [0, 1, 2],
    [1, 2, 0],
    [2, 0, 1],
    [0, 2, 1],
    [2, 1, 0],
    [1, 0, 2],
];
const CONTROL_NAMES: [&str; 8] = [
    "ownedEvidenceParity",
    "decisionParity",
    "allowTwoReads",
    "denyOneRead",
    "pendingOneRead",
    "crossSecondExpiry",
    "finalRevokeRefusal",
    "noLegacyReads",
];
const PREMISE_NAMES: [&str; 15] = [
    "entry",
    "evidencePort",
    "fixture",
    "cardPort",
    "resourceOwnership",
    "orgPort",
    "engine",
    "cached",
    "forced",
    "production",
    "readCounter",
    "latency",
    "throughput",
    "order",
    "scopeExclusions",
];
const MEASUREMENT_FIELDS: [&str; 16] = [
    "decisions",
    "wallNs",
    "latencyNs",
    "cardChecks",
    "orgReads",
    "evidenceReads",
    "scopedReads",
    "evidenceGrants",
    "cacheHits",
    "initialEvidenceNs",
    "finalEvidenceNs",
    "allowed",
    "denied",
    "pending",
    "mismatches",
    "legacyReads",
];
const SCOPE_BOUNDARIES: [&str; 8] = [
    "CPU-only whole PolicyEngine.evaluate call benchmark; owned evidence is still cloned.",
    "All arms use the same engine and fixture map data; independent cache stores prevent cross-arm contamination.",
    "Synthetic perpetual grants/card state and ORG checks are supplied by fixture ports, not production persistence.",
    "Fixture identity assertions cover PLATFORM_USER, identity_card 18/card 17/user 42/tenant 7/domain 11, and TenantScoped authoritative target 7/11.",
    "Per-decision latency covers the complete evaluate call through awaited return.",
    "Wall throughput includes barrier wake, in-loop result verification/storage/destruction, and worker joins; it excludes runtime/thread construction and cache prewarm.",
    "Forced assembly uses a unique synthetic second per read and no production hook; phase timers are fixture read-port totals, not engine ArcSwap statistics.",
    "Not a signed HTTP, database, session, SDK, business-admission, allocation, or deployment-capacity benchmark.",
];
const BOOTSTRAP_RESAMPLES: usize = 2000;
const BOOTSTRAP_SEED: u32 = 20261010;

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

fn uint(value: &Value, name: &str, minimum: Option<u64>) -> Result<u64, String> {
    let value = value
        .as_u64()
        .ok_or_else(|| format!("invalid integer field: {name}"))?;
    if minimum.is_some_and(|minimum| value < minimum) {
        return Err(format!("invalid integer field: {name}"));
    }
    Ok(value)
}

fn nonempty_string(value: &Value) -> bool {
    value.as_str().is_some_and(|text| !text.trim().is_empty())
}
fn fail(reason: impl Into<String>) -> Value {
    json!({"status":"FAIL", "reason":reason.into(), "performance":null, "verified_postcondition":{"complete":false}})
}

fn expected_cases() -> Vec<(String, u64, u64, &'static str)> {
    let mut cases = Vec::with_capacity(45);
    for grants in GRANT_SIZES {
        for threads in THREAD_COUNTS {
            for outcome in OUTCOMES {
                cases.push((
                    format!("evaluate/{grants}/threads-{threads}/{outcome}"),
                    grants,
                    threads,
                    outcome,
                ));
            }
        }
    }
    cases
}

fn decisions_per_thread(grants: u64) -> Option<u64> {
    match grants {
        1 | 8 => Some(256),
        128 => Some(96),
        512 => Some(32),
        2048 => Some(16),
        _ => None,
    }
}

fn validate_meta(meta: &Value) -> Result<(), String> {
    let object = meta
        .as_object()
        .ok_or("benchmark meta must be a JSON object")?;
    for (key, expected) in [
        ("schema", json!(SCHEMA)),
        ("scope", json!(SCOPE)),
        ("samplesPerCase", json!(SAMPLES_PER_CASE)),
        ("grantSizes", json!(GRANT_SIZES)),
        ("threads", json!(THREAD_COUNTS)),
        ("outcomes", json!(OUTCOMES)),
        ("arms", json!(ARMS)),
        ("timing", json!("evaluate-call-return")),
        ("debugAssertions", json!(false)),
    ] {
        let actual = object
            .get(key)
            .ok_or("benchmark meta differs from the exact protocol or topology")?;
        if actual != &expected {
            return Err("benchmark meta differs from the exact protocol or topology".into());
        }
    }
    let controls = object
        .get("controls")
        .and_then(Value::as_object)
        .ok_or("benchmark controls are missing or not all asserted true")?;
    if controls.len() != CONTROL_NAMES.len()
        || CONTROL_NAMES
            .iter()
            .any(|name| controls.get(*name).and_then(Value::as_bool) != Some(true))
    {
        return Err("benchmark controls are missing or not all asserted true".into());
    }
    if let Some(premises) = object.get("premises") {
        let premises = premises
            .as_object()
            .ok_or("benchmark explanatory premises are incomplete")?;
        if PREMISE_NAMES
            .iter()
            .any(|name| !premises.contains_key(*name))
            || premises.values().any(|value| !nonempty_string(value))
        {
            return Err("benchmark explanatory premises are incomplete".into());
        }
    } else if PREMISE_NAMES.iter().any(|name| !object.contains_key(*name)) {
        return Err("benchmark explanatory premises are incomplete".into());
    }
    for (name, value) in object {
        if [
            "schema",
            "scope",
            "samplesPerCase",
            "grantSizes",
            "threads",
            "outcomes",
            "arms",
            "timing",
            "debugAssertions",
            "controls",
        ]
        .contains(&name.as_str())
        {
            continue;
        }
        if name == "premises" && value.is_object() {
            continue;
        }
        let key = name.to_ascii_lowercase();
        if key.contains("debug")
            || ["profile", "buildprofile", "buildmode", "mode"].contains(&key.as_str())
        {
            let text = value.as_str().unwrap_or_default().to_ascii_lowercase();
            if value.as_bool() == Some(true)
                || (["profile", "buildprofile", "buildmode", "mode"].contains(&key.as_str())
                    && text.contains("debug"))
                || ["debug build", "debug profile"].contains(&text.as_str())
            {
                return Err("debug-build benchmark output is not accepted".into());
            }
        }
        if !nonempty_string(value) {
            return Err("additional benchmark meta fields must be nonempty text".into());
        }
    }
    Ok(())
}

fn validate_measurement(
    measurement: &Value,
    arm: &str,
    grants: u64,
    threads: u64,
    outcome: &str,
    decisions: u64,
) -> Result<(), String> {
    if !keys_exact(measurement, &MEASUREMENT_FIELDS) {
        return Err("measurement fields differ from the exact protocol".into());
    }
    let mut values = BTreeMap::new();
    for field in MEASUREMENT_FIELDS
        .iter()
        .copied()
        .filter(|field| *field != "latencyNs")
    {
        values.insert(field, uint(&measurement[field], field, Some(0))?);
    }
    if values["decisions"] != decisions {
        return Err("measurement decision count differs from the workload".into());
    }
    let wall = values["wallNs"];
    if wall < 1 {
        return Err("measurement wall time must be positive".into());
    }
    let latencies = measurement["latencyNs"]
        .as_array()
        .ok_or("measurement must contain one latency per decision")?;
    if latencies.len() as u64 != decisions {
        return Err("measurement must contain one latency per decision".into());
    }
    let latencies = latencies
        .iter()
        .map(|value| uint(value, "latencyNs", Some(1)))
        .collect::<Result<Vec<_>, _>>()?;
    let max_latency = latencies.iter().copied().max().unwrap_or(0);
    let sum_latency = latencies.iter().try_fold(0u64, |sum, value| {
        sum.checked_add(*value).ok_or("latency sum overflow")
    })?;
    if wall < max_latency {
        return Err("wall time is shorter than an individual evaluate call".into());
    }
    if u128::from(sum_latency) > u128::from(threads) * u128::from(wall) {
        return Err("total evaluate time exceeds the concurrent worker wall-time budget".into());
    }
    let allow = outcome == "allow-first" || outcome == "allow-last";
    let reads = decisions * if allow { 2 } else { 1 };
    let expected = [
        ("cardChecks", decisions),
        ("orgReads", decisions),
        ("evidenceReads", reads),
        ("scopedReads", reads),
        ("evidenceGrants", reads * grants),
        ("allowed", if allow { decisions } else { 0 }),
        ("denied", if allow { 0 } else { decisions }),
        ("pending", 0),
        ("mismatches", 0),
        ("legacyReads", 0),
    ];
    if expected
        .iter()
        .any(|(field, expected)| values[field] != *expected)
    {
        return Err("measurement decision or repository-read counters violate the contract".into());
    }
    if values["cacheHits"] > reads {
        return Err("cache hit count is outside the evidence-read count".into());
    }
    if arm == "cached-fixed-second" && values["cacheHits"] != reads {
        return Err("fixed-second arm did not demonstrate real cache hits".into());
    }
    if arm == "forced-assembly" && values["cacheHits"] != 0 {
        return Err("forced-assembly arm unexpectedly recorded cache hits".into());
    }
    if values["initialEvidenceNs"] == 0 {
        return Err("initial repository evidence timing must be positive".into());
    }
    if (values["finalEvidenceNs"] > 0) != allow {
        return Err("final evidence timing does not match the outcome".into());
    }
    if u128::from(values["initialEvidenceNs"]) + u128::from(values["finalEvidenceNs"])
        > u128::from(sum_latency)
    {
        return Err("repository evidence timing exceeds measured evaluate time".into());
    }
    Ok(())
}

fn validate_case(row: &Value) -> Result<(), String> {
    if !keys_exact(
        row,
        &[
            "case",
            "grants",
            "threads",
            "outcome",
            "decisionsPerThread",
            "samples",
        ],
    ) {
        return Err("case row fields differ from the exact protocol".into());
    }
    let grants = uint(&row["grants"], "grants", Some(1))?;
    let threads = uint(&row["threads"], "threads", Some(1))?;
    let outcome = row["outcome"].as_str().ok_or("case outcome is invalid")?;
    if !GRANT_SIZES.contains(&grants)
        || !THREAD_COUNTS.contains(&threads)
        || !OUTCOMES.contains(&outcome)
    {
        return Err("case is outside the exact benchmark topology".into());
    }
    let expected_name = format!("evaluate/{grants}/threads-{threads}/{outcome}");
    if row["case"].as_str() != Some(&expected_name) {
        return Err("case string does not encode its exact workload".into());
    }
    let per_thread = decisions_per_thread(grants).ok_or("unknown grant workload")?;
    if uint(&row["decisionsPerThread"], "decisionsPerThread", Some(0))? != per_thread {
        return Err("decisionsPerThread differs from the registered workload map".into());
    }
    let decisions = threads * per_thread;
    let samples = row["samples"]
        .as_array()
        .ok_or("case does not contain exactly 18 samples")?;
    if samples.len() != SAMPLES_PER_CASE {
        return Err("case does not contain exactly 18 samples".into());
    }
    for (index, sample) in samples.iter().enumerate() {
        if !keys_exact(sample, &["index", "order", "measurements"]) {
            return Err("sample fields differ from the exact protocol".into());
        }
        if uint(&sample["index"], "sample.index", Some(0))? != index as u64 {
            return Err("sample indices must be contiguous from 0 through 17".into());
        }
        let expected_order = ORDERS[index % ORDERS.len()]
            .iter()
            .map(|arm| ARMS[*arm])
            .collect::<Vec<_>>();
        let order = sample["order"]
            .as_array()
            .ok_or("sample arm order differs from the six-step rotation")?;
        if order.len() != 3
            || order
                .iter()
                .zip(expected_order)
                .any(|(actual, expected)| actual.as_str() != Some(expected))
        {
            return Err("sample arm order differs from the six-step rotation".into());
        }
        let measurements = sample["measurements"]
            .as_object()
            .ok_or("sample must contain exactly the three benchmark arms")?;
        if measurements.len() != ARMS.len()
            || ARMS.iter().any(|arm| !measurements.contains_key(*arm))
        {
            return Err("sample must contain exactly the three benchmark arms".into());
        }
        for arm in ARMS {
            validate_measurement(&measurements[arm], arm, grants, threads, outcome, decisions)?;
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
        return Err("benchmark end record fields differ from the exact protocol".into());
    }
    if end["schema"].as_str() != Some(SCHEMA)
        || end["status"].as_str() != Some("PASS")
        || uint(&end["cases"], "cases", Some(0))? != 45
        || uint(&end["samples"], "samples", Some(0))? != 810
        || uint(&end["measurements"], "measurements", Some(0))? != 2430
    {
        return Err("benchmark end counts or status are incomplete".into());
    }
    if !keys_exact(
        &end["postconditions"],
        &[
            "workersJoined",
            "allDecisionsChecked",
            "allReadCountsChecked",
        ],
    ) || [
        "workersJoined",
        "allDecisionsChecked",
        "allReadCountsChecked",
    ]
    .iter()
    .any(|field| end["postconditions"][field].as_bool() != Some(true))
    {
        return Err("benchmark worker or per-decision postconditions are not proven".into());
    }
    Ok(())
}

fn nearest_rank(values: &[u64], percentile: f64) -> u64 {
    let mut values = values.to_vec();
    values.sort_unstable();
    let rank = (percentile * values.len() as f64).ceil() as usize;
    values[rank.saturating_sub(1).min(values.len() - 1)]
}
fn mean(values: &[f64]) -> Result<f64, String> {
    if values.is_empty() {
        return Err("empty statistic".into());
    }
    let value = values.iter().sum::<f64>() / values.len() as f64;
    if value.is_finite() {
        Ok(value)
    } else {
        Err("non-finite summary statistic".into())
    }
}
fn quantile(values: &[f64], probability: f64) -> f64 {
    let mut values = values.to_vec();
    values.sort_by(f64::total_cmp);
    let position = (values.len() - 1) as f64 * probability;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    if lower == upper {
        values[lower]
    } else {
        values[lower] + (values[upper] - values[lower]) * (position - lower as f64)
    }
}

struct PythonRandom {
    state: [u32; 624],
    index: usize,
}
impl PythonRandom {
    fn seeded(seed: u32) -> Self {
        let mut rng = Self {
            state: [0; 624],
            index: 624,
        };
        rng.state[0] = 19650218;
        for i in 1..624 {
            rng.state[i] = 1812433253u32
                .wrapping_mul(rng.state[i - 1] ^ (rng.state[i - 1] >> 30))
                .wrapping_add(i as u32);
        }
        let key = [seed];
        let mut i = 1usize;
        let mut j = 0usize;
        for _ in 0..624 {
            rng.state[i] = (rng.state[i]
                ^ ((rng.state[i - 1] ^ (rng.state[i - 1] >> 30)).wrapping_mul(1664525)))
            .wrapping_add(key[j])
            .wrapping_add(j as u32);
            i += 1;
            j += 1;
            if i >= 624 {
                rng.state[0] = rng.state[623];
                i = 1;
            }
            if j >= key.len() {
                j = 0;
            }
        }
        for _ in 0..623 {
            rng.state[i] = (rng.state[i]
                ^ ((rng.state[i - 1] ^ (rng.state[i - 1] >> 30)).wrapping_mul(1566083941)))
            .wrapping_sub(i as u32);
            i += 1;
            if i >= 624 {
                rng.state[0] = rng.state[623];
                i = 1;
            }
        }
        rng.state[0] = 0x80000000;
        rng
    }
    fn next_u32(&mut self) -> u32 {
        if self.index >= 624 {
            for i in 0..624 {
                let y = (self.state[i] & 0x80000000) | (self.state[(i + 1) % 624] & 0x7fffffff);
                let mut value = self.state[(i + 397) % 624] ^ (y >> 1);
                if y & 1 != 0 {
                    value ^= 0x9908b0df;
                }
                self.state[i] = value;
            }
            self.index = 0;
        }
        let mut value = self.state[self.index];
        self.index += 1;
        value ^= value >> 11;
        value ^= (value << 7) & 0x9d2c5680;
        value ^= (value << 15) & 0xefc60000;
        value ^= value >> 18;
        value
    }
    fn random(&mut self) -> f64 {
        let a = (self.next_u32() >> 5) as u64;
        let b = (self.next_u32() >> 6) as u64;
        ((a << 26) + b) as f64 / 9007199254740992.0
    }
}
fn bootstrap_interval(ratios: &[f64], seed: u32) -> Result<(f64, f64), String> {
    let logs = ratios.iter().map(|ratio| ratio.ln()).collect::<Vec<_>>();
    let mut random = PythonRandom::seeded(seed);
    let mut estimates = Vec::with_capacity(BOOTSTRAP_RESAMPLES);
    for _ in 0..BOOTSTRAP_RESAMPLES {
        let draw = (0..logs.len())
            .map(|_| logs[(random.random() * logs.len() as f64) as usize])
            .collect::<Vec<_>>();
        estimates.push(mean(&draw)?);
    }
    let interval = (
        quantile(&estimates, 0.025).exp(),
        quantile(&estimates, 0.975).exp(),
    );
    if !interval.0.is_finite() || !interval.1.is_finite() || interval.0 <= 0.0 || interval.1 <= 0.0
    {
        return Err("non-finite bootstrap interval".into());
    }
    Ok(interval)
}

fn summarize_case(row: &Value, seed: u32) -> Result<Value, String> {
    let samples = row["samples"].as_array().ok_or("case samples missing")?;
    let outcome = row["outcome"].as_str().ok_or("case outcome missing")?;
    let decisions = uint(&row["threads"], "threads", Some(1))?
        * uint(&row["decisionsPerThread"], "decisionsPerThread", Some(1))?;
    let mut latency = BTreeMap::<&str, Vec<u64>>::new();
    let mut mean_decision = BTreeMap::<&str, Vec<f64>>::new();
    let mut batch_throughput = BTreeMap::<&str, Vec<f64>>::new();
    let mut total_decisions = BTreeMap::<&str, u64>::new();
    let mut total_wall = BTreeMap::<&str, u128>::new();
    let mut initial_timing = BTreeMap::<&str, Vec<f64>>::new();
    let mut final_timing = BTreeMap::<&str, Vec<f64>>::new();
    for arm in ARMS {
        latency.insert(arm, Vec::new());
        mean_decision.insert(arm, Vec::new());
        batch_throughput.insert(arm, Vec::new());
        total_decisions.insert(arm, 0);
        total_wall.insert(arm, 0);
        initial_timing.insert(arm, Vec::new());
        final_timing.insert(arm, Vec::new());
    }
    let mut production_hits = 0u64;
    let mut production_reads = 0u64;
    let mut paired_time = Vec::new();
    let mut paired_throughput = Vec::new();
    for sample in samples {
        let measurements = sample["measurements"]
            .as_object()
            .ok_or("sample measurements missing")?;
        for arm in ARMS {
            let measurement = &measurements[arm];
            let latencies = measurement["latencyNs"]
                .as_array()
                .ok_or("latency list missing")?
                .iter()
                .map(|value| value.as_u64().ok_or("latency must be integer"))
                .collect::<Result<Vec<_>, _>>()?;
            latency.get_mut(arm).unwrap().extend_from_slice(&latencies);
            let mean_latency = mean(
                &latencies
                    .iter()
                    .map(|value| *value as f64)
                    .collect::<Vec<_>>(),
            )?;
            mean_decision.get_mut(arm).unwrap().push(mean_latency);
            let wall = uint(&measurement["wallNs"], "wallNs", Some(1))?;
            let batch_rate = decisions as f64 * 1_000_000_000.0 / wall as f64;
            if !batch_rate.is_finite() {
                return Err("non-finite throughput statistic".into());
            }
            batch_throughput.get_mut(arm).unwrap().push(batch_rate);
            *total_decisions.get_mut(arm).unwrap() +=
                uint(&measurement["decisions"], "decisions", Some(0))?;
            *total_wall.get_mut(arm).unwrap() += u128::from(wall);
            initial_timing.get_mut(arm).unwrap().push(uint(
                &measurement["initialEvidenceNs"],
                "initialEvidenceNs",
                Some(0),
            )? as f64);
            final_timing.get_mut(arm).unwrap().push(uint(
                &measurement["finalEvidenceNs"],
                "finalEvidenceNs",
                Some(0),
            )? as f64);
        }
        let production = &measurements["production-clock"];
        production_hits += uint(&production["cacheHits"], "cacheHits", Some(0))?;
        production_reads += uint(&production["evidenceReads"], "evidenceReads", Some(0))?;
        let cached_mean = *mean_decision["cached-fixed-second"].last().unwrap();
        let forced_mean = *mean_decision["forced-assembly"].last().unwrap();
        let time_ratio = forced_mean / cached_mean;
        let rate_cached = *batch_throughput["cached-fixed-second"].last().unwrap();
        let rate_forced = *batch_throughput["forced-assembly"].last().unwrap();
        let throughput_ratio = rate_cached / rate_forced;
        if [time_ratio, throughput_ratio]
            .iter()
            .any(|value| !value.is_finite() || *value <= 0.0)
        {
            return Err("invalid paired benchmark ratio".into());
        }
        paired_time.push(time_ratio);
        paired_throughput.push(throughput_ratio);
    }
    let latency_output = ARMS.iter().map(|arm| {
        let values = &latency[arm]; (arm.to_string(), json!({"count":values.len(),"p50_ns":nearest_rank(values,0.50),"p99_ns":nearest_rank(values,0.99)}))
    }).collect::<Map<_,_>>();
    let median_mean = ARMS
        .iter()
        .map(|arm| (arm.to_string(), json!(median(&mean_decision[arm]))))
        .collect::<Map<_, _>>();
    let mut throughput_output = Map::new();
    for arm in ARMS {
        let total = total_decisions[arm] as f64 * 1_000_000_000.0 / total_wall[arm] as f64;
        let batch = &batch_throughput[arm];
        let values = [total, mean(batch)?, median(batch)];
        if values
            .iter()
            .any(|value| !value.is_finite() || *value <= 0.0)
        {
            return Err("non-finite pooled throughput".into());
        }
        throughput_output.insert(arm.to_owned(), json!({"pooled_decisions_per_second":values[0],"mean_batch_decisions_per_second":values[1],"median_batch_decisions_per_second":values[2]}));
    }
    let mut phase_timing = Map::new();
    for arm in ARMS {
        phase_timing.insert(
            arm.to_owned(),
            json!({
                "initial_mean_per_batch": mean(&initial_timing[arm])?,
                "final_mean_per_batch": mean(&final_timing[arm])?
            }),
        );
    }
    let mut phase_decomposition = Map::new();
    for arm in ARMS {
        let mut initial = Vec::new();
        let mut final_values = Vec::new();
        let mut residual = Vec::new();
        for sample in samples {
            let measurement = &sample["measurements"][arm];
            let count = uint(&measurement["decisions"], "decisions", Some(1))? as f64;
            let latencies = measurement["latencyNs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_u64().unwrap() as f64)
                .collect::<Vec<_>>();
            let mean_eval = mean(&latencies)?;
            let initial_ns = uint(
                &measurement["initialEvidenceNs"],
                "initialEvidenceNs",
                Some(0),
            )? as f64
                / count;
            let final_ns =
                uint(&measurement["finalEvidenceNs"], "finalEvidenceNs", Some(0))? as f64 / count;
            initial.push(initial_ns);
            final_values.push(final_ns);
            residual.push(mean_eval - initial_ns - final_ns);
        }
        phase_decomposition.insert(arm.to_owned(), json!({"initial_port_mean_ns_per_decision":mean(&initial)?,"final_port_mean_ns_per_decision":mean(&final_values)?,"residual_mean_ns_per_decision":mean(&residual)?}));
    }
    let geometric = mean(
        &paired_time
            .iter()
            .map(|value| value.ln())
            .collect::<Vec<_>>(),
    )?
    .exp();
    let label = if (geometric - 1.0).abs() <= 1e-12 {
        "no observed paired decision-time difference"
    } else if geometric < 1.0 {
        "cached arm slower than forced arm in paired measurements"
    } else {
        "cached arm faster than forced arm in paired measurements"
    };
    let bootstrap = bootstrap_interval(&paired_time, seed)?;
    let paired_time_mean = mean(&paired_time)?;
    let paired_throughput_mean = mean(&paired_throughput)?;
    let paired_throughput_geomean = mean(
        &paired_throughput
            .iter()
            .map(|value| value.ln())
            .collect::<Vec<_>>(),
    )?
    .exp();
    let cache_fraction = production_hits as f64 / production_reads as f64;
    if !cache_fraction.is_finite() {
        return Err("invalid production cache hit fraction".into());
    }
    Ok(json!({
        "case":row["case"],"grants":row["grants"],"threads":row["threads"],"outcome":outcome,
        "decisionsPerThread":row["decisionsPerThread"],"decisionsPerBatch":decisions,
        "latency_ns":latency_output,"median_per_batch_mean_decision_ns":median_mean,
        "throughput_decisions_per_second":throughput_output,"production_clock_cache_hit_fraction":cache_fraction,
        "production_repository_timing_ns":{"initial_mean_per_batch":mean(&initial_timing["production-clock"])?,"final_mean_per_batch":mean(&final_timing["production-clock"])?,"initial_median_per_batch":median(&initial_timing["production-clock"]),"final_median_per_batch":median(&final_timing["production-clock"])},
        "repository_phase_timing_ns_by_arm":phase_timing,"phase_decomposition_mean_ns_per_decision_by_arm":phase_decomposition,
        "paired":{"mean_forced_over_cached_decision_time_ratio":paired_time_mean,"geometric_mean_forced_over_cached_decision_time_ratio":geometric,"comparison_label":label,"mean_cached_over_forced_throughput_ratio":paired_throughput_mean,"geometric_mean_cached_over_forced_throughput_ratio":paired_throughput_geomean,"bootstrap_geometric_mean_time_ratio_forced_over_cached_ci95":[bootstrap.0,bootstrap.1],"bootstrap_resamples":BOOTSTRAP_RESAMPLES,"bootstrap_seed":seed,"paired_batches":paired_time.len(),"interpretation":"forced/cached decision-time ratio; values below 1 indicate cached was slower","interval_scope":"unadjusted exploratory interval; no multiplicity correction across 45 cases"}
    }))
}

fn median(values: &[f64]) -> f64 {
    let mut values = values.to_vec();
    values.sort_by(f64::total_cmp);
    if values.len() % 2 == 1 {
        values[values.len() / 2]
    } else {
        (values[values.len() / 2 - 1] + values[values.len() / 2]) / 2.0
    }
}

pub fn check_evaluate_performance(stdout: &str) -> Value {
    check_evaluate_performance_value(&Value::String(stdout.to_owned()))
}

pub fn check_evaluate_performance_value(stdout: &Value) -> Value {
    let Some(stdout) = stdout.as_str() else {
        return fail("stdout must be a string");
    };
    match check_evaluate_performance_inner(stdout) {
        Ok(value) => value,
        Err(reason) => fail(reason),
    }
}

fn check_evaluate_performance_inner(stdout: &str) -> Result<Value, String> {
    let prefixes = [
        "EVALUATE_PERF_META",
        "EVALUATE_PERF_CASE",
        "EVALUATE_PERF_END",
    ];
    let mut records: BTreeMap<&str, Vec<Value>> = prefixes
        .iter()
        .map(|prefix| (*prefix, Vec::new()))
        .collect();
    let mut sequence = Vec::new();
    let mut footer_seen = false;
    let footer_re = regex::Regex::new(r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in \d+(?:\.\d+)?s$").unwrap();
    for line in stdout.lines() {
        if line.to_ascii_lowercase().contains("filtered out") {
            if !footer_seen
                && footer_re.is_match(line)
                && sequence.last().copied() == Some("EVALUATE_PERF_END")
            {
                footer_seen = true;
                continue;
            }
            return Err("filtered benchmark output is not accepted".into());
        }
        let matching = prefixes
            .iter()
            .copied()
            .find(|prefix| line.starts_with(prefix));
        let Some(prefix) = matching else {
            if line.contains("EVALUATE_PERF_") {
                return Err("protocol marker is not at the start of its line".into());
            }
            continue;
        };
        if !line.starts_with(&format!("{prefix} ")) {
            return Err("malformed benchmark protocol line prefix".into());
        }
        if footer_seen {
            return Err("benchmark protocol record follows the terminal Rust result".into());
        }
        let payload = line[prefix.len() + 1..].trim();
        if payload.is_empty() {
            return Err("empty benchmark protocol record".into());
        }
        let value = decode_json(payload)?;
        records.get_mut(prefix).unwrap().push(value);
        sequence.push(prefix);
    }
    let mut expected_sequence = vec!["EVALUATE_PERF_META"];
    expected_sequence.extend(std::iter::repeat_n("EVALUATE_PERF_CASE", 45));
    expected_sequence.push("EVALUATE_PERF_END");
    if sequence != expected_sequence {
        return Err("benchmark records are incomplete or outside meta/cases/end order".into());
    }
    if records["EVALUATE_PERF_META"].len() != 1
        || records["EVALUATE_PERF_END"].len() != 1
        || records["EVALUATE_PERF_CASE"].len() != 45
    {
        return Err("benchmark meta/end or case records are incomplete".into());
    }
    let meta = &records["EVALUATE_PERF_META"][0];
    let end = &records["EVALUATE_PERF_END"][0];
    validate_meta(meta)?;
    let rows = &records["EVALUATE_PERF_CASE"];
    let expected = expected_cases();
    let expected_set = expected
        .iter()
        .map(|(name, _, _, _)| name.as_str())
        .collect::<BTreeSet<_>>();
    let mut cases = BTreeMap::<String, Value>::new();
    for row in rows {
        validate_case(row)?;
        let name = row["case"]
            .as_str()
            .ok_or("benchmark case name missing")?
            .to_owned();
        if cases.insert(name, row.clone()).is_some() {
            return Err("duplicate benchmark case".into());
        }
    }
    if cases.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_set {
        return Err("benchmark case set differs from the exact Cartesian product".into());
    }
    validate_end(end)?;
    let mut ordered_rows = Vec::with_capacity(45);
    let mut summaries = Vec::with_capacity(45);
    for (index, (name, _, _, _)) in expected.iter().enumerate() {
        let row = cases.get(name).unwrap();
        ordered_rows.push(row.clone());
        summaries.push(summarize_case(row, BOOTSTRAP_SEED + index as u32)?);
    }
    let performance = json!({
        "scope":SCOPE,"scope_boundaries":SCOPE_BOUNDARIES,"producer_premises":meta.get("premises").cloned().unwrap_or_else(||{let mut values=Map::new();for name in PREMISE_NAMES{values.insert(name.to_owned(),meta[name].clone());}Value::Object(values)}),
        "cases":45,"samples_per_case":SAMPLES_PER_CASE,"measurements":2430,"summary":summaries,"raw":{"meta":meta,"cases":ordered_rows,"end":end},
        "interpretation":"protocol acceptance only; no minimum speedup or no-regression threshold is applied",
        "bootstrap":{"resamples_per_case":BOOTSTRAP_RESAMPLES,"seed_base":BOOTSTRAP_SEED,"interval":"paired percentile 95% interval for geometric mean forced/cached decision-time ratio, resampling 18 per-case batch log-ratios","multiplicity":"unadjusted and exploratory across the 45 cases; not deployment inference"}
    });
    Ok(
        json!({"status":"PASS","reason":"complete strict CPU PolicyEngine.evaluate protocol; estimates are reported without a benefit threshold","performance":performance,"verified_postcondition":{"complete":true,"schema":SCHEMA,"cases":45,"samples":810,"measurements":2430,"workersJoined":true,"allDecisionsChecked":true,"allReadCountsChecked":true}}),
    )
}

#[cfg(test)]
pub(crate) fn valid_output_fixture() -> String {
    tests::valid_stdout()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> Value {
        let mut controls = Map::new();
        for name in CONTROL_NAMES {
            controls.insert(name.to_owned(), json!(true));
        }
        let mut premises = Map::new();
        for name in PREMISE_NAMES {
            premises.insert(
                name.to_owned(),
                json!(format!("fixture premise for {name}")),
            );
        }
        json!({"schema":SCHEMA,"scope":SCOPE,"samplesPerCase":18,"grantSizes":GRANT_SIZES,"threads":THREAD_COUNTS,"outcomes":OUTCOMES,"arms":ARMS,"timing":"evaluate-call-return","debugAssertions":false,"controls":controls,"premises":premises})
    }
    fn measurement(arm: &str, grants: u64, threads: u64, outcome: &str) -> Value {
        let decisions = threads * decisions_per_thread(grants).unwrap();
        let allow = outcome != "deny";
        let reads = decisions * if allow { 2 } else { 1 };
        json!({"decisions":decisions,"wallNs":decisions*200,"latencyNs":vec![200;decisions as usize],"cardChecks":decisions,"orgReads":decisions,"evidenceReads":reads,"scopedReads":reads,"evidenceGrants":reads*grants,"cacheHits":if arm=="cached-fixed-second"{reads}else{0},"initialEvidenceNs":10,"finalEvidenceNs":if allow{10}else{0},"allowed":if allow{decisions}else{0},"denied":if allow{0}else{decisions},"pending":0,"mismatches":0,"legacyReads":0})
    }
    fn row(grants: u64, threads: u64, outcome: &str) -> Value {
        let samples=(0..SAMPLES_PER_CASE).map(|index|json!({"index":index,"order":ORDERS[index%ORDERS.len()].iter().map(|arm|ARMS[*arm]).collect::<Vec<_>>(),"measurements":ARMS.iter().map(|arm|((*arm).to_owned(),measurement(arm,grants,threads,outcome))).collect::<Map<_,_>>() })).collect::<Vec<_>>();
        json!({"case":format!("evaluate/{grants}/threads-{threads}/{outcome}"),"grants":grants,"threads":threads,"outcome":outcome,"decisionsPerThread":decisions_per_thread(grants).unwrap(),"samples":samples})
    }
    fn end() -> Value {
        json!({"schema":SCHEMA,"status":"PASS","cases":45,"samples":810,"measurements":2430,"postconditions":{"workersJoined":true,"allDecisionsChecked":true,"allReadCountsChecked":true}})
    }
    fn mutate_record(output: &str, prefix: &str, mutate: impl FnOnce(&mut Value)) -> String {
        let mut mutate = Some(mutate);
        let mut changed = false;
        let mut lines = Vec::new();
        for line in output.lines() {
            let Some(payload) = line.strip_prefix(&format!("{prefix} ")) else {
                lines.push(line.to_owned());
                continue;
            };
            if changed {
                lines.push(line.to_owned());
                continue;
            }
            changed = true;
            let mut value: Value = serde_json::from_str(payload).unwrap();
            mutate.take().unwrap()(&mut value);
            lines.push(format!(
                "{prefix} {}",
                serde_json::to_string(&value).unwrap()
            ));
        }
        assert!(changed, "fixture contains {prefix}");
        lines.join("\n") + "\n"
    }

    pub(super) fn valid_stdout() -> String {
        let mut lines = vec![format!("EVALUATE_PERF_META {}", meta())];
        for (_name, grants, threads, outcome) in expected_cases() {
            lines.push(format!(
                "EVALUATE_PERF_CASE {}",
                row(grants, threads, outcome)
            ));
        }
        lines.push(format!("EVALUATE_PERF_END {}", end()));
        lines.push("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 864 filtered out; finished in 12.34s".to_owned());
        lines.join("\n") + "\n"
    }
    #[test]
    fn public_acceptance_rejects_non_string_stdout_without_panicking() {
        let result = check_evaluate_performance_value(&Value::Null);
        assert_eq!(result["status"], "FAIL");
        assert_eq!(result["performance"], Value::Null);
        assert_eq!(result["verified_postcondition"]["complete"], false);
    }

    #[test]
    fn complete_policy_evaluate_protocol_is_accepted_without_speed_threshold() {
        let output = valid_stdout();
        let accepted = check_evaluate_performance(&output);
        assert_eq!(accepted["status"], "PASS", "{}", accepted["reason"]);
        assert_eq!(accepted["verified_postcondition"]["measurements"], 2430);
        assert_eq!(
            accepted["performance"]["summary"].as_array().unwrap().len(),
            45
        );
        assert_eq!(
            accepted["performance"]["summary"][0]["latency_ns"]["cached-fixed-second"]["p50_ns"],
            200
        );
        assert_eq!(
            accepted["performance"]["summary"][0]["paired"]
                ["geometric_mean_forced_over_cached_decision_time_ratio"],
            1.0
        );
        assert!(accepted["performance"]["scope_boundaries"][7]
            .as_str()
            .unwrap()
            .contains("Not a signed HTTP"));
    }
    #[test]
    fn paired_statistics_match_python_seeded_reference_and_report_regressions() {
        let output = valid_stdout();
        let row = row(1, 1, "allow-first");
        let mut regressed = row.clone();
        for sample in regressed["samples"].as_array_mut().unwrap() {
            sample["measurements"]["cached-fixed-second"] =
                measurement("cached-fixed-second", 1, 1, "allow-first");
            sample["measurements"]["cached-fixed-second"]["latencyNs"] = json!(vec![300; 256]);
            sample["measurements"]["cached-fixed-second"]["wallNs"] = json!(256 * 300);
            sample["measurements"]["forced-assembly"]["latencyNs"] = json!(vec![200; 256]);
            sample["measurements"]["forced-assembly"]["wallNs"] = json!(256 * 200);
        }
        let summary = summarize_case(&regressed, 12345).unwrap();
        let paired = &summary["paired"];
        assert!(
            (paired["geometric_mean_forced_over_cached_decision_time_ratio"]
                .as_f64()
                .unwrap()
                - 2.0 / 3.0)
                .abs()
                < 1e-12
        );
        assert_eq!(
            paired["comparison_label"],
            "cached arm slower than forced arm in paired measurements"
        );
        let expected_ci = [0.8709967875166152, 1.2294281908073685];
        let actual_ci = bootstrap_interval(
            &[
                0.5, 0.8, 1.2, 2.0, 1.5, 0.7, 1.1, 0.9, 1.4, 0.6, 1.7, 0.8, 1.3, 1.0, 0.7, 1.2,
                0.9, 1.6,
            ],
            12345,
        )
        .unwrap();
        assert!((actual_ci.0 - expected_ci[0]).abs() < 1e-12);
        assert!((actual_ci.1 - expected_ci[1]).abs() < 1e-12);
        assert!(check_evaluate_performance(&output)["status"] == "PASS");
    }

    #[test]
    fn incomplete_duplicate_reordered_and_ambiguous_json_records_fail() {
        let good = valid_stdout();
        let case_line = good
            .lines()
            .find(|line| line.starts_with("EVALUATE_PERF_CASE "))
            .unwrap();
        let duplicate = good.replacen(
            "EVALUATE_PERF_END ",
            &format!("{case_line}\nEVALUATE_PERF_END "),
            1,
        );
        assert_eq!(
            check_evaluate_performance(&good.replace(case_line, ""))["status"],
            "FAIL"
        );
        assert_eq!(check_evaluate_performance(&duplicate)["status"], "FAIL");
        assert_eq!(
            check_evaluate_performance("EVALUATE_PERF_META {\"schema\":\"x\",\"schema\":\"y\"}\n")
                ["status"],
            "FAIL"
        );
        let mut reordered = good.lines().map(str::to_owned).collect::<Vec<_>>();
        reordered.swap(0, 1);
        assert_eq!(
            check_evaluate_performance(&reordered.join("\n"))["status"],
            "FAIL"
        );
    }
    #[test]
    fn measurement_and_end_postconditions_cannot_be_relaxed() {
        let mut invalid = row(1, 1, "allow-first");
        invalid["samples"][0]["measurements"]["cached-fixed-second"]["cacheHits"] = json!(0);
        assert!(validate_case(&invalid).is_err());
        let mut footer = end();
        footer["postconditions"]["workersJoined"] = json!(false);
        assert!(validate_end(&footer).is_err());
    }
    #[test]
    fn python_seeded_bootstrap_is_reproducible() {
        let values = vec![0.5; 18];
        assert_eq!(
            bootstrap_interval(&values, BOOTSTRAP_SEED).unwrap(),
            (0.5, 0.5)
        );
        let ratios = [
            0.5, 0.8, 1.2, 2.0, 1.5, 0.7, 1.1, 0.9, 1.4, 0.6, 1.7, 0.8, 1.3, 1.0, 0.7, 1.2, 0.9,
            1.6,
        ];
        let first = bootstrap_interval(&ratios, 12345).unwrap();
        let second = bootstrap_interval(&ratios, 12345).unwrap();
        assert_eq!(first, second);
        assert!((first.0 - 0.8709967875166152).abs() < 1e-12);
        assert!((first.1 - 1.2294281908073685).abs() < 1e-12);
    }

    #[test]
    fn python_test_rejects_footer_placement_and_count_mutations() {
        let good = valid_stdout();
        let footer = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 864 filtered out; finished in 12.34s\n";
        let protocol = good
            .lines()
            .filter(|line| !line.starts_with("test result: "))
            .collect::<Vec<_>>()
            .join("\n");
        let with_test_name = format!(
            "running 1 test\n{protocol}\ntest policy_evaluate_complete_benefit_matrix ... ok\n{footer}"
        );
        let accepted = check_evaluate_performance(&with_test_name);
        assert_eq!(accepted["status"], "PASS", "{}", accepted["reason"]);
        for malformed in [
            format!("{footer}{good}"),
            format!("{good}{footer}{footer}"),
            good.replace("1 passed", "0 passed"),
            good.replace("0 ignored", "1 ignored"),
        ] {
            assert_eq!(check_evaluate_performance(&malformed)["status"], "FAIL");
        }
    }

    #[test]
    fn python_test_rejects_malformed_json_meta_topology_and_debug_markers() {
        for input in [
            "EVALUATE_PERF_META {\"schema\":NaN}\n",
            "EVALUATE_PERF_META {\"schema\":\"one\",\"schema\":\"two\"}\n",
            "EVALUATE_PERF_META {\"schema\":\"unterminated}\n",
        ] {
            assert_eq!(check_evaluate_performance(input)["status"], "FAIL");
        }
        let good = valid_stdout();
        let invalid_meta = [
            mutate_record(&good, "EVALUATE_PERF_META", |meta| {
                meta["samplesPerCase"] = json!(true)
            }),
            mutate_record(&good, "EVALUATE_PERF_META", |meta| {
                meta["grantSizes"][0] = json!(true)
            }),
            mutate_record(&good, "EVALUATE_PERF_META", |meta| {
                meta["threads"] = json!([1, 4, 7])
            }),
            mutate_record(&good, "EVALUATE_PERF_META", |meta| {
                meta["controls"]
                    .as_object_mut()
                    .unwrap()
                    .remove("crossSecondExpiry");
            }),
            mutate_record(&good, "EVALUATE_PERF_META", |meta| {
                meta["premises"]
                    .as_object_mut()
                    .unwrap()
                    .remove("scopeExclusions");
            }),
            mutate_record(&good, "EVALUATE_PERF_META", |meta| {
                meta["controls"]["denyOneRead"] = json!(1)
            }),
            mutate_record(&good, "EVALUATE_PERF_META", |meta| {
                meta["debugAssertions"] = json!(true)
            }),
            mutate_record(&good, "EVALUATE_PERF_META", |meta| {
                meta["buildProfile"] = json!("debug")
            }),
        ];
        for input in invalid_meta {
            assert_eq!(check_evaluate_performance(&input)["status"], "FAIL");
        }
    }

    #[test]
    fn python_test_rejects_case_topology_boolean_and_order_mutations() {
        let good = valid_stdout();
        let invalid_cases = [
            mutate_record(&good, "EVALUATE_PERF_CASE", |row| {
                row["decisionsPerThread"] = json!(255)
            }),
            mutate_record(&good, "EVALUATE_PERF_CASE", |row| {
                row["grants"] = json!(true)
            }),
            mutate_record(&good, "EVALUATE_PERF_CASE", |row| {
                row["threads"] = json!(true)
            }),
            mutate_record(&good, "EVALUATE_PERF_CASE", |row| {
                row["samples"][0]["order"] =
                    json!(["production-clock", "forced-assembly", "cached-fixed-second"])
            }),
            mutate_record(&good, "EVALUATE_PERF_CASE", |row| {
                row["samples"].as_array_mut().unwrap().pop();
            }),
        ];
        for input in invalid_cases {
            assert_eq!(check_evaluate_performance(&input)["status"], "FAIL");
        }
    }

    #[test]
    fn python_test_rejects_measurement_count_cache_and_timing_mutations() {
        let good = valid_stdout();
        let mutations = [
            ("allowed", 0, "cached-fixed-second"),
            ("denied", 1, "production-clock"),
            ("pending", 1, "forced-assembly"),
            ("mismatches", 1, "production-clock"),
            ("legacyReads", 1, "cached-fixed-second"),
            ("cardChecks", 0, "forced-assembly"),
            ("orgReads", 0, "forced-assembly"),
            ("evidenceReads", 1, "production-clock"),
            ("scopedReads", 1, "production-clock"),
            ("evidenceGrants", 1, "production-clock"),
            ("cacheHits", 0, "cached-fixed-second"),
            ("cacheHits", 1, "forced-assembly"),
            ("wallNs", 1, "production-clock"),
            ("wallNs", 200, "production-clock"),
            ("initialEvidenceNs", 0, "production-clock"),
            ("finalEvidenceNs", 0, "cached-fixed-second"),
        ];
        for (field, value, arm) in mutations {
            let input = mutate_record(&good, "EVALUATE_PERF_CASE", |row| {
                row["samples"][0]["measurements"][arm][field] = json!(value)
            });
            assert_eq!(
                check_evaluate_performance(&input)["status"],
                "FAIL",
                "{field}/{arm}"
            );
        }
        let bool_latency = mutate_record(&good, "EVALUATE_PERF_CASE", |row| {
            row["samples"][0]["measurements"]["cached-fixed-second"]["latencyNs"][0] = json!(true);
        });
        let zero_latency = mutate_record(&good, "EVALUATE_PERF_CASE", |row| {
            row["samples"][0]["measurements"]["cached-fixed-second"]["latencyNs"][0] = json!(0);
        });
        let bool_cache_hits = mutate_record(&good, "EVALUATE_PERF_CASE", |row| {
            row["samples"][0]["measurements"]["cached-fixed-second"]["cacheHits"] = json!(true);
        });
        for input in [bool_latency, zero_latency, bool_cache_hits] {
            assert_eq!(check_evaluate_performance(&input)["status"], "FAIL");
        }
        let short_latency = mutate_record(&good, "EVALUATE_PERF_CASE", |row| {
            row["samples"][0]["measurements"]["cached-fixed-second"]["latencyNs"]
                .as_array_mut()
                .unwrap()
                .pop();
        });
        assert_eq!(check_evaluate_performance(&short_latency)["status"], "FAIL");
    }

    #[test]
    fn python_test_deny_footer_and_wrong_input_preserve_fail_closed_results() {
        let good = valid_stdout();
        let deny = mutate_record(&good, "EVALUATE_PERF_CASE", |row| {
            row["outcome"] = json!("deny");
            let grants = row["grants"].as_u64().unwrap();
            let threads = row["threads"].as_u64().unwrap();
            for arm in ARMS {
                row["samples"][0]["measurements"][arm] = measurement(arm, grants, threads, "deny");
            }
        });
        assert_eq!(check_evaluate_performance(&deny)["status"], "FAIL");
        let mut invalid_end = end();
        invalid_end["cases"] = json!(44);
        assert!(validate_end(&invalid_end).is_err());
        invalid_end = end();
        invalid_end["samples"] = json!(809);
        assert!(validate_end(&invalid_end).is_err());
        invalid_end = end();
        invalid_end["measurements"] = json!(2429);
        assert!(validate_end(&invalid_end).is_err());
        invalid_end = end();
        invalid_end["postconditions"]["workersJoined"] = json!(false);
        assert!(validate_end(&invalid_end).is_err());
        invalid_end = end();
        invalid_end["postconditions"]["extra"] = json!(true);
        assert!(validate_end(&invalid_end).is_err());
        invalid_end = end();
        invalid_end["measurements"] = json!(true);
        assert!(validate_end(&invalid_end).is_err());
        assert_eq!(check_evaluate_performance("")["status"], "FAIL");
    }
}
