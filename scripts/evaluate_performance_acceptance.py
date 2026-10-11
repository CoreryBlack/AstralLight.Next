"""Strict acceptance for whole-PolicyEngine.evaluate CPU measurements.

A PASS means the complete benchmark protocol and its producer-asserted checks
were present. It does not establish a performance benefit or service capacity.
"""
from __future__ import annotations

import json
import math
import random
import re
import statistics

SCHEMA = "policy-evaluate-benefit-v1"
SCOPE = "policy-engine-evaluate-cpu"
SAMPLES_PER_CASE = 18
GRANT_SIZES = (1, 8, 128, 512, 2048)
THREAD_COUNTS = (1, 4, 8)
OUTCOMES = ("allow-first", "allow-last", "deny")
ARMS = ("cached-fixed-second", "forced-assembly", "production-clock")
ORDERS = (
    ("cached-fixed-second", "forced-assembly", "production-clock"),
    ("forced-assembly", "production-clock", "cached-fixed-second"),
    ("production-clock", "cached-fixed-second", "forced-assembly"),
    ("cached-fixed-second", "production-clock", "forced-assembly"),
    ("production-clock", "forced-assembly", "cached-fixed-second"),
    ("forced-assembly", "cached-fixed-second", "production-clock"),
)
DECISIONS_PER_THREAD = {1: 256, 8: 256, 128: 96, 512: 32, 2048: 16}
CONTROL_NAMES = (
    "ownedEvidenceParity",
    "decisionParity",
    "allowTwoReads",
    "denyOneRead",
    "pendingOneRead",
    "crossSecondExpiry",
    "finalRevokeRefusal",
    "noLegacyReads",
)
PREMISE_NAMES = (
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
)
PREFIXES = ("EVALUATE_PERF_META", "EVALUATE_PERF_CASE", "EVALUATE_PERF_END")
RUST_SUCCESS_FOOTER = re.compile(
    r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; "
    r"\d+ filtered out; finished in \d+(?:\.\d+)?s"
)
BOOTSTRAP_RESAMPLES = 2000
BOOTSTRAP_SEED = 20261010

MEASUREMENT_FIELDS = {
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
}

# These boundaries are part of the archived result, not inferences from speed.
SCOPE_BOUNDARIES = (
    "CPU-only whole PolicyEngine.evaluate call benchmark; owned evidence is still cloned.",
    "All arms use the same engine and fixture map data; independent cache stores prevent cross-arm contamination.",
    "Synthetic perpetual grants/card state and ORG checks are supplied by fixture ports, not production persistence.",
    "Fixture identity assertions cover PLATFORM_USER, identity_card 18/card 17/user 42/tenant 7/domain 11, and TenantScoped authoritative target 7/11.",
    "Per-decision latency covers the complete evaluate call through awaited return.",
    "Wall throughput includes barrier wake, in-loop result verification/storage/destruction, and worker joins; it excludes runtime/thread construction and cache prewarm.",
    "Forced assembly uses a unique synthetic second per read and no production hook; phase timers are fixture read-port totals, not engine ArcSwap statistics.",
    "Not a signed HTTP, database, session, SDK, business-admission, allocation, or deployment-capacity benchmark.",
)


class _DuplicateJsonKey(ValueError):
    pass


def _object_without_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value):
    raise ValueError(f"non-finite JSON number: {value}")


def _decode_json(payload):
    return json.loads(
        payload,
        object_pairs_hook=_object_without_duplicate_keys,
        parse_constant=_reject_json_constant,
    )


def _failure(reason):
    return {
        "status": "FAIL",
        "reason": reason,
        "performance": None,
        "verified_postcondition": {"complete": False},
    }


def _is_int(value):
    return type(value) is int


def _expect_int(value, name, minimum=None):
    if not _is_int(value) or (minimum is not None and value < minimum):
        raise ValueError(f"invalid integer field: {name}")


def _expected_cases():
    for grants in GRANT_SIZES:
        for threads in THREAD_COUNTS:
            for outcome in OUTCOMES:
                yield f"evaluate/{grants}/threads-{threads}/{outcome}", grants, threads, outcome


def _validate_meta(meta):
    if not isinstance(meta, dict):
        raise ValueError("benchmark meta must be a JSON object")
    required = {
        "schema": SCHEMA,
        "scope": SCOPE,
        "samplesPerCase": SAMPLES_PER_CASE,
        "grantSizes": list(GRANT_SIZES),
        "threads": list(THREAD_COUNTS),
        "outcomes": list(OUTCOMES),
        "arms": list(ARMS),
        "timing": "evaluate-call-return",
        "debugAssertions": False,
    }
    for key, value in required.items():
        actual = meta.get(key)
        if key in {"samplesPerCase"}:
            matches = _is_int(actual) and actual == value
        elif key in {"grantSizes", "threads"}:
            matches = isinstance(actual, list) and len(actual) == len(value) and all(
                _is_int(item) and item == expected for item, expected in zip(actual, value)
            )
        else:
            matches = actual is value if key == "debugAssertions" else actual == value
        if not matches:
            raise ValueError("benchmark meta differs from the exact protocol or topology")
    controls = meta.get("controls")
    if not set(required).issubset(meta) or not isinstance(controls, dict) or set(controls) != set(CONTROL_NAMES) or any(
        controls[name] is not True for name in CONTROL_NAMES
    ):
        raise ValueError("benchmark controls are missing or not all asserted true")
    premise_values = meta.get("premises")
    if isinstance(premise_values, dict):
        if not PREMISE_NAMES or not set(PREMISE_NAMES).issubset(premise_values):
            raise ValueError("benchmark explanatory premises are incomplete")
        if any(not isinstance(value, str) or not value.strip() for value in premise_values.values()):
            raise ValueError("premise fields must be nonempty text")
    elif not set(PREMISE_NAMES).issubset(meta):
        raise ValueError("benchmark explanatory premises are incomplete")
    for name, value in meta.items():
        if name in required or name == "controls":
            continue
        if name == "premises" and isinstance(value, dict):
            continue
        key = name.lower()
        if "debug" in key or key in {"profile", "buildprofile", "buildmode", "mode"}:
            text = value.lower() if isinstance(value, str) else ""
            profile_key = key in {"profile", "buildprofile", "buildmode", "mode"}
            if value is True or (profile_key and "debug" in text) or text in {"debug build", "debug profile"}:
                raise ValueError("debug-build benchmark output is not accepted")
        if not isinstance(value, str) or not value.strip():
            raise ValueError("additional benchmark meta fields must be nonempty text")


def _validate_measurement(measurement, *, arm, grants, threads, outcome, decisions):
    if not isinstance(measurement, dict) or set(measurement) != MEASUREMENT_FIELDS:
        raise ValueError("measurement fields differ from the exact protocol")
    for name in MEASUREMENT_FIELDS - {"latencyNs"}:
        _expect_int(measurement[name], name, 0)
    if measurement["decisions"] != decisions:
        raise ValueError("measurement decision count differs from the workload")
    if measurement["wallNs"] < 1:
        raise ValueError("measurement wall time must be positive")
    latencies = measurement["latencyNs"]
    if not isinstance(latencies, list) or len(latencies) != decisions:
        raise ValueError("measurement must contain one latency per decision")
    if any(not _is_int(value) or value <= 0 for value in latencies):
        raise ValueError("latencies must be positive integers")
    if measurement["wallNs"] < max(latencies):
        raise ValueError("wall time is shorter than an individual evaluate call")
    if sum(latencies) > threads * measurement["wallNs"]:
        raise ValueError("total evaluate time exceeds the concurrent worker wall-time budget")

    allow = outcome in ("allow-first", "allow-last")
    evidence_reads = decisions * (2 if allow else 1)
    expected_counts = {
        "cardChecks": decisions,
        "orgReads": decisions,
        "evidenceReads": evidence_reads,
        "scopedReads": evidence_reads,
        "evidenceGrants": evidence_reads * grants,
        "allowed": decisions if allow else 0,
        "denied": 0 if allow else decisions,
        "pending": 0,
        "mismatches": 0,
        "legacyReads": 0,
    }
    if any(measurement[name] != count for name, count in expected_counts.items()):
        raise ValueError("measurement decision or repository-read counters violate the contract")
    if not 0 <= measurement["cacheHits"] <= evidence_reads:
        raise ValueError("cache hit count is outside the evidence-read count")
    if arm == "cached-fixed-second" and measurement["cacheHits"] != evidence_reads:
        raise ValueError("fixed-second arm did not demonstrate real cache hits")
    if arm == "forced-assembly" and measurement["cacheHits"] != 0:
        raise ValueError("forced-assembly arm unexpectedly recorded cache hits")
    if measurement["initialEvidenceNs"] <= 0:
        raise ValueError("initial repository evidence timing must be positive")
    expected_final = 1 if allow else 0
    if (measurement["finalEvidenceNs"] > 0) != bool(expected_final):
        raise ValueError("final evidence timing does not match the outcome")
    if measurement["finalEvidenceNs"] < 0:
        raise ValueError("final evidence timing cannot be negative")
    if measurement["initialEvidenceNs"] + measurement["finalEvidenceNs"] > sum(latencies):
        raise ValueError("repository evidence timing exceeds measured evaluate time")


def _validate_case(row):
    if not isinstance(row, dict) or set(row) != {
        "case", "grants", "threads", "outcome", "decisionsPerThread", "samples"
    }:
        raise ValueError("case row fields differ from the exact protocol")
    grants, threads, outcome = row["grants"], row["threads"], row["outcome"]
    _expect_int(grants, "grants", 1)
    _expect_int(threads, "threads", 1)
    if grants not in GRANT_SIZES or threads not in THREAD_COUNTS or outcome not in OUTCOMES:
        raise ValueError("case is outside the exact benchmark topology")
    expected_case = f"evaluate/{grants}/threads-{threads}/{outcome}"
    if row["case"] != expected_case:
        raise ValueError("case string does not encode its exact workload")
    decisions_per_thread = DECISIONS_PER_THREAD[grants]
    if row["decisionsPerThread"] != decisions_per_thread or not _is_int(row["decisionsPerThread"]):
        raise ValueError("decisionsPerThread differs from the registered workload map")
    decisions = threads * decisions_per_thread
    samples = row["samples"]
    if not isinstance(samples, list) or len(samples) != SAMPLES_PER_CASE:
        raise ValueError("case does not contain exactly 18 samples")
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict) or set(sample) != {"index", "order", "measurements"}:
            raise ValueError("sample fields differ from the exact protocol")
        if not _is_int(sample["index"]) or sample["index"] != index:
            raise ValueError("sample indices must be contiguous from 0 through 17")
        if sample["order"] != list(ORDERS[index % len(ORDERS)]):
            raise ValueError("sample arm order differs from the six-step rotation")
        measurements = sample["measurements"]
        if not isinstance(measurements, dict) or set(measurements) != set(ARMS):
            raise ValueError("sample must contain exactly the three benchmark arms")
        for arm in ARMS:
            _validate_measurement(
                measurements[arm], arm=arm, grants=grants, threads=threads,
                outcome=outcome, decisions=decisions,
            )


def _validate_end(end):
    if not isinstance(end, dict) or set(end) != {
        "schema", "status", "cases", "samples", "measurements", "postconditions"
    }:
        raise ValueError("benchmark end record fields differ from the exact protocol")
    if (end["schema"] != SCHEMA or end["status"] != "PASS"
            or end["cases"] != 45 or end["samples"] != 810 or end["measurements"] != 2430
            or any(not _is_int(end[name]) for name in ("cases", "samples", "measurements"))):
        raise ValueError("benchmark end counts or status are incomplete")
    required = {"workersJoined", "allDecisionsChecked", "allReadCountsChecked"}
    if (not isinstance(end["postconditions"], dict)
            or set(end["postconditions"]) != required
            or any(end["postconditions"][name] is not True for name in required)):
        raise ValueError("benchmark worker or per-decision postconditions are not proven")


def _nearest_rank(values, percentile):
    ordered = sorted(values)
    rank = math.ceil(percentile * len(ordered))
    return ordered[max(0, rank - 1)]


def _mean(values):
    value = sum(values) / len(values)
    if not math.isfinite(value):
        raise ValueError("non-finite summary statistic")
    return value


def _quantile(values, probability):
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _bootstrap_log_ratio_interval(ratios, seed):
    logs = [math.log(ratio) for ratio in ratios]
    rng = random.Random(seed)
    estimates = [
        _mean(rng.choices(logs, k=len(logs)))
        for _ in range(BOOTSTRAP_RESAMPLES)
    ]
    lower_log = _quantile(estimates, 0.025)
    upper_log = _quantile(estimates, 0.975)
    interval = (math.exp(lower_log), math.exp(upper_log))
    if any(not math.isfinite(value) or value <= 0 for value in interval):
        raise ValueError("non-finite bootstrap interval")
    return interval


def _summarize_case(row, seed):
    samples = row["samples"]
    outcome = row["outcome"]
    decisions = row["threads"] * row["decisionsPerThread"]
    all_latencies = {arm: [] for arm in ARMS}
    mean_decision_ns = {arm: [] for arm in ARMS}
    batch_throughput = {arm: [] for arm in ARMS}
    total_decisions = {arm: 0 for arm in ARMS}
    total_wall_ns = {arm: 0 for arm in ARMS}
    initial_evidence_ns = []
    final_evidence_ns = []
    production_cache_hits = 0
    production_evidence_reads = 0
    paired_time_ratios = []
    paired_throughput_ratios = []

    for sample in samples:
        by_arm = sample["measurements"]
        for arm in ARMS:
            measurement = by_arm[arm]
            all_latencies[arm].extend(measurement["latencyNs"])
            mean_decision_ns[arm].append(_mean(measurement["latencyNs"]))
            throughput = measurement["decisions"] * 1_000_000_000 / measurement["wallNs"]
            if not math.isfinite(throughput):
                raise ValueError("non-finite throughput statistic")
            batch_throughput[arm].append(throughput)
            total_decisions[arm] += measurement["decisions"]
            total_wall_ns[arm] += measurement["wallNs"]
        production = by_arm["production-clock"]
        production_cache_hits += production["cacheHits"]
        production_evidence_reads += production["evidenceReads"]
        initial_evidence_ns.append(production["initialEvidenceNs"])
        final_evidence_ns.append(production["finalEvidenceNs"])
        cached_mean = mean_decision_ns["cached-fixed-second"][-1]
        forced_mean = mean_decision_ns["forced-assembly"][-1]
        time_ratio = forced_mean / cached_mean
        throughput_ratio = batch_throughput["cached-fixed-second"][-1] / batch_throughput["forced-assembly"][-1]
        if any(not math.isfinite(value) or value <= 0 for value in (time_ratio, throughput_ratio)):
            raise ValueError("invalid paired benchmark ratio")
        paired_time_ratios.append(time_ratio)
        paired_throughput_ratios.append(throughput_ratio)

    latency = {
        arm: {
            "count": len(all_latencies[arm]),
            "p50_ns": _nearest_rank(all_latencies[arm], 0.50),
            "p99_ns": _nearest_rank(all_latencies[arm], 0.99),
        }
        for arm in ARMS
    }
    throughput = {
        arm: {
            "pooled_decisions_per_second": total_decisions[arm] * 1_000_000_000 / total_wall_ns[arm],
            "mean_batch_decisions_per_second": _mean(batch_throughput[arm]),
            "median_batch_decisions_per_second": statistics.median(batch_throughput[arm]),
        }
        for arm in ARMS
    }
    for values in throughput.values():
        if any(not math.isfinite(value) or value <= 0 for value in values.values()):
            raise ValueError("non-finite pooled throughput")
    phase_timing = {
        arm: {
            "initial_mean_per_batch": _mean([
                sample["measurements"][arm]["initialEvidenceNs"] for sample in samples
            ]),
            "final_mean_per_batch": _mean([
                sample["measurements"][arm]["finalEvidenceNs"] for sample in samples
            ]),
        }
        for arm in ARMS
    }
    phase_decomposition = {}
    for arm in ARMS:
        per_batch = []
        for sample in samples:
            measurement = sample["measurements"][arm]
            count = measurement["decisions"]
            mean_evaluate_ns = _mean(measurement["latencyNs"])
            initial_ns_per_decision = measurement["initialEvidenceNs"] / count
            final_ns_per_decision = measurement["finalEvidenceNs"] / count
            per_batch.append({
                "initial": initial_ns_per_decision,
                "final": final_ns_per_decision,
                "residual": mean_evaluate_ns - initial_ns_per_decision - final_ns_per_decision,
            })
        phase_decomposition[arm] = {
            "initial_port_mean_ns_per_decision": _mean([item["initial"] for item in per_batch]),
            "final_port_mean_ns_per_decision": _mean([item["final"] for item in per_batch]),
            "residual_mean_ns_per_decision": _mean([item["residual"] for item in per_batch]),
        }
    geometric_time_ratio = math.exp(_mean([math.log(value) for value in paired_time_ratios]))
    if math.isclose(geometric_time_ratio, 1.0, rel_tol=1e-12, abs_tol=1e-12):
        comparison_label = "no observed paired decision-time difference"
    elif geometric_time_ratio < 1.0:
        comparison_label = "cached arm slower than forced arm in paired measurements"
    else:
        comparison_label = "cached arm faster than forced arm in paired measurements"
    return {
        "case": row["case"],
        "grants": row["grants"],
        "threads": row["threads"],
        "outcome": outcome,
        "decisionsPerThread": row["decisionsPerThread"],
        "decisionsPerBatch": decisions,
        "latency_ns": latency,
        "median_per_batch_mean_decision_ns": {
            arm: statistics.median(mean_decision_ns[arm]) for arm in ARMS
        },
        "throughput_decisions_per_second": throughput,
        "production_clock_cache_hit_fraction": production_cache_hits / production_evidence_reads,
        "production_repository_timing_ns": {
            "initial_mean_per_batch": _mean(initial_evidence_ns),
            "final_mean_per_batch": _mean(final_evidence_ns),
            "initial_median_per_batch": statistics.median(initial_evidence_ns),
            "final_median_per_batch": statistics.median(final_evidence_ns),
        },
        "repository_phase_timing_ns_by_arm": phase_timing,
        "phase_decomposition_mean_ns_per_decision_by_arm": phase_decomposition,
        "paired": {
            "mean_forced_over_cached_decision_time_ratio": _mean(paired_time_ratios),
            "geometric_mean_forced_over_cached_decision_time_ratio": geometric_time_ratio,
            "comparison_label": comparison_label,
            "mean_cached_over_forced_throughput_ratio": _mean(paired_throughput_ratios),
            "geometric_mean_cached_over_forced_throughput_ratio": math.exp(
                _mean([math.log(value) for value in paired_throughput_ratios])
            ),
            "bootstrap_geometric_mean_time_ratio_forced_over_cached_ci95": list(
                _bootstrap_log_ratio_interval(paired_time_ratios, seed)
            ),
            "bootstrap_resamples": BOOTSTRAP_RESAMPLES,
            "bootstrap_seed": seed,
            "paired_batches": len(paired_time_ratios),
            "interpretation": "forced/cached decision-time ratio; values below 1 indicate cached was slower",
            "interval_scope": "unadjusted exploratory interval; no multiplicity correction across 45 cases",
        },
    }


def check_evaluate_performance(stdout):
    """Accept the complete strict EVALUATE_PERF protocol or return FAIL."""
    try:
        if not isinstance(stdout, str):
            raise ValueError("benchmark stdout must be text")
        records = {prefix: [] for prefix in PREFIXES}
        sequence = []
        footer_seen = False
        for line in stdout.splitlines():
            if "filtered out" in line.lower():
                if (not footer_seen and RUST_SUCCESS_FOOTER.fullmatch(line)
                        and sequence and sequence[-1] == "EVALUATE_PERF_END"):
                    footer_seen = True
                    continue
                raise ValueError("filtered benchmark output is not accepted")
            matching = next((prefix for prefix in PREFIXES if line.startswith(prefix)), None)
            if matching is None:
                if "EVALUATE_PERF_" in line:
                    raise ValueError("protocol marker is not at the start of its line")
                continue
            if not line.startswith(matching + " "):
                raise ValueError("malformed benchmark protocol line prefix")
            payload = line[len(matching) + 1:]
            if not payload:
                raise ValueError("empty benchmark protocol record")
            if footer_seen:
                raise ValueError("benchmark protocol record follows the terminal Rust result")
            records[matching].append(_decode_json(payload))
            sequence.append(matching)

        expected_sequence = ["EVALUATE_PERF_META"] + ["EVALUATE_PERF_CASE"] * 45 + ["EVALUATE_PERF_END"]
        if sequence != expected_sequence:
            raise ValueError("benchmark records are incomplete or outside meta/cases/end order")
        if any(len(records[prefix]) != 1 for prefix in ("EVALUATE_PERF_META", "EVALUATE_PERF_END")):
            raise ValueError("benchmark meta/end record is missing or duplicated")
        if len(records["EVALUATE_PERF_CASE"]) != 45:
            raise ValueError("benchmark must emit all 45 unfiltered cases exactly once")
        meta, end = records["EVALUATE_PERF_META"][0], records["EVALUATE_PERF_END"][0]
        _validate_meta(meta)
        rows = records["EVALUATE_PERF_CASE"]
        cases = {}
        for row in rows:
            _validate_case(row)
            case = row["case"]
            if case in cases:
                raise ValueError("duplicate benchmark case")
            cases[case] = row
        expected = {case for case, _, _, _ in _expected_cases()}
        if set(cases) != expected:
            raise ValueError("benchmark case set differs from the exact Cartesian product")
        _validate_end(end)

        ordered_rows = [cases[case] for case, _, _, _ in _expected_cases()]
        summaries = [
            _summarize_case(row, BOOTSTRAP_SEED + index)
            for index, row in enumerate(ordered_rows)
        ]
        performance = {
            "scope": SCOPE,
            "scope_boundaries": list(SCOPE_BOUNDARIES),
            "producer_premises": meta["premises"] if "premises" in meta else {
                name: meta[name] for name in PREMISE_NAMES
            },
            "cases": len(ordered_rows),
            "samples_per_case": SAMPLES_PER_CASE,
            "measurements": 2430,
            "summary": summaries,
            "raw": {"meta": meta, "cases": rows, "end": end},
            "interpretation": "protocol acceptance only; no minimum speedup or no-regression threshold is applied",
            "bootstrap": {
                "resamples_per_case": BOOTSTRAP_RESAMPLES,
                "seed_base": BOOTSTRAP_SEED,
                "interval": "paired percentile 95% interval for geometric mean forced/cached decision-time ratio, resampling 18 per-case batch log-ratios",
                "multiplicity": "unadjusted and exploratory across the 45 cases; not deployment inference",
            },
        }
        return {
            "status": "PASS",
            "reason": "complete strict CPU PolicyEngine.evaluate protocol; estimates are reported without a benefit threshold",
            "performance": performance,
            "verified_postcondition": {
                "complete": True,
                "schema": SCHEMA,
                "cases": 45,
                "samples": 810,
                "measurements": 2430,
                "workersJoined": True,
                "allDecisionsChecked": True,
                "allReadCountsChecked": True,
            },
        }
    except Exception as error:
        return _failure(f"strict evaluate benchmark acceptance failed: {type(error).__name__}: {error}")
