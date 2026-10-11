from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import evaluate_performance_acceptance as acceptance


def _meta():
    return {
        "schema": acceptance.SCHEMA,
        "scope": acceptance.SCOPE,
        "samplesPerCase": 18,
        "grantSizes": list(acceptance.GRANT_SIZES),
        "threads": list(acceptance.THREAD_COUNTS),
        "outcomes": list(acceptance.OUTCOMES),
        "arms": list(acceptance.ARMS),
        "timing": "evaluate-call-return",
        "debugAssertions": False,
        "controls": {name: True for name in acceptance.CONTROL_NAMES},
        "premises": {
            name: f"fixture premise for {name}"
            for name in acceptance.PREMISE_NAMES
        },
    }


def _measurement(arm, grants, threads, outcome, latency_ns=200, wall_ns=None):
    decisions = threads * acceptance.DECISIONS_PER_THREAD[grants]
    allow = outcome in ("allow-first", "allow-last")
    reads = decisions * (2 if allow else 1)
    if wall_ns is None:
        wall_ns = decisions * latency_ns
    return {
        "decisions": decisions,
        "wallNs": wall_ns,
        "latencyNs": [latency_ns] * decisions,
        "cardChecks": decisions,
        "orgReads": decisions,
        "evidenceReads": reads,
        "scopedReads": reads,
        "evidenceGrants": reads * grants,
        "cacheHits": reads if arm == "cached-fixed-second" else 0,
        "initialEvidenceNs": 10,
        "finalEvidenceNs": 10 if allow else 0,
        "allowed": decisions if allow else 0,
        "denied": 0 if allow else decisions,
        "pending": 0,
        "mismatches": 0,
        "legacyReads": 0,
    }


def _case(grants=1, threads=1, outcome="allow-first", latencies=None):
    if latencies is None:
        latencies = {arm: 200 for arm in acceptance.ARMS}
    decisions_per_thread = acceptance.DECISIONS_PER_THREAD[grants]
    samples = []
    for index in range(18):
        samples.append({
            "index": index,
            "order": list(acceptance.ORDERS[index % len(acceptance.ORDERS)]),
            "measurements": {
                arm: _measurement(arm, grants, threads, outcome, latencies[arm])
                for arm in acceptance.ARMS
            },
        })
    return {
        "case": f"evaluate/{grants}/threads-{threads}/{outcome}",
        "grants": grants,
        "threads": threads,
        "outcome": outcome,
        "decisionsPerThread": decisions_per_thread,
        "samples": samples,
    }


def _end():
    return {
        "schema": acceptance.SCHEMA,
        "status": "PASS",
        "cases": 45,
        "samples": 810,
        "measurements": 2430,
        "postconditions": {
            "workersJoined": True,
            "allDecisionsChecked": True,
            "allReadCountsChecked": True,
        },
    }


def _valid_stdout(latencies=None):
    lines = ["EVALUATE_PERF_META " + json.dumps(_meta(), separators=(",", ":"))]
    for case, grants, threads, outcome in acceptance._expected_cases():
        row = _case(grants, threads, outcome, latencies)
        assert row["case"] == case
        lines.append("EVALUATE_PERF_CASE " + json.dumps(row, separators=(",", ":")))
    lines.append("EVALUATE_PERF_END " + json.dumps(_end(), separators=(",", ":")))
    return "\n".join(lines) + "\n"


class EvaluatePerformanceAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stdout = _valid_stdout()

    def test_complete_no_benefit_protocol_passes_without_speed_threshold(self):
        result = acceptance.check_evaluate_performance(self.stdout)
        self.assertEqual(result["status"], "PASS", result["reason"])
        self.assertEqual(result["verified_postcondition"]["measurements"], 2430)
        performance = result["performance"]
        self.assertEqual(len(performance["raw"]["cases"]), 45)
        self.assertEqual(len(performance["summary"]), 45)
        first = performance["summary"][0]
        self.assertEqual(first["latency_ns"]["cached-fixed-second"]["p50_ns"], 200)
        self.assertEqual(first["latency_ns"]["forced-assembly"]["p99_ns"], 200)
        self.assertEqual(first["throughput_decisions_per_second"]["production-clock"]["pooled_decisions_per_second"], 5_000_000)
        self.assertEqual(first["paired"]["geometric_mean_forced_over_cached_decision_time_ratio"], 1.0)
        self.assertEqual(first["paired"]["comparison_label"], "no observed paired decision-time difference")
        self.assertEqual(first["paired"]["bootstrap_geometric_mean_time_ratio_forced_over_cached_ci95"], [1.0, 1.0])
        self.assertIn("Not a signed HTTP", " ".join(performance["scope_boundaries"]))
        self.assertEqual(performance["raw"]["meta"]["premises"], _meta()["premises"])
        self.assertIn("unadjusted", performance["bootstrap"]["multiplicity"])
        self.assertIn("exploratory", performance["bootstrap"]["multiplicity"])

    def test_complete_regression_estimate_is_reported_but_does_not_fail_acceptance(self):
        slower_cached = {
            "cached-fixed-second": 300,
            "forced-assembly": 200,
            "production-clock": 250,
        }
        result = acceptance.check_evaluate_performance(_valid_stdout(slower_cached))
        self.assertEqual(result["status"], "PASS", result["reason"])
        paired = result["performance"]["summary"][0]["paired"]
        self.assertAlmostEqual(paired["geometric_mean_forced_over_cached_decision_time_ratio"], 2 / 3)
        self.assertEqual(paired["comparison_label"], "cached arm slower than forced arm in paired measurements")

    def test_protocol_rejects_partial_duplicate_filtered_and_misplaced_records(self):
        case_line = next(line for line in self.stdout.splitlines() if line.startswith("EVALUATE_PERF_CASE "))
        cases = [line for line in self.stdout.splitlines() if line.startswith("EVALUATE_PERF_CASE ")]
        malformed = (
            self.stdout.replace(case_line + "\n", "", 1),
            self.stdout + case_line + "\n",
            self.stdout + "filtered out 1 benchmark case\n",
            self.stdout.replace("EVALUATE_PERF_META ", " EVALUATE_PERF_META ", 1),
            self.stdout + "EVALUATE_PERF_CASE{}\n",
        )
        self.assertEqual(len(cases), 45)
        for output in malformed:
            with self.subTest(length=len(output)):
                self.assertEqual(acceptance.check_evaluate_performance(output)["status"], "FAIL")

    def test_complete_protocol_accepts_exact_cargo_success_footer(self):
        footer = (
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
            "864 filtered out; finished in 12.34s\n"
        )
        output = "running 1 test\n" + self.stdout + "test policy_evaluate_complete_benefit_matrix ... ok\n" + footer
        result = acceptance.check_evaluate_performance(output)
        self.assertEqual(result["status"], "PASS", result["reason"])
        for invalid in (footer + self.stdout, self.stdout + footer + footer,
                        self.stdout + footer.replace("1 passed", "0 passed"),
                        self.stdout + footer.replace("0 ignored", "1 ignored")):
            with self.subTest(output_end=invalid[-120:]):
                self.assertEqual(acceptance.check_evaluate_performance(invalid)["status"], "FAIL")

    def test_protocol_requires_meta_first_and_end_after_all_cases(self):
        lines = self.stdout.splitlines()
        for reordered in ([lines[-1], *lines[:-1]], [lines[1], lines[0], *lines[2:]],
                          [lines[0], lines[-1], *lines[1:-1]]):
            with self.subTest(first_line=reordered[0][:30]):
                self.assertEqual(acceptance.check_evaluate_performance("\n".join(reordered))["status"], "FAIL")

    def test_parser_rejects_invalid_json_nonfinite_and_duplicate_keys(self):
        for output in (
            'EVALUATE_PERF_META {"schema":NaN}\n',
            'EVALUATE_PERF_META {"schema":"one","schema":"two"}\n',
            'EVALUATE_PERF_META {"schema":"unterminated}\n',
        ):
            self.assertEqual(acceptance.check_evaluate_performance(output)["status"], "FAIL")

    def test_meta_rejects_topology_type_bool_controls_and_debug_build(self):
        invalid_metas = []
        meta = _meta()
        meta["samplesPerCase"] = True
        invalid_metas.append(meta)
        meta = _meta()
        meta["grantSizes"][0] = True
        invalid_metas.append(meta)
        meta = _meta()
        meta["threads"] = [1, 4, 7]
        invalid_metas.append(meta)
        meta = _meta()
        del meta["controls"]["crossSecondExpiry"]
        invalid_metas.append(meta)
        meta = _meta()
        meta["premises"].pop("scopeExclusions")
        invalid_metas.append(meta)
        meta = _meta()
        meta["controls"]["denyOneRead"] = 1
        invalid_metas.append(meta)
        meta = _meta()
        meta["debugAssertions"] = True
        invalid_metas.append(meta)
        meta = _meta()
        meta["buildProfile"] = "debug"
        invalid_metas.append(meta)
        for candidate in invalid_metas:
            with self.subTest(meta=candidate):
                with self.assertRaises(ValueError):
                    acceptance._validate_meta(candidate)

    def test_case_rejects_workload_drift_bool_fields_and_changed_order(self):
        candidate = _case()
        candidate["decisionsPerThread"] = 255
        with self.assertRaises(ValueError):
            acceptance._validate_case(candidate)
        candidate = _case()
        candidate["grants"] = True
        with self.assertRaises(ValueError):
            acceptance._validate_case(candidate)
        candidate = _case()
        candidate["threads"] = True
        with self.assertRaises(ValueError):
            acceptance._validate_case(candidate)
        candidate = _case()
        candidate["samples"][0]["order"] = list(reversed(candidate["samples"][0]["order"]))
        with self.assertRaises(ValueError):
            acceptance._validate_case(candidate)
        candidate = _case()
        candidate["samples"].pop()
        with self.assertRaises(ValueError):
            acceptance._validate_case(candidate)

    def test_case_rejects_early_allow_deny_count_cache_read_and_timing_errors(self):
        mutations = (
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
        )
        for field, value, arm in mutations:
            candidate = _case()
            candidate["samples"][0]["measurements"][arm][field] = value
            with self.subTest(field=field, arm=arm):
                with self.assertRaises(ValueError):
                    acceptance._validate_case(candidate)

        candidate = _case()
        sample = candidate["samples"][0]["measurements"]["cached-fixed-second"]
        sample["latencyNs"].pop()
        with self.assertRaises(ValueError):
            acceptance._validate_case(candidate)
        candidate = _case()
        sample = candidate["samples"][0]["measurements"]["cached-fixed-second"]
        sample["latencyNs"][0] = True
        with self.assertRaises(ValueError):
            acceptance._validate_case(candidate)
        candidate = _case()
        sample = candidate["samples"][0]["measurements"]["cached-fixed-second"]
        sample["latencyNs"][0] = 0
        with self.assertRaises(ValueError):
            acceptance._validate_case(candidate)
        candidate = _case()
        sample = candidate["samples"][0]["measurements"]["cached-fixed-second"]
        sample["cacheHits"] = True
        with self.assertRaises(ValueError):
            acceptance._validate_case(candidate)

    def test_deny_requires_one_read_and_zero_final_phase(self):
        candidate = _case(outcome="deny")
        acceptance._validate_case(candidate)
        candidate["samples"][0]["measurements"]["production-clock"]["finalEvidenceNs"] = 1
        with self.assertRaises(ValueError):
            acceptance._validate_case(candidate)

    def test_end_requires_exact_counts_and_all_nonvacuous_postconditions(self):
        end = _end()
        acceptance._validate_end(end)
        for field, value in (("cases", 44), ("samples", 809), ("measurements", 2429)):
            candidate = copy.deepcopy(end)
            candidate[field] = value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    acceptance._validate_end(candidate)
        candidate = copy.deepcopy(end)
        candidate["postconditions"]["workersJoined"] = False
        with self.assertRaises(ValueError):
            acceptance._validate_end(candidate)
        candidate = copy.deepcopy(end)
        candidate["postconditions"]["extra"] = True
        with self.assertRaises(ValueError):
            acceptance._validate_end(candidate)
        candidate = copy.deepcopy(end)
        candidate["measurements"] = True
        with self.assertRaises(ValueError):
            acceptance._validate_end(candidate)

    def test_paired_metrics_and_fixed_seed_bootstrap_are_reproducible(self):
        row = _case(latencies={
            "cached-fixed-second": 200,
            "forced-assembly": 100,
            "production-clock": 150,
        })
        summary = acceptance._summarize_case(row, 12345)
        self.assertEqual(summary["latency_ns"]["cached-fixed-second"]["p50_ns"], 200)
        self.assertEqual(summary["latency_ns"]["forced-assembly"]["p99_ns"], 100)
        self.assertEqual(summary["throughput_decisions_per_second"]["cached-fixed-second"]["pooled_decisions_per_second"], 5_000_000)
        self.assertEqual(summary["throughput_decisions_per_second"]["forced-assembly"]["pooled_decisions_per_second"], 10_000_000)
        self.assertEqual(summary["paired"]["mean_forced_over_cached_decision_time_ratio"], 0.5)
        self.assertEqual(summary["paired"]["mean_cached_over_forced_throughput_ratio"], 0.5)
        self.assertEqual(summary["production_clock_cache_hit_fraction"], 0.0)
        self.assertEqual(summary["production_repository_timing_ns"]["initial_mean_per_batch"], 10.0)
        self.assertEqual(
            summary["phase_decomposition_mean_ns_per_decision_by_arm"]["cached-fixed-second"],
            {
                "initial_port_mean_ns_per_decision": 10 / 256,
                "final_port_mean_ns_per_decision": 10 / 256,
                "residual_mean_ns_per_decision": 200 - 20 / 256,
            },
        )
        deny = acceptance._summarize_case(_case(outcome="deny"), 12345)
        self.assertEqual(
            deny["phase_decomposition_mean_ns_per_decision_by_arm"]["production-clock"],
            {
                "initial_port_mean_ns_per_decision": 10 / 256,
                "final_port_mean_ns_per_decision": 0.0,
                "residual_mean_ns_per_decision": 200 - 10 / 256,
            },
        )
        self.assertEqual(
            acceptance._bootstrap_log_ratio_interval([0.5] * 18, 12345),
            acceptance._bootstrap_log_ratio_interval([0.5] * 18, 12345),
        )

    def test_public_api_never_raises_for_wrong_stdout_type(self):
        result = acceptance.check_evaluate_performance(None)
        self.assertEqual(result["status"], "FAIL")
        self.assertIsNone(result["performance"])
        self.assertFalse(result["verified_postcondition"]["complete"])


if __name__ == "__main__":
    unittest.main()
