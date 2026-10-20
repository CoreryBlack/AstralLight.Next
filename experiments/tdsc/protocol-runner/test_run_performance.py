#!/usr/bin/env python3
import importlib.util
import socket
import unittest
import urllib.error
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("run-performance.py")
MODULE_SPEC = importlib.util.spec_from_file_location("run_performance", MODULE_PATH)
if MODULE_SPEC is None or MODULE_SPEC.loader is None:
    raise RuntimeError("Unable to load run-performance.py for tests.")
run_performance = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(run_performance)


class ClassificationTests(unittest.TestCase):
    def test_status_classification_is_mutually_exclusive(self):
        cases = {
            200: "success",
            302: "success",
            400: "http_4xx",
            499: "http_4xx",
            500: "http_5xx",
            599: "http_5xx",
            0: "transport_error",
            None: "transport_error",
        }
        for status, expected in cases.items():
            with self.subTest(status=status):
                self.assertEqual(expected, run_performance.classify_status(status))

    def test_exception_classification_distinguishes_timeout(self):
        self.assertEqual(("timeout", None), run_performance.classify_exception(socket.timeout("late")))
        self.assertEqual(
            ("timeout", None),
            run_performance.classify_exception(urllib.error.URLError(socket.timeout("late"))),
        )
        self.assertEqual(
            ("http_4xx", 404),
            run_performance.classify_exception(urllib.error.HTTPError("http://example", 404, "missing", {}, None)),
        )
        self.assertEqual(
            ("transport_error", None),
            run_performance.classify_exception(urllib.error.URLError("unreachable")),
        )


class PercentileTests(unittest.TestCase):
    def test_percentiles_are_interpolated(self):
        values = [1.0, 2.0, 3.0, 4.0]
        self.assertEqual(1.0, run_performance.percentile(values, 0.0))
        self.assertEqual(2.5, run_performance.percentile(values, 50.0))
        self.assertAlmostEqual(3.85, run_performance.percentile(values, 95.0))
        self.assertEqual(4.0, run_performance.percentile(values, 100.0))

    def test_empty_percentile_is_none(self):
        self.assertIsNone(run_performance.percentile([], 50.0))

    def test_percentile_rejects_invalid_range(self):
        with self.assertRaises(ValueError):
            run_performance.percentile([1.0], 101.0)


class SchemaTests(unittest.TestCase):
    def test_sample_row_matches_declared_schema(self):
        row = run_performance.sample_row(1, 4, 2, 3, "success", 200, 2_500_000)
        self.assertEqual(run_performance.SAMPLE_FIELDS, tuple(row.keys()))
        self.assertEqual("2.500000", row["latency_ms"])
        run_performance.validate_sample_row(row)

    def test_schema_rejects_invalid_outcome(self):
        row = run_performance.sample_row(1, 1, 1, 1, "success", 200, 1)
        row["outcome"] = "unknown"
        with self.assertRaises(ValueError):
            run_performance.validate_sample_row(row)

    def test_concurrency_parser_requires_unique_positive_values(self):
        self.assertEqual([1, 4, 8], run_performance.parse_concurrencies("1,4,8"))
        for value in ("", "1, 4", "1,1", "0,4", "a,4"):
            with self.subTest(value=value):
                with self.assertRaises(run_performance.DriverError):
                    run_performance.parse_concurrencies(value)
    def test_replicate_summary_has_rate_and_success_throughput_metrics(self):
        rows = [
            run_performance.sample_row(1, 2, 1, 1, "success", 200, 1_000_000),
            run_performance.sample_row(1, 2, 2, 1, "http_5xx", 503, 3_000_000),
        ]
        summary = run_performance.replicate_summary(rows, 1, 2, 1_000_000_000)
        self.assertEqual(2, summary["sampleCount"])
        self.assertEqual(1, summary["successfulCount"])
        self.assertEqual(1, summary["errorCount"])
        self.assertEqual(2.0, summary["throughputQps"])
        self.assertEqual(1.0, summary["successQps"])
        self.assertEqual(0.5, summary["successRate"])
        self.assertEqual(0.5, summary["errorRate"])

    def test_concurrency_summary_uses_replicate_level_metrics(self):
        replicates = [
            {"throughputQps": 4.0, "successQps": 3.0, "successRate": 0.75, "errorRate": 0.25, "p50Ms": 1.0, "p95Ms": 2.0, "p99Ms": 3.0, "sampleCount": 4, "outcomes": {"success": 3, "http_4xx": 1, "http_5xx": 0, "transport_error": 0, "timeout": 0}},
            {"throughputQps": 6.0, "successQps": 6.0, "successRate": 1.0, "errorRate": 0.0, "p50Ms": 2.0, "p95Ms": 4.0, "p99Ms": 5.0, "sampleCount": 6, "outcomes": {"success": 6, "http_4xx": 0, "http_5xx": 0, "transport_error": 0, "timeout": 0}},
        ]
        summary = run_performance.concurrency_summary(replicates, 2)
        metrics = summary["replicateLevelMetrics"]
        self.assertEqual(5.0, metrics["throughputQps"]["mean"])
        self.assertEqual(4.5, metrics["successQps"]["mean"])
        self.assertEqual(0.875, metrics["successRate"]["mean"])
        self.assertEqual(0.125, metrics["errorRate"]["mean"])


if __name__ == "__main__":
    unittest.main()
